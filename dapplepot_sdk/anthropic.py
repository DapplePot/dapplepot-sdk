"""
Drop-in replacement for the Anthropic SDK.

    from dapplepot_sdk.anthropic import anthropic

All anthropic.* calls work identically but are traced per session via
dp.session() context manager or, when used outside one, as individual sessions.

Tool calls are traced automatically — no client code required:
  - tool_start is emitted when the model returns a tool_use block
  - tool_end   is emitted when the next messages.create() carries the matching tool_result
"""

import json
import time
import uuid
import functools
import logging

logger = logging.getLogger(__name__)

try:
    import anthropic as _anthropic
except ImportError:
    raise ImportError("anthropic not installed. Run: pip install anthropic")

from dapplepot_sdk.session import get_current_session_id
from dapplepot_sdk._adapter import first_user_text

_client_ref = None

# {session_id: {tool_use_id: (tool_name, start_time)}}
# Populated when the model returns tool_use blocks; consumed when the matching
# tool_result appears in the next messages.create() call.
_pending_tools: dict[str, dict[str, tuple[str, float]]] = {}


def _get_client():
    return _client_ref


def _extract_output(content_field) -> str:
    """Normalise a tool_result content field to a plain string."""
    if isinstance(content_field, list):
        return ' '.join(
            b.get('text', '') if isinstance(b, dict) else str(b)
            for b in content_field
        )
    return str(content_field) if content_field is not None else ''


def _flush_tool_results(messages: list, session_id: str, dp, adapter) -> None:
    """
    Scan incoming messages for tool_result blocks and emit tool_end or tool_error
    for each one that has a matching pending tool_start in this session.

    Anthropic signals a failed tool execution via is_error=True on the tool_result
    block. When present, tool_error is emitted instead of tool_end.
    """
    pending = _pending_tools.get(session_id)
    if not pending:
        return
    for msg in messages:
        if not isinstance(msg, dict) or msg.get('role') != 'user':
            continue
        content = msg.get('content', [])
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict) or block.get('type') != 'tool_result':
                continue
            tool_use_id = block.get('tool_use_id', '')
            if tool_use_id not in pending:
                continue
            tool_name, t_start = pending.pop(tool_use_id)
            latency_ms = int((time.time() - t_start) * 1000)
            output = _extract_output(block.get('content'))
            if block.get('is_error'):
                dp._process_event(
                    adapter.tool_error(
                        session_id,
                        tool_name=tool_name,
                        error_type='ToolExecutionError',
                        error_message=output,
                    )
                )
            else:
                dp._process_event(
                    adapter.tool_end(
                        session_id,
                        tool_name=tool_name,
                        tool_output=output,
                        latency_ms=latency_ms,
                    )
                )


class _AnthropicStreamAccumulator:
    """Folds Anthropic MessageStreamEvent variants into the same shape the
    non-streaming response carries — concatenated text, accumulated tool_use
    blocks, stop_reason, and a merged usage record.

    Event sequence (from the Anthropic streaming wire format):
      message_start          → usage.input_tokens
      content_block_start    → opens a block at `index`; carries id+name if tool_use
      content_block_delta    → text_delta (text fragment) or input_json_delta (args fragment)
      content_block_stop     → block is closed
      message_delta          → stop_reason and updated usage.output_tokens
      message_stop           → terminal sentinel
    """

    def __init__(self):
        self.completion: str = ''
        # index -> {'type': 'text'|'tool_use', 'id'?, 'name'?, 'text': '', 'partial_json': ''}
        self.blocks: dict = {}
        self.stop_reason = None
        self.input_tokens = None
        self.output_tokens = None

    def absorb(self, event) -> None:
        etype = getattr(event, 'type', None)

        if etype == 'message_start':
            msg = getattr(event, 'message', None)
            if msg is not None:
                u = getattr(msg, 'usage', None)
                if u is not None:
                    self.input_tokens = getattr(u, 'input_tokens', self.input_tokens)
                    # output_tokens on message_start is 0; final value comes in message_delta
                    ot = getattr(u, 'output_tokens', None)
                    if ot:
                        self.output_tokens = ot

        elif etype == 'content_block_start':
            idx = getattr(event, 'index', 0)
            cb = getattr(event, 'content_block', None)
            if cb is not None:
                btype = getattr(cb, 'type', None)
                slot = {'type': btype, 'text': '', 'partial_json': ''}
                if btype == 'tool_use':
                    slot['id'] = getattr(cb, 'id', '') or ''
                    slot['name'] = getattr(cb, 'name', '') or ''
                self.blocks[idx] = slot

        elif etype == 'content_block_delta':
            idx = getattr(event, 'index', 0)
            slot = self.blocks.setdefault(idx, {'type': None, 'text': '', 'partial_json': ''})
            delta = getattr(event, 'delta', None)
            if delta is not None:
                dtype = getattr(delta, 'type', None)
                if dtype == 'text_delta':
                    text = getattr(delta, 'text', '') or ''
                    if text:
                        slot['text'] += text
                        self.completion += text
                elif dtype == 'input_json_delta':
                    pj = getattr(delta, 'partial_json', '') or ''
                    if pj:
                        slot['partial_json'] += pj

        elif etype == 'message_delta':
            delta = getattr(event, 'delta', None)
            if delta is not None:
                sr = getattr(delta, 'stop_reason', None)
                if sr:
                    self.stop_reason = sr
            u = getattr(event, 'usage', None)
            if u is not None:
                ot = getattr(u, 'output_tokens', None)
                if ot is not None:
                    self.output_tokens = ot

    def usage_dict(self):
        if self.input_tokens is None and self.output_tokens is None:
            return None
        return {
            'prompt_tokens': self.input_tokens,
            'completion_tokens': self.output_tokens,
        }

    def collected_tool_uses(self) -> list:
        """Reassemble tool_use blocks. Each block's `partial_json` is the full
        arguments JSON once `content_block_stop` has fired for that index."""
        out = []
        for idx in sorted(self.blocks.keys()):
            slot = self.blocks[idx]
            if slot.get('type') != 'tool_use':
                continue
            try:
                tool_input = json.loads(slot.get('partial_json') or '{}')
            except (json.JSONDecodeError, TypeError):
                tool_input = slot.get('partial_json')
            out.append({
                'id': slot.get('id', ''),
                'name': slot.get('name', ''),
                'input': tool_input,
            })
        return out


def _acc_from_final_message(msg) -> _AnthropicStreamAccumulator:
    """Build an accumulator from a fully-formed Message object — used by the
    `messages.stream()` path, where the SDK gives us a final Message at exit
    rather than the raw event stream."""
    acc = _AnthropicStreamAccumulator()
    if msg is None:
        return acc
    for block in (getattr(msg, 'content', None) or []):
        btype = getattr(block, 'type', None)
        if btype == 'text':
            txt = getattr(block, 'text', '') or ''
            acc.completion += txt
        elif btype == 'tool_use':
            idx = len(acc.blocks)
            tool_input = getattr(block, 'input', None) or {}
            acc.blocks[idx] = {
                'type': 'tool_use',
                'id': getattr(block, 'id', '') or '',
                'name': getattr(block, 'name', '') or '',
                'text': '',
                'partial_json': json.dumps(tool_input),
            }
    acc.stop_reason = getattr(msg, 'stop_reason', None)
    u = getattr(msg, 'usage', None)
    if u is not None:
        acc.input_tokens = getattr(u, 'input_tokens', None)
        acc.output_tokens = getattr(u, 'output_tokens', None)
    return acc


class _AnthropicTracingStream:
    """Wraps a `Stream[MessageStreamEvent]` returned by
    `messages.create(stream=True)`. Forwards iteration + ctx-mgr protocol
    while absorbing every event into an accumulator. `on_close` fires once.
    """

    def __init__(self, stream, on_close):
        self._stream = stream
        self._acc = _AnthropicStreamAccumulator()
        self._on_close = on_close
        self._closed = False

    def __iter__(self):
        return self

    def __next__(self):
        try:
            event = next(self._stream)
        except StopIteration:
            self._close()
            raise
        try:
            self._acc.absorb(event)
        except Exception:
            logger.exception('DapplePot stream event absorption failed')
        return event

    def __enter__(self):
        enter = getattr(self._stream, '__enter__', None)
        if enter is not None:
            enter()
        return self

    def __exit__(self, *exc):
        try:
            exit_ = getattr(self._stream, '__exit__', None)
            if exit_ is not None:
                exit_(*exc)
        finally:
            self._close()

    def _close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self._on_close(self._acc)
        except Exception:
            logger.exception('DapplePot stream on_close failed')

    def __del__(self):
        try:
            self._close()
        except Exception:
            pass

    def __getattr__(self, name):
        return getattr(self._stream, name)


class _AnthropicAsyncTracingStream:
    """Async mirror of `_AnthropicTracingStream` — forwards `__aiter__` /
    `__anext__` and async context-manager protocol. `on_close` is sync since
    it only emits events into the DapplePot buffer."""

    def __init__(self, stream, on_close):
        self._stream = stream
        self._acc = _AnthropicStreamAccumulator()
        self._on_close = on_close
        self._closed = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            event = await self._stream.__anext__()
        except StopAsyncIteration:
            self._close()
            raise
        try:
            self._acc.absorb(event)
        except Exception:
            logger.exception('DapplePot stream event absorption failed')
        return event

    async def __aenter__(self):
        enter = getattr(self._stream, '__aenter__', None)
        if enter is not None:
            await enter()
        return self

    async def __aexit__(self, *exc):
        try:
            exit_ = getattr(self._stream, '__aexit__', None)
            if exit_ is not None:
                await exit_(*exc)
        finally:
            self._close()

    def _close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self._on_close(self._acc)
        except Exception:
            logger.exception('DapplePot stream on_close failed')

    def __del__(self):
        try:
            self._close()
        except Exception:
            pass

    def __getattr__(self, name):
        return getattr(self._stream, name)


class _AnthropicMessageStreamManagerWrapper:
    """Wraps the `MessageStreamManager` returned by `messages.stream(...)`.

    Strategy: when the `with` block exits, call `stream.get_final_message()` to
    obtain the fully-formed Message object — same shape as the non-streaming
    response — then build an accumulator from it and fire `on_close` once.

    We intentionally return the underlying `MessageStream` unchanged from
    `__enter__` so the user's iteration / `text_stream` / `get_final_message`
    usage is undisturbed.
    """

    def __init__(self, manager, on_close):
        self._mgr = manager
        self._stream = None
        self._on_close = on_close
        self._closed = False

    def __enter__(self):
        self._stream = self._mgr.__enter__()
        return self._stream

    def __exit__(self, *exc):
        final_msg = None
        try:
            try:
                # Fully drain the stream if the user didn't, then return the Message.
                if self._stream is not None:
                    final_msg = self._stream.get_final_message()
            except Exception:
                logger.exception('DapplePot stream get_final_message failed')
        finally:
            try:
                self._mgr.__exit__(*exc)
            finally:
                self._close(final_msg)

    def _close(self, final_msg):
        if self._closed:
            return
        self._closed = True
        try:
            self._on_close(_acc_from_final_message(final_msg))
        except Exception:
            logger.exception('DapplePot stream on_close failed')

    def __del__(self):
        try:
            self._close(None)
        except Exception:
            pass


class _AnthropicAsyncMessageStreamManagerWrapper:
    """Async mirror of `_AnthropicMessageStreamManagerWrapper`. Calls
    `await stream.get_final_message()` on exit, builds an accumulator from
    the result, fires `on_close` once."""

    def __init__(self, manager, on_close):
        self._mgr = manager
        self._stream = None
        self._on_close = on_close
        self._closed = False

    async def __aenter__(self):
        self._stream = await self._mgr.__aenter__()
        return self._stream

    async def __aexit__(self, *exc):
        final_msg = None
        try:
            try:
                if self._stream is not None:
                    final_msg = await self._stream.get_final_message()
            except Exception:
                logger.exception('DapplePot stream get_final_message failed')
        finally:
            try:
                await self._mgr.__aexit__(*exc)
            finally:
                self._close(final_msg)

    def _close(self, final_msg):
        if self._closed:
            return
        self._closed = True
        try:
            self._on_close(_acc_from_final_message(final_msg))
        except Exception:
            logger.exception('DapplePot stream on_close failed')

    def __del__(self):
        try:
            self._close(None)
        except Exception:
            pass


def _patch(client) -> None:
    global _client_ref
    _client_ref = client

    try:
        _Messages = _anthropic.resources.Messages
    except AttributeError:
        logger.warning('Could not find anthropic.resources.Messages to patch')
        return
    orig_create = getattr(_Messages, 'create', None)
    if orig_create is None:
        logger.warning('Could not patch anthropic.resources.Messages.create')
        return

    @functools.wraps(orig_create)
    def patched_create(self_sdk, *args, **kwargs):
        dp = _get_client()
        if dp is None:
            return orig_create(self_sdk, *args, **kwargs)

        session_id = get_current_session_id() or str(uuid.uuid4())
        adapter = dp._adapter('anthropic')

        standalone = get_current_session_id() is None
        model = kwargs.get('model', 'unknown')
        messages = kwargs.get('messages', [])

        # Emit tool_end for any tool_result blocks in the incoming messages
        _flush_tool_results(messages, session_id, dp, adapter)

        if standalone:
            sampled = dp._should_sample()
            dp._buffer.set_sampled(session_id, sampled)
            dp._process_event(adapter.session_start(session_id, input=first_user_text(messages)))

        tools = kwargs.get('tools') or []
        try:
            dp._process_event(adapter.llm_start(session_id, model=model, messages=messages,
                                                 max_tokens=kwargs.get('max_tokens'),
                                                 tools=tools))
        except Exception as pre_exc:
            from dapplepot_sdk import DapplePotBlockedError
            if isinstance(pre_exc, DapplePotBlockedError):
                if standalone:
                    dp._buffer.flush_sync()
                return None
            raise

        streaming = bool(kwargs.get('stream'))

        t0 = time.time()
        try:
            response = orig_create(self_sdk, *args, **kwargs)
        except Exception as exc:
            latency_ms = int((time.time() - t0) * 1000)
            dp._process_event(adapter.llm_error(session_id, model=model,
                                                error_type=type(exc).__name__,
                                                error_message=str(exc),
                                                latency_ms=latency_ms))
            if standalone:
                # In standalone mode there is no dp.session() context manager to
                # emit session_error, so the patcher is responsible for it.
                dp._process_event(adapter.session_error(session_id,
                                                        error_type=type(exc).__name__,
                                                        error_message=str(exc)))
            # In session mode, dp.session().__exit__ catches the propagated
            # exception and emits session_error — emitting it here would duplicate it.
            raise

        if streaming:
            def _on_stream_close(acc):
                latency_ms = int((time.time() - t0) * 1000)
                dp._process_event(adapter.llm_end(session_id, completion=acc.completion,
                                                  model=model,
                                                  finish_reason=acc.stop_reason,
                                                  usage=acc.usage_dict(),
                                                  latency_ms=latency_ms,
                                                  streamed=True))
                tool_uses = acc.collected_tool_uses()
                if tool_uses:
                    t_tool = time.time()
                    for tu in tool_uses:
                        tu_id = tu['id'] or str(uuid.uuid4())
                        tu_name = tu['name'] or 'unknown'
                        if session_id not in _pending_tools:
                            _pending_tools[session_id] = {}
                        _pending_tools[session_id][tu_id] = (tu_name, t_tool)
                        dp._process_event(
                            adapter.tool_start(session_id, tool_name=tu_name, tool_input=tu['input'])
                        )
                if standalone:
                    dp._process_event(adapter.session_end(session_id, output=acc.completion,
                                                           latency_ms=latency_ms))
            return _AnthropicTracingStream(response, _on_stream_close)

        latency_ms = int((time.time() - t0) * 1000)
        content = response.content
        completion = ''
        if content:
            for block in content:
                if hasattr(block, 'text'):
                    completion += block.text

        usage_obj = getattr(response, 'usage', None)
        usage = None
        if usage_obj:
            usage = {
                'prompt_tokens': getattr(usage_obj, 'input_tokens', None),
                'completion_tokens': getattr(usage_obj, 'output_tokens', None),
            }

        dp._process_event(adapter.llm_end(session_id, completion=completion,
                                          model=model,
                                          finish_reason=getattr(response, 'stop_reason', None),
                                          usage=usage,
                                          latency_ms=latency_ms))

        # Emit tool_start for every tool_use block in the response
        if content:
            t_tool = time.time()
            for block in content:
                if getattr(block, 'type', None) == 'tool_use':
                    if session_id not in _pending_tools:
                        _pending_tools[session_id] = {}
                    _pending_tools[session_id][block.id] = (block.name, t_tool)
                    dp._process_event(
                        adapter.tool_start(
                            session_id,
                            tool_name=block.name,
                            tool_input=getattr(block, 'input', None),
                        )
                    )

        if standalone:
            dp._process_event(adapter.session_end(session_id, output=completion,
                                                   latency_ms=latency_ms))
        return response

    _Messages.create = patched_create

    orig_stream = getattr(_Messages, 'stream', None)
    if orig_stream is not None:
        @functools.wraps(orig_stream)
        def patched_stream(self_sdk, *args, **kwargs):
            dp = _get_client()
            if dp is None:
                return orig_stream(self_sdk, *args, **kwargs)

            session_id = get_current_session_id() or str(uuid.uuid4())
            adapter = dp._adapter('anthropic')

            standalone = get_current_session_id() is None
            model = kwargs.get('model', 'unknown')
            messages = kwargs.get('messages', [])

            _flush_tool_results(messages, session_id, dp, adapter)

            if standalone:
                sampled = dp._should_sample()
                dp._buffer.set_sampled(session_id, sampled)
                dp._process_event(adapter.session_start(session_id, input=first_user_text(messages)))

            tools = kwargs.get('tools') or []
            try:
                dp._process_event(adapter.llm_start(session_id, model=model, messages=messages,
                                                     max_tokens=kwargs.get('max_tokens'),
                                                     tools=tools))
            except Exception as pre_exc:
                from dapplepot_sdk import DapplePotBlockedError
                if isinstance(pre_exc, DapplePotBlockedError):
                    if standalone:
                        dp._buffer.flush_sync()
                    return None
                raise

            t0 = time.time()
            try:
                mgr = orig_stream(self_sdk, *args, **kwargs)
            except Exception as exc:
                latency_ms = int((time.time() - t0) * 1000)
                dp._process_event(adapter.llm_error(session_id, model=model,
                                                    error_type=type(exc).__name__,
                                                    error_message=str(exc),
                                                    latency_ms=latency_ms))
                if standalone:
                    dp._process_event(adapter.session_error(session_id,
                                                            error_type=type(exc).__name__,
                                                            error_message=str(exc)))
                raise

            def _on_stream_close(acc):
                latency_ms = int((time.time() - t0) * 1000)
                dp._process_event(adapter.llm_end(session_id, completion=acc.completion,
                                                  model=model,
                                                  finish_reason=acc.stop_reason,
                                                  usage=acc.usage_dict(),
                                                  latency_ms=latency_ms,
                                                  streamed=True))
                tool_uses = acc.collected_tool_uses()
                if tool_uses:
                    t_tool = time.time()
                    for tu in tool_uses:
                        tu_id = tu['id'] or str(uuid.uuid4())
                        tu_name = tu['name'] or 'unknown'
                        if session_id not in _pending_tools:
                            _pending_tools[session_id] = {}
                        _pending_tools[session_id][tu_id] = (tu_name, t_tool)
                        dp._process_event(
                            adapter.tool_start(session_id, tool_name=tu_name, tool_input=tu['input'])
                        )
                if standalone:
                    dp._process_event(adapter.session_end(session_id, output=acc.completion,
                                                           latency_ms=latency_ms))

            return _AnthropicMessageStreamManagerWrapper(mgr, _on_stream_close)

        _Messages.stream = patched_stream

    try:
        _AsyncMessages = _anthropic.resources.AsyncMessages
    except AttributeError:
        return
    orig_acreate = getattr(_AsyncMessages, 'create', None)
    if orig_acreate is None:
        return

    @functools.wraps(orig_acreate)
    async def patched_acreate(self_sdk, *args, **kwargs):
        dp = _get_client()
        if dp is None:
            return await orig_acreate(self_sdk, *args, **kwargs)

        session_id = get_current_session_id() or str(uuid.uuid4())
        adapter = dp._adapter('anthropic')

        standalone = get_current_session_id() is None
        model = kwargs.get('model', 'unknown')
        messages = kwargs.get('messages', [])

        _flush_tool_results(messages, session_id, dp, adapter)

        if standalone:
            sampled = dp._should_sample()
            dp._buffer.set_sampled(session_id, sampled)
            dp._process_event(adapter.session_start(session_id, input=first_user_text(messages)))

        tools = kwargs.get('tools') or []
        try:
            dp._process_event(adapter.llm_start(session_id, model=model, messages=messages,
                                                 max_tokens=kwargs.get('max_tokens'),
                                                 tools=tools))
        except Exception as pre_exc:
            from dapplepot_sdk import DapplePotBlockedError
            if isinstance(pre_exc, DapplePotBlockedError):
                if standalone:
                    dp._buffer.flush_sync()
                return None
            raise

        streaming = bool(kwargs.get('stream'))

        t0 = time.time()
        try:
            response = await orig_acreate(self_sdk, *args, **kwargs)
        except Exception as exc:
            latency_ms = int((time.time() - t0) * 1000)
            dp._process_event(adapter.llm_error(session_id, model=model,
                                                error_type=type(exc).__name__,
                                                error_message=str(exc),
                                                latency_ms=latency_ms))
            if standalone:
                dp._process_event(adapter.session_error(session_id,
                                                        error_type=type(exc).__name__,
                                                        error_message=str(exc)))
            raise

        if streaming:
            def _on_stream_close(acc):
                latency_ms = int((time.time() - t0) * 1000)
                dp._process_event(adapter.llm_end(session_id, completion=acc.completion,
                                                  model=model,
                                                  finish_reason=acc.stop_reason,
                                                  usage=acc.usage_dict(),
                                                  latency_ms=latency_ms,
                                                  streamed=True))
                tool_uses = acc.collected_tool_uses()
                if tool_uses:
                    t_tool = time.time()
                    for tu in tool_uses:
                        tu_id = tu['id'] or str(uuid.uuid4())
                        tu_name = tu['name'] or 'unknown'
                        if session_id not in _pending_tools:
                            _pending_tools[session_id] = {}
                        _pending_tools[session_id][tu_id] = (tu_name, t_tool)
                        dp._process_event(
                            adapter.tool_start(session_id, tool_name=tu_name, tool_input=tu['input'])
                        )
                if standalone:
                    dp._process_event(adapter.session_end(session_id, output=acc.completion,
                                                           latency_ms=latency_ms))
            return _AnthropicAsyncTracingStream(response, _on_stream_close)

        latency_ms = int((time.time() - t0) * 1000)
        content = response.content
        completion = ''
        if content:
            for block in content:
                if hasattr(block, 'text'):
                    completion += block.text

        usage_obj = getattr(response, 'usage', None)
        usage = None
        if usage_obj:
            usage = {
                'prompt_tokens': getattr(usage_obj, 'input_tokens', None),
                'completion_tokens': getattr(usage_obj, 'output_tokens', None),
            }

        dp._process_event(adapter.llm_end(session_id, completion=completion,
                                          model=model,
                                          finish_reason=getattr(response, 'stop_reason', None),
                                          usage=usage,
                                          latency_ms=latency_ms))

        if content:
            t_tool = time.time()
            for block in content:
                if getattr(block, 'type', None) == 'tool_use':
                    if session_id not in _pending_tools:
                        _pending_tools[session_id] = {}
                    _pending_tools[session_id][block.id] = (block.name, t_tool)
                    dp._process_event(
                        adapter.tool_start(
                            session_id,
                            tool_name=block.name,
                            tool_input=getattr(block, 'input', None),
                        )
                    )

        if standalone:
            dp._process_event(adapter.session_end(session_id, output=completion,
                                                   latency_ms=latency_ms))
        return response

    _AsyncMessages.create = patched_acreate

    orig_astream = getattr(_AsyncMessages, 'stream', None)
    if orig_astream is not None:
        @functools.wraps(orig_astream)
        def patched_astream(self_sdk, *args, **kwargs):
            # Note: messages.stream() (sync OR async) is itself a regular
            # function that returns a (Async)MessageStreamManager. It is NOT
            # awaitable — the user does `async with client.messages.stream(...)
            # as stream:` directly. So patched_astream is `def`, not `async def`.
            dp = _get_client()
            if dp is None:
                return orig_astream(self_sdk, *args, **kwargs)

            session_id = get_current_session_id() or str(uuid.uuid4())
            adapter = dp._adapter('anthropic')

            standalone = get_current_session_id() is None
            model = kwargs.get('model', 'unknown')
            messages = kwargs.get('messages', [])

            _flush_tool_results(messages, session_id, dp, adapter)

            if standalone:
                sampled = dp._should_sample()
                dp._buffer.set_sampled(session_id, sampled)
                dp._process_event(adapter.session_start(session_id, input=first_user_text(messages)))

            tools = kwargs.get('tools') or []
            try:
                dp._process_event(adapter.llm_start(session_id, model=model, messages=messages,
                                                     max_tokens=kwargs.get('max_tokens'),
                                                     tools=tools))
            except Exception as pre_exc:
                from dapplepot_sdk import DapplePotBlockedError
                if isinstance(pre_exc, DapplePotBlockedError):
                    if standalone:
                        dp._buffer.flush_sync()
                    return None
                raise

            t0 = time.time()
            try:
                mgr = orig_astream(self_sdk, *args, **kwargs)
            except Exception as exc:
                latency_ms = int((time.time() - t0) * 1000)
                dp._process_event(adapter.llm_error(session_id, model=model,
                                                    error_type=type(exc).__name__,
                                                    error_message=str(exc),
                                                    latency_ms=latency_ms))
                if standalone:
                    dp._process_event(adapter.session_error(session_id,
                                                            error_type=type(exc).__name__,
                                                            error_message=str(exc)))
                raise

            def _on_stream_close(acc):
                latency_ms = int((time.time() - t0) * 1000)
                dp._process_event(adapter.llm_end(session_id, completion=acc.completion,
                                                  model=model,
                                                  finish_reason=acc.stop_reason,
                                                  usage=acc.usage_dict(),
                                                  latency_ms=latency_ms,
                                                  streamed=True))
                tool_uses = acc.collected_tool_uses()
                if tool_uses:
                    t_tool = time.time()
                    for tu in tool_uses:
                        tu_id = tu['id'] or str(uuid.uuid4())
                        tu_name = tu['name'] or 'unknown'
                        if session_id not in _pending_tools:
                            _pending_tools[session_id] = {}
                        _pending_tools[session_id][tu_id] = (tu_name, t_tool)
                        dp._process_event(
                            adapter.tool_start(session_id, tool_name=tu_name, tool_input=tu['input'])
                        )
                if standalone:
                    dp._process_event(adapter.session_end(session_id, output=acc.completion,
                                                           latency_ms=latency_ms))

            return _AnthropicAsyncMessageStreamManagerWrapper(mgr, _on_stream_close)

        _AsyncMessages.stream = patched_astream


