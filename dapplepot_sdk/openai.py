"""
OpenAI SDK patcher for DapplePot.

Activate with dp.instrument_openai() after initialising DapplePot.
Import openai directly as normal — no proxy, no coupling to DapplePot releases.

Tool calls are traced automatically — no client code required:
  - tool_start is emitted when the model returns tool_calls in the response
  - tool_end   is emitted when the next chat.completions.create() carries role="tool" messages
"""

import json
import time
import uuid
import functools
import logging

logger = logging.getLogger(__name__)

try:
    import openai as _openai
except ImportError:
    raise ImportError("openai not installed. Run: pip install openai")

from dapplepot_sdk.session import get_current_session_id
from dapplepot_sdk._adapter import first_user_text

_client_ref = None

# {session_id: {tool_call_id: (tool_name, start_time)}}
_pending_tools: dict[str, dict[str, tuple[str, float]]] = {}


def _get_client():
    """Return the DapplePot client this module was patched with, if any."""
    return _client_ref


def _flush_tool_results(messages: list, session_id: str, dp, adapter) -> None:
    """
    Scan incoming messages for role='tool' entries and emit tool_end (or tool_error
    when is_error=True) for each one that has a matching pending tool_start.

    is_error is a DapplePot convention — set it on the tool message when the tool
    execution failed so DapplePot emits tool_error instead of tool_end.
    """
    pending = _pending_tools.get(session_id)
    if not pending:
        return
    for msg in messages:
        if not isinstance(msg, dict) or msg.get('role') != 'tool':
            continue
        tool_call_id = msg.get('tool_call_id', '')
        if tool_call_id not in pending:
            continue
        tool_name, t_start = pending.pop(tool_call_id)
        latency_ms = int((time.time() - t_start) * 1000)
        output = str(msg.get('content', ''))
        if msg.get('is_error'):
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


class _OpenAIStreamAccumulator:
    """Folds OpenAI ChatCompletionChunk deltas into the same shape the
    non-streaming response carries — content, tool_calls, finish_reason, usage.

    Tool-call deltas arrive in pieces: a `ChoiceDeltaToolCall` may carry an `id`
    only on its first chunk, a `function.name` only on its first chunk, and
    `function.arguments` as a string fragment on every subsequent chunk. We key
    by `index` (the tool slot, not the call id) and concatenate.
    """

    def __init__(self):
        self.completion: str = ''
        self.tool_calls: dict = {}  # index -> {id, name, arguments}
        self.usage = None
        self.finish_reason = None

    def absorb(self, chunk) -> None:
        """Fold one streamed chunk into the accumulator's running state."""
        choices = getattr(chunk, 'choices', None) or []
        if choices:
            choice = choices[0]
            delta = getattr(choice, 'delta', None)
            if delta is not None:
                content = getattr(delta, 'content', None)
                if content:
                    self.completion += content
                tcs = getattr(delta, 'tool_calls', None) or []
                for tc in tcs:
                    idx = getattr(tc, 'index', 0)
                    slot = self.tool_calls.setdefault(idx, {'id': '', 'name': '', 'arguments': ''})
                    tc_id = getattr(tc, 'id', None)
                    if tc_id:
                        slot['id'] = tc_id
                    fn = getattr(tc, 'function', None)
                    if fn is not None:
                        fn_name = getattr(fn, 'name', None)
                        if fn_name:
                            slot['name'] = fn_name
                        fn_args = getattr(fn, 'arguments', None)
                        if fn_args:
                            slot['arguments'] += fn_args
            fr = getattr(choice, 'finish_reason', None)
            if fr:
                self.finish_reason = fr
        # Usage typically rides on the terminal chunk when stream_options
        # {'include_usage': True} is set; the chunk has no choices in that case.
        u = getattr(chunk, 'usage', None)
        if u:
            self.usage = u

    def usage_dict(self):
        """Return the accumulated token usage, or None if none was observed."""
        if self.usage is None:
            return None
        return {
            'prompt_tokens': getattr(self.usage, 'prompt_tokens', None),
            'completion_tokens': getattr(self.usage, 'completion_tokens', None),
        }

    def collected_tool_calls(self) -> list:
        """Return reassembled tool calls, ordered by their stream index."""
        return [self.tool_calls[k] for k in sorted(self.tool_calls.keys())]


class _TracingStream:
    """Sync wrapper around an OpenAI `Stream`. Forwards iteration and ctx-mgr
    protocol while absorbing each chunk into an accumulator. Calls `on_close`
    exactly once when iteration finishes (StopIteration), the context manager
    exits, or the object is garbage-collected — whichever happens first.
    """

    def __init__(self, stream, on_close):
        self._stream = stream
        self._acc = _OpenAIStreamAccumulator()
        self._on_close = on_close
        self._closed = False

    def __iter__(self):
        return self

    def __next__(self):
        try:
            chunk = next(self._stream)
        except StopIteration:
            self._close()
            raise
        try:
            self._acc.absorb(chunk)
        except Exception:
            logger.exception('DapplePot stream chunk absorption failed')
        return chunk

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
        """Fire on_close(accumulator) exactly once, however iteration ended."""
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


class _AsyncTracingStream:
    """Async mirror of `_TracingStream` — forwards `__aiter__` / `__anext__` and
    async context-manager protocol. `on_close` itself is synchronous (it only
    emits events into the DapplePot buffer), so no `await` inside `_close`.
    """

    def __init__(self, stream, on_close):
        self._stream = stream
        self._acc = _OpenAIStreamAccumulator()
        self._on_close = on_close
        self._closed = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            chunk = await self._stream.__anext__()
        except StopAsyncIteration:
            self._close()
            raise
        try:
            self._acc.absorb(chunk)
        except Exception:
            logger.exception('DapplePot stream chunk absorption failed')
        return chunk

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
        """Fire on_close(accumulator) exactly once, however iteration ended."""
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


def _patch(client) -> None:
    """Monkey-patch ``openai`` chat completions to emit trace events.

    Called by :meth:`dapplepot_sdk.DapplePot.instrument_openai`. Patches
    the ``Completions`` class (not the lazy module-level proxy — see
    inline note below) so every ``chat.completions.create()`` call, sync
    or async, streaming or not, emits ``llm_start``/``llm_end``/
    ``llm_error`` (and ``tool_start``/``tool_end`` for tool calls), via the
    stream accumulator/wrapper classes above. Safe to call more than once.
    """
    global _client_ref
    _client_ref = client

    # Patch the Completions class directly. Every openai.OpenAI() instance
    # routes through this method, and patching the class avoids the lazy
    # module-level proxy on `openai.chat.completions`, which requires
    # OPENAI_API_KEY in env even when the caller passes api_key= explicitly.
    try:
        from openai.resources.chat.completions import Completions
    except ImportError:
        Completions = None

    if Completions is None:
        logger.warning('Could not find openai.resources.chat.completions.Completions to patch')
        return

    orig_create = Completions.create

    @functools.wraps(orig_create)
    def patched_create(self_sdk, *args, **kwargs):
        dp = _get_client()
        if dp is None:
            return orig_create(self_sdk, *args, **kwargs)

        session_id = get_current_session_id() or str(uuid.uuid4())
        adapter = dp._adapter('openai')

        standalone = get_current_session_id() is None
        model = kwargs.get('model', 'unknown')
        messages = kwargs.get('messages', [])

        # Auto-emit tool_end for any role="tool" messages in the incoming messages
        _flush_tool_results(messages, session_id, dp, adapter)

        if standalone:
            sampled = dp._should_sample()
            dp._buffer.set_sampled(session_id, sampled)
            dp._process_event(adapter.session_start(session_id, input=first_user_text(messages)))

        tools = kwargs.get('tools') or []
        dp._process_event(adapter.llm_start(session_id, model=model, messages=messages,
                                             temperature=kwargs.get('temperature'),
                                             max_tokens=kwargs.get('max_tokens'),
                                             tools=tools))

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
                # In standalone mode there is no dp.session() to emit session_error
                dp._process_event(adapter.session_error(session_id,
                                                        error_type=type(exc).__name__,
                                                        error_message=str(exc)))
            raise

        if streaming:
            def _on_stream_close(acc):
                latency_ms = int((time.time() - t0) * 1000)
                dp._process_event(adapter.llm_end(session_id, completion=acc.completion,
                                                  model=model,
                                                  finish_reason=acc.finish_reason,
                                                  usage=acc.usage_dict(),
                                                  latency_ms=latency_ms,
                                                  streamed=True))
                tool_calls = acc.collected_tool_calls()
                if tool_calls:
                    t_tool = time.time()
                    for tc in tool_calls:
                        tc_id = tc['id'] or str(uuid.uuid4())
                        tc_name = tc['name'] or 'unknown'
                        try:
                            tc_input = json.loads(tc['arguments'] or '{}')
                        except (json.JSONDecodeError, TypeError):
                            tc_input = tc['arguments']
                        if session_id not in _pending_tools:
                            _pending_tools[session_id] = {}
                        _pending_tools[session_id][tc_id] = (tc_name, t_tool)
                        dp._process_event(
                            adapter.tool_start(session_id, tool_name=tc_name, tool_input=tc_input)
                        )
                if standalone:
                    dp._process_event(adapter.session_end(session_id, output=acc.completion,
                                                           latency_ms=latency_ms))
            return _TracingStream(response, _on_stream_close)

        latency_ms = int((time.time() - t0) * 1000)
        completion = ''
        finish_reason = None
        usage = None
        choices = getattr(response, 'choices', [])
        if choices:
            msg = getattr(choices[0], 'message', None)
            completion = getattr(msg, 'content', '') or ''
            finish_reason = getattr(choices[0], 'finish_reason', None)
        usage_obj = getattr(response, 'usage', None)
        if usage_obj:
            usage = {
                'prompt_tokens': getattr(usage_obj, 'prompt_tokens', None),
                'completion_tokens': getattr(usage_obj, 'completion_tokens', None),
            }
        dp._process_event(adapter.llm_end(session_id, completion=completion,
                                          model=model,
                                          finish_reason=finish_reason, usage=usage,
                                          latency_ms=latency_ms))

        # Auto-emit tool_start for each tool_call in the response
        if choices:
            tool_calls = getattr(getattr(choices[0], 'message', None), 'tool_calls', None)
            if tool_calls:
                t_tool = time.time()
                for tc in tool_calls:
                    tc_id = getattr(tc, 'id', str(uuid.uuid4()))
                    fn = getattr(tc, 'function', None)
                    tc_name = getattr(fn, 'name', 'unknown')
                    tc_args = getattr(fn, 'arguments', '{}')
                    try:
                        tc_input = json.loads(tc_args)
                    except (json.JSONDecodeError, TypeError):
                        tc_input = tc_args
                    if session_id not in _pending_tools:
                        _pending_tools[session_id] = {}
                    _pending_tools[session_id][tc_id] = (tc_name, t_tool)
                    dp._process_event(
                        adapter.tool_start(session_id, tool_name=tc_name, tool_input=tc_input)
                    )

        if standalone:
            dp._process_event(adapter.session_end(session_id, output=completion,
                                                   latency_ms=latency_ms))
        return response

    Completions.create = patched_create

    try:
        from openai.resources.chat.completions import AsyncCompletions
    except ImportError:
        AsyncCompletions = None

    if AsyncCompletions is None:
        return

    orig_acreate = AsyncCompletions.create

    @functools.wraps(orig_acreate)
    async def patched_acreate(self_sdk, *args, **kwargs):
        dp = _get_client()
        if dp is None:
            return await orig_acreate(self_sdk, *args, **kwargs)

        session_id = get_current_session_id() or str(uuid.uuid4())
        adapter = dp._adapter('openai')

        standalone = get_current_session_id() is None
        model = kwargs.get('model', 'unknown')
        messages = kwargs.get('messages', [])

        _flush_tool_results(messages, session_id, dp, adapter)

        if standalone:
            sampled = dp._should_sample()
            dp._buffer.set_sampled(session_id, sampled)
            dp._process_event(adapter.session_start(session_id, input=first_user_text(messages)))

        tools = kwargs.get('tools') or []
        dp._process_event(adapter.llm_start(session_id, model=model, messages=messages,
                                             temperature=kwargs.get('temperature'),
                                             max_tokens=kwargs.get('max_tokens'),
                                             tools=tools))

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
                                                  finish_reason=acc.finish_reason,
                                                  usage=acc.usage_dict(),
                                                  latency_ms=latency_ms,
                                                  streamed=True))
                tool_calls = acc.collected_tool_calls()
                if tool_calls:
                    t_tool = time.time()
                    for tc in tool_calls:
                        tc_id = tc['id'] or str(uuid.uuid4())
                        tc_name = tc['name'] or 'unknown'
                        try:
                            tc_input = json.loads(tc['arguments'] or '{}')
                        except (json.JSONDecodeError, TypeError):
                            tc_input = tc['arguments']
                        if session_id not in _pending_tools:
                            _pending_tools[session_id] = {}
                        _pending_tools[session_id][tc_id] = (tc_name, t_tool)
                        dp._process_event(
                            adapter.tool_start(session_id, tool_name=tc_name, tool_input=tc_input)
                        )
                if standalone:
                    dp._process_event(adapter.session_end(session_id, output=acc.completion,
                                                           latency_ms=latency_ms))
            return _AsyncTracingStream(response, _on_stream_close)

        latency_ms = int((time.time() - t0) * 1000)
        completion = ''
        finish_reason = None
        usage = None
        choices = getattr(response, 'choices', [])
        if choices:
            msg = getattr(choices[0], 'message', None)
            completion = getattr(msg, 'content', '') or ''
            finish_reason = getattr(choices[0], 'finish_reason', None)
        usage_obj = getattr(response, 'usage', None)
        if usage_obj:
            usage = {
                'prompt_tokens': getattr(usage_obj, 'prompt_tokens', None),
                'completion_tokens': getattr(usage_obj, 'completion_tokens', None),
            }
        dp._process_event(adapter.llm_end(session_id, completion=completion,
                                          model=model,
                                          finish_reason=finish_reason, usage=usage,
                                          latency_ms=latency_ms))

        if choices:
            tool_calls = getattr(getattr(choices[0], 'message', None), 'tool_calls', None)
            if tool_calls:
                t_tool = time.time()
                for tc in tool_calls:
                    tc_id = getattr(tc, 'id', str(uuid.uuid4()))
                    fn = getattr(tc, 'function', None)
                    tc_name = getattr(fn, 'name', 'unknown')
                    tc_args = getattr(fn, 'arguments', '{}')
                    try:
                        tc_input = json.loads(tc_args)
                    except (json.JSONDecodeError, TypeError):
                        tc_input = tc_args
                    if session_id not in _pending_tools:
                        _pending_tools[session_id] = {}
                    _pending_tools[session_id][tc_id] = (tc_name, t_tool)
                    dp._process_event(
                        adapter.tool_start(session_id, tool_name=tc_name, tool_input=tc_input)
                    )

        if standalone:
            dp._process_event(adapter.session_end(session_id, output=completion,
                                                   latency_ms=latency_ms))
        return response

    AsyncCompletions.create = patched_acreate
