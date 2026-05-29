"""
Drop-in replacement for the Anthropic SDK.

    from dapplepot_sdk.anthropic import anthropic

All anthropic.* calls work identically but are traced per session via
dp.session() context manager or, when used outside one, as individual sessions.

Tool calls are traced automatically — no client code required:
  - tool_start is emitted when the model returns a tool_use block
  - tool_end   is emitted when the next messages.create() carries the matching tool_result
"""

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


