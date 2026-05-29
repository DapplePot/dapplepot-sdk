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


def _patch(client) -> None:
    global _client_ref
    _client_ref = client

    orig_create = _openai.chat.completions.create

    @functools.wraps(orig_create)
    def patched_create(*args, **kwargs):
        dp = _get_client()
        if dp is None:
            return orig_create(*args, **kwargs)

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

        t0 = time.time()
        try:
            response = orig_create(*args, **kwargs)
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

    _openai.chat.completions.create = patched_create
