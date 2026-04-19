"""
Drop-in replacement for the Anthropic SDK.

    from dapplepot_sdk.anthropic import anthropic

All anthropic.* calls work identically but are traced per session via
dp.session() context manager or, when used outside one, as individual sessions.
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

_client_ref = None


def _get_client():
    return _client_ref


def _patch(client) -> None:
    global _client_ref
    _client_ref = client

    orig_create = _anthropic.Anthropic.messages.create if hasattr(_anthropic, 'Anthropic') else None
    if orig_create is None:
        logger.warning('Could not patch anthropic.Anthropic.messages.create')
        return

    @functools.wraps(orig_create)
    def patched_create(self_sdk, *args, **kwargs):
        dp = _get_client()
        if dp is None:
            return orig_create(self_sdk, *args, **kwargs)

        session_id = get_current_session_id() or str(uuid.uuid4())
        adapter = dp._adapter('anthropic')

        standalone = get_current_session_id() is None
        if standalone:
            sampled = dp._should_sample()
            dp._buffer.set_sampled(session_id, sampled)
            dp._process_event(adapter.session_start(session_id))

        model = kwargs.get('model', 'unknown')
        messages = kwargs.get('messages', [])
        dp._process_event(adapter.llm_start(session_id, model=model, messages=messages,
                                             max_tokens=kwargs.get('max_tokens')))
        t0 = time.time()
        try:
            response = orig_create(self_sdk, *args, **kwargs)
        except Exception as exc:
            dp._process_event(adapter.session_error(session_id,
                                                    error_type=type(exc).__name__,
                                                    error_message=str(exc)))
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
                                          finish_reason=getattr(response, 'stop_reason', None),
                                          usage=usage))
        if standalone:
            dp._process_event(adapter.session_end(session_id, output=completion,
                                                   latency_ms=latency_ms))
        return response

    _anthropic.Anthropic.messages.create = patched_create


class _AnthropicProxy:
    def __getattr__(self, name):
        return getattr(_anthropic, name)


anthropic = _AnthropicProxy()
