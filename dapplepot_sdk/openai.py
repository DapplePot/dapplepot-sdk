"""
Drop-in replacement for the OpenAI SDK.

    from dapplepot_sdk.openai import openai

All openai.* calls work identically but are traced per session via
dp.session() context manager or, when used outside one, as individual sessions.
"""

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


def _get_client():
    return _client_ref


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

        model = kwargs.get('model', 'unknown')
        messages = kwargs.get('messages', [])
        if get_current_session_id() is None:
            sampled = dp._should_sample()
            dp._buffer.set_sampled(session_id, sampled)
            dp._process_event(adapter.session_start(session_id, input=first_user_text(messages)))
        dp._process_event(adapter.llm_start(session_id, model=model, messages=messages,
                                             temperature=kwargs.get('temperature'),
                                             max_tokens=kwargs.get('max_tokens')))
        t0 = time.time()
        try:
            response = orig_create(*args, **kwargs)
        except Exception as exc:
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
                                          finish_reason=finish_reason, usage=usage))
        if get_current_session_id() is None:
            dp._process_event(adapter.session_end(session_id, output=completion,
                                                   latency_ms=latency_ms))
        return response

    _openai.chat.completions.create = patched_create


class _OpenAIProxy:
    """Transparent proxy; attribute access falls through to the real openai module."""
    def __getattr__(self, name):
        return getattr(_openai, name)


openai = _OpenAIProxy()
