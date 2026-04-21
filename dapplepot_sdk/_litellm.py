import time
import uuid
import logging

logger = logging.getLogger(__name__)


def register(client) -> None:
    try:
        import litellm
    except ImportError:
        raise ImportError("litellm not installed. Run: pip install 'dapplepot-sdk[litellm]'")

    handler = _DapplePotLiteLLMHandler(client)
    litellm.success_callback = [handler.on_success]
    litellm.failure_callback = [handler.on_failure]
    logger.debug('LiteLLM callbacks registered')


class _DapplePotLiteLLMHandler:
    def __init__(self, client):
        self._client = client
        self._adapter = client._adapter('litellm')

    def on_success(self, kwargs, response_obj, start_time, end_time) -> None:
        session_id = str(kwargs.get('litellm_call_id', uuid.uuid4()))
        sampled = self._client._should_sample()
        self._client._buffer.set_sampled(session_id, sampled)

        model = kwargs.get('model', 'unknown')
        messages = kwargs.get('messages', [])
        latency_ms = int((end_time - start_time).total_seconds() * 1000)

        self._client._process_event(self._adapter.session_start(session_id))
        self._client._process_event(
            self._adapter.llm_start(session_id, model=model, messages=messages)
        )

        completion = ''
        usage = None
        finish_reason = None
        if response_obj:
            choices = getattr(response_obj, 'choices', [])
            if choices:
                msg = getattr(choices[0], 'message', None)
                if msg:
                    completion = getattr(msg, 'content', '') or ''
                finish_reason = getattr(choices[0], 'finish_reason', None)
            usage_obj = getattr(response_obj, 'usage', None)
            if usage_obj:
                usage = {
                    'prompt_tokens': getattr(usage_obj, 'prompt_tokens', None),
                    'completion_tokens': getattr(usage_obj, 'completion_tokens', None),
                }

        self._client._process_event(
            self._adapter.llm_end(session_id, completion=completion,
                                  finish_reason=finish_reason, usage=usage)
        )
        self._client._process_event(
            self._adapter.session_end(session_id, output=completion, latency_ms=latency_ms)
        )
        self._client._buffer.flush_sync()

    def on_failure(self, kwargs, response_obj, start_time, end_time) -> None:
        session_id = str(kwargs.get('litellm_call_id', uuid.uuid4()))
        sampled = self._client._should_sample()
        self._client._buffer.set_sampled(session_id, sampled)

        exc = kwargs.get('exception', Exception('unknown'))
        self._client._process_event(self._adapter.session_start(session_id))
        self._client._process_event(
            self._adapter.session_error(
                session_id,
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
        )
        self._client._buffer.flush_sync()
