import uuid
import time
import threading
import traceback as _tb

_local = threading.local()


def get_current_session_id() -> str | None:
    return getattr(_local, 'session_id', None)


class SessionContext:
    def __init__(self, client, session_id: str = None, user_context_id: str = None,
                 user_tenant_id: str = None):
        self._client = client
        self._session_id = session_id or str(uuid.uuid4())
        self._user_context_id = user_context_id
        self._user_tenant_id = user_tenant_id
        self._t0 = None

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def user_context_id(self) -> str | None:
        return self._user_context_id

    @property
    def user_tenant_id(self) -> str | None:
        return self._user_tenant_id

    def __enter__(self):
        self._t0 = time.time()
        sampled = self._client._should_sample()
        self._client._buffer.set_sampled(self._session_id, sampled)
        _local.session_id = self._session_id
        framework = getattr(self._client, '_framework', 'unknown')
        event = self._client._adapter(framework).session_start(
            self._session_id,
            user_context_id=self._user_context_id,
            user_tenant_id=self._user_tenant_id,
        )
        self._client._process_event(event)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        latency_ms = int((time.time() - self._t0) * 1000) if self._t0 else None
        framework = getattr(self._client, '_framework', 'unknown')
        if exc_type:
            from dapplepot_sdk import DapplePotSessionTerminatedError, DapplePotBlockedError
            if not issubclass(exc_type, (DapplePotSessionTerminatedError, DapplePotBlockedError)):
                err = self._client._adapter(framework).session_error(
                    self._session_id,
                    error_type=exc_type.__name__,
                    error_message=str(exc_val),
                    traceback=''.join(_tb.format_tb(exc_tb)),
                )
                self._client._process_event(err)
        else:
            end = self._client._adapter(framework).session_end(self._session_id, latency_ms=latency_ms)
            self._client._process_event(end)
        _local.session_id = None
        return False
