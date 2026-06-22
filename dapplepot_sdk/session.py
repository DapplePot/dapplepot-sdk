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

        last_seq = self._client._fetch_session_last_seq(self._session_id)
        if last_seq == -1:
            from dapplepot_sdk import DapplePotSessionTerminatedError
            raise DapplePotSessionTerminatedError('Session permanently terminated by security policy')
        if last_seq is not None:
            self._client._buffer.set_session_seq(self._session_id, last_seq + 1)

        framework = getattr(self._client, '_framework', 'unknown')
        event = self._client._adapter(framework).session_start(
            self._session_id,
            user_context_id=self._user_context_id,
            user_tenant_id=self._user_tenant_id,
        )
        self._client._process_event(event)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        from dapplepot_sdk import DapplePotSessionTerminatedError, DapplePotBlockedError
        latency_ms = int((time.time() - self._t0) * 1000) if self._t0 else None
        framework = getattr(self._client, '_framework', 'unknown')
        if exc_type:
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

        self._client._buffer.flush_sync()
        if not (exc_type and issubclass(exc_type, DapplePotSessionTerminatedError)):
            last_seq = self._client._buffer.get_session_last_seq(self._session_id)
            if last_seq is not None:
                self._client._store_session_last_seq(self._session_id, last_seq)

        _local.session_id = None
        return False
