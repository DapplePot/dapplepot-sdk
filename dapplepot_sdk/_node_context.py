import time


class NodeContext:
    """Context manager returned by dp.node(). Emits node_start / node_end / node_error."""

    def __init__(self, client, session_id: str | None, node_name: str, input=None):
        """Args mirror :meth:`dapplepot_sdk.DapplePot.node`, plus the resolved session_id."""
        self._client = client
        self._session_id = session_id
        self._node_name = node_name
        self._input = input
        self._t0 = None

    def __enter__(self):
        """Start timing the node and emit node_start."""
        self._t0 = time.time()
        framework = getattr(self._client, '_framework', 'unknown')
        self._client._process_event(
            self._client._adapter(framework).node_start(
                self._session_id, node_name=self._node_name, input=self._input
            )
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop timing the node and emit node_end or node_error."""
        latency_ms = int((time.time() - self._t0) * 1000) if self._t0 else None
        framework = getattr(self._client, '_framework', 'unknown')
        adapter = self._client._adapter(framework)
        if exc_type:
            self._client._process_event(
                adapter.node_error(
                    self._session_id,
                    node_name=self._node_name,
                    error_type=type(exc_val).__name__,
                    error_message=str(exc_val),
                )
            )
        else:
            self._client._process_event(
                adapter.node_end(
                    self._session_id, node_name=self._node_name, latency_ms=latency_ms
                )
            )
        return False
