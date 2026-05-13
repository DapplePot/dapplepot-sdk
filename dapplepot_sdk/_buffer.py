import atexit
import json
import queue
import threading
import time
import logging

import requests

logger = logging.getLogger(__name__)


class _SafeEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'model_dump'):
            return obj.model_dump()
        if hasattr(obj, 'dict'):
            return obj.dict()
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return repr(obj)


class EventBuffer:
    def __init__(self, ingest_url: str, sdk_key: str,
                 flush_interval_ms: int = 500, flush_batch_size: int = 100):
        self._url = ingest_url.rstrip('/') + '/v1/ingest/events'
        self._sdk_key = sdk_key
        self._interval = flush_interval_ms / 1000.0
        self._batch_size = flush_batch_size
        self._queue: queue.Queue = queue.Queue()
        self._session_samples: dict = {}
        self._session_seqs: dict = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name='telemetry')
        self._thread.start()
        # Flush remaining events on normal process exit so the daemon thread
        # dying at interpreter shutdown doesn't silently drop buffered events.
        atexit.register(self.shutdown)

    # ── sampling ──────────────────────────────────────────────────────────────

    def set_sampled(self, session_id: str, sampled: bool) -> None:
        self._session_samples[session_id] = sampled

    def is_sampled(self, session_id: str) -> bool:
        return self._session_samples.get(session_id, True)

    # ── push ──────────────────────────────────────────────────────────────────

    def push(self, event: dict) -> None:
        sid = event.get('dp_session_id')
        if sid and not self.is_sampled(sid):
            return
        # Stamp a monotonic per-session sequence_index for SDK paths that don't
        # set one (openai, anthropic, session.py). LangChain sets it in _emit()
        # before calling here, so we leave those events unchanged.
        if 'sequence_index' not in event and sid:
            n = self._session_seqs.get(sid, 0)
            self._session_seqs[sid] = n + 1
            event = {**event, 'sequence_index': n}
        self._queue.put(event)

    def push_sync(self, event: dict) -> None:
        """Flush a single event immediately (used before raising a blocked error)."""
        self._send([event])

    def flush_sync(self) -> None:
        """Drain all queued events immediately on the calling thread.
        Safe to call after shutdown() — push() always enqueues regardless of stop state."""
        self._drain()

    # ── flush loop ────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(self._interval)
            self._drain()

    def _drain(self) -> None:
        batch = []
        try:
            while len(batch) < self._batch_size:
                batch.append(self._queue.get_nowait())
        except queue.Empty:
            pass
        if batch:
            self._send(batch)

    def _send(self, batch: list, retries: int = 3) -> None:
        for attempt in range(retries):
            try:
                resp = requests.post(
                    self._url,
                    data=json.dumps({'events': batch}, cls=_SafeEncoder),
                    headers={
                        'Authorization': f'Bearer {self._sdk_key}',
                        'Content-Type': 'application/json',
                    },
                    timeout=5,
                )
                resp.raise_for_status()
                return
            except Exception as exc:
                if attempt == retries - 1:
                    logger.error('event flush failed after %d retries: %s', retries, exc)
                else:
                    time.sleep(0.1 * (2 ** attempt))

    # ── shutdown ──────────────────────────────────────────────────────────────

    def shutdown(self, timeout_ms: int = 5000) -> None:
        self._stop.set()
        self._thread.join(timeout=timeout_ms / 1000.0)
        self._drain()
