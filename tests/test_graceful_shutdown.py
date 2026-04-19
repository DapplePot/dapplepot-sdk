"""test_graceful_shutdown — buffer flush on shutdown, no lost events."""

import queue
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from dapplepot_sdk.buffer import EventBuffer


def _make_buf():
    buf = EventBuffer.__new__(EventBuffer)
    buf._url = 'http://localhost:9000/events'
    buf._sdk_key = 'test'
    buf._interval = 0.5
    buf._batch_size = 100
    buf._queue = queue.Queue()
    buf._session_samples = {}
    buf._stop = threading.Event()
    buf._thread = MagicMock()
    return buf


class TestGracefulShutdown(unittest.TestCase):

    def test_shutdown_flushes_remaining_events(self):
        buf = _make_buf()
        flushed = []

        def fake_send(batch, retries=3):
            flushed.extend(batch)

        buf._send = fake_send
        for i in range(10):
            buf._queue.put({'dp_event_type': 'llm_end', 'i': i})

        buf.shutdown(timeout_ms=2000)
        self.assertEqual(len(flushed), 10)

    def test_shutdown_no_events_is_clean(self):
        buf = _make_buf()
        buf._send = MagicMock()
        buf.shutdown(timeout_ms=500)
        # No exception means success

    def test_shutdown_sets_stop_flag(self):
        buf = _make_buf()
        buf._send = MagicMock()
        buf.shutdown(timeout_ms=200)
        self.assertTrue(buf._stop.is_set())

    def test_push_sync_sends_immediately(self):
        sent = []
        buf = _make_buf()
        buf._send = lambda batch, **kw: sent.extend(batch)
        event = {'dp_event_type': 'security_finding', 'dp_session_id': 's1'}
        buf.push_sync(event)
        self.assertIn(event, sent)

    def test_atexit_pattern(self):
        import atexit
        dp_mock = MagicMock()
        atexit.register(dp_mock.shutdown)
        # Just verifying the atexit pattern works without error


if __name__ == '__main__':
    unittest.main()
