"""test_sampling — validates sample_rate=0.0, 0.5, 1.0 and per-session consistency."""

import unittest
from unittest.mock import MagicMock

from dapplepot_sdk.buffer import EventBuffer


def _make_buffer(ingest_url='http://localhost:9000', sdk_key='test'):
    buf = EventBuffer.__new__(EventBuffer)
    buf._url = ingest_url
    buf._sdk_key = sdk_key
    buf._interval = 0.5
    buf._batch_size = 100
    import queue, threading
    buf._queue = queue.Queue()
    buf._session_samples = {}
    buf._stop = threading.Event()
    buf._thread = MagicMock()
    return buf


class TestSampling(unittest.TestCase):

    def test_rate_zero_drops_all(self):
        buf = _make_buffer()
        buf.set_sampled('s1', False)
        buf.push({'dp_session_id': 's1', 'dp_event_type': 'session_start'})
        self.assertTrue(buf._queue.empty())

    def test_rate_one_keeps_all(self):
        buf = _make_buffer()
        buf.set_sampled('s2', True)
        buf.push({'dp_session_id': 's2', 'dp_event_type': 'session_start'})
        self.assertEqual(buf._queue.qsize(), 1)

    def test_per_session_consistency(self):
        buf = _make_buffer()
        # sampled session
        buf.set_sampled('sampled', True)
        for _ in range(5):
            buf.push({'dp_session_id': 'sampled', 'dp_event_type': 'llm_start'})
        # unsampled session
        buf.set_sampled('dropped', False)
        for _ in range(5):
            buf.push({'dp_session_id': 'dropped', 'dp_event_type': 'llm_start'})

        self.assertEqual(buf._queue.qsize(), 5)
        while not buf._queue.empty():
            e = buf._queue.get()
            self.assertEqual(e['dp_session_id'], 'sampled')

    def test_no_session_id_passes(self):
        buf = _make_buffer()
        buf.push({'dp_event_type': 'unknown'})
        self.assertEqual(buf._queue.qsize(), 1)

    def test_dp_sample_rate_integration(self):
        from dapplepot_sdk import DapplePot
        dp = DapplePot.__new__(DapplePot)
        dp._sample_rate = 0.0
        for _ in range(100):
            self.assertFalse(dp._should_sample())

        dp._sample_rate = 1.0
        for _ in range(100):
            self.assertTrue(dp._should_sample())

    def test_dp_sample_rate_half(self):
        import random
        from dapplepot_sdk import DapplePot
        dp = DapplePot.__new__(DapplePot)
        dp._sample_rate = 0.5
        random.seed(0)
        results = [dp._should_sample() for _ in range(1000)]
        ratio = sum(results) / len(results)
        self.assertAlmostEqual(ratio, 0.5, delta=0.1)


if __name__ == '__main__':
    unittest.main()
