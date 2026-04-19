"""test_error_handling — span errors → session_error events, retry behaviour."""

import unittest
from unittest.mock import MagicMock, patch, call

from dapplepot_sdk.adapter import TraceAdapter
from dapplepot_sdk.buffer import EventBuffer


def _make_dp(captured):
    from dapplepot_sdk import DapplePot
    dp = DapplePot.__new__(DapplePot)
    dp._tenant_id = 'test'
    dp._agent_id = 'test'
    dp._sdk_key = 'test'
    dp._ingest_url = 'http://localhost'
    dp._sample_rate = 1.0
    dp._online_action = 'warn'
    dp._pii_scrubber = None
    dp._redact_keys = set()
    dp._tool_allowlist = None
    buf = MagicMock()
    buf.is_sampled.return_value = True
    buf.push.side_effect = captured.append
    from dapplepot_sdk.interceptor import OnlineCheckInterceptor
    dp._interceptor = OnlineCheckInterceptor([], 'warn', buf, dp)
    dp._buffer = buf
    return dp


class TestErrorEvents(unittest.TestCase):

    def test_session_error_event_emitted(self):
        captured = []
        dp = _make_dp(captured)
        adapter = dp._adapter('langchain')
        sid = 'err-session-1'
        dp._process_event(adapter.session_error(sid, error_type='ValueError', error_message='bad'))
        self.assertEqual(captured[0]['dp_event_type'], 'session_error')
        self.assertEqual(captured[0]['payload']['error_type'], 'ValueError')

    def test_node_error_event_emitted(self):
        captured = []
        dp = _make_dp(captured)
        adapter = dp._adapter('langchain')
        sid = 'err-session-2'
        dp._process_event(adapter.node_error(sid, node_name='llm', error_type='TimeoutError', error_message='timed out'))
        self.assertEqual(captured[0]['dp_event_type'], 'node_error')
        self.assertEqual(captured[0]['payload']['node_name'], 'llm')

    def test_session_context_manager_emits_error_on_exception(self):
        captured = []
        dp = _make_dp(captured)
        dp._buffer.set_sampled = MagicMock()
        from dapplepot_sdk.session import SessionContext

        try:
            with SessionContext(dp, session_id='ctx-err-1'):
                raise RuntimeError('boom')
        except RuntimeError:
            pass

        types = [e['dp_event_type'] for e in captured]
        self.assertIn('session_error', types)
        self.assertIn('session_end', types)


class TestBufferRetry(unittest.TestCase):

    def test_retry_on_http_error(self):
        import requests
        buf = EventBuffer.__new__(EventBuffer)
        buf._url = 'http://localhost:9999/events'
        buf._sdk_key = 'test'
        buf._interval = 0.5
        buf._batch_size = 100

        call_count = [0]

        def fake_post(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] < 3:
                raise requests.ConnectionError('refused')
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            return resp

        with patch('requests.post', side_effect=fake_post):
            with patch('time.sleep'):
                buf._send([{'dp_event_type': 'session_start'}], retries=3)

        self.assertEqual(call_count[0], 3)

    def test_drops_after_max_retries(self):
        import requests
        buf = EventBuffer.__new__(EventBuffer)
        buf._url = 'http://localhost:9999/events'
        buf._sdk_key = 'test'

        with patch('requests.post', side_effect=requests.ConnectionError('refused')):
            with patch('time.sleep'):
                with self.assertLogs('dapplepot_sdk.buffer', level='ERROR') as cm:
                    buf._send([{'dp_event_type': 'session_start'}], retries=3)
        self.assertTrue(any('failed' in line.lower() for line in cm.output))


if __name__ == '__main__':
    unittest.main()
