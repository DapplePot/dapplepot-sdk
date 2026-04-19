"""test_control_channel — terminate_session, update_tool_blocklist, update_sample_rate."""

import unittest
from unittest.mock import MagicMock, patch

from dapplepot_sdk.control_channel import ControlChannel


def _make_client():
    client = MagicMock()
    client._sample_rate = 1.0
    client._tool_allowlist = None
    interceptor = MagicMock()
    interceptor._checks = set()
    client._interceptor = interceptor
    return client


class TestControlChannel(unittest.TestCase):

    def _channel(self):
        client = _make_client()
        cc = ControlChannel(tenant_id='test-tenant', client=client)
        return cc, client

    def test_update_sample_rate(self):
        cc, client = self._channel()
        cc._handle({'command': 'update_sample_rate', 'sample_rate': 0.3})
        self.assertAlmostEqual(client._sample_rate, 0.3)

    def test_update_tool_blocklist(self):
        cc, client = self._channel()
        cc._handle({'command': 'update_tool_blocklist', 'blocklist': ['evil_tool', 'bad_tool']})
        self.assertEqual(client._tool_allowlist, {'evil_tool', 'bad_tool'})

    def test_update_online_checks(self):
        cc, client = self._channel()
        cc._handle({'command': 'update_online_checks', 'online_checks': ['prompt_injection', 'pii_input']})
        self.assertEqual(client._interceptor._checks, {'prompt_injection', 'pii_input'})

    def test_terminate_session_logged(self):
        cc, client = self._channel()
        with self.assertLogs('dapplepot_sdk.control_channel', level='INFO') as cm:
            cc._handle({'command': 'terminate_session', 'session_id': 'abc-123'})
        self.assertTrue(any('abc-123' in line for line in cm.output))

    def test_unknown_command_ignored(self):
        cc, client = self._channel()
        # should not raise
        cc._handle({'command': 'unknown_future_command', 'data': 'x'})

    def test_start_without_redis(self):
        cc, _ = self._channel()
        with patch.dict('sys.modules', {'redis': None}):
            # should not raise; just log debug
            cc.start()

    def test_stop(self):
        cc, _ = self._channel()
        cc.stop()
        self.assertTrue(cc._stop.is_set())


if __name__ == '__main__':
    unittest.main()
