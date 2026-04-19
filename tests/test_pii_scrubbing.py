"""test_pii_scrubbing — validates regex scrubber, custom scrubber, redact_keys."""

import re
import unittest

from dapplepot_sdk.scrubbers import RegexScrubber, BaseScrubber


class TestRegexScrubber(unittest.TestCase):

    def test_email(self):
        s = RegexScrubber(patterns=['email'])
        self.assertEqual(s.scrub('Contact user@example.com today'), 'Contact [EMAIL] today')

    def test_phone(self):
        s = RegexScrubber(patterns=['phone'])
        out = s.scrub('Call 555-867-5309 now')
        self.assertIn('[PHONE]', out)

    def test_ssn(self):
        s = RegexScrubber(patterns=['ssn'])
        self.assertEqual(s.scrub('SSN: 123-45-6789'), 'SSN: [SSN]')

    def test_aws_key(self):
        s = RegexScrubber(patterns=['aws_key'])
        out = s.scrub('Key: AKIAIOSFODNN7EXAMPLE')
        self.assertIn('[AWS_KEY]', out)

    def test_jwt(self):
        s = RegexScrubber(patterns=['jwt'])
        token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456'
        out = s.scrub(f'Token: {token}')
        self.assertIn('[JWT]', out)

    def test_multiple_patterns(self):
        s = RegexScrubber(patterns=['email', 'ssn'])
        out = s.scrub('Email: a@b.com, SSN: 123-45-6789')
        self.assertIn('[EMAIL]', out)
        self.assertIn('[SSN]', out)

    def test_nested_dict(self):
        s = RegexScrubber(patterns=['email'])
        result = s.scrub_value({'user': {'email': 'a@b.com', 'name': 'Alice'}})
        self.assertEqual(result['user']['email'], '[EMAIL]')
        self.assertEqual(result['user']['name'], 'Alice')

    def test_list_scrubbing(self):
        s = RegexScrubber(patterns=['email'])
        result = s.scrub_value(['hello a@b.com', 'no email here'])
        self.assertIn('[EMAIL]', result[0])
        self.assertNotIn('[EMAIL]', result[1])

    def test_non_string_passthrough(self):
        s = RegexScrubber()
        self.assertEqual(s.scrub_value(42), 42)
        self.assertIsNone(s.scrub_value(None))


class TestCustomScrubber(unittest.TestCase):

    def test_custom_scrubber(self):
        class NHSScrubber(BaseScrubber):
            def scrub(self, text: str) -> str:
                return re.sub(r'\bNHS\d{10}\b', '[NHS_ID]', text)

        s = NHSScrubber()
        out = s.scrub('Patient NHS1234567890 admitted')
        self.assertEqual(out, 'Patient [NHS_ID] admitted')

    def test_custom_scrubber_nested(self):
        class UpperScrubber(BaseScrubber):
            def scrub(self, text: str) -> str:
                return text.upper()

        s = UpperScrubber()
        result = s.scrub_value({'key': 'hello'})
        self.assertEqual(result['key'], 'HELLO')


class TestRedactKeys(unittest.TestCase):

    def _make_dp(self, redact_keys):
        from unittest.mock import MagicMock
        from dapplepot_sdk import DapplePot
        dp = DapplePot.__new__(DapplePot)
        dp._tenant_id = 'test'
        dp._agent_id = 'test'
        dp._sdk_key = 'test'
        dp._ingest_url = 'http://localhost'
        dp._sample_rate = 1.0
        dp._online_action = 'warn'
        dp._pii_scrubber = None
        dp._redact_keys = set(redact_keys)
        dp._tool_allowlist = None
        dp._buffer = MagicMock()
        dp._buffer.is_sampled.return_value = True
        from dapplepot_sdk.interceptor import OnlineCheckInterceptor
        dp._interceptor = OnlineCheckInterceptor([], 'warn', dp._buffer, dp)
        return dp

    def test_redact_top_level_key(self):
        captured = []
        dp = self._make_dp(['authorization'])
        dp._buffer.push.side_effect = captured.append
        from dapplepot_sdk.adapter import TraceAdapter
        adapter = TraceAdapter('t', 'a', 'test')
        event = adapter.session_start('sid-1')
        event['payload']['authorization'] = 'Bearer secret123'
        dp._process_event(event)
        self.assertEqual(captured[0]['payload']['authorization'], '[REDACTED]')

    def test_redact_nested_key(self):
        captured = []
        dp = self._make_dp(['password'])
        dp._buffer.push.side_effect = captured.append
        from dapplepot_sdk.adapter import TraceAdapter
        adapter = TraceAdapter('t', 'a', 'test')
        event = adapter.session_start('sid-2')
        event['payload']['creds'] = {'password': 'hunter2', 'user': 'alice'}
        dp._process_event(event)
        self.assertEqual(captured[0]['payload']['creds']['password'], '[REDACTED]')
        self.assertEqual(captured[0]['payload']['creds']['user'], 'alice')


if __name__ == '__main__':
    unittest.main()
