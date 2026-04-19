"""test_event_capture — validates session/span/llm/tool lifecycle events."""

import unittest
import uuid
from unittest.mock import MagicMock, patch

from dapplepot_sdk import DapplePot
from dapplepot_sdk.adapter import TraceAdapter


def _make_dp(captured: list) -> DapplePot:
    dp = DapplePot.__new__(DapplePot)
    dp._tenant_id = 'test-tenant'
    dp._agent_id  = 'test-agent'
    dp._sdk_key   = 'dp_sk_test'
    dp._ingest_url = 'http://localhost:9000'
    dp._sample_rate = 1.0
    dp._online_action = 'warn'
    dp._pii_scrubber = None
    dp._redact_keys = set()
    dp._tool_allowlist = None

    buf = MagicMock()
    buf.is_sampled.return_value = True
    buf.push.side_effect = captured.append
    buf.push_sync.side_effect = captured.append
    dp._buffer = buf

    from dapplepot_sdk.interceptor import OnlineCheckInterceptor
    dp._interceptor = OnlineCheckInterceptor(
        online_checks=[], online_action='warn', buffer=buf, client=dp
    )
    dp._control_channel = MagicMock()
    return dp


class TestEventCapture(unittest.TestCase):

    def test_session_start_end(self):
        captured = []
        dp = _make_dp(captured)
        adapter = dp._adapter('langchain')
        sid = str(uuid.uuid4())
        dp._buffer.set_sampled = MagicMock()

        dp._process_event(adapter.session_start(sid))
        dp._process_event(adapter.session_end(sid, output='hello', latency_ms=100))

        types = [e['dp_event_type'] for e in captured]
        self.assertIn('session_start', types)
        self.assertIn('session_end', types)

    def test_llm_events(self):
        captured = []
        dp = _make_dp(captured)
        adapter = dp._adapter('openai')
        sid = str(uuid.uuid4())

        dp._process_event(adapter.llm_start(sid, model='gpt-4o', messages=[{'role': 'user', 'content': 'hi'}]))
        dp._process_event(adapter.llm_end(sid, completion='hello', usage={'prompt_tokens': 5, 'completion_tokens': 2}))

        types = [e['dp_event_type'] for e in captured]
        self.assertIn('llm_start', types)
        self.assertIn('llm_end', types)

        llm_start = next(e for e in captured if e['dp_event_type'] == 'llm_start')
        self.assertEqual(llm_start['payload']['model'], 'gpt-4o')

    def test_tool_events(self):
        captured = []
        dp = _make_dp(captured)
        adapter = dp._adapter('langchain')
        sid = str(uuid.uuid4())

        dp._process_event(adapter.tool_start(sid, tool_name='search', tool_input='python'))
        dp._process_event(adapter.tool_end(sid, tool_name='search', tool_output='Python is a language.', latency_ms=50))

        types = [e['dp_event_type'] for e in captured]
        self.assertIn('tool_start', types)
        self.assertIn('tool_end', types)

    def test_node_events(self):
        captured = []
        dp = _make_dp(captured)
        adapter = dp._adapter('langgraph')
        sid = str(uuid.uuid4())

        dp._process_event(adapter.node_start(sid, node_name='research', input={'q': 'hi'}))
        dp._process_event(adapter.node_end(sid, node_name='research', output='done', latency_ms=200))

        types = [e['dp_event_type'] for e in captured]
        self.assertIn('node_start', types)
        self.assertIn('node_end', types)

    def test_event_envelope_fields(self):
        captured = []
        dp = _make_dp(captured)
        adapter = dp._adapter('anthropic')
        sid = str(uuid.uuid4())

        dp._process_event(adapter.session_start(sid))
        e = captured[0]
        for field in ('dp_tenant_id', 'dp_agent_id', 'dp_session_id',
                      'dp_event_type', 'dp_schema_version', 'dp_sampled',
                      'dp_framework', 'ts', 'payload'):
            self.assertIn(field, e, f'Missing field: {field}')
        self.assertEqual(e['dp_schema_version'], '2')
        self.assertEqual(e['dp_framework'], 'anthropic')

    def test_error_event(self):
        captured = []
        dp = _make_dp(captured)
        adapter = dp._adapter('langchain')
        sid = str(uuid.uuid4())

        dp._process_event(adapter.session_error(sid, error_type='ValueError', error_message='bad input'))

        types = [e['dp_event_type'] for e in captured]
        self.assertIn('session_error', types)


if __name__ == '__main__':
    unittest.main()
