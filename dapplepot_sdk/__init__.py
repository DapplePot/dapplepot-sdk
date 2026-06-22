import logging
import random

import requests

from dapplepot_sdk._adapter import TraceAdapter
from dapplepot_sdk._buffer import EventBuffer
from dapplepot_sdk._interceptor import OnlineCheckInterceptor

logging.getLogger(__name__).addHandler(logging.NullHandler())
logger = logging.getLogger(__name__)

_DEFAULT_INGEST_URL = "https://api.dapplepot.com"

_ONLINE_CAPABLE_SUB_CHECKS: frozenset[str] = frozenset({
    'PI-01a', 'PI-01b', 'PI-01c', 'PI-02a', 'PI-05a', 'PI-08a',
    'SID-01a', 'SID-01c', 'SID-02a',
    'IOH-01a',
    'EA-01a', 'EA-02b',
})


class DapplePotBlockedError(Exception):
    def __init__(self, signal: str, reason: str, session_id: str):
        super().__init__(f'[{signal}] {reason}')
        self.signal = signal
        self.reason = reason
        self.session_id = session_id


class DapplePotSessionTerminatedError(Exception):
    pass


class DapplePot:
    def __init__(
        self,
        sdk_key: str,
        agent_id: str,
        ingest_url: str = None,
        *,
        sample_rate: float = 1.0,
        pii_scrubber=None,
        redact_keys: list = None,
        flush_interval_ms: int = 500,
        flush_batch_size: int = 100,
    ):
        self._sdk_key      = sdk_key
        self._agent_id     = agent_id
        self._ingest_url   = (ingest_url or _DEFAULT_INGEST_URL).rstrip('/')
        self._sample_rate  = sample_rate
        self._pii_scrubber = pii_scrubber
        self._redact_keys  = set(redact_keys or [])
        self._tool_allowlist = None

        check_actions = self._fetch_check_actions()

        self._buffer = EventBuffer(
            ingest_url=self._ingest_url,
            sdk_key=self._sdk_key,
            flush_interval_ms=flush_interval_ms,
            flush_batch_size=flush_batch_size,
        )
        self._interceptor = OnlineCheckInterceptor(
            check_actions=check_actions,
            buffer=self._buffer,
            client=self,
        )

        tool_manifest, max_tool_calls = self._fetch_tool_manifest()
        ea01a_action = check_actions.get('EA-01a', 'block_call')
        ea02b_action = check_actions.get('EA-02b', 'alert')
        self._interceptor.set_tool_manifest(
            manifest=tool_manifest,
            action=ea01a_action,
            max_tool_calls=max_tool_calls,
            ea02b_action=ea02b_action,
        )

        self._framework = 'unknown'

    # ── startup ───────────────────────────────────────────────────────────────

    def _fetch_check_actions(self) -> dict[str, str]:
        """Pull per-subcheck online config from the API. Returns {sub_check_id: action}."""
        url = f'{self._ingest_url}/v1/sdk/security/agents/{self._agent_id}/subcheck-config'
        try:
            resp = requests.get(
                url,
                headers={'Authorization': f'Bearer {self._sdk_key}'},
                timeout=5,
            )
            resp.raise_for_status()
            overrides: dict = resp.json().get('overrides', {})
            check_actions = {}
            for sub_check_id, cfg in overrides.items():
                if cfg.get('online_detection') and sub_check_id in _ONLINE_CAPABLE_SUB_CHECKS:
                    check_actions[sub_check_id] = cfg.get('action', 'alert')
            logger.debug('Loaded %d online checks from API', len(check_actions))
            return check_actions
        except Exception as exc:
            logger.warning(
                'Could not fetch online check config from %s: %s — online checks disabled',
                url, exc,
            )
            return {}

    def _fetch_tool_manifest(self) -> tuple[list[str], int | None]:
        """Fetch the tool manifest and max_tool_calls_per_session from the API."""
        url = f'{self._ingest_url}/v1/sdk/security/agents/{self._agent_id}/tool-manifest'
        try:
            resp = requests.get(
                url,
                headers={'Authorization': f'Bearer {self._sdk_key}'},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            manifest = data.get('tool_manifest') or []
            max_calls = data.get('max_tool_calls_per_session')
            logger.debug('Loaded tool manifest (%d tools, max_calls=%s)', len(manifest), max_calls)
            return manifest, max_calls
        except Exception as exc:
            logger.warning(
                'Could not fetch tool manifest from %s: %s — EA-01a/EA-02b disabled',
                url, exc,
            )
            return [], None

    # ── internal helpers ──────────────────────────────────────────────────────

    def _adapter(self, framework: str) -> TraceAdapter:
        return TraceAdapter(
            agent_id=self._agent_id,
            framework=framework,
        )

    def _should_sample(self) -> bool:
        return random.random() < self._sample_rate

    def _scrub(self, event: dict) -> dict:
        if not self._pii_scrubber and not self._redact_keys:
            return event
        payload = event.get('payload', {})
        if self._pii_scrubber:
            payload = self._pii_scrubber.scrub_value(payload)
        if self._redact_keys:
            payload = self._redact_keys_in(payload)
        return {**event, 'payload': payload}

    def _redact_keys_in(self, obj):
        if isinstance(obj, dict):
            return {k: '[REDACTED]' if k in self._redact_keys else self._redact_keys_in(v)
                    for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._redact_keys_in(i) for i in obj]
        return obj

    def _process_event(self, event: dict) -> None:
        event = self._interceptor.evaluate(event)
        event = self._scrub(event)
        self._buffer.push(event)

    # ── public API ────────────────────────────────────────────────────────────

    def instrument_anthropic(self) -> None:
        """Patch the Anthropic SDK so all messages.create() calls are traced automatically.

        Call once after DapplePot() is initialised, before creating your Anthropic client.
        The standard anthropic package is unaffected — upgrade it freely at any time.

        Usage::

            import anthropic
            from dapplepot_sdk import DapplePot

            dp = DapplePot(...)
            dp.instrument_anthropic()

            client = anthropic.Anthropic(api_key="...")
        """
        from dapplepot_sdk import anthropic as _dp_anth
        _dp_anth._patch(self)
        self._framework = 'anthropic'

    def instrument_openai(self) -> None:
        """Patch the OpenAI SDK so all chat.completions.create() calls are traced automatically.

        Call once after DapplePot() is initialised, before creating your OpenAI client.

        Usage::

            import openai
            from dapplepot_sdk import DapplePot

            dp = DapplePot(...)
            dp.instrument_openai()

            client = openai.OpenAI(api_key="...")
        """
        from dapplepot_sdk import openai as _dp_openai
        _dp_openai._patch(self)
        self._framework = 'openai'

    def callback_handler(self, session_id: str = None, user_context_id: str = None,
                         user_tenant_id: str = None):
        """Return a fresh LangChain/LangGraph CallbackHandler for one session."""
        from dapplepot_sdk._langchain import DapplePotCallbackHandler
        self._framework = 'langchain'
        return DapplePotCallbackHandler(self, session_id=session_id,
                                        user_context_id=user_context_id,
                                        user_tenant_id=user_tenant_id)

    def session(self, session_id: str = None, user_context_id: str = None,
                user_tenant_id: str = None):
        """Context manager that wraps OpenAI / Anthropic calls in a DapplePot session."""
        from dapplepot_sdk.session import SessionContext
        return SessionContext(self, session_id=session_id, user_context_id=user_context_id,
                              user_tenant_id=user_tenant_id)

    def node(self, node_name: str, input=None):
        """Context manager to trace a named step inside an active dp.session().

        Emits node_start on enter and node_end / node_error on exit.
        Use this to add structure to your agent loop — it is entirely optional.

        Usage::

            with dp.node("retrieval", input=query):
                docs = vector_store.search(query)

            with dp.node("call_model"):
                response = client.messages.create(...)
        """
        from dapplepot_sdk._node_context import NodeContext
        from dapplepot_sdk.session import get_current_session_id
        return NodeContext(self, session_id=get_current_session_id(),
                           node_name=node_name, input=input)

    def _fetch_session_last_seq(self, session_id: str) -> int | None:
        url = f'{self._ingest_url}/v1/sdk/seq/{session_id}'
        try:
            resp = requests.get(url, headers={'Authorization': f'Bearer {self._sdk_key}'}, timeout=3)
            resp.raise_for_status()
            return resp.json().get('lastSeq')
        except Exception as exc:
            logger.warning('Could not fetch seq offset for %s: %s', session_id, exc)
            return None

    def _store_session_last_seq(self, session_id: str, last_seq: int) -> None:
        url = f'{self._ingest_url}/v1/sdk/seq/{session_id}'
        try:
            requests.post(url, json={'seq': last_seq},
                          headers={'Authorization': f'Bearer {self._sdk_key}'}, timeout=3)
        except Exception as exc:
            logger.warning('Could not store seq offset for %s: %s', session_id, exc)

    def shutdown(self, timeout_ms: int = 5000) -> None:
        """Flush remaining events and stop background threads."""
        self._buffer.shutdown(timeout_ms=timeout_ms)
