import logging
import random
import sys

import requests

from dapplepot_sdk._adapter import TraceAdapter
from dapplepot_sdk._buffer import EventBuffer
from dapplepot_sdk._interceptor import OnlineCheckInterceptor

logging.getLogger(__name__).addHandler(logging.NullHandler())
logger = logging.getLogger(__name__)

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
        tenant_id: str,
        agent_id: str,
        ingest_url: str,
        *,
        sample_rate: float = 1.0,
        pii_scrubber=None,
        redact_keys: list = None,
        flush_interval_ms: int = 500,
        flush_batch_size: int = 100,
    ):
        self._sdk_key      = sdk_key
        self._tenant_id    = tenant_id
        self._agent_id     = agent_id
        self._ingest_url   = ingest_url.rstrip('/')
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
        # Auto-register with OpenAI/Anthropic proxies if they were imported before
        # the client was created (the documented usage pattern).
        for mod_name in ('dapplepot_sdk.openai', 'dapplepot_sdk.anthropic'):
            mod = sys.modules.get(mod_name)
            if mod is not None:
                mod._patch(self)
                self._framework = mod_name.split('.')[-1]  # 'openai' or 'anthropic'

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
            tenant_id=self._tenant_id,
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

    def callback_handler(self, session_id: str = None):
        """Return a fresh LangChain/LangGraph CallbackHandler for one session."""
        from dapplepot_sdk._langchain import DapplePotCallbackHandler
        self._framework = 'langchain'
        return DapplePotCallbackHandler(self, session_id=session_id)

    def instrument_llama_index(self) -> None:
        """Process-wide LlamaIndex instrumentation. Call once at startup."""
        from dapplepot_sdk._llama_index import instrument
        instrument(self)
        self._framework = 'llama_index'

    def uninstrument_llama_index(self) -> None:
        from dapplepot_sdk._llama_index import uninstrument
        uninstrument()

    def register_litellm_callbacks(self) -> None:
        """Register DapplePot as LiteLLM's success/failure callbacks."""
        from dapplepot_sdk._litellm import register
        register(self)
        self._framework = 'litellm'

    def session(self, session_id: str = None, user_context_id: str = None):
        """Context manager that wraps OpenAI / Anthropic calls in a DapplePot session."""
        from dapplepot_sdk.session import SessionContext
        return SessionContext(self, session_id=session_id, user_context_id=user_context_id)

    def shutdown(self, timeout_ms: int = 5000) -> None:
        """Flush remaining events and stop background threads."""
        self._buffer.shutdown(timeout_ms=timeout_ms)
