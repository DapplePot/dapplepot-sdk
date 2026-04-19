import logging
import random

import requests

from dapplepot_sdk.adapter import TraceAdapter
from dapplepot_sdk.buffer import EventBuffer
from dapplepot_sdk.control_channel import ControlChannel
from dapplepot_sdk.interceptor import OnlineCheckInterceptor

logger = logging.getLogger(__name__)

# Maps API sub_check_id → SDK signal name (reverse of security service _ONLINE_SIGNAL_MAP)
_SUBCHECK_TO_SIGNAL: dict[str, str] = {
    'llm-01-online':       'prompt_injection',
    'llm-09-online':       'insecure_output',
    'llm-02-online-in':    'pii_input',
    'llm-02-online-out':   'pii_output',
    'llm-02-online-exfil': 'sensitive_data_exfiltration',
    'llm-05-online':       'tool_misuse',
    'asi-08-online':       'resource_exhaustion',
    'asi-05-online-priv':  'privilege_escalation',
    'asi-05-online-code':  'unsafe_code_execution',
    'asi-04-online':       'supply_chain_tool',
}


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
        ingest_url: str = 'http://localhost:3000',
        *,
        redis_url: str = 'redis://localhost:6379',
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
        self._control_channel = ControlChannel(
            tenant_id=self._tenant_id,
            client=self,
            redis_url=redis_url,
        )
        self._control_channel.start()

    # ── startup ───────────────────────────────────────────────────────────────

    def _fetch_check_actions(self) -> dict[str, str]:
        """Pull per-subcheck online config from the API. Returns {signal_name: action}."""
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
                if cfg.get('online_detection'):
                    signal = _SUBCHECK_TO_SIGNAL.get(sub_check_id)
                    if signal:
                        check_actions[signal] = cfg.get('action', 'alert')
            logger.debug('Loaded %d online checks from API', len(check_actions))
            return check_actions
        except Exception as exc:
            logger.warning(
                'Could not fetch online check config from %s: %s — online checks disabled',
                url, exc,
            )
            return {}

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
        self._interceptor.evaluate(event)
        event = self._scrub(event)
        self._buffer.push(event)

    # ── public API ────────────────────────────────────────────────────────────

    def callback_handler(self, session_id: str = None):
        """Return a fresh LangChain/LangGraph CallbackHandler for one session."""
        from dapplepot_sdk._langchain import DapplePotCallbackHandler
        return DapplePotCallbackHandler(self, session_id=session_id)

    def instrument_llama_index(self) -> None:
        """Process-wide LlamaIndex instrumentation. Call once at startup."""
        from dapplepot_sdk._llama_index import instrument
        instrument(self)

    def uninstrument_llama_index(self) -> None:
        from dapplepot_sdk._llama_index import uninstrument
        uninstrument()

    def register_litellm_callbacks(self) -> None:
        """Register DapplePot as LiteLLM's success/failure callbacks."""
        from dapplepot_sdk._litellm import register
        register(self)

    def session(self, session_id: str = None):
        """Context manager that wraps OpenAI / Anthropic calls in a DapplePot session."""
        from dapplepot_sdk.session import SessionContext
        return SessionContext(self, session_id=session_id)

    def shutdown(self, timeout_ms: int = 5000) -> None:
        """Flush remaining events and stop background threads."""
        self._control_channel.stop()
        self._buffer.shutdown(timeout_ms=timeout_ms)
