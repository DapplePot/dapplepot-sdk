"""DapplePot Python SDK — runtime security and observability for AI agents.

See :class:`DapplePot` for the main entry point.
"""

import logging
import random

import requests

from dapplepot_sdk._adapter import TraceAdapter
from dapplepot_sdk._buffer import EventBuffer
from dapplepot_sdk._interceptor import OnlineCheckInterceptor

logging.getLogger(__name__).addHandler(logging.NullHandler())
logger = logging.getLogger(__name__)

_DEFAULT_INGEST_URL = "https://api.dapplepot.com"

# Single source of truth in the SDK: the interceptor owns this set. Kept
# re-exported here for backward compatibility with any external code that
# imported it from the package root.
from dapplepot_sdk._interceptor import _ONLINE_CAPABLE_SUB_CHECKS


class DapplePotBlockedError(Exception):
    """Raised when an online security check blocks the call in progress.

    DapplePot evaluates active online sub-checks (e.g. prompt injection,
    excessive agency) synchronously as events are recorded. When a check's
    configured action is ``block_call``, the SDK raises this instead of
    letting the underlying LLM/tool call proceed.

    Attributes:
        signal: The sub-check ID that triggered the block (e.g. ``"PI-01a"``).
        reason: Human-readable explanation of why the call was blocked.
        session_id: The session in which the block occurred.

    Note:
        The message deliberately does not embed a dashboard URL — that
        would couple the SDK to a specific dashboard URL shape and put
        URLs in every customer log line. Build a link yourself from
        ``session_id`` + ``signal`` if you want a click-through.
    """
    def __init__(self, signal: str, reason: str, session_id: str):
        super().__init__(f'[{signal}] {reason}')
        self.signal = signal
        self.reason = reason
        self.session_id = session_id


class DapplePotSessionTerminatedError(Exception):
    """Raised when a security policy terminates the current session.

    Unlike :class:`DapplePotBlockedError` (which blocks a single call),
    this indicates the whole session has been shut down by policy and no
    further calls should be made within it.

    Attributes:
        signal: The sub-check ID that triggered termination, if known.
        session_id: The session that was terminated.
    """
    def __init__(
        self,
        message: str = 'Session terminated by security policy',
        session_id: str | None = None,
        signal: str | None = None,
    ):
        super().__init__(message)
        self.session_id = session_id
        self.signal = signal


class DapplePot:
    """Main SDK client — instrument LLM frameworks and stream traced events.

    Create one ``DapplePot`` instance per application (or per long-lived
    worker), then call one of ``instrument_anthropic()``,
    ``instrument_openai()``, or ``callback_handler()`` to start capturing
    LLM/tool activity. Events are evaluated against your account's active
    security checks synchronously, optionally PII-scrubbed, then buffered
    and flushed in the background to the DapplePot ingest API.

    Usage::

        from dapplepot_sdk import DapplePot

        dp = DapplePot(sdk_key="dp_sk_...", agent_id="my-agent")
        dp.instrument_anthropic()
    """

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
        """Initialize the client and fetch this agent's security config.

        Args:
            sdk_key: Your DapplePot SDK key, used as a bearer token for
                both the config/manifest lookups made here and every
                event flush made by the background buffer.
            agent_id: The ID of the agent this client instruments, used to
                scope config lookups (subcheck overrides, tool manifest).
            ingest_url: Base URL of the DapplePot ingest API. Defaults to
                the production endpoint; override for self-hosted or
                staging deployments.
            sample_rate: Fraction of sessions to actually trace, in
                ``[0.0, 1.0]``. ``1.0`` (default) traces every session.
                Use a lower value to cut ingest volume on high-throughput
                agents — security checks still run on sampled sessions.
            pii_scrubber: Optional :class:`dapplepot_sdk.scrubbers.BaseScrubber`
                instance (e.g. ``RegexScrubber``) applied to event payloads
                before they're buffered, so sensitive text never leaves
                the process.
            redact_keys: Optional list of dict keys to redact wholesale
                (replaced with ``"[REDACTED]"``) anywhere they appear in
                an event payload, e.g. ``["api_key", "password"]``.
            flush_interval_ms: How often the background buffer flushes
                queued events to the ingest API, in milliseconds.
            flush_batch_size: Max number of events sent per flush request.
        """
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

        tool_manifest, max_tool_calls, policy_fields = self._fetch_tool_manifest()
        ea01a_action = check_actions.get('EA-01a', 'block_call')
        ea02b_action = check_actions.get('EA-02b', 'alert')
        self._interceptor.set_tool_manifest(
            manifest=tool_manifest,
            action=ea01a_action,
            max_tool_calls=max_tool_calls,
            ea02b_action=ea02b_action,
        )
        # Policy fields silently no-op if the API doesn't return them (older
        # API versions). Each field unlocks one online check when set.
        if policy_fields:
            self._interceptor.set_policy_fields(**policy_fields)

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

    def _fetch_tool_manifest(self) -> tuple[list[str], int | None, dict]:
        """Fetch the governance-config bundle from the API.

        Returns (tool_manifest, max_tool_calls_per_session, policy_fields).
        `policy_fields` is a dict of policy-field kwargs suitable for
        `OnlineCheckInterceptor.set_policy_fields(**policy_fields)`. Empty
        when the API doesn't return those keys (older backend).
        """
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

            # Policy fields — only include keys the API actually returned.
            # `None`/missing means "keep default"; a returned key (even empty
            # list / None) becomes the source of truth.
            policy_fields: dict = {}
            for key in (
                'write_namespace', 'network_allowlist',
                'irreversible_tools', 'tool_approval_policy',
                'working_directory', 'connected_llms', 'environment',
                'privilege_scope', 'mcp_endpoints', 'sbom_allowlist',
                'connected_agents', 'operating_hours',
            ):
                if key in data:
                    policy_fields[key] = data[key]

            logger.debug(
                'Loaded tool manifest (%d tools, max_calls=%s, %d policy fields)',
                len(manifest), max_calls, len(policy_fields),
            )
            return manifest, max_calls, policy_fields
        except Exception as exc:
            logger.warning(
                'Could not fetch tool manifest from %s: %s — EA-01a/EA-02b disabled',
                url, exc,
            )
            return [], None, {}

    # ── internal helpers ──────────────────────────────────────────────────────

    def _adapter(self, framework: str) -> TraceAdapter:
        """Build a TraceAdapter scoped to this agent and the given framework."""
        return TraceAdapter(
            agent_id=self._agent_id,
            framework=framework,
        )

    def _should_sample(self) -> bool:
        """Roll the dice against sample_rate for a new session."""
        return random.random() < self._sample_rate

    def _scrub(self, event: dict) -> dict:
        """Apply pii_scrubber and redact_keys to an event's payload, if configured."""
        if not self._pii_scrubber and not self._redact_keys:
            return event
        payload = event.get('payload', {})
        if self._pii_scrubber:
            payload = self._pii_scrubber.scrub_value(payload)
        if self._redact_keys:
            payload = self._redact_keys_in(payload)
        return {**event, 'payload': payload}

    def _redact_keys_in(self, obj):
        """Recursively replace values of any key in redact_keys with '[REDACTED]'."""
        if isinstance(obj, dict):
            return {k: '[REDACTED]' if k in self._redact_keys else self._redact_keys_in(v)
                    for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._redact_keys_in(i) for i in obj]
        return obj

    def _process_event(self, event: dict) -> None:
        """Run the full per-event pipeline: security check, scrub, buffer."""
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
        """Return a fresh LangChain/LangGraph callback handler for one session.

        Use this instead of ``instrument_anthropic()``/``instrument_openai()``
        when your agent is built with LangChain or LangGraph — those
        frameworks already have a callback protocol, so DapplePot hooks in
        that way rather than patching the underlying model client. Create a
        new handler per logical session; it is not intended to be reused
        across unrelated sessions.

        Args:
            session_id: Resume an existing session instead of starting a
                new one. Leave unset to start a fresh session.
            user_context_id: Opaque end-user/context identifier to attach
                to every event emitted by this handler.
            user_tenant_id: Opaque tenant identifier, for multi-tenant
                agents, attached to every event emitted by this handler.

        Returns:
            A ``DapplePotCallbackHandler`` implementing LangChain's
            ``BaseCallbackHandler`` interface.

        Usage::

            handler = dp.callback_handler(user_context_id="user_123")
            result = chain.invoke({"input": "Hello!"}, config={"callbacks": [handler]})
        """
        from dapplepot_sdk._langchain import DapplePotCallbackHandler
        self._framework = 'langchain'
        return DapplePotCallbackHandler(self, session_id=session_id,
                                        user_context_id=user_context_id,
                                        user_tenant_id=user_tenant_id)

    def session(self, session_id: str = None, user_context_id: str = None,
                user_tenant_id: str = None):
        """Context manager that groups OpenAI/Anthropic calls into one session.

        Wrap a logical unit of work (e.g. one user request) in
        ``with dp.session():`` so that every LLM/tool call inside it is
        attributed to the same session, and ``session_start``/
        ``session_end``/``session_error`` events are emitted around it.
        Only relevant when using ``instrument_anthropic()`` /
        ``instrument_openai()`` — LangChain sessions are scoped per
        ``callback_handler()`` instance instead.

        Args:
            session_id: Resume an existing session instead of starting a
                new one. Leave unset to start a fresh session.
            user_context_id: Opaque end-user/context identifier to attach
                to every event in this session.
            user_tenant_id: Opaque tenant identifier, for multi-tenant
                agents, attached to every event in this session.

        Returns:
            A ``SessionContext`` context manager.

        Usage::

            with dp.session(user_context_id="user_123"):
                response = client.messages.create(...)
        """
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
        """Look up the last stored event sequence number for a resumed session."""
        url = f'{self._ingest_url}/v1/sdk/seq/{session_id}'
        try:
            resp = requests.get(url, headers={'Authorization': f'Bearer {self._sdk_key}'}, timeout=3)
            resp.raise_for_status()
            return resp.json().get('lastSeq')
        except Exception as exc:
            logger.warning('Could not fetch seq offset for %s: %s', session_id, exc)
            return None

    def _store_session_last_seq(self, session_id: str, last_seq: int) -> None:
        """Persist the last event sequence number so the session can be resumed later."""
        url = f'{self._ingest_url}/v1/sdk/seq/{session_id}'
        try:
            requests.post(url, json={'seq': last_seq},
                          headers={'Authorization': f'Bearer {self._sdk_key}'}, timeout=3)
        except Exception as exc:
            logger.warning('Could not store seq offset for %s: %s', session_id, exc)

    def shutdown(self, timeout_ms: int = 5000) -> None:
        """Flush remaining buffered events and stop the background thread.

        Call this before your process exits (e.g. in a ``finally`` block or
        an ``atexit`` handler) so events queued but not yet flushed aren't
        lost. Safe to call more than once.

        Args:
            timeout_ms: Maximum time to wait for the final flush to
                complete before giving up, in milliseconds.

        Usage::

            dp = DapplePot(...)
            try:
                ...
            finally:
                dp.shutdown()
        """
        self._buffer.shutdown(timeout_ms=timeout_ms)
