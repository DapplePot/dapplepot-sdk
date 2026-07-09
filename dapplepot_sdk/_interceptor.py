"""Event evaluation pipeline."""
from __future__ import annotations

import logging
import uuid
import re
from typing import Any

import requests
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)

# ─── Enforceable sub-check ID set ─────────────────────────────────────────────
#
# MUST MIRROR: dapplepot-security/security_eval/registry.ENFORCEABLE_SUBCHECK_IDS
#
# The SDK is a separately-installed package and can't import the security
# service's registry at runtime, so this list is duplicated. Server-side
# validates every configured check against its own set; unknown IDs are
# silently no-oped. That means an SDK slightly behind the server just misses
# newly-added checks — never fires spuriously.
#
# To update: add IDs here, verify via
#   python dapplepot-security/scripts/check_sdk_sync.py
# which cross-references this set with the registry snapshot.
_ONLINE_CAPABLE_SUB_CHECKS: frozenset[str] = frozenset({
    # OW-LLM01 injection signatures
    'PI-01a', 'PI-01b', 'PI-01c', 'PI-02a', 'PI-02c',
    'PI-03a', 'PI-03b', 'PI-05a', 'PI-07a', 'PI-08a', 'PI-09a',
    # OW-LLM02 disclosure signatures
    'SID-01a', 'SID-01b', 'SID-01c', 'SID-02a', 'SID-02b', 'SID-02c', 'SID-03b',
    # OW-LLM05 output handling
    'IOH-01a', 'IOH-01b', 'IOH-01c', 'IOH-04a',
    # OW-LLM06 excessive-agency policy checks
    'EA-01a', 'EA-01c', 'EA-02a', 'EA-02b', 'EA-03a', 'EA-03b', 'EA-04a',
    # OW-ASI01 agent-goal hijack
    'AGH-04a',
    # OW-ASI02 tool misuse
    'TME-03b', 'TME-06a',
    # OW-ASI03 privilege / permission abuse
    'IPA-01a', 'IPA-02a', 'IPA-02b',
    # OW-ASI04 supply-chain
    'ASCV-01a', 'ASCV-02b', 'ASCV-03b', 'ASCV-04a',
    # OW-ASI05 code execution / RCE — deterministic signatures
    'RCE-01a', 'RCE-01b', 'RCE-01c', 'RCE-02a', 'RCE-02b',
    'RCE-03a', 'RCE-03b', 'RCE-05a', 'RCE-06a', 'RCE-08a',
    # OW-ASI06 memory / context — tenant boundary
    'MCP-01a', 'MCP-03a', 'MCP-04a',
    # OW-ASI07 inter-agent communication
    'IAC-01a', 'IAC-02a', 'IAC-02b', 'IAC-05a',
    # OW-ASI09 human trust
    'HAT-02a', 'HAT-03a',
    # OW-ASI10 rogue behaviour
    'RA-01b', 'RA-04a',
})

# Regex matching a call to a confirm/approve/authorize-style tool. Used by
# the interceptor to flip `confirm_gate_seen` for the rest of the session
# so that a later destructive call passes EA-02a.
_EA02A_CONFIRM_GATE = re.compile(
    r"(?i)(confirm|approve|authorize|sign_off|validate_action|review_action)"
)

# Sanitization patterns (kept for _sanitize_text)
_PII_PATTERNS = [
    re.compile(r"\b\d{3}[-.\\s]?\d{3}[-.\\s]?\d{4}\b"),
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
]

_HEX_PATTERN = re.compile(r"(?:\\x[0-9a-f]{2}){4,}", re.IGNORECASE)
_BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _make_session(pool_connections: int = 4, pool_maxsize: int = 10) -> requests.Session:
    """Create a requests.Session with connection pooling."""
    s = requests.Session()
    adapter = HTTPAdapter(pool_connections=pool_connections, pool_maxsize=pool_maxsize)
    s.mount('http://', adapter)
    s.mount('https://', adapter)
    return s


class OnlineCheckInterceptor:
    """Calls backend for online checks, handles findings locally.

    Instantiated once per DapplePot instance.
    _action_map: { sub_check_id → action }
    """

    def __init__(self, check_actions: dict[str, str], buffer, client) -> None:
        """Seed the active check map from ``check_actions`` (sub_check_id -> action)."""
        self._buffer = buffer
        self._client = client
        self._action_map: dict[str, str] = {}
        self._ea01a_online: bool = False
        self._ea01a_action: str = 'block_call'
        self._ea02b_online: bool = False
        self._ea02b_action: str = 'alert'
        self._tool_manifest: list[str] = []
        self._max_tool_calls: int | None = None
        self._tool_call_count: int = 0
        # Governance policy fields for EA-01c / EA-02a / EA-03b
        self._write_namespace: str | None       = None
        self._network_allowlist: list[str]      = []
        self._irreversible_tools: list[str]     = []
        self._tool_approval_policy: dict[str, str] = {}
        # Policy fields — each unlocks a different online check.
        # All optional; None / [] means "check is silent" (blind mode).
        self._working_directory: str | None     = None   # EA-03a
        self._connected_llms: list[str]         = []     # EA-04a
        self._environment: str | None           = None   # TME-03b ('production' | 'staging')
        self._privilege_scope: list[str]        = []     # IPA-01a
        self._mcp_endpoints: list[str]          = []     # ASCV-01a
        self._sbom_allowlist: list[str]         = []     # ASCV-02b
        self._connected_agents: list[str]       = []     # IAC-05a
        self._operating_hours: dict | None      = None   # RA-01b {days, from, to}
        # Session-scoped flag: True once a confirm/approve/authorize tool has
        # been invoked. Reset by reset_session_state().
        self._confirm_gate_seen: bool = False
        self._http: requests.Session = _make_session()
        self.update_active(check_actions)

    def update_active(self, action_map: dict[str, str]) -> None:
        """Replace the active sub-check→action map."""
        self._ea01a_online = 'EA-01a' in action_map
        if 'EA-01a' in action_map:
            self._ea01a_action = action_map['EA-01a']
        self._ea02b_online = 'EA-02b' in action_map
        if 'EA-02b' in action_map:
            self._ea02b_action = action_map['EA-02b']
        self._action_map = {
            sid: action
            for sid, action in action_map.items()
            if sid in _ONLINE_CAPABLE_SUB_CHECKS
        }

    def update_check_actions(self, check_actions: dict[str, str]) -> None:
        """Alias for :meth:`update_active`."""
        self.update_active(check_actions)

    def set_tool_manifest(
        self,
        manifest: list[str],
        action: str = 'block_call',
        max_tool_calls: int | None = None,
        ea02b_action: str = 'alert',
    ) -> None:
        self._tool_manifest = manifest or []
        if action:
            self._ea01a_action = action
        self._max_tool_calls = max_tool_calls
        if ea02b_action:
            self._ea02b_action = ea02b_action

    def set_policy_fields(
        self,
        *,
        write_namespace: str | None = None,
        network_allowlist: list[str] | None = None,
        irreversible_tools: list[str] | None = None,
        tool_approval_policy: dict[str, str] | None = None,
        working_directory: str | None = None,
        connected_llms: list[str] | None = None,
        environment: str | None = None,
        privilege_scope: list[str] | None = None,
        mcp_endpoints: list[str] | None = None,
        sbom_allowlist: list[str] | None = None,
        connected_agents: list[str] | None = None,
        operating_hours: dict | None = None,
    ) -> None:
        """Update the Governance fields the server needs for Guard policy checks.

        Called on session/agent config refresh. Any argument left as None
        keeps its current value; pass [] or {} to explicitly clear.
        """
        if write_namespace is not None:
            self._write_namespace = write_namespace or None
        if network_allowlist is not None:
            self._network_allowlist = list(network_allowlist)
        if irreversible_tools is not None:
            self._irreversible_tools = list(irreversible_tools)
        if tool_approval_policy is not None:
            self._tool_approval_policy = dict(tool_approval_policy)
        if working_directory is not None:
            self._working_directory = working_directory or None
        if connected_llms is not None:
            self._connected_llms = list(connected_llms)
        if environment is not None:
            self._environment = environment or None
        if privilege_scope is not None:
            self._privilege_scope = list(privilege_scope)
        if mcp_endpoints is not None:
            self._mcp_endpoints = list(mcp_endpoints)
        if sbom_allowlist is not None:
            self._sbom_allowlist = list(sbom_allowlist)
        if connected_agents is not None:
            self._connected_agents = list(connected_agents)
        if operating_hours is not None:
            self._operating_hours = dict(operating_hours) if operating_hours else None

    def reset_session_state(self) -> None:
        """Reset per-session counters (e.g. tool_call_count) for a new session."""
        self._tool_call_count = 0
        self._confirm_gate_seen = False

    @property
    def has_active(self) -> bool:
        """Whether any online check is currently active and worth evaluating events against."""
        return (
            bool(self._action_map)
            or (self._ea01a_online and bool(self._tool_manifest))
            or (self._ea02b_online and self._max_tool_calls is not None)
            # EA-01c / EA-02a / EA-03b become active as soon as their policy
            # field is declared (silent otherwise); the SDK doesn't need a
            # separate per-check enable flag because _action_map covers it.
        )

    def evaluate(self, event: dict) -> dict:
        """Run all active online checks against the event.

        Returns the event, with sensitive content redacted from the payload
        when any firing check has action='sanitize'. Raises
        DapplePotBlockedError / DapplePotSessionTerminatedError for the
        corresponding actions.
        """
        if not self.has_active:
            return event

        et = event.get('dp_event_type', '')
        payload = event.get('payload', {})
        sid = event.get('dp_session_id', '')

        if et == 'tool_start':
            self._tool_call_count += 1
            # Track confirm-gate invocation for EA-02a. This mirrors the server
            # regex so we don't need to round-trip a "was this a gate?" question.
            tool_name = str(payload.get('tool_name', '') or '')
            if tool_name and _EA02A_CONFIRM_GATE.search(tool_name):
                self._confirm_gate_seen = True

        findings = self._run(et, payload, sid)
        if not findings:
            return event

        block_sub_check_id = None
        block_reason = None
        should_terminate = False
        terminate_sub_check = None
        sanitize_findings: list[dict] = []

        for finding, action in findings:
            security_event = {
                **event,
                'dp_event_type': 'security_finding',
                'event_id': str(uuid.uuid4()),
                'payload': {
                    **payload,
                    'trigger_event_id': event.get('event_id'),
                    'trigger_event_type': event.get('dp_event_type'),
                    'signal': finding['sub_check_id'],
                    'reason': finding.get('matched_text', ''),
                    'action_taken': action,
                    **finding,
                },
            }
            self._buffer.push(security_event)

            if action == 'terminate_session':
                should_terminate = True
                if terminate_sub_check is None:
                    terminate_sub_check = finding['sub_check_id']
            elif action == 'block_call' and block_sub_check_id is None:
                block_sub_check_id = finding['sub_check_id']
                block_reason = finding.get('matched_text', '')
            elif action == 'sanitize':
                sanitize_findings.append(finding)
            # 'alert': finding emitted above; session continues unchanged

        if sanitize_findings:
            event = self._apply_sanitize(event, et, sanitize_findings)

        if should_terminate:
            from dapplepot_sdk import DapplePotSessionTerminatedError
            session_error = self._client._adapter(
                event.get('dp_framework', 'sdk')
            ).session_error(
                sid,
                error_type='DapplePotSessionTerminatedError',
                error_message='Session terminated by security policy',
                exit_reason=f'terminated:{terminate_sub_check}',
            )
            self._buffer.push(session_error)
            self._buffer.flush_sync()
            self._client._store_session_last_seq(sid, -1)
            raise DapplePotSessionTerminatedError(
                message='Session terminated by security policy',
                session_id=sid,
                signal=terminate_sub_check,
            )
        if block_sub_check_id:
            from dapplepot_sdk import DapplePotBlockedError
            self._buffer.flush_sync()
            raise DapplePotBlockedError(
                signal=block_sub_check_id,
                reason=block_reason,
                session_id=sid,
            )

        return event

    def _sanitize_text(self, text: str, finding: dict) -> str:
        """Redact the matched sensitive content from a text string."""
        sub_check_id = finding['sub_check_id']
        matched = finding.get('matched_text', '')

        if sub_check_id == 'SID-02a':
            # Replace every PII pattern match individually
            result = text
            for pat in _PII_PATTERNS:
                result = pat.sub('[SANITIZED]', result)
            return result
        elif sub_check_id == 'PI-01c':
            # Replace hex sequences and base64 candidates
            result = _HEX_PATTERN.sub('[SANITIZED]', text)
            result = _BASE64_CANDIDATE.sub('[SANITIZED]', result)
            return result
        elif matched and matched not in ('[encoded content detected]', '[multiple PII patterns detected]'):
            return text.replace(matched, '[SANITIZED]', 1)
        return text

    def _apply_sanitize(self, event: dict, event_type: str, sanitize_findings: list[dict]) -> dict:
        """Return a copy of event with sensitive content redacted from the payload."""
        import copy
        event = copy.deepcopy(event)
        payload = event.get('payload', {})

        if event_type in ('llm_start', 'chat_model_start'):
            messages = payload.get('messages') or []
            for i, msg in enumerate(messages):
                if isinstance(msg, dict) and msg.get('content'):
                    content = str(msg['content'])
                    for finding in sanitize_findings:
                        content = self._sanitize_text(content, finding)
                    messages[i] = {**msg, 'content': content}
            payload['messages'] = messages

        elif event_type == 'llm_end':
            completion = payload.get('completion')
            if completion:
                sanitized = str(completion)
                for finding in sanitize_findings:
                    sanitized = self._sanitize_text(sanitized, finding)
                payload['completion'] = sanitized

        elif event_type == 'tool_start':
            tool_input = payload.get('tool_input')
            if tool_input is not None:
                sanitized = str(tool_input)
                for finding in sanitize_findings:
                    sanitized = self._sanitize_text(sanitized, finding)
                payload['tool_input'] = sanitized

        elif event_type == 'tool_end':
            tool_output = payload.get('tool_output')
            if tool_output is not None:
                sanitized = str(tool_output)
                for finding in sanitize_findings:
                    sanitized = self._sanitize_text(sanitized, finding)
                payload['tool_output'] = sanitized

        event['payload'] = payload
        return event

    def _run(
        self,
        event_type: str,
        payload: dict[str, Any],
        sid: str,
    ) -> list[tuple[dict, str]]:
        """Call backend API for detection, return list of (finding_dict, action)."""
        enabled_checks = dict(self._action_map)
        if self._ea01a_online:
            enabled_checks['EA-01a'] = self._ea01a_action
        if self._ea02b_online and self._max_tool_calls is not None:
            enabled_checks['EA-02b'] = self._ea02b_action

        if not enabled_checks:
            return []

        # Serialize payload to ensure JSON compatibility
        import json
        try:
            serializable_payload = json.loads(json.dumps(payload, default=str))
        except Exception:
            # If serialization fails, convert to string representation
            serializable_payload = {k: str(v) for k, v in payload.items()}

        url = f'{self._client._ingest_url}/v1/sdk/security/online-check'
        try:
            resp = self._http.post(
                url,
                json={
                    'event_type': event_type,
                    'payload': serializable_payload,
                    'session_id': sid,
                    'agent_id': self._client._agent_id,
                    'enabled_checks': enabled_checks,
                    'tool_manifest': self._tool_manifest,
                    'max_tool_calls': self._max_tool_calls,
                    'tool_call_count': self._tool_call_count,
                    'redact_keys': list(self._client._redact_keys),
                    # Governance fields for EA-01c / EA-02a / EA-03b, plus the
                    # remaining per-check policy fields below. Sent every time
                    # so the server never has to hold per-session state — a
                    # check is silent when its field is absent, and enforces
                    # only when its field is non-empty AND the sub-check is
                    # in enabled_checks.
                    'write_namespace':      self._write_namespace,
                    'network_allowlist':    self._network_allowlist,
                    'irreversible_tools':   self._irreversible_tools,
                    'tool_approval_policy': self._tool_approval_policy,
                    'confirm_gate_seen':    self._confirm_gate_seen,
                    'working_directory':    self._working_directory,
                    'connected_llms':       self._connected_llms,
                    'environment':          self._environment,
                    'privilege_scope':      self._privilege_scope,
                    'mcp_endpoints':        self._mcp_endpoints,
                    'sbom_allowlist':       self._sbom_allowlist,
                    'connected_agents':     self._connected_agents,
                    'operating_hours':      self._operating_hours,
                },
                headers={'Authorization': f'Bearer {self._client._sdk_key}'},
                timeout=5,
            )
            resp.raise_for_status()
            findings_list = resp.json().get('findings', [])

            # Convert backend response to (finding, action) tuples
            results: list[tuple[dict, str]] = []
            for f in findings_list:
                action = f.pop('action', 'alert')
                results.append((f, action))

            return results
        except Exception as exc:
            return self._on_api_failure(enabled_checks, sid, exc)

    def _on_api_failure(
        self,
        enabled_checks: dict[str, str],
        sid: str,
        exc: Exception,
    ) -> list[tuple[dict, str]]:
        """Handle an unreachable online-check backend.

        Always emits a security_availability_error event to the buffer so the
        audit trail records the failure, then returns [] — the caller
        (evaluate) treats it as "no findings" and lets the session continue.
        """
        availability_event = {
            'dp_event_type': 'security_availability_error',
            'event_id': str(uuid.uuid4()),
            'dp_session_id': sid,
            'payload': {
                'error': str(exc)[:500],
                'enabled_checks': sorted(enabled_checks.keys()),
            },
        }
        try:
            self._buffer.push(availability_event)
        except Exception:
            logger.exception('failed to push security_availability_error event')

        logger.warning('online-check call failed: %s — session continues', exc)
        return []
