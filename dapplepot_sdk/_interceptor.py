"""Event evaluation pipeline."""
from __future__ import annotations

import logging
import uuid
import re
from typing import Any

import requests
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)

_ONLINE_CAPABLE_SUB_CHECKS: frozenset[str] = frozenset({
    'PI-01a', 'PI-01b', 'PI-01c', 'PI-02a', 'PI-05a', 'PI-08a',
    'SID-01a', 'SID-01c', 'SID-02a',
    'IOH-01a',
    'EA-01a', 'EA-02b',
})

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

    def reset_session_state(self) -> None:
        """Reset per-session counters (e.g. tool_call_count) for a new session."""
        self._tool_call_count = 0

    @property
    def has_active(self) -> bool:
        """Whether any online check is currently active and worth evaluating events against."""
        return (
            bool(self._action_map)
            or (self._ea01a_online and bool(self._tool_manifest))
            or (self._ea02b_online and self._max_tool_calls is not None)
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
            raise DapplePotSessionTerminatedError('Session terminated by security policy')
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
            logger.warning('online-check call failed: %s — skipping', exc)
            return []
