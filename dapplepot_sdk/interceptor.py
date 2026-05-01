"""Online check interceptor for dapplepot-sdk.

Evaluates events against configured security checks and communicates with the backend.
"""
from __future__ import annotations

import logging
from typing import Any

import requests
from requests.adapters import HTTPAdapter

from .scrubbers import RegexScrubber

logger = logging.getLogger(__name__)

ONLINE_CAPABLE_SUB_CHECKS: frozenset[str] = frozenset({
    'PI-01a', 'PI-01b', 'PI-01c', 'PI-02a', 'PI-05a', 'PI-08a',
    'SID-01a', 'SID-01c', 'SID-02a',
    'EA-01a', 'EA-02b',
})

# Actions that require a synchronous call — agent cannot continue without the answer.
_BLOCKING_ACTIONS: frozenset[str] = frozenset({'block_call', 'terminate_session'})

# Actions that modify the event (sanitize/redact)
_SCRUBBING_ACTIONS: frozenset[str] = frozenset({'sanitize'})


def _make_session(pool_connections: int = 4, pool_maxsize: int = 10) -> requests.Session:
    """Create a requests.Session with connection pooling so TCP connections are reused."""
    s = requests.Session()
    adapter = HTTPAdapter(pool_connections=pool_connections, pool_maxsize=pool_maxsize)
    s.mount('http://', adapter)
    s.mount('https://', adapter)
    return s


class OnlineCheckInterceptor:
    """Thin HTTP client that calls the security service for online checks.

    Instantiated once per DapplePot instance. Reuses a single requests.Session
    (connection pooling) so the TCP handshake only happens once at startup.
    """

    def __init__(self, check_actions: dict[str, str], buffer, client) -> None:
        self._buffer = buffer
        self._client = client
        self._action_map: dict[str, str] = {}
        self._ea01a_online: bool = False
        self._ea01a_action: str = 'block_call'
        self._tool_manifest: list[str] = []
        self._max_tool_calls: int | None = None
        self._ea02b_action: str = 'alert'
        self._tool_call_count: int = 0
        self._http: requests.Session = _make_session()
        self._scrubber: RegexScrubber = RegexScrubber()
        self.update_active(check_actions)

    def update_active(self, action_map: dict[str, str]) -> None:
        """Replace the active sub-check→action map (called by control channel)."""
        self._ea01a_online = 'EA-01a' in action_map
        if 'EA-01a' in action_map:
            self._ea01a_action = action_map['EA-01a']
        if 'EA-02b' in action_map:
            self._ea02b_action = action_map['EA-02b']
        self._action_map = {
            sid: action
            for sid, action in action_map.items()
            if sid in ONLINE_CAPABLE_SUB_CHECKS
        }

    def update_check_actions(self, check_actions: dict[str, str]) -> None:
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
        self._tool_call_count = 0

    @property
    def has_active(self) -> bool:
        return (
            bool(self._action_map)
            or (self._ea01a_online and bool(self._tool_manifest))
            or self._max_tool_calls is not None
        )

    @property
    def _has_blocking_checks(self) -> bool:
        """True if any enabled check has a blocking action (block_call or terminate_session)."""
        for action in self._action_map.values():
            if action in _BLOCKING_ACTIONS:
                return True
        if self._ea01a_online and self._ea01a_action in _BLOCKING_ACTIONS:
            return True
        if self._max_tool_calls is not None and self._ea02b_action in _BLOCKING_ACTIONS:
            return True
        return False

    def evaluate(self, event: dict) -> None:
        if not self.has_active:
            return

        et      = event.get('dp_event_type', '')
        payload = event.get('payload', {})
        sid     = event.get('dp_session_id', '')

        # Track tool call count locally — needed for EA-02b
        if et == 'tool_start':
            self._tool_call_count += 1

        findings = self._run(et, payload, sid)
        if not findings:
            return

        block_sub_check_id = None
        block_reason       = None
        should_terminate   = False

        for finding in findings:
            action = finding.get('action', 'alert')

            security_event = {
                **event,
                'dp_event_type': 'security_finding',
                'payload': {
                    **payload,
                    'signal':       finding['sub_check_id'],
                    'reason':       finding.get('matched_text', ''),
                    'action_taken': action,
                    **finding,
                },
            }
            self._buffer.push_sync(security_event)

            if action == 'terminate_session':
                should_terminate = True
            elif action == 'block_call' and block_sub_check_id is None:
                block_sub_check_id = finding['sub_check_id']
                block_reason       = finding.get('matched_text', '')
            elif action == 'sanitize':
                # Scrub happens client-side using RegexScrubber.
                # Both local ref and event dict are updated so chained
                # sanitize findings don't re-scrub the original payload.
                payload = self._scrubber.scrub_value(payload)
                event['payload'] = payload
            else:
                logger.warning(
                    'DapplePot [%s] %s — %s',
                    action, finding['sub_check_id'], finding.get('matched_text', ''),
                )

        if should_terminate:
            from dapplepot_sdk import DapplePotSessionTerminatedError
            raise DapplePotSessionTerminatedError('Session terminated by security policy')
        if block_sub_check_id:
            from dapplepot_sdk import DapplePotBlockedError
            raise DapplePotBlockedError(
                signal=block_sub_check_id,
                reason=block_reason,
                session_id=sid,
            )

    def _run(
        self,
        event_type: str,
        payload: dict[str, Any],
        sid: str,
    ) -> list[dict]:
        """Call POST /v1/sdk/security/online-check on the API and return findings list."""
        enabled_checks = dict(self._action_map)
        if self._ea01a_online:
            enabled_checks['EA-01a'] = self._ea01a_action
        if self._max_tool_calls is not None:
            enabled_checks['EA-02b'] = self._ea02b_action

        if not enabled_checks:
            return []

        url = f'{self._client._ingest_url}/v1/sdk/security/online-check'
        try:
            resp = self._http.post(
                url,
                json={
                    'event_type':      event_type,
                    'payload':         payload,
                    'session_id':      sid,
                    'agent_id':        self._client._agent_id,
                    'tenant_id':       self._client._tenant_id,
                    'enabled_checks':  enabled_checks,
                    'tool_manifest':   self._tool_manifest,
                    'max_tool_calls':  self._max_tool_calls,
                    'tool_call_count': self._tool_call_count,
                },
                headers={'Authorization': f'Bearer {self._client._sdk_key}'},
                timeout=5,
            )
            resp.raise_for_status()
            return resp.json().get('findings', [])
        except Exception as exc:
            logger.warning('online-check call failed: %s — skipping', exc)
            return []