"""Online security interceptor for dapplepot-sdk.

Mirrors the langgraph-sdk OnlineDetector, adapted to the dapplepot-sdk event
format (dp_event_type / dp_session_id / payload).

11 onlineCapable sub-checks (from signalRegistry.ts):
  PI-01a  PI-01b  PI-01c  PI-02a  PI-05a  PI-08a   (injection, input-side)
  SID-01a  SID-01c  SID-02a                          (data disclosure, output-side)
  EA-01a  EA-02b                                     (excessive agency, tool_start)
"""
from __future__ import annotations

import base64
import math
import re
import logging
from typing import Any

logger = logging.getLogger(__name__)

# ─── Pattern constants (mirrors langgraph-sdk online_detector.py) ─────────────

_ROLE_OVERRIDE_PATTERNS = [
    re.compile(r"(?i)(ignore|disregard|forget).{0,30}(previous|prior|above|system).{0,30}(instruction|prompt|message)"),
    re.compile(r"(?i)(pretend|act|behave|you are now|you are a).{0,40}(without|no|ignore).{0,30}(restriction|limit|filter|rule)"),
    re.compile(r"(?i)(you (must|should|shall|will)).{0,40}(do|execute|perform|run)"),
    re.compile(r"(?i)(new (instruction|task|directive|command))"),
    re.compile(r"(?i)(override|bypass|circumvent).{0,30}(filter|restriction|policy)"),
]

_DELIMITER_PATTERNS = re.compile(
    r"(?i)\[system\]|\<system\>|###\s*system|</s>|<\|im_start\|>|<\|im_end\|>"
    r"|```\s*system|---\s*system\s*---|<<SYS>>|\[INST\]"
)

_HEX_PATTERN = re.compile(r"(?:\\x[0-9a-f]{2}){4,}", re.IGNORECASE)
_BASE64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

_SECRET_PATTERNS = [
    re.compile(r"(?i)(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35})"),
    re.compile(r"(?i)(password|passwd|secret|api[_\-]key)\s*[:=]\s*\S{8,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"),
]

_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")

_PII_PATTERNS = [
    re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
]

_CODE_INJECTION = [
    re.compile(r"(?i)(import\s+os|import\s+subprocess|__import__|eval\s*\(|exec\s*\()"),
    re.compile(r"(?i)(require\s*\(\s*['\"]child_process|\.exec\s*\(|spawn\s*\()"),
]

_INDIRECT_INJECTION = [
    re.compile(r"(?i)(ignore|disregard|forget).{0,30}(instruction|prompt|rule)"),
    re.compile(r"(?i)(you (must|should|shall|will)).{0,40}(do|execute|perform|run)"),
    re.compile(r"(?i)(new (instruction|task|directive|command))"),
    re.compile(r"(?i)(override|bypass|circumvent).{0,30}(filter|restriction|policy)"),
]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _char_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    total = len(text)
    return -sum((v / total) * math.log2(v / total) for v in counts.values())


def _is_base64_encoded(text: str) -> bool:
    for m in _BASE64_CANDIDATE.finditer(text):
        candidate = m.group()
        try:
            decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
            if len(decoded) > 10 and any(p.search(decoded) for p in _ROLE_OVERRIDE_PATTERNS):
                return True
        except Exception:
            pass
    return False


# ─── Per-sub-check detector functions ─────────────────────────────────────────
# Each returns a partial finding dict (just the detection-specific fields) or None.

def _check_pi01a(content: str) -> dict | None:
    for pat in _ROLE_OVERRIDE_PATTERNS:
        m = pat.search(content)
        if m:
            return {
                'owasp_signal_id': 'OW-LLM01', 'sub_check_id': 'PI-01a',
                'check_label': 'Role-override phrase match', 'check_score': 85,
                'category': 'prompt_injection', 'severity': 'high',
                'matched_text': m.group()[:200], 'confidence_tier': 'high',
            }
    return None


def _check_pi01b(content: str) -> dict | None:
    m = _DELIMITER_PATTERNS.search(content)
    if m:
        return {
            'owasp_signal_id': 'OW-LLM01', 'sub_check_id': 'PI-01b',
            'check_label': 'Delimiter smuggling', 'check_score': 90,
            'category': 'prompt_injection', 'severity': 'critical',
            'matched_text': m.group()[:200], 'confidence_tier': 'deterministic',
        }
    return None


def _check_pi01c(content: str) -> dict | None:
    if _HEX_PATTERN.search(content) or _is_base64_encoded(content):
        return {
            'owasp_signal_id': 'OW-LLM01', 'sub_check_id': 'PI-01c',
            'check_label': 'Encoded / obfuscated payload', 'check_score': 75,
            'category': 'prompt_injection', 'severity': 'high',
            'matched_text': '[encoded content detected]', 'confidence_tier': 'high',
        }
    return None


def _check_pi02a(content: str) -> dict | None:
    for pat in _INDIRECT_INJECTION:
        m = pat.search(content)
        if m:
            return {
                'owasp_signal_id': 'OW-LLM01', 'sub_check_id': 'PI-02a',
                'check_label': 'Web-fetched content with injection pattern', 'check_score': 70,
                'category': 'prompt_injection', 'severity': 'high',
                'matched_text': m.group()[:200], 'confidence_tier': 'high',
            }
    return None


def _check_pi05a(content: str) -> dict | None:
    for pat in _CODE_INJECTION:
        m = pat.search(content)
        if m:
            return {
                'owasp_signal_id': 'OW-LLM01', 'sub_check_id': 'PI-05a',
                'check_label': 'Code injection pattern in prompt', 'check_score': 80,
                'category': 'prompt_injection', 'severity': 'high',
                'matched_text': m.group()[:200], 'confidence_tier': 'high',
            }
    return None


def _check_pi08a(content: str) -> dict | None:
    if len(content) > 80:
        tail = content[-60:]
        if _char_entropy(tail) > 4.5:
            return {
                'owasp_signal_id': 'OW-LLM01', 'sub_check_id': 'PI-08a',
                'check_label': 'Adversarial suffix (high-entropy tail)', 'check_score': 75,
                'category': 'prompt_injection', 'severity': 'high',
                'matched_text': tail[:200], 'confidence_tier': 'medium',
            }
    return None


def _check_sid01a(content: str) -> dict | None:
    for pat in _SECRET_PATTERNS:
        m = pat.search(content)
        if m:
            return {
                'owasp_signal_id': 'OW-LLM02', 'sub_check_id': 'SID-01a',
                'check_label': 'API key / token pattern in output', 'check_score': 95,
                'category': 'data_disclosure', 'severity': 'critical',
                'matched_text': m.group()[:200], 'confidence_tier': 'deterministic',
            }
    return None


def _check_sid01c(content: str) -> dict | None:
    m = _JWT_PATTERN.search(content)
    if m:
        return {
            'owasp_signal_id': 'OW-LLM02', 'sub_check_id': 'SID-01c',
            'check_label': 'JWT / session token in agent message', 'check_score': 90,
            'category': 'data_disclosure', 'severity': 'critical',
            'matched_text': m.group()[:200], 'confidence_tier': 'deterministic',
        }
    return None


def _check_sid02a(content: str) -> dict | None:
    hits = sum(1 for pat in _PII_PATTERNS if pat.search(content))
    if hits >= 2:
        return {
            'owasp_signal_id': 'OW-LLM02', 'sub_check_id': 'SID-02a',
            'check_label': 'Name + email + phone co-occurrence', 'check_score': 75,
            'category': 'data_disclosure', 'severity': 'high',
            'matched_text': '[multiple PII patterns detected]', 'confidence_tier': 'high',
        }
    return None


# ─── Dispatch tables ──────────────────────────────────────────────────────────

_CHECKER_MAP: dict[str, Any] = {
    'PI-01a':  _check_pi01a,
    'PI-01b':  _check_pi01b,
    'PI-01c':  _check_pi01c,
    'PI-02a':  _check_pi02a,
    'PI-05a':  _check_pi05a,
    'PI-08a':  _check_pi08a,
    'SID-01a': _check_sid01a,
    'SID-01c': _check_sid01c,
    'SID-02a': _check_sid02a,
}

_CHECK_EVENT_TYPES: dict[str, frozenset[str]] = {
    'PI-01a':  frozenset({'llm_start', 'tool_start'}),
    'PI-01b':  frozenset({'llm_start', 'tool_start'}),
    'PI-01c':  frozenset({'llm_start', 'tool_start'}),
    'PI-02a':  frozenset({'tool_end'}),
    'PI-05a':  frozenset({'llm_start', 'tool_start'}),
    'PI-08a':  frozenset({'llm_start'}),
    'SID-01a': frozenset({'llm_end', 'tool_end'}),
    'SID-01c': frozenset({'llm_end', 'tool_end'}),
    'SID-02a': frozenset({'llm_end', 'tool_end'}),
}

ONLINE_CAPABLE_SUB_CHECKS: frozenset[str] = frozenset(_CHECKER_MAP.keys())


def _extract_content(event_type: str, payload: dict[str, Any]) -> list[str]:
    """Extract text blobs to scan from the event payload."""
    texts: list[str] = []
    if event_type in ('llm_start', 'chat_model_start'):
        for msg in payload.get('messages') or []:
            content = msg.get('content', '') if isinstance(msg, dict) else str(msg)
            if content:
                texts.append(str(content))
    elif event_type == 'llm_end':
        c = payload.get('completion')
        if c:
            texts.append(str(c))
    elif event_type == 'tool_start':
        ti = payload.get('tool_input')
        if ti:
            texts.append(str(ti))
    elif event_type == 'tool_end':
        to = payload.get('tool_output')
        if to:
            texts.append(str(to))
    return texts


# ─── Interceptor ──────────────────────────────────────────────────────────────

class OnlineCheckInterceptor:
    """Runs online sub-checks per event.

    Instantiated once per DapplePot instance.
    _action_map: { sub_check_id → action }
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

    # kept for backwards compat with control_channel
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

    def evaluate(self, event: dict) -> None:
        if not self.has_active:
            return

        et      = event.get('dp_event_type', '')
        payload = event.get('payload', {})
        sid     = event.get('dp_session_id', '')

        findings = self._run(et, payload, sid)
        if not findings:
            return

        block_sub_check_id = None
        block_reason       = None
        should_terminate   = False

        for finding, action in findings:
            security_event = {
                **event,
                'dp_event_type': 'security_finding',
                'payload': {
                    **payload,
                    'signal':        finding['sub_check_id'],
                    'reason':        finding.get('matched_text', ''),
                    'action_taken':  action,
                    **finding,
                },
            }
            self._buffer.push_sync(security_event)

            if action == 'terminate_session':
                should_terminate = True
            elif action == 'block_call' and block_sub_check_id is None:
                block_sub_check_id = finding['sub_check_id']
                block_reason       = finding.get('matched_text', '')
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
    ) -> list[tuple[dict, str]]:
        """Return list of (finding_dict, action) for every check that fires."""
        results: list[tuple[dict, str]] = []

        if event_type == 'tool_start':
            self._tool_call_count += 1

            # EA-01a: tool manifest enforcement
            if self._ea01a_online and self._tool_manifest:
                tool_name: str = payload.get('tool_name', '') or ''
                if tool_name and tool_name not in self._tool_manifest:
                    results.append(({
                        'owasp_signal_id': 'OW-LLM06', 'sub_check_id': 'EA-01a',
                        'check_label': 'Tool not in approved manifest invoked',
                        'check_score': 80,
                        'category': 'excessive_agency', 'severity': 'high',
                        'matched_text': tool_name[:200], 'confidence_tier': 'deterministic',
                        'detection_phase': 'online',
                    }, self._ea01a_action))

            # EA-02b: max tool calls per session
            if self._max_tool_calls is not None and self._tool_call_count > self._max_tool_calls:
                excess = self._tool_call_count - self._max_tool_calls
                check_score = min(65 + excess * 2, 85)
                results.append(({
                    'owasp_signal_id': 'OW-LLM06', 'sub_check_id': 'EA-02b',
                    'check_label': 'Tool calls exceed configured session limit',
                    'check_score': check_score,
                    'category': 'excessive_agency', 'severity': 'high',
                    'matched_text': f'call #{self._tool_call_count} (limit: {self._max_tool_calls})',
                    'confidence_tier': 'deterministic', 'detection_phase': 'online',
                }, self._ea02b_action))

        # Content-based checks
        if not self._action_map:
            return results
        texts = _extract_content(event_type, payload)
        if not texts:
            return results

        for sub_check_id, action in self._action_map.items():
            allowed = _CHECK_EVENT_TYPES.get(sub_check_id)
            if allowed and event_type not in allowed:
                continue
            checker = _CHECKER_MAP.get(sub_check_id)
            if not checker:
                continue
            for text in texts:
                finding = checker(text)
                if finding:
                    finding['detection_phase'] = 'online'
                    results.append((finding, action))
                    break  # one finding per sub-check per event

        return results
