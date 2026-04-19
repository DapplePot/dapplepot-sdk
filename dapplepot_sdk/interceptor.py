import re
import logging

logger = logging.getLogger(__name__)

_INJECTION = [
    r'ignore\s+(previous|all|above)\s+instructions',
    r'you\s+are\s+now\s+',
    r'disregard\s+(your|the)\s+(previous|system|original)',
    r'forget\s+(everything|all|your)',
    r'act\s+as\s+(if|a|an)\s+',
    r'jailbreak',
    r'do\s+anything\s+now',
    r'pretend\s+(you\s+are|to\s+be)',
]

_UNSAFE_OUTPUT = [
    r'<script[^>]*>',
    r'\beval\s*\(',
    r'\bexec\s*\(',
    r'os\.system\s*\(',
    r'subprocess\.(call|run|Popen)\s*\(',
    r'\brm\s+-rf\b',
    r'\bDROP\s+TABLE\b',
]

_PII = [
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    r'\b\d{3}-\d{2}-\d{4}\b',
    r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
    r'\bAKIA[0-9A-Z]{16}\b',
]

_SENSITIVE = [
    r'(?:password|secret|api_key|token|credential)\s*[:=]\s*\S+',
    r'AKIA[0-9A-Z]{16}',
    r'eyJ[A-Za-z0-9_-]+\.eyJ',
]

_DANGEROUS_TOOL_NAMES = {'bash', 'shell', 'exec', 'eval', 'python_repl', 'terminal', 'cmd'}
_DANGEROUS_ARGS = [r'rm\s+-rf', r';\s*rm\b', r'\|\s*sh\b', r'wget\s+http', r'curl\s+.+-o\b']
_PRIVILEGE = [r'\bsudo\s+', r'chmod\s+777', r'chown\s+root', r'\bsu\s+-\b', r'\bpasswd\b']

# Actions that terminate the call / session (highest severity first)
_BLOCKING_ACTIONS = {'block_call', 'terminate_session'}


def _text(payload: dict, *keys) -> str:
    parts = []
    for key in keys:
        val = payload.get(key, '')
        if isinstance(val, list):
            for m in val:
                if isinstance(m, dict):
                    parts.append(str(m.get('content', '')))
                else:
                    parts.append(str(m))
        elif val:
            parts.append(str(val))
    return ' '.join(parts)


def _match(patterns, text, flags=re.IGNORECASE):
    for p in patterns:
        if re.search(p, text, flags):
            return p
    return None


class OnlineCheckInterceptor:
    def __init__(self, check_actions: dict[str, str], buffer, client):
        # check_actions: {signal_name: action} — only signals with online_detection=true
        self._check_actions = check_actions
        self._buffer = buffer
        self._client = client
        self._node_counts: dict = {}

    def update_check_actions(self, check_actions: dict[str, str]) -> None:
        """Replace the active check→action map (called by control channel)."""
        self._check_actions = check_actions

    def evaluate(self, event: dict) -> None:
        if not self._check_actions:
            return

        et      = event.get('dp_event_type', '')
        payload = event.get('payload', {})
        sid     = event.get('dp_session_id', '')

        block_signal    = None
        block_reason    = None
        should_terminate = False

        for signal, reason in self._dispatch_all(et, payload, sid):
            action = self._check_actions.get(signal, 'alert')
            finding = {
                **event,
                'dp_event_type': 'security_finding',
                'payload': {
                    'signal':       signal,
                    'reason':       reason,
                    'action_taken': action,
                    **payload,
                },
            }
            self._buffer.push_sync(finding)

            if action == 'terminate_session':
                should_terminate = True
            elif action == 'block_call' and block_signal is None:
                block_signal = signal
                block_reason = reason
            else:
                logger.warning('DapplePot [%s] %s – %s', action, signal, reason)

        # terminate_session takes precedence over block_call
        if should_terminate:
            from dapplepot_sdk import DapplePotSessionTerminatedError
            raise DapplePotSessionTerminatedError('Session terminated by security policy')
        if block_signal:
            from dapplepot_sdk import DapplePotBlockedError
            raise DapplePotBlockedError(signal=block_signal, reason=block_reason, session_id=sid)

    def _dispatch_all(self, et, payload, sid):
        """Yield (signal, reason) for every enabled check that fires on this event."""
        checks = self._check_actions  # only iterate signals that are actually enabled

        if 'prompt_injection' in checks and et == 'llm_start':
            s, r = self._prompt_injection(payload)
            if s:
                yield s, r

        if 'insecure_output' in checks and et == 'llm_end':
            s, r = self._insecure_output(payload)
            if s:
                yield s, r

        if 'pii_input' in checks and et in ('llm_start', 'tool_start'):
            s, r = self._pii(payload, 'input')
            if s:
                yield s, r

        if 'pii_output' in checks and et in ('llm_end', 'tool_end'):
            s, r = self._pii(payload, 'output')
            if s:
                yield s, r

        if 'sensitive_data_exfiltration' in checks and et == 'tool_end':
            s, r = self._exfiltration(payload)
            if s:
                yield s, r

        if 'tool_misuse' in checks and et == 'tool_start':
            s, r = self._tool_misuse(payload)
            if s:
                yield s, r

        if 'resource_exhaustion' in checks and et == 'node_start':
            s, r = self._resource_exhaustion(sid, payload)
            if s:
                yield s, r

        if 'privilege_escalation' in checks and et == 'tool_start':
            s, r = self._privilege_escalation(payload)
            if s:
                yield s, r

        if 'unsafe_code_execution' in checks and et == 'tool_start':
            s, r = self._unsafe_code(payload)
            if s:
                yield s, r

        if 'supply_chain_tool' in checks and et == 'tool_start':
            s, r = self._supply_chain_tool(payload)
            if s:
                yield s, r

    def _prompt_injection(self, payload):
        text = _text(payload, 'messages')
        p = _match(_INJECTION, text)
        return ('prompt_injection', f'Pattern: {p}') if p else (None, None)

    def _insecure_output(self, payload):
        text = _text(payload, 'completion')
        p = _match(_UNSAFE_OUTPUT, text)
        return ('insecure_output', f'Pattern: {p}') if p else (None, None)

    def _pii(self, payload, direction):
        keys = ('messages', 'tool_input') if direction == 'input' else ('completion', 'tool_output')
        text = _text(payload, *keys)
        p = _match(_PII, text, 0)
        sig = f'pii_{direction}'
        return (sig, f'PII detected: {p}') if p else (None, None)

    def _exfiltration(self, payload):
        text = _text(payload, 'tool_output')
        p = _match(_SENSITIVE, text, re.IGNORECASE)
        return ('sensitive_data_exfiltration', f'Sensitive data: {p}') if p else (None, None)

    def _tool_misuse(self, payload):
        text = _text(payload, 'tool_input')
        p = _match(_DANGEROUS_ARGS, text)
        return ('tool_misuse', f'Dangerous argument: {p}') if p else (None, None)

    def _resource_exhaustion(self, sid, payload):
        key = (sid, payload.get('node_name', ''))
        self._node_counts[key] = self._node_counts.get(key, 0) + 1
        count = self._node_counts[key]
        if count > 50:
            return ('resource_exhaustion', f'Node {payload.get("node_name")} called {count} times')
        return None, None

    def _privilege_escalation(self, payload):
        text = _text(payload, 'tool_input')
        p = _match(_PRIVILEGE, text)
        return ('privilege_escalation', f'Pattern: {p}') if p else (None, None)

    def _unsafe_code(self, payload):
        name = payload.get('tool_name', '').lower()
        if not any(d in name for d in _DANGEROUS_TOOL_NAMES):
            return None, None
        text = _text(payload, 'tool_input')
        p = _match(_DANGEROUS_ARGS, text)
        return ('unsafe_code_execution', f'Dangerous code in {name}: {p}') if p else (None, None)

    def _supply_chain_tool(self, payload):
        allowlist = getattr(self._client, '_tool_allowlist', None)
        if allowlist is None:
            return None, None
        name = payload.get('tool_name', '')
        if name not in allowlist:
            return ('supply_chain_tool', f'Unknown tool: {name}')
        return None, None
