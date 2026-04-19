import datetime


def _now() -> str:
    return datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


class TraceAdapter:
    def __init__(self, tenant_id: str, agent_id: str, framework: str):
        self._tenant_id = tenant_id
        self._agent_id = agent_id
        self._framework = framework

    def _base(self, session_id: str, event_type: str) -> dict:
        return {
            'dp_tenant_id':      self._tenant_id,
            'dp_agent_id':       self._agent_id,
            'dp_session_id':     session_id,
            'dp_event_type':     event_type,
            'dp_schema_version': '2',
            'dp_sampled':        True,
            'dp_framework':      self._framework,
            'ts':                _now(),
            'payload':           {},
        }

    def session_start(self, session_id: str, user_id=None, metadata=None) -> dict:
        e = self._base(session_id, 'session_start')
        e['payload'] = {'session_id': session_id, 'framework': self._framework, 'agent_id': self._agent_id}
        if user_id:
            e['payload']['user_id'] = user_id
        if metadata:
            e['payload']['metadata'] = metadata
        return e

    def session_end(self, session_id: str, output=None, latency_ms=None, total_tokens=None) -> dict:
        e = self._base(session_id, 'session_end')
        e['payload'] = {}
        if output is not None:
            e['payload']['output'] = output
        if latency_ms is not None:
            e['payload']['latency_ms'] = latency_ms
        if total_tokens is not None:
            e['payload']['total_tokens'] = total_tokens
        return e

    def session_error(self, session_id: str, error_type: str, error_message: str, traceback: str = None) -> dict:
        e = self._base(session_id, 'session_error')
        e['payload'] = {'error_type': error_type, 'error_message': error_message}
        if traceback:
            e['payload']['traceback'] = traceback
        return e

    def node_start(self, session_id: str, node_name: str, parent_span_id=None, input=None) -> dict:
        e = self._base(session_id, 'node_start')
        e['payload'] = {'node_name': node_name}
        if parent_span_id:
            e['payload']['parent_span_id'] = parent_span_id
        if input is not None:
            e['payload']['input'] = input
        return e

    def node_end(self, session_id: str, node_name: str, output=None, latency_ms=None) -> dict:
        e = self._base(session_id, 'node_end')
        e['payload'] = {'node_name': node_name}
        if output is not None:
            e['payload']['output'] = output
        if latency_ms is not None:
            e['payload']['latency_ms'] = latency_ms
        return e

    def node_error(self, session_id: str, node_name: str, error_type: str, error_message: str, traceback: str = None) -> dict:
        e = self._base(session_id, 'node_error')
        e['payload'] = {'node_name': node_name, 'error_type': error_type, 'error_message': error_message}
        if traceback:
            e['payload']['traceback'] = traceback
        return e

    def llm_start(self, session_id: str, model: str, messages: list,
                  temperature=None, max_tokens=None) -> dict:
        e = self._base(session_id, 'llm_start')
        e['payload'] = {'model': model, 'messages': messages}
        if temperature is not None:
            e['payload']['temperature'] = temperature
        if max_tokens is not None:
            e['payload']['max_tokens'] = max_tokens
        return e

    def llm_end(self, session_id: str, completion: str, finish_reason=None, usage=None) -> dict:
        e = self._base(session_id, 'llm_end')
        e['payload'] = {'completion': completion}
        if finish_reason:
            e['payload']['finish_reason'] = finish_reason
        if usage:
            e['payload']['usage'] = usage
        return e

    def tool_start(self, session_id: str, tool_name: str, tool_input) -> dict:
        e = self._base(session_id, 'tool_start')
        e['payload'] = {'tool_name': tool_name, 'tool_input': tool_input}
        return e

    def tool_end(self, session_id: str, tool_name: str, tool_output, latency_ms=None) -> dict:
        e = self._base(session_id, 'tool_end')
        e['payload'] = {'tool_name': tool_name, 'tool_output': tool_output}
        if latency_ms is not None:
            e['payload']['latency_ms'] = latency_ms
        return e
