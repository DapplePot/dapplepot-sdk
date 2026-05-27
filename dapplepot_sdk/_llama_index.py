import time
import uuid
import logging
from typing import Optional

from dapplepot_sdk._adapter import first_user_text

logger = logging.getLogger(__name__)

_handler_ref = None


def instrument(client, user_context_id: str = None) -> None:
    global _handler_ref
    try:
        from llama_index.core import Settings
        from llama_index.core.callbacks import CallbackManager
    except ImportError:
        raise ImportError(
            "llama_index not installed. Run: pip install 'dapplepot-sdk[llama-index]'"
        )
    handler = _DapplePotLlamaHandler(client, user_context_id=user_context_id)
    Settings.callback_manager = CallbackManager([handler])
    _handler_ref = handler
    logger.debug('LlamaIndex instrumented')


def uninstrument() -> None:
    global _handler_ref
    try:
        from llama_index.core import Settings
        from llama_index.core.callbacks import CallbackManager
        Settings.callback_manager = CallbackManager([])
    except ImportError:
        pass
    _handler_ref = None
    logger.debug('LlamaIndex uninstrumented')


class _DapplePotLlamaHandler:
    def __init__(self, client, user_context_id: str = None):
        self._client = client
        self._user_context_id = user_context_id
        self._adapter = client._adapter('llama_index')
        self._sessions: dict = {}
        self._t: dict = {}
        self._active_query: Optional[str] = None  # session_id of the current root query
        # BaseCallbackHandler attributes consulted by CallbackManager.event()
        self.event_starts_to_ignore: tuple = ()
        self.event_ends_to_ignore: tuple = ()

    # LlamaIndex calls these methods on its CBEventType enum values.
    # We implement the BaseCallbackHandler interface loosely via duck-typing.

    def on_event_start(self, event_type, payload=None, event_id='', **kwargs):
        session_id = self._session_for(event_id, event_type=str(event_type))
        self._t[event_id] = time.time()

        et = str(event_type)
        if 'QUERY' in et or 'AGENT_STEP' in et:
            p = payload or {}
            initial = (
                p.get('query_str')
                or (first_user_text(p.get('messages', [])) if p.get('messages') else None)
                or (str(p['input']) if p.get('input') else None)
            ) or None
            self._client._process_event(
                self._adapter.session_start(
                    session_id, input=initial, user_context_id=self._user_context_id
                )
            )
        elif 'LLM' in et:
            messages = (payload or {}).get('messages', [])
            msgs = [{'role': getattr(m, 'role', 'user'), 'content': str(getattr(m, 'content', m))}
                    for m in messages]
            self._client._process_event(
                self._adapter.llm_start(session_id, model='unknown', messages=msgs)
            )
        elif 'FUNCTION_CALL' in et or 'TOOL' in et:
            tool_name = (payload or {}).get('tool_name', 'unknown')
            tool_input = (payload or {}).get('tool_input', '')
            self._client._process_event(
                self._adapter.tool_start(session_id, tool_name=tool_name, tool_input=tool_input)
            )

    def on_event_end(self, event_type, payload=None, event_id='', **kwargs):
        session_id = self._session_for(event_id, event_type=str(event_type))
        latency_ms = self._elapsed(event_id)
        et = str(event_type)

        if 'QUERY' in et or 'AGENT_STEP' in et:
            output = str((payload or {}).get('response', ''))
            self._client._process_event(
                self._adapter.session_end(session_id, output=output, latency_ms=latency_ms)
            )
            if self._active_query == session_id:
                self._active_query = None
        elif 'LLM' in et:
            response = (payload or {}).get('response', None)
            completion = ''
            if response:
                msg = getattr(response, 'message', None)
                if msg:
                    completion = str(getattr(msg, 'content', ''))
                else:
                    completion = str(response)
            self._client._process_event(
                self._adapter.llm_end(session_id, completion=completion, latency_ms=latency_ms)
            )
        elif 'FUNCTION_CALL' in et or 'TOOL' in et:
            tool_name = (payload or {}).get('tool_name', 'unknown')
            output = str((payload or {}).get('tool_output', ''))
            self._client._process_event(
                self._adapter.tool_end(session_id, tool_name=tool_name,
                                       tool_output=output, latency_ms=latency_ms)
            )

    def start_trace(self, trace_id=None) -> None:
        pass

    def end_trace(self, trace_id=None, trace_map=None) -> None:
        pass

    def _session_for(self, event_id: str, event_type: str = '') -> str:
        if event_id not in self._sessions:
            is_root = 'QUERY' in event_type or 'AGENT_STEP' in event_type
            if is_root or self._active_query is None:
                # Create a new session for root events or when there's no active query
                session_id = str(uuid.uuid4())
                sampled = self._client._should_sample()
                self._client._buffer.set_sampled(session_id, sampled)
                self._sessions[event_id] = session_id
                if is_root:
                    self._active_query = session_id
            else:
                # Child events (LLM, TOOL) reuse the active query's session
                self._sessions[event_id] = self._active_query
        return self._sessions[event_id]

    def _elapsed(self, event_id: str):
        start = self._t.pop(event_id, None)
        return int((time.time() - start) * 1000) if start else None
