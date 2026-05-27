import time
import uuid
import logging

from dapplepot_sdk._adapter import first_user_text

logger = logging.getLogger(__name__)

try:
    from langchain_core.callbacks import BaseCallbackHandler as _Base
except ImportError:
    try:
        from langchain.callbacks.base import BaseCallbackHandler as _Base
    except ImportError:
        _Base = object


class DapplePotCallbackHandler(_Base):
    """LangChain / LangGraph callback handler. One instance per session."""

    raise_error = True  # propagate DapplePotBlockedError / SessionTerminatedError instead of swallowing

    def __init__(self, client, session_id: str = None, user_context_id: str = None):
        if _Base is not object:
            super().__init__()
        self._client = client
        self._session_id = session_id or str(uuid.uuid4())
        self._user_context_id = user_context_id
        self._adapter = client._adapter('langchain')
        self._t: dict = {}
        self._node_names: dict = {}
        self._root_run = None
        self._seq = 0

    def _emit(self, event: dict) -> None:
        event['sequence_index'] = self._seq
        self._seq += 1
        self._client._process_event(event)

    # ── chain ─────────────────────────────────────────────────────────────────

    def on_chain_start(self, serialized, inputs, **kwargs):
        run_id = str(kwargs.get('run_id', uuid.uuid4()))
        parent = kwargs.get('parent_run_id')
        self._t[run_id] = time.time()

        if parent is None:
            self._root_run = run_id
            sampled = self._client._should_sample()
            self._client._buffer.set_sampled(self._session_id, sampled)
            initial = (
                first_user_text(inputs.get("messages", [])) if isinstance(inputs, dict) and "messages" in inputs
                else inputs.get("input") if isinstance(inputs, dict) and "input" in inputs
                else str(inputs) if isinstance(inputs, str) and inputs
                else None
            )
            self._emit(self._adapter.session_start(
                self._session_id, input=initial, user_context_id=self._user_context_id
            ))
        else:
            # LangGraph passes the node name via kwargs['name']; fall back to serialized
            name = (
                kwargs.get('name')
                or (serialized or {}).get('name')
                or ((serialized or {}).get('id') or ['chain'])[-1]
                or 'chain'
            )
            self._node_names[run_id] = name
            self._emit(
                self._adapter.node_start(
                    self._session_id, node_name=name,
                    parent_span_id=str(parent), input=inputs,
                )
            )

    def on_chain_end(self, outputs, **kwargs):
        run_id = str(kwargs.get('run_id', ''))
        parent = kwargs.get('parent_run_id')
        latency_ms = self._elapsed(run_id)

        if parent is None:
            output_text = str(outputs) if outputs else None
            self._emit(
                self._adapter.session_end(self._session_id, output=output_text, latency_ms=latency_ms)
            )
        else:
            name = self._node_names.pop(run_id, 'chain')
            self._emit(
                self._adapter.node_end(
                    self._session_id, node_name=name,
                    output=str(outputs) if outputs else None,
                    latency_ms=latency_ms,
                )
            )

    def on_chain_error(self, error, **kwargs):
        parent = kwargs.get('parent_run_id')
        if parent is None:
            from dapplepot_sdk import DapplePotSessionTerminatedError, DapplePotBlockedError
            if isinstance(error, (DapplePotSessionTerminatedError, DapplePotBlockedError)):
                # session_error was already emitted and flushed by the interceptor
                return
            self._emit(
                self._adapter.session_error(
                    self._session_id,
                    error_type=type(error).__name__,
                    error_message=str(error),
                )
            )

    # ── LLM ──────────────────────────────────────────────────────────────────

    def on_llm_start(self, serialized, prompts, **kwargs):
        run_id = str(kwargs.get('run_id', uuid.uuid4()))
        self._t[run_id] = time.time()
        model = (serialized or {}).get('name', 'unknown')
        messages = [{'role': 'user', 'content': p} for p in prompts]
        params = kwargs.get('invocation_params', {})
        self._emit(
            self._adapter.llm_start(
                self._session_id, model=model, messages=messages,
                temperature=params.get('temperature'),
                max_tokens=params.get('max_tokens'),
            )
        )

    def on_chat_model_start(self, serialized, messages, **kwargs):
        run_id = str(kwargs.get('run_id', uuid.uuid4()))
        self._t[run_id] = time.time()
        model = (serialized or {}).get('name', 'unknown')
        formatted = []
        for msg_list in messages:
            for msg in msg_list:
                formatted.append({
                    'role': getattr(msg, 'type', 'user'),
                    'content': getattr(msg, 'content', str(msg)),
                })
        params = kwargs.get('invocation_params', {})
        self._emit(
            self._adapter.llm_start(
                self._session_id, model=model, messages=formatted,
                temperature=params.get('temperature'),
                max_tokens=params.get('max_tokens'),
            )
        )

    def on_llm_end(self, response, **kwargs):
        run_id = str(kwargs.get('run_id', ''))
        latency_ms = self._elapsed(run_id)
        completion = ''
        finish_reason = None
        usage = None
        if response and response.generations:
            for gen_list in response.generations:
                for gen in gen_list:
                    completion += getattr(gen, 'text', '')
                    if getattr(gen, 'generation_info', None):
                        finish_reason = gen.generation_info.get('finish_reason')
        if getattr(response, 'llm_output', None):
            tok = response.llm_output.get('token_usage', {})
            if tok:
                usage = {
                    'prompt_tokens': tok.get('prompt_tokens'),
                    'completion_tokens': tok.get('completion_tokens'),
                }
        self._emit(
            self._adapter.llm_end(
                self._session_id, completion=completion,
                finish_reason=finish_reason, usage=usage,
            )
        )

    def on_llm_error(self, error, **kwargs):
        self._emit(
            self._adapter.node_error(
                self._session_id, node_name='llm',
                error_type=type(error).__name__, error_message=str(error),
            )
        )

    # ── tool ──────────────────────────────────────────────────────────────────

    def on_tool_start(self, serialized, input_str, **kwargs):
        run_id = str(kwargs.get('run_id', uuid.uuid4()))
        self._t[run_id] = time.time()
        tool_name = (serialized or {}).get('name', 'unknown')
        self._emit(
            self._adapter.tool_start(self._session_id, tool_name=tool_name, tool_input=input_str)
        )

    def on_tool_end(self, output, **kwargs):
        run_id = str(kwargs.get('run_id', ''))
        tool_name = kwargs.get('name', 'unknown')
        latency_ms = self._elapsed(run_id)
        self._emit(
            self._adapter.tool_end(
                self._session_id, tool_name=tool_name,
                tool_output=output, latency_ms=latency_ms,
            )
        )

    def on_tool_error(self, error, **kwargs):
        self._emit(
            self._adapter.node_error(
                self._session_id, node_name='tool',
                error_type=type(error).__name__, error_message=str(error),
            )
        )

    # ── agent ─────────────────────────────────────────────────────────────────

    def on_agent_action(self, action, **kwargs):
        self._emit(
            self._adapter.node_start(
                self._session_id, node_name=action.tool,
                input=action.tool_input,
            )
        )

    def on_agent_finish(self, finish, **kwargs):
        self._emit(
            self._adapter.node_end(
                self._session_id, node_name='agent',
                output=str(finish.return_values),
            )
        )

    # ── helpers ───────────────────────────────────────────────────────────────

    def _elapsed(self, run_id: str):
        start = self._t.pop(run_id, None)
        return int((time.time() - start) * 1000) if start else None
