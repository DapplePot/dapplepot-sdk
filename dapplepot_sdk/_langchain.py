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
    """LangChain / LangGraph callback handler. One instance per session.

    Implements LangChain's ``BaseCallbackHandler`` protocol — each
    ``on_*`` method below is invoked by LangChain/LangGraph at the
    corresponding point in a chain's execution and translates it into a
    DapplePot event via :class:`dapplepot_sdk._adapter.TraceAdapter`.
    Obtain an instance via ``dp.callback_handler()`` rather than
    constructing this directly.
    """

    raise_error = True  # propagate DapplePotBlockedError / SessionTerminatedError instead of swallowing

    def __init__(self, client, session_id: str = None, user_context_id: str = None,
                 user_tenant_id: str = None):
        """Args mirror :meth:`dapplepot_sdk.DapplePot.callback_handler`."""
        if _Base is not object:
            super().__init__()
        self._client = client
        self._session_id = session_id or str(uuid.uuid4())
        self._user_context_id = user_context_id
        self._user_tenant_id = user_tenant_id
        self._adapter = client._adapter('langchain')
        self._t: dict = {}
        self._models: dict = {}
        self._node_names: dict = {}
        self._root_run = None
        self._seq = client._buffer._session_seqs.get(session_id, 0)

    def _emit(self, event: dict) -> None:
        """Attach a monotonic sequence_index to ``event`` and process it."""
        event['sequence_index'] = self._seq
        self._seq += 1
        self._client._process_event(event)

    # ── chain ─────────────────────────────────────────────────────────────────

    def on_chain_start(self, serialized, inputs, **kwargs):
        """LangChain hook: emits session_start for the root run, node_start otherwise."""
        run_id = str(kwargs.get('run_id', uuid.uuid4()))
        parent = kwargs.get('parent_run_id')
        self._t[run_id] = time.time()

        if parent is None:
            self._root_run = run_id
            last_seq = self._client._fetch_session_last_seq(self._session_id)
            if last_seq == -1:
                from dapplepot_sdk import DapplePotSessionTerminatedError
                raise DapplePotSessionTerminatedError('Session permanently terminated by security policy')
            if last_seq is not None:
                self._seq = last_seq + 1
            sampled = self._client._should_sample()
            self._client._buffer.set_sampled(self._session_id, sampled)
            initial = (
                first_user_text(inputs.get("messages", [])) if isinstance(inputs, dict) and "messages" in inputs
                else inputs.get("input") if isinstance(inputs, dict) and "input" in inputs
                else str(inputs) if isinstance(inputs, str) and inputs
                else None
            )
            self._emit(self._adapter.session_start(
                self._session_id, input=initial,
                user_context_id=self._user_context_id,
                user_tenant_id=self._user_tenant_id,
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
        """LangChain hook: emits session_end for the root run, node_end otherwise."""
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
        """LangChain hook: emits session_error/node_error, skipping DapplePot's own control-flow exceptions."""
        parent = kwargs.get('parent_run_id')
        from dapplepot_sdk import DapplePotSessionTerminatedError, DapplePotBlockedError
        if isinstance(error, (DapplePotSessionTerminatedError, DapplePotBlockedError)):
            # session_error was already emitted and flushed by the interceptor
            return
        if parent is None:
            self._emit(
                self._adapter.session_error(
                    self._session_id,
                    error_type=type(error).__name__,
                    error_message=str(error),
                )
            )
        else:
            run_id = str(kwargs.get('run_id', ''))
            name = self._node_names.pop(run_id, 'chain')
            self._emit(
                self._adapter.node_error(
                    self._session_id, node_name=name,
                    error_type=type(error).__name__,
                    error_message=str(error),
                )
            )

    # ── LLM ──────────────────────────────────────────────────────────────────

    def on_llm_start(self, serialized, prompts, **kwargs):
        """LangChain hook: emits llm_start for plain (non-chat) LLM calls."""
        run_id = str(kwargs.get('run_id', uuid.uuid4()))
        self._t[run_id] = time.time()
        model = (serialized or {}).get('name', 'unknown')
        self._models[run_id] = model
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
        """LangChain hook: emits llm_start for chat-model calls."""
        run_id = str(kwargs.get('run_id', uuid.uuid4()))
        self._t[run_id] = time.time()
        model = (serialized or {}).get('name', 'unknown')
        self._models[run_id] = model
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
        """LangChain hook: emits llm_end with the aggregated completion/usage."""
        run_id = str(kwargs.get('run_id', ''))
        latency_ms = self._elapsed(run_id)
        model = self._models.pop(run_id, 'unknown')
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
                self._session_id, completion=completion, model=model,
                finish_reason=finish_reason, usage=usage,
                latency_ms=latency_ms,
            )
        )

    def on_llm_error(self, error, **kwargs):
        """LangChain hook: emits llm_error; session/node_error is handled by on_chain_error."""
        run_id = str(kwargs.get('run_id', ''))
        latency_ms = self._elapsed(run_id)
        # Close the open llm_start span; on_chain_error handles session/node_error
        self._emit(
            self._adapter.llm_error(
                self._session_id,
                error_type=type(error).__name__,
                error_message=str(error),
                latency_ms=latency_ms,
            )
        )

    # ── tool ──────────────────────────────────────────────────────────────────

    def on_tool_start(self, serialized, input_str, **kwargs):
        """LangChain hook: emits tool_start."""
        run_id = str(kwargs.get('run_id', uuid.uuid4()))
        self._t[run_id] = time.time()
        tool_name = (serialized or {}).get('name', 'unknown')
        self._emit(
            self._adapter.tool_start(self._session_id, tool_name=tool_name, tool_input=input_str)
        )

    def on_tool_end(self, output, **kwargs):
        """LangChain hook: emits tool_end."""
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
        """LangChain hook: emits tool_error, closing the open tool_start span."""
        tool_name = kwargs.get('name', 'unknown')
        # Close the open tool_start span with a tool_error
        self._emit(
            self._adapter.tool_error(
                self._session_id, tool_name=tool_name,
                error_type=type(error).__name__, error_message=str(error),
            )
        )

    # ── agent ─────────────────────────────────────────────────────────────────

    def on_agent_action(self, action, **kwargs):
        """LangChain hook: represents an agent tool decision as a node_start."""
        self._emit(
            self._adapter.node_start(
                self._session_id, node_name=action.tool,
                input=action.tool_input,
            )
        )

    def on_agent_finish(self, finish, **kwargs):
        """LangChain hook: represents agent completion as a node_end."""
        self._emit(
            self._adapter.node_end(
                self._session_id, node_name='agent',
                output=str(finish.return_values),
            )
        )

    # ── helpers ───────────────────────────────────────────────────────────────

    def _elapsed(self, run_id: str):
        """Return elapsed ms since ``run_id`` started, popping its start time."""
        start = self._t.pop(run_id, None)
        return int((time.time() - start) * 1000) if start else None
