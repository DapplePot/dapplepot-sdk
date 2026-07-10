import datetime
import uuid


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def first_user_text(messages: list) -> "str | None":
    """Extract the first user message text from a standard messages list."""
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        if msg.get("role") in ("user", "human"):
            content = msg.get("content", "")
            if isinstance(content, str) and content:
                return content
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        t = block.get("text", "")
                        if t:
                            return t
    return None


class TraceAdapter:
    """Builds DapplePot event dicts (the ingest API's wire schema).

    One instance is scoped to a single agent/framework pair (see
    ``DapplePot._adapter()``). Each ``*_start``/``*_end``/``*_error`` method
    below builds one event dict ready to hand to
    ``DapplePot._process_event()`` — it does not send anything over the
    network itself.
    """

    def __init__(self, agent_id: str, framework: str):
        self._agent_id = agent_id
        self._framework = framework

    def _base(self, session_id: str, event_type: str) -> dict:
        """Build the common envelope fields shared by every event type."""
        return {
            'dp_agent_id':       self._agent_id,
            'dp_session_id':     session_id,
            'dp_event_type':     event_type,
            'dp_schema_version': '2',
            'dp_sampled':        True,
            'dp_framework':      self._framework,
            'ts':                _now(),
            'event_id':          str(uuid.uuid4()),
            'payload':           {},
        }

    def session_start(self, session_id: str, user_context_id: str = None, metadata=None,
                      input=None, user_tenant_id: str = None) -> dict:
        """Build a session_start event, emitted on entering dp.session()."""
        e = self._base(session_id, 'session_start')
        if user_context_id:
            e['user_context_id'] = user_context_id
        if user_tenant_id:
            e['user_tenant_id'] = user_tenant_id
        e['payload'] = {'session_id': session_id, 'framework': self._framework, 'agent_id': self._agent_id}
        if user_context_id:
            e['payload']['user_context_id'] = user_context_id
        if user_tenant_id:
            e['payload']['user_tenant_id'] = user_tenant_id
        if metadata:
            e['payload']['metadata'] = metadata
        if input is not None:
            e['payload']['input'] = input
        return e

    def session_end(self, session_id: str, output=None, latency_ms=None, total_tokens=None) -> dict:
        """Build a session_end event, emitted on a clean exit from dp.session()."""
        e = self._base(session_id, 'session_end')
        e['payload'] = {}
        if output is not None:
            e['payload']['output'] = output
        if latency_ms is not None:
            e['payload']['latency_ms'] = latency_ms
        if total_tokens is not None:
            e['payload']['total_tokens'] = total_tokens
        return e

    def session_error(self, session_id: str, error_type: str, error_message: str,
                      traceback: str = None, exit_reason: str = None) -> dict:
        """Build a session_error event, emitted when dp.session() exits via an exception."""
        e = self._base(session_id, 'session_error')
        e['payload'] = {'error_type': error_type, 'error_message': error_message}
        if traceback:
            e['payload']['traceback'] = traceback
        if exit_reason:
            e['payload']['exit_reason'] = exit_reason
        return e

    def node_start(self, session_id: str, node_name: str, parent_span_id=None, input=None) -> dict:
        """Build a node_start event, emitted on entering dp.node()."""
        e = self._base(session_id, 'node_start')
        e['payload'] = {'node_name': node_name}
        if parent_span_id:
            e['payload']['parent_span_id'] = parent_span_id
        if input is not None:
            e['payload']['input'] = input
        return e

    def node_end(self, session_id: str, node_name: str, output=None, latency_ms=None) -> dict:
        """Build a node_end event, emitted on a clean exit from dp.node()."""
        e = self._base(session_id, 'node_end')
        e['payload'] = {'node_name': node_name}
        if output is not None:
            e['payload']['output'] = output
        if latency_ms is not None:
            e['payload']['latency_ms'] = latency_ms
        return e

    def node_error(self, session_id: str, node_name: str, error_type: str, error_message: str, traceback: str = None) -> dict:
        """Build a node_error event, emitted when dp.node() exits via an exception."""
        e = self._base(session_id, 'node_error')
        e['payload'] = {'node_name': node_name, 'error_type': error_type, 'error_message': error_message}
        if traceback:
            e['payload']['traceback'] = traceback
        return e

    def llm_start(self, session_id: str, model: str, messages: list,
                  temperature=None, max_tokens=None, tools=None) -> dict:
        """Build an llm_start event, emitted just before an instrumented LLM call.

        Emits a compact payload — only the essentials of THIS call — instead
        of the full accumulated conversation history that stateful frameworks
        (LangGraph, LangChain, Anthropic / OpenAI tool loops) rebuild for
        every model invocation. Rebuilding + emitting the whole history on
        every call bloats storage quadratically with turn count and buries
        the actual "current input" in noise.

        Compact fields (payload):
            model                       — model id, unchanged
            messages                    — 1-element list containing only the
                                          last user/human/tool message (the
                                          actual input triggering this call).
                                          Same key as before; meaning changed
                                          from "full accumulated history" to
                                          "current turn only".
            n_prior_context_messages    — count of every message elided from
                                          the payload (system prompt + prior
                                          turns). Helps consumers know how
                                          much context was in the model's
                                          window without carrying the bytes.
            temperature / max_tokens / tools — unchanged

        System prompt is deliberately NOT emitted — it's static per agent /
        node, already declared via the agent manifest (which SPL-01a already
        reads for leakage checks), and repeating it in every llm_start would
        multiply storage cost for zero information gain.

        Callers pass the same `messages` list they always did — we take the
        essentials here so no per-adapter changes are needed."""
        e = self._base(session_id, 'llm_start')
        payload: dict = {'model': model}

        if isinstance(messages, list) and messages:
            current = None
            for m in reversed(messages):
                if not isinstance(m, dict):
                    continue
                if m.get('role') in ('user', 'human', 'tool'):
                    current = m
                    break
            if current is not None:
                payload['messages'] = [current]

            counted = 1 if current is not None else 0
            payload['n_prior_context_messages'] = max(0, len(messages) - counted)
        # If messages was empty or non-list, we simply don't include the
        # message fields — the payload is still valid.

        if temperature is not None:
            payload['temperature'] = temperature
        if max_tokens is not None:
            payload['max_tokens'] = max_tokens
        if tools:
            payload['tools'] = tools
        e['payload'] = payload
        return e

    def llm_end(self, session_id: str, completion: str, model: str | None = None, finish_reason=None, usage=None, latency_ms=None, streamed: bool = False) -> dict:
        """Build an llm_end event, emitted after an instrumented LLM call completes."""
        e = self._base(session_id, 'llm_end')
        e['payload'] = {'completion': completion}
        if model:
            e['payload']['model'] = model
        if finish_reason:
            e['payload']['finish_reason'] = finish_reason
        if usage:
            e['payload']['usage'] = usage
        if latency_ms is not None:
            e['payload']['latency_ms'] = latency_ms
        if streamed:
            e['payload']['streamed'] = True
        return e

    def llm_error(self, session_id: str, model: str | None = None, error_type: str = None,
                  error_message: str = None, latency_ms: int = None) -> dict:
        """Build an llm_error event, emitted when an instrumented LLM call raises."""
        e = self._base(session_id, 'llm_error')
        e['payload'] = {}
        if model:
            e['payload']['model'] = model
        if error_type:
            e['payload']['error_type'] = error_type
        if error_message:
            e['payload']['error_message'] = error_message
        if latency_ms is not None:
            e['payload']['latency_ms'] = latency_ms
        return e

    def tool_start(self, session_id: str, tool_name: str, tool_input) -> dict:
        """Build a tool_start event, emitted when a tool call is detected."""
        e = self._base(session_id, 'tool_start')
        e['payload'] = {'tool_name': tool_name, 'tool_input': tool_input}
        return e

    def tool_error(self, session_id: str, tool_name: str, error_message: str,
                   error_type: str = "ToolError", tool_input=None) -> dict:
        """Build a tool_error event, emitted when a tool call fails."""
        e = self._base(session_id, 'tool_error')
        e['payload'] = {'tool_name': tool_name, 'error_type': error_type, 'error_message': error_message}
        if tool_input is not None:
            e['payload']['tool_input'] = tool_input
        return e

    def tool_end(
        self,
        session_id: str,
        tool_name: str,
        tool_output,
        latency_ms=None,
        # ── retrieval telemetry ─────────────────────────────
        # When the tool is a RAG/vector-search call, populate these so the
        # scorer can evaluate DMP-01b, VEW-01a, VEW-03a. All optional; a
        # non-retrieval tool leaves them None. The SDK caller (usually a
        # framework adapter) knows which tools do retrieval.
        embedding_model=None,
        retrieval_distance=None,
        retrieval_similarity=None,
    ) -> dict:
        """Build a tool_end event, emitted when a tool call's result is observed."""
        e = self._base(session_id, 'tool_end')
        e['payload'] = {'tool_name': tool_name, 'tool_output': tool_output}
        if latency_ms is not None:
            e['payload']['latency_ms'] = latency_ms
        if embedding_model is not None:
            e['payload']['embedding_model'] = embedding_model
        if retrieval_distance is not None:
            e['payload']['retrieval_distance'] = retrieval_distance
        if retrieval_similarity is not None:
            e['payload']['retrieval_similarity'] = retrieval_similarity
        return e
