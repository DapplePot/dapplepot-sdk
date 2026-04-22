# DapplePot SDK — Agent Index

**Role:** Python SDK for AI agent security & observability. Instruments LangChain/LangGraph, OpenAI, Anthropic, LiteLLM, and LlamaIndex agents to emit structured events to the DapplePot ingest API and run real-time online threat detection.

**Stack:** Python 3.8+, requests, redis (optional for control channel)

---

## Directory Map

```
dapplepot_sdk/
  __init__.py          DapplePot client; DapplePotBlockedError; DapplePotSessionTerminatedError
  buffer.py            Thread-safe event buffer; flushes to POST /v1/ingest/events
  interceptor.py       OnlineCheckInterceptor — 11 sub-check evaluators (hot path)
  adapter.py           Event schema builders: session_start, node_start, llm_start, …
  _langchain.py        DapplePotCallbackHandler — LangChain/LangGraph callbacks
                       Tracks node names by run_id (_node_names dict) — accurate per-node attribution
  openai.py            Drop-in OpenAI proxy — patches openai.chat.completions.create
  anthropic.py         Drop-in Anthropic proxy — patches anthropic.resources.Messages.create
  _litellm.py          LiteLLM success/failure callback handler
  _llama_index.py      LlamaIndex process-wide instrumentation via Settings.callback_manager
  session.py           SessionContext — context manager for scoping OpenAI/Anthropic calls
  control_channel.py   Reserved for future use (Redis pub/sub removed; HTTP polling planned)

tests/
pyproject.toml
.env.example           All env vars documented
```

---

## Event Flow

```
Agent code
  │
  ├─ DapplePotCallbackHandler (LangGraph callbacks)
  │    on_chain_start(parent=None) → session_start
  │    on_chain_start(parent≠None) → node_start (name from run_id map)
  │    on_llm_start / on_chat_model_start → llm_start
  │    on_llm_end → llm_end
  │    on_tool_start → tool_start
  │    on_tool_end → tool_end
  │    on_chain_end(parent=None) → session_end
  │    on_chain_error → session_error
  │
  ├─ openai.py / anthropic.py (drop-in proxies)
  │    patched create() → session_start → llm_start → llm_end → session_end
  │    (session_start/end skipped when inside dp.session() context manager)
  │
  ├─ _litellm.py (callbacks)
  │    on_success → session_start → llm_start → llm_end → session_end
  │    on_failure → session_start → session_error
  │
  ├─ _llama_index.py (CallbackManager)
  │    QUERY/AGENT_STEP start → session_start
  │    LLM start/end → llm_start / llm_end
  │    FUNCTION_CALL/TOOL start/end → tool_start / tool_end
  │    QUERY/AGENT_STEP end → session_end
  │
  ├─ OnlineCheckInterceptor (evaluates every event before it hits the buffer)
  │    → 11 sub-checks evaluated synchronously
  │    → fires security_finding via push_sync (bypasses batch buffer)
  │    → raises DapplePotBlockedError or DapplePotSessionTerminatedError on action
  │
  └─ EventBuffer
       → batch POST to {ingest_url}/v1/ingest/events
         header: Authorization: Bearer {sdk_key}
```

---

## Event Types Sent

| Event | Trigger | Forwarded to Security? |
|-------|---------|----------------------|
| `session_start` | Session opens | ✅ (seeds per-agent config) |
| `node_start` | LangGraph node enters | — |
| `node_end` | LangGraph node exits | — |
| `node_error` | Node-level error | — |
| `llm_start` | LLM call begins | — |
| `llm_end` | LLM call completes | — |
| `tool_start` | Tool call begins | — |
| `tool_end` | Tool call completes | — |
| `security_finding` | Online check fires | ✅ (persisted immediately via push_sync) |
| `session_end` | Session succeeds | ✅ (triggers post-session scoring) |
| `session_error` | Session errors | ✅ (triggers post-session scoring) |

---

## Online Checks (12 sub-checks)

Evaluated synchronously in `OnlineCheckInterceptor` on every event. Config fetched at startup from the API.

| Sub-check | OWASP | Category | Phase | Severity |
|-----------|-------|----------|-------|----------|
| `PI-01a` | OW-LLM01 | prompt_injection | llm_start, tool_start | high |
| `PI-01b` | OW-LLM01 | prompt_injection | llm_start, tool_start | critical |
| `PI-01c` | OW-LLM01 | prompt_injection | llm_start, tool_start | high |
| `PI-02a` | OW-LLM01 | prompt_injection | tool_end | high |
| `PI-05a` | OW-LLM01 | prompt_injection | llm_start, tool_start | high |
| `PI-08a` | OW-LLM01 | prompt_injection | llm_start | high |
| `SID-01a` | OW-LLM02 | data_disclosure | llm_end, tool_end | critical |
| `SID-01c` | OW-LLM02 | data_disclosure | llm_end, tool_end | critical |
| `SID-02a` | OW-LLM02 | data_disclosure | llm_end, tool_end | high |
| `IOH-01a` | OW-LLM05 | output_handling | llm_end, tool_end | critical |
| `EA-01a` | OW-LLM06 | excessive_agency | tool_start | high |
| `EA-02b` | OW-LLM06 | excessive_agency | tool_start | high |

Each finding is emitted as a `security_finding` event with `{sub_check_id, owasp_signal_id, category, severity, check_score, matched_text, confidence_tier, action_taken, detection_phase}`.

### Actions

| Action | Effect |
|--------|--------|
| `alert` | Logs warning; execution continues |
| `sanitize` | Redacts matched content from event payload; execution continues |
| `block_call` | Raises `DapplePotBlockedError(signal, reason, session_id)` |
| `terminate_session` | Raises `DapplePotSessionTerminatedError` |

---

## Startup API Calls

At `DapplePot.__init__`, two blocking GET requests are made:

| Endpoint | What it returns | Used for |
|----------|----------------|----------|
| `GET /v1/sdk/security/agents/{agent_id}/subcheck-config` | `{overrides: {sub_check_id: {online_detection, action}}}` | Activates sub-checks in interceptor |
| `GET /v1/sdk/security/agents/{agent_id}/tool-manifest` | `{tool_manifest: [...], max_tool_calls_per_session: N}` | Powers EA-01a and EA-02b |

Both fail silently (warning log only) — the SDK still runs, just with checks disabled.

---

## Control Channel

The Redis pub/sub control channel (`dapplepot:control:{tenant_id}`) has been removed. The `ControlChannel` class in `control_channel.py` is now a stub. Live config updates will be delivered via `GET /v1/control/commands` (HTTP polling — planned). The `redis_url` constructor parameter has been removed.

---

## Constructor Parameters

No environment variables are read. All config is passed directly:

| Parameter | Required | Default | Notes |
|-----------|----------|---------|-------|
| `sdk_key` | ✅ | — | Sent as `Authorization: Bearer` header |
| `tenant_id` | ✅ | — | Used in event payloads |
| `agent_id` | ✅ | — | Used to fetch sub-check config and tool manifest |
| `ingest_url` | — | `http://localhost:3000` | SDK appends `/v1/ingest/events` |
| `sample_rate` | — | `1.0` | 0.0–1.0; checked per session |
| `pii_scrubber` | — | `None` | Must implement `.scrub_value(payload)` |
| `redact_keys` | — | `None` | `list[str]` of payload keys to replace with `[REDACTED]` |
| `flush_interval_ms` | — | `500` | Buffer flush interval |
| `flush_batch_size` | — | `100` | Max events per flush batch |

---

## Public Methods

| Method | Description |
|--------|-------------|
| `callback_handler(session_id=None)` | Returns a `DapplePotCallbackHandler` for LangChain/LangGraph |
| `instrument_llama_index()` | Process-wide LlamaIndex instrumentation; call once at startup |
| `uninstrument_llama_index()` | Remove LlamaIndex instrumentation |
| `register_litellm_callbacks()` | Register DapplePot as LiteLLM's success/failure callbacks |
| `session(session_id=None)` | Context manager scoping OpenAI/Anthropic calls to one session |
| `shutdown(timeout_ms=5000)` | Flush remaining events and stop background threads |

---

## Finding Specific Code

| Need to... | File |
|-----------|------|
| Add a new online sub-check | `interceptor.py` → add `_check_*` function, register in `_CHECKER_MAP` and `_CHECK_EVENT_TYPES` |
| Change event schema | `adapter.py` → relevant builder method |
| Debug events not reaching API | `buffer.py` → check URL construction and `sdk_key` header |
| Add a new LangChain hook | `_langchain.py` → `DapplePotCallbackHandler.on_*` |
| Add OpenAI/Anthropic tracing | `openai.py` / `anthropic.py` → `_patch()` function |
| Add a new online sub-check (output-side) | `interceptor.py` → add `_check_*` function, register in `_CHECKER_MAP`, `_CHECK_EVENT_TYPES`, and `_ONLINE_CAPABLE_SUB_CHECKS` |
| Change session lifecycle | `session.py` → `SessionContext.__exit__` |
