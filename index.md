# DapplePot SDK — Agent Index

**Role:** Python SDK for AI agent security & observability. Instruments LangChain/LangGraph agents (and any agent via the context-manager API) to emit structured events to the DapplePot ingest API and run real-time online threat detection.

**Stack:** Python 3.8+, requests, redis (optional for control channel)

---

## Directory Map

```
dapplepot_sdk/
  __init__.py          Public API: Client, Session, LangChainHandler
  buffer.py            Thread-safe event buffer; flushes to POST /v1/ingest/events
  interceptor.py       OnlineCheckInterceptor — 10 OWASP signal evaluators (hot path)
  adapter.py           Event schema builders: session_start, node_start, llm_start, …
  _langchain.py        DapplePotCallbackHandler — LangChain/LangGraph callbacks
                       Tracks node names by run_id (_node_names dict) — accurate per-node attribution
  session.py           SessionContext — context manager for manual instrumentation
  control_channel.py   Redis pub/sub subscriber for live config updates (DAPPLEPOT_REDIS_URL)

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
  │    on_chain_start(parent=None) → session_start → graph_start
  │    on_chain_start(parent≠None) → node_start (name from run_id map)
  │    on_llm_start / on_chat_model_start → llm_start
  │    on_llm_end → llm_end
  │    on_tool_start → tool_start
  │    on_tool_end → tool_end
  │    on_chain_end(parent=None) → session_end → graph_end
  │    on_chain_error → session_error → graph_error
  │
  ├─ OnlineCheckInterceptor (wraps LLM/tool calls)
  │    → 10 OWASP checks evaluated synchronously
  │    → fires security_finding events on detection
  │
  └─ EventBuffer
       → batch POST to {DAPPLEPOT_INGEST_URL}/v1/ingest/events
         header: x-sdk-key: {DAPPLEPOT_SDK_KEY}
```

---

## Event Types Sent

| Event | Trigger | Forwarded to Security? |
|-------|---------|----------------------|
| `graph_start` | Session opens | ✅ (seeds per-agent config) |
| `node_start` | LangGraph node enters | — |
| `node_end` | LangGraph node exits | — |
| `llm_start` | LLM call begins | — |
| `llm_end` | LLM call completes | — |
| `tool_start` | Tool call begins | — |
| `tool_end` | Tool call completes | — |
| `security_finding` | Online check fires | ✅ (persisted immediately) |
| `graph_end` | Session succeeds | ✅ (triggers post-session scoring) |
| `graph_error` | Session errors | ✅ (triggers post-session scoring) |

---

## Online Checks (10 signals)

Evaluated synchronously in `OnlineCheckInterceptor` on every LLM input/output and tool call:

| Signal | OWASP ID | Phase | Severity |
|--------|----------|-------|----------|
| `prompt_injection` | OW-LLM01 | input | high |
| `insecure_output` | OW-LLM09 | output | high |
| `pii_input` | OW-LLM02 | input | medium |
| `pii_output` | OW-LLM02 | output | medium |
| `sensitive_data_exfiltration` | OW-LLM02 | output | high |
| `tool_misuse` | OW-LLM05 | tool | high |
| `resource_exhaustion` | OW-ASI08 | any | medium |
| `privilege_escalation` | OW-ASI05 | tool | critical |
| `unsafe_code_execution` | OW-ASI05 | tool | critical |
| `supply_chain_tool` | OW-ASI04 | tool | high |

Sending format: `{signal, reason, action_taken, ...}` — the security service maps to full OWASP fields via `_ONLINE_SIGNAL_MAP`.

---

## Control Channel

| Redis key | `dapplepot:control:{tenant_id}` (pub/sub) |
|-----------|------------------------------------------|
| URL source | `redis_url` constructor param (default `redis://localhost:6379`) |
| Thread | daemon thread `dp-control`, started in `DapplePot.__init__` |

Supported commands:

| command | Effect |
|---------|--------|
| `terminate_session` | Logs session ID for termination |
| `update_tool_blocklist` | Updates `client._tool_allowlist` |
| `update_sample_rate` | Updates `client._sample_rate` |
| `update_online_checks` | Updates `client._interceptor.update_check_actions({signal: action, …})` |

---

## Constructor Parameters

No environment variables are read. All config is passed directly:

| Parameter | Required | Default | Notes |
|-----------|----------|---------|-------|
| `sdk_key` | ✅ | — | Sent as `Authorization: Bearer` header |
| `tenant_id` | ✅ | — | |
| `agent_id` | ✅ | — | Also used to fetch online check config |
| `ingest_url` | — | `http://localhost:3000` | SDK appends `/v1/ingest/events` |
| `redis_url` | — | `redis://localhost:6379` | Control channel (optional dep) |
| `sample_rate` | — | `1.0` | 0.0–1.0 |

---

## Finding Specific Code

| Need to... | File |
|-----------|------|
| Add a new online check | `interceptor.py` → `OnlineCheckInterceptor._check_*` + register in `_checks` set |
| Change event schema | `adapter.py` → relevant builder method |
| Debug events not reaching API | `buffer.py` → check URL construction, check `DAPPLEPOT_INGEST_URL` |
| Add a new LangChain hook | `_langchain.py` → `DapplePotCallbackHandler.on_*` |
| Change control channel behavior | `control_channel.py` → `_handle()` |
| Change session lifecycle | `session.py` → `SessionContext.__exit__` |
