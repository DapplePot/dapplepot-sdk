# dapplepot-sdk

Python SDK for instrumenting LLM agents with DapplePot security observability. Drop-in integration for LangChain/LangGraph agents — sends structured events to the DapplePot API over HTTP.

## Installation

```bash
pip install dapplepot-sdk
# or, for LangChain/LangGraph support:
pip install "dapplepot-sdk[langchain]"
```

## Quick Start

### LangChain / LangGraph (recommended)

```python
import dapplepot_sdk as dp

client = dp.DapplePot(
    sdk_key   = "dp_sk_...",
    tenant_id = "your-tenant-id",
    agent_id  = "your-agent-id",
)

handler = client.callback_handler()
result = graph.invoke({"messages": [...]}, config={"callbacks": [handler]})
```

### Manual (context manager)

```python
import dapplepot_sdk as dp

client = dp.DapplePot(
    sdk_key   = "dp_sk_...",
    tenant_id = "your-tenant-id",
    agent_id  = "your-agent-id",
)

with client.session() as session:
    result = my_agent(session_id=session.session_id)
```

## Constructor

```python
dp.DapplePot(
    sdk_key,          # required — your SDK key from the DapplePot UI
    tenant_id,        # required — your tenant ID
    agent_id,         # required — the agent being instrumented
    ingest_url = "http://localhost:3000",  # optional
    *,
    redis_url          = "redis://localhost:6379",  # optional, for control channel
    sample_rate        = 1.0,    # optional, 0.0–1.0
    pii_scrubber       = None,   # optional, custom scrubber
    redact_keys        = None,   # optional, list of payload keys to redact
    flush_interval_ms  = 500,    # optional
    flush_batch_size   = 100,    # optional
)
```

No environment variables are read. All events are posted to `{ingest_url}/v1/ingest/events`.

## Online Security Checks

The SDK runs 10 OWASP signal checks synchronously in the hot path via `OnlineCheckInterceptor`. When a check fires it sends a `security_finding` event to the API; the security service persists it immediately without waiting for session end.

| Signal | OWASP ID | Severity |
|--------|----------|----------|
| `prompt_injection` | OW-LLM01 | high |
| `insecure_output` | OW-LLM09 | high |
| `pii_input` | OW-LLM02 | medium |
| `pii_output` | OW-LLM02 | medium |
| `sensitive_data_exfiltration` | OW-LLM02 | high |
| `tool_misuse` | OW-LLM05 | high |
| `resource_exhaustion` | OW-ASI08 | medium |
| `privilege_escalation` | OW-ASI05 | critical |
| `unsafe_code_execution` | OW-ASI05 | critical |
| `supply_chain_tool` | OW-ASI04 | high |

Online checks and their actions are configured per-agent in the DapplePot UI and fetched automatically at SDK startup via `GET /v1/sdk/security/agents/{agent_id}/subcheck-config`. No code or environment changes needed to toggle checks — update in the UI and restart the agent.

## Control Channel

When `redis` is installed, the SDK subscribes to `dapplepot:control:{tenant_id}` for live configuration updates (`DAPPLEPOT_REDIS_URL`). Supported commands:

- `terminate_session` — flag a session for termination
- `update_tool_blocklist` — update blocked tool list
- `update_sample_rate` — change sampling rate
- `update_online_checks` — enable/disable specific online checks

## Event Flow

```
SDK → POST {DAPPLEPOT_INGEST_URL}/v1/ingest/events
  ├─ graph_start      session opened
  ├─ node_start/end   LangGraph node enter/exit (per run_id name tracking)
  ├─ llm_start/end    LLM call enter/exit (tokens, latency, model)
  ├─ tool_start/end   tool call enter/exit
  ├─ security_finding online check fired (real-time)
  └─ graph_end/error  session closed → triggers post-session scoring
```

## Key Files

| File | Description |
|------|-------------|
| `dapplepot_sdk/__init__.py` | Public API: `Client`, `Session`, `LangChainHandler` |
| `buffer.py` | Thread-safe event buffer + HTTP flush to `/v1/ingest/events` |
| `interceptor.py` | `OnlineCheckInterceptor` — 10 signal evaluators in the hot path |
| `adapter.py` | Event schema builders (`session_start`, `node_start`, `llm_start`, …) |
| `_langchain.py` | `DapplePotCallbackHandler` — LangChain/LangGraph callbacks |
| `session.py` | `SessionContext` — context manager for manual instrumentation |
| `control_channel.py` | Redis pub/sub subscriber for live config updates |

## Related Repos

| Repo | Role |
|------|------|
| [dapplepot-api](../dapplepot-api) | Hono/Node ingest API + REST endpoints (port 3000) |
| [dapplepot-security](../dapplepot-security) | FastAPI security scoring engine (port 8001) |
| [dapplepot-ui](../dapplepot-ui) | React dashboard (port 5173) |
