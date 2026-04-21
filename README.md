# dapplepot-sdk

Python SDK for instrumenting LLM agents with DapplePot security observability. Drop-in integrations for LangChain/LangGraph, OpenAI, Anthropic, LiteLLM, and LlamaIndex — sends structured events to the DapplePot API over HTTP.

## Installation

```bash
pip install dapplepot-sdk

# Framework-specific extras:
pip install "dapplepot-sdk[langchain]"    # LangChain / LangGraph
pip install "dapplepot-sdk[llama-index]"  # LlamaIndex
pip install "dapplepot-sdk[litellm]"      # LiteLLM
pip install "dapplepot-sdk[openai]"       # OpenAI
pip install "dapplepot-sdk[anthropic]"    # Anthropic
pip install "dapplepot-sdk[all]"          # Everything
```

## Quick Start

### LangChain / LangGraph

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

### OpenAI (drop-in replacement)

```python
import dapplepot_sdk as dp
from dapplepot_sdk.openai import openai  # use in place of `import openai`

client = dp.DapplePot(sdk_key="dp_sk_...", tenant_id="...", agent_id="...")

response = openai.chat.completions.create(model="gpt-4o", messages=[...])
```

Use with `dp.session()` to group multiple calls under one session:

```python
with client.session() as session:
    r1 = openai.chat.completions.create(...)
    r2 = openai.chat.completions.create(...)
```

### Anthropic (drop-in replacement)

```python
import dapplepot_sdk as dp
from dapplepot_sdk.anthropic import anthropic  # use in place of `import anthropic`

client = dp.DapplePot(sdk_key="dp_sk_...", tenant_id="...", agent_id="...")

response = anthropic.Anthropic().messages.create(model="claude-3-5-sonnet-20241022", ...)
```

### LiteLLM

```python
import dapplepot_sdk as dp
import litellm

client = dp.DapplePot(sdk_key="dp_sk_...", tenant_id="...", agent_id="...")
client.register_litellm_callbacks()

response = litellm.completion(model="gpt-4o", messages=[...])
```

### LlamaIndex

```python
import dapplepot_sdk as dp

client = dp.DapplePot(sdk_key="dp_sk_...", tenant_id="...", agent_id="...")
client.instrument_llama_index()  # process-wide, call once at startup

# all LlamaIndex queries are now traced automatically
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
    pii_scrubber       = None,   # optional, custom scrubber (must implement .scrub_value())
    redact_keys        = None,   # optional, list[str] of payload keys to redact
    flush_interval_ms  = 500,    # optional
    flush_batch_size   = 100,    # optional
)
```

No environment variables are read. All events are posted to `{ingest_url}/v1/ingest/events`.

## Online Security Checks

The SDK runs **11 sub-checks** synchronously in the hot path via `OnlineCheckInterceptor`. When a check fires it emits a `security_finding` event immediately (without waiting for session end). Which checks run and what action they take is configured per-agent in the DapplePot UI and fetched automatically at SDK startup.

| Sub-check | Category | Phase | Severity | Description |
|-----------|----------|-------|----------|-------------|
| `PI-01a` | prompt_injection | input | high | Role-override phrase match |
| `PI-01b` | prompt_injection | input | critical | Delimiter smuggling |
| `PI-01c` | prompt_injection | input | high | Encoded / obfuscated payload |
| `PI-02a` | prompt_injection | tool_end | high | Indirect injection via tool output |
| `PI-05a` | prompt_injection | input | high | Code injection pattern in prompt |
| `PI-08a` | prompt_injection | llm_start | high | Adversarial suffix (high-entropy tail) |
| `SID-01a` | data_disclosure | output | critical | API key / token in output |
| `SID-01c` | data_disclosure | output | critical | JWT / session token in output |
| `SID-02a` | data_disclosure | output | high | Multiple PII patterns co-occurring |
| `EA-01a` | excessive_agency | tool_start | high | Tool not in approved manifest |
| `EA-02b` | excessive_agency | tool_start | high | Tool calls exceed session limit |

Check config is fetched from `GET /v1/sdk/security/agents/{agent_id}/subcheck-config`. Tool manifest and `max_tool_calls_per_session` are fetched from `GET /v1/sdk/security/agents/{agent_id}/tool-manifest`. Update checks in the DapplePot UI and restart the agent — no code changes needed.

### Actions

When a check fires, it can take one of three actions (configured per sub-check in the UI):

| Action | Effect |
|--------|--------|
| `alert` | Logs a warning; execution continues |
| `block_call` | Raises `DapplePotBlockedError` |
| `terminate_session` | Raises `DapplePotSessionTerminatedError` |

```python
import dapplepot_sdk as dp

try:
    result = graph.invoke(...)
except dp.DapplePotBlockedError as e:
    print(e.signal, e.reason, e.session_id)
except dp.DapplePotSessionTerminatedError:
    print("Session terminated by security policy")
```

## Control Channel

When `redis` is installed, the SDK subscribes to `dapplepot:control:{tenant_id}` for live configuration updates. Supported commands:

| Command | Effect |
|---------|--------|
| `terminate_session` | Flag a session for termination |
| `update_tool_blocklist` | Update blocked tool list |
| `update_sample_rate` | Change sampling rate |
| `update_online_checks` | Enable/disable specific sub-checks live |

## Event Flow

```
SDK → POST {ingest_url}/v1/ingest/events
  ├─ session_start      session opened
  ├─ node_start/end     LangGraph node enter/exit (per run_id name tracking)
  ├─ node_error         node-level error
  ├─ llm_start/end      LLM call enter/exit (tokens, latency, model)
  ├─ tool_start/end     tool call enter/exit
  ├─ security_finding   online check fired (real-time, bypasses buffer)
  └─ session_end/error  session closed → triggers post-session scoring
```

## Key Files

| File | Description |
|------|-------------|
| `dapplepot_sdk/__init__.py` | `DapplePot` client, `DapplePotBlockedError`, `DapplePotSessionTerminatedError` |
| `buffer.py` | Thread-safe event buffer + HTTP flush to `/v1/ingest/events` |
| `interceptor.py` | `OnlineCheckInterceptor` — 11 sub-check evaluators in the hot path |
| `adapter.py` | Event schema builders (`session_start`, `node_start`, `llm_start`, …) |
| `_langchain.py` | `DapplePotCallbackHandler` — LangChain/LangGraph callbacks |
| `openai.py` | Drop-in OpenAI proxy — patches `openai.chat.completions.create` |
| `anthropic.py` | Drop-in Anthropic proxy — patches `anthropic.resources.Messages.create` |
| `_litellm.py` | LiteLLM success/failure callback handler |
| `_llama_index.py` | LlamaIndex process-wide instrumentation via `CallbackManager` |
| `session.py` | `SessionContext` — context manager for manual session scoping |
| `control_channel.py` | Redis pub/sub subscriber for live config updates |

## Related Repos

| Repo | Role |
|------|------|
| [dapplepot-api](../dapplepot-api) | Hono/Node ingest API + REST endpoints (port 3000) |
| [dapplepot-security](../dapplepot-security) | FastAPI security scoring engine (port 8001) |
| [dapplepot-ui](../dapplepot-ui) | React dashboard (port 5173) |
