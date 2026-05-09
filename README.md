# dapplepot-sdk

Python SDK for instrumenting LLM agents with DapplePot security observability. Drop-in integrations for LangChain/LangGraph, OpenAI, Anthropic, LiteLLM, and LlamaIndex — sends structured events to the DapplePot ingest API and runs real-time threat detection in the hot path.

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

Get your `sdk_key`, `tenant_id`, `agent_id`, and `ingest_url` from the DapplePot dashboard.

### LangChain / LangGraph

```python
import dapplepot_sdk as dp

client = dp.DapplePot(
    sdk_key    = "dp_sk_...",
    tenant_id  = "your-tenant-id",
    agent_id   = "your-agent-id",
    ingest_url = "https://ingest.dapplepot.com",
)

handler = client.callback_handler()
result = graph.invoke({"messages": [...]}, config={"callbacks": [handler]})
```

### OpenAI (drop-in replacement)

```python
import dapplepot_sdk as dp
from dapplepot_sdk.openai import openai  # use in place of `import openai`

client = dp.DapplePot(
    sdk_key    = "dp_sk_...",
    tenant_id  = "...",
    agent_id   = "...",
    ingest_url = "https://ingest.dapplepot.com",
)

response = openai.chat.completions.create(model="gpt-4o", messages=[...])
```

Use `dp.session()` to group multiple calls under one session:

```python
with client.session() as session:
    r1 = openai.chat.completions.create(...)
    r2 = openai.chat.completions.create(...)
```

### Anthropic (drop-in replacement)

```python
import dapplepot_sdk as dp
from dapplepot_sdk.anthropic import anthropic  # use in place of `import anthropic`

client = dp.DapplePot(
    sdk_key    = "dp_sk_...",
    tenant_id  = "...",
    agent_id   = "...",
    ingest_url = "https://ingest.dapplepot.com",
)

response = anthropic.Anthropic().messages.create(model="claude-3-5-sonnet-20241022", ...)
```

### LiteLLM

```python
import dapplepot_sdk as dp
import litellm

client = dp.DapplePot(
    sdk_key    = "dp_sk_...",
    tenant_id  = "...",
    agent_id   = "...",
    ingest_url = "https://ingest.dapplepot.com",
)
client.register_litellm_callbacks()

response = litellm.completion(model="gpt-4o", messages=[...])
```

### LlamaIndex

```python
import dapplepot_sdk as dp

client = dp.DapplePot(
    sdk_key    = "dp_sk_...",
    tenant_id  = "...",
    agent_id   = "...",
    ingest_url = "https://ingest.dapplepot.com",
)
client.instrument_llama_index()  # process-wide, call once at startup

# all LlamaIndex queries are now traced automatically
```

## Constructor

```python
dp.DapplePot(
    sdk_key,     # required — your SDK key from the DapplePot dashboard
    tenant_id,   # required — your tenant ID
    agent_id,    # required — the agent being instrumented
    ingest_url,  # required — your DapplePot ingest endpoint
    *,
    sample_rate        = 1.0,   # 0.0–1.0; controls what fraction of sessions are traced
    pii_scrubber       = None,  # custom scrubber object (must implement .scrub_value())
    redact_keys        = None,  # list[str] of payload keys to replace with [REDACTED]
    flush_interval_ms  = 500,   # how often the background thread flushes buffered events
    flush_batch_size   = 100,   # max events per flush batch
)
```

All events are posted to `{ingest_url}/v1/ingest/events` with `Authorization: Bearer {sdk_key}`.

## Online Security Checks

The SDK runs **12 sub-checks** synchronously on every event. When a check fires it emits a finding immediately (without waiting for session end). Which checks are active and what action they take is configured per-agent in the DapplePot dashboard and fetched automatically at SDK startup.

| Sub-check | Category | Phase | Severity |
|-----------|----------|-------|----------|
| `PI-01a` | prompt_injection | input | high |
| `PI-01b` | prompt_injection | input | critical |
| `PI-01c` | prompt_injection | input | high |
| `PI-02a` | prompt_injection | tool_end | high |
| `PI-05a` | prompt_injection | input | high |
| `PI-08a` | prompt_injection | llm_start | high |
| `SID-01a` | data_disclosure | output | critical |
| `SID-01c` | data_disclosure | output | critical |
| `SID-02a` | data_disclosure | output | high |
| `IOH-01a` | output_handling | output | critical |
| `EA-01a` | excessive_agency | tool_start | high |
| `EA-02b` | excessive_agency | tool_start | high |

Check configuration and the tool manifest are fetched from the DapplePot API at startup. Update checks in the dashboard and restart your agent — no code changes needed.

### Actions

When a check fires, it takes one of four actions (configured per sub-check in the dashboard):

| Action | Effect |
|--------|--------|
| `alert` | Logs a warning; execution continues |
| `sanitize` | Redacts matched content from the event payload; execution continues |
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

## PII Scrubbing

Use the built-in `RegexScrubber` or implement your own:

```python
from dapplepot_sdk.scrubbers import RegexScrubber

scrubber = RegexScrubber(patterns=["email", "ssn", "aws_key", "jwt", "phone"])

client = dp.DapplePot(
    sdk_key    = "dp_sk_...",
    tenant_id  = "...",
    agent_id   = "...",
    ingest_url = "https://ingest.dapplepot.com",
    pii_scrubber = scrubber,
)
```

Built-in pattern names: `email`, `phone`, `ssn`, `credit_card`, `uk_nino`, `iban`, `ip_address`, `aws_key`, `jwt`.

To implement a custom scrubber, subclass `BaseScrubber` and implement `scrub(text: str) -> str`:

```python
from dapplepot_sdk.scrubbers import BaseScrubber

class MyScrubber(BaseScrubber):
    def scrub(self, text: str) -> str:
        return text.replace("sensitive", "[REDACTED]")
```

## Event Flow

```
SDK → POST {ingest_url}/v1/ingest/events
  ├─ session_start      session opened
  ├─ node_start/end     LangGraph node enter/exit
  ├─ node_error         node-level error
  ├─ llm_start/end      LLM call enter/exit (tokens, latency, model)
  ├─ tool_start/end     tool call enter/exit
  └─ session_end/error  session closed
```

## License

MIT
