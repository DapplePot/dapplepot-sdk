# DapplePot Python SDK

Security observability for LLM agents. Full session traces and real-time threat detection on every LLM and tool call — no per-call wrapping, no framework rewrite.

```python
dp = DapplePot(sdk_key="dp_sk_...", agent_id="my-agent")
dp.instrument_anthropic()   # or .instrument_openai(), or use dp.callback_handler() for LangChain
```

From here, every Anthropic / OpenAI / LangChain / LangGraph call your agent makes flows through DapplePot — captured as a structured timeline, scanned for prompt injection, data leakage, and tool abuse in the hot path, and visible in the dashboard within seconds.

## What you get

- **Auto-instrumentation** for the standard `openai`, `anthropic`, `langchain`, and `langgraph` packages. Upgrade them freely — DapplePot patches in-place at runtime, not at build time.
- **Tool tracking** without code changes — `tool_start` / `tool_end` events are detected from the model's response and the next call's tool result, including multi-turn loops.
- **12 online security checks** that run synchronously on every event (prompt injection, secret exfiltration, output handling, excessive agency) with configurable actions: `alert`, `sanitize`, `block_call`, or `terminate_session`.
- **PII scrubbing** with built-in regex patterns or a custom scrubber, plus key-based redaction.
- **Sync, async, and streaming** all covered in one `instrument_*()` call.

## Requirements

- Python 3.10+
- A DapplePot account — sign up at [dapplepot.com](https://dapplepot.com) to get your `sdk_key` and create an agent.

## Installation

```bash
pip install dapplepot-sdk

# Framework-specific extras:
pip install "dapplepot-sdk[langchain]"    # LangChain / LangGraph
pip install "dapplepot-sdk[openai]"       # OpenAI
pip install "dapplepot-sdk[anthropic]"    # Anthropic
pip install "dapplepot-sdk[all]"          # Everything
```

## Quick Start

Sign up at [dapplepot.com](https://dapplepot.com) and grab your `sdk_key` and `agent_id` from the dashboard. That's all you need — the SDK talks to `https://api.dapplepot.com` by default.

### Anthropic

The standard `anthropic` package is patched in-place — upgrade it freely without coordinating with DapplePot releases.

```python
import anthropic
from dapplepot_sdk import DapplePot

dp = DapplePot(
    sdk_key  = "dp_sk_...",
    agent_id = "your-agent-id",
)
dp.instrument_anthropic()

client = anthropic.Anthropic(api_key="...")

with dp.session(user_context_id="user_123", user_tenant_id="acme_corp"):
    response = client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Hello!"}],
    )
```

All LLM, tool, and session events are captured automatically. See [Tool Tracking](#tool-tracking) for how multi-turn tool-use loops are traced with zero extra code.

### OpenAI

```python
import openai
from dapplepot_sdk import DapplePot

dp = DapplePot(sdk_key="dp_sk_...", agent_id="your-agent-id")
dp.instrument_openai()

with dp.session(user_context_id="user_123"):
    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello!"}],
    )
```

### LangChain / LangGraph

LangChain fires its own callbacks during chain or graph execution — pass `dp.callback_handler()` and DapplePot listens.

```python
from dapplepot_sdk import DapplePot

dp = DapplePot(sdk_key="dp_sk_...", agent_id="your-agent-id")

handler = dp.callback_handler(
    user_context_id="user_123",
    user_tenant_id="acme_corp",
)
result = graph.invoke(
    {"messages": [...]},
    config={"callbacks": [handler]},
)
```

For LangGraph: each named graph node automatically becomes a `node_start` / `node_end` event. Tool calls handled via `ToolNode` emit `tool_start` / `tool_end` automatically.

## Core API

### `dp.session(*, user_context_id=None, user_tenant_id=None)`

Context manager that opens a DapplePot session for a multi-call conversation. The session ID is generated automatically.

```python
with dp.session(user_context_id="u_42", user_tenant_id="acme") as sess:
    # All LLM calls inside this block belong to the same session
    response = client.messages.create(...)
```

| Parameter | Description |
|---|---|
| `user_context_id` | Identifies the end-user within the session (optional) |
| `user_tenant_id`  | For multi-tenant agents, identifies the customer tenant (optional) |

Outside `dp.session()`, every patched LLM call becomes its own one-event session.

### `dp.node(name, *, input=None)`

Optional context manager that adds named structure to your agent code. Emits `node_start` on entry, `node_end` on success, or `node_error` if an exception escapes.

```python
with dp.session():
    with dp.node("retrieve_context", input=query):
        docs = vector_store.search(query)

    with dp.node("generate_response"):
        response = client.messages.create(...)
```

Use this when you want named steps in the trace UI — it is entirely optional. LangChain and LangGraph emit node events automatically from their own callbacks.

### `dp.callback_handler(*, user_context_id=None, user_tenant_id=None)`

Returns a fresh `DapplePotCallbackHandler` for one invocation of a LangChain chain or LangGraph run.

## Tool Tracking

For the Anthropic and OpenAI integrations, tool calls are detected automatically — no client-side instrumentation is required.

**Anthropic**: when the model returns `tool_use` content blocks, `tool_start` is emitted. When the next `messages.create()` call carries matching `tool_result` blocks, `tool_end` is emitted with the real tool output and latency. Set `is_error=True` on the `tool_result` block to emit `tool_error` instead.

**OpenAI**: when the model returns `tool_calls`, `tool_start` is emitted. When the next `chat.completions.create()` carries the corresponding `role="tool"` message, `tool_end` is emitted. Add `is_error=True` to the tool message to emit `tool_error` instead (a DapplePot convention — OpenAI ignores extra fields).

**LangChain / LangGraph**: tool callbacks are wired automatically by the framework's own `BaseTool` and `ToolNode`.

## Constructor

```python
DapplePot(
    sdk_key,                                   # required — your SDK key from the DapplePot dashboard
    agent_id,                                  # required — the agent being instrumented
    ingest_url = "https://api.dapplepot.com",  # optional — override for self-hosted / staging
    *,
    sample_rate        = 1.0,   # 0.0–1.0; fraction of sessions traced
    pii_scrubber       = None,  # custom scrubber object (must implement .scrub_value())
    redact_keys        = None,  # list[str] of payload keys to replace with [REDACTED]
    flush_interval_ms  = 500,   # background flush cadence
    flush_batch_size   = 100,   # max events per flush batch
)
```

Your tenant is resolved server-side from `sdk_key` — you do not pass it. All events are posted to `{ingest_url}/v1/ingest/events` with `Authorization: Bearer {sdk_key}`.

Call `dp.shutdown()` on exit to flush buffered events.

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
from dapplepot_sdk import DapplePot, DapplePotBlockedError, DapplePotSessionTerminatedError

try:
    result = graph.invoke(...)
except DapplePotBlockedError as e:
    print(e.signal, e.reason, e.session_id)
except DapplePotSessionTerminatedError:
    print("Session terminated by security policy")
```

## PII Scrubbing

Use the built-in `RegexScrubber` or implement your own:

```python
from dapplepot_sdk import DapplePot
from dapplepot_sdk.scrubbers import RegexScrubber

scrubber = RegexScrubber(patterns=["email", "ssn", "aws_key", "jwt", "phone"])

dp = DapplePot(
    sdk_key      = "dp_sk_...",
    agent_id     = "your-agent-id",
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

You can also redact known keys without touching values:

```python
dp = DapplePot(..., redact_keys=["api_key", "password", "ssn"])
```

**Impact on detection:** Scrubbing runs after real-time online checks, so live session checks marked for online detection (e.g. `SID-02a`) still operate on the original content and fire correctly. However, events stored for post-session analysis contain the scrubbed values — PII is replaced with tokens like `[EMAIL]` or `[SANITIZED]` before storage, so any offline detection pass on those events will find nothing to flag.

## Event Reference

All events flow through `POST {ingest_url}/v1/ingest/events`.

| Event | When |
|---|---|
| `session_start` | `dp.session()` enter, or first patched call in standalone mode |
| `session_end` | `dp.session()` exit (normal close), or last patched call in standalone mode |
| `session_error` | Exception escapes `dp.session()` uncaught |
| `node_start` | `dp.node()` enter, or LangGraph/LangChain child chain start |
| `node_end` | `dp.node()` clean exit, or LangGraph/LangChain child chain end |
| `node_error` | `dp.node()` raises, or LangGraph/LangChain child chain fails |
| `llm_start` | Patched LLM call begins |
| `llm_end` | Patched LLM call returns (tokens, latency, model, finish reason) |
| `llm_error` | Patched LLM call raises |
| `tool_start` | Tool invoked by the model (auto-detected from response) |
| `tool_end` | Tool result fed back into the model (auto-detected from next call) |
| `tool_error` | Tool result marked `is_error=True`, or framework tool callback fails |
| `security_finding` | Online security check fired (out-of-band) |

Errors propagate upward only as far as the exception actually travels. Catch an exception inside `dp.node()` and the session keeps going. Catch it inside `dp.session()` and you only see `node_error` and `llm_error`, never `session_error`.

## Supported Integrations & Known Limitations

DapplePot SDK ships with first-class support for specific integration points. What is covered today, and what is on the roadmap:

### Currently supported

| Surface                                             | Status |
|-----------------------------------------------------|:------:|
| OpenAI `chat.completions` — sync                    | ✅ |
| OpenAI `chat.completions` — async                   | ✅ |
| OpenAI `chat.completions` — streaming (sync/async)  | ✅ |
| Anthropic `messages.create` — sync                  | ✅ |
| Anthropic `messages.create` — async                 | ✅ |
| Anthropic `messages.create(stream=True)` (sync/async) | ✅ |
| Anthropic `messages.stream()` context manager (sync/async) | ✅ |
| LangChain / LangGraph via `CallbackHandler`         | ✅ |

For OpenAI and Anthropic, sync / async / streaming variants are patched in one call to `dp.instrument_openai()` or `dp.instrument_anthropic()`. No per-call wrapping. Tool calls flowing through any of these surfaces are auto-detected.

### Not yet supported (roadmap)

- **OpenAI Responses API** (`client.responses.create`), Assistants API, and the OpenAI Agents SDK. Use `chat.completions` for now — Responses support is planned.
- **Anthropic Bedrock / Vertex clients** (`AnthropicBedrock`, `AnthropicVertex`).
- **Other LLM providers**: Google Gemini, Mistral, Cohere, Ollama, LiteLLM, OpenRouter.
- **Other agent frameworks**: CrewAI, AutoGen, PydanticAI, LlamaIndex, smolagents.


### Usage notes for LangChain / LangGraph

**Custom tool dispatch.** If you handle tool calls outside `ToolNode` or `BaseTool` (for example, parsing `tool_calls` off an `AIMessage` and invoking the tool yourself in a custom node), LangChain does not fire `on_tool_start` / `on_tool_end` for that execution. Wrap your manual dispatch in `dp.node(...)` so the trace reflects it:

```python
with dp.node("execute_tool", input=tool_args):
    result = my_tool(tool_args)
```

**Async callback propagation.** In async LangGraph (`ainvoke`, `astream`), LangChain does not always propagate callbacks to child runs automatically. Always thread the handler through `RunnableConfig`:

```python
handler = dp.callback_handler(user_context_id="u_42")

result = await graph.ainvoke(
    {"messages": [...]},
    config={"callbacks": [handler]},   # required for async
)
```

If your trace shows a `session_start` followed by silence in async mode, this is almost always the cause.

### Usage notes for streaming

**Output-content detection is post-hoc, not preventive, on streamed responses.** DapplePot's `llm_end`-based detectors (PII leak, secret exfiltration, output policy) fire when the SDK emits `llm_end` — for streamed responses, that happens after the stream has closed and the application has already iterated every chunk. The detector still *runs* and the finding still lands on the session timeline, but it cannot retroactively prevent your code from receiving the streamed content. Use `stream=False` on endpoints where real-time output blocking is required.

This applies only to *output-content* detection. Two other detection surfaces are unaffected by streaming:

- **Input detection** (`llm_start`) fires before the stream opens, so prompt-injection and similar input-side checks still block in real time.
- **Tool-execution detection** (`tool_start`) fires at stream close, before your application has executed the tool, so excessive-agency and similar tool-side checks still block in real time.

Streamed `llm_end` events carry `payload.streamed: true`; the dashboard renders a small "streamed" badge on those rows. The `latency_ms` field on streamed `llm_end` events is end-to-end stream duration (including time your code spent iterating chunks), not server-side round-trip.

Per-chunk detection (real-time output blocking via opt-in `llm_chunk` events and mid-stream interrupt) is on the post-MVP roadmap.

## License

Licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
