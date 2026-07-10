# Changelog

## [0.2.2] - 2026-07-10
- `llm_start` payload is now compact: `messages` carries only the current
  user/tool turn; `n_prior_context_messages` records elided count. System
  prompt is no longer emitted per-event (it's already available via the
  agent manifest for SPL-01a). Cuts storage ~90% on long / multi-node
  stateful sessions; all framework adapters benefit uniformly.

## [0.2.1] - 2026-07-09
- Added docstrings across the SDK's public classes and methods.
- Expanded Runtime Guard from 12 to 60 online checks, spanning the OWASP LLM
  and Agentic (ASI) Top 10.
- Wired Governance policy fields (write namespace, network allowlist,
  irreversible tools, tool approval policy, and others) end-to-end so
  EA-01c/EA-02a/EA-03b and related checks actually receive their config.
- `DapplePotSessionTerminatedError` now carries `signal`/`session_id`
  attributes, matching `DapplePotBlockedError`.
- Removed `DapplePotSecurityUnavailableError` and the `fail_policy` option —
  neither was reachable through the public API.
- Fixed docstring code examples (`Usage::` → `Example:`) so the generated
  API reference site renders them as formatted code blocks instead of
  unformatted text.

## [0.2.0] - 2026-07-01
- Version bump; packaging/build updates.

## [0.1.0] - 2026-06-22
- Initial release: `DapplePot` client with `instrument_anthropic()`,
  `instrument_openai()`, and `callback_handler()` (LangChain/LangGraph)
  instrumentation, `session()`/`node()` context managers, online security
  checks, event buffering, and PII scrubbing (`RegexScrubber`).
