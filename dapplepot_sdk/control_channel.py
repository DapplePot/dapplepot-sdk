"""
Control channel — reserved for future use.

The Redis pub/sub mechanism (dapplepot:control:{tenant_id}) was removed when
kill-switch and interrupt were dropped from dapplepot-api. The API now exposes
GET /v1/control/commands (HTTP polling) for future command delivery.
"""
