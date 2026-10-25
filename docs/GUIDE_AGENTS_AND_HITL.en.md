# AI Agent Integration, HITL Cascade, Rate-Limiting & Self-Authoring Guide

This guide explains how to connect an MCP client or REST orchestrator to `mod_aim`, handle Human-in-the-Loop (HITL) approvals, verify `HMAC-SHA256` webhooks, and use AI Self-Authoring.

---

## 1. Connecting an MCP Client (`POST /mcp` on Port `8080`)

`mod_aim` exposes a standard **MCP JSON-RPC 2.0** endpoint at `POST /mcp`:
* `initialize`: Returns protocol capabilities (`2025-03-26`) and server version (`2.2.0`).
* `tools/list`: Dynamically returns all enabled `.aim` tools plus the 3 built-in system meta-tools (`_system_check_approval`, `_system_propose_tool`, `_system_test_tool`).
* `tools/call`: Validates inputs, checks rate limits (`rate_limit = "60/min"`), enforces API key scopes (`Authorization: Bearer aim_live_...`), and executes the tool or triggers the HITL cascade.

---

## 2. 3-Tier Human-in-the-Loop (HITL) Cascade

When `require_human_approval = true`:
1. **Tier 1 — Synchronous Long-Polling (`0` to `long_polling_wait_sec`)**: Holds the connection open via `tokio::sync::oneshot`. If approved in `/_admin` within 25s, returns the result on the same HTTP request.
2. **Tier 2 — Signed Webhook (`_callback`)**: After timeout, returns `PENDING_HUMAN_APPROVAL` and a `ticket_id`. Once resolved by a human in `/_admin` (including optional JSON argument overrides), dispatches an `HMAC-SHA256` signed `POST` (`X-AIM-Signature-256`) to `_callback.url`.
3. **Tier 3 — Agent Polling (`_system_check_approval`)**: Local agents without a webhook server can call `_system_check_approval` with `{"ticket_id": "tkt_..."}` at any time.
