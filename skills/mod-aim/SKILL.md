---
name: mod-aim
description: Author, test, propose, and invoke .aim tools on a mod_aim Zero-Trust server via MCP JSON-RPC 2.0 or REST. Use when the user asks to write or debug a .aim tool file (native_sql, native_http, rhai, or wasm), call a mod_aim MCP/REST endpoint, handle Human-in-the-Loop (HITL) approval tickets, resolve AIM_CONTRACT_VIOLATION self-healing errors, or self-author tools with _system_propose_tool and _system_test_tool.
---
# mod-aim

Author declarative `.aim` tools and interact with a `mod_aim` server over MCP (`POST /mcp`) or REST (`POST /api/v1/:tool_name`), including Human-in-the-Loop (HITL) approval cascades, self-healing error recovery, and AI self-authoring.

## Summary

`mod_aim` is a standalone Zero-Trust Rust engine that exposes `.aim` TOML tool contracts over MCP JSON-RPC 2.0 and REST on port `8080` while isolating human governance (`/_admin`) on port `8081`. Use this skill to write valid `.aim` files across all four embedded engines (`native_sql`, `native_http`, `rhai`, `wasm`) and to execute or troubleshoot MCP tool calls.

## When to Use

- Writing, reviewing, or refactoring a `.aim` tool definition file.
- Calling a `mod_aim` server via `POST /mcp` (JSON-RPC 2.0) or `POST /api/v1/:tool_name`.
- Handling `PENDING_HUMAN_APPROVAL` responses, polling `_system_check_approval`, or configuring `_callback` HMAC-SHA256 webhooks.
- Fixing an `AIM_CONTRACT_VIOLATION` (`-32000`) or `AIM_RATE_LIMIT_EXCEEDED` (`-32005`) error using `ai_fix_hint`.
- Proposing or dry-run testing a new tool dynamically using `_system_test_tool` and `_system_propose_tool`.

## Steps

### 1. Discover Active Tools and Server Capabilities

Before calling or authoring tools on a running `mod_aim` instance, inspect the active catalog:

- Read `GET http://<host>:8080/llms.txt` for a human- and LLM-readable summary of all enabled tools, engines, scopes, and REST routes.
- Or send an MCP `tools/list` request to `POST http://<host>:8080/mcp` (include `Authorization: Bearer aim_live_...` if API keys are enabled):

```json
{
  "jsonrpc": "2.0",
  "id": "list-1",
  "method": "tools/list"
}
```

### 2. Invoke Tools via MCP or REST

Use `POST /mcp` for standard JSON-RPC 2.0 calls or `POST /api/v1/:tool_name` with the JSON arguments object as the body.

```json
{
  "jsonrpc": "2.0",
  "id": "call-1",
  "method": "tools/call",
  "params": {
    "name": "search_invoices",
    "arguments": {
      "client_id": 1,
      "status": "unpaid"
    }
  }
}
```

### 3. Handle Human-in-the-Loop (HITL) Approvals

When a tool has `require_human_approval = true` in its `[security]` block, `mod_aim` holds the connection for `long_polling_wait_sec` (default 25s).

- **Fast non-blocking call**: Pass `"_wait_sec": 1` inside `arguments` if you want an immediate `ticket_id` without waiting 25 seconds.
- **Webhook delivery**: Pass a `"_callback"` object inside `arguments` so `mod_aim` pushes the signed result (`X-AIM-Signature-256: sha256=<hex>`) as soon as a human resolves the ticket on port `8081`:

```json
{
  "_callback": {
    "url": "https://agent.example.com/webhooks/aim",
    "secret": "whsec_your_hmac_secret",
    "context_id": "thread_42"
  }
}
```

- **Polling delivery**: If `tools/call` returns `"status": "PENDING_HUMAN_APPROVAL"`, poll `_system_check_approval` with the returned `ticket_id`:

```json
{
  "jsonrpc": "2.0",
  "id": "poll-1",
  "method": "tools/call",
  "params": {
    "name": "_system_check_approval",
    "arguments": {
      "ticket_id": "tkt_20261025_a1b2c3d4"
    }
  }
}
```

### 4. Recover from Self-Healing Errors (`AIM_CONTRACT_VIOLATION`)

When `mod_aim` returns JSON-RPC error code `-32000` (`AIM_CONTRACT_VIOLATION`) or `-32005` (`AIM_RATE_LIMIT_EXCEEDED`):

1. Read `error.data.phase`, `error.data.field`, and `error.data.ai_fix_hint`.
2. If `phase` is `input_schema_validation`, adjust the offending argument type, range (`min`/`max`), string length (`min_len`), or `enum` value and retry.
3. If `phase` is `output_schema_validation`, fix the `.aim` handler return map so every key declared in `[output]` matches its expected type (`int`, `float`, `string`, `bool`, or `array`).
4. If code is `-32005` (`AIM_RATE_LIMIT_EXCEEDED`), respect `error.data.retry_after_sec` before retrying.

### 5. Author a New `.aim` Tool Contract

Every `.aim` file is a standalone TOML contract containing 5 sections: `[tool]`, `[security]`, `[input]`, `[output]`, and `[handler]`. Choose the simplest engine that satisfies the requirement:

- **`native_sql`**: For direct database reads (`SELECT ... WHERE col = :param`). Uses named `:param` bindings against embedded SQLite or an encrypted PostgreSQL DSN in the vault.
- **`native_http`**: For outbound REST calls (`url = "https://api.example.com/items/:id"`). Automatically injects `Authorization: Bearer <secret>` from the encrypted `connection` alias in the vault.
- **`rhai`**: For multi-step business logic, conditional checks, and SQL writes. Use the injected `env` bridge:
  - `env.db_query_one("alias", "SELECT ... WHERE id = :id", #{ id: input.id })`
  - `env.db_execute("alias", "UPDATE ... SET val = :v WHERE id = :id", #{ v: new_val, id: input.id })`
  - `env.http_request("alias", "POST", "https://...", #{ key: val })`
  - `env.timestamp_sec()`
- **`wasm`**: For CPU-intensive deterministic calculations in WebAssembly text (`wat`) or binary (`wasm_file`) with fuel metering (`wasm_export` and `wasm_param_order`).

```toml
[tool]
name = "apply_discount"
description = "Applies a validated discount to an unpaid invoice."
version = "1.0.0"
exposure = ["mcp", "rest"]

[security]
auth_scope = "billing:write"
require_human_approval = true
rate_limit = "30/min"
max_cpu_instructions = 40000
max_memory_kb = 1024

[input]
invoice_id = { type = "int", min = 1, description = "Target invoice ID" }
discount = { type = "float", min = 1.0, max = 500.0, description = "Discount amount" }

[output]
invoice_id = "int"
new_total = "float"
status = "string"

[handler]
engine = "rhai"
script = """
  let inv = env.db_query_one(
      "erp_postgres",
      "SELECT amount_total, status FROM invoices WHERE id = :id",
      #{ id: input.invoice_id }
  );
  if inv == () {
      throw #{ code: "NOT_FOUND", hint: "Verify invoice_id with search_invoices." };
  }
  let updated = inv.amount_total - input.discount;
  env.db_execute(
      "erp_postgres",
      "UPDATE invoices SET amount_total = :tot WHERE id = :id",
      #{ tot: updated, id: input.invoice_id }
  );
  return #{
      invoice_id: input.invoice_id,
      new_total: updated,
      status: "discounted"
  };
"""
```

### 6. Test and Propose Tools Dynamically (Self-Authoring)

When connected to a running `mod_aim` server over MCP, always dry-run test your `.aim` TOML before proposing it for human activation:

1. Call `_system_test_tool` with `{"aim_toml": "<full TOML>", "arguments": { ... }}` to verify TOML syntax, Rhai AST / Wasm compilation, input/output contracts, and CPU instruction usage (`cpu_instructions_used`).
2. Once `_system_test_tool` returns `"status": "DRY_RUN_SUCCESS"`, call `_system_propose_tool` with `{"aim_toml": "<full TOML>"}` to place the verified tool in the `/_admin` quarantine for 1-click human activation.

## Gotchas

- Never hardcode database passwords or API tokens inside a `.aim` file. Always reference a logical `connection` alias (e.g. `"erp_postgres"`, `"external_billing_api"`) configured in the `AES-256-GCM` vault on port `8081`.
- Never attempt to call `/_admin` routes on public port `8080`. The public router only serves `/mcp`, `/api/v1/:tool_name`, and `/llms.txt`; `/_admin` is isolated on port `8081`.
- In `rhai` handlers, `env.db_query_one` returns `()` (unit) when no row matches. Always check `if row == ()` before accessing fields on the returned map.
- In `wasm` handlers, exported functions must take `i64` parameters matching `wasm_param_order` and return an `i64` result, while the `[output]` block must declare `result = "int"` and `engine = "string"`.
