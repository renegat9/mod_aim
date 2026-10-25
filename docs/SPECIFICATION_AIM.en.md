# Complete `.aim` Format Specification (`mod_aim` v2.2)

An `.aim` file is a **100% self-contained contract** written in **TOML**. It bundles the LLM-facing metadata, security and human-governance policies, strict input/output schemas, and execution handler in a single file.

---

## 1. File Sections Overview

Every `.aim` file dropped into `tools/` (hot-reloaded via `notify`) contains 5 sections:

1. `[tool]`: Metadata and exposure protocols (`mcp`, `rest`).
2. `[security]`: Authorization scopes, human approval (`require_human_approval`), rate limits (`rate_limit = "60/min"`), and hardware quotas (`max_cpu_instructions`, `max_memory_kb`).
3. `[input]`: Typed input arguments and validation constraints (`min`, `max`, `min_len`, `enum`, `default`).
4. `[output]`: Output contract verified before returning any response to the calling agent.
5. `[handler]`: Execution engine (`native_sql`, `native_http`, `rhai`, or `wasm`) and associated query/code.

---

## 2. The 4 Embedded Execution Engines (`[handler]`)

| Engine (`engine`) | Description & Security Model |
| :--- | :--- |
| **`native_sql`** | Executes prepared SQL queries (against embedded WAL SQLite or external PostgreSQL DSNs stored encrypted in the AES-256-GCM vault) with named `:param` substitution and zero interpreted code. |
| **`native_http`** | Executes outbound REST requests (`GET`, `POST`, `PUT`, `DELETE`) with `:param` URL substitution and automatic injection of `Authorization: Bearer <secret>` decrypted on the fly from the AES-256-GCM vault. |
| **`rhai`** | Executes memory-safe sandboxed business logic with zero OS primitives. Exposes only `env.db_query_one`, `env.db_execute`, `env.http_request`, and `env.timestamp_sec`, bounded by `max_cpu_instructions`. |
| **`wasm`** | Executes isolated WebAssembly modules (inline `wat` or binary `wasm_file`) with deterministic instruction fuel metering (`consume_fuel`). |
