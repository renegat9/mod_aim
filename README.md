# `mod_aim` — Standalone Zero-Trust Rust Engine for `.aim` AI Tools (MCP & REST)

[![Build & Release mod_aim (Rust)](https://github.com/renegat9/mod_aim/actions/workflows/build.yml/badge.svg)](https://github.com/renegat9/mod_aim/actions/workflows/build.yml)

**Languages:** [🇬🇧 **English**](README.md) | [🇫🇷 **Français**](README.fr.md)

> **Vision:** A compiled, 100% self-contained, memory-safe Rust server engine that brings *"Drop-in"* simplicity (drop a `.aim` file = instant hot-reloaded tool) while completely eliminating traditional script interpreters (PHP, Node, Python) and their attack surface. Designed to be authored by AI, invoked by agents over **MCP / REST**, and governed by humans.

---

## Key Features

1. **Zero External Interpreter Dependency**: A single static-style binary (`aim-daemon`) embedding the HTTP/MCP server (`axum`), WAL-mode SQLite persistence (`rusqlite`), sandboxed scripting engine (`rhai`), WebAssembly runtime (`wasmi` + `wat`), **AES-256-GCM** encrypted secrets vault, and embedded human control plane (`/_admin`).
2. **Dual-Port Zero-Trust Network Isolation**:
   - **Public Data Plane Port (`8080`)**: Exposes only `/mcp`, `/api/v1/:tool_name`, and `/llms.txt`, protected by Agent API Keys (`Authorization: Bearer aim_live_...`) and per-tool `auth_scope` enforcement. No admin routes exist on this port.
   - **Isolated Admin Control Plane Port (`8081`)**: Exposes only `/_admin` and governance APIs, protected by constant-time `SHA-256` verification of `AIM_ADMIN_PASSWORD`.
3. **3 Embedded Execution Engines**:
   - `native_sql`: Prepared SQL queries with named parameters (`:param`) and zero interpreted code.
   - `rhai`: Memory-safe sandboxed business logic with zero OS primitives (no `exec`, filesystem, or raw sockets), strictly bounded by `max_cpu_instructions` and `max_memory_kb`.
   - `wasm`: Isolated WebAssembly module execution with deterministic instruction fuel metering (`consume_fuel`).
4. **3-Tier Human-in-the-Loop (HITL) Approval Cascade**:
   - **Tier 1 (Synchronous Long-Polling)**: Holds the HTTP request open via `tokio::sync::oneshot` for `long_polling_wait_sec` (default 25s). If approved in `/_admin` within that window, returns the execution result synchronously.
   - **Tier 2 (Cryptographically Signed Webhook)**: After timeout, returns `PENDING_HUMAN_APPROVAL` with a `ticket_id`. Once resolved by a human (including optional on-the-fly JSON argument overrides), dispatches an `HMAC-SHA256` signed webhook (`X-AIM-Signature-256`).
   - **Tier 3 (Agent Polling)**: Local agents without an incoming webhook URL can poll the built-in `_system_check_approval` MCP meta-tool.
5. **Self-Healing Error Protocol (`AIM_CONTRACT_VIOLATION`)**: Schema or runtime violations return structured diagnostics containing an actionable `ai_fix_hint` so LLMs can self-correct on their next turn.
6. **AI Self-Authoring Quarantine (`_system_propose_tool` & `_system_test_tool`)**: Allows AI agents to test and submit new `.aim` tools. The engine dry-run compiles the Rhai AST or Wasm module and places valid tools in quarantine inside `/_admin` until a human clicks **Activate**.

---

## Repository Structure

```text
├── .github/workflows/build.yml           # GitHub Actions CI/CD (13 Unit Tests + Linux & Windows Binaries)
├── .devcontainer/devcontainer.json       # 1-Click GitHub Codespaces Configuration (Ports 8080 & 8081)
├── Cargo.toml                            # Rust Manifest & Dependencies (v2.1.0)
├── Dockerfile                            # Multi-stage Zero-Trust Docker Image (non-root aim-runner user)
├── docker-compose.yml                    # Docker Compose Stack (Public 8080 + Local-only 8081 + Volumes)
├── README.md                             # English Documentation (Default)
├── README.fr.md                          # Documentation Française
├── src/
│   ├── main.rs                           # Core mod_aim Engine + 13 Unit & Contract Tests
│   └── admin_ui.html                     # Embedded SPA Human Control Plane UI
├── tools/                                # Hot-Reloaded .aim Tool Definitions (watched via notify)
│   ├── search_invoices.aim               # [native_sql] Declarative invoice search by client & status
│   ├── apply_credit_note.aim             # [rhai + HITL] Credit note generation with human approval
│   ├── cancel_overdue_invoice.aim        # [rhai + HITL] Controlled overdue invoice cancellation
│   ├── customer_billing_summary.aim      # [rhai + SQL] Client exposure & risk tier analytics
│   ├── compute_margin_wasm.aim           # [wasm] Net margin calculation in cents via WebAssembly
│   └── compound_interest_wasm.aim        # [wasm] Fuel-metered compound interest loop in WebAssembly
├── examples/                             # Ready-to-run Client & Webhook Examples
│   ├── demo_mcp_requests.sh              # Full curl walkthrough (MCP, REST, Wasm, Self-Healing, HITL)
│   └── webhook_receiver_verify.py        # Python Webhook Receiver verifying X-AIM-Signature-256 (HMAC-SHA256)
├── deploy/                               # Production Deployment Templates
│   ├── config.example.toml               # Example configuration file
│   ├── apache/mod_aim_vhost.conf         # Hardened Apache 2.4 Reverse Proxy VirtualHost
│   └── systemd/aim-daemon.service        # Hardened systemd service unit (NoNewPrivileges, ProtectSystem=strict)
└── docs/                                 # Detailed Technical Guides
    ├── SPECIFICATION_AIM.md              # Full .aim TOML Specification & Engine Reference
    ├── GUIDE_AGENTS_ET_HITL.md           # Agent Integration, HITL Cascade, Webhooks & Self-Authoring
    ├── DOCKER_ET_SECURITE_ADMIN.md       # Docker Deployment, Dual-Port 8080/8081 & Admin Security
    └── DEPLOIEMENT_APACHE.md             # Linux, Systemd & Apache 2.4 Production Setup Guide
```

---

## Quick Start

### Option 1: Run with Docker Compose (Recommended)
```bash
export AIM_MASTER_KEY="your_32_byte_minimum_aes256_master_secret"
export AIM_ADMIN_PASSWORD="your_strong_admin_password"

docker compose up -d --build
```
* **AI Agent Data Plane (`8080`)**: `http://127.0.0.1:8080/mcp` and `http://127.0.0.1:8080/llms.txt`
* **Human Control Plane (`8081`)**: `http://127.0.0.1:8081/_admin`

### Option 2: Download Pre-Compiled Binaries (GitHub Actions)
1. Open the **[Actions](https://github.com/renegat9/mod_aim/actions)** tab on GitHub.
2. Select the latest successful workflow run and download **`aim-engine-linux-x86_64`** or **`aim-engine-windows-x86_64`** under **Artifacts**.
3. Run `./aim-daemon` (Linux) or `aim-daemon.exe` (Windows).

### Option 3: Build from Source
```bash
cargo test
cargo run --release
```

---

## Exposed Endpoints

### Public Data Plane Port (`8080` default — `AIM_BIND_ADDR`)

| Method & Route | Description |
| :--- | :--- |
| `POST /mcp` | **MCP JSON-RPC 2.0** endpoint (`initialize`, `tools/list`, `tools/call`) |
| `POST /api/v1/:tool_name` | Mirror **REST** endpoint for each active `.aim` tool |
| `GET /llms.txt` | Dynamically generated Markdown catalog for LLM tool discovery |

### Isolated Admin Control Plane Port (`8081` default — `AIM_ADMIN_BIND_ADDR`)

| Method & Route | Description |
| :--- | :--- |
| `GET /_admin` (or `/`) | **Human Control Plane UI** protected by `AIM_ADMIN_PASSWORD` (HITL queue, On/Off tool switches, AES-256 Vault, API Keys, AI Proposals, Live MCP Simulator) |
| `GET /_admin/api/state` | Full engine state JSON (tools, HITL tickets, AI proposals, vault metadata, API keys, audit logs) |
| `POST /_admin/tickets/:id/resolve` | Approve, override JSON arguments, or reject a pending HITL ticket |

---

## Detailed Documentation

* [**🇫🇷 Documentation en Français (`README.fr.md`)**](README.fr.md)
* [**.aim Format Specification (`docs/SPECIFICATION_AIM.md`)**](docs/SPECIFICATION_AIM.md)
* [**AI Agent Integration, HITL Cascade & Webhooks (`docs/GUIDE_AGENTS_ET_HITL.md`)**](docs/GUIDE_AGENTS_ET_HITL.md)
* [**Docker Deployment & Dual-Port Admin Security (`docs/DOCKER_ET_SECURITE_ADMIN.md`)**](docs/DOCKER_ET_SECURITE_ADMIN.md)
* [**Apache 2.4 & Systemd Production Guide (`docs/DEPLOIEMENT_APACHE.md`)**](docs/DEPLOIEMENT_APACHE.md)
