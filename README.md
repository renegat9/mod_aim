# `mod_aim` — Standalone Zero-Trust Rust Engine for `.aim` AI Tools (MCP & REST)

[![Latest Release](https://img.shields.io/github/v/release/renegat9/mod_aim?label=Release&color=0284c7)](https://github.com/renegat9/mod_aim/releases/latest)
[![Build & Release mod_aim (Rust)](https://github.com/renegat9/mod_aim/actions/workflows/build.yml/badge.svg)](https://github.com/renegat9/mod_aim/releases/latest)

**Languages:** [🇬🇧 **English**](README.md) | [🇫🇷 **Français**](README.fr.md)

> **Vision:** A compiled, 100% self-contained, memory-safe Rust server engine that brings *"Drop-in"* simplicity (drop a `.aim` file = instant hot-reloaded tool) while completely eliminating traditional script interpreters (PHP, Node, Python) and their attack surface. Designed to be authored by AI, invoked by agents over **MCP / REST**, and governed by humans.

---

## Key Features

1. **Zero External Interpreter Dependency**: A single static-style binary (`aim-daemon`) embedding the HTTP/MCP server (`axum`), WAL-mode SQLite persistence (`rusqlite`), sandboxed scripting engine (`rhai`), WebAssembly runtime (`wasmi` + `wat`), **AES-256-GCM** encrypted secrets vault, and embedded human control plane (`/_admin`).
2. **Dual-Port Zero-Trust Network Isolation**:
   - **Public Data Plane Port (`8080`)**: Exposes only `/mcp`, `/api/v1/:tool_name`, and `/llms.txt`, protected by Agent API Keys (`Authorization: Bearer aim_live_...`), per-tool `auth_scope` enforcement, and sliding-window `rate_limit`. No admin routes exist on this port.
   - **Isolated Admin Control Plane Port (`8081`)**: Exposes only `/_admin` and governance APIs, protected by constant-time `SHA-256` verification of `AIM_ADMIN_PASSWORD`.
3. **4 Embedded Execution Engines (`native_sql` SQLite/PostgreSQL, `native_http`, `rhai`, `wasm`)**:
   - `native_sql`: Prepared SQL queries (embedded WAL SQLite or external PostgreSQL DSNs stored encrypted in the vault) with named parameters (`:param`) and zero interpreted code.
   - `native_http`: Outbound REST calls (`GET`, `POST`, `PUT`, `DELETE`) with `:param` URL substitution and automatic injection of `Authorization: Bearer <secret>` decrypted on the fly from the AES-256-GCM vault.
   - `rhai`: Memory-safe sandboxed business logic with zero OS primitives (no `exec`, filesystem, or raw sockets), strictly bounded by `max_cpu_instructions` and `max_memory_kb`.
   - `wasm`: Isolated WebAssembly module execution with deterministic instruction fuel metering (`consume_fuel`).
4. **3-Tier Human-in-the-Loop (HITL) Approval Cascade**:
   - **Tier 1 (Synchronous Long-Polling)**: Holds the HTTP request open via `tokio::sync::oneshot` for `long_polling_wait_sec` (default 25s). If approved in `/_admin` within that window, returns the execution result synchronously.
   - **Tier 2 (Cryptographically Signed Webhook)**: After timeout, returns `PENDING_HUMAN_APPROVAL` with a `ticket_id`. Once resolved by a human (including optional on-the-fly JSON argument overrides), dispatches an `HMAC-SHA256` signed webhook (`X-AIM-Signature-256`).
   - **Tier 3 (Agent Polling)**: Local agents without an incoming webhook URL can poll the built-in `_system_check_approval` MCP meta-tool.
5. **Self-Healing Error Protocol (`AIM_CONTRACT_VIOLATION`)**: Schema or runtime violations return structured diagnostics containing an actionable `ai_fix_hint` so LLMs can self-correct on their next turn.
6. **AI Self-Authoring Quarantine (`_system_propose_tool` & `_system_test_tool`)**: Allows AI agents to test and submit new `.aim` tools. The engine dry-run compiles the Rhai AST or Wasm module and places valid tools in quarantine inside `/_admin` until a human clicks **Activate**.

---

## Quick Start

### Option 1: Run with Docker Compose (Recommended)

Create a `docker-compose.yml` file (using the official image published on `ghcr.io/renegat9/mod_aim:latest`) and a local `./tools` folder for your `.aim` files:

```yaml
services:
  aim-daemon:
    image: ghcr.io/renegat9/mod_aim:latest
    container_name: mod_aim_daemon
    restart: unless-stopped
    ports:
      # Public Data Plane Port (MCP JSON-RPC 2.0, REST API, /llms.txt)
      - "8080:8080"
      # Isolated Admin Control Plane Port (bound to localhost 127.0.0.1 only)
      - "127.0.0.1:8081:8081"
    environment:
      AIM_BIND_ADDR: "0.0.0.0:8080"
      AIM_ADMIN_BIND_ADDR: "0.0.0.0:8081"
      AIM_TOOLS_DIR: "/app/tools"
      AIM_DB_PATH: "/data/engine.sqlite"
      AIM_MASTER_KEY: "${AIM_MASTER_KEY:-replace_with_a_32_byte_minimum_aes256_secret}"
      AIM_ADMIN_PASSWORD: "${AIM_ADMIN_PASSWORD:-replace_with_a_strong_admin_password}"
      RUST_LOG: "info"
    volumes:
      # Instant Hot-Reload: any .aim file added or edited in ./tools is loaded live
      - ./tools:/app/tools
      # Persistent WAL SQLite storage (AES-256 vault, API keys, HITL tickets, audit logs)
      - aim_sqlite_data:/data
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL

volumes:
  aim_sqlite_data:
```

Start the stack:
```bash
docker compose up -d
```
* **AI Agent Data Plane (`8080`)**: `http://127.0.0.1:8080/mcp` and `http://127.0.0.1:8080/llms.txt`
* **Human Control Plane (`8081`)**: `http://127.0.0.1:8081/_admin`

### Option 2: Integrate `mod_aim` into an Existing Stack or Image (e.g., `php:8.5-apache`)

#### 2A. Sidecar Pattern in `docker-compose.yml` (Zero custom Dockerfile)
Attach `aim-daemon` alongside your existing `php:8.5-apache` container so Apache proxies `/mcp`, `/api/v1/`, and `/llms.txt` directly to `mod_aim` while sharing the `./tools` directory:

```yaml
services:
  php-app:
    image: php:8.5-apache
    ports:
      - "80:80"
    volumes:
      - ./public:/var/www/html
      - ./tools:/var/www/aim-tools
    command: >
      bash -c "a2enmod proxy proxy_http headers &&
      echo 'ProxyPass /mcp http://aim-daemon:8080/mcp' >> /etc/apache2/apache2.conf &&
      echo 'ProxyPassReverse /mcp http://aim-daemon:8080/mcp' >> /etc/apache2/apache2.conf &&
      echo 'ProxyPass /api/v1/ http://aim-daemon:8080/api/v1/' >> /etc/apache2/apache2.conf &&
      echo 'ProxyPassReverse /api/v1/ http://aim-daemon:8080/api/v1/' >> /etc/apache2/apache2.conf &&
      echo 'ProxyPass /llms.txt http://aim-daemon:8080/llms.txt' >> /etc/apache2/apache2.conf &&
      apache2-foreground"
    depends_on:
      - aim-daemon

  aim-daemon:
    image: ghcr.io/renegat9/mod_aim:latest
    ports:
      - "127.0.0.1:8081:8081" # Human Control Plane /_admin (localhost only)
    environment:
      AIM_TOOLS_DIR: "/app/tools"
      AIM_DB_PATH: "/data/engine.sqlite"
      AIM_MASTER_KEY: "${AIM_MASTER_KEY:-replace_with_a_32_byte_minimum_aes256_secret}"
      AIM_ADMIN_PASSWORD: "${AIM_ADMIN_PASSWORD:-replace_with_a_strong_admin_password}"
    volumes:
      - ./tools:/app/tools
      - aim_sqlite_data:/data

volumes:
  aim_sqlite_data:
```

#### 2B. Single-Container Injection (`COPY --from` inside an existing `php:8.5-apache` Dockerfile)
Because `aim-daemon` is a self-contained binary, you can inject it into any Debian/Ubuntu-based image (`php:8.5-apache`, `php:8.5-fpm`, `node`, etc.) in a single line:

```dockerfile
FROM ghcr.io/renegat9/mod_aim:latest AS mod_aim_bin

FROM php:8.5-apache
COPY --from=mod_aim_bin /usr/local/bin/aim-daemon /usr/local/bin/aim-daemon

RUN a2enmod proxy proxy_http headers \
    && printf "\nProxyPass /mcp http://127.0.0.1:8080/mcp\nProxyPassReverse /mcp http://127.0.0.1:8080/mcp\nProxyPass /api/v1/ http://127.0.0.1:8080/api/v1/\nProxyPassReverse /api/v1/ http://127.0.0.1:8080/api/v1/\n" >> /etc/apache2/apache2.conf

CMD ["sh", "-c", "/usr/local/bin/aim-daemon & exec apache2-foreground"]
```

### Option 3: Download Pre-Compiled Binaries (GitHub Releases)

1. Go to the **[Releases](https://github.com/renegat9/mod_aim/releases/latest)** page on GitHub.
2. Download the archive for your platform:
   - **Linux (`x86_64`)**: `aim-engine-linux-x86_64.tar.gz` (includes `aim-daemon`, example `.aim` tools, documentation, and Apache/systemd templates).
   - **Windows (`x86_64`)**: `aim-daemon.exe`.
3. Extract and launch `./aim-daemon` (Linux) or `aim-daemon.exe` (Windows).

### Option 4: Build from Source
```bash
cargo test
cargo run --release
```

---

## Repository Structure

```text
├── .github/workflows/build.yml           # CI/CD Pipeline (16 Unit Tests, GitHub Releases & GHCR Docker Image)
├── .devcontainer/devcontainer.json       # 1-Click GitHub Codespaces Configuration (Ports 8080 & 8081)
├── Cargo.toml                            # Rust Manifest & Dependencies (v2.2.0)
├── Dockerfile                            # Multi-stage Zero-Trust Docker Image (non-root aim-runner user)
├── docker-compose.yml                    # Docker Compose Stack (Public 8080 + Local-only 8081 + Volumes)
├── LICENSE                               # MIT License
├── README.md                             # English Documentation (Default)
├── README.fr.md                          # Documentation Française
├── src/
│   ├── main.rs                           # Core mod_aim Engine + 16 Unit & Contract Tests
│   └── admin_ui.html                     # Embedded SPA Human Control Plane UI
├── tools/                                # Hot-Reloaded .aim Tool Definitions (watched via notify)
│   ├── search_invoices.aim               # [native_sql] Declarative invoice search by client & status
│   ├── check_external_status_http.aim    # [native_http] Outbound REST call with Blind Bearer Credential
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
└── docs/                                 # Detailed Technical Guides (EN & FR)
    ├── SPECIFICATION_AIM.en.md           # Full .aim TOML Specification & Engine Reference (EN / FR)
    ├── GUIDE_AGENTS_AND_HITL.en.md       # Agent Integration, HITL Cascade, Webhooks & Self-Authoring (EN / FR)
    ├── DOCKER_AND_ADMIN_SECURITY.en.md   # Docker Deployment, Dual-Port 8080/8081 & Admin Security (EN / FR)
    └── APACHE_DEPLOYMENT.en.md           # Linux, Systemd & Apache 2.4 Production Setup Guide (EN / FR)
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
* [**.aim Format Specification (EN)**](docs/SPECIFICATION_AIM.en.md) | [**(FR)**](docs/SPECIFICATION_AIM.md)
* [**AI Agent Integration, HITL & Webhooks (EN)**](docs/GUIDE_AGENTS_AND_HITL.en.md) | [**(FR)**](docs/GUIDE_AGENTS_ET_HITL.md)
* [**Docker Deployment & Dual-Port Security (EN)**](docs/DOCKER_AND_ADMIN_SECURITY.en.md) | [**(FR)**](docs/DOCKER_ET_SECURITE_ADMIN.md)
* [**Apache 2.4 & Systemd Production Guide (EN)**](docs/APACHE_DEPLOYMENT.en.md) | [**(FR)**](docs/DEPLOIEMENT_APACHE.md)
* [**MIT License (`LICENSE`)**](LICENSE)
