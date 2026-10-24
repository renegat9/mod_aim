# `mod_aim` — Édition Standalone Zero-PHP (Rust v2.0 — Phases 1 à 4 Complètes)

Moteur serveur compilé en Rust, sécurisé au niveau de la mémoire (*Memory-Safe*), qui expose des fichiers d'outils déclaratifs `.aim` via **MCP (JSON-RPC 2.0)** et **REST**, couvrant les 4 phases de l'architecture :

1. **Phase 1 — Cœur Rust, Parseur `.aim` & Serveur MCP/REST** :
   - Surveillance temps réel *Hot-Reload* (`notify`) sur le dossier `tools/`.
   - Routes MCP (`/mcp`), REST (`/api/v1/:tool_name`) et documentation dynamique (`/llms.txt`).
2. **Phase 2 — Exécuteurs Zéro-Confiance (`native_sql` & `rhai`) & Auto-Guérison** :
   - Requêtes préparées SQLite (`rusqlite` en mode WAL) et scripts sandboxés `rhai` bornés par `max_cpu_instructions` et `max_memory_kb`.
   - Erreurs structurées `AIM_CONTRACT_VIOLATION` avec `ai_fix_hint`.
3. **Phase 3 — Coffre-Fort `AES-256-GCM`, Control Plane `/_admin` & Cascade HITL** :
   - Secrets chiffrés en `AES-256-GCM` (`connections_vault`), clés API (`api_keys`), états d'outils (`tool_states`), tickets (`approval_tickets`) et audit (`audit_logs`).
   - Cascade HITL : Long-Polling `tokio::sync::oneshot`, Webhook signé `HMAC-SHA256` et meta-tool `_system_check_approval`.
4. **Phase 4 — Mode "Self-Authoring" IA & Sandbox WebAssembly (`engine = "wasm"`)** :
   - Meta-tools MCP `_system_propose_tool` et `_system_test_tool` : validation TOML, compilation à blanc de l'AST `Rhai` ou du module `Wasm`, mise en quarantaine et activation humaine dans `/_admin`.
   - Exécuteur WebAssembly (`wasmi`) avec compteur d'instructions CPU (`consume_fuel`) et outil d'exemple `tools/compute_margin_wasm.aim`.
