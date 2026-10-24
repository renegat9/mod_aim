# `mod_aim` — Édition Standalone Zero-PHP (Rust)

Moteur serveur compilé en Rust, sécurisé au niveau de la mémoire (*Memory-Safe*), qui expose des fichiers d'outils déclaratifs `.aim` via **MCP (JSON-RPC 2.0)** et **REST**, avec :

1. **Zéro Dépendance d'Interpréteur Externe** : Un binaire unique (`aim-daemon`) embarquant le serveur HTTP/MCP (`axum`), la base SQLite (`rusqlite`), le moteur de script sandboxé (`rhai`) et la surveillance temps réel des fichiers `.aim` (`notify`).
2. **Quotas Matériels par Requête** : Limitation stricte du nombre d'instructions CPU (`max_cpu_instructions`) et de la mémoire par exécution de script Rhai.
3. **Validation Humaine (HITL) en Cascade** :
   - **Niveau 1** : Long-Polling synchrone (`tokio::sync::oneshot`) pendant `long_polling_wait_sec`.
   - **Niveau 2** : Webhook sortant signé par `HMAC-SHA256` (`X-AIM-Signature-256`) avec support de la modification d'arguments à la volée par l'humain.
   - **Niveau 3** : Consultation via le meta-tool natif `_system_check_approval`.
4. **Protocole d'Auto-Guérison (`AIM_CONTRACT_VIOLATION`)** : Génère des erreurs structurées contenant `ai_fix_hint` pour permettre aux LLM de corriger leurs appels automatiquement.

---

## Arborescence du Dépôt

```text
├── .github/workflows/build.yml   # Pipeline CI/CD GitHub Actions (Tests + Binaires Linux & Windows)
├── .devcontainer/                # Configuration GitHub Codespaces (Rust préinstallé)
├── Cargo.toml                    # Manifeste Rust et dépendances
├── src/main.rs                   # Cœur du moteur mod_aim + Tests unitaires intégrés
└── tools/                        # Dossier surveillé en temps réel (Hot-Reload)
    ├── search_invoices.aim       # Exemple d'outil déclaratif pur (native_sql)
    └── apply_credit_note.aim     # Exemple d'outil Rhai sandboxé avec approbation humaine (HITL)
```

---

## Compilation Automatique avec GitHub Actions

À chaque commit sur `main`, le workflow [`.github/workflows/build.yml`](.github/workflows/build.yml) :
1. Exécute les tests unitaires et d'intégration (`cargo test`).
2. Compile le binaire optimisé `aim-daemon` pour **Linux (`x86_64`)** et **Windows (`x86_64`)**.
3. Publie les exécutables prêts à télécharger dans l'onglet **Actions > Artifacts** du dépôt GitHub.

## Exécution Locale

```bash
cargo test
cargo run --release
```

Endpoints exposés par défaut sur `http://127.0.0.1:8080` :
- `POST /mcp` : Serveur MCP JSON-RPC 2.0 (`initialize`, `tools/list`, `tools/call`)
- `POST /api/v1/:tool_name` : Endpoint REST miroir pour chaque outil `.aim`
- `GET /llms.txt` : Documentation générée dynamiquement pour les agents IA
- `GET /_admin` : Console web d'administration et de suivi des tickets HITL
- `POST /_admin/tickets/:ticket_id/resolve` : Approbation, modification ou rejet humain d'un ticket en attente
