# `mod_aim` — Moteur Serveur Rust Autonome Zero-Trust (MCP & REST)

[![Build & Release mod_aim (Rust)](https://github.com/renegat9/mod_aim/actions/workflows/build.yml/badge.svg)](https://github.com/renegat9/mod_aim/actions/workflows/build.yml)

> **Vision :** Un moteur serveur compilé en Rust, 100 % indépendant et sécurisé au niveau de la mémoire (*Memory-Safe*), qui apporte la simplicité du déploiement *"Drop-in"* (un fichier `.aim` déposé = un outil actif instantanément en *Hot-Reload*) tout en éliminant les interpréteurs traditionnels (PHP, Node, Python) et leur surface d'attaque. Pensé pour être codé par des IA, appelé par des agents via **MCP / REST**, et gouverné par des humains.

---

## Fonctionnalités Clés (Architecture Phases 1 à 4 Complètes)

1. **Zéro Dépendance d'Interpréteur Externe** : Un binaire unique (`aim-daemon`) embarquant le serveur HTTP/MCP (`axum`), la base SQLite en mode WAL (`rusqlite`), le moteur de script sandboxé (`rhai`), l'exécuteur WebAssembly (`wasmi` + `wat`), le coffre-fort de secrets **AES-256-GCM** et l'interface web d'administration (`/_admin`).
2. **3 Moteurs d'Exécution Embarqués** :
   - `native_sql` : Requêtes SQL préparées à paramètres nommés (`:param`) sans aucun code interprété.
   - `rhai` : Scripts métier sandboxés en mémoire sans aucune primitive système (`exec`, fichiers ou sockets bruts n'existent pas), bornés par `max_cpu_instructions` et `max_memory_kb`.
   - `wasm` : Exécution de modules WebAssembly isolés avec compteur d'instructions matériel (`consume_fuel`).
3. **Validation Humaine (HITL) en Cascade** :
   - **Niveau 1** : Long-Polling synchrone (`tokio::sync::oneshot`) pendant `long_polling_wait_sec`.
   - **Niveau 2** : Webhook sortant signé cryptographiquement par `HMAC-SHA256` (`X-AIM-Signature-256`) avec possibilité pour l'humain de modifier les arguments JSON avant exécution.
   - **Niveau 3** : Consultation par polling via le meta-tool natif `_system_check_approval`.
4. **Protocole d'Auto-Guérison (`AIM_CONTRACT_VIOLATION`)** : Chaque erreur d'entrée, de sortie ou d'exécution retourne un diagnostic structuré contenant un champ `ai_fix_hint` permettant au LLM de corriger sa requête au tour suivant.
5. **Mode "Self-Authoring" IA (`_system_propose_tool` & `_system_test_tool`)** : Permet à un agent IA de proposer de nouveaux fichiers `.aim` vérifiés à blanc (compilation AST Rhai / module Wasm) et placés en quarantaine dans `/_admin` jusqu'à leur activation en un clic par un humain.

---

## Arborescence du Projet

```text
├── .github/workflows/build.yml           # Pipeline CI/CD GitHub Actions (Tests + Binaires Linux & Windows)
├── .devcontainer/devcontainer.json       # Configuration GitHub Codespaces (1 clic)
├── Cargo.toml                            # Manifeste Rust et dépendances
├── src/
│   ├── main.rs                           # Cœur du moteur mod_aim + 11 tests unitaires et contractuels
│   └── admin_ui.html                     # Interface Web SPA du Control Plane Humain (embarquée dans le binaire)
├── tools/                                # Catalogue d'outils .aim surveillé en temps réel (Hot-Reload)
│   ├── search_invoices.aim               # [native_sql] Recherche déclarative de factures par statut
│   ├── apply_credit_note.aim             # [rhai + HITL] Application d'une note de crédit avec approbation humaine
│   ├── cancel_overdue_invoice.aim        # [rhai + HITL] Annulation contrôlée d'une facture impayée
│   ├── customer_billing_summary.aim      # [rhai + SQL] Analyse d'exposition et calcul du score de risque client
│   └── compute_margin_wasm.aim           # [wasm] Calcul de marge nette en centimes en WebAssembly
│   └── compound_interest_wasm.aim        # [wasm] Calcul d'intérêts composés en boucle WebAssembly bornée par fuel
├── examples/                             # Scripts prêts à l'emploi pour tester le serveur
│   ├── demo_mcp_requests.sh              # Scénario complet curl (MCP, REST, Wasm, Auto-Guérison, HITL)
│   └── webhook_receiver_verify.py        # Serveur Python de vérification des Webhooks signés HMAC-SHA256
├── deploy/                               # Configurations de mise en production
│   ├── config.example.toml               # Exemple de fichier de configuration
│   ├── apache/mod_aim_vhost.conf         # VirtualHost Apache 2.4 Reverse Proxy sécurisé
│   └── systemd/aim-daemon.service        # Unité systemd durcie (NoNewPrivileges, ProtectSystem=strict)
└── docs/                                 # Documentation technique détaillée
    ├── SPECIFICATION_AIM.md              # Spécification complète du format .aim et des 3 moteurs
    ├── GUIDE_AGENTS_ET_HITL.md           # Guide MCP/REST, Cascade HITL, Webhooks et Self-Authoring IA
    └── DEPLOIEMENT_APACHE.md             # Guide d'installation Linux, Systemd et Apache
```

---

## Démarrage Rapide

### Option 1 : Télécharger le binaire pré-compilé depuis GitHub Actions
1. Rendez-vous dans l'onglet **[Actions](https://github.com/renegat9/mod_aim/actions)** du dépôt.
2. Cliquez sur le dernier build vert et téléchargez **`aim-engine-linux-x86_64`** ou **`aim-engine-windows-x86_64`** dans la section **Artifacts**.
3. Lancez `./aim-daemon` (Linux) ou `aim-daemon.exe` (Windows) et ouvrez **`http://127.0.0.1:8080/_admin`**.

### Option 2 : Compiler depuis les sources
```bash
cargo test
cargo run --release
```

---

## Endpoints Exposés (Port `8080` par défaut)

| Méthode & Route | Description |
| :--- | :--- |
| `POST /mcp` | Serveur **MCP JSON-RPC 2.0** (`initialize`, `tools/list`, `tools/call`) |
| `POST /api/v1/:tool_name` | Endpoint **REST** miroir pour chaque fichier `.aim` actif |
| `GET /llms.txt` | Catalogue Markdown généré dynamiquement pour la découverte par les LLM |
| `GET /_admin` | **Control Plane Humain** (Approbation HITL, Switch On/Off, Coffre-Fort AES-256, Clés API, Propositions IA, Simulateur MCP) |
| `POST /_admin/tickets/:id/resolve` | API de résolution humaine d'un ticket HITL (`approve` / `reject` + surcharge d'arguments) |

---

## Documentation Complémentaire

* [**Spécification du format `.aim`**](docs/SPECIFICATION_AIM.md)
* [**Guide d'intégration des Agents IA, Cascade HITL & Webhooks**](docs/GUIDE_AGENTS_ET_HITL.md)
* [**Guide de déploiement Apache 2.4 & Systemd**](docs/DEPLOIEMENT_APACHE.md)
