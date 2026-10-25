# `mod_aim` — Moteur Serveur Rust Autonome Zero-Trust (MCP & REST)

[![Dernière Release](https://img.shields.io/github/v/release/renegat9/mod_aim?label=Release&color=0284c7)](https://github.com/renegat9/mod_aim/releases/latest)
[![Build & Release mod_aim (Rust)](https://github.com/renegat9/mod_aim/actions/workflows/build.yml/badge.svg)](https://github.com/renegat9/mod_aim/releases/latest)

**Langues :** [🇬🇧 **English**](README.md) | [🇫🇷 **Français**](README.fr.md)

> **Vision :** Un moteur serveur compilé en Rust, 100 % indépendant et sécurisé au niveau de la mémoire (*Memory-Safe*), qui apporte la simplicité du déploiement *"Drop-in"* (un fichier `.aim` déposé = un outil actif instantanément en *Hot-Reload*) tout en éliminant les interpréteurs traditionnels (PHP, Node, Python) et leur surface d'attaque. Pensé pour être codé par des IA, appelé par des agents via **MCP / REST**, et gouverné par des humains.

---

## Fonctionnalités Clés

1. **Zéro Dépendance d'Interpréteur Externe** : Un binaire unique (`aim-daemon`) embarquant le serveur HTTP/MCP (`axum`), la base SQLite en mode WAL (`rusqlite`), le moteur de script sandboxé (`rhai`), l'exécuteur WebAssembly (`wasmi` + `wat`), le coffre-fort de secrets **AES-256-GCM** et l'interface web d'administration (`/_admin`).
2. **Séparation Physique des Ports Réseau (Dual-Port Zero-Trust)** :
   - **Port Public (`8080` — Data Plane Agents)** : Expose uniquement `/mcp`, `/api/v1/:tool_name` et `/llms.txt`, protégés par clés API (`Authorization: Bearer aim_live_...`), contrôle strict du `auth_scope` par outil et limiteur de débit (`rate_limit`). Aucune route d'administration n'existe sur ce port.
   - **Port d'Administration (`8081` — Control Plane Humain)** : Expose uniquement l'interface `/_admin` et ses API de gouvernance, protégées par mot de passe administrateur (`AIM_ADMIN_PASSWORD`, vérifié par hachage `SHA-256` en temps constant).
3. **4 Moteurs d'Exécution Embarqués (`native_sql` SQLite/PostgreSQL, `native_http`, `rhai`, `wasm`)** :
   - `native_sql` : Requêtes SQL préparées (SQLite embarqué ou serveur PostgreSQL externe dont le DSN est chiffré dans le coffre-fort) à paramètres nommés (`:param`) sans aucun code interprété.
   - `native_http` : Appels REST sortants (`GET`, `POST`, `PUT`, `DELETE`) avec substitution `:param` dans l'URL et injection automatique du jeton `Authorization: Bearer <secret>` déchiffré à la volée depuis le coffre-fort AES-256-GCM.
   - `rhai` : Scripts métier sandboxés en mémoire sans aucune primitive système (`exec`, fichiers ou sockets bruts n'existent pas), bornés par `max_cpu_instructions` et `max_memory_kb`.
   - `wasm` : Exécution de modules WebAssembly isolés avec compteur d'instructions matériel (`consume_fuel`).
4. **Validation Humaine (HITL) en Cascade** :
   - **Niveau 1** : Long-Polling synchrone (`tokio::sync::oneshot`) pendant `long_polling_wait_sec`.
   - **Niveau 2** : Webhook sortant signé cryptographiquement par `HMAC-SHA256` (`X-AIM-Signature-256`) avec possibilité pour l'humain de modifier les arguments JSON avant exécution.
   - **Niveau 3** : Consultation par polling via le meta-tool natif `_system_check_approval`.
5. **Protocole d'Auto-Guérison (`AIM_CONTRACT_VIOLATION`)** : Chaque erreur d'entrée, de sortie ou d'exécution retourne un diagnostic structuré contenant un champ `ai_fix_hint` permettant au LLM de corriger sa requête au tour suivant.
6. **Mode "Self-Authoring" IA (`_system_propose_tool` & `_system_test_tool`)** : Permet à un agent IA de proposer de nouveaux fichiers `.aim` vérifiés à blanc (compilation AST Rhai / module Wasm) et placés en quarantaine dans `/_admin` jusqu'à leur activation en un clic par un humain.
7. **Skill IA Prêt à Importer (`skills/mod-aim/SKILL.md`)** : Skill officiel permettant aux agents IA (Gemini, Claude Code, Cursor, Windsurf) d'écrire des outils `.aim`, d'effectuer des appels MCP JSON-RPC 2.0, de gérer les tickets d'approbation HITL et de s'auto-corriger via `AIM_CONTRACT_VIOLATION`.

---

## Démarrage Rapide

### Option 1 : Avec Docker Compose (Recommandé)

Créez un fichier `docker-compose.yml` (utilisant l'image officielle publiée sur `ghcr.io/renegat9/mod_aim:latest`) ainsi qu'un dossier local `./tools` contenant vos fichiers `.aim` :

```yaml
services:
  aim-daemon:
    image: ghcr.io/renegat9/mod_aim:latest
    container_name: mod_aim_daemon
    restart: unless-stopped
    ports:
      # Port Public Data Plane (MCP JSON-RPC 2.0, API REST, /llms.txt)
      - "8080:8080"
      # Port Admin Control Plane (lié uniquement à localhost 127.0.0.1 par sécurité)
      - "127.0.0.1:8081:8081"
    environment:
      AIM_BIND_ADDR: "0.0.0.0:8080"
      AIM_ADMIN_BIND_ADDR: "0.0.0.0:8081"
      AIM_TOOLS_DIR: "/app/tools"
      AIM_DB_PATH: "/data/engine.sqlite"
      AIM_MASTER_KEY: "${AIM_MASTER_KEY:-remplacez_par_une_cle_maitre_aes256_de_32_octets}"
      AIM_ADMIN_PASSWORD: "${AIM_ADMIN_PASSWORD:-remplacez_par_un_mot_de_passe_admin_fort}"
      RUST_LOG: "info"
    volumes:
      # Hot-Reload instantané : tout fichier .aim modifié dans ./tools est chargé à chaud
      - ./tools:/app/tools
      # Persistance SQLite WAL (coffre-fort AES-256, clés API, tickets HITL, audit)
      - aim_sqlite_data:/data
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL

volumes:
  aim_sqlite_data:
```

Lancez le conteneur :
```bash
docker compose up -d
```
* **Data Plane Agents IA (`8080`)** : `http://127.0.0.1:8080/mcp` et `http://127.0.0.1:8080/llms.txt`
* **Control Plane Humain (`8081`)** : `http://127.0.0.1:8081/_admin`

### Option 2 : Intégrer `mod_aim` dans une image ou stack existante (ex: `php:8.5-apache`)

#### 2A. En conteneur Sidecar dans `docker-compose.yml` (Sans modifier votre image PHP)
Ajoutez simplement `aim-daemon` à côté de votre service `php:8.5-apache`. Apache sert votre site PHP habituel sur le port `80` et relaie `/mcp`, `/api/v1/` et `/llms.txt` vers `aim-daemon` tout en partageant le dossier `./tools` :

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
      - "127.0.0.1:8081:8081" # Console humaine /_admin isolée sur localhost
    environment:
      AIM_TOOLS_DIR: "/app/tools"
      AIM_DB_PATH: "/data/engine.sqlite"
      AIM_MASTER_KEY: "${AIM_MASTER_KEY:-remplacez_par_une_cle_maitre_aes256_de_32_octets}"
      AIM_ADMIN_PASSWORD: "${AIM_ADMIN_PASSWORD:-remplacez_par_un_mot_de_passe_admin_fort}"
    volumes:
      - ./tools:/app/tools
      - aim_sqlite_data:/data

volumes:
  aim_sqlite_data:
```

#### 2B. Injection directe dans un seul conteneur (`COPY --from` dans votre `Dockerfile` `php:8.5-apache`)
Comme `aim-daemon` est un binaire autonome, vous pouvez l'injecter en une seule ligne dans n'importe quelle image Debian/Ubuntu existante (`php:8.5-apache`, `php:8.5-fpm`, `node`, etc.) :

```dockerfile
FROM ghcr.io/renegat9/mod_aim:latest AS mod_aim_bin

FROM php:8.5-apache
COPY --from=mod_aim_bin /usr/local/bin/aim-daemon /usr/local/bin/aim-daemon

RUN a2enmod proxy proxy_http headers \
    && printf "\nProxyPass /mcp http://127.0.0.1:8080/mcp\nProxyPassReverse /mcp http://127.0.0.1:8080/mcp\nProxyPass /api/v1/ http://127.0.0.1:8080/api/v1/\nProxyPassReverse /api/v1/ http://127.0.0.1:8080/api/v1/\n" >> /etc/apache2/apache2.conf

CMD ["sh", "-c", "/usr/local/bin/aim-daemon & exec apache2-foreground"]
```

### Option 3 : Télécharger les Binaires Pré-Compilés (GitHub Releases)

1. Rendez-vous sur la page **[Releases](https://github.com/renegat9/mod_aim/releases/latest)** du dépôt GitHub.
2. Téléchargez directement la version compilée correspondant à votre système :
   - **Linux (`x86_64`)** : `aim-engine-linux-x86_64.tar.gz` (inclut le binaire `aim-daemon`, les outils `.aim` d'exemple, la documentation et les modèles Apache/systemd).
   - **Windows (`x86_64`)** : `aim-daemon.exe`.
3. Décompressez et lancez `./aim-daemon` (Linux) ou `aim-daemon.exe` (Windows).

### Option 4 : Compiler depuis les sources
```bash
cargo test
cargo run --release
```

---

## Skill pour Agents IA (`skills/mod-aim/SKILL.md`)

Le dépôt inclut un skill dédié dans [`skills/mod-aim/SKILL.md`](skills/mod-aim/SKILL.md) qui enseigne automatiquement aux assistants et agents IA comment :
- Découvrir le catalogue d'outils via `GET /llms.txt` et `POST /mcp` (`tools/list`).
- Appeler les outils `.aim` en MCP JSON-RPC 2.0 (`tools/call`) et REST (`POST /api/v1/:tool_name`) avec authentification `Bearer`.
- Gérer la cascade de validation humaine HITL en 3 niveaux (`_wait_sec`, webhooks `_callback` signés `HMAC-SHA256` et polling `_system_check_approval`).
- S'auto-corriger automatiquement lors d'une erreur `AIM_CONTRACT_VIOLATION` (`-32000`) ou `AIM_RATE_LIMIT_EXCEEDED` (`-32005`) grâce au champ `ai_fix_hint`.
- Concevoir, tester à blanc (`_system_test_tool`) et soumettre en quarantaine (`_system_propose_tool`) de nouveaux outils `.aim` sur les 4 moteurs (`native_sql`, `native_http`, `rhai`, `wasm`).

### Comment installer le Skill dans votre Agent IA
- **Claude Code / Agents CLI** : Exécutez `npx skills add https://github.com/renegat9/mod_aim --skill mod-aim` ou copiez [`skills/mod-aim/SKILL.md`](skills/mod-aim/SKILL.md) dans votre dossier `skills/mod-aim/SKILL.md`.
- **Gemini / Agents Web** : Importez [`skills/mod-aim/SKILL.md`](skills/mod-aim/SKILL.md) dans votre gestionnaire de skills ou demandez à l'agent d'importer `https://github.com/renegat9/mod_aim/tree/main/skills/mod-aim`.

---

## Arborescence du Projet

```text
├── .github/workflows/build.yml           # Pipeline CI/CD (16 Tests, GitHub Releases & Image Docker GHCR)
├── .devcontainer/devcontainer.json       # Configuration GitHub Codespaces (Ports 8080 & 8081)
├── Cargo.toml                            # Manifeste Rust et dépendances (v2.2.0)
├── Dockerfile                            # Image Docker multi-stage Zero-Trust (utilisateur non-root aim-runner)
├── docker-compose.yml                    # Stack Docker Compose (Port 8080 public + Port 8081 local + volumes)
├── LICENSE                               # Licence MIT
├── README.md                             # Documentation Anglaise (par défaut)
├── README.fr.md                          # Documentation Française
├── src/
│   ├── main.rs                           # Cœur du moteur mod_aim + 16 tests unitaires et contractuels
│   └── admin_ui.html                     # Interface Web SPA du Control Plane Humain (embarquée dans le binaire)
├── tools/                                # Catalogue d'outils .aim surveillé en temps réel (Hot-Reload)
│   ├── search_invoices.aim               # [native_sql] Recherche déclarative de factures par statut
│   ├── check_external_status_http.aim    # [native_http] Appel REST sortant avec Blind Bearer Credential
│   ├── apply_credit_note.aim             # [rhai + HITL] Application d'une note de crédit avec approbation humaine
│   ├── cancel_overdue_invoice.aim        # [rhai + HITL] Annulation contrôlée d'une facture impayée
│   ├── customer_billing_summary.aim      # [rhai + SQL] Analyse d'exposition et calcul du score de risque client
│   ├── compute_margin_wasm.aim           # [wasm] Calcul de marge nette en centimes en WebAssembly
│   └── compound_interest_wasm.aim        # [wasm] Calcul d'intérêts composés en boucle WebAssembly bornée par fuel
├── skills/mod-aim/SKILL.md               # Skill pour Agents IA (Appels MCP, HITL & création d'outils .aim)
├── examples/                             # Scripts prêts à l'emploi pour tester le serveur
│   ├── demo_mcp_requests.sh              # Scénario complet curl (MCP, REST, Wasm, Auto-Guérison, HITL)
│   └── webhook_receiver_verify.py        # Serveur Python de vérification des Webhooks signés HMAC-SHA256
├── deploy/                               # Configurations de mise en production
│   ├── config.example.toml               # Exemple de fichier de configuration
│   ├── apache/mod_aim_vhost.conf         # VirtualHost Apache 2.4 Reverse Proxy sécurisé
│   └── systemd/aim-daemon.service        # Unité systemd durcie (NoNewPrivileges, ProtectSystem=strict)
└── docs/                                 # Documentation technique détaillée (EN & FR)
    ├── SPECIFICATION_AIM.md              # Spécification complète du format .aim et des 4 moteurs (FR / EN)
    ├── GUIDE_AGENTS_ET_HITL.md           # Guide MCP/REST, Cascade HITL, Webhooks et Self-Authoring IA (FR / EN)
    ├── DOCKER_ET_SECURITE_ADMIN.md       # Déploiement Docker, séparation des ports 8080/8081 et sécurité Admin (FR / EN)
    └── DEPLOIEMENT_APACHE.md             # Guide d'installation Linux, Systemd et Apache (FR / EN)
```

---

## Endpoints Exposés

### Port Public Data Plane (`8080` par défaut — `AIM_BIND_ADDR`)

| Méthode & Route | Description |
| :--- | :--- |
| `POST /mcp` | Serveur **MCP JSON-RPC 2.0** (`initialize`, `tools/list`, `tools/call`) |
| `POST /api/v1/:tool_name` | Endpoint **REST** miroir pour chaque fichier `.aim` actif |
| `GET /llms.txt` | Catalogue Markdown généré dynamiquement pour la découverte par les LLM |

### Port d'Administration Isolé (`8081` par défaut — `AIM_ADMIN_BIND_ADDR`)

| Méthode & Route | Description |
| :--- | :--- |
| `GET /_admin` (ou `/`) | **Control Plane Humain** protégé par `AIM_ADMIN_PASSWORD` (Approbation HITL, Switch On/Off, Coffre-Fort AES-256, Clés API, Propositions IA, Simulateur MCP) |
| `GET /_admin/api/state` | État complet du moteur (outils, tickets HITL, propositions IA, coffre-fort, clés API, logs d'audit) |
| `POST /_admin/tickets/:id/resolve` | Approbation, surcharge d'arguments JSON ou rejet humain d'un ticket HITL |

---

## Documentation Complémentaire

* [**🤖 Skill pour Agents IA (`skills/mod-aim/SKILL.md`)**](skills/mod-aim/SKILL.md)
* [**🇬🇧 English Documentation (`README.md`)**](README.md)
* [**Spécification du format `.aim` (FR)**](docs/SPECIFICATION_AIM.md) | [**(EN)**](docs/SPECIFICATION_AIM.en.md)
* [**Guide d'intégration des Agents IA, Cascade HITL & Webhooks (FR)**](docs/GUIDE_AGENTS_ET_HITL.md) | [**(EN)**](docs/GUIDE_AGENTS_AND_HITL.en.md)
* [**Déploiement Docker & Sécurité du Control Plane (FR)**](docs/DOCKER_ET_SECURITE_ADMIN.md) | [**(EN)**](docs/DOCKER_AND_ADMIN_SECURITY.en.md)
* [**Guide de déploiement Apache 2.4 & Systemd (FR)**](docs/DEPLOIEMENT_APACHE.md) | [**(EN)**](docs/APACHE_DEPLOYMENT.en.md)
* [**Licence MIT (`LICENSE`)**](LICENSE)
