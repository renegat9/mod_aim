# `mod_aim` — Édition Standalone Zero-PHP (Rust v1.3 — Phases 1, 2 & 3)

Moteur serveur compilé en Rust, sécurisé au niveau de la mémoire (*Memory-Safe*), qui expose des fichiers d'outils déclaratifs `.aim` via **MCP (JSON-RPC 2.0)** et **REST**, avec :

1. **Zéro Dépendance d'Interpréteur Externe** : Un binaire unique (`aim-daemon`) embarquant le serveur HTTP/MCP (`axum`), la base SQLite en mode WAL (`rusqlite`), le moteur de script sandboxé (`rhai`), le coffre-fort de secrets chiffré **AES-256-GCM** (`aes-gcm`) et l'interface web d'administration complète (`/_admin`).
2. **Quotas Matériels par Requête** : Limitation stricte du nombre d'instructions CPU (`max_cpu_instructions`) et de la mémoire par exécution de script Rhai.
3. **Validation Humaine (HITL) en Cascade & Persistance SQLite** :
   - **Niveau 1** : Long-Polling synchrone (`tokio::sync::oneshot`) pendant `long_polling_wait_sec`.
   - **Niveau 2** : Webhook sortant signé par `HMAC-SHA256` (`X-AIM-Signature-256`) avec support de la modification d'arguments à la volée par l'humain.
   - **Niveau 3** : Consultation via le meta-tool natif `_system_check_approval`.
4. **Control Plane Humain Embarqué (`/_admin`)** :
   - File d'approbation/modification/rejet des tickets HITL en un clic.
   - Interrupteur **Actif / Désactivé** en temps réel par outil `.aim` (persisté dans SQLite).
   - Coffre-fort de connexions **Blind Credentials** chiffré en **AES-256-GCM** (`connections_vault`).
   - Générateur de clés API agents (stockées sous forme de hash SHA-256 dans `api_keys`).
   - Simulateur MCP JSON-RPC en direct et journal d'audit SQLite (`audit_logs`).
