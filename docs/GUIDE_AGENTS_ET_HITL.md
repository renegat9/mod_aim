# Guide d'Intégration des Agents IA, Cascade HITL & Auto-Guérison

Ce guide détaille comment connecter un orchestrateur IA ou un client MCP à `mod_aim`, gérer les validations humaines asynchrones (HITL) et exploiter les erreurs auto-cicatrisantes.

---

## 1. Connexion d'un Client MCP (`POST /mcp`)

`mod_aim` implémente le transport **MCP JSON-RPC 2.0** sur l'endpoint unique `POST /mcp`.

### 1.1. Lister les outils (`tools/list`)
Retourne automatiquement tous les outils `.aim` actifs (dont l'interrupteur est sur `ACTIF` dans `/_admin`) ainsi que les 3 meta-tools système :
* `_system_check_approval`
* `_system_propose_tool`
* `_system_test_tool`

### 1.2. Appeler un outil en REST (`POST /api/v1/:tool_name`)
Tout outil `.aim` est également appelable directement en REST en envoyant ses arguments JSON dans le corps d'un `POST /api/v1/:tool_name`.

---

## 2. Cascade de Validation Humaine (HITL) en 3 Niveaux

Lorsqu'un outil définit `require_human_approval = true` (comme `apply_credit_note.aim` ou `cancel_overdue_invoice.aim`), `mod_aim` protège l'exécution selon 3 niveaux automatiques :

### Niveau 1 : Long-Polling Synchrone (`0` à `long_polling_wait_sec`)
La requête HTTP de l'agent est mise en pause via un canal mémoire `tokio::sync::oneshot`.
* Si un opérateur humain clique sur **[Approuver & Exécuter]** dans `http://localhost:8080/_admin` avant la fin du délai (25 secondes par défaut), l'outil s'exécute immédiatement et l'agent reçoit son résultat dans la **même réponse HTTP**.

### Niveau 2 : Webhook Sortant Signé `HMAC-SHA256` (`_callback`)
Si l'opérateur humain n'a pas encore répondu après 25 secondes, `mod_aim` libère proprement la connexion de l'agent avec :
```json
{
  "status": "PENDING_HUMAN_APPROVAL",
  "ticket_id": "tkt_20261024_a1b2c3d4",
  "delivery_mode": "webhook",
  "poll_tool": "_system_check_approval"
}
```
Dès que l'humain approuve (ou modifie les arguments JSON puis approuve) dans `/_admin`, `mod_aim` exécute l'outil et envoie un `POST` vers `_callback.url` avec :
* En-tête `X-AIM-Ticket-ID: tkt_...`
* En-tête `X-AIM-Signature-256: sha256=<hex_hmac_sha256>` calculé avec `_callback.secret`.

Un script complet de vérification de signature est fourni dans [`examples/webhook_receiver_verify.py`](../examples/webhook_receiver_verify.py).

### Niveau 3 : Polling par l'Agent (`_system_check_approval`)
Pour les agents locaux qui n'ont pas d'URL de webhook entrante, l'agent peut appeler à tout moment le meta-tool MCP `_system_check_approval` avec `{"ticket_id": "tkt_..."}` pour récupérer l'état et le résultat d'exécution du ticket.

---

## 3. Mode "Self-Authoring" IA (`_system_propose_tool` & `_system_test_tool`)

Un agent IA peut créer lui-même de nouvelles capacités pour `mod_aim` sans jamais pouvoir compromettre le serveur :

1. **Test à blanc (`_system_test_tool`)** : L'IA envoie un brouillon `aim_toml` et un jeu d'`arguments`. Le moteur valide le schéma, compile l'AST Rhai ou le module Wasm et exécute l'outil dans la sandbox en retournant le nombre exact d'instructions CPU consommées (`cpu_instructions_used`).
2. **Mise en quarantaine (`_system_propose_tool`)** : Une fois satisfaite, l'IA appelle `_system_propose_tool`. Le moteur vérifie l'AST à blanc et enregistre la proposition dans SQLite (`proposed_tools`).
3. **Activation humaine dans `/_admin`** : L'administrateur humain inspecte le code TOML dans l'onglet **Propositions IA** de `/_admin` et clique sur **[Activer & Écrire dans `tools/<nom>.aim`]**. Le fichier est écrit sur disque et chargé à chaud instantanément.
