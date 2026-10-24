# Spécification Complète du Format `.aim` (`mod_aim` v2.0)

Un fichier `.aim` est un contrat **100 % autonome** écrit en **TOML**. Il contient à la fois la documentation destinée au LLM, les règles de sécurité et de gouvernance humaine, le schéma strict des entrées et sorties, ainsi que la logique d'exécution.

---

## 1. Structure Générale d'un Fichier `.aim`

Chaque fichier déposé dans le dossier `tools/` (surveillé en temps réel par `notify`) comporte 5 sections :

1. `[tool]` : Métadonnées et canaux d'exposition (`mcp`, `rest`).
2. `[security]` : Scopes d'autorisation, validation humaine (`require_human_approval`) et quotas matériels (`max_cpu_instructions`, `max_memory_kb`).
3. `[input]` : Définition typée des arguments attendus et contraintes de validation (`min`, `max`, `min_len`, `enum`, `default`).
4. `[output]` : Contrat de sortie vérifié systématiquement avant de renvoyer la réponse à l'agent.
5. `[handler]` : Choix du moteur (`native_sql`, `rhai`, ou `wasm`) et code/requête associé.

---

## 2. Référence des Champs par Section

### 2.1. Section `[tool]`

| Champ | Type | Obligatoire | Description |
| :--- | :--- | :--- | :--- |
| `name` | `string` | Oui | Identifiant unique de l'outil (snake_case recommandé). |
| `description` | `string` | Oui | Description claire utilisée par le LLM pour comprendre quand appeler l'outil. |
| `version` | `string` | Oui | Version sémantique de l'outil (ex: `"1.2.0"`). |
| `exposure` | `array<string>` | Oui | Protocoles activés : `["mcp"]`, `["rest"]` ou `["mcp", "rest"]`. |

### 2.2. Section `[security]`

| Champ | Type | Défaut | Description |
| :--- | :--- | :--- | :--- |
| `auth_scope` | `string` | *(Requis)* | Scope requis pour appeler l'outil (ex: `"billing:read"`, `"billing:write"`). |
| `require_human_approval` | `bool` | `false` | Si `true`, déclenche la cascade de validation humaine (HITL) avant toute exécution. |
| `long_polling_wait_sec` | `int` | `25` | Durée (en secondes) pendant laquelle la requête HTTP reste ouverte en attente d'un clic humain. |
| `approval_timeout_sec` | `int` | `86400` | Délai d'expiration d'un ticket HITL en attente (24h par défaut). |
| `max_cpu_instructions` | `int` | `50000` | Quota maximal d'opérations Rhai ou d'unités de *fuel* WebAssembly par requête. |
| `max_memory_kb` | `int` | `1024` | Limite mémoire allouée aux structures dynamiques du script. |

### 2.3. Section `[input]`

Chaque clé de `[input]` définit un paramètre d'entrée :

```toml
[input]
client_id = { type = "int", min = 1, description = "ID unique du client" }
credit_amount = { type = "float", min = 0.01, max = 5000.00 }
status = { type = "string", enum = ["paid", "unpaid", "overdue"], default = "unpaid" }
reason = { type = "string", min_len = 10 }
```

* Types supportés : `"int"`, `"float"`, `"string"`, `"bool"`.
* Contraintes numériques : `min`, `max`.
* Contraintes chaînes : `min_len`, `enum`.
* Valeur par défaut : `default` (rend le champ optionnel dans le schéma JSON-RPC MCP).

### 2.4. Section `[output]`

Deux formats sont possibles :

* **Sortie Objet (Map JSON)** :
  ```toml
  [output]
  new_balance = "float"
  credit_note_ref = "string"
  status = "string"
  ```
* **Sortie Tableau (Array JSON)** :
  ```toml
  [output]
  type = "array"
  items = { invoice_id = "int", amount_total = "float", due_date = "string" }
  ```

---

## 3. Les 3 Moteurs d'Exécution (`[handler]`)

### Moteur 1 : `engine = "native_sql"` (Zéro Code Interprété)
Exécute une requête SQL préparée avec substitution sécurisée des paramètres nommés `:param` :

```toml
[handler]
engine = "native_sql"
connection = "erp_postgres"
query = """
  SELECT id AS invoice_id, amount_total, due_date
  FROM invoices
  WHERE client_id = :client_id AND status = :status
"""
```

### Moteur 2 : `engine = "rhai"` (Sandbox de Script Métier)
Exécute un script Rhai isolé en mémoire. Aucune primitive système (`exec`, fichiers, réseau) n'existe. Seul l'objet pont contrôlé `env` est exposé :
* `env.db_query_one(alias, sql, #{ param: val })` : Retourne la première ligne sous forme de map Rhai ou `()` si vide.
* `env.db_execute(alias, sql, #{ param: val })` : Exécute un `INSERT` / `UPDATE` / `DELETE` paramétré et retourne le nombre de lignes modifiées.
* `env.timestamp_sec()` : Retourne l'horodatage Unix courant en secondes sous forme de chaîne.

### Moteur 3 : `engine = "wasm"` (Sandbox WebAssembly avec Compteur de Fuel)
Exécute une fonction exportée d'un module WebAssembly (inline via `wat` ou fichier binaire via `wasm_file`) avec limitation matérielle du nombre d'instructions (`consume_fuel`) :

```toml
[handler]
engine = "wasm"
wasm_export = "compute"
wasm_param_order = ["revenue_cents", "cost_cents"]
wat = """
(module
  (func (export "compute") (param $rev i64) (param $cost i64) (result i64)
    local.get $rev
    local.get $cost
    i64.sub
  )
)
"""
```
