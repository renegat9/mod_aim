# Déploiement Docker & Séparation des Ports (`8080` Agents vs `8081` Admin)

Depuis la version `v2.1.0`, `mod_aim` applique une **séparation physique des ports réseau** et intègre une **authentification native** :

---

## 1. Architecture Réseau à Double Port (Dual-Port Zero-Trust)

| Port par défaut | Variable d'environnement | Rôle | Routes Exposées | Protection |
| :--- | :--- | :--- | :--- | :--- |
| **`8080`** | `AIM_BIND_ADDR` | **Data Plane Public** (Agents IA & Clients REST) | `POST /mcp`<br>`POST /api/v1/:tool`<br>`GET /llms.txt` | Clés API (`Authorization: Bearer aim_live_...`) et vérification stricte du `auth_scope` de chaque outil `.aim`. **Aucune route `/_admin` n'existe sur ce port.** |
| **`8081`** | `AIM_ADMIN_BIND_ADDR` | **Control Plane Humain** (Administration & HITL) | `GET /_admin`<br>`GET /_admin/api/state`<br>`POST /_admin/tickets/:id/resolve` | Mot de passe administrateur obligatoire (`AIM_ADMIN_PASSWORD`) vérifié par hachage SHA-256 en temps constant + isolation réseau (`127.0.0.1:8081`). |

---

## 2. Lancement Rapide avec Docker Compose

Le fichier [`docker-compose.yml`](../docker-compose.yml) fourni à la racine du dépôt configure automatiquement :
* Le port **`8080`** ouvert pour vos agents IA (`"8080:8080"`).
* Le port **`8081`** attaché **uniquement à l'interface locale de la machine hôte** (`"127.0.0.1:8081:8081"`), le rendant inaccessible depuis Internet (accessible uniquement en local, via VPN ou tunnel SSH `ssh -L 8081:127.0.0.1:8081 user@serveur`).
* Le montage à chaud du dossier `./tools:/app/tools` (*Hot-Reload*).
* Le volume persistant `aim_sqlite_data:/data` pour la base SQLite en mode WAL.

### Commandes de démarrage :

```bash
export AIM_MASTER_KEY="votre_cle_maitre_aes256_tres_longue"
export AIM_ADMIN_PASSWORD="votre_mot_de_passe_admin_fort"

docker compose up -d --build
```

* **Endpoints Agents IA** : `http://localhost:8080/mcp` et `http://localhost:8080/llms.txt`
* **Console d'Administration Humaine** : `http://127.0.0.1:8081/_admin` (demande le mot de passe `AIM_ADMIN_PASSWORD` à l'ouverture).
