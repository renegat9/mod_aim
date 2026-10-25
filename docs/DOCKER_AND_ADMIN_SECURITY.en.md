# Docker Deployment & Dual-Port Security (`8080` Public vs `8081` Admin)

`mod_aim` enforces **physical port separation** between agent traffic and human administration:

| Port (Default) | Env Variable | Role | Exposed Routes | Security Enforcement |
| :--- | :--- | :--- | :--- | :--- |
| **`8080`** | `AIM_BIND_ADDR` | **Public Data Plane** (AI Agents & REST) | `POST /mcp`<br>`POST /api/v1/:tool`<br>`GET /llms.txt` | Agent API Keys (`Authorization: Bearer aim_live_...`), per-tool `auth_scope` verification, and sliding-window `rate_limit`. **No `/_admin` routes exist on this port.** |
| **`8081`** | `AIM_ADMIN_BIND_ADDR` | **Isolated Control Plane** (Human Admin) | `GET /_admin`<br>`GET /_admin/api/state`<br>`POST /_admin/tickets/:id/resolve` | Mandatory `AIM_ADMIN_PASSWORD` verified via constant-time `SHA-256` comparison + localhost binding (`127.0.0.1:8081`). |

## Run from GitHub Container Registry (`ghcr.io`)

```bash
docker run -d \
  -p 8080:8080 \
  -p 127.0.0.1:8081:8081 \
  -e AIM_MASTER_KEY="your_32_byte_minimum_aes256_master_secret" \
  -e AIM_ADMIN_PASSWORD="your_strong_admin_password" \
  -v $(pwd)/tools:/app/tools \
  -v aim_sqlite_data:/data \
  ghcr.io/renegat9/mod_aim:latest
```


---

## 3. Integrating into an Existing Image (`php:8.5-apache`)

See the ready-to-use templates in [`examples/docker-php-integration/`](../examples/docker-php-integration/) (`docker-compose.yml` for Sidecar mode and `Dockerfile.php85-embedded` for single-container `COPY --from=ghcr.io/renegat9/mod_aim:latest` injection).
