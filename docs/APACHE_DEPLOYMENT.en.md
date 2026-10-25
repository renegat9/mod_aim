# Production Deployment Guide (Apache 2.4 & Systemd)

`mod_aim` is designed to run as an **unprivileged isolated daemon (`aim-daemon`)** behind Apache (`mod_proxy_http`). Even if the front-end web server is compromised, the `AES-256-GCM` master key and SQLite vault remain isolated inside the `aim-runner` OS user.

1. **Systemd Service**: Copy [`deploy/systemd/aim-daemon.service`](../deploy/systemd/aim-daemon.service) to `/etc/systemd/system/aim-daemon.service`, set `AIM_MASTER_KEY` and `AIM_ADMIN_PASSWORD`, and run `sudo systemctl enable --now aim-daemon`.
2. **Apache VirtualHost**: Copy [`deploy/apache/mod_aim_vhost.conf`](../deploy/apache/mod_aim_vhost.conf) to `/etc/apache2/sites-available/mod_aim.conf` and enable `proxy`, `proxy_http`, and `headers`.
