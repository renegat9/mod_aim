# Guide de Déploiement en Production (Apache 2.4 & Systemd)

`mod_aim` est conçu pour tourner en **démon isolé non-privilégié (`aim-daemon`)** derrière Apache (`mod_proxy_http`). Ainsi, même en cas de compromission du serveur frontal Apache, les clés maîtres et la base SQLite de `aim-daemon` demeurent isolées dans un processus système distinct.

---

## 1. Installation du Binaire Compilé

Téléchargez l'artefact Linux (`aim-engine-linux-x86_64.tar.gz`) généré par GitHub Actions :

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin aim-runner
sudo mkdir -p /var/lib/aim-engine /var/www/my-project/aim-tools

tar -xzvf aim-engine-linux-x86_64.tar.gz
sudo cp aim-engine-linux-x86_64/aim-daemon /usr/local/bin/aim-daemon
sudo chmod 755 /usr/local/bin/aim-daemon

sudo cp aim-engine-linux-x86_64/tools/*.aim /var/www/my-project/aim-tools/
sudo chown -R aim-runner:aim-runner /var/lib/aim-engine /var/www/my-project/aim-tools
```

---

## 2. Activation du Service Systemd Durci

Copiez le fichier [`deploy/systemd/aim-daemon.service`](../deploy/systemd/aim-daemon.service) :

```bash
sudo cp deploy/systemd/aim-daemon.service /etc/systemd/system/aim-daemon.service
# Éditez AIM_MASTER_KEY dans le fichier service avant de démarrer
sudo systemctl daemon-reload
sudo systemctl enable --now aim-daemon
sudo systemctl status aim-daemon
```

---

## 3. Configuration du VirtualHost Apache

Activez les modules proxy d'Apache et copiez [`deploy/apache/mod_aim_vhost.conf`](../deploy/apache/mod_aim_vhost.conf) :

```bash
sudo a2enmod proxy proxy_http headers rewrite ssl
sudo cp deploy/apache/mod_aim_vhost.conf /etc/apache2/sites-available/mod_aim.conf
sudo a2ensite mod_aim.conf
sudo systemctl reload apache2
```
