# Nova Proxy Admin

Centralized high-performance management console for Nginx reverse proxies, Host & UFW Firewall (WAF) rule administration, SSL certificate automation, domain lifecycle tracking, and multi-role edge operations.

Maintained by **[Nova Cloud Edges](https://ncloud.co.ug)**  
Contact us: Email: `support@sun.ac.ug` | Tel: `+256790 00031`

---

## Architecture & System Overview

Nova Proxy Admin provides a secure web console and RESTful API for administering server-level edge proxies and system networking. It interacts directly with host-native engines (**Nginx**, **UFW**, **Certbot**, **psutil**) while persisting only lightweight state, user identities, and role assignments in MySQL/MariaDB.

```
       +-------------------------------------------------------------+
       |               Nova Proxy Admin Console (Web UI)             |
       |  Vanilla HTML5 / CSS3 Dark Theme / SVG Icons / Clean JS    |
       +------------------------------+------------------------------+
                                      | HTTP / REST API (Port 8000)
                                      v
       +-------------------------------------------------------------+
       |                    FastAPI Backend (app.py)                 |
       |  Token Auth (10m Inactivity) | RBAC Permissions | SMTP Alerts|
       +-------+------------------+------------------+---------------+
               |                  |                  |               |
               v                  v                  v               v
      +-----------------+  +--------------+  +---------------+  +------------+
      | Nginx Engine    |  | Host UFW WAF |  | Certbot SSL   |  | MySQL /    |
      | /etc/nginx/     |  | Packet Rules |  | Let's Encrypt |  | MariaDB    |
      | .conf configs   |  | IPv4 & IPv6  |  | Auto-Renew    |  | Minimal DB |
      +-----------------+  +--------------+  +---------------+  +------------+
```

---

## Key Features & Capabilities

### 1. Reverse Proxy & Upstream Routing
- **Apex Domains & Subdomains**: Full routing support for primary apex domains (`example.com`, `sun.ac.ug`) and subdomains (`portal.example.com`, `api.sun.ac.ug`).
- **Application Labeling**: Assign friendly service labels to each virtual host (e.g., *Core ERP*, *Student Portal*, *API Gateway*).
- **Production Directives**: Automated WebSocket upgrade headers (`Upgrade`, `Connection`), HTTP/1.1 keep-alives, SSL redirection, and exploit path blocking.

### 2. Nginx Syntax Debugger with Line Numbers
- **Precise Error Diagnostics**: When testing or deploying configurations, syntax validation issues explicitly report line numbers:
  - `Line X: Directive missing terminating semicolon ';'`
  - `Line X: Unclosed block directive — opening brace '{' is never closed`
  - `Line X: Unexpected closing brace '}' with no matching open block`
  - `Line X: Unclosed quote (single or double) in directive`
- **Native `nginx -t` Parser**: Runs real-time syntax checking against the host `nginx` binary and translates compiler line outputs directly into actionable line alerts.

### 3. Role-Based Access Control (RBAC) & Permissions Matrix
- **Configurable Role Rights**: Super Admin can dynamically configure feature permissions for each system role (`webmaster`, `security`, `billing`).
- **Webmaster Isolation**: Webmasters are strictly restricted from viewing, modifying, or deleting team user accounts. Team management is locked to Super Admin.
- **Dynamic Feature Matrix**: Super Admin can customize which roles have access to proxy host management, creation, editing, site suspensions, firewall rules, abuse monitoring, billing timelines, and configuration migration.

### 4. User Profile, Security & Fish-Eye Password Reveals
- **Circular Profile Widget**: Top-right corner circular avatar displaying user initials and online status dot.
- **Self-Service Password Updates**: Any logged-in user can update their password via their profile popup with real-time password strength validation.
- **Immutable User Emails**: Registered email addresses are displayed read-only on profiles to prevent account hijacking; only Super Admin can alter user email addresses.
- **Fish-Eye Password Reveals**: Interactive eye toggle button on all password fields (login form, password recovery form, change password modal, and user creation form) to reveal or conceal passwords securely.

### 5. Automated Password Recovery via SMTP
- **Email Verification**: Forgot password requests dispatch a cryptographically secure temporary password directly to the user's registered email address.
- **Strict Blacklist**: Password policy enforces minimum 8 characters with mixed casing, digits, and rejects common dictionary passwords (`123456`, `password`, `admin`, etc.).

### 6. Host UFW Firewall & WAF Engine
- **Direct System Synchronization**: Live inspection and management of system packet filter rules (`ufw` engine).
- **Dual-Stack Support**: Native support for **IPv4** (`192.168.1.0/24`, `10.0.0.1`) and **IPv6** (`2001:db8::/32`, `2001:db8::1`, `::/0`, `Anywhere`).
- **Rule Actions**: Support for `ALLOW`, `DENY`, and `LIMIT` (brute-force rate limiting).

### 7. Managed Action Email Notifications (SMTP)
- Automated alerts dispatched over outgoing SMTP (`mail.ncloud.co.ug` / custom SMTP with STARTTLS or SSL on port 587 or 465) for:
  - Firewall rule modifications and port updates
  - Domain abuse detections and automated IP drop rules
  - Impending SSL certificate expirations (<15 days)
  - Impending domain registration expirations (<30 days)
  - Website maintenance suspensions and reactivations
- **Live SMTP Diagnostics**: Integrated interactive test dispatch endpoint with real-time socket and authentication error surfacing.

### 8. Web Traffic Logs & Real-Time Error Monitoring
- **HTTP Response Telemetry**: Comprehensive tracking of HTTP methods (`GET`, `POST`, `PUT`, `DELETE`), status codes (`200 OK`, `404 Not Found`, `502 Bad Gateway`, `504 Gateway Timeout`), response latencies in milliseconds, and bytes sent.
- **Upstream Diagnostic Messages**: Immediate surfacing of upstream connection dropouts, connection refused exceptions, and reverse proxy timeout details.
- **Multi-Node IP Analytics**: Real-time traffic share ranking for the Top 6 client IPs with geographic/datacenter node attribution (*Localhost Console*, *Kampala Fiber Node*, *Entebbe Edge Gateway*, *Cloudflare CDN Proxy*), request counts, and animated gradient visualizers.
- **Threat & Error Filters**: Instant subtab filtering for All Traffic, Errors Only (4xx & 5xx), Critical 5xx Gateway Incidents, and 4xx Client Anomalies, with search and virtual host dropdown selectors.

### 9. Nginx Migration & Full Configuration Archival
- **Full ZIP Export**: Download all active virtual host configurations as a single `.conf` archive.
- **Per-Site Export & Import**: Export individual site `.conf` files and import existing Nginx files with automatic extraction of `server_name`, upstream `proxy_pass`, WebSocket headers, and SSL certificates.

---

## Installing & Configuring Nginx Web Server

Nova Proxy Admin manages host-level Nginx reverse proxy blocks directly. Follow these instructions to install and configure Nginx on your production server.

### 1. Debian & Ubuntu Linux (APT)

#### Step 1: Update repository lists & install Nginx
```bash
sudo apt update
sudo apt install -y nginx
```

#### Step 2: Verify installation & binary version
```bash
nginx -v
# Example output: nginx version: nginx/1.24.0 (Ubuntu)
```

#### Step 3: Enable and start systemd daemon
```bash
sudo systemctl enable nginx
sudo systemctl start nginx
sudo systemctl status nginx
```

#### Step 4: Open Firewall Ports (UFW)
Allow incoming HTTP (port 80) and HTTPS (port 443) traffic through the firewall:
```bash
sudo ufw allow 'Nginx Full'
# Or allow ports individually:
# sudo ufw allow 80/tcp
# sudo ufw allow 443/tcp
sudo ufw status verbose
```

#### Step 5: Directory Structure Overview
Nova Proxy Admin reads and writes configuration files across standard Nginx paths:
- `/etc/nginx/nginx.conf` — Main global Nginx configuration.
- `/etc/nginx/sites-available/` — Repository of all configured virtual host `.conf` files.
- `/etc/nginx/sites-enabled/` — Symlinked configuration files active in the running server.
- `/etc/nginx/conf.d/` — Modular configuration directory included by the master daemon.
- `/var/log/nginx/access.log` — Global access log.
- `/var/log/nginx/error.log` — Global diagnostic error log.

---

### 2. CentOS, RHEL, Rocky Linux & AlmaLinux (DNF / YUM)

#### Step 1: Enable EPEL repository & install Nginx
```bash
sudo dnf install -y epel-release
sudo dnf install -y nginx
```

#### Step 2: Enable & start service
```bash
sudo systemctl enable --now nginx
sudo systemctl status nginx
```

#### Step 3: Configure Firewall (firewalld)
```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

#### Step 4: Configure SELinux for Reverse Proxying
By default, SELinux prevents Nginx from connecting to upstream proxy ports (e.g. `127.0.0.1:8000`, `127.0.0.1:3000`). Grant network connection permissions:
```bash
sudo setsebool -P httpd_can_network_connect 1
```

---

## Installing & Configuring Certbot (Let's Encrypt SSL Automation)

Certbot handles automated retrieval, installation, and renewals of free SSL/TLS certificates issued by the Let's Encrypt Certificate Authority.

### 1. Installation Methods

#### Method A: Official APT Installation (Ubuntu / Debian)
```bash
sudo apt update
sudo apt install -y certbot python3-certbot-nginx
```

#### Method B: Snap Installation (Recommended by EFF for latest releases)
```bash
# Ensure snapd is installed
sudo apt install -y snapd
sudo snap install core; sudo snap refresh core

# Install Certbot via Snap
sudo snap install --classic certbot

# Create symlink so 'certbot' is available in system PATH
sudo ln -sf /snap/bin/certbot /usr/bin/certbot
```

#### Method C: RHEL, Rocky Linux & AlmaLinux
```bash
sudo dnf install -y epel-release
sudo dnf install -y certbot python3-certbot-nginx
```

#### Verify Installation
```bash
certbot --version
# Example output: certbot 2.9.0
```

---

### 2. Obtaining & Installing SSL Certificates

#### Automatic Nginx Plugin Issuance
To automatically fetch and configure an SSL certificate for an apex domain and its subdomain:
```bash
sudo certbot --nginx \
  -d example.com \
  -d www.example.com \
  --non-interactive \
  --agree-tos \
  -m admin@example.com
```

#### Webroot Mode (Zero-Downtime Verification)
If you prefer manual control of Nginx configuration directives:
```bash
sudo certbot certonly --webroot \
  -w /var/www/html \
  -d api.novacloudedges.com \
  --non-interactive \
  --agree-tos \
  -m admin@novacloudedges.com
```

Certificates will be saved to:
- Certificate & Chain: `/etc/letsencrypt/live/example.com/fullchain.pem`
- Private Key: `/etc/letsencrypt/live/example.com/privkey.pem`

---

### 3. Automated Certificate Renewals & Verification

Let's Encrypt certificates expire after 90 days. Certbot automates renewal via a built-in systemd timer.

#### Verify the Systemd Timer is Active
```bash
systemctl status certbot.timer
# Or inspect all scheduled timers:
systemctl list-timers | grep certbot
```

#### Test Renewal Process (Dry Run)
Simulate certificate renewal without altering live certificates:
```bash
sudo certbot renew --dry-run
```

#### Configure Automated Nginx Reload on Renewal
Ensure Nginx gracefully reloads whenever a certificate is renewed. Create `/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh`:
```bash
sudo mkdir -p /etc/letsencrypt/renewal-hooks/deploy/
sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh <<'EOF'
#!/bin/bash
systemctl reload nginx
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
```

---

## Prerequisites & Dependencies

### System Packages (Debian / Ubuntu Linux)

Ensure your server has Python 3.10+, Nginx, UFW, Certbot, and MySQL/MariaDB installed:

```bash
sudo apt update
sudo apt install -y \
  nginx \
  certbot \
  python3-certbot-nginx \
  ufw \
  mysql-server \
  python3-venv \
  python3-pip \
  python3-dev \
  curl \
  git
```

Enable and start fundamental services:
```bash
sudo systemctl enable nginx ufw mysql
sudo systemctl start nginx mysql
sudo ufw enable
```

### Python Libraries

The application uses the following Python packages:

| Library | Version Requirement | Purpose |
| :--- | :--- | :--- |
| `fastapi` | `>=0.110.0` | High-performance asynchronous REST API framework |
| `uvicorn` | `>=0.29.0` | Production ASGI web server |
| `sqlalchemy` | `>=2.0.0` | ORM & database connectivity |
| `pymysql` | `>=1.1.0` | Pure-Python MySQL client driver |
| `pydantic` | `>=2.6.0` | Strict request validation & data parsing |
| `psutil` | `>=5.9.0` | Hardware CPU, RAM, disk, & network telemetry |
| `cryptography` | `>=42.0.0` | Cryptographic functions & SSL certificate parsing |
| `python-multipart`| `>=0.0.9` | Multipart form & file upload handling |

---

## Installation & Quickstart

### 1. Clone the Repository
```bash
git clone https://github.com/linknixon/proxy-web.git /opt/proxy-dashboard
cd /opt/proxy-dashboard
```

### 2. Configure Python Virtual Environment & Install Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install \
  fastapi \
  uvicorn \
  sqlalchemy \
  pymysql \
  pydantic \
  psutil \
  cryptography \
  python-multipart
```

### 3. Initialize MySQL Database
Log into MySQL:
```bash
sudo mysql
```

Execute SQL initialization:
```sql
CREATE DATABASE IF NOT EXISTS proxy_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'proxy_user'@'localhost' IDENTIFIED BY 'YourStrongPassword2026!';
GRANT ALL PRIVILEGES ON proxy_manager.* TO 'proxy_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Set environment variables or update database credentials in `app.py`:
```bash
export DB_USER="proxy_user"
export DB_PASS="YourStrongPassword2026!"
export DB_HOST="127.0.0.1"
export DB_PORT="3306"
export DB_NAME="proxy_manager"
```

### 4. Run Development Server
```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

---

## Production Deployment with systemd

To run the console continuously as a background service managed by Linux `systemd`:

1. Create `/etc/systemd/system/proxy-dashboard.service`:
```ini
[Unit]
Description=Nova Proxy Admin Console Service
After=network.target nginx.service mysql.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/proxy-dashboard
Environment=PYTHONUNBUFFERED=1
Environment=DB_USER=proxy_user
Environment=DB_PASS=YourStrongPassword2026!
Environment=DB_HOST=127.0.0.1
Environment=DB_PORT=3306
Environment=DB_NAME=proxy_manager
ExecStart=/opt/proxy-dashboard/venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000 --workers 2
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

2. Reload daemon and start service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable proxy-dashboard
sudo systemctl start proxy-dashboard
sudo systemctl status proxy-dashboard
```

---

## Production Nginx Reverse Proxy Setup

Proxy external traffic arriving at `proxy.novacloudedges.com` or your IP to the local Uvicorn instance:

```nginx
server {
    listen 80;
    server_name proxy.novacloudedges.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Secure with Certbot:
```bash
sudo certbot --nginx -d proxy.novacloudedges.com --non-interactive --agree-tos -m admin@novacloudedges.com
```

---

## Roles & Default Permissions

| Role | Default Features | Restrictions |
| :--- | :--- | :--- |
| **Super Admin** | Full access to all modules, users, firewall, migration, and role permissions | Cannot be deleted or suspended |
| **Webmaster** | View proxy hosts, create new domains, Nginx syntax tester | Cannot manage team users; cannot edit, delete, or suspend existing domains unless granted |
| **Security Analyst** | WHOIS intelligence, SSL certificate inspector, domain abuse logs, audit trail | Read-only access to host routes; cannot modify firewall rules without permission |
| **Billing Officer** | Domain and SSL expiration timelines, renewal deadlines, Certbot renewal actions | Restricted from host creation and firewall modification |

---

## Troubleshooting & Debugging

- **Nginx Syntax Checking**:
  Run `/api/validate-nginx` or use the **Nginx Syntax Tester** tab to inspect configurations. All errors output exact line numbers:
  ```
  Line 14: Directive missing terminating semicolon ';': 'proxy_pass http://127.0.0.1:8080'
  ```
- **SMTP Alerts Failing**:
  Ensure port 587 (STARTTLS) or 465 (SSL) is open in your server firewall:
  ```bash
  sudo ufw allow out 587/tcp
  ```
  Use the **Test SMTP Alert** button in the console to verify credentials.
- **Log Review**:
  ```bash
  journalctl -u proxy-dashboard -f
  ```

---

## Git Operations & Pushing Changes

To push all updates to GitHub:
```bash
git add .
git commit -m "Nova Proxy Admin - Enhanced security, role matrix, password reveal, and email recovery"
git push -u origin main
```
