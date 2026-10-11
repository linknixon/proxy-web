# Nova Proxy Admin

Centralized high-performance management console for Nginx reverse proxies, Host & UFW Firewall (WAF) rule administration, SSL automation, domain lifecycle tracking, and multi-role operations.

Maintained by **[Nova Cloud Edges](https://ncloud.co.ug)**  
Contact us: Email: `support@sun.ac.ug` | Tel: `+256790 00031`

---

## Key Features & Capabilities

- **Primary Apex Domains & Subdomains with Application Labeling**:
  - Full support for primary apex domains (`example.com`, `sun.ac.ug`) and subdomains (`app.example.com`, `api.sun.ac.ug`).
  - Customizable **Application Name / Service Label** for each proxy host (e.g., University Portal, ERP Backend, API Gateway).
  - Reverse proxy upstream mapping with WebSocket upgrade headers, exploit blocking, and SSL enforcement.

- **Host Machine & UFW Firewall (WAF) Management**:
  - Live system-synchronized firewall rule management (`ufw` CLI host engine integration).
  - Comprehensive IP filtering supporting both **IPv4** (`192.168.1.0/24`, `10.0.0.1`) and **IPv6** (`2001:db8::/32`, `2001:db8::1`, `::/0`, `Anywhere`).
  - Action types: `ALLOW`, `DENY`, and `LIMIT` (brute-force rate limiting) across ports 80, 443, 22, 3306, and custom ports.

- **Security & Deployment Audit Trail with Traffic Anomaly Detection**:
  - Real-time logging of administrative actions, proxy deployments, and firewall changes.
  - Automated **Abnormal Traffic & Anomaly Threat Detection**: identifies exploit probing signatures (`.env`, `wp-login`, SQLi, path traversal), brute-force spikes, authentication violations, and high-frequency client request bursts.
  - **Access & Request Distribution by Client IP**: displays top 6 client IPs with live distribution percentages.

- **Managed Action Email Notifications (SMTP)**:
  - Configurable outgoing SMTP server integration (`mail.ncloud.co.ug`, custom SMTP servers with STARTTLS, SSL, or plain auth).
  - Automated email broadcast triggers for:
    1. UFW rule add, edit, status toggle, and deletion.
    2. Domain abuse reports and automated IP drop rules.
    3. Impending SSL certificate expirations (<15 days) and renewals.
    4. Domain registration expiration deadlines (<30 days).
    5. Website suspensions and reactivations.
  - Test alert dispatch endpoint to verify outgoing mail server connectivity.

- **Domain & SSL Expiration Timelines**:
  - Unified timeline tracking both **SSL Certificate expiration** and **Domain Registration expiration**.
  - Days-remaining countdown with health badges (`Healthy (>30d)`, `Expiring Soon`, `Urgent (<15d)`).
  - One-click renewal integration via Certbot.

- **Authentication, Sessions & Security**:
  - Strict authentication with token-based sessions and automated **10-minute inactivity logout**.
  - No public registration; administrative user provisioning with role-based access control (`super_admin`, `webmaster`, `security`, `billing`).
  - Forgot password recovery flow with strict blacklist blocking common and easily guessed passwords (`password`, `123456`, `admin`, common roots).

- **Nginx Server Migration & Configuration Backup**:
  - Full archive backup of all active server blocks as a `.conf` ZIP package.
  - Per-site `.conf` export and drag-and-drop import for migrating websites across servers.

---

## Tech Stack

- **Backend**: FastAPI, Python 3.12, SQLAlchemy, PyMySQL, Pydantic, psutil
- **Database**: MySQL / MariaDB (stored minimal configuration items)
- **Web Server / Proxy**: Nginx, Certbot (Let's Encrypt), systemd, UFW
- **Frontend**: Vanilla HTML5, CSS3 with dark/light themes, pure SVG icons (zero emoji policy), and vanilla JavaScript

---

## Installation & Deployment

### 1. Clone the Repository
```bash
git clone https://github.com/linknixon/proxy-web.git /opt/proxy-dashboard
cd /opt/proxy-dashboard
```

### 2. Set Up Python Virtual Environment & Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn sqlalchemy pymysql pydantic psutil cryptography
```

### 3. Configure Database
```sql
CREATE DATABASE proxy_manager CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'proxy_user'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON proxy_manager.* TO 'proxy_user'@'localhost';
FLUSH PRIVILEGES;
```

Update your database credentials in `app.py` or `.env`.

### 4. Run Locally / Development Server
```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

### 5. Production systemd Service
Create `/etc/systemd/system/proxy-dashboard.service`:
```ini
[Unit]
Description=Nova Proxy Admin Console
After=network.target nginx.service mysql.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/proxy-dashboard
ExecStart=/opt/proxy-dashboard/venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Reload and start:
```bash
systemctl daemon-reload
systemctl enable proxy-dashboard
systemctl start proxy-dashboard
```

---

## Git Operations

To stage changes, commit, and push to GitHub:
```bash
git add .
git commit -m "Nova Proxy Admin - Enhanced security, IPv6 WAF, SMTP alerts, and domain management"
git push -u origin main
```
