# Nova Proxy Admin

Centralized management dashboard for Nginx and backend applications on Ubuntu 22.04. Features SSL automation via Certbot, domain CRUD operations, search auto-discovery, suspension toggles, and a live configuration editor with syntax validation (nginx -t).

## Tech Stack
- Backend: FastAPI, Python 3.12, SQLAlchemy, PyMySQL
- Database: MySQL / MariaDB
- Web Server / Proxy: Nginx, Certbot (Let's Encrypt), systemd

## Installation & Deployment

1. Clone the Repository:
   git clone [https://github.com/linknixon/proxy-web.git](https://github.com/linknixon/proxy-web.git) /opt/proxy-dashboard
   cd /opt/proxy-dashboard

2. Set Up Python Virtual Environment & Dependencies:
   python3 -m venv venv
   source venv/bin/activate
   pip install fastapi uvicorn sqlalchemy pymysql bcrypt

3. Configure Database:
   Create your MySQL database and user:
   CREATE DATABASE proxy_manager;
   CREATE USER 'proxy_user'@'localhost' IDENTIFIED BY 'your_password';
   GRANT ALL PRIVILEGES ON proxy_manager.* TO 'proxy_user'@'localhost';
   FLUSH PRIVILEGES;

4. Create a systemd Service:
   Create /etc/systemd/system/proxy-dashboard.service with your app config, then:
   systemctl daemon-reload
   systemctl enable proxy-dashboard
   systemctl start proxy-dashboard

## Pushing Updates to GitHub
To commit changes and push updates to your GitHub repository:
   git add .
   git commit -m "Nova Proxy Admin - Update"
   git push -u origin main
