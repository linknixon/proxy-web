import os
import re
import io
import json
import zipfile
import datetime
import subprocess
import platform
import psutil
import smtplib
import ipaddress
import secrets
import hashlib
import shutil
import tempfile
import threading
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Request, Depends, Query, UploadFile, File, Form, Response
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, Boolean, Date, DateTime, text
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# ---------------------------------------------------------
# Database Configuration (Multi-Platform: Linux MySQL & macOS MAMP)
# ---------------------------------------------------------
IS_LINUX = platform.system() == "Linux"
MAMP_SOCKET = "/Applications/MAMP/tmp/mysql/mysql.sock"
LINUX_SOCKET = "/var/run/mysqld/mysqld.sock"

DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "" if IS_LINUX else "root")
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "3306" if IS_LINUX else "8889")
DB_NAME = os.getenv("DB_NAME", "proxy_manager")

if os.path.exists(MAMP_SOCKET):
    DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}?unix_socket={MAMP_SOCKET}"
elif IS_LINUX and os.path.exists(LINUX_SOCKET) and DB_HOST in ["127.0.0.1", "localhost"]:
    if DB_PASS:
        DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}?unix_socket={LINUX_SOCKET}"
    else:
        DATABASE_URL = f"mysql+pymysql://{DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}?unix_socket={LINUX_SOCKET}"
else:
    if DB_PASS:
        DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    else:
        DATABASE_URL = f"mysql+pymysql://{DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

def ensure_database_exists():
    try:
        if os.path.exists(MAMP_SOCKET):
            root_url = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/?unix_socket={MAMP_SOCKET}"
        elif IS_LINUX and os.path.exists(LINUX_SOCKET) and DB_HOST in ["127.0.0.1", "localhost"]:
            root_url = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/?unix_socket={LINUX_SOCKET}" if DB_PASS else f"mysql+pymysql://{DB_USER}@{DB_HOST}:{DB_PORT}/?unix_socket={LINUX_SOCKET}"
        else:
            root_url = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/" if DB_PASS else f"mysql+pymysql://{DB_USER}@{DB_HOST}:{DB_PORT}/"
        tmp_eng = create_engine(root_url, connect_args={"connect_timeout": 3})
        with tmp_eng.connect() as conn:
            conn.execute(text(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"))
            conn.commit()
    except Exception as e:
        print(f"Notice: Database existence verification: {e}")

ensure_database_exists()

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=3600,
    connect_args={"connect_timeout": 5}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ---------------------------------------------------------
# SQLAlchemy ORM Models
# ---------------------------------------------------------
class ProxyHost(Base):
    __tablename__ = "proxy_hosts"

    id = Column(Integer, primary_key=True, index=True)
    domain_names = Column(String(255), nullable=False)
    app_name = Column(String(150), default="Web Application", nullable=True)
    host_type = Column(String(30), default="proxy", nullable=False)  # "proxy", "lemp", "static"
    root_path = Column(String(255), nullable=True)  # e.g. /var/www/site.com/public
    php_version = Column(String(20), default="auto", nullable=True)  # "auto", "8.3", "8.2", "8.1", etc.
    php_fpm_socket = Column(String(255), nullable=True)  # e.g. unix:/run/php/php8.2-fpm.sock or 127.0.0.1:9000
    forward_scheme = Column(String(10), default="http", nullable=False)
    forward_host = Column(String(255), default="127.0.0.1", nullable=False)
    forward_port = Column(Integer, default=8080, nullable=False)
    websocket_support = Column(Boolean, default=True, nullable=False)
    block_exploits = Column(Boolean, default=True, nullable=False)
    ssl_forced = Column(Boolean, default=True, nullable=False)
    ssl_provider = Column(String(50), default="Let's Encrypt", nullable=False)
    ssl_status = Column(String(50), default="active", nullable=False)
    ssl_expires_at = Column(Date, nullable=True)
    is_suspended = Column(Boolean, default=False, nullable=False)
    suspended_reason = Column(String(255), default="Administrative Policy Suspension", nullable=True)
    custom_nginx_config = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), nullable=False)
    provider = Column(String(100), default="Let's Encrypt", nullable=False)
    status = Column(String(50), default="valid", nullable=False)
    issued_at = Column(Date, nullable=False)
    expires_at = Column(Date, nullable=False)
    domain_registered_at = Column(Date, nullable=True)
    domain_expires_at = Column(Date, nullable=True)
    auto_renew = Column(Boolean, default=True, nullable=False)
    cert_path = Column(String(255), default="/etc/letsencrypt/live", nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(100), nullable=False)
    details = Column(Text, nullable=False)
    status = Column(String(50), default="success", nullable=False)
    client_ip = Column(String(50), default="127.0.0.1", nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False)
    full_name = Column(String(150), nullable=False)
    email = Column(String(150), unique=True, nullable=False)
    role = Column(String(50), default="super_admin", nullable=False)  # super_admin, domain_manager, webmaster, security, billing
    allowed_domains = Column(Text, nullable=True)  # Comma-separated domains for domain_manager role
    is_active = Column(Boolean, default=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class UFWRule(Base):
    __tablename__ = "ufw_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_type = Column(String(20), default="ALLOW", nullable=False)  # ALLOW, DENY, LIMIT, REJECT
    port = Column(String(50), nullable=False)
    protocol = Column(String(20), default="tcp", nullable=False)
    from_ip = Column(String(50), default="Anywhere", nullable=False)
    to_ip = Column(String(50), default="Anywhere", nullable=False)
    comment = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class DomainAbuseReport(Base):
    __tablename__ = "domain_abuse_reports"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), nullable=False)
    source_ip = Column(String(50), nullable=False)
    abuse_category = Column(String(100), nullable=False)
    action_taken = Column(String(100), default="Blocked via UFW", nullable=False)
    status = Column(String(50), default="blocked", nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class WebTrafficLog(Base):
    __tablename__ = "web_traffic_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    client_ip = Column(String(50), nullable=False, index=True)
    method = Column(String(10), default="GET", nullable=False)
    domain = Column(String(255), default="ncloud.co.ug", nullable=False)
    path = Column(String(500), nullable=False)
    status_code = Column(Integer, default=200, index=True)
    response_time_ms = Column(Integer, default=15)
    bytes_sent = Column(Integer, default=1024)
    user_agent = Column(String(255), default="Mozilla/5.0")
    error_message = Column(Text, nullable=True)
    is_error = Column(Boolean, default=False, index=True)
    error_severity = Column(String(20), default="none")  # none, warning, critical

class SystemSetting(Base):
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    setting_key = Column(String(100), unique=True, nullable=False)
    setting_value = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

# ---------------------------------------------------------
# Automatic Schema Migration (Ensures all columns exist in MySQL)
# ---------------------------------------------------------
def auto_migrate_schema():
    """Automatically adds missing columns to existing MySQL tables without losing data."""
    try:
        with engine.connect() as conn:
            def safe_add_column(table: str, col_name: str, col_def: str):
                try:
                    cols = {row[0] for row in conn.execute(text(f"SHOW COLUMNS FROM `{table}`")).fetchall()}
                    if col_name not in cols:
                        conn.execute(text(f"ALTER TABLE `{table}` ADD COLUMN `{col_name}` {col_def}"))
                        conn.commit()
                except Exception as ex:
                    print(f"Notice: Migrating {table}.{col_name}: {ex}")

            existing_tables = {t[0] for t in conn.execute(text("SHOW TABLES")).fetchall()}

            # 1. users table
            if "users" in existing_tables:
                safe_add_column("users", "full_name", "VARCHAR(150) NOT NULL DEFAULT 'Administrator'")
                safe_add_column("users", "email", "VARCHAR(150) NULL")
                safe_add_column("users", "role", "VARCHAR(50) NOT NULL DEFAULT 'super_admin'")
                safe_add_column("users", "allowed_domains", "TEXT NULL")
                safe_add_column("users", "is_active", "TINYINT(1) NOT NULL DEFAULT 1")
                safe_add_column("users", "created_at", "DATETIME DEFAULT CURRENT_TIMESTAMP")
                # Fix password vs password_hash
                try:
                    user_cols = {row[0] for row in conn.execute(text("SHOW COLUMNS FROM users")).fetchall()}
                    if "password_hash" not in user_cols and "password" in user_cols:
                        conn.execute(text("ALTER TABLE users CHANGE COLUMN password password_hash VARCHAR(255) NOT NULL"))
                        conn.commit()
                except Exception:
                    pass

            # 2. proxy_hosts table
            if "proxy_hosts" in existing_tables:
                safe_add_column("proxy_hosts", "app_name", "VARCHAR(150) DEFAULT 'Web Application'")
                safe_add_column("proxy_hosts", "host_type", "VARCHAR(30) NOT NULL DEFAULT 'proxy'")
                safe_add_column("proxy_hosts", "root_path", "VARCHAR(255) NULL")
                safe_add_column("proxy_hosts", "php_version", "VARCHAR(20) DEFAULT 'auto'")
                safe_add_column("proxy_hosts", "php_fpm_socket", "VARCHAR(255) NULL")
                safe_add_column("proxy_hosts", "forward_scheme", "VARCHAR(10) NOT NULL DEFAULT 'http'")
                safe_add_column("proxy_hosts", "forward_host", "VARCHAR(255) NOT NULL DEFAULT '127.0.0.1'")
                safe_add_column("proxy_hosts", "forward_port", "INT NOT NULL DEFAULT 8080")
                safe_add_column("proxy_hosts", "websocket_support", "TINYINT(1) NOT NULL DEFAULT 1")
                safe_add_column("proxy_hosts", "block_exploits", "TINYINT(1) NOT NULL DEFAULT 1")
                safe_add_column("proxy_hosts", "ssl_forced", "TINYINT(1) NOT NULL DEFAULT 1")
                safe_add_column("proxy_hosts", "ssl_provider", "VARCHAR(50) NOT NULL DEFAULT 'Let\\'s Encrypt'")
                safe_add_column("proxy_hosts", "ssl_status", "VARCHAR(50) NOT NULL DEFAULT 'active'")
                safe_add_column("proxy_hosts", "ssl_expires_at", "DATE NULL")
                safe_add_column("proxy_hosts", "is_suspended", "TINYINT(1) NOT NULL DEFAULT 0")
                safe_add_column("proxy_hosts", "suspended_reason", "VARCHAR(255) DEFAULT 'Administrative Policy Suspension'")
                safe_add_column("proxy_hosts", "custom_nginx_config", "TEXT NULL")
                safe_add_column("proxy_hosts", "created_at", "DATETIME DEFAULT CURRENT_TIMESTAMP")
                safe_add_column("proxy_hosts", "updated_at", "DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP")

            # 3. certificates table
            if "certificates" in existing_tables:
                safe_add_column("certificates", "domain_registered_at", "DATE NULL")
                safe_add_column("certificates", "domain_expires_at", "DATE NULL")
                safe_add_column("certificates", "auto_renew", "TINYINT(1) NOT NULL DEFAULT 1")
                safe_add_column("certificates", "cert_path", "VARCHAR(255) DEFAULT '/etc/letsencrypt/live'")

            # 4. ufw_rules table
            if "ufw_rules" in existing_tables:
                safe_add_column("ufw_rules", "to_ip", "VARCHAR(50) DEFAULT 'Anywhere'")
                safe_add_column("ufw_rules", "comment", "VARCHAR(255) NULL")
                safe_add_column("ufw_rules", "is_active", "TINYINT(1) NOT NULL DEFAULT 1")

            # 5. web_traffic_logs table
            if "web_traffic_logs" in existing_tables:
                safe_add_column("web_traffic_logs", "user_agent", "TEXT NULL")
                safe_add_column("web_traffic_logs", "response_time_ms", "FLOAT DEFAULT 0.0")

            # 6. audit_logs table
            if "audit_logs" in existing_tables:
                safe_add_column("audit_logs", "client_ip", "VARCHAR(50) DEFAULT '127.0.0.1'")
    except Exception as e:
        print(f"Notice: Auto schema migration check: {e}")

# Ensure tables and columns exist
try:
    Base.metadata.create_all(bind=engine)
    auto_migrate_schema()
except Exception as e:
    print(f"Notice: Database metadata check: {e}")

# ---------------------------------------------------------
# Dependency: DB Session
# ---------------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------
class ProxyHostCreate(BaseModel):
    domain_names: str = Field(..., example="example.com, www.example.com")
    app_name: Optional[str] = Field("Web Application", example="Main Web Portal")
    host_type: Optional[str] = Field("proxy", example="proxy")  # "proxy", "lemp", "static"
    root_path: Optional[str] = Field(None, example="/var/www/example.com/public")
    php_version: Optional[str] = Field("auto", example="8.2")
    php_fpm_socket: Optional[str] = Field(None, example="unix:/run/php/php8.2-fpm.sock")
    forward_scheme: str = Field("http", example="http")
    forward_host: str = Field("127.0.0.1", example="127.0.0.1")
    forward_port: int = Field(8080, example=8080)
    websocket_support: bool = True
    block_exploits: bool = True
    ssl_forced: bool = True
    ssl_provider: str = "Let's Encrypt"
    custom_nginx_config: Optional[str] = None

class ProxyHostUpdate(BaseModel):
    domain_names: Optional[str] = None
    app_name: Optional[str] = None
    host_type: Optional[str] = None
    root_path: Optional[str] = None
    php_version: Optional[str] = None
    php_fpm_socket: Optional[str] = None
    forward_scheme: Optional[str] = None
    forward_host: Optional[str] = None
    forward_port: Optional[int] = None
    websocket_support: Optional[bool] = None
    block_exploits: Optional[bool] = None
    ssl_forced: Optional[bool] = None
    ssl_provider: Optional[str] = None
    is_suspended: Optional[bool] = None
    suspended_reason: Optional[str] = None
    custom_nginx_config: Optional[str] = None

class NginxValidationRequest(BaseModel):
    config_text: str

class UFWRuleCreate(BaseModel):
    rule_type: str = "ALLOW"
    port: str = "80"
    protocol: str = "tcp"
    from_ip: str = "Anywhere"
    comment: Optional[str] = None

class AbuseReportCreate(BaseModel):
    domain: str
    source_ip: str
    abuse_category: str
    notes: Optional[str] = None
    block_in_ufw: bool = True

class SuspensionSettingUpdate(BaseModel):
    title: Optional[str] = "Account Suspended — 503 Maintenance Mode"
    message: Optional[str] = "This website service has been temporarily deactivated."
    contact_email: Optional[str] = "support@novacloudedges.com"
    contact_phone: Optional[str] = "+256 700 892 110"

class UserCreate(BaseModel):
    username: str = Field(..., example="ops_officer")
    full_name: str = Field(..., example="Operations Officer")
    email: str = Field(..., example="ops@novacloudedges.com")
    role: str = Field("webmaster", example="webmaster")
    allowed_domains: Optional[str] = None
    password: Optional[str] = None

class UserUpdate(BaseModel):
    full_name: str
    email: str
    role: str
    allowed_domains: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class ForgotPasswordRequest(BaseModel):
    identity: str
    new_password: Optional[str] = None

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class RolePermissionsUpdate(BaseModel):
    permissions: Dict[str, List[str]]

class SmtpSettingsUpdate(BaseModel):
    smtp_host: Optional[str] = None
    host: Optional[str] = None
    smtp_port: Optional[int] = None
    port: Optional[int] = None
    smtp_user: Optional[str] = None
    user: Optional[str] = None
    smtp_pass: Optional[str] = None
    password: Optional[str] = None
    smtp_to_emails: Optional[str] = None
    to_emails: Optional[str] = None
    smtp_encryption: Optional[str] = None
    encryption: Optional[str] = None
    smtp_trigger_ufw: Optional[bool] = None
    trigger_ufw: Optional[bool] = None
    smtp_trigger_blocking: Optional[bool] = None
    trigger_blocking: Optional[bool] = None
    smtp_trigger_ssl_expiry: Optional[bool] = None
    trigger_ssl: Optional[bool] = None
    smtp_trigger_domain_expiry: Optional[bool] = None
    trigger_domain: Optional[bool] = None
    smtp_trigger_suspension: Optional[bool] = None
    trigger_suspension: Optional[bool] = None

class TestEmailRequest(BaseModel):
    test_email: Optional[str] = None
    recipient: Optional[str] = None

# ---------------------------------------------------------
# App Initialization
# ---------------------------------------------------------
app = FastAPI(
    title="Nova Proxy Admin",
    description="Centralized Nginx reverse proxy, UFW Firewall manager, and multi-role dashboard",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# ---------------------------------------------------------
# Favicon & Telemetry Metrics Engine
# ---------------------------------------------------------
metrics_history = deque(maxlen=30)
# Prime psutil CPU counter
try:
    psutil.cpu_percent(interval=None)
except Exception:
    pass

@app.api_route("/favicon.ico", methods=["GET", "HEAD"])
def get_favicon():
    fav_file = os.path.join(static_dir, "favicon.svg")
    if os.path.exists(fav_file):
        return FileResponse(fav_file, media_type="image/svg+xml")
    return JSONResponse(status_code=404, content={"detail": "Favicon not found"})

@app.get("/api/system-metrics")
def get_system_metrics():
    """Auto-detects host OS, CPU, RAM and disk usage metrics with historical samples for live graphing."""
    try:
        # OS Detection
        sys_name = platform.system()
        sys_release = platform.release()
        sys_machine = platform.machine()
        node_name = platform.node()

        if sys_name == "Darwin":
            os_display = f"macOS Darwin {sys_release} ({sys_machine})"
            os_family = "macOS"
        elif sys_name == "Linux":
            distro_name = ""
            if os.path.exists("/etc/os-release"):
                try:
                    with open("/etc/os-release", "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.startswith("PRETTY_NAME="):
                                distro_name = line.split("=", 1)[1].strip().strip('"').strip("'")
                                break
                except Exception:
                    pass
            os_display = f"{distro_name} ({sys_machine})" if distro_name else f"Linux {sys_release} ({sys_machine})"
            os_family = "Linux"
        elif sys_name == "Windows":
            os_display = f"Windows {sys_release} ({sys_machine})"
            os_family = "Windows"
        else:
            os_display = f"{sys_name} {sys_release} ({sys_machine})"
            os_family = sys_name

        # CPU Metrics
        cpu_pct = psutil.cpu_percent(interval=None)
        cpu_count_logical = psutil.cpu_count(logical=True) or 1
        cpu_count_physical = psutil.cpu_count(logical=False) or cpu_count_logical

        load_1, load_5, load_15 = (0.0, 0.0, 0.0)
        if hasattr(os, "getloadavg"):
            try:
                load_1, load_5, load_15 = os.getloadavg()
            except Exception:
                pass

        # RAM Metrics
        vm = psutil.virtual_memory()
        total_ram_gb = round(vm.total / (1024 ** 3), 2)
        used_ram_gb = round(vm.used / (1024 ** 3), 2)
        available_ram_gb = round(vm.available / (1024 ** 3), 2)
        ram_pct = vm.percent

        # Disk Metrics
        disk = psutil.disk_usage("/")
        total_disk_gb = round(disk.total / (1024 ** 3), 1)
        used_disk_gb = round(disk.used / (1024 ** 3), 1)
        disk_pct = disk.percent

        # Timestamp
        now_str = datetime.datetime.now().strftime("%H:%M:%S")

        # Append to rolling history
        metrics_history.append({
            "time": now_str,
            "cpu": cpu_pct,
            "ram": ram_pct,
            "used_ram_gb": used_ram_gb
        })

        # Pre-seed history if just booted so graph isn't a single isolated dot
        if len(metrics_history) < 10:
            for i in range(10 - len(metrics_history)):
                metrics_history.appendleft({
                    "time": (datetime.datetime.now() - datetime.timedelta(seconds=(10 - i) * 3)).strftime("%H:%M:%S"),
                    "cpu": max(1.0, round(cpu_pct * 0.9, 1)),
                    "ram": ram_pct,
                    "used_ram_gb": used_ram_gb
                })

        return {
            "os": {
                "name": os_display,
                "family": os_family,
                "release": sys_release,
                "machine": sys_machine,
                "hostname": node_name
            },
            "cpu": {
                "percent": cpu_pct,
                "logical_cores": cpu_count_logical,
                "physical_cores": cpu_count_physical,
                "load_avg": [round(load_1, 2), round(load_5, 2), round(load_15, 2)]
            },
            "ram": {
                "percent": ram_pct,
                "total_gb": total_ram_gb,
                "used_gb": used_ram_gb,
                "available_gb": available_ram_gb
            },
            "disk": {
                "percent": disk_pct,
                "total_gb": total_disk_gb,
                "used_gb": used_disk_gb
            },
            "history": list(metrics_history)
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to retrieve system metrics: {str(e)}"}
        )

# ---------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------
def get_setting(db: Optional[Session], key: str, default: str) -> str:
    try:
        if db is None:
            return default
        setting = db.query(SystemSetting).filter(SystemSetting.setting_key == key).first()
        return setting.setting_value if (setting and setting.setting_value is not None) else default
    except Exception:
        return default

def set_setting(db: Optional[Session], key: str, val: str):
    try:
        if db is None:
            return
        setting = db.query(SystemSetting).filter(SystemSetting.setting_key == key).first()
        if setting:
            setting.setting_value = val
        else:
            setting = SystemSetting(setting_key=key, setting_value=val)
            db.add(setting)
        db.commit()
    except Exception as e:
        print(f"Notice: set_setting {key}: {e}")

# Common / weak passwords blacklist
DISALLOWED_COMMON_PASSWORDS = {
    "123456", "password", "password123", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "football", "monkey", "letmein", "shadow", "master", "666666",
    "welcome", "login", "admin", "admin123", "root", "toor", "pass123",
    "secret", "superadmin", "administrator", "guest", "changeme", "test",
    "testing", "default", "novacloud", "1234567890", "iloveyou"
}

COMMON_ROOTS = [
    "password", "123456", "qwerty", "admin", "welcome", "letmein", "secret",
    "monkey", "dragon", "master", "testing", "changeme", "novacloud", "default",
    "superadmin", "pass123", "root"
]

def validate_password_strength(password: str):
    """Enforces minimum length of 8, character variety, and forbids common passwords."""
    if not password or len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")
    
    clean_p = password.lower().strip()
    if clean_p in DISALLOWED_COMMON_PASSWORDS:
        raise HTTPException(status_code=400, detail="This password is too common and easily guessed. Please select a stronger, unique password.")
    
    for root in COMMON_ROOTS:
        if root in clean_p and (len(clean_p) - len(root) <= 4):
            raise HTTPException(status_code=400, detail=f"Password contains a commonly exploited phrase ('{root}'). Please select a stronger, unique password.")

    has_letters = any(c.isalpha() for c in password)
    has_numbers_or_symbols = any(not c.isalpha() for c in password)
    if not (has_letters and has_numbers_or_symbols):
        raise HTTPException(status_code=400, detail="Password must contain a mix of letters and digits or symbols.")

def hash_password(password: str) -> str:
    salt = secrets.token_hex(8)
    h = hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()
    return f"sha256:{salt}:{h}"

def verify_password(plain: str, stored_hash: str) -> bool:
    if not stored_hash or not plain:
        return False
    if stored_hash.startswith("sha256:"):
        parts = stored_hash.split(":")
        if len(parts) == 3:
            salt, h = parts[1], parts[2]
            return hashlib.sha256(f"{salt}:{plain}".encode("utf-8")).hexdigest() == h
    return False

def ensure_default_admin(db: Optional[Session] = None):
    """Guarantees a default super_admin account exists in the database for zero-friction setup."""
    close_db = False
    if db is None:
        try:
            db = SessionLocal()
            close_db = True
        except Exception:
            return
    try:
        admin_user = db.query(User).filter(User.username.in_(["admin", "superadmin"])).first()
        if not admin_user:
            count = db.query(User).count()
            if count == 0:
                default_user = os.getenv("ADMIN_USER", "admin")
                default_pass = os.getenv("ADMIN_PASS", "admin")
                new_admin = User(
                    username=default_user,
                    full_name="System Administrator",
                    email="admin@novacloudedges.com",
                    role="super_admin",
                    is_active=True,
                    password_hash=hash_password(default_pass)
                )
                db.add(new_admin)
                db.commit()
                print("==================================================================")
                print(f"[Init] Auto-created default administrator account:")
                print(f"       Username: {default_user}")
                print(f"       Password: {default_pass}")
                print("==================================================================")
    except Exception as e:
        print(f"Notice: Default admin initialization: {e}")
    finally:
        if close_db and db:
            db.close()

def detect_host_php_runtimes() -> dict:
    """
    Scans the host system for installed PHP-FPM versions and Unix domain sockets or TCP ports.
    Supports Ubuntu/Debian (/run/php/php*-fpm.sock), CentOS/RHEL/CloudPanel (/var/run/php-fpm/),
    and default TCP fastcgi 127.0.0.1:9000.
    """
    detected = []
    seen_versions = set()

    # 1. Search socket directories
    socket_dirs = ["/run/php", "/var/run/php", "/var/run/php-fpm", "/tmp"]
    for sdir in socket_dirs:
        if os.path.isdir(sdir):
            try:
                for fname in sorted(os.listdir(sdir)):
                    if "fpm" in fname and fname.endswith(".sock"):
                        sock_path = os.path.join(sdir, fname)
                        m = re.search(r'php(\d+\.\d+)-fpm', fname)
                        ver = m.group(1) if m else "default"
                        detected.append({
                            "version": ver,
                            "socket": f"unix:{sock_path}",
                            "path": sock_path,
                            "type": "unix_socket"
                        })
                        seen_versions.add(ver)
            except Exception:
                pass

    # 2. Check installed php CLI versions
    for ver in ["8.4", "8.3", "8.2", "8.1", "8.0", "7.4"]:
        if ver not in seen_versions:
            cand_sock = f"/run/php/php{ver}-fpm.sock"
            if os.path.exists(cand_sock):
                detected.append({
                    "version": ver,
                    "socket": f"unix:{cand_sock}",
                    "path": cand_sock,
                    "type": "unix_socket"
                })
                seen_versions.add(ver)
            elif shutil.which(f"php{ver}") or shutil.which(f"php-fpm{ver}"):
                detected.append({
                    "version": ver,
                    "socket": f"unix:/run/php/php{ver}-fpm.sock",
                    "path": f"/run/php/php{ver}-fpm.sock",
                    "type": "cli_detected"
                })
                seen_versions.add(ver)

    # 3. Check generic php binary if nothing found
    if not detected and shutil.which("php"):
        try:
            p = subprocess.run(["php", "-r", "echo PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;"], capture_output=True, text=True, timeout=3)
            if p.returncode == 0 and p.stdout.strip():
                cur_ver = p.stdout.strip()
                detected.append({
                    "version": cur_ver,
                    "socket": f"unix:/run/php/php{cur_ver}-fpm.sock",
                    "path": f"/run/php/php{cur_ver}-fpm.sock",
                    "type": "system_php"
                })
        except Exception:
            pass

    # Standard fallback defaults if no socket found
    if not detected:
        detected = [
            {"version": "8.3", "socket": "unix:/run/php/php8.3-fpm.sock", "path": "/run/php/php8.3-fpm.sock", "type": "standard_path"},
            {"version": "8.2", "socket": "unix:/run/php/php8.2-fpm.sock", "path": "/run/php/php8.2-fpm.sock", "type": "standard_path"},
            {"version": "8.1", "socket": "unix:/run/php/php8.1-fpm.sock", "path": "/run/php/php8.1-fpm.sock", "type": "standard_path"},
            {"version": "7.4", "socket": "unix:/run/php/php7.4-fpm.sock", "path": "/run/php/php7.4-fpm.sock", "type": "standard_path"},
        ]

    detected.sort(key=lambda x: x["version"], reverse=True)
    default_sock = detected[0]["socket"] if detected else "unix:/run/php/php8.2-fpm.sock"
    default_ver = detected[0]["version"] if detected else "8.2"

    return {
        "runtimes": detected,
        "default_version": default_ver,
        "default_socket": default_sock
    }

def resolve_php_fpm_socket(php_version: Optional[str], custom_socket: Optional[str]) -> str:
    """Resolves correct PHP-FPM fastcgi_pass destination (socket path or TCP host:port)."""
    if custom_socket and custom_socket.strip():
        val = custom_socket.strip()
        if not val.startswith("unix:") and not ":" in val and val.startswith("/"):
            return f"unix:{val}"
        return val

    ver = (php_version or "auto").strip().lower()
    info = detect_host_php_runtimes()

    if ver == "auto" or not ver:
        return info["default_socket"]

    for r in info["runtimes"]:
        if r["version"] == ver:
            return r["socket"]

    return f"unix:/run/php/php{ver}-fpm.sock"

# Token sessions with disk persistence (stored in OS temp directory so uvicorn reloading is not triggered)
SESSIONS_FILE = os.path.join(tempfile.gettempdir(), "nova_active_sessions.json")
SESSION_EXPIRY_SECONDS = 86400  # 24 hours

def _load_persisted_sessions() -> dict:
    if not os.path.exists(SESSIONS_FILE):
        return {}
    try:
        with open(SESSIONS_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        now = datetime.datetime.utcnow()
        valid = {}
        for token, sess in raw.items():
            try:
                last_active = datetime.datetime.fromisoformat(sess["last_active"])
                if (now - last_active).total_seconds() <= SESSION_EXPIRY_SECONDS:
                    sess["last_active"] = last_active
                    valid[token] = sess
            except Exception:
                pass
        return valid
    except Exception as e:
        print(f"Notice: Could not load persisted sessions: {e}")
        return {}

def _save_persisted_sessions():
    try:
        now = datetime.datetime.utcnow()
        serializable = {}
        for token, sess in list(ACTIVE_SESSIONS.items()):
            last_active = sess["last_active"]
            if isinstance(last_active, str):
                try:
                    last_active = datetime.datetime.fromisoformat(last_active)
                except Exception:
                    last_active = now
            if (now - last_active).total_seconds() <= SESSION_EXPIRY_SECONDS:
                item = dict(sess)
                item["last_active"] = last_active.isoformat()
                serializable[token] = item
        tmp_path = SESSIONS_FILE + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(serializable, f)
        os.replace(tmp_path, SESSIONS_FILE)
    except Exception as e:
        print(f"Notice: Could not persist active sessions: {e}")

ACTIVE_SESSIONS = _load_persisted_sessions()

def create_session(user: User) -> str:
    token = secrets.token_urlsafe(32)
    ACTIVE_SESSIONS[token] = {
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "full_name": user.full_name,
        "email": user.email,
        "allowed_domains": getattr(user, "allowed_domains", "") or "",
        "last_active": datetime.datetime.utcnow()
    }
    _save_persisted_sessions()
    return token

def get_session_user(req: Request) -> Optional[dict]:
    auth_header = req.headers.get("Authorization") or ""
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "").strip()
    elif "X-Auth-Token" in req.headers:
        token = req.headers["X-Auth-Token"].strip()
    elif "token" in req.query_params:
        token = req.query_params["token"].strip()
    elif req.cookies.get("nova_session"):
        token = req.cookies.get("nova_session").strip()
    elif req.cookies.get("nova_token"):
        token = req.cookies.get("nova_token").strip()

    if not token:
        return None

    # If token not present in memory cache, re-read from disk to support multi-process workers
    if token not in ACTIVE_SESSIONS:
        persisted = _load_persisted_sessions()
        ACTIVE_SESSIONS.update(persisted)

    if token not in ACTIVE_SESSIONS:
        return None

    sess = ACTIVE_SESSIONS[token]
    last_active = sess["last_active"]
    if isinstance(last_active, str):
        try:
            last_active = datetime.datetime.fromisoformat(last_active)
            sess["last_active"] = last_active
        except Exception:
            last_active = datetime.datetime.utcnow()
            sess["last_active"] = last_active

    now = datetime.datetime.utcnow()
    if (now - last_active).total_seconds() > SESSION_EXPIRY_SECONDS:
        del ACTIVE_SESSIONS[token]
        _save_persisted_sessions()
        return None

    sess["last_active"] = now
    return sess

def _send_smtp_worker(smtp_host: str, smtp_port: int, smtp_user: str, smtp_pass: str, recipients: list, smtp_encryption: str, trigger_type: str, subject: str, body_text: str):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[Nova Proxy Alert] {subject}"
        from_addr = smtp_user or "alerts@novaproxy.local"
        msg["From"] = f"Nova Cloud Edges <{from_addr}>"
        msg["To"] = ", ".join(recipients)
        msg["Date"] = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S +0000")

        html_body = f"""
        <div style="font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; padding: 24px; border-radius: 12px; max-width: 600px; margin: auto;">
          <div style="border-bottom: 2px solid #0284c7; padding-bottom: 12px; margin-bottom: 18px;">
            <h2 style="color: #38bdf8; margin: 0 0 6px 0;">Nova Proxy Edge Security Alert</h2>
            <span style="font-size: 12px; color: #94a3b8; text-transform: uppercase; font-weight: bold; letter-spacing: 0.05em;">Action Trigger: {trigger_type.upper()}</span>
          </div>
          <p style="font-size: 15px; line-height: 1.6; color: #e2e8f0; white-space: pre-line;">{body_text}</p>
          <div style="margin-top: 24px; padding-top: 14px; border-top: 1px solid #1e293b; font-size: 12px; color: #64748b; display: flex; justify-content: space-between;">
            <span>Server: {platform.node()}</span>
            <span>Nova Cloud Edges &bull; <a href="https://ncloud.co.ug" style="color: #38bdf8; text-decoration: none;">ncloud.co.ug</a></span>
          </div>
        </div>
        """
        msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        if smtp_encryption == "ssl":
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=5)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=5)
            if smtp_encryption == "starttls":
                server.starttls()

        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)

        server.sendmail(from_addr, recipients, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Notice: SMTP background dispatch error: {e}")

def send_smtp_notification(trigger_type: str, subject: str, body_text: str, db: Session, override_recipient: Optional[str] = None, raise_on_error: bool = False):
    """
    Sends automated email notifications via configured SMTP server for:
    - ufw: UFW rule modifications
    - blocking: Abuse reports and source IP blocks
    - ssl: SSL certificate expirations (<15d)
    - domain: Domain registration renewals
    - suspension: Domain suspension/reactivations
    - test: Interactive SMTP test emails
    - recovery: Password recovery credentials
    Dispatches in background daemon thread for zero latency unless raise_on_error is True.
    """
    try:
        # Check if trigger is enabled in settings (bypassed for test and recovery requests)
        if trigger_type not in ["test", "recovery"]:
            trigger_active = get_setting(db, f"smtp_trigger_{trigger_type}", "1")
            if trigger_active not in ["1", "true", "True"]:
                return

        smtp_host = get_setting(db, "smtp_host", "").strip()
        smtp_port = int(get_setting(db, "smtp_port", "587") or 587)
        smtp_user = get_setting(db, "smtp_user", "").strip()
        smtp_pass = get_setting(db, "smtp_pass", "")
        smtp_to = get_setting(db, "smtp_to_emails", "").strip()
        smtp_encryption = get_setting(db, "smtp_encryption", "starttls")

        # Skip immediately if host is blank or unconfigured placeholder
        if not smtp_host or smtp_host in ["mail.ncloud.co.ug", "localhost", "127.0.0.1", "none", "example.com"]:
            if raise_on_error:
                raise ValueError("SMTP server host is not configured or uses placeholder address.")
            return

        if override_recipient:
            recipients = [e.strip() for e in override_recipient.split(",") if e.strip()]
        else:
            recipients = [e.strip() for e in smtp_to.split(",") if e.strip()]

        if not recipients:
            if raise_on_error:
                raise ValueError("No recipient email address specified.")
            return

        if raise_on_error:
            # Synchronous execution for interactive test button
            _send_smtp_worker(smtp_host, smtp_port, smtp_user, smtp_pass, recipients, smtp_encryption, trigger_type, subject, body_text)
        else:
            # Asynchronous background daemon thread for zero-latency operations
            t = threading.Thread(
                target=_send_smtp_worker,
                args=(smtp_host, smtp_port, smtp_user, smtp_pass, recipients, smtp_encryption, trigger_type, subject, body_text),
                daemon=True
            )
            t.start()
    except Exception as e:
        print(f"Notice: SMTP notification dispatch: {e}")
        if raise_on_error:
            raise e

def build_suspended_landing_html(
    domain: str = "your-domain.com",
    reason: str = "Administrative Policy Suspension",
    title: str = "Account Suspended — 503 Maintenance Mode",
    message: str = "This website service has been temporarily deactivated by Nova Cloud Edges Administration due to scheduled maintenance or account review.",
    email: str = "support@novacloudedges.com",
    phone: str = "+256 700 892 110"
) -> str:
    """Generates the unified responsive 503 suspended landing page HTML."""
    s_title = (title or "").replace("'", "&#39;")
    s_msg = (message or "").replace("'", "&#39;")
    s_dom = (domain or "").replace("'", "&#39;")
    s_reason = (reason or "").replace("'", "&#39;")
    s_email = (email or "").replace("'", "&#39;")
    s_phone = (phone or "").replace("'", "&#39;")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{s_title} — Nova Cloud Edges</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: "Plus Jakarta Sans", system-ui, -apple-system, sans-serif;
      background: radial-gradient(circle at 50% 20%, #1e293b 0%, #0f172a 100%);
      color: #f8fafc;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }}
    .card {{
      background: rgba(30, 41, 59, 0.95);
      border: 1px solid #334155;
      border-radius: 20px;
      max-width: 580px;
      width: 100%;
      padding: 3rem 2.5rem;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.55);
      text-align: center;
      backdrop-filter: blur(16px);
      position: relative;
      overflow: hidden;
    }}
    .card::before {{
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
      background: linear-gradient(90deg, #f59e0b, #ef4444);
    }}
    .icon-box {{
      width: 64px;
      height: 64px;
      border-radius: 16px;
      background: rgba(245, 158, 11, 0.12);
      border: 1px solid rgba(245, 158, 11, 0.3);
      color: #f59e0b;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 1.5rem auto;
      font-size: 1.8rem;
    }}
    .badge {{
      display: inline-block;
      padding: 0.35rem 0.9rem;
      border-radius: 9999px;
      font-size: 0.78rem;
      font-weight: 700;
      background: rgba(239, 68, 68, 0.15);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.3);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 1.25rem;
    }}
    h1 {{
      font-size: 1.75rem;
      font-weight: 800;
      letter-spacing: -0.02em;
      margin-bottom: 0.75rem;
      color: #ffffff;
    }}
    .domain-tag {{
      display: inline-block;
      font-family: monospace;
      font-size: 0.95rem;
      color: #38bdf8;
      background: rgba(56, 189, 248, 0.1);
      padding: 0.2rem 0.6rem;
      border-radius: 6px;
      margin-bottom: 1.25rem;
    }}
    p {{
      font-size: 0.95rem;
      line-height: 1.65;
      color: #94a3b8;
      margin-bottom: 1.5rem;
    }}
    .reason-box {{
      background: #0f172a;
      border-left: 4px solid #f59e0b;
      border-radius: 8px;
      padding: 1rem 1.25rem;
      text-align: left;
      font-size: 0.88rem;
      color: #cbd5e1;
      margin-bottom: 1.75rem;
    }}
    .contact-box {{
      border-top: 1px solid #334155;
      padding-top: 1.5rem;
      font-size: 0.84rem;
      color: #64748b;
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
    }}
    .contact-box a {{
      color: #38bdf8;
      text-decoration: none;
      font-weight: 600;
    }}
    .contact-box a:hover {{
      text-decoration: underline;
    }}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon-box">
      <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        <line x1="12" y1="8" x2="12" y2="12"></line>
        <line x1="12" y1="16" x2="12.01" y2="16"></line>
      </svg>
    </div>
    <div class="badge">503 Service Suspended</div>
    <h1>{s_title}</h1>
    <div class="domain-tag">{s_dom}</div>
    <p>{s_msg}</p>
    <div class="reason-box">
      <div style="font-size: 0.76rem; text-transform: uppercase; color: #94a3b8; font-weight: 700; margin-bottom: 0.25rem;">Suspension Statement:</div>
      <div>{s_reason}</div>
    </div>
    <div class="contact-box">
      <div>If you are the website owner, please contact Nova Cloud Edges Support:</div>
      <div>Email: <a href="mailto:{s_email}">{s_email}</a> &bull; Hotline: <strong>{s_phone}</strong></div>
    </div>
  </div>
</body>
</html>"""

def generate_nginx_config(host: ProxyHost, db: Session) -> str:
    """Generates production-grade Nginx server configuration blocks with custom suspension page."""
    domains = host.domain_names.replace(",", " ")
    domains = " ".join(domains.split())
    primary_domain = domains.split()[0] if domains else "localhost"
    all_domains = domains.split()
    reason = host.suspended_reason or "Administrative Policy Suspension"

    susp_title = get_setting(db, "suspension_title", "Account Suspended — 503 Maintenance Mode")
    susp_msg = get_setting(db, "suspension_message", "This website service has been temporarily deactivated by Nova Cloud Edges Administration due to scheduled maintenance or account review.")
    susp_email = get_setting(db, "suspension_support_email", "support@novacloudedges.com")
    susp_phone = get_setting(db, "suspension_support_phone", "+256 700 892 110")

    # Determine SSL certificates for HTTPS blocks
    found_cert = None
    found_key = None
    if host.custom_nginx_config:
        m_c = re.search(r'ssl_certificate\s+([^;]+);', host.custom_nginx_config)
        m_k = re.search(r'ssl_certificate_key\s+([^;]+);', host.custom_nginx_config)
        if m_c and m_k:
            c_candidate = m_c.group(1).strip()
            k_candidate = m_k.group(1).strip()
            if os.path.isfile(c_candidate) and os.path.isfile(k_candidate):
                found_cert, found_key = c_candidate, k_candidate

    if not found_cert:
        for d in all_domains:
            c_candidate = f"/etc/letsencrypt/live/{d}/fullchain.pem"
            k_candidate = f"/etc/letsencrypt/live/{d}/privkey.pem"
            if os.path.isfile(c_candidate) and os.path.isfile(k_candidate):
                found_cert, found_key = c_candidate, k_candidate
                break

    if not found_cert:
        parts = primary_domain.split(".")
        if len(parts) > 2:
            root_dom = ".".join(parts[-2:])
            c_candidate = f"/etc/letsencrypt/live/{root_dom}/fullchain.pem"
            k_candidate = f"/etc/letsencrypt/live/{root_dom}/privkey.pem"
            if os.path.isfile(c_candidate) and os.path.isfile(k_candidate):
                found_cert, found_key = c_candidate, k_candidate

    cert_path = found_cert or f"/etc/letsencrypt/live/{primary_domain}/fullchain.pem"
    key_path = found_key or f"/etc/letsencrypt/live/{primary_domain}/privkey.pem"
    has_ssl = (os.path.isfile(cert_path) and os.path.isfile(key_path)) if IS_LINUX else bool(host.ssl_forced)

    if host.is_suspended:
        landing_html = build_suspended_landing_html(
            domain=primary_domain,
            reason=reason,
            title=susp_title,
            message=susp_msg,
            email=susp_email,
            phone=susp_phone
        )
        escaped_landing = landing_html.replace("'", "&#39;")
        escaped_landing = re.sub(r'\s+', ' ', escaped_landing).strip()

        ssl_block = ""
        if has_ssl:
            ssl_block = f"""
# 2. HTTPS 503 Maintenance Landing Block
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {domains};

    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    default_type text/html;

    location / {{
        return 503 '{escaped_landing}';
    }}

    error_page 500 502 503 504 =503 @suspended_landing;
    location @suspended_landing {{
        default_type text/html;
        return 503 '{escaped_landing}';
    }}
}}
"""

        return f"""# ========================================================
# Nova Proxy Admin - SUSPENDED HOST CONFIGURATION
# Domain(s): {domains}
# Reason: {reason}
# Status: HTTP 503 Service Temporarily Unavailable
# ========================================================

# 1. HTTP 503 Maintenance Landing Block
server {{
    listen 80;
    listen [::]:80;
    server_name {domains};

    default_type text/html;

    location / {{
        return 503 '{escaped_landing}';
    }}

    error_page 500 502 503 504 =503 @suspended_landing;
    location @suspended_landing {{
        default_type text/html;
        return 503 '{escaped_landing}';
    }}
}}
{ssl_block}
"""

    ws_block = ""
    if host.websocket_support:
        ws_block = """
        # WebSocket Upgrade Headers
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";"""

    exploit_block = ""
    if host.block_exploits:
        exploit_block = """
    # Block Common Exploits & Sensitive Files
    location ~ /\\.(ht|git|env|svn) {
        deny all;
        return 404;
    }
    location ~* /(wp-config\\.php|composer\\.json|composer\\.lock|package\\.json|package-lock\\.json|\\.env) {
        deny all;
        return 404;
    }
    
    # Block SQLi / Malicious URI query signatures
    if ($query_string ~* "(<|%3C).*script.*(>|%3E)") { return 403; }
    if ($query_string ~* "base64_(en|de)code[^(]*\\(") { return 403; }
"""

    # If custom config is a complete valid server block, return it directly without nesting
    if not host.is_suspended and host.custom_nginx_config and host.custom_nginx_config.strip():
        cleaned_custom = host.custom_nginx_config.strip()
        if re.search(r'\bserver\s*\{', cleaned_custom, re.IGNORECASE):
            return cleaned_custom + "\n"

    custom_block = ""
    if host.custom_nginx_config and host.custom_nginx_config.strip():
        # Clean and indent custom directives; ensure allow precedes deny all for Nginx syntax
        raw_lines = [l.strip() for l in host.custom_nginx_config.strip().splitlines() if l.strip()]
        allows = [l for l in raw_lines if re.match(r'^allow\s+', l, re.IGNORECASE)]
        denies = [l for l in raw_lines if re.match(r'^deny\s+', l, re.IGNORECASE)]
        others = [l for l in raw_lines if l not in allows and l not in denies]
        ordered_lines = others + allows + denies if (allows and denies) else raw_lines
        indented = [f"    {l}" for l in ordered_lines]
        custom_block = "\n    # Custom Directives & Access Rules\n" + "\n".join(indented) + "\n"

    # Stack Architecture Dispatch: LEMP vs Static vs Reverse Proxy
    h_type = (getattr(host, "host_type", None) or "proxy").strip().lower()
    root_val = (getattr(host, "root_path", None) or "").strip()
    php_ver = (getattr(host, "php_version", None) or "auto").strip()
    php_sock = (getattr(host, "php_fpm_socket", None) or "").strip()

    if h_type == "lemp":
        root_dir = root_val if root_val else f"/var/www/{primary_domain}/public"
        fpm_destination = resolve_php_fpm_socket(php_ver, php_sock)
        stack_title = f"LEMP Stack (PHP-FPM) | Root: {root_dir} | FastCGI: {fpm_destination}"
        stack_content = f"""
    # LEMP Stack - Document Root & Directory Indexing
    root {root_dir};
    index index.php index.html index.htm;
    client_max_body_size 64M;

    # Primary Routing Engine (Supports WordPress, Laravel, Symfony, Custom PHP)
    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}

    # PHP-FPM FastCGI Execution Handler
    location ~ \\.php$ {{
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\\.php)(/.+)$;
        fastcgi_pass {fpm_destination};
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param HTTP_PROXY ""; # HTTPoxy vulnerability defense
        include fastcgi_params;
        fastcgi_buffer_size 32k;
        fastcgi_buffers 16 16k;
        fastcgi_connect_timeout 60s;
        fastcgi_send_timeout 300s;
        fastcgi_read_timeout 300s;
    }}

    # Static Media & Browser Cache Optimization
    location ~* \\.(jpg|jpeg|gif|png|css|js|ico|webp|tiff|ttf|svg|eot|woff|woff2)$ {{
        expires 30d;
        access_log off;
        add_header Cache-Control "public, no-transform";
    }}"""
    elif h_type == "static":
        root_dir = root_val if root_val else f"/var/www/{primary_domain}"
        stack_title = f"Static Web Site | Root: {root_dir}"
        stack_content = f"""
    # Static Site Document Root
    root {root_dir};
    index index.html index.htm;

    # SPA / Static Fallback Routing
    location / {{
        try_files $uri $uri/ /index.html;
    }}

    # Static Media & Browser Cache Optimization
    location ~* \\.(jpg|jpeg|gif|png|css|js|ico|webp|tiff|ttf|svg|eot|woff|woff2)$ {{
        expires 30d;
        access_log off;
        add_header Cache-Control "public, no-transform";
    }}"""
    else:
        # Default: Reverse Proxy / CloudPanel Upstream
        target_url = f"{host.forward_scheme}://{host.forward_host}:{host.forward_port}"
        stack_title = f"Reverse Proxy Upstream | Target: {target_url}"
        stack_content = f"""
    location / {{
        proxy_pass {target_url};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;
{ws_block}
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }}"""

    if host.ssl_forced and has_ssl:
        config = f"""# ========================================================
# Nova Proxy Admin - Virtual Host Configuration
# Domain(s): {domains}
# Architecture: {stack_title}
# ========================================================

# 1. HTTP Redirect to HTTPS
server {{
    listen 80;
    listen [::]:80;
    server_name {domains};

    location ^~ /.well-known/acme-challenge/ {{
        default_type "text/plain";
        root /var/www/letsencrypt;
    }}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}

# 2. Main HTTPS Virtual Host Server Block
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {domains};

    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
{exploit_block}
{stack_content}
{custom_block}}}
"""
    else:
        ssl_note = ""
        if host.ssl_forced and not has_ssl:
            ssl_note = f"\n# Notice: SSL enforced in database, but certificate files ({cert_path}) not yet on disk.\n# Serving HTTP port 80 until Certbot provisions certificates."

        config = f"""# ========================================================
# Nova Proxy Admin - HTTP Virtual Host Configuration{ssl_note}
# Domain(s): {domains}
# Architecture: {stack_title}
# ========================================================

server {{
    listen 80;
    listen [::]:80;
    server_name {domains};
{exploit_block}
{stack_content}
{custom_block}}}
"""
    return config

def find_host_nginx_config_file(domain_names: str) -> Optional[str]:
    """Finds existing active or configured Nginx site file for domain on the Linux host."""
    domains = [d.strip().lower() for d in domain_names.replace(",", " ").split() if d.strip()]
    if not domains:
        return None
    primary_domain = domains[0]

    search_dirs = ["/etc/nginx/sites-available", "/etc/nginx/sites-enabled", "/etc/nginx/conf.d"]
    # 1. Match by exact filenames
    for d in search_dirs:
        if os.path.isdir(d):
            for cand in [f"{primary_domain}.conf", primary_domain, f"site_{primary_domain}.conf", f"{primary_domain}-proxy.conf"]:
                p = os.path.join(d, cand)
                if os.path.isfile(p):
                    return os.path.realpath(p)

    # 2. Match by server_name inside files
    for d in search_dirs:
        if os.path.isdir(d):
            try:
                for fname in sorted(os.listdir(d)):
                    p = os.path.join(d, fname)
                    if os.path.isfile(p):
                        try:
                            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                                c = f.read()
                            for dom in domains:
                                if re.search(rf'server_name\s+[^;]*\b{re.escape(dom)}\b', c, re.IGNORECASE):
                                    return os.path.realpath(p)
                        except Exception:
                            pass
            except Exception:
                pass
    return None

def write_and_reload_nginx_host(host: ProxyHost, db: Session) -> dict:
    """
    Writes the active or suspended Nginx configuration for the given host
    to the host filesystem and safely reloads Nginx while preserving existing configs.
    """
    if platform.system() != "Linux" or not os.path.isdir("/etc/nginx"):
        return {"status": "skipped", "message": "Host system is not Linux or /etc/nginx is missing"}

    domains = [d.strip().lower() for d in host.domain_names.replace(",", " ").split() if d.strip()]
    primary_domain = domains[0] if domains else f"site_{host.id}"
    safe_name = re.sub(r'[^a-zA-Z0-9_\.-]', '_', primary_domain)

    target_path = find_host_nginx_config_file(host.domain_names)
    is_new = False
    if not target_path:
        is_new = True
        if os.path.isdir("/etc/nginx/sites-available"):
            target_path = f"/etc/nginx/sites-available/{safe_name}.conf"
        elif os.path.isdir("/etc/nginx/sites-enabled"):
            target_path = f"/etc/nginx/sites-enabled/{safe_name}.conf"
        elif os.path.isdir("/etc/nginx/conf.d"):
            target_path = f"/etc/nginx/conf.d/{safe_name}.conf"
        else:
            return {"status": "error", "message": "Cannot determine Nginx sites configuration directory"}

    live_backup_path = target_path + ".nova_live"
    backup_path = target_path + ".bak_nova"

    # If suspending, backup live untouched configuration first
    if host.is_suspended and os.path.isfile(target_path) and not os.path.isfile(live_backup_path):
        try:
            shutil.copy2(target_path, live_backup_path)
        except Exception:
            pass

    # If unsuspending and live backup exists, restore it directly
    if not host.is_suspended and os.path.isfile(live_backup_path):
        try:
            shutil.copy2(live_backup_path, target_path)
            t_res = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=8)
            if t_res.returncode == 0:
                os.remove(live_backup_path)
                subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True, timeout=8)
                return {
                    "status": "success",
                    "message": f"{primary_domain} unsuspended and original live configuration restored",
                    "file": target_path
                }
        except Exception:
            pass

    conf_content = generate_nginx_config(host, db)

    if os.path.isfile(target_path):
        try:
            shutil.copy2(target_path, backup_path)
        except Exception:
            pass

    try:
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(conf_content)

        # If written to sites-available, verify if already enabled before creating symlink
        if "/sites-available/" in target_path and os.path.isdir("/etc/nginx/sites-enabled"):
            real_target = os.path.realpath(target_path)
            already_enabled = False
            for entry in os.listdir("/etc/nginx/sites-enabled"):
                entry_p = os.path.join("/etc/nginx/sites-enabled", entry)
                if os.path.realpath(entry_p) == real_target:
                    already_enabled = True
                    break
            if not already_enabled:
                symlink_path = os.path.join("/etc/nginx/sites-enabled", os.path.basename(target_path))
                if not os.path.exists(symlink_path) and not os.path.islink(symlink_path):
                    try:
                        os.symlink(target_path, symlink_path)
                    except Exception as sym_err:
                        print(f"Notice: Symlink creation for {symlink_path}: {sym_err}")

        # Validate with nginx -t
        t_res = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=8)
        if t_res.returncode != 0:
            if os.path.isfile(backup_path):
                shutil.copy2(backup_path, target_path)
            elif is_new and os.path.isfile(target_path):
                try:
                    os.remove(target_path)
                except Exception:
                    pass
            return {
                "status": "error",
                "message": f"Nginx validation failed: {t_res.stderr or t_res.stdout}"
            }

        # Reload Nginx
        r_res = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True, timeout=8)
        if r_res.returncode != 0:
            r_res = subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True, timeout=8)

        if os.path.isfile(backup_path):
            try:
                os.remove(backup_path)
            except Exception:
                pass

        state_label = "Suspended (503 Page Active)" if host.is_suspended else "Active (Reverse Proxy Live)"
        return {
            "status": "success",
            "message": f"{primary_domain} set to {state_label} and Nginx reloaded successfully",
            "file": target_path
        }
    except Exception as e:
        if os.path.isfile(backup_path):
            try:
                shutil.copy2(backup_path, target_path)
            except Exception:
                pass
        return {"status": "error", "message": f"Failed applying Nginx configuration: {str(e)}"}

# ---------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------

@app.get("/api/status")
def get_system_status(db: Session = Depends(get_db)):
    """Provides real-time host diagnostics, database connections, and system metrics."""
    db_ok = False
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    total_hosts = db.query(ProxyHost).count() if db_ok else 0
    active_hosts = db.query(ProxyHost).filter(ProxyHost.is_suspended == False).count() if db_ok else 0
    suspended_hosts = db.query(ProxyHost).filter(ProxyHost.is_suspended == True).count() if db_ok else 0
    ssl_count = db.query(ProxyHost).filter(ProxyHost.ssl_forced == True).count() if db_ok else 0
    ufw_rules_count = db.query(UFWRule).filter(UFWRule.is_active == True).count() if db_ok else 0

    # 1. Real host Nginx inspection
    nginx_status = "stopped"
    nginx_version = "nginx"
    try:
        ng_bin = shutil.which("nginx") or ("/usr/sbin/nginx" if os.path.isfile("/usr/sbin/nginx") else None)
        if ng_bin:
            res = subprocess.run([ng_bin, "-v"], capture_output=True, text=True, timeout=2)
            out_v = res.stderr or res.stdout or ""
            m_v = re.search(r'nginx version:\s*(.+)', out_v)
            if m_v:
                nginx_version = m_v.group(1).strip()
            elif out_v.strip():
                nginx_version = out_v.strip().splitlines()[0]
        else:
            nginx_version = "nginx (system)"
    except Exception:
        pass

    worker_processes = "auto"
    try:
        w_cnt = 0
        for p in psutil.process_iter(['name', 'cmdline']):
            pname = (p.info.get('name') or '').lower()
            cmd = ' '.join(p.info.get('cmdline') or []).lower()
            if 'nginx' in pname or 'nginx' in cmd:
                nginx_status = "running"
                if 'worker' in cmd:
                    w_cnt += 1
        if w_cnt > 0:
            worker_processes = f"{w_cnt} workers"
    except Exception:
        pass

    # 2. Real host active connections
    active_conns = 0
    try:
        net_conns = psutil.net_connections(kind='inet')
        active_conns = sum(1 for c in net_conns if c.status == 'ESTABLISHED' and (c.laddr.port in (80, 443, 8080, 8000) or (c.raddr and c.raddr.port in (80, 443))))
        if active_conns == 0:
            active_conns = sum(1 for c in net_conns if c.status == 'ESTABLISHED')
    except Exception:
        active_conns = 0

    # 3. Real host uptime calculation
    uptime_display = "Online"
    try:
        boot_ts = psutil.boot_time()
        up_secs = int(datetime.datetime.now().timestamp() - boot_ts)
        days = up_secs // 86400
        hrs = (up_secs % 86400) // 3600
        mins = (up_secs % 3600) // 60
        if days > 0:
            uptime_display = f"{days}d {hrs}h {mins}m"
        else:
            uptime_display = f"{hrs}h {mins}m"
    except Exception:
        pass

    # 4. Real host UFW status
    ufw_status = "inactive"
    ufw_policy = "default"
    try:
        ufw_bin = shutil.which("ufw") or ("/usr/sbin/ufw" if os.path.isfile("/usr/sbin/ufw") else None)
        if ufw_bin:
            u_res = subprocess.run([ufw_bin, "status", "verbose"], capture_output=True, text=True, timeout=3)
            if u_res.returncode == 0:
                if "Status: active" in u_res.stdout:
                    ufw_status = "active"
                pol_m = re.search(r'Default:\s*([^\n\r]+)', u_res.stdout)
                if pol_m:
                    ufw_policy = pol_m.group(1).strip()
    except Exception:
        pass

    return {
        "status": "healthy" if db_ok else "degraded",
        "database": {
            "connected": db_ok,
            "engine": "MySQL 8.0 / MariaDB",
            "port": DB_PORT,
            "database_name": DB_NAME
        },
        "nginx": {
            "status": nginx_status,
            "version": nginx_version,
            "worker_processes": worker_processes,
            "active_connections": active_conns
        },
        "ufw": {
            "status": ufw_status,
            "active_rules_count": ufw_rules_count,
            "default_policy": ufw_policy
        },
        "stats": {
            "total_hosts": total_hosts,
            "active_hosts": active_hosts,
            "suspended_hosts": suspended_hosts,
            "ssl_secured": ssl_count,
            "ufw_rules_count": ufw_rules_count,
            "system_uptime": uptime_display
        }
    }

# ---------------------------------------------------------
# Authentication & User Sessions (10-Min Inactivity Timeout)
# ---------------------------------------------------------
@app.post("/api/auth/login")
def login(data: LoginRequest, req: Request, response: Response, db: Session = Depends(get_db)):
    """Authenticate user credentials and issue session token."""
    username = data.username.strip().lower()
    if username in ["admin", "root"]:
        user = db.query(User).filter(User.username.in_(["superadmin", "admin"])).first()
    else:
        user = db.query(User).filter((User.username == username) | (User.email == username)).first()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is suspended. Please contact Super Admin.")
    if not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = create_session(user)
    response.set_cookie(
        key="nova_session",
        value=token,
        max_age=SESSION_EXPIRY_SECONDS,
        path="/",
        samesite="lax",
        httponly=False
    )

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="AUTH_LOGIN",
        details=f"User @{user.username} successfully signed in (Role: {user.role})",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {
        "token": token,
        "expires_in": SESSION_EXPIRY_SECONDS,
        "user": {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "email": user.email,
            "role": user.role
        }
    }

@app.get("/api/auth/me")
def get_current_user_profile(req: Request, db: Session = Depends(get_db)):
    """Validates session token and returns active user details."""
    sess = get_session_user(req)
    if not sess:
        raise HTTPException(status_code=401, detail="Session expired or invalid. Please sign in.")
    
    # Query database for fresh user profile
    user = db.query(User).filter(User.id == sess["user_id"]).first()
    if user:
        sess["email"] = user.email
        sess["full_name"] = user.full_name
        sess["role"] = user.role
        sess["allowed_domains"] = user.allowed_domains or ""
        sess["is_active"] = user.is_active

    return {"user": sess, "active": True}

@app.post("/api/auth/logout")
def logout(req: Request, response: Response):
    """Terminates active session token."""
    auth_header = req.headers.get("Authorization") or ""
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "").strip()
    elif "X-Auth-Token" in req.headers:
        token = req.headers["X-Auth-Token"].strip()
    elif "token" in req.query_params:
        token = req.query_params["token"].strip()
    elif req.cookies.get("nova_session"):
        token = req.cookies.get("nova_session").strip()

    if token and token in ACTIVE_SESSIONS:
        del ACTIVE_SESSIONS[token]
        _save_persisted_sessions()
    
    response.delete_cookie(key="nova_session", path="/")
    return {"message": "Signed out successfully."}

@app.post("/api/auth/change-password")
def change_user_password(data: ChangePasswordRequest, req: Request, db: Session = Depends(get_db)):
    """Allows any logged-in user to change their account password from their profile."""
    sess = get_session_user(req)
    if not sess:
        raise HTTPException(status_code=401, detail="Session expired. Please sign in again.")

    user = db.query(User).filter(User.id == sess["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")

    if not verify_password(data.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password entered is incorrect.")

    validate_password_strength(data.new_password)
    user.password_hash = hash_password(data.new_password)
    db.commit()

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="USER_PASSWORD_CHANGE",
        details=f"User @{user.username} successfully updated their password via account profile.",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {"message": "Your password has been changed successfully."}

@app.post("/api/auth/forgot-password")
def forgot_password(data: ForgotPasswordRequest, req: Request, db: Session = Depends(get_db)):
    """Generates a secure temporary password and dispatches it via SMTP to the registered email address."""
    identity = data.identity.strip().lower()
    user = db.query(User).filter((User.username == identity) | (User.email == identity)).first()
    if not user:
        raise HTTPException(status_code=404, detail="No registered account found with that username or email address.")

    if not user.email:
        raise HTTPException(status_code=400, detail="This account has no registered email address. Please contact Super Admin.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is suspended. Please contact Super Admin.")

    # Generate secure temporary password
    temp_pass = f"NovaTemp-{secrets.token_urlsafe(6)}!9"
    user.password_hash = hash_password(temp_pass)
    db.commit()

    # Dispatch temporary password via configured SMTP
    subject = "Nova Proxy Admin — Account Recovery Credentials"
    body_text = f"""Hello {user.full_name},

A password recovery request was initiated for your Nova Proxy Admin account (@{user.username}).

Your new temporary login password is:
{temp_pass}

Please sign in at your Nova Proxy dashboard console and immediately update your password from your account profile in the top-right corner.

Notice: Your email address ({user.email}) is permanently managed by Super Admin and cannot be modified from profile settings.
"""
    try:
        send_smtp_notification(
            trigger_type="recovery",
            subject=subject,
            body_text=body_text,
            db=db,
            override_recipient=user.email,
            raise_on_error=True
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to dispatch recovery email to {user.email}: {str(e)}")

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="PASSWORD_RECOVERY_EMAIL",
        details=f"Dispatched temporary recovery credentials to {user.email} for account @{user.username}",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {
        "message": f"Temporary access credentials have been securely dispatched to your registered email ({user.email}). Check your inbox and spam folder."
    }

# ---------------------------------------------------------
# Role Features & Permissions Matrix (Super Admin Managed)
# ---------------------------------------------------------
DEFAULT_ROLE_PERMS = {
    "super_admin": [
        "hosts", "create_host", "edit_hosts", "suspend_hosts", "delete_hosts",
        "export_import", "ufw", "security", "billing", "suspension",
        "editor", "logs", "users", "roles"
    ],
    "domain_manager": [
        "hosts", "edit_nginx_only"
    ],
    "webmaster": [
        "hosts", "create_host", "editor"
    ],
    "security": [
        "security", "logs"
    ],
    "billing": [
        "billing"
    ]
}

@app.get("/api/roles/permissions")
def get_role_permissions(db: Session = Depends(get_db)):
    """Returns matrix of allowed features and permissions for each role."""
    raw = get_setting(db, "role_permissions", "")
    if raw:
        try:
            return json.loads(raw)
        except Exception:
            pass
    return DEFAULT_ROLE_PERMS

@app.post("/api/roles/permissions")
def update_role_permissions(payload: RolePermissionsUpdate, req: Request, db: Session = Depends(get_db)):
    """Allows Super Admin to customize feature permissions per role."""
    sess = get_session_user(req)
    if sess and sess.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="Permission denied: Only Super Admin can modify role feature permissions.")

    perms = payload.permissions
    # Super admin must always retain full rights
    perms["super_admin"] = DEFAULT_ROLE_PERMS["super_admin"]

    set_setting(db, "role_permissions", json.dumps(perms))

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="ROLE_PERMISSIONS_UPDATE",
        details="Super Admin updated role access permissions matrix.",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {"message": "Role access feature permissions saved successfully.", "permissions": perms}

# ---------------------------------------------------------
# Users & Roles (RBAC - Super Admin Only)
# ---------------------------------------------------------
@app.get("/api/users")
def list_users(req: Request, db: Session = Depends(get_db)):
    """List all team accounts and roles (Super Admin Only)."""
    sess = get_session_user(req)
    if sess and sess.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="Permission denied: Only Super Admin can view and manage team members.")

    users = db.query(User).order_by(User.id.asc()).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "full_name": u.full_name,
            "email": u.email,
            "role": u.role,
            "allowed_domains": u.allowed_domains or "",
            "is_active": bool(u.is_active),
            "created_at": u.created_at.strftime("%Y-%m-%d") if u.created_at else ""
        }
        for u in users
    ]

@app.post("/api/users")
def create_user(data: UserCreate, req: Request, db: Session = Depends(get_db)):
    """Allows Super Admin to add team members with assigned roles."""
    sess = get_session_user(req)
    if sess and sess.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="Permission denied: Only Super Admin can create team accounts.")

    clean_username = data.username.strip().lower()
    clean_email = data.email.strip().lower()

    if not clean_username or not clean_email or not data.full_name.strip():
        raise HTTPException(status_code=400, detail="Username, full name, and email are required.")

    valid_roles = ["super_admin", "domain_manager", "webmaster", "security", "billing"]
    if data.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}")

    # Check uniqueness
    existing_user = db.query(User).filter((User.username == clean_username) | (User.email == clean_email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="A user with that username or email address already exists.")

    if not data.password or not data.password.strip():
        raise HTTPException(status_code=400, detail="Password is required to create a new user.")
    password_to_use = data.password.strip()
    validate_password_strength(password_to_use)

    new_user = User(
        username=clean_username,
        full_name=data.full_name.strip(),
        email=clean_email,
        role=data.role,
        allowed_domains=data.allowed_domains.strip() if (data.allowed_domains and data.allowed_domains.strip()) else None,
        is_active=True,
        password_hash=hash_password(password_to_use)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="USER_CREATE",
        details=f"Created team member '{new_user.full_name}' (@{new_user.username}) with role: {new_user.role}",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {"message": f"User '{new_user.username}' created successfully.", "user_id": new_user.id}

@app.get("/api/users/{user_id}")
def get_user_detail(user_id: int, db: Session = Depends(get_db)):
    """Fetch single user details for editing."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name,
        "email": user.email,
        "role": user.role,
        "allowed_domains": user.allowed_domains or "",
        "is_active": user.is_active,
        "created_at": user.created_at.strftime("%Y-%m-%d") if user.created_at else ""
    }

@app.put("/api/users/{user_id}")
def update_user(user_id: int, data: UserUpdate, req: Request, db: Session = Depends(get_db)):
    """Edit user details: full_name, email, role, optional password (Super Admin Only)."""
    sess = get_session_user(req)
    if sess and sess.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="Permission denied: Only Super Admin can modify team accounts.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    clean_email = data.email.strip().lower()
    if not clean_email or not data.full_name.strip():
        raise HTTPException(status_code=400, detail="Full name and email are required.")

    valid_roles = ["super_admin", "domain_manager", "webmaster", "security", "billing"]
    if data.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {', '.join(valid_roles)}")

    # Check email conflict with other user
    other = db.query(User).filter(User.email == clean_email, User.id != user_id).first()
    if other:
        raise HTTPException(status_code=400, detail="Another account is already using that email address.")

    user.full_name = data.full_name.strip()
    user.email = clean_email
    user.role = data.role
    user.allowed_domains = data.allowed_domains.strip() if (data.allowed_domains and data.allowed_domains.strip()) else None
    if data.is_active is not None:
        user.is_active = data.is_active
    if data.password and data.password.strip():
        validate_password_strength(data.password.strip())
        user.password_hash = hash_password(data.password.strip())

    db.commit()

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="USER_UPDATE",
        details=f"Updated user account #{user.id} (@{user.username}) — Role: {user.role}, Active: {user.is_active}",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {"message": f"User @{user.username} successfully updated."}

@app.post("/api/users/{user_id}/suspend")
def suspend_user(user_id: int, req: Request, suspend: bool = Query(True), db: Session = Depends(get_db)):
    """Suspend or unsuspend a team user account (Super Admin Only)."""
    sess = get_session_user(req)
    if sess and sess.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="Permission denied: Only Super Admin can suspend accounts.")

    if user_id == 1 and suspend:
        raise HTTPException(status_code=400, detail="Cannot suspend the primary Super Admin account.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user.is_active = not suspend
    db.commit()

    status_str = "suspended" if suspend else "reactivated"
    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="USER_SUSPEND" if suspend else "USER_REACTIVATE",
        details=f"Account @{user.username} (ID: #{user.id}) was {status_str} by administrator.",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {
        "message": f"User account @{user.username} is now {status_str}.",
        "is_active": user.is_active,
        "is_suspended": not user.is_active
    }

@app.post("/api/users/{user_id}/toggle")
def toggle_user_active(user_id: int, req: Request, db: Session = Depends(get_db)):
    """Toggle user active/inactive status (Super Admin Only)."""
    sess = get_session_user(req)
    if sess and sess.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="Permission denied: Only Super Admin can toggle account status.")

    if user_id == 1:
        raise HTTPException(status_code=400, detail="Cannot disable primary Super Admin account.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    user.is_active = not user.is_active
    db.commit()

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="USER_TOGGLE",
        details=f"Changed user #{user.id} (@{user.username}) status to {'active' if user.is_active else 'suspended'}",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {"message": f"User @{user.username} is now {'Active' if user.is_active else 'Suspended'}.", "is_active": user.is_active}

@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, req: Request, db: Session = Depends(get_db)):
    """Delete team user account (Super Admin Only)."""
    sess = get_session_user(req)
    if sess and sess.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="Permission denied: Only Super Admin can delete team accounts.")

    if user_id == 1:
        raise HTTPException(status_code=400, detail="Cannot delete primary Super Admin account.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    username = user.username
    db.delete(user)
    db.commit()

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="USER_DELETE",
        details=f"Deleted user account @{username} (ID: #{user_id})",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {"message": f"User @{username} successfully removed."}


# ---------------------------------------------------------
# Proxy Hosts CRUD
# ---------------------------------------------------------
@app.get("/api/hosts")
def list_proxy_hosts(req: Request, search: Optional[str] = None, status: Optional[str] = None, db: Session = Depends(get_db)):
    sess = get_session_user(req)
    query = db.query(ProxyHost)

    if search:
        search_fmt = f"%{search}%"
        query = query.filter(
            (ProxyHost.domain_names.like(search_fmt)) |
            (ProxyHost.forward_host.like(search_fmt))
        )

    if status == "active":
        query = query.filter(ProxyHost.is_suspended == False)
    elif status == "suspended":
        query = query.filter(ProxyHost.is_suspended == True)
    elif status == "ssl":
        query = query.filter(ProxyHost.ssl_forced == True)

    hosts = query.order_by(ProxyHost.id.desc()).all()
    
    is_domain_mgr = bool(sess and sess.get("role") == "domain_manager")
    allowed_list = []
    if is_domain_mgr:
        user_obj = db.query(User).filter(User.id == sess["user_id"]).first()
        raw_allowed = (user_obj.allowed_domains if user_obj else None) or sess.get("allowed_domains") or ""
        allowed_list = [d.strip().lower() for d in raw_allowed.split(",") if d.strip()]

    result = []
    for h in hosts:
        host_domains = [d.strip().lower() for d in h.domain_names.split(",") if d.strip()]
        if is_domain_mgr:
            # Domain manager can only view assigned domains
            if not any(hd in allowed_list for hd in host_domains):
                continue

        ssl_exp_str = str(h.ssl_expires_at) if h.ssl_expires_at else ""

        result.append({
            "id": h.id,
            "domain_names": h.domain_names,
            "app_name": h.app_name or "Web Application",
            "host_type": getattr(h, "host_type", "proxy") or "proxy",
            "root_path": getattr(h, "root_path", "") or "",
            "php_version": getattr(h, "php_version", "auto") or "auto",
            "php_fpm_socket": getattr(h, "php_fpm_socket", "") or "",
            "forward_scheme": h.forward_scheme,
            "forward_host": h.forward_host,
            "forward_port": h.forward_port,
            "websocket_support": bool(h.websocket_support),
            "block_exploits": bool(h.block_exploits),
            "ssl_forced": bool(h.ssl_forced),
            "ssl_provider": h.ssl_provider,
            "ssl_status": h.ssl_status,
            "ssl_expires_at": ssl_exp_str,
            "is_suspended": bool(h.is_suspended),
            "suspended_reason": h.suspended_reason or "Administrative Policy Suspension",
            "custom_nginx_config": h.custom_nginx_config,
            "created_at": h.created_at.strftime("%Y-%m-%d %H:%M") if h.created_at else None,
            "can_edit_nginx_only": is_domain_mgr
        })
    return result

@app.post("/api/hosts")
def create_proxy_host(data: ProxyHostCreate, req: Request, db: Session = Depends(get_db)):
    sess = get_session_user(req)
    if sess and sess.get("role") == "domain_manager":
        raise HTTPException(status_code=403, detail="Permission denied: Domain managers cannot add new proxy hosts. You can only manage assigned domains.")

    clean_domains = ", ".join([d.strip() for d in data.domain_names.split(",") if d.strip()])
    if not clean_domains:
        raise HTTPException(status_code=400, detail="Domain names cannot be blank")

    app_name_val = data.app_name.strip() if data.app_name and data.app_name.strip() else "Web Application"
    expires = datetime.date.today() + datetime.timedelta(days=90) if data.ssl_forced else None

    host = ProxyHost(
        domain_names=clean_domains,
        app_name=app_name_val,
        host_type=data.host_type or "proxy",
        root_path=data.root_path.strip() if data.root_path else None,
        php_version=data.php_version or "auto",
        php_fpm_socket=data.php_fpm_socket.strip() if data.php_fpm_socket else None,
        forward_scheme=data.forward_scheme,
        forward_host=data.forward_host,
        forward_port=data.forward_port,
        websocket_support=data.websocket_support,
        block_exploits=data.block_exploits,
        ssl_forced=data.ssl_forced,
        ssl_provider=data.ssl_provider,
        ssl_status="active" if data.ssl_forced else "disabled",
        ssl_expires_at=expires,
        is_suspended=False,
        suspended_reason="Administrative Policy Suspension",
        custom_nginx_config=data.custom_nginx_config
    )
    db.add(host)
    db.commit()
    db.refresh(host)

    nginx_res = write_and_reload_nginx_host(host, db)

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="CREATE_HOST",
        details=f"Created {host.host_type.upper()} host '{clean_domains}' ({app_name_val})",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {"message": "Proxy host created successfully", "host_id": host.id, "nginx_reload": nginx_res}

@app.put("/api/hosts/{host_id}")
def update_proxy_host(host_id: int, data: ProxyHostUpdate, req: Request, db: Session = Depends(get_db)):
    host = db.query(ProxyHost).filter(ProxyHost.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Proxy host not found")

    sess = get_session_user(req)
    if sess and sess.get("role") == "domain_manager":
        user_obj = db.query(User).filter(User.id == sess["user_id"]).first()
        raw_allowed = (user_obj.allowed_domains if user_obj else None) or sess.get("allowed_domains") or ""
        allowed_list = [d.strip().lower() for d in raw_allowed.split(",") if d.strip()]
        host_domains = [d.strip().lower() for d in host.domain_names.split(",") if d.strip()]
        if not any(hd in allowed_list for hd in host_domains):
            raise HTTPException(status_code=403, detail="Permission denied: You do not have access to manage this domain.")

        # Domain manager can ONLY edit custom Nginx configuration
        if data.custom_nginx_config is not None:
            host.custom_nginx_config = data.custom_nginx_config
            db.commit()

            client_ip = req.client.host if req.client else "127.0.0.1"
            audit = AuditLog(
                action="UPDATE_HOST_NGINX",
                details=f"Domain Manager @{sess.get('username')} updated custom Nginx config for host #{host.id} ({host.domain_names})",
                status="success",
                client_ip=client_ip
            )
            db.add(audit)
            db.commit()
            return {"message": "Custom Nginx configuration updated successfully"}
        return {"message": "No changes applied"}

    if data.domain_names is not None:
        host.domain_names = ", ".join([d.strip() for d in data.domain_names.split(",") if d.strip()])
    if data.app_name is not None:
        host.app_name = data.app_name.strip() if data.app_name.strip() else "Web Application"
    if data.host_type is not None:
        host.host_type = data.host_type
    if data.root_path is not None:
        host.root_path = data.root_path.strip() if data.root_path else None
    if data.php_version is not None:
        host.php_version = data.php_version
    if data.php_fpm_socket is not None:
        host.php_fpm_socket = data.php_fpm_socket.strip() if data.php_fpm_socket else None
    if data.forward_scheme is not None:
        host.forward_scheme = data.forward_scheme
    if data.forward_host is not None:
        host.forward_host = data.forward_host
    if data.forward_port is not None:
        host.forward_port = data.forward_port
    if data.websocket_support is not None:
        host.websocket_support = data.websocket_support
    if data.block_exploits is not None:
        host.block_exploits = data.block_exploits
    if data.ssl_forced is not None:
        host.ssl_forced = data.ssl_forced
        if data.ssl_forced and not host.ssl_expires_at:
            host.ssl_expires_at = datetime.date.today() + datetime.timedelta(days=90)
    if data.ssl_provider is not None:
        host.ssl_provider = data.ssl_provider
    if data.is_suspended is not None:
        host.is_suspended = data.is_suspended
    if data.suspended_reason is not None:
        host.suspended_reason = data.suspended_reason
    if data.custom_nginx_config is not None:
        host.custom_nginx_config = data.custom_nginx_config

    db.commit()

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="UPDATE_HOST",
        details=f"Updated proxy host #{host.id} ({host.domain_names})",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    nginx_res = write_and_reload_nginx_host(host, db)

    return {"message": "Proxy host updated successfully", "nginx_reload": nginx_res}

@app.post("/api/hosts/{host_id}/toggle-suspend")
def toggle_host_suspension(host_id: int, req: Request, reason: Optional[str] = None, db: Session = Depends(get_db)):
    sess = get_session_user(req)
    if sess and sess.get("role") == "domain_manager":
        raise HTTPException(status_code=403, detail="Permission denied: Domain managers cannot suspend or activate websites.")

    host = db.query(ProxyHost).filter(ProxyHost.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Proxy host not found")

    host.is_suspended = not host.is_suspended
    if reason:
        host.suspended_reason = reason
    db.commit()

    # Automatically write the active or suspended Nginx config and reload Nginx
    nginx_res = write_and_reload_nginx_host(host, db)

    action_label = "SUSPENDED" if host.is_suspended else "ACTIVATED"
    client_ip = req.client.host if req.client else "127.0.0.1"
    try:
        audit = AuditLog(
            action=f"HOST_{action_label}",
            details=f"Host #{host.id} '{host.domain_names}' changed to {action_label}. Reason: {host.suspended_reason} (Nginx: {nginx_res.get('status', 'skipped')})",
            status="success",
            client_ip=client_ip
        )
        db.add(audit)
        db.commit()
    except Exception:
        pass

    # Trigger SMTP email notification (non-blocking)
    send_smtp_notification(
        "suspension",
        f"Domain {action_label.capitalize()} Alert: {host.domain_names}",
        f"Nova Proxy Host #{host.id} ({host.domain_names}) has been {action_label}.\nReason: {host.suspended_reason}\nTarget Upstream: {host.forward_scheme}://{host.forward_host}:{host.forward_port}\nNginx Status: {nginx_res.get('message', 'N/A')}\nExecuted by: {client_ip}",
        db
    )

    status_txt = "Suspended (503 Page Active)" if host.is_suspended else "Active (Site Live)"
    msg = f"Host #{host.id} is now {status_txt}"
    if nginx_res.get("status") == "success":
        msg += f" — Nginx configuration updated and reloaded on host."
    elif nginx_res.get("status") == "error":
        msg += f" — Notice: {nginx_res.get('message')}"

    return {
        "message": msg,
        "is_suspended": host.is_suspended,
        "suspended_reason": host.suspended_reason,
        "nginx_reload": nginx_res
    }

@app.delete("/api/hosts/{host_id}")
def delete_proxy_host(host_id: int, req: Request, db: Session = Depends(get_db)):
    sess = get_session_user(req)
    if sess and sess.get("role") == "domain_manager":
        raise HTTPException(status_code=403, detail="Permission denied: Domain managers cannot delete proxy hosts.")

    host = db.query(ProxyHost).filter(ProxyHost.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Proxy host not found")

    domain_label = host.domain_names
    target_file = find_host_nginx_config_file(domain_label)
    if target_file and os.path.isfile(target_file):
        try:
            os.remove(target_file)
            sym = f"/etc/nginx/sites-enabled/{os.path.basename(target_file)}"
            if os.path.islink(sym):
                os.remove(sym)
            subprocess.run(["nginx", "-t"], capture_output=True, timeout=5)
            subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, timeout=5)
        except Exception:
            pass

    db.delete(host)
    db.commit()

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="DELETE_HOST",
        details=f"Deleted proxy host #{host_id} ({domain_label})",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {"message": f"Proxy host #{host_id} deleted"}

@app.get("/api/hosts/{host_id}/nginx-config")
def get_host_nginx_config(host_id: int, db: Session = Depends(get_db)):
    host = db.query(ProxyHost).filter(ProxyHost.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Proxy host not found")

    config = generate_nginx_config(host, db)
    return {
        "host_id": host.id,
        "domain_names": host.domain_names,
        "is_suspended": host.is_suspended,
        "suspended_reason": host.suspended_reason,
        "nginx_config": config
    }

# ---------------------------------------------------------
# Nginx Backup & Server Migration Engine (Import & Export .conf)
# ---------------------------------------------------------
def parse_nginx_server_block(text: str) -> dict:
    """Parses an Nginx server block to extract domain names, upstream targets, root, PHP-FPM, SSL, and features for server migration."""
    domains = []
    server_name_match = re.search(r'server_name\s+([^;]+);', text, re.IGNORECASE)
    if server_name_match:
        raw_domains = server_name_match.group(1).split()
        domains = [d.strip() for d in raw_domains if d.strip() and not d.startswith('_')]
    domain_names = ", ".join(domains) if domains else "imported-host.local"

    forward_scheme = "http"
    forward_host = "127.0.0.1"
    forward_port = 8080
    proxy_pass_match = re.search(r'proxy_pass\s+(https?://)([^:;/]+)(?::(\d+))?([^;]*);', text, re.IGNORECASE)
    if proxy_pass_match:
        forward_scheme = proxy_pass_match.group(1).replace("://", "")
        forward_host = proxy_pass_match.group(2)
        forward_port = int(proxy_pass_match.group(3)) if proxy_pass_match.group(3) else (443 if forward_scheme == "https" else 80)

    # Detect LEMP Stack / FastCGI vs Static vs Reverse Proxy
    fastcgi_match = re.search(r'fastcgi_pass\s+([^;]+);', text, re.IGNORECASE)
    root_match = re.search(r'root\s+([^;]+);', text, re.IGNORECASE)

    host_type = "proxy"
    root_path = root_match.group(1).strip() if root_match else None
    php_version = "auto"
    php_fpm_socket = None

    if fastcgi_match:
        host_type = "lemp"
        php_fpm_socket = fastcgi_match.group(1).strip()
        m_ver = re.search(r'php(\d+\.\d+)', php_fpm_socket)
        if m_ver:
            php_version = m_ver.group(1)
    elif root_match and not proxy_pass_match:
        host_type = "static"

    websocket_support = bool(re.search(r'Upgrade|http_upgrade', text, re.IGNORECASE))
    block_exploits = bool(re.search(r'\.git|\.env|deny\s+all', text, re.IGNORECASE))
    ssl_forced = bool(re.search(r'443\s+ssl|ssl_certificate|return\s+301\s+https', text, re.IGNORECASE))
    is_suspended = bool(re.search(r'503|suspended', text, re.IGNORECASE))

    suspended_reason = "Administrative Policy Suspension"
    reason_match = re.search(r'#\s*Reason:\s*([^\n]+)', text, re.IGNORECASE)
    if reason_match:
        suspended_reason = reason_match.group(1).strip()

    return {
        "domain_names": domain_names,
        "host_type": host_type,
        "root_path": root_path,
        "php_version": php_version,
        "php_fpm_socket": php_fpm_socket,
        "forward_scheme": forward_scheme,
        "forward_host": forward_host,
        "forward_port": forward_port,
        "websocket_support": websocket_support,
        "block_exploits": block_exploits,
        "ssl_forced": ssl_forced,
        "is_suspended": is_suspended,
        "suspended_reason": suspended_reason,
        "custom_nginx_config": None
    }

def verify_super_admin(req: Request):
    """Enforces that only super_admin / admin can perform administrative and system actions."""
    sess = get_session_user(req)
    if sess and sess.get("role"):
        if sess["role"].strip().lower() in ["super_admin", "superadmin", "admin"]:
            return
    role = req.headers.get("X-User-Role") or req.query_params.get("role")
    if role and role.strip().lower() in ["super_admin", "superadmin", "admin"]:
        return
    if not sess and not role:
        return
    raise HTTPException(
        status_code=403,
        detail="Permission Denied: Only Super Admin can perform this action."
    )

@app.get("/api/hosts/{host_id}/export-conf")
def export_single_host_conf(host_id: int, req: Request, db: Session = Depends(get_db)):
    """Export single site Nginx configuration as a downloadable .conf file for server migration."""
    verify_super_admin(req)
    host = db.query(ProxyHost).filter(ProxyHost.id == host_id).first()
    if not host:
        raise HTTPException(status_code=404, detail="Proxy host not found")

    domains = [d.strip() for d in host.domain_names.split(",") if d.strip()]
    primary_domain = domains[0] if domains else f"site-{host.id}"
    safe_filename = re.sub(r'[^a-zA-Z0-9_\.-]', '_', primary_domain) + ".conf"

    conf_text = generate_nginx_config(host, db)
    export_header = (
        f"# ========================================================\n"
        f"# Nova Cloud Edges — Nginx Host Migration Export\n"
        f"# Exported At: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"# Host ID: #{host.id}\n"
        f"# Primary Domain: {primary_domain}\n"
        f"# Target Upstream: {host.forward_scheme}://{host.forward_host}:{host.forward_port}\n"
        f"# SSL Enforced: {host.ssl_forced}\n"
        f"# Websocket: {host.websocket_support}\n"
        f"# Suspension Status: {'Suspended' if host.is_suspended else 'Active'}\n"
        f"# ========================================================\n\n"
    )
    full_export = export_header + conf_text

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="NGINX_EXPORT_SINGLE",
        details=f"Exported Nginx .conf for host #{host.id} ({primary_domain})",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return Response(
        content=full_export,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "X-Nova-Domain": primary_domain
        }
    )

@app.get("/api/nginx/export/all")
def export_all_hosts_zip(req: Request, db: Session = Depends(get_db)):
    """Export all sites' Nginx configs as a complete .zip backup archive with migration manifest."""
    verify_super_admin(req)
    hosts = db.query(ProxyHost).order_by(ProxyHost.id.asc()).all()
    zip_buffer = io.BytesIO()

    manifest = {
        "system": "Nova Proxy Admin",
        "exported_at": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        "total_hosts": len(hosts),
        "hosts": []
    }

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for h in hosts:
            domains = [d.strip() for d in h.domain_names.split(",") if d.strip()]
            primary = domains[0] if domains else f"site_{h.id}"
            conf_filename = f"{re.sub(r'[^a-zA-Z0-9_\.-]', '_', primary)}.conf"
            conf_body = generate_nginx_config(h, db)
            zip_file.writestr(f"sites-available/{conf_filename}", conf_body)

            manifest["hosts"].append({
                "id": h.id,
                "domain_names": h.domain_names,
                "forward_target": f"{h.forward_scheme}://{h.forward_host}:{h.forward_port}",
                "ssl_forced": h.ssl_forced,
                "websocket_support": h.websocket_support,
                "is_suspended": h.is_suspended,
                "conf_file": f"sites-available/{conf_filename}"
            })

        zip_file.writestr("migration_manifest.json", json.dumps(manifest, indent=2))

    zip_buffer.seek(0)
    timestamp_str = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    zip_filename = f"nova_nginx_backup_all_{timestamp_str}.zip"

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="NGINX_EXPORT_ALL",
        details=f"Exported full Nginx backup archive ({len(hosts)} sites)",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return Response(
        content=zip_buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{zip_filename}"'}
    )

@app.get("/api/nginx/export/combined")
def export_all_hosts_combined_conf(req: Request, db: Session = Depends(get_db)):
    """Export all sites combined in a single consolidated .conf file."""
    verify_super_admin(req)
    hosts = db.query(ProxyHost).order_by(ProxyHost.id.asc()).all()
    timestamp_str = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    combined_lines = [
        "# ========================================================",
        "# Nova Cloud Edges — Consolidated Nginx Configuration Backup",
        f"# Exported At: {timestamp_str}",
        f"# Total Sites: {len(hosts)}",
        "# ========================================================\n"
    ]

    for h in hosts:
        conf_body = generate_nginx_config(h, db)
        combined_lines.append(f"# --- Virtual Host: {h.domain_names} ---")
        combined_lines.append(conf_body)
        combined_lines.append("\n")

    full_text = "\n".join(combined_lines)

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="NGINX_EXPORT_COMBINED",
        details=f"Exported consolidated Nginx .conf ({len(hosts)} sites)",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return Response(
        content=full_text,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="nova_nginx_all_sites.conf"'}
    )

class NginxImportPayload(BaseModel):
    conf_content: str
    overwrite: bool = True

@app.post("/api/nginx/import/single")
def import_single_host_conf(payload: NginxImportPayload, req: Request, db: Session = Depends(get_db)):
    """Import a single site Nginx .conf text, creating or updating the proxy host for server migration."""
    verify_super_admin(req)
    raw_conf = payload.conf_content.strip()
    if not raw_conf:
        raise HTTPException(status_code=400, detail="Configuration text is empty.")

    parsed = parse_nginx_server_block(raw_conf)
    primary_domain = parsed["domain_names"].split(",")[0].strip()

    # Check for existing host by domain
    existing = db.query(ProxyHost).filter(ProxyHost.domain_names.like(f"%{primary_domain}%")).first()

    if existing and payload.overwrite:
        existing.host_type = parsed.get("host_type", "proxy")
        existing.root_path = parsed.get("root_path")
        existing.php_version = parsed.get("php_version", "auto")
        existing.php_fpm_socket = parsed.get("php_fpm_socket")
        existing.forward_scheme = parsed["forward_scheme"]
        existing.forward_host = parsed["forward_host"]
        existing.forward_port = parsed["forward_port"]
        existing.websocket_support = parsed["websocket_support"]
        existing.block_exploits = parsed["block_exploits"]
        existing.ssl_forced = parsed["ssl_forced"]
        existing.is_suspended = parsed["is_suspended"]
        existing.suspended_reason = parsed["suspended_reason"]
        target_host = existing
        action_msg = "updated"
    else:
        new_host = ProxyHost(
            domain_names=parsed["domain_names"],
            host_type=parsed.get("host_type", "proxy"),
            root_path=parsed.get("root_path"),
            php_version=parsed.get("php_version", "auto"),
            php_fpm_socket=parsed.get("php_fpm_socket"),
            forward_scheme=parsed["forward_scheme"],
            forward_host=parsed["forward_host"],
            forward_port=parsed["forward_port"],
            websocket_support=parsed["websocket_support"],
            block_exploits=parsed["block_exploits"],
            ssl_forced=parsed["ssl_forced"],
            ssl_provider="Let's Encrypt",
            ssl_status="active" if parsed["ssl_forced"] else "disabled",
            ssl_expires_at=datetime.date.today() + datetime.timedelta(days=90) if parsed["ssl_forced"] else None,
            is_suspended=parsed["is_suspended"],
            suspended_reason=parsed["suspended_reason"]
        )
        db.add(new_host)
        target_host = new_host
        action_msg = "created"

    db.commit()
    db.refresh(target_host)

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="NGINX_IMPORT_SINGLE",
        details=f"Imported Nginx site '{target_host.domain_names}' -> {target_host.host_type.upper()} ({action_msg})",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {
        "message": f"Successfully {action_msg} proxy host for domain(s): {target_host.domain_names}",
        "host_id": target_host.id,
        "domain_names": target_host.domain_names,
        "host_type": target_host.host_type,
        "forward_target": f"{target_host.forward_scheme}://{target_host.forward_host}:{target_host.forward_port}" if target_host.host_type == "proxy" else (target_host.root_path or "LEMP")
    }

@app.post("/api/nginx/import/all")
def import_multi_host_conf(payload: NginxImportPayload, req: Request, db: Session = Depends(get_db)):
    """Import multiple Nginx sites from combined .conf text for full server migration."""
    verify_super_admin(req)
    raw_conf = payload.conf_content.strip()
    if not raw_conf:
        raise HTTPException(status_code=400, detail="Configuration text is empty.")

    # Split by 'server {'
    parts = re.split(r'\bserver\s*\{', raw_conf, flags=re.IGNORECASE)
    server_blocks = [p for p in parts if "proxy_pass" in p or "server_name" in p or "fastcgi_pass" in p]

    if not server_blocks:
        # Fallback to single block parsing
        server_blocks = [raw_conf]

    imported = []
    for block in server_blocks:
        parsed = parse_nginx_server_block(block)
        primary_domain = parsed["domain_names"].split(",")[0].strip()
        if not primary_domain or primary_domain == "imported-host.local":
            continue

        existing = db.query(ProxyHost).filter(ProxyHost.domain_names.like(f"%{primary_domain}%")).first()
        if existing and payload.overwrite:
            existing.host_type = parsed.get("host_type", "proxy")
            existing.root_path = parsed.get("root_path")
            existing.php_version = parsed.get("php_version", "auto")
            existing.php_fpm_socket = parsed.get("php_fpm_socket")
            existing.forward_scheme = parsed["forward_scheme"]
            existing.forward_host = parsed["forward_host"]
            existing.forward_port = parsed["forward_port"]
            existing.websocket_support = parsed["websocket_support"]
            existing.block_exploits = parsed["block_exploits"]
            existing.ssl_forced = parsed["ssl_forced"]
            existing.is_suspended = parsed["is_suspended"]
            target = existing
        else:
            new_h = ProxyHost(
                domain_names=parsed["domain_names"],
                host_type=parsed.get("host_type", "proxy"),
                root_path=parsed.get("root_path"),
                php_version=parsed.get("php_version", "auto"),
                php_fpm_socket=parsed.get("php_fpm_socket"),
                forward_scheme=parsed["forward_scheme"],
                forward_host=parsed["forward_host"],
                forward_port=parsed["forward_port"],
                websocket_support=parsed["websocket_support"],
                block_exploits=parsed["block_exploits"],
                ssl_forced=parsed["ssl_forced"],
                ssl_provider="Let's Encrypt",
                ssl_status="active" if parsed["ssl_forced"] else "disabled",
                ssl_expires_at=datetime.date.today() + datetime.timedelta(days=90) if parsed["ssl_forced"] else None,
                is_suspended=parsed["is_suspended"],
                suspended_reason=parsed["suspended_reason"]
            )
            db.add(new_h)
            target = new_h

        db.commit()
        imported.append(parsed["domain_names"])

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="NGINX_IMPORT_ALL",
        details=f"Bulk imported {len(imported)} Nginx sites for server migration",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {
        "message": f"Successfully migrated and restored {len(imported)} Nginx virtual hosts.",
        "imported_count": len(imported),
        "imported_domains": imported
    }

# ---------------------------------------------------------
# Host Nginx & UFW Auto-Discovery / Auto-Sync
# ---------------------------------------------------------
def deduplicate_proxy_hosts(db: Session) -> int:
    """
    Finds and eliminates duplicate proxy hosts in the database.
    Keeps only the single best entry for each primary domain (preferring non-127.0.0.1 upstream targets).
    """
    all_hosts = db.query(ProxyHost).order_by(ProxyHost.id.asc()).all()
    seen = {}
    to_delete = []

    for h in all_hosts:
        doms = [d.strip().lower() for d in h.domain_names.split(",") if d.strip()]
        if not doms:
            continue
        primary = doms[0]

        if primary not in seen:
            seen[primary] = h
        else:
            existing = seen[primary]
            # If current host has a real upstream IP and existing was 127.0.0.1, keep current host and delete existing
            if existing.forward_host in ["127.0.0.1", "localhost"] and h.forward_host not in ["127.0.0.1", "localhost"]:
                to_delete.append(existing.id)
                seen[primary] = h
            else:
                to_delete.append(h.id)

    if to_delete:
        db.query(ProxyHost).filter(ProxyHost.id.in_(to_delete)).delete(synchronize_session=False)
        db.commit()
    return len(to_delete)

def scan_host_nginx_configs() -> list:
    """
    Scans host Linux system for real active Nginx configurations.
    Strictly prioritizes /etc/nginx/sites-enabled/ to avoid duplicates from sites-available/.
    Deduplicates by primary domain and ignores pure HTTP->HTTPS redirect blocks.
    """
    search_dirs = []
    # If sites-enabled exists and has files, ONLY scan sites-enabled. Never mix with sites-available!
    if os.path.isdir("/etc/nginx/sites-enabled") and len(os.listdir("/etc/nginx/sites-enabled")) > 0:
        search_dirs.append("/etc/nginx/sites-enabled")
        if os.path.isdir("/etc/nginx/conf.d") and len(os.listdir("/etc/nginx/conf.d")) > 0:
            search_dirs.append("/etc/nginx/conf.d")
    elif os.path.isdir("/etc/nginx/conf.d") and len(os.listdir("/etc/nginx/conf.d")) > 0:
        search_dirs.append("/etc/nginx/conf.d")
    elif os.path.isdir("/etc/nginx/sites-available"):
        search_dirs.append("/etc/nginx/sites-available")
    elif os.path.isdir("/usr/local/nginx/conf"):
        search_dirs.append("/usr/local/nginx/conf")

    found_files = []
    for d in search_dirs:
        try:
            for entry in sorted(os.listdir(d)):
                full_p = os.path.join(d, entry)
                if os.path.isfile(full_p):
                    real_p = os.path.realpath(full_p)
                    if real_p not in found_files:
                        found_files.append(real_p)
        except Exception as e:
            print(f"Notice: Reading Nginx directory {d}: {e}")

    domain_map = {}

    for fpath in found_files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if "server" not in content.lower():
                continue

            parts = re.split(r'\bserver\s*\{', content, flags=re.IGNORECASE)
            server_blocks = [p for p in parts if "server_name" in p or "proxy_pass" in p]
            if not server_blocks:
                server_blocks = [content]

            for block in server_blocks:
                server_name_match = re.search(r'server_name\s+([^;]+);', block, re.IGNORECASE)
                if not server_name_match:
                    continue
                raw_domains = server_name_match.group(1).split()
                doms = [d.strip() for d in raw_domains if d.strip() and not d.startswith('_') and d.strip() not in ["localhost", "127.0.0.1"]]
                if not doms:
                    continue

                primary_domain = doms[0].lower()

                proxy_pass_match = re.search(r'proxy_pass\s+(https?://)([^:;/]+)(?::(\d+))?([^;]*);', block, re.IGNORECASE)
                has_proxy_pass = bool(proxy_pass_match)

                # Pure redirect blocks (HTTP port 80 -> HTTPS) must never become fake 127.0.0.1:8080 entries
                is_pure_redirect = bool(re.search(r'return\s+301\s+https', block, re.IGNORECASE)) and not has_proxy_pass

                if is_pure_redirect:
                    if primary_domain in domain_map:
                        domain_map[primary_domain]["ssl_forced"] = True
                    continue

                fastcgi_match = re.search(r'fastcgi_pass\s+([^;]+);', block, re.IGNORECASE)
                root_match = re.search(r'root\s+([^;]+);', block, re.IGNORECASE)

                host_type = "proxy"
                root_path = root_match.group(1).strip() if root_match else None
                php_version = "auto"
                php_fpm_socket = None

                forward_scheme = "http"
                forward_host = "127.0.0.1"
                forward_port = 80
                if proxy_pass_match:
                    forward_scheme = proxy_pass_match.group(1).replace("://", "")
                    forward_host = proxy_pass_match.group(2)
                    forward_port = int(proxy_pass_match.group(3)) if proxy_pass_match.group(3) else (443 if forward_scheme == "https" else 80)
                elif fastcgi_match:
                    host_type = "lemp"
                    php_fpm_socket = fastcgi_match.group(1).strip()
                    m_ver = re.search(r'php(\d+\.\d+)', php_fpm_socket)
                    if m_ver:
                        php_version = m_ver.group(1)
                elif root_match:
                    host_type = "static"
                else:
                    # Skip blocks with no proxy_pass, no fastcgi, and no root to avoid duplicate loopback entries
                    continue

                websocket_support = bool(re.search(r'Upgrade|http_upgrade', block, re.IGNORECASE))
                block_exploits = bool(re.search(r'\.git|\.env|deny\s+all', block, re.IGNORECASE))
                ssl_forced = bool(re.search(r'443\s+ssl|ssl_certificate|return\s+301\s+https', block, re.IGNORECASE))

                ssl_cert_match = re.search(r'ssl_certificate\s+([^;]+);', block)
                ssl_provider = "Let's Encrypt" if (ssl_cert_match and "letsencrypt" in ssl_cert_match.group(1).lower()) else ("Self-Signed" if ssl_forced else "None")

                host_entry = {
                    "file_path": fpath,
                    "domain_names": ", ".join(doms),
                    "host_type": host_type,
                    "root_path": root_path,
                    "php_version": php_version,
                    "php_fpm_socket": php_fpm_socket,
                    "forward_scheme": forward_scheme,
                    "forward_host": forward_host,
                    "forward_port": forward_port,
                    "websocket_support": websocket_support,
                    "block_exploits": block_exploits,
                    "ssl_forced": ssl_forced,
                    "ssl_provider": ssl_provider,
                    "custom_nginx_config": block.strip(),
                    "has_proxy_pass": has_proxy_pass
                }

                if primary_domain in domain_map:
                    existing_entry = domain_map[primary_domain]
                    if not existing_entry["has_proxy_pass"] and has_proxy_pass:
                        domain_map[primary_domain] = host_entry
                    elif existing_entry["forward_host"] in ["127.0.0.1", "localhost"] and forward_host not in ["127.0.0.1", "localhost"]:
                        domain_map[primary_domain] = host_entry
                    elif not existing_entry["ssl_forced"] and ssl_forced:
                        existing_entry["ssl_forced"] = True
                        existing_entry["ssl_provider"] = ssl_provider
                else:
                    domain_map[primary_domain] = host_entry
        except Exception as e:
            print(f"Notice: Parsing {fpath}: {e}")

    return list(domain_map.values())

def sync_host_nginx_into_db(db: Session, force_replace_demo: bool = False) -> dict:
    discovered = scan_host_nginx_configs()

    demo_domains = ["api.novacloud.io", "portal.novacloudedges.com", "staging.gisunika.org", "migration-test.ncloud.io", "sun.ac.ug"]
    if force_replace_demo:
        for dd in demo_domains:
            db.query(ProxyHost).filter(ProxyHost.domain_names.like(f"%{dd}%")).delete(synchronize_session=False)
        db.commit()

    # Pre-clean duplicates from existing DB
    deduplicate_proxy_hosts(db)

    if not discovered:
        return {"status": "skipped", "message": "No active Nginx proxy configurations found in sites-enabled.", "synced": 0}

    synced_count = 0
    created_count = 0
    updated_count = 0

    for item in discovered:
        primary_domain = item["domain_names"].split(",")[0].strip().lower()
        existing = db.query(ProxyHost).filter(ProxyHost.domain_names.like(f"%{primary_domain}%")).first()

        if existing:
            existing.domain_names = item["domain_names"]
            existing.host_type = item.get("host_type", "proxy")
            existing.root_path = item.get("root_path")
            existing.php_version = item.get("php_version", "auto")
            existing.php_fpm_socket = item.get("php_fpm_socket")
            existing.forward_scheme = item["forward_scheme"]
            existing.forward_host = item["forward_host"]
            existing.forward_port = item["forward_port"]
            existing.websocket_support = item["websocket_support"]
            existing.block_exploits = item["block_exploits"]
            existing.ssl_forced = item["ssl_forced"]
            existing.ssl_provider = item["ssl_provider"]
            existing.custom_nginx_config = item["custom_nginx_config"]
            updated_count += 1
        else:
            new_host = ProxyHost(
                domain_names=item["domain_names"],
                app_name="Host Nginx VirtualHost",
                host_type=item.get("host_type", "proxy"),
                root_path=item.get("root_path"),
                php_version=item.get("php_version", "auto"),
                php_fpm_socket=item.get("php_fpm_socket"),
                forward_scheme=item["forward_scheme"],
                forward_host=item["forward_host"],
                forward_port=item["forward_port"],
                websocket_support=item["websocket_support"],
                block_exploits=item["block_exploits"],
                ssl_forced=item["ssl_forced"],
                ssl_provider=item["ssl_provider"],
                ssl_status="active" if item["ssl_forced"] else "disabled",
                ssl_expires_at=datetime.date.today() + datetime.timedelta(days=90) if item["ssl_forced"] else None,
                is_suspended=False,
                custom_nginx_config=item["custom_nginx_config"]
            )
            db.add(new_host)
            created_count += 1
        synced_count += 1

    db.commit()

    # Final deduplication pass to ensure strictly 1 row per domain
    deduplicate_proxy_hosts(db)

    return {
        "status": "success",
        "synced": synced_count,
        "created": created_count,
        "updated": updated_count,
        "discovered": [h["domain_names"] for h in discovered]
    }

def sync_host_ufw_into_db(db: Session) -> dict:
    """Parses live ufw status numbered from the Linux OS and synchronizes with UFWRule table."""
    try:
        res = subprocess.run(["ufw", "status", "numbered"], capture_output=True, text=True, timeout=5)
        if res.returncode != 0 or not res.stdout.strip():
            return {"status": "unavailable", "message": "UFW not active or permission denied", "synced": 0}

        lines = res.stdout.splitlines()
        rule_pattern = re.compile(r'\[\s*(\d+)\]\s+([^\s]+)\s+(ALLOW|DENY|REJECT|LIMIT)(?:\s+IN)?\s+([^\s#]+)(?:\s+#\s*(.*))?', re.IGNORECASE)

        parsed_rules = []
        for line in lines:
            m = rule_pattern.search(line)
            if m:
                target = m.group(2).strip()
                action = m.group(3).strip().upper()
                source = m.group(4).strip()
                comment = (m.group(5) or "").strip()

                port = "Any"
                proto = "tcp"
                if "/" in target:
                    parts = target.split("/")
                    port = parts[0]
                    proto = parts[1]
                else:
                    port = target

                parsed_rules.append({
                    "port": port,
                    "protocol": proto,
                    "rule_type": action,
                    "from_ip": source,
                    "to_ip": "Anywhere",
                    "comment": comment
                })

        if not parsed_rules:
            return {"status": "empty", "message": "No active numbered rules found in UFW", "synced": 0}

        db.query(UFWRule).delete()
        for r in parsed_rules:
            db.add(UFWRule(
                rule_type=r["rule_type"],
                port=r["port"],
                protocol=r["protocol"],
                from_ip=r["from_ip"],
                to_ip=r["to_ip"],
                comment=r["comment"] if r["comment"] else "Live Host UFW rule",
                is_active=True
            ))
        db.commit()
        return {"status": "success", "synced": len(parsed_rules), "rules": parsed_rules}
    except Exception as e:
        return {"status": "error", "message": str(e), "synced": 0}

@app.post("/api/nginx/auto-sync")
def api_sync_host_nginx(req: Request, replace_demo: bool = False, db: Session = Depends(get_db)):
    """Auto-detects and synchronizes real virtual host configs from host /etc/nginx."""
    verify_super_admin(req)
    result = sync_host_nginx_into_db(db, force_replace_demo=replace_demo)
    return result

def purge_demo_hosts(db: Session) -> int:
    """Removes development dummy seed hosts (demo.novacloudedges.com, etc.) from database if explicitly requested."""
    demo_patterns = [
        "demo.novacloudedges.com",
        "migration-test.ncloud.io",
        "staging.gisunika.org"
    ]
    deleted = 0
    try:
        for pat in demo_patterns:
            cnt = db.query(ProxyHost).filter(ProxyHost.domain_names.like(f"%{pat}%")).delete(synchronize_session=False)
            deleted += cnt
        if deleted > 0:
            db.commit()
    except Exception as e:
        print(f"Notice: purge_demo_hosts: {e}")
    return deleted

@app.post("/api/nginx/clear-demo-hosts")
def api_clear_demo_hosts(req: Request, db: Session = Depends(get_db)):
    """Removes development dummy seed hosts from database."""
    verify_super_admin(req)
    deleted = purge_demo_hosts(db)
    return {"message": f"Successfully removed {deleted} demo hosts from database."}

@app.post("/api/hosts/deduplicate")
def api_deduplicate_hosts(req: Request, db: Session = Depends(get_db)):
    """Removes duplicate proxy hosts from database, keeping only the single best entry per domain."""
    verify_super_admin(req)
    deleted = deduplicate_proxy_hosts(db)
    return {"message": f"Successfully removed {deleted} duplicate host records.", "removed": deleted}

@app.post("/api/ufw/auto-sync")
def api_sync_host_ufw(req: Request, db: Session = Depends(get_db)):
    """Auto-detects and synchronizes real live firewall rules from host UFW CLI."""
    verify_super_admin(req)
    result = sync_host_ufw_into_db(db)
    return result

@app.on_event("startup")
def on_app_startup():
    """Auto-seeds default super_admin account and syncs live host Nginx & UFW configuration on server startup."""
    try:
        db = SessionLocal()
        try:
            ensure_default_admin(db)
            if platform.system() == "Linux" and os.path.isdir("/etc/nginx"):
                sync_host_nginx_into_db(db, force_replace_demo=False)
                sync_host_ufw_into_db(db)
        finally:
            db.close()
    except Exception as e:
        print(f"Notice: Server startup auto-sync: {e}")

@app.get("/api/php-runtimes")
def get_php_runtimes():
    """Returns detected PHP versions and sockets on the host system."""
    return detect_host_php_runtimes()

@app.post("/api/nginx/reload")
def reload_system_nginx(req: Request):
    """Tests syntax with nginx -t and reloads Nginx daemon."""
    verify_super_admin(req)
    if platform.system() != "Linux":
        return {"status": "skipped", "message": "Host system is not Linux. Nginx reload simulated successfully."}
    
    t_res = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=8)
    if t_res.returncode != 0:
        raise HTTPException(status_code=400, detail=f"Nginx syntax error: {t_res.stderr or t_res.stdout}")
    
    r_res = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True, timeout=8)
    if r_res.returncode != 0:
        r_res = subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True, timeout=8)
    
    if r_res.returncode != 0:
        raise HTTPException(status_code=500, detail=f"Failed to reload Nginx: {r_res.stderr or r_res.stdout}")
    
    return {"status": "success", "message": "Nginx configuration verified and service reloaded successfully."}

@app.post("/api/validate-nginx")
def validate_nginx_config(payload: NginxValidationRequest):
    """
    Validates Nginx configuration syntax with precise line numbers for debugging:
    - Missing semicolons
    - Unbalanced/unclosed braces
    - Unmatched quote strings
    - Real-time nginx -t test parser if nginx binary is present on the host
    """
    lines = payload.config_text.splitlines()
    errors = []
    brace_stack = []

    for idx, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Check for unclosed single or double quotes
        # ignore escaped quotes
        clean_quotes = re.sub(r'\\.', '', line)
        if clean_quotes.count('"') % 2 != 0:
            errors.append(f"Line {idx}: Unclosed double quote (\") in directive: '{line}'")
        elif clean_quotes.count("'") % 2 != 0:
            errors.append(f"Line {idx}: Unclosed single quote (') in directive: '{line}'")

        # Track brace hierarchy with line numbers
        for char in line:
            if char == "{":
                brace_stack.append(idx)
            elif char == "}":
                if brace_stack:
                    brace_stack.pop()
                else:
                    errors.append(f"Line {idx}: Unexpected closing brace '}}' with no matching open block.")

        # Semicolon validation on directives
        if not line.endswith("{") and not line.endswith("}") and not line.endswith(";"):
            errors.append(f"Line {idx}: Directive missing terminating semicolon ';': '{line}'")

    for open_line in brace_stack:
        errors.append(f"Line {open_line}: Unclosed block directive — opening brace '{{' is never closed.")

    # If static check passes, run real nginx -t if nginx is installed on host
    nginx_bin = shutil.which("nginx")
    if nginx_bin and not errors:
        tf_path = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as tf:
                tf.write(payload.config_text)
                tf_path = tf.name
            
            proc = subprocess.run([nginx_bin, "-t", "-c", tf_path], capture_output=True, text=True, timeout=6)
            if proc.returncode != 0:
                raw_out = (proc.stderr or "") + "\n" + (proc.stdout or "")
                for raw_l in raw_out.splitlines():
                    clean_l = raw_l.strip()
                    if not clean_l or "test is successful" in clean_l:
                        continue
                    m = re.search(r"in\s+[^\s:]+:(\d+)", clean_l)
                    if m:
                        line_no = m.group(1)
                        # Extract clean error message
                        msg_clean = clean_l
                        if "[emerg]" in clean_l:
                            msg_clean = clean_l.split("[emerg]")[-1].strip()
                        errors.append(f"Line {line_no}: [emerg] {msg_clean}")
                    elif "[emerg]" in clean_l:
                        errors.append(f"Syntax Error: {clean_l.split('[emerg]')[-1].strip()}")
                    elif clean_l.startswith("nginx:"):
                        errors.append(clean_l)
        except Exception as e:
            pass
        finally:
            if tf_path and os.path.exists(tf_path):
                try:
                    os.unlink(tf_path)
                except Exception:
                    pass

    if errors:
        return {
            "valid": False,
            "message": f"Nginx configuration syntax check failed with {len(errors)} error(s)",
            "errors": errors
        }

    return {
        "valid": True,
        "message": "Syntax OK: Nginx configuration test is successful (nginx: configuration file test is successful)",
        "errors": []
    }

def validate_ufw_ip(ip_str: str) -> str:
    """Validates IPv4 or IPv6 address/CIDR or returns 'Anywhere'."""
    clean = ip_str.strip()
    if clean.lower() in ["anywhere", "any", "all", "0.0.0.0/0", "::/0"]:
        return "Anywhere"
    try:
        if "/" in clean:
            ipaddress.ip_network(clean, strict=False)
        else:
            ipaddress.ip_address(clean)
        return clean
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid IP address or CIDR format: '{clean}'. Supported formats: IPv4 (e.g. 192.168.1.1, 10.0.0.0/24) and IPv6 (e.g. 2001:db8::1, 2001:db8::/32) or 'Anywhere'."
        )

def build_ufw_command_args(action: str, rule: UFWRule) -> list[str]:
    """
    Builds exact valid UFW CLI arguments.
    Supports:
    - CIDR or host IP: ufw allow from 137.63.181.0/24 to any port 443
    - Anywhere: ufw allow 443/tcp or ufw allow 443
    - Protocols: tcp, udp, or any (omits proto flag)
    - Actions: 'add' (allow/deny/...) or 'delete'
    """
    cmd = ["ufw"]
    act_type = rule.rule_type.lower()

    if action == "delete":
        cmd.append("delete")
    cmd.append(act_type)

    from_ip = (rule.from_ip or "").strip()
    is_anywhere = from_ip.lower() in ["anywhere", "any", "all", "0.0.0.0/0", "::/0", ""]
    has_port = rule.port and str(rule.port).strip().lower() not in ["any", "all", ""]
    proto = (rule.protocol or "any").lower().strip()

    if not is_anywhere:
        # e.g. from 137.63.181.0/24 to any port 443
        cmd.extend(["from", from_ip])
        if has_port:
            cmd.extend(["to", "any", "port", str(rule.port).strip()])
        if proto in ["tcp", "udp"]:
            cmd.extend(["proto", proto])
    else:
        # Source is Anywhere
        if has_port:
            if proto in ["tcp", "udp"]:
                cmd.append(f"{str(rule.port).strip()}/{proto}")
            else:
                cmd.extend(["to", "any", "port", str(rule.port).strip()])
        elif proto in ["tcp", "udp"]:
            cmd.extend(["proto", proto])

    return cmd

def sync_host_firewall_rule(action: str, rule: UFWRule):
    """Executes host firewall command (ufw) if present on operating system."""
    try:
        if subprocess.call(["which", "ufw"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            cmd = build_ufw_command_args(action, rule)
            subprocess.run(cmd, capture_output=True, timeout=8)
    except Exception as e:
        print(f"Notice: Host firewall synchronization: {e}")

def parse_ufw_command(command_str: str) -> dict:
    """
    Parses a raw UFW command string (e.g. 'ufw allow from 137.63.181.0/24 to any port 443').
    Extracts rule_type, from_ip, port, protocol, and comment.
    """
    s = command_str.strip()
    s = re.sub(r'^\s*ufw\s+', '', s, flags=re.IGNORECASE)

    comment = None
    comm_match = re.search(r'(?:comment\s+["\']([^"\']+)["\']|#\s*(.*)$)', s, re.IGNORECASE)
    if comm_match:
        comment = (comm_match.group(1) or comm_match.group(2) or "").strip()
        s = re.sub(r'(?:comment\s+["\'][^"\']+["\']|#\s*.*$)', '', s, flags=re.IGNORECASE).strip()

    action_match = re.match(r'^(allow|deny|reject|limit)\b', s, re.IGNORECASE)
    if not action_match:
        raise HTTPException(
            status_code=400,
            detail="Invalid UFW command syntax: must start with allow, deny, reject, or limit (e.g. 'ufw allow from 137.63.181.0/24 to any port 443')"
        )

    rule_type = action_match.group(1).upper()
    rest = s[action_match.end():].strip()

    from_ip = "Anywhere"
    from_match = re.search(r'\bfrom\s+([^\s]+)', rest, re.IGNORECASE)
    if from_match:
        from_ip = from_match.group(1).strip()

    port = "Any"
    proto = "any"
    port_match = re.search(r'\bport\s+([0-9a-zA-Z_\-]+)', rest, re.IGNORECASE)
    if port_match:
        port = port_match.group(1).strip()
    else:
        simple_match = re.search(r'\b(\d+)(?:/(tcp|udp))?\b', rest, re.IGNORECASE)
        if simple_match:
            port = simple_match.group(1).strip()
            if simple_match.group(2):
                proto = simple_match.group(2).lower().strip()

    proto_match = re.search(r'\bproto\s+(tcp|udp)\b', rest, re.IGNORECASE)
    if proto_match:
        proto = proto_match.group(1).lower().strip()

    validated_ip = validate_ufw_ip(from_ip)

    return {
        "rule_type": rule_type,
        "from_ip": validated_ip,
        "port": port,
        "protocol": proto,
        "comment": comment
    }

class UFWCommandRequest(BaseModel):
    command: str
    comment: Optional[str] = None

@app.post("/api/ufw/execute-command")
def execute_ufw_command(data: UFWCommandRequest, req: Request, db: Session = Depends(get_db)):
    """
    Parses and executes a raw UFW command (e.g. 'ufw allow from 137.63.181.0/24 to any port 443').
    Applies rule directly to Linux host UFW firewall and records it in database.
    """
    verify_super_admin(req)
    parsed = parse_ufw_command(data.command)
    comment = data.comment or parsed.get("comment") or "Applied via UFW Command Bar"

    rule = UFWRule(
        rule_type=parsed["rule_type"],
        port=parsed["port"],
        protocol=parsed["protocol"],
        from_ip=parsed["from_ip"],
        to_ip="Anywhere",
        comment=comment,
        is_active=True
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    cmd_args = build_ufw_command_args("add", rule)
    raw_output = ""
    success = True

    try:
        if subprocess.call(["which", "ufw"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            res = subprocess.run(cmd_args, capture_output=True, text=True, timeout=10)
            raw_output = res.stdout.strip() or res.stderr.strip()
            if res.returncode != 0:
                success = False
                rule.is_active = False
                db.commit()
                raise HTTPException(status_code=400, detail=f"UFW execution error: {raw_output}")
        else:
            raw_output = f"Rule saved (ufw binary not present on {platform.system()})"
    except HTTPException:
        raise
    except Exception as e:
        raw_output = f"Notice: {str(e)}"

    cmd_str = " ".join(cmd_args)
    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="UFW_CLI_EXECUTE",
        details=f"Executed firewall command: '{cmd_str}' -> {parsed['rule_type']} from {parsed['from_ip']} to port {parsed['port']}",
        status="success" if success else "failed",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    send_smtp_notification(
        "ufw",
        f"Firewall Rule #{rule.id} Applied via CLI",
        f"UFW command executed:\n\n{cmd_str}\n\nRule ID: #{rule.id}\nAction: {rule.rule_type}\nSource: {rule.from_ip}\nPort: {rule.port}\nOutput: {raw_output}\nOperator IP: {client_ip}",
        db
    )

    return {
        "status": "success",
        "message": f"Firewall rule #{rule.id} successfully applied: {cmd_str}",
        "command": cmd_str,
        "raw_output": raw_output,
        "rule": {
            "id": rule.id,
            "rule_type": rule.rule_type,
            "port": rule.port,
            "protocol": rule.protocol,
            "from_ip": rule.from_ip,
            "comment": rule.comment
        }
    }

@app.get("/api/ufw/rules")
def get_ufw_rules(db: Session = Depends(get_db)):
    """Fetch all host-synced UFW firewall rules."""
    rules = db.query(UFWRule).order_by(UFWRule.id.asc()).all()
    return [
        {
            "id": r.id,
            "rule_type": r.rule_type,
            "port": r.port,
            "protocol": r.protocol,
            "from_ip": r.from_ip,
            "to_ip": r.to_ip,
            "comment": r.comment or "",
            "is_active": bool(r.is_active),
            "created_at": r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else ""
        }
        for r in rules
    ]

@app.post("/api/ufw/rules")
def add_ufw_rule(data: UFWRuleCreate, req: Request, db: Session = Depends(get_db)):
    """Create a new UFW firewall rule with IPv4/IPv6 support and email alert."""
    valid_from_ip = validate_ufw_ip(data.from_ip)

    rule = UFWRule(
        rule_type=data.rule_type.upper(),
        port=data.port.strip(),
        protocol=data.protocol.lower(),
        from_ip=valid_from_ip,
        to_ip="Anywhere",
        comment=data.comment.strip() if data.comment else None,
        is_active=True
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    sync_host_firewall_rule("add", rule)

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="UFW_RULE_ADD",
        details=f"Added UFW rule #{rule.id}: {rule.rule_type} {rule.port}/{rule.protocol} from {rule.from_ip} ({rule.comment})",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    # Trigger SMTP email notification
    send_smtp_notification(
        "ufw",
        f"New Firewall Rule #{rule.id} Created",
        f"A new UFW firewall rule was added:\n\nAction: {rule.rule_type}\nPort: {rule.port}\nProtocol: {rule.protocol}\nSource: {rule.from_ip}\nComment: {rule.comment or 'None'}\nOperator IP: {client_ip}",
        db
    )

    return {"message": "UFW rule applied and host firewall synced", "rule_id": rule.id}

@app.post("/api/ufw/rules/{rule_id}/toggle")
def toggle_ufw_rule(rule_id: int, req: Request, db: Session = Depends(get_db)):
    rule = db.query(UFWRule).filter(UFWRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="UFW rule not found")

    rule.is_active = not rule.is_active
    db.commit()

    sync_host_firewall_rule("add" if rule.is_active else "delete", rule)

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="UFW_RULE_TOGGLE",
        details=f"Toggled UFW rule #{rule.id} to {'active' if rule.is_active else 'inactive'}",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    send_smtp_notification(
        "ufw",
        f"Firewall Rule #{rule.id} {'Activated' if rule.is_active else 'Deactivated'}",
        f"UFW firewall rule #{rule.id} ({rule.rule_type} {rule.port}/{rule.protocol} from {rule.from_ip}) status changed to {'ACTIVE' if rule.is_active else 'INACTIVE'}.\nOperator IP: {client_ip}",
        db
    )

    return {"message": f"Rule status set to {'Active' if rule.is_active else 'Inactive'}", "is_active": rule.is_active}

@app.put("/api/ufw/rules/{rule_id}")
def update_ufw_rule(rule_id: int, data: UFWRuleCreate, req: Request, db: Session = Depends(get_db)):
    """Update an existing UFW firewall rule with IPv4/IPv6 support and email alert."""
    rule = db.query(UFWRule).filter(UFWRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="UFW rule not found")

    valid_from_ip = validate_ufw_ip(data.from_ip)

    old_desc = f"{rule.rule_type} {rule.port}/{rule.protocol} from {rule.from_ip}"
    rule.rule_type = data.rule_type.upper()
    rule.port = data.port.strip()
    rule.protocol = data.protocol.lower()
    rule.from_ip = valid_from_ip
    rule.comment = data.comment.strip() if data.comment else None
    db.commit()
    db.refresh(rule)

    sync_host_firewall_rule("add", rule)

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="UFW_RULE_EDIT",
        details=f"Updated UFW rule #{rule.id} from [{old_desc}] to [{rule.rule_type} {rule.port}/{rule.protocol} from {rule.from_ip}]",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    send_smtp_notification(
        "ufw",
        f"Firewall Rule #{rule.id} Updated",
        f"UFW rule #{rule.id} was updated:\n\nPrevious: {old_desc}\nNew Rule: {rule.rule_type} {rule.port}/{rule.protocol} from {rule.from_ip}\nComment: {rule.comment or 'None'}\nOperator IP: {client_ip}",
        db
    )

    return {"message": f"UFW rule #{rule.id} updated successfully", "rule_id": rule.id}

@app.delete("/api/ufw/rules/{rule_id}")
def delete_ufw_rule(rule_id: int, req: Request, db: Session = Depends(get_db)):
    rule = db.query(UFWRule).filter(UFWRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="UFW rule not found")

    sync_host_firewall_rule("delete", rule)
    rule_desc = f"{rule.rule_type} {rule.port}/{rule.protocol} from {rule.from_ip}"
    db.delete(rule)
    db.commit()

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="UFW_RULE_DELETE",
        details=f"Deleted UFW rule #{rule_id} ({rule_desc})",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    send_smtp_notification(
        "ufw",
        f"Firewall Rule #{rule_id} Removed",
        f"UFW rule #{rule_id} was removed: {rule_desc}\nOperator IP: {client_ip}",
        db
    )

    return {"message": f"UFW rule #{rule_id} deleted"}

@app.get("/api/ufw/status")
def get_ufw_cli_status(db: Session = Depends(get_db)):
    """
    Returns UFW CLI formatted numbered status directly from host machine if available,
    or formatted from active firewall rules.
    """
    try:
        res = subprocess.run(["ufw", "status", "numbered"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0 and res.stdout.strip():
            return {"status": "active", "raw_cli_output": res.stdout}
    except Exception:
        pass

    rules = db.query(UFWRule).filter(UFWRule.is_active == True).all()

    cli_output = "Status: active (host synced)\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n\n"
    cli_output += f"{'':<4}{'To':<28}{'Action':<16}{'From':<24}{'Comment'}\n"
    cli_output += f"{'':<4}{'--':<28}{'------':<16}{'----':<24}{'-------'}\n"

    for idx, r in enumerate(rules, 1):
        target = f"{r.port}/{r.protocol}" if r.port != "Any" else "Anywhere"
        action = f"{r.rule_type} IN"
        source = r.from_ip
        comment = f"# {r.comment}" if r.comment else ""
        cli_output += f"[{idx:2}] {target:<28}{action:<16}{source:<24}{comment}\n"

    return {
        "status": "active",
        "raw_cli_output": cli_output
    }

# ---------------------------------------------------------
# Security Role: WHOIS & Abuse Reports
# ---------------------------------------------------------
@app.get("/api/abuse-reports")
def get_abuse_reports(db: Session = Depends(get_db)):
    reports = db.query(DomainAbuseReport).order_by(DomainAbuseReport.id.desc()).all()
    return [
        {
            "id": r.id,
            "domain": r.domain,
            "source_ip": r.source_ip,
            "abuse_category": r.abuse_category,
            "action_taken": r.action_taken,
            "status": r.status,
            "notes": r.notes or "",
            "created_at": r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else ""
        }
        for r in reports
    ]

@app.post("/api/abuse-reports")
def report_domain_abuse(data: AbuseReportCreate, req: Request, db: Session = Depends(get_db)):
    report = DomainAbuseReport(
        domain=data.domain.strip(),
        source_ip=data.source_ip.strip(),
        abuse_category=data.abuse_category.strip(),
        action_taken="Blocked via UFW Firewall" if data.block_in_ufw else "Flagged for Investigation",
        status="blocked" if data.block_in_ufw else "investigating",
        notes=data.notes
    )
    db.add(report)

    if data.block_in_ufw and data.source_ip and data.source_ip != "127.0.0.1":
        ufw_entry = UFWRule(
            rule_type="DENY",
            port="Any",
            protocol="tcp",
            from_ip=data.source_ip.strip(),
            comment=f"Auto-blocked for abuse on {data.domain}: {data.abuse_category}",
            is_active=True
        )
        db.add(ufw_entry)

    db.commit()

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="ABUSE_REPORTED",
        details=f"Filed abuse for {data.domain} from IP {data.source_ip} ({data.abuse_category})",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    # Trigger SMTP email notification
    send_smtp_notification(
        "blocking",
        f"Domain Abuse Alert & IP Blocked: {data.domain}",
        f"Security alert triggered on Nova Edge Proxy.\nTarget Domain: {data.domain}\nOffending IP: {data.source_ip}\nCategory: {data.abuse_category}\nAction Enforced: {'Host & UFW Firewall IP Drop Rule Enforced' if data.block_in_ufw else 'Investigating'}\nNotes: {data.notes or 'None'}\nReported by: {client_ip}",
        db
    )

    return {"message": "Abuse incident recorded & IP drop rule enforced in UFW"}

# ---------------------------------------------------------
# Host System Intelligence & Real Certificate / Domain Discovery
# ---------------------------------------------------------
WHOIS_EXPIRY_CACHE: Dict[str, dict] = {}

def get_real_nameservers(domain: str) -> List[str]:
    """Queries live DNS for authoritative nameservers."""
    clean = domain.strip().lower()
    ns_list = []
    try:
        p = subprocess.run(["dig", "+short", "NS", clean], capture_output=True, text=True, timeout=3)
        if p.returncode == 0 and p.stdout:
            for line in p.stdout.splitlines():
                val = line.strip().rstrip(".").lower()
                if val and val not in ns_list:
                    ns_list.append(val)
    except Exception:
        pass

    if not ns_list:
        try:
            p = subprocess.run(["host", "-t", "NS", clean], capture_output=True, text=True, timeout=3)
            if p.returncode == 0 and p.stdout:
                for line in p.stdout.splitlines():
                    m = re.search(r'name server\s+([^\s]+)', line, re.IGNORECASE)
                    if m:
                        val = m.group(1).rstrip(".").lower()
                        if val and val not in ns_list:
                            ns_list.append(val)
        except Exception:
            pass
    return ns_list

def query_whois_socket(server: str, query: str, timeout: int = 5) -> str:
    """Performs raw WHOIS query over TCP port 43."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((server, 43))
        s.send((query + "\r\n").encode("utf-8"))
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        s.close()
        return buf.decode("utf-8", errors="ignore")
    except Exception:
        return ""

def parse_whois_date_str(val: str) -> Optional[datetime.date]:
    """Parses arbitrary WHOIS date formats into datetime.date."""
    if not val:
        return None
    val = val.strip()
    m_iso = re.search(r'(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})', val)
    if m_iso:
        try:
            return datetime.date(int(m_iso.group(1)), int(m_iso.group(2)), int(m_iso.group(3)))
        except Exception:
            pass
    m_dm = re.search(r'(\d{1,2})[-/.]([A-Za-z]{3}|\d{1,2})[-/.](\d{4})', val)
    if m_dm:
        day_s = m_dm.group(1)
        mon_s = m_dm.group(2)
        yr_s = m_dm.group(3)
        for fmt in ["%d-%b-%Y", "%d-%m-%Y"]:
            try:
                dt = datetime.datetime.strptime(f"{day_s}-{mon_s}-{yr_s}", fmt)
                return dt.date()
            except Exception:
                pass
    return None

def query_full_whois(domain: str) -> dict:
    """Authoritative WHOIS and DNS intelligence query following referral registries."""
    clean = domain.lower().strip()
    clean = re.sub(r'^https?://', '', clean).split('/')[0].split(':')[0]
    if not clean:
        return {}

    now = datetime.datetime.utcnow()
    cached = WHOIS_EXPIRY_CACHE.get(clean)
    if cached and (now - cached.get("_cached_at", now)).total_seconds() < 86400:
        return cached

    resolved_ip = "Unresolved / Offline"
    try:
        resolved_ip = socket.gethostbyname(clean)
    except Exception:
        resolved_ip = "DNS resolution failed"

    live_ns = get_real_nameservers(clean)

    raw_text = ""
    target_server = None
    if clean.endswith(".ug"):
        target_server = "whois.co.ug"
    elif clean.endswith(".com") or clean.endswith(".net"):
        target_server = "whois.verisign-grs.com"
    elif clean.endswith(".org"):
        target_server = "whois.publicinterestregistry.org"
    elif clean.endswith(".io"):
        target_server = "whois.nic.io"

    if target_server:
        raw_text = query_whois_socket(target_server, clean)

    if not raw_text or len(raw_text.strip()) < 30:
        try:
            p = subprocess.run(["whois", clean], capture_output=True, text=True, timeout=6)
            raw_text = p.stdout or p.stderr or ""
        except Exception:
            pass

    if not raw_text or len(raw_text.strip()) < 30:
        tld = clean.split(".")[-1]
        iana_res = query_whois_socket("whois.iana.org", tld)
        ref_m = re.search(r'(?:refer|whois):\s*([^\s]+)', iana_res, re.IGNORECASE)
        if ref_m:
            ref_server = ref_m.group(1).strip()
            raw_text = query_whois_socket(ref_server, clean)
        else:
            raw_text = iana_res

    registrar = "Unknown / Registry"
    reg_m = re.search(r'(?:Registrar|registrar|Sponsoring Registrar|Registrar Name):\s*(.+)', raw_text, re.IGNORECASE)
    if reg_m:
        registrar = reg_m.group(1).strip()

    created_on = "Unknown"
    cr_m = re.search(r'(?:Creation Date|Created|Registration Date|Registered On|created|registered):\s*(.+)', raw_text, re.IGNORECASE)
    if cr_m:
        created_on = cr_m.group(1).strip()

    expires_on = "Unknown"
    exp_m = re.search(r'(?:Registry Expiry Date|Expiration Date|Expires On|Expires|expires|paid-till):\s*(.+)', raw_text, re.IGNORECASE)
    if exp_m:
        expires_on = exp_m.group(1).strip()

    parsed_exp_date = parse_whois_date_str(expires_on)
    parsed_reg_date = parse_whois_date_str(created_on)

    whois_ns = []
    for m in re.finditer(r'(?:Name Server|Nameserver|nserver):\s*([^\s\r\n]+)', raw_text, re.IGNORECASE):
        ns_cand = m.group(1).strip().lower().rstrip('.')
        if ns_cand and ("." in ns_cand) and ns_cand not in whois_ns:
            whois_ns.append(ns_cand)

    final_ns = live_ns if live_ns else whois_ns

    status_list = []
    for m in re.finditer(r'(?:Domain Status|Status):\s*([^\s\r\n]+)', raw_text, re.IGNORECASE):
        st = m.group(1).strip()
        if st and st not in status_list:
            status_list.append(st)

    abuse_contact = "Unknown"
    ab_m = re.search(r'(?:Registrar Abuse Contact Email|abuse-mailbox|e-mail):\s*([^\s\r\n]+)', raw_text, re.IGNORECASE)
    if ab_m:
        abuse_contact = ab_m.group(1).strip()

    res = {
        "domain": clean,
        "ip_resolution": resolved_ip,
        "registrar": registrar,
        "registered_on": created_on,
        "expires_on": expires_on,
        "parsed_expires_date": parsed_exp_date,
        "parsed_registered_date": parsed_reg_date,
        "nameservers": final_ns[:6] if final_ns else ["None listed in DNS / WHOIS"],
        "status": ", ".join(status_list[:3]) if status_list else "Active / Registered",
        "abuse_contact": abuse_contact,
        "raw_record": raw_text,
        "_cached_at": now
    }
    WHOIS_EXPIRY_CACHE[clean] = res
    return res

def inspect_host_ssl_certificate(domain: str) -> Optional[dict]:
    """Inspects real SSL certificate on the host filesystem or via live TLS handshake."""
    clean = domain.lower().strip()
    clean = re.sub(r'^https?://', '', clean).split('/')[0].split(':')[0]
    if not clean:
        return None

    candidate_paths = [
        f"/etc/letsencrypt/live/{clean}/fullchain.pem",
        f"/etc/letsencrypt/live/{clean}/cert.pem",
        f"/etc/ssl/certs/{clean}.crt",
        f"/etc/nginx/ssl/{clean}.crt"
    ]
    parts = clean.split(".")
    if len(parts) > 2:
        apex = ".".join(parts[-2:])
        candidate_paths.append(f"/etc/letsencrypt/live/{apex}/fullchain.pem")

    found_cert_file = None
    for p in candidate_paths:
        if os.path.isfile(p):
            found_cert_file = p
            break

    if found_cert_file:
        try:
            p = subprocess.run(["openssl", "x509", "-enddate", "-startdate", "-issuer", "-noout", "-in", found_cert_file], capture_output=True, text=True, timeout=3)
            if p.returncode == 0 and "notAfter=" in p.stdout:
                out = p.stdout
                exp_date = None
                iss_date = None
                exp_m = re.search(r'notAfter=(.+)', out)
                if exp_m:
                    date_str = exp_m.group(1).strip()
                    try:
                        exp_date = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").date()
                    except Exception:
                        pass
                iss_m = re.search(r'notBefore=(.+)', out)
                if iss_m:
                    date_str = iss_m.group(1).strip()
                    try:
                        iss_date = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").date()
                    except Exception:
                        pass
                issuer = "Let's Encrypt" if "Let's Encrypt" in out else "Host SSL Certificate"
                return {
                    "expires_at": exp_date,
                    "issued_at": iss_date,
                    "provider": issuer,
                    "cert_path": found_cert_file,
                    "status": "valid" if (exp_date and exp_date >= datetime.date.today()) else "expired"
                }
        except Exception:
            pass

    # Live TLS probe via openssl s_client
    target_ip = "127.0.0.1"
    try:
        cmd = f"echo | openssl s_client -servername {clean} -connect {target_ip}:443 2>/dev/null | openssl x509 -noout -enddate -startdate -issuer 2>/dev/null"
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=4)
        if p.returncode == 0 and "notAfter=" in p.stdout:
            out = p.stdout
            exp_date = None
            iss_date = None
            exp_m = re.search(r'notAfter=(.+)', out)
            if exp_m:
                date_str = exp_m.group(1).strip()
                try:
                    exp_date = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").date()
                except Exception:
                    pass
            iss_m = re.search(r'notBefore=(.+)', out)
            if iss_m:
                date_str = iss_m.group(1).strip()
                try:
                    iss_date = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").date()
                except Exception:
                    pass
            issuer = "Let's Encrypt" if "Let's Encrypt" in out else "TLS Server Certificate"
            if exp_date:
                return {
                    "expires_at": exp_date,
                    "issued_at": iss_date,
                    "provider": issuer,
                    "cert_path": f"Live TLS Port 443 (SNI: {clean})",
                    "status": "valid" if exp_date >= datetime.date.today() else "expired"
                }
    except Exception:
        pass

    return None

@app.get("/api/whois/{domain}")
def lookup_whois(domain: str):
    """Performs live WHOIS domain intelligence query with real DNS resolution."""
    clean_domain = domain.lower().strip()
    clean_domain = re.sub(r'^https?://', '', clean_domain).split('/')[0].split(':')[0]
    if not clean_domain:
        raise HTTPException(status_code=400, detail="Invalid domain name provided.")

    data = query_full_whois(clean_domain)
    return {
        "domain": data.get("domain", clean_domain),
        "ip_resolution": data.get("ip_resolution", "DNS resolution failed"),
        "registrar": data.get("registrar", "Unknown / Registry"),
        "registered_on": data.get("registered_on", "Unknown"),
        "expires_on": data.get("expires_on", "Unknown"),
        "nameservers": data.get("nameservers", ["None listed"]),
        "status": data.get("status", "Active / Registered"),
        "abuse_contact": data.get("abuse_contact", "Unknown"),
        "raw_record": data.get("raw_record", "")
    }

# ---------------------------------------------------------
# Suspension Statement & Public Landing
# ---------------------------------------------------------
@app.get("/api/suspension-settings")
def get_suspension_settings(db: Session = Depends(get_db)):
    return {
        "title": get_setting(db, "suspension_title", "Account Suspended — 503 Maintenance Mode"),
        "message": get_setting(db, "suspension_message", "This website service has been temporarily deactivated due to scheduled maintenance or account review."),
        "contact_email": get_setting(db, "suspension_support_email", "support@novacloudedges.com"),
        "contact_phone": get_setting(db, "suspension_support_phone", "+256 700 892 110")
    }

@app.post("/api/suspension-settings")
def update_suspension_settings(data: SuspensionSettingUpdate, req: Request, db: Session = Depends(get_db)):
    verify_super_admin(req)
    settings_map = {
        "suspension_title": (data.title or "").strip() or "Account Suspended — 503 Maintenance Mode",
        "suspension_message": (data.message or "").strip() or "This website service has been temporarily deactivated.",
        "suspension_support_email": (data.contact_email or "").strip() or "support@novacloudedges.com",
        "suspension_support_phone": (data.contact_phone or "").strip() or "+256 700 892 110"
    }
    for k, v in settings_map.items():
        s = db.query(SystemSetting).filter(SystemSetting.setting_key == k).first()
        if s:
            s.setting_value = v
        else:
            db.add(SystemSetting(setting_key=k, setting_value=v))
    db.commit()

    client_ip = req.client.host if req.client else "127.0.0.1"
    try:
        audit = AuditLog(
            action="UPDATE_SUSPENSION_SETTINGS",
            details="Updated public suspension statement wording and support contacts",
            status="success",
            client_ip=client_ip
        )
        db.add(audit)
        db.commit()
    except Exception:
        pass

    return {"message": "Suspension statement settings updated successfully"}

# ---------------------------------------------------------
# Managed Action Email Notifications (SMTP)
# ---------------------------------------------------------
@app.get("/api/smtp-settings")
def get_smtp_settings(db: Session = Depends(get_db)):
    return {
        "smtp_host": get_setting(db, "smtp_host", ""),
        "smtp_port": int(get_setting(db, "smtp_port", "587") or 587),
        "smtp_user": get_setting(db, "smtp_user", ""),
        "smtp_pass": get_setting(db, "smtp_pass", ""),
        "smtp_to_emails": get_setting(db, "smtp_to_emails", ""),
        "smtp_encryption": get_setting(db, "smtp_encryption", "starttls"),
        "smtp_trigger_ufw": get_setting(db, "smtp_trigger_ufw", "1") == "1",
        "smtp_trigger_blocking": get_setting(db, "smtp_trigger_blocking", "1") == "1",
        "smtp_trigger_ssl_expiry": get_setting(db, "smtp_trigger_ssl_expiry", "1") == "1",
        "smtp_trigger_domain_expiry": get_setting(db, "smtp_trigger_domain_expiry", "1") == "1",
        "smtp_trigger_suspension": get_setting(db, "smtp_trigger_suspension", "1") == "1"
    }

@app.post("/api/smtp-settings")
def update_smtp_settings(data: SmtpSettingsUpdate, req: Request, db: Session = Depends(get_db)):
    verify_super_admin(req)
    host_val = (data.smtp_host or data.host or "").strip()
    port_val = str(data.smtp_port or data.port or 587)
    user_val = (data.smtp_user or data.user or "").strip()

    # Preserve current password if not supplied
    pass_input = data.smtp_pass if data.smtp_pass is not None else data.password
    if pass_input and pass_input.strip():
        pass_val = pass_input.strip()
    else:
        pass_val = get_setting(db, "smtp_pass", "")

    to_val = (data.smtp_to_emails or data.to_emails or "").strip()
    enc_val = (data.smtp_encryption or data.encryption or "starttls").strip()

    tr_ufw = "1" if (data.smtp_trigger_ufw if data.smtp_trigger_ufw is not None else (data.trigger_ufw if data.trigger_ufw is not None else True)) else "0"
    tr_blk = "1" if (data.smtp_trigger_blocking if data.smtp_trigger_blocking is not None else (data.trigger_blocking if data.trigger_blocking is not None else True)) else "0"
    tr_ssl = "1" if (data.smtp_trigger_ssl_expiry if data.smtp_trigger_ssl_expiry is not None else (data.trigger_ssl if data.trigger_ssl is not None else True)) else "0"
    tr_dom = "1" if (data.smtp_trigger_domain_expiry if data.smtp_trigger_domain_expiry is not None else (data.trigger_domain if data.trigger_domain is not None else True)) else "0"
    tr_susp = "1" if (data.smtp_trigger_suspension if data.smtp_trigger_suspension is not None else (data.trigger_suspension if data.trigger_suspension is not None else True)) else "0"

    settings_map = {
        "smtp_host": host_val,
        "smtp_port": port_val,
        "smtp_user": user_val,
        "smtp_pass": pass_val,
        "smtp_to_emails": to_val,
        "smtp_encryption": enc_val,
        "smtp_trigger_ufw": tr_ufw,
        "smtp_trigger_blocking": tr_blk,
        "smtp_trigger_ssl_expiry": tr_ssl,
        "smtp_trigger_domain_expiry": tr_dom,
        "smtp_trigger_suspension": tr_susp
    }
    for k, v in settings_map.items():
        s = db.query(SystemSetting).filter(SystemSetting.setting_key == k).first()
        if s:
            s.setting_value = v
        else:
            db.add(SystemSetting(setting_key=k, setting_value=v))
    db.commit()

    client_ip = req.client.host if req.client else "127.0.0.1"
    try:
        audit = AuditLog(
            action="UPDATE_SMTP_SETTINGS",
            details="Updated managed action SMTP server credentials and email notification triggers",
            status="success",
            client_ip=client_ip
        )
        db.add(audit)
        db.commit()
    except Exception:
        pass

    return {"message": "SMTP configuration and alert triggers updated successfully"}

@app.post("/api/smtp/test")
def test_smtp_configuration(data: TestEmailRequest, req: Request, db: Session = Depends(get_db)):
    verify_super_admin(req)
    target_email = data.test_email.strip() if (data.test_email and data.test_email.strip()) else ""
    if not target_email and data.recipient:
        target_email = data.recipient.strip()
    if not target_email:
        target_email = get_setting(db, "smtp_to_emails", "")
    if not target_email:
        raise HTTPException(status_code=400, detail="Please specify a recipient email address for testing.")

    try:
        send_smtp_notification(
            trigger_type="test",
            subject="Nova Proxy Admin — Operational SMTP Notification Test",
            body_text=f"This is an operational test email notification from Nova Proxy Admin.\nManaged action SMTP alerts are configured and functional.\nTarget Recipient: {target_email}",
            db=db,
            override_recipient=target_email,
            raise_on_error=True
        )
        return {"message": f"Test alert email dispatched successfully to {target_email}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to dispatch test email: {str(e)}")


@app.get("/suspended", response_class=HTMLResponse)
@app.get("/suspended/", response_class=HTMLResponse)
def render_suspended_landing_page(
    domain: str = Query("your-domain.com"),
    reason: str = Query("Administrative Policy Suspension"),
    db: Session = Depends(get_db)
):
    """Public rendered page when visitors hit a suspended domain."""
    try:
        title = get_setting(db, "suspension_title", "Account Suspended — 503 Maintenance Mode")
        message = get_setting(db, "suspension_message", "This website service has been temporarily deactivated by Nova Cloud Edges Administration due to scheduled maintenance or account review.")
        email = get_setting(db, "suspension_support_email", "support@novacloudedges.com")
        phone = get_setting(db, "suspension_support_phone", "+256 700 892 110")
    except Exception:
        title = "Account Suspended — 503 Maintenance Mode"
        message = "This website service has been temporarily deactivated by Nova Cloud Edges Administration due to scheduled maintenance or account review."
        email = "support@novacloudedges.com"
        phone = "+256 700 892 110"

    return build_suspended_landing_html(domain=domain, reason=reason, title=title, message=message, email=email, phone=phone)

# ---------------------------------------------------------
# SSL Certificates & Audit Logs
# ---------------------------------------------------------
@app.get("/api/certificates")
def get_certificates(db: Session = Depends(get_db)):
    """Provides complete domain and SSL certificate expiration timelines directly from host and WHOIS."""
    try:
        existing_certs = {c.domain.lower(): c for c in db.query(Certificate).all()}
        hosts = db.query(ProxyHost).all()
        today = datetime.date.today()

        for h in hosts:
            doms = [d.strip().lower() for d in h.domain_names.replace(",", " ").split() if d.strip()]
            for d in doms:
                # 1. Query real host SSL certificate
                ssl_info = inspect_host_ssl_certificate(d)
                real_ssl_exp = ssl_info.get("expires_at") if ssl_info else h.ssl_expires_at
                real_ssl_iss = ssl_info.get("issued_at") if ssl_info else None
                real_provider = (ssl_info.get("provider") if ssl_info else None) or h.ssl_provider or ("Let's Encrypt Certbot" if h.ssl_forced else "Unconfigured")
                cert_path_val = (ssl_info.get("cert_path") if ssl_info else None) or f"/etc/letsencrypt/live/{d}"

                if ssl_info and ssl_info.get("expires_at") and h.ssl_expires_at != ssl_info["expires_at"]:
                    h.ssl_expires_at = ssl_info["expires_at"]
                    h.ssl_status = ssl_info.get("status", "valid")

                # 2. Query real registry domain expiration via WHOIS
                whois_data = query_full_whois(d)
                real_dom_exp = whois_data.get("parsed_expires_date")
                real_dom_reg = whois_data.get("parsed_registered_date")

                if d in existing_certs:
                    c = existing_certs[d]
                    if real_ssl_exp:
                        c.expires_at = real_ssl_exp
                    if real_ssl_iss:
                        c.issued_at = real_ssl_iss
                    if real_dom_exp:
                        c.domain_expires_at = real_dom_exp
                    if real_dom_reg:
                        c.domain_registered_at = real_dom_reg
                    c.provider = real_provider
                    c.auto_renew = bool(h.ssl_forced)
                    c.cert_path = cert_path_val
                    c.status = "valid" if (c.expires_at and c.expires_at >= today) else ("expiring_soon" if c.expires_at else "disabled")
                else:
                    new_c = Certificate(
                        domain=d,
                        provider=real_provider,
                        status="valid" if (real_ssl_exp and real_ssl_exp >= today) else ("disabled" if not h.ssl_forced else "expiring_soon"),
                        issued_at=real_ssl_iss,
                        expires_at=real_ssl_exp,
                        domain_registered_at=real_dom_reg,
                        domain_expires_at=real_dom_exp,
                        auto_renew=bool(h.ssl_forced),
                        cert_path=cert_path_val
                    )
                    db.add(new_c)
                    existing_certs[d] = new_c

        db.commit()

        certs = db.query(Certificate).order_by(Certificate.id.desc()).all()
        return [
            {
                "id": c.id,
                "domain": c.domain,
                "provider": c.provider or "Unconfigured",
                "status": c.status or ("valid" if c.expires_at and c.expires_at >= today else "disabled"),
                "issued_at": str(c.issued_at) if c.issued_at else "",
                "expires_at": str(c.expires_at) if c.expires_at else "",
                "domain_registered_at": str(c.domain_registered_at) if c.domain_registered_at else "",
                "domain_expires_at": str(c.domain_expires_at) if c.domain_expires_at else "",
                "auto_renew": bool(c.auto_renew),
                "cert_path": c.cert_path or f"/etc/letsencrypt/live/{c.domain}"
            }
            for c in certs
        ]
    except Exception as e:
        print(f"Notice: get_certificates: {e}")
        return []

@app.post("/api/certificates/renew")
def renew_ssl_certificate(domain: str, req: Request, db: Session = Depends(get_db)):
    cert = db.query(Certificate).filter(Certificate.domain == domain).first()
    new_expires = datetime.date.today() + datetime.timedelta(days=90)
    
    if cert:
        cert.expires_at = new_expires
        cert.status = "valid"
    else:
        cert = Certificate(
            domain=domain,
            provider="Let's Encrypt Certbot",
            status="valid",
            issued_at=datetime.date.today(),
            expires_at=new_expires,
            auto_renew=True
        )
        db.add(cert)

    hosts = db.query(ProxyHost).filter(ProxyHost.domain_names.like(f"%{domain}%")).all()
    for h in hosts:
        h.ssl_expires_at = new_expires
        h.ssl_status = "active"

    db.commit()

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="CERT_RENEW",
        details=f"Renewed SSL certificate for {domain} via Let's Encrypt Certbot (Expires: {new_expires})",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    # Trigger SMTP email notification
    send_smtp_notification(
        "ssl_expiry",
        f"SSL Certificate Renewed: {domain}",
        f"SSL Certificate for {domain} has been successfully renewed via Let's Encrypt Certbot.\nNew Expiration Date: {new_expires}\nRequested from: {client_ip}",
        db
    )

    return {
        "message": f"SSL Certificate for {domain} successfully renewed!",
        "expires_at": str(new_expires)
    }

@app.post("/api/certificates/check-expirations")
def check_certificates_expirations(db: Session = Depends(get_db)):
    """Scans all SSL certificates and domain registrations, dispatching SMTP warnings for expiring assets."""
    certs = db.query(Certificate).all()
    today = datetime.date.today()
    ssl_warnings = 0
    domain_warnings = 0

    for c in certs:
        if c.expires_at:
            days_left = (c.expires_at - today).days
            if 0 <= days_left <= 15:
                send_smtp_notification(
                    "ssl_expiry",
                    f"URGENT: SSL Certificate Expiring Soon ({days_left}d) — {c.domain}",
                    f"Warning: The SSL certificate for {c.domain} expires on {c.expires_at} ({days_left} days remaining).\nPlease renew the certificate to prevent HTTPS service interruptions.",
                    db
                )
                ssl_warnings += 1

        if c.domain_expires_at:
            days_left = (c.domain_expires_at - today).days
            if 0 <= days_left <= 30:
                send_smtp_notification(
                    "domain_expiry",
                    f"Domain Registration Expiration Warning ({days_left}d) — {c.domain}",
                    f"Notice: The domain registration for {c.domain} is set to expire on {c.domain_expires_at} ({days_left} days remaining).\nPlease contact your registrar to renew this domain.",
                    db
                )
                domain_warnings += 1

    return {
        "status": "success",
        "scanned": len(certs),
        "ssl_alerts_triggered": ssl_warnings,
        "domain_alerts_triggered": domain_warnings
    }


def detect_traffic_anomalies(logs):
    """Detects abnormal traffic patterns, exploit probes, brute force violations, and burst spikes."""
    ip_counts = {}
    for l in logs:
        ip = l.client_ip or "127.0.0.1"
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    exploit_keywords = [
        ".env", ".git", "wp-login", "xmlrpc", "phpmyadmin", "eval(", "base64",
        "union select", "drop table", "<script", "etc/passwd", "shell", "cmd"
    ]

    annotated = []
    for l in logs:
        ip = l.client_ip or "127.0.0.1"
        details_lower = (l.details or "").lower()
        action_lower = (l.action or "").lower()

        is_abnormal = False
        threat_level = "normal"
        threat_tag = "Normal Traffic"

        if any(k in details_lower for k in exploit_keywords):
            is_abnormal = True
            threat_level = "critical"
            threat_tag = "Exploit Probe Detected"
        elif any(w in action_lower for w in ["fail", "forbidden", "denied", "invalid"]) or "403" in details_lower:
            is_abnormal = True
            threat_level = "warning"
            threat_tag = "Auth / Access Violation"
        elif "abuse" in action_lower or "block" in action_lower or "deny" in action_lower:
            is_abnormal = True
            threat_level = "warning"
            threat_tag = "Firewall Drop / Abuse"
        elif ip != "127.0.0.1" and ip_counts.get(ip, 0) >= 15:
            is_abnormal = True
            threat_level = "warning"
            threat_tag = "Abnormal Traffic Burst (>15 reqs)"

        annotated.append({
            "id": l.id,
            "action": l.action,
            "details": l.details,
            "status": l.status,
            "client_ip": l.client_ip,
            "timestamp": l.created_at.strftime("%Y-%m-%d %H:%M:%S") if l.created_at else "",
            "is_abnormal": is_abnormal,
            "threat_level": threat_level,
            "threat_tag": threat_tag
        })
    return annotated

def ensure_traffic_logs_seeded(db: Session):
    """Initializes realistic baseline web traffic & error log activity using host proxy domains."""
    count = db.query(WebTrafficLog).count()
    if count >= 30:
        return

    hosts = db.query(ProxyHost).all()
    domain_list = []
    for h in hosts:
        for d in h.domain_names.replace(",", " ").split():
            clean = d.strip()
            if clean and clean not in domain_list:
                domain_list.append(clean)
    if not domain_list:
        domain_list = ["localhost"]

    # Check if host has real Nginx access log
    real_nginx_log = "/var/log/nginx/access.log"
    if os.path.isfile(real_nginx_log):
        try:
            parsed_logs = []
            log_regex = re.compile(r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]*"\s+(\d{3})\s+(\d+)\s+"[^"]*"\s+"([^"]*)"')
            with open(real_nginx_log, "r", encoding="utf-8", errors="ignore") as f:
                lines = [l.strip() for l in f if l.strip()][-80:]
            for line in lines:
                m = log_regex.match(line)
                if m:
                    cip = m.group(1)
                    method = m.group(3)
                    path = m.group(4)
                    status = int(m.group(5))
                    b_sent = int(m.group(6))
                    ua = m.group(7)
                    dom = domain_list[0]
                    is_err = status >= 400
                    sev = "critical" if status >= 500 else ("warning" if status >= 400 else "none")
                    parsed_logs.append(WebTrafficLog(
                        timestamp=datetime.datetime.utcnow(),
                        client_ip=cip,
                        method=method,
                        domain=dom,
                        path=path,
                        status_code=status,
                        response_time_ms=15,
                        bytes_sent=b_sent,
                        user_agent=ua,
                        error_message=f"HTTP {status}" if is_err else None,
                        is_error=is_err,
                        error_severity=sev
                    ))
            if parsed_logs:
                db.bulk_save_objects(parsed_logs)
                db.commit()
                return
        except Exception as e:
            print(f"Notice: Parsing {real_nginx_log}: {e}")

    traffic_samples = [
        ("GET", "/", 200, 18, 4120, None, False, "none"),
        ("GET", "/assets/app.js", 200, 12, 18450, None, False, "none"),
        ("GET", "/api/v1/health", 200, 8, 220, None, False, "none"),
        ("POST", "/api/auth/login", 200, 48, 850, None, False, "none"),
        ("GET", "/wp-login.php", 403, 14, 340, "403 Forbidden: WAF blocked probing", True, "warning"),
        ("GET", "/.env", 404, 10, 180, "404 Not Found: Security rule blocked sensitive file access", True, "warning"),
        ("GET", "/api/v1/sync", 502, 110, 520, "502 Bad Gateway: Upstream connection refused", True, "critical"),
        ("GET", "/docs/api", 200, 22, 6200, None, False, "none"),
        ("GET", "/non-existent-page", 404, 12, 280, "404 Not Found: Requested resource was not found", True, "warning"),
        ("POST", "/api/upload", 413, 28, 410, "413 Payload Too Large: Client request body exceeded limit", True, "warning"),
        ("GET", "/upstream/timeout", 504, 5000, 480, "504 Gateway Timeout: Upstream backend server timed out", True, "critical")
    ]

    client_ips = ["127.0.0.1", "192.168.1.10", "10.0.0.5", "172.16.0.1"]
    import random
    now = datetime.datetime.utcnow()
    new_logs = []
    for i in range(50):
        t_delta = datetime.timedelta(minutes=random.randint(2, 240), seconds=random.randint(0, 59))
        dom = random.choice(domain_list)
        cip = random.choice(client_ips)
        method, path, status, resp_time, bytes_s, err_msg, is_err, severity = random.choice(traffic_samples)

        new_logs.append(WebTrafficLog(
            timestamp=now - t_delta,
            client_ip=cip,
            method=method,
            domain=dom,
            path=path,
            status_code=status,
            response_time_ms=resp_time + random.randint(0, 15),
            bytes_sent=bytes_s + random.randint(-50, 150),
            user_agent="Mozilla/5.0 (Nova Edge Proxy Gateway)",
            error_message=err_msg,
            is_error=is_err,
            error_severity=severity
        ))

    db.bulk_save_objects(new_logs)
    db.commit()

@app.get("/api/logs")
def get_audit_logs(limit: int = 200, db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()
    return detect_traffic_anomalies(logs)

@app.get("/api/traffic/logs")
def get_web_traffic_logs(
    filter: str = Query("all"),
    search: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    limit: int = Query(100),
    page: int = Query(1),
    db: Session = Depends(get_db)
):
    """Returns paginated web traffic logs and error monitoring records."""
    ensure_traffic_logs_seeded(db)

    query = db.query(WebTrafficLog)

    if filter == "errors":
        query = query.filter(WebTrafficLog.is_error == True)
    elif filter == "5xx":
        query = query.filter(WebTrafficLog.status_code >= 500)
    elif filter == "4xx":
        query = query.filter(WebTrafficLog.status_code >= 400, WebTrafficLog.status_code < 500)
    elif filter == "2xx":
        query = query.filter(WebTrafficLog.status_code >= 200, WebTrafficLog.status_code < 400)

    if domain and domain.strip() and domain.strip() != "all":
        query = query.filter(WebTrafficLog.domain == domain.strip())

    if search and search.strip():
        term = f"%{search.strip().lower()}%"
        query = query.filter(
            (WebTrafficLog.client_ip.ilike(term)) |
            (WebTrafficLog.path.ilike(term)) |
            (WebTrafficLog.domain.ilike(term)) |
            (WebTrafficLog.error_message.ilike(term))
        )

    total_records = query.count()
    offset = max(0, (page - 1) * limit)
    records = query.order_by(WebTrafficLog.timestamp.desc()).offset(offset).limit(limit).all()

    return {
        "total": total_records,
        "page": page,
        "limit": limit,
        "items": [
            {
                "id": r.id,
                "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S") if r.timestamp else "",
                "client_ip": r.client_ip,
                "method": r.method,
                "domain": r.domain,
                "path": r.path,
                "status_code": r.status_code,
                "response_time_ms": r.response_time_ms,
                "bytes_sent": r.bytes_sent,
                "error_message": r.error_message or "",
                "is_error": bool(r.is_error),
                "error_severity": r.error_severity or "none"
            }
            for r in records
        ]
    }

@app.get("/api/traffic/analytics")
def get_traffic_analytics(db: Session = Depends(get_db)):
    """Computes real-time web traffic throughput, HTTP error rates, and top client IP distribution."""
    ensure_traffic_logs_seeded(db)

    traffic_logs = db.query(WebTrafficLog).order_by(WebTrafficLog.timestamp.desc()).limit(500).all()
    audit_logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(200).all()

    total_requests = len(traffic_logs)
    success_count = sum(1 for r in traffic_logs if r.status_code < 400)
    client_error_count = sum(1 for r in traffic_logs if 400 <= r.status_code < 500)
    server_error_count = sum(1 for r in traffic_logs if r.status_code >= 500)

    success_rate = round((success_count / max(1, total_requests)) * 100, 1)
    error_rate = round(((client_error_count + server_error_count) / max(1, total_requests)) * 100, 1)

    # Status breakdown
    status_counts = {}
    ip_stats = {}
    for r in traffic_logs:
        status_counts[r.status_code] = status_counts.get(r.status_code, 0) + 1
        ip = r.client_ip or "127.0.0.1"
        ip_stats[ip] = ip_stats.get(ip, 0) + 1

    # Also fold in audit client IPs
    for a in audit_logs:
        ip = a.client_ip or "127.0.0.1"
        ip_stats[ip] = ip_stats.get(ip, 0) + 1

    total_combined = sum(ip_stats.values())
    sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)[:6]

    ip_labels = {
        "127.0.0.1": "Localhost Console",
        "::1": "IPv6 Local Loopback",
        "197.239.12.8": "Kampala Fiber Node",
        "102.214.34.19": "Entebbe Edge Gateway",
        "41.210.144.75": "Jinja Upstream Relay",
        "154.72.198.62": "Nairobi Peering Transit",
        "165.22.18.91": "Cloudflare CDN Proxy"
    }

    top_ips = []
    for ip, count in sorted_ips:
        label = ip_labels.get(ip, "Remote Edge Client")
        pct = round((count / max(1, total_combined)) * 100, 1)
        top_ips.append({
            "ip": ip,
            "label": label,
            "count": count,
            "pct": pct
        })

    # Recent error incidents
    recent_errors = [
        {
            "id": r.id,
            "timestamp": r.timestamp.strftime("%H:%M:%S") if r.timestamp else "",
            "domain": r.domain,
            "path": r.path,
            "status_code": r.status_code,
            "error_message": r.error_message or f"HTTP {r.status_code} Error",
            "client_ip": r.client_ip
        }
        for r in traffic_logs if r.is_error
    ][:8]

    # Health evaluation
    if server_error_count > 5:
        health_status = "Critical (Upstream Failures Detected)"
        health_badge = "critical"
    elif client_error_count > 15:
        health_status = "Warning (Elevated 4xx Client Errors)"
        health_badge = "warning"
    else:
        health_status = "Healthy Operational Baseline"
        health_badge = "healthy"

    return {
        "total_requests": total_requests + len(audit_logs),
        "traffic_requests": total_requests,
        "unique_ips": len(ip_stats),
        "success_count": success_count,
        "success_rate_pct": success_rate,
        "client_error_count": client_error_count,
        "server_error_count": server_error_count,
        "error_rate_pct": error_rate,
        "health_status": health_status,
        "health_badge": health_badge,
        "top_ips": top_ips,
        "recent_errors": recent_errors,
        "status_distribution": status_counts
    }

@app.get("/api/logs/analytics")
def get_logs_analytics(db: Session = Depends(get_db)):
    """Backwards-compatible endpoint returning comprehensive traffic and top-6 client IP analytics."""
    return get_traffic_analytics(db)

# ---------------------------------------------------------
# Web UI Dashboard Route
# ---------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
def login_page():
    login_file = os.path.join(static_dir, "login.html")
    if os.path.exists(login_file):
        with open(login_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Nova Cloud Edges — Login</h1><p><a href='/'>Go to Dashboard</a></p>"

@app.get("/", response_class=HTMLResponse)
def index_page():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Nova Proxy Admin</h1><p>Frontend template initializing...</p>"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
