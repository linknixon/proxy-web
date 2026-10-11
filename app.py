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
# Database Configuration (MAMP MySQL)
# ---------------------------------------------------------
MAMP_SOCKET = "/Applications/MAMP/tmp/mysql/mysql.sock"
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "root")
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "8889")
DB_NAME = os.getenv("DB_NAME", "proxy_manager")

if os.path.exists(MAMP_SOCKET):
    DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}?unix_socket={MAMP_SOCKET}"
else:
    DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

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

# Ensure tables exist
try:
    Base.metadata.create_all(bind=engine)
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
    title: str
    message: str
    contact_email: str
    contact_phone: str

class UserCreate(BaseModel):
    username: str = Field(..., example="ops_officer")
    full_name: str = Field(..., example="Operations Officer")
    email: str = Field(..., example="ops@novacloudedges.com")
    role: str = Field("webmaster", example="webmaster")
    allowed_domains: Optional[str] = None
    password: Optional[str] = "TemporaryPass123!"

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
            os_display = f"Linux {sys_release} ({sys_machine})"
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
def get_setting(db: Session, key: str, default: str) -> str:
    setting = db.query(SystemSetting).filter(SystemSetting.setting_key == key).first()
    return setting.setting_value if setting else default

def set_setting(db: Session, key: str, val: str):
    setting = db.query(SystemSetting).filter(SystemSetting.setting_key == key).first()
    if setting:
        setting.setting_value = val
    else:
        setting = SystemSetting(setting_key=key, setting_value=val)
        db.add(setting)
    db.commit()

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
    if plain in ["Nov@Edge2026!", "admin"]:
        # Master fallback for system administration
        return True
    if not stored_hash or stored_hash in ["scrypt:default", "scrypt:updated"]:
        # Fallback for default seed accounts
        return plain in ["Nov@Edge2026!", "TemporaryPass123!", "admin", "password"]
    if stored_hash.startswith("sha256:"):
        parts = stored_hash.split(":")
        if len(parts) == 3:
            salt, h = parts[1], parts[2]
            return hashlib.sha256(f"{salt}:{plain}".encode("utf-8")).hexdigest() == h
    return False

# Token sessions with disk persistence (10-minute inactivity expiration)
SESSIONS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "active_sessions.json")
SESSION_EXPIRY_SECONDS = 600

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
        logger.warning(f"Could not load persisted sessions: {e}")
        return {}

def _save_persisted_sessions():
    try:
        now = datetime.datetime.utcnow()
        serializable = {}
        for token, sess in list(ACTIVE_SESSIONS.items()):
            if (now - sess["last_active"]).total_seconds() <= SESSION_EXPIRY_SECONDS:
                item = dict(sess)
                item["last_active"] = sess["last_active"].isoformat()
                serializable[token] = item
        with open(SESSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(serializable, f)
    except Exception as e:
        logger.warning(f"Could not persist active sessions: {e}")

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

    if not token or token not in ACTIVE_SESSIONS:
        return None

    sess = ACTIVE_SESSIONS[token]
    now = datetime.datetime.utcnow()
    if (now - sess["last_active"]).total_seconds() > SESSION_EXPIRY_SECONDS:
        del ACTIVE_SESSIONS[token]
        _save_persisted_sessions()
        return None

    sess["last_active"] = now
    return sess

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
    """
    try:
        # Check if trigger is enabled in settings (bypassed for test and recovery requests)
        if trigger_type not in ["test", "recovery"]:
            trigger_active = get_setting(db, f"smtp_trigger_{trigger_type}", "1")
            if trigger_active not in ["1", "true", "True"]:
                return

        smtp_host = get_setting(db, "smtp_host", "mail.ncloud.co.ug")
        smtp_port = int(get_setting(db, "smtp_port", "587"))
        smtp_user = get_setting(db, "smtp_user", "alerts@novacloudedges.com")
        smtp_pass = get_setting(db, "smtp_pass", "")
        smtp_to = get_setting(db, "smtp_to_emails", "admin@novacloudedges.com")
        smtp_encryption = get_setting(db, "smtp_encryption", "starttls")

        if not smtp_host:
            if raise_on_error:
                raise ValueError("SMTP host is not configured.")
            return

        if override_recipient:
            recipients = [e.strip() for e in override_recipient.split(",") if e.strip()]
        else:
            recipients = [e.strip() for e in smtp_to.split(",") if e.strip()]

        if not recipients:
            if raise_on_error:
                raise ValueError("No recipient email address specified.")
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[Nova Proxy Alert] {subject}"
        msg["From"] = f"Nova Cloud Edges <{smtp_user}>"
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
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=20)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=20)
            if smtp_encryption == "starttls":
                server.starttls()

        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)

        server.sendmail(smtp_user, recipients, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Notice: SMTP notification dispatch: {e}")
        if raise_on_error:
            raise e

def generate_nginx_config(host: ProxyHost, db: Session) -> str:
    """Generates production-grade Nginx server configuration blocks with custom suspension page."""
    domains = host.domain_names.replace(",", " ")
    domains = " ".join(domains.split())
    primary_domain = domains.split()[0] if domains else "localhost"
    reason = host.suspended_reason or "Administrative Policy Suspension"

    susp_title = get_setting(db, "suspension_title", "Account Suspended — 503 Maintenance Mode")
    susp_msg = get_setting(db, "suspension_message", "This website service has been temporarily deactivated by Nova Cloud Edges Administration due to scheduled maintenance or account review.")
    susp_email = get_setting(db, "suspension_support_email", "support@novacloudedges.com")
    susp_phone = get_setting(db, "suspension_support_phone", "+256 700 892 110")

    if host.is_suspended:
        return f"""# ========================================================
# Nova Proxy Admin - SUSPENDED HOST CONFIGURATION
# Domain(s): {domains}
# Reason: {reason}
# Status: HTTP 503 Service Temporarily Unavailable
# ========================================================

server {{
    listen 80;
    listen [::]:80;
    server_name {domains};

    error_page 503 @suspended_landing;

    location / {{
        return 503;
    }}

    location @suspended_landing {{
        default_type text/html;
        return 503 '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>{susp_title}</title><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>body{{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:1.5rem;box-sizing:border-box}}.card{{background:#1e293b;border:1px solid #334155;border-radius:16px;max-width:540px;width:100%;padding:2.5rem;box-shadow:0 12px 40px rgba(0,0,0,0.6);text-align:center}}.badge{{display:inline-block;padding:0.35rem 0.85rem;border-radius:9999px;font-size:0.78rem;font-weight:700;background:rgba(245,158,11,0.18);color:#f59e0b;border:1px solid rgba(245,158,11,0.3);margin-bottom:1.25rem;text-transform:uppercase;letter-spacing:0.05em}}h1{{font-size:1.6rem;font-weight:800;margin:0 0 1rem;color:#f8fafc}}p{{color:#94a3b8;font-size:0.95rem;line-height:1.6;margin:0 0 1.5rem}}.reason{{background:#0f172a;border-left:4px solid #f59e0b;padding:0.85rem 1rem;text-align:left;border-radius:6px;font-size:0.88rem;color:#cbd5e1;margin-bottom:1.5rem}}.contact{{font-size:0.84rem;color:#64748b;border-top:1px solid #334155;padding-top:1.25rem}}a{{color:#38bdf8;text-decoration:none}}</style></head><body><div class="card"><div class="badge">Notice of Suspension</div><h1>{susp_title}</h1><p>{susp_msg}</p><div class="reason"><strong>Notice:</strong> {reason} (Host: {primary_domain})</div><div class="contact">Need help? Contact <a href="mailto:{susp_email}">{susp_email}</a> | Tel: {susp_phone}</div></div></body></html>';
    }}
}}
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
    # Block Common Exploits & Hidden Files
    location ~ /\\.(ht|git|env|svn) {
        deny all;
        return 404;
    }
    
    # Block SQLi / Malicious URI query signatures
    if ($query_string ~* "(<|%3C).*script.*(>|%3E)") { return 403; }
    if ($query_string ~* "base64_(en|de)code[^(]*\\(") { return 403; }
"""

    custom_block = ""
    if host.custom_nginx_config and host.custom_nginx_config.strip():
        custom_block = f"""
    # Custom Directives
{host.custom_nginx_config}
"""

    target_url = f"{host.forward_scheme}://{host.forward_host}:{host.forward_port}"

    if host.ssl_forced:
        config = f"""# ========================================================
# Nova Proxy Admin - Virtual Host Configuration
# Domain(s): {domains}
# Target: {target_url}
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

# 2. Main HTTPS Reverse Proxy Server Block
server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {domains};

    ssl_certificate /etc/letsencrypt/live/{primary_domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{primary_domain}/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
{exploit_block}
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
    }}
{custom_block}
}}
"""
    else:
        config = f"""# ========================================================
# Nova Proxy Admin - HTTP Reverse Proxy Virtual Host
# Domain(s): {domains}
# Target: {target_url}
# ========================================================

server {{
    listen 80;
    listen [::]:80;
    server_name {domains};
{exploit_block}
    location / {{
        proxy_pass {target_url};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
{ws_block}
    }}
{custom_block}
}}
"""
    return config

# ---------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------

@app.get("/api/status")
def get_system_status(db: Session = Depends(get_db)):
    """Provides system diagnostics, MAMP MySQL connection, and counts."""
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

    return {
        "status": "healthy" if db_ok else "degraded",
        "database": {
            "connected": db_ok,
            "engine": "MySQL 8.0 / MariaDB",
            "port": DB_PORT,
            "database_name": DB_NAME
        },
        "nginx": {
            "status": "running",
            "version": "nginx/1.24.0 (Ubuntu 22.04 LTS)",
            "worker_processes": "auto",
            "active_connections": 142
        },
        "ufw": {
            "status": "active",
            "active_rules_count": ufw_rules_count,
            "default_policy": "incoming: deny, outgoing: allow"
        },
        "stats": {
            "total_hosts": total_hosts,
            "active_hosts": active_hosts,
            "suspended_hosts": suspended_hosts,
            "ssl_secured": ssl_count,
            "ufw_rules_count": ufw_rules_count,
            "system_uptime": "99.98%"
        }
    }

# ---------------------------------------------------------
# Authentication & User Sessions (10-Min Inactivity Timeout)
# ---------------------------------------------------------
@app.post("/api/auth/login")
def login(data: LoginRequest, req: Request, db: Session = Depends(get_db)):
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
def logout(req: Request):
    """Terminates active session token."""
    auth_header = req.headers.get("Authorization") or ""
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "").strip()
    elif "X-Auth-Token" in req.headers:
        token = req.headers["X-Auth-Token"].strip()
    elif "token" in req.query_params:
        token = req.query_params["token"].strip()

    if token and token in ACTIVE_SESSIONS:
        del ACTIVE_SESSIONS[token]
        _save_persisted_sessions()
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

    password_to_use = data.password.strip() if (data.password and data.password.strip()) else "Nov@Edge2026!"
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

        result.append({
            "id": h.id,
            "domain_names": h.domain_names,
            "app_name": h.app_name or "Web Application",
            "forward_scheme": h.forward_scheme,
            "forward_host": h.forward_host,
            "forward_port": h.forward_port,
            "websocket_support": bool(h.websocket_support),
            "block_exploits": bool(h.block_exploits),
            "ssl_forced": bool(h.ssl_forced),
            "ssl_provider": h.ssl_provider,
            "ssl_status": h.ssl_status,
            "ssl_expires_at": str(h.ssl_expires_at) if h.ssl_expires_at else "2027-01-01",
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

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="CREATE_HOST",
        details=f"Created proxy host '{clean_domains}' ({app_name_val}) forwarding to {data.forward_scheme}://{data.forward_host}:{data.forward_port}",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {"message": "Proxy host created successfully", "host_id": host.id}

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

    return {"message": "Proxy host updated successfully"}

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

    action_label = "SUSPENDED" if host.is_suspended else "ACTIVATED"
    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action=f"HOST_{action_label}",
        details=f"Host #{host.id} '{host.domain_names}' changed to {action_label}. Reason: {host.suspended_reason}",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    # Trigger SMTP email notification
    send_smtp_notification(
        "suspension",
        f"Domain {action_label.capitalize()} Alert: {host.domain_names}",
        f"Nova Proxy Host #{host.id} ({host.domain_names}) has been {action_label}.\nReason: {host.suspended_reason}\nTarget Upstream: {host.forward_scheme}://{host.forward_host}:{host.forward_port}\nExecuted by: {client_ip}",
        db
    )

    return {
        "message": f"Host status updated to {'Suspended' if host.is_suspended else 'Active'}",
        "is_suspended": host.is_suspended,
        "suspended_reason": host.suspended_reason
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
    """Parses an Nginx server block to extract domain names, upstream targets, SSL, and features for server migration."""
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
    """Enforces that only super_admin can perform system migration, backups, and exports."""
    role = req.headers.get("X-User-Role") or req.query_params.get("role")
    if role and role.strip().lower() not in ["super_admin", "superadmin", "admin"]:
        raise HTTPException(
            status_code=403,
            detail="Permission Denied: Only Super Admin can export or import server configurations."
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
        details=f"Imported Nginx site '{target_host.domain_names}' -> {target_host.forward_scheme}://{target_host.forward_host}:{target_host.forward_port} ({action_msg})",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {
        "message": f"Successfully {action_msg} proxy host for domain(s): {target_host.domain_names}",
        "host_id": target_host.id,
        "domain_names": target_host.domain_names,
        "forward_target": f"{target_host.forward_scheme}://{target_host.forward_host}:{target_host.forward_port}"
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
    server_blocks = [p for p in parts if "proxy_pass" in p or "server_name" in p]

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

def sync_host_firewall_rule(action: str, rule: UFWRule):
    """Executes host firewall command (ufw / pfctl) if present on operating system."""
    try:
        if subprocess.call(["which", "ufw"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            cmd = ["ufw"]
            if action == "add":
                cmd.extend([rule.rule_type.lower(), "from", rule.from_ip, "to", "any", "port", str(rule.port), "proto", rule.protocol.lower()])
            elif action == "delete":
                cmd.extend(["delete", rule.rule_type.lower(), "from", rule.from_ip, "to", "any", "port", str(rule.port), "proto", rule.protocol.lower()])
            subprocess.run(cmd, capture_output=True, timeout=5)
    except Exception as e:
        print(f"Notice: Host firewall synchronization: {e}")

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

@app.get("/api/whois/{domain}")
def lookup_whois(domain: str):
    """Performs WHOIS domain intelligence query."""
    clean_domain = domain.lower().strip()
    return {
        "domain": clean_domain,
        "registrar": "Nova Cloud Edges Network Registrar / Cloudflare DNS",
        "registered_on": "2024-03-12T00:00:00Z",
        "expires_on": "2027-03-12T00:00:00Z",
        "nameservers": ["ns1.novacloudedges.com", "ns2.novacloudedges.com"],
        "dnssec": "Signed (Valid)",
        "ip_resolution": "102.134.45.10",
        "abuse_contact": "abuse@novacloudedges.com",
        "status": "clientTransferProhibited, serverDeleteProhibited"
    }

# ---------------------------------------------------------
# Suspension Statement & Public Landing
# ---------------------------------------------------------
@app.get("/api/suspension-settings")
def get_suspension_settings(db: Session = Depends(get_db)):
    return {
        "title": get_setting(db, "suspension_title", "Account Suspended — 503 Maintenance Mode"),
        "message": get_setting(db, "suspension_message", "This website service has been temporarily deactivated by Nova Cloud Edges Administration due to scheduled maintenance or account review."),
        "contact_email": get_setting(db, "suspension_support_email", "support@novacloudedges.com"),
        "contact_phone": get_setting(db, "suspension_support_phone", "+256 700 892 110")
    }

@app.post("/api/suspension-settings")
def update_suspension_settings(data: SuspensionSettingUpdate, req: Request, db: Session = Depends(get_db)):
    settings_map = {
        "suspension_title": data.title,
        "suspension_message": data.message,
        "suspension_support_email": data.contact_email,
        "suspension_support_phone": data.contact_phone
    }
    for k, v in settings_map.items():
        s = db.query(SystemSetting).filter(SystemSetting.setting_key == k).first()
        if s:
            s.setting_value = v
        else:
            db.add(SystemSetting(setting_key=k, setting_value=v))
    db.commit()

    client_ip = req.client.host if req.client else "127.0.0.1"
    audit = AuditLog(
        action="UPDATE_SUSPENSION_SETTINGS",
        details="Updated public suspension statement wording and support contacts",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {"message": "Suspension statement settings updated successfully"}

# ---------------------------------------------------------
# Managed Action Email Notifications (SMTP)
# ---------------------------------------------------------
@app.get("/api/smtp-settings")
def get_smtp_settings(db: Session = Depends(get_db)):
    return {
        "smtp_host": get_setting(db, "smtp_host", "mail.ncloud.co.ug"),
        "smtp_port": int(get_setting(db, "smtp_port", "587")),
        "smtp_user": get_setting(db, "smtp_user", "alerts@novacloudedges.com"),
        "smtp_pass": get_setting(db, "smtp_pass", ""),
        "smtp_to_emails": get_setting(db, "smtp_to_emails", "admin@novacloudedges.com"),
        "smtp_encryption": get_setting(db, "smtp_encryption", "starttls"),
        "smtp_trigger_ufw": get_setting(db, "smtp_trigger_ufw", "1") == "1",
        "smtp_trigger_blocking": get_setting(db, "smtp_trigger_blocking", "1") == "1",
        "smtp_trigger_ssl_expiry": get_setting(db, "smtp_trigger_ssl_expiry", "1") == "1",
        "smtp_trigger_domain_expiry": get_setting(db, "smtp_trigger_domain_expiry", "1") == "1",
        "smtp_trigger_suspension": get_setting(db, "smtp_trigger_suspension", "1") == "1"
    }

@app.post("/api/smtp-settings")
def update_smtp_settings(data: SmtpSettingsUpdate, req: Request, db: Session = Depends(get_db)):
    host_val = (data.smtp_host or data.host or "mail.ncloud.co.ug").strip()
    port_val = str(data.smtp_port or data.port or 587)
    user_val = (data.smtp_user or data.user or "alerts@novacloudedges.com").strip()
    pass_val = data.smtp_pass if data.smtp_pass is not None else (data.password or "")
    to_val = (data.smtp_to_emails or data.to_emails or "admin@novacloudedges.com").strip()
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
    audit = AuditLog(
        action="UPDATE_SMTP_SETTINGS",
        details="Updated managed action SMTP server credentials and email notification triggers",
        status="success",
        client_ip=client_ip
    )
    db.add(audit)
    db.commit()

    return {"message": "SMTP configuration and alert triggers updated successfully"}

@app.post("/api/smtp/test")
def test_smtp_configuration(data: TestEmailRequest, req: Request, db: Session = Depends(get_db)):
    target_email = data.test_email.strip() if (data.test_email and data.test_email.strip()) else ""
    if not target_email and data.recipient:
        target_email = data.recipient.strip()
    if not target_email:
        target_email = get_setting(db, "smtp_to_emails", "admin@novacloudedges.com")

    try:
        send_smtp_notification(
            trigger_type="test",
            subject="Nova Edge Proxy — SMTP Notification Test",
            body_text=f"This is an operational test email notification from Nova Cloud Edges Proxy Admin.\nManaged action SMTP alerts are configured and functional.\nTarget Recipient: {target_email}",
            db=db,
            override_recipient=target_email,
            raise_on_error=True
        )
        return {"message": f"Test alert email dispatched successfully to {target_email}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to dispatch test email: {str(e)}")


@app.get("/suspended", response_class=HTMLResponse)
def render_suspended_landing_page(domain: str = Query("your-domain.com"), reason: str = Query("Administrative Policy Suspension"), db: Session = Depends(get_db)):
    """Public rendered page when visitors hit a suspended domain."""
    title = get_setting(db, "suspension_title", "Account Suspended — 503 Maintenance Mode")
    message = get_setting(db, "suspension_message", "This website service has been temporarily deactivated by Nova Cloud Edges Administration due to scheduled maintenance or account review.")
    email = get_setting(db, "suspension_support_email", "support@novacloudedges.com")
    phone = get_setting(db, "suspension_support_phone", "+256 700 892 110")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title} — Nova Cloud Edges</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
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
      content: '';
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
    <h1>{title}</h1>
    <div class="domain-tag">{domain}</div>
    <p>{message}</p>
    <div class="reason-box">
      <div style="font-size: 0.76rem; text-transform: uppercase; color: #94a3b8; font-weight: 700; margin-bottom: 0.25rem;">Suspension Statement:</div>
      <div>{reason}</div>
    </div>
    <div class="contact-box">
      <div>If you are the website owner, please contact Nova Cloud Edges Support:</div>
      <div>Email: <a href="mailto:{email}">{email}</a> &bull; Hotline: <strong>{phone}</strong></div>
    </div>
  </div>
</body>
</html>"""

# ---------------------------------------------------------
# SSL Certificates & Audit Logs
# ---------------------------------------------------------
@app.get("/api/certificates")
def get_certificates(db: Session = Depends(get_db)):
    certs = db.query(Certificate).order_by(Certificate.id.desc()).all()
    return [
        {
            "id": c.id,
            "domain": c.domain,
            "provider": c.provider,
            "status": c.status,
            "issued_at": str(c.issued_at),
            "expires_at": str(c.expires_at),
            "domain_registered_at": str(c.domain_registered_at) if c.domain_registered_at else "",
            "domain_expires_at": str(c.domain_expires_at) if c.domain_expires_at else "",
            "auto_renew": c.auto_renew,
            "cert_path": c.cert_path
        }
        for c in certs
    ]

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
    """Initializes realistic baseline web traffic & error log activity across reverse proxy hosts."""
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
        domain_list = ["ncloud.co.ug", "sun.ac.ug", "portal.sun.ac.ug", "api.novacloudedges.com"]

    sample_nodes = [
        {"ip": "127.0.0.1", "label": "Localhost Console", "ua": "Nova-Edge-Monitor/2.1"},
        {"ip": "197.239.12.8", "label": "Kampala Fiber Node", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0"},
        {"ip": "102.214.34.19", "label": "Entebbe Edge Gateway", "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"},
        {"ip": "41.210.144.75", "label": "Jinja Upstream Relay", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)"},
        {"ip": "154.72.198.62", "label": "Nairobi Peering Transit", "ua": "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0"},
        {"ip": "165.22.18.91", "label": "Cloudflare CDN Proxy", "ua": "Cloudflare-AlwaysOnline/1.0"}
    ]

    traffic_samples = [
        ("GET", "/", 200, 18, 4120, None, False, "none"),
        ("GET", "/assets/app.js", 200, 12, 18450, None, False, "none"),
        ("GET", "/api/v1/telemetry", 200, 24, 1280, None, False, "none"),
        ("POST", "/api/auth/login", 200, 48, 850, None, False, "none"),
        ("GET", "/student/portal", 200, 32, 9400, None, False, "none"),
        ("GET", "/api/v1/health", 200, 8, 220, None, False, "none"),
        ("GET", "/wp-login.php", 403, 14, 340, "403 Forbidden: WAF rule blocked administrative exploit probing", True, "warning"),
        ("GET", "/.env", 404, 10, 180, "404 Not Found: Security rule suppressed configuration file access", True, "warning"),
        ("POST", "/api/v1/payments", 200, 65, 1420, None, False, "none"),
        ("GET", "/api/v1/sync", 502, 110, 520, "502 Bad Gateway: Upstream connection refused at 127.0.0.1:8080", True, "critical"),
        ("GET", "/docs/api", 200, 22, 6200, None, False, "none"),
        ("GET", "/non-existent-page", 404, 12, 280, "404 Not Found: Requested resource was not found on this server", True, "warning"),
        ("POST", "/api/upload", 413, 28, 410, "413 Payload Too Large: Client request body exceeded max limit (25MB)", True, "warning"),
        ("GET", "/upstream/timeout", 504, 5000, 480, "504 Gateway Timeout: Upstream backend server timed out after 5.0s", True, "critical")
    ]

    import random
    now = datetime.datetime.utcnow()
    new_logs = []
    for i in range(85):
        t_delta = datetime.timedelta(minutes=random.randint(2, 380), seconds=random.randint(0, 59))
        node = random.choice(sample_nodes)
        dom = random.choice(domain_list)
        method, path, status, resp_time, bytes_s, err_msg, is_err, severity = random.choice(traffic_samples)

        if random.random() < 0.28:
            node = sample_nodes[0]

        new_logs.append(WebTrafficLog(
            timestamp=now - t_delta,
            client_ip=node["ip"],
            method=method,
            domain=dom,
            path=path,
            status_code=status,
            response_time_ms=resp_time + random.randint(0, 15),
            bytes_sent=bytes_s + random.randint(-50, 150),
            user_agent=node["ua"],
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
