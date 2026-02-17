"""
Tailscale JIT (Just-In-Time) Access Management

A self-hosted web application for managing temporary access grants using
Tailscale's custom posture attributes. Provides secure, time-limited access
to resources with full audit logging and approval workflows.
"""

import json
import logging
import os
import re
import signal
import sqlite3
import sys
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps

import requests as http_requests
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFProtect

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
__version__ = "1.1.0"

# ---------------------------------------------------------------------------
# Environment & Configuration
# ---------------------------------------------------------------------------
load_dotenv()

def _require_env(name: str) -> str:
    """Return an environment variable or exit with a clear error."""
    value = os.environ.get(name)
    if not value:
        print(f"FATAL: Required environment variable {name} is not set. "
              f"Copy .env.example to .env and fill in all values.", file=sys.stderr)
        sys.exit(1)
    return value


# Required configuration
TAILSCALE_CLIENT_ID = _require_env("TAILSCALE_CLIENT_ID")
TAILSCALE_CLIENT_SECRET = _require_env("TAILSCALE_CLIENT_SECRET")
TAILSCALE_TAILNET = _require_env("TAILSCALE_TAILNET")

# Optional configuration with safe defaults
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not FLASK_SECRET_KEY:
    print("FATAL: FLASK_SECRET_KEY is not set. Generate one with: "
          "python3 -c \"import secrets; print(secrets.token_hex(32))\"", file=sys.stderr)
    sys.exit(1)

# Capability domain - the ACL capability string used with --accept-app-caps
# Must match your ACL and the --accept-app-caps flag in tailscale-serve.service
CAP_DOMAIN = os.environ.get("CAP_DOMAIN", "yourdomain.com/cap/jit-access")

# Database path
DB_PATH = os.environ.get("DB_PATH", "jit_access.db")

# Access profiles and default approval rules - loaded from config.py.
# Edit config.py to add, rename, or remove profiles and set approval defaults.
try:
    from config import ACCESS_PROFILES, APPROVAL_RULES as CONFIG_APPROVAL_RULES
except ImportError:
    print("FATAL: config.py not found. Copy config.py from the repository to the app directory.",
          file=sys.stderr)
    sys.exit(1)

# Cache TTLs (seconds)
CACHE_TTL = int(os.environ.get("DEVICE_CACHE_TTL", "300"))   # 5 minutes
TOKEN_TTL = int(os.environ.get("TOKEN_CACHE_TTL", "3000"))   # 50 minutes

# Self-approve prevention: off by default - set ALLOW_SELF_APPROVE=true only for dev/test
ALLOW_SELF_APPROVE = os.environ.get("ALLOW_SELF_APPROVE", "false").lower() == "true"

# Default required approvals when no rule is configured for a profile
DEFAULT_REQUIRED_APPROVALS = min(3, max(1, int(os.environ.get("DEFAULT_REQUIRED_APPROVALS", "1"))))

# Audit log retention: number of days to keep entries (0 = keep forever)
AUDIT_LOG_RETENTION_DAYS = max(0, int(os.environ.get("AUDIT_LOG_RETENTION_DAYS", "365")))

# Audit log / activity page size (rows per page)
AUDIT_PAGE_SIZE = min(500, max(10, int(os.environ.get("AUDIT_PAGE_SIZE", "100"))))

# How often (seconds) the background worker runs expiry checks and log pruning
EXPIRY_CHECK_INTERVAL = max(30, int(os.environ.get("EXPIRY_CHECK_INTERVAL", "60")))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("jit-access")

# ---------------------------------------------------------------------------
# Flask Application
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = FLASK_SECRET_KEY
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["WTF_CSRF_TIME_LIMIT"] = None  # CSRF tokens valid for the session lifetime

csrf = CSRFProtect(app)

# SocketIO CORS: use engine.io's built-in same-origin validation (default).
# It checks the Origin header against the Host from the WSGI environ,
# which works correctly behind Tailscale Serve without needing Flask's
# request context.
socketio = SocketIO(app)


@app.after_request
def set_security_headers(response):
    """Add standard security headers to every response."""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------
_cache = {
    "devices": [],
    "devices_ts": None,
    "token": None,
    "token_ts": None,
}


def get_tailscale_token():
    """Get OAuth access token from Tailscale (cached for TOKEN_TTL seconds)."""
    now = datetime.now(timezone.utc)

    if _cache["token"] and _cache["token_ts"]:
        age = (now - _cache["token_ts"]).total_seconds()
        if age < TOKEN_TTL:
            logger.debug("Using cached OAuth token (%ds old)", int(age))
            return _cache["token"]

    url = "https://api.tailscale.com/api/v2/oauth/token"
    data = {
        "client_id": TAILSCALE_CLIENT_ID,
        "client_secret": TAILSCALE_CLIENT_SECRET,
    }
    logger.info("Fetching new OAuth token from Tailscale...")

    try:
        response = http_requests.post(url, data=data, timeout=15)
    except http_requests.RequestException as exc:
        logger.error("OAuth token request failed: %s", exc)
        return _cache.get("token")  # return stale token if available

    if response.status_code == 200:
        token = response.json().get("access_token")
        _cache["token"] = token
        _cache["token_ts"] = now
        logger.info("Obtained new OAuth token (cached for %ds)", TOKEN_TTL)
        return token

    logger.error("OAuth token error %d: %s", response.status_code, response.text)
    return None


def get_cached_devices(force_refresh=False):
    """Get devices from cache or fetch from Tailscale API."""
    now = datetime.now(timezone.utc)

    if not force_refresh and _cache["devices_ts"]:
        age = (now - _cache["devices_ts"]).total_seconds()
        if age < CACHE_TTL:
            logger.debug("Using cached devices (%ds old)", int(age))
            return _cache["devices"]

    token = get_tailscale_token()
    if not token:
        return _cache["devices"] or []

    try:
        url = f"https://api.tailscale.com/api/v2/tailnet/{TAILSCALE_TAILNET}/devices"
        headers = {"Authorization": f"Bearer {token}"}
        response = http_requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            devices = response.json().get("devices", [])
            _cache["devices"] = devices
            _cache["devices_ts"] = now
            logger.info("Fetched %d devices from API (cached for %ds)", len(devices), CACHE_TTL)
            return devices
    except http_requests.RequestException as exc:
        logger.error("Device fetch failed: %s", exc)

    return _cache["devices"] or []


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
@contextmanager
def get_db():
    """Context manager for safe database access."""
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    # WAL mode: allows concurrent readers alongside a single writer, eliminates
    # most "database is locked" errors under normal multi-request load.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create tables if they don't exist."""
    with get_db() as conn:
        c = conn.cursor()

        c.execute("""CREATE TABLE IF NOT EXISTS access_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester TEXT NOT NULL,
            device_id TEXT NOT NULL,
            device_name TEXT NOT NULL,
            profile TEXT NOT NULL,
            duration INTEGER NOT NULL,
            reason TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            approver TEXT,
            denial_reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            processed_at TIMESTAMP
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            user TEXT NOT NULL,
            target TEXT,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS user_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            action TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            session_id TEXT,
            capabilities TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        # Multi-approval: tracks individual approval votes for a request
        c.execute("""CREATE TABLE IF NOT EXISTS approval_votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            voter TEXT NOT NULL,
            voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(request_id, voter),
            FOREIGN KEY(request_id) REFERENCES access_requests(id)
        )""")

        # Multi-approval: configurable required approvals per access profile
        c.execute("""CREATE TABLE IF NOT EXISTS approval_rules (
            profile TEXT PRIMARY KEY,
            required_approvals INTEGER NOT NULL DEFAULT 1,
            updated_by TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

        # Authorized approvers: restrict who may approve requests for a given profile
        # Empty list means any user with can_approve_requests may approve.
        # Max 3 per profile (enforced in application logic).
        # is_required=1 means this approver MUST vote before the request can be
        # granted, even if general quorum is already reached by other approvers.
        c.execute("""CREATE TABLE IF NOT EXISTS authorized_approvers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile TEXT NOT NULL,
            approver TEXT NOT NULL,
            is_required INTEGER NOT NULL DEFAULT 0,
            added_by TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(profile, approver)
        )""")

        # Migration: add is_required column to existing deployments
        try:
            c.execute("ALTER TABLE authorized_approvers ADD COLUMN is_required INTEGER NOT NULL DEFAULT 0")
        except Exception:
            pass  # column already exists

        # Seed approval rules from config.py for any profile that has no DB row yet.
        # If the Admin page has already written a row for a profile, the DB wins - no overwrite.
        for profile_id, rule in CONFIG_APPROVAL_RULES.items():
            existing = c.execute(
                "SELECT 1 FROM approval_rules WHERE profile = ?", (profile_id,)
            ).fetchone()
            if not existing:
                n = max(1, min(3, int(rule.get("required_approvals", 1))))
                c.execute(
                    """INSERT INTO approval_rules (profile, required_approvals, updated_by, updated_at)
                       VALUES (?, ?, 'config.py', ?)""",
                    (profile_id, n, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
                )
                for entry in rule.get("authorized_approvers", []):
                    email = str(entry.get("email", "")).strip().lower()
                    if email:
                        c.execute(
                            """INSERT OR IGNORE INTO authorized_approvers
                               (profile, approver, is_required, added_by) VALUES (?, ?, ?, 'config.py')""",
                            (profile_id, email, 1 if entry.get("required") else 0),
                        )
                logger.info("Seeded approval rules for %s from config.py", profile_id)

    logger.info("Database initialized at %s", DB_PATH)


# ---------------------------------------------------------------------------
# Helpers: auth, permissions, logging
# ---------------------------------------------------------------------------
def get_user_capabilities():
    """Read app capabilities from Tailscale-App-Capabilities header."""
    cap_header = request.headers.get("Tailscale-App-Capabilities")
    if not cap_header:
        return {}
    try:
        return json.loads(cap_header)
    except json.JSONDecodeError:
        logger.warning("Malformed Tailscale-App-Capabilities header")
        return {}


def get_client_ip():
    """Get real client IP from X-Forwarded-For when behind Tailscale Serve.
    Only trust the header when the direct connection is from localhost (the
    reverse proxy), preventing spoofed IPs from external clients."""
    remote = request.remote_addr or ""
    if remote.startswith("127.") or remote == "::1":
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return remote


def get_current_user():
    """Get current user from Tailscale-User-Login header or session."""
    user = request.headers.get("Tailscale-User-Login")
    if user:
        return user
    return session.get("user")


def has_permission(permission_name):
    """Check if current user has a specific JIT-access capability."""
    caps = get_user_capabilities()
    jit_caps = caps.get(CAP_DOMAIN, [])
    return any(cap_obj.get(permission_name, False) for cap_obj in jit_caps)


def log_user_activity(action):
    """Log user activity (login)."""
    user = get_current_user()
    if not user:
        return
    caps = get_user_capabilities()
    with get_db() as conn:
        conn.execute(
            """INSERT INTO user_activity
               (user, action, ip_address, user_agent, session_id, capabilities)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user, action, get_client_ip(), request.headers.get("User-Agent"),
             session.get("session_id", "unknown"), json.dumps(caps)),
        )


def log_audit(event_type, target=None, details=None):
    """Log audit event."""
    user = get_current_user()
    with get_db() as conn:
        conn.execute(
            """INSERT INTO audit_log
               (event_type, user, target, details, ip_address, user_agent)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (event_type, user or "anonymous", target, details,
             get_client_ip(), request.headers.get("User-Agent")),
        )


# ---------------------------------------------------------------------------
# Multi-approval helpers
# ---------------------------------------------------------------------------
def get_required_approvals(profile):
    """Return the number of approvals required for a profile."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT required_approvals FROM approval_rules WHERE profile = ?", (profile,)
        ).fetchone()
    return row["required_approvals"] if row else DEFAULT_REQUIRED_APPROVALS


def get_authorized_approvers(profile):
    """Return the list of authorized approvers for a profile as dicts with
    'approver' and 'is_required' keys.
    An empty list means any user with can_approve_requests may approve."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT approver, is_required FROM authorized_approvers WHERE profile = ? ORDER BY added_at",
            (profile,),
        ).fetchall()
    return [{"approver": r["approver"], "is_required": bool(r["is_required"])} for r in rows]


def get_required_approver_emails(profile):
    """Return just the emails of approvers marked is_required=1 for a profile."""
    return [a["approver"] for a in get_authorized_approvers(profile) if a["is_required"]]


def get_vote_count(conn, request_id):
    """Return the number of votes cast for a request."""
    row = conn.execute(
        "SELECT COUNT(*) AS cnt FROM approval_votes WHERE request_id = ?", (request_id,)
    ).fetchone()
    return row["cnt"] if row else 0


def get_voters(conn, request_id):
    """Return list of voters for a request."""
    rows = conn.execute(
        "SELECT voter FROM approval_votes WHERE request_id = ? ORDER BY voted_at", (request_id,)
    ).fetchall()
    return [r["voter"] for r in rows]


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
# Tailscale device IDs are numeric strings
_DEVICE_ID_RE = re.compile(r"^\d+$")
# Device names: allow printable characters except angle brackets and null bytes
# Tailscale device names can include apostrophes, spaces, and unicode (e.g. "Carlos's MacBook Pro")
_DEVICE_NAME_RE = re.compile(r"^[^\x00<>]{1,255}$")
# Posture attributes must start with custom:
_PROFILE_RE = re.compile(r"^custom:[a-zA-Z0-9_]+$")
# Allowed durations in minutes
_ALLOWED_DURATIONS = {5, 15, 30, 60, 120, 240, 480, 1440}


def _safe_int(value, default=None):
    """Safely convert to int, returning default on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _escape_like(s):
    """Escape special LIKE characters so they match literally."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _validate_request_fields(device_id, device_name, profile, duration, reason):
    """Validate access request fields. Returns error message or None."""
    if not all([device_id, device_name, profile, reason]):
        return "Missing required fields"
    if not _DEVICE_ID_RE.match(str(device_id)):
        return "Invalid device ID format"
    if not _DEVICE_NAME_RE.match(str(device_name)):
        return "Invalid device name format"
    if not _PROFILE_RE.match(profile):
        return "Invalid profile format: must be custom:<alphanumeric>"
    dur = _safe_int(duration)
    if dur is None or dur not in _ALLOWED_DURATIONS:
        return f"Invalid duration: must be one of {sorted(_ALLOWED_DURATIONS)}"
    if len(reason.strip()) < 3:
        return "Reason must be at least 3 characters"
    if len(reason) > 1000:
        return "Reason must be less than 1000 characters"
    return None


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------------------------
# Session tracking: log activity on first request of any new session
# ---------------------------------------------------------------------------
@app.before_request
def track_session():
    """Log user activity once per session, regardless of entry point.
    Handles the case where a user bypasses /login via a saved URL and a
    still-valid session cookie after a DB wipe."""
    user = get_current_user()
    if not user:
        return
    if not session.get("session_id"):
        session["session_id"] = os.urandom(16).hex()
        session["user"] = user
        log_user_activity("login")
        log_audit("user_login", details=f"User {user} logged in via Tailscale")


# ---------------------------------------------------------------------------
# Template context: inject common variables into all templates
# ---------------------------------------------------------------------------
@app.context_processor
def inject_globals():
    """Make permissions and version available in all templates."""
    return {
        "app_version": __version__,
        "can_request_access": has_permission("can_request_access"),
        "can_admin_config": has_permission("can_admin_config"),
    }


# ---------------------------------------------------------------------------
# Routes: Authentication
# ---------------------------------------------------------------------------
@app.route("/login")
def login():
    """Login via Tailscale header (automatic when accessed via Tailscale Serve)."""
    user = request.headers.get("Tailscale-User-Login")

    if user:
        # track_session() (before_request) already handles session creation
        # and login logging for new sessions. Only update the session user here
        # in case they navigated to /login explicitly with an existing session.
        session["user"] = user
        if not session.get("session_id"):
            session["session_id"] = os.urandom(16).hex()
        return redirect(url_for("index"))

    return (
        "<html><body>"
        "<h1>Login Required</h1>"
        "<p>You must access this application through Tailscale Serve.</p>"
        "<p>See the README for setup instructions.</p>"
        "</body></html>"
    ), 401


# ---------------------------------------------------------------------------
# Routes: Pages
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    """Main page: shows pending and partially-approved requests."""
    user = get_current_user()
    can_approve = has_permission("can_approve_requests")
    can_view_audit = has_permission("can_view_audit")

    with get_db() as conn:
        if can_approve:
            rows = conn.execute(
                """SELECT id, requester, device_name, profile, duration, reason, created_at, status
                   FROM access_requests
                   WHERE status IN ('pending', 'partially_approved')
                   ORDER BY created_at DESC"""
            ).fetchall()
        else:
            # Regular users only see their own pending requests
            rows = conn.execute(
                """SELECT id, requester, device_name, profile, duration, reason, created_at, status
                   FROM access_requests
                   WHERE status IN ('pending', 'partially_approved')
                   AND requester = ?
                   ORDER BY created_at DESC""",
                (user,),
            ).fetchall()

        # Annotate each request with vote info and approver restrictions
        pending_requests = []
        for r in rows:
            req = dict(r)
            req["vote_count"] = get_vote_count(conn, r["id"])
            req["voters"] = get_voters(conn, r["id"])
            req["required_approvals"] = get_required_approvals(r["profile"])
            req["already_voted"] = user in req["voters"]
            req["authorized_approvers"] = get_authorized_approvers(r["profile"])
            # True if there is a restriction and this user is not in it
            auth_emails = [a["approver"] for a in req["authorized_approvers"]]
            req["not_authorized"] = bool(auth_emails) and user not in auth_emails
            # Required approvers who haven't voted yet (used for UI warning)
            req["missing_required"] = [
                a["approver"] for a in req["authorized_approvers"]
                if a["is_required"] and a["approver"] not in req["voters"]
            ]
            pending_requests.append(req)

        # For non-approvers: also fetch their recent completed requests (last 10)
        # and any currently active grants
        my_recent = []
        my_active = []
        if not can_approve:
            recent_rows = conn.execute(
                """SELECT id, device_name, profile, duration, reason, status,
                          approver, denial_reason, created_at, processed_at
                   FROM access_requests
                   WHERE requester = ?
                   AND status IN ('approved', 'denied', 'expired', 'revoked')
                   ORDER BY processed_at DESC
                   LIMIT 10""",
                (user,),
            ).fetchall()
            my_recent = [dict(r) for r in recent_rows]

            # Active grants: approved requests whose expiry hasn't passed yet
            now = datetime.now(timezone.utc)
            active_ids = set()
            for row in my_recent:
                if row["status"] != "approved" or not row["processed_at"]:
                    continue
                try:
                    processed_at = datetime.fromisoformat(row["processed_at"].replace("Z", "+00:00"))
                    if processed_at.tzinfo is None:
                        processed_at = processed_at.replace(tzinfo=timezone.utc)
                except (ValueError, AttributeError):
                    continue
                expires_at = processed_at + timedelta(minutes=int(row["duration"]))
                if expires_at > now:
                    active_ids.add(row["id"])
                    my_active.append({
                        **row,
                        "expires_at": expires_at.isoformat(),
                    })

            # Don't show active grants again in the Recent section
            if active_ids:
                my_recent = [r for r in my_recent if r["id"] not in active_ids]

    return render_template(
        "index.html",
        pending_requests=pending_requests,
        my_recent=my_recent,
        my_active=my_active,
        can_approve=can_approve,
        can_view_audit=can_view_audit,
        can_view_current_access=has_permission("can_view_current_access"),
        can_view_debug=has_permission("can_view_debug"),
        current_user=user,
    )


@app.route("/request", methods=["GET", "POST"])
@login_required
def request_access():
    """Request access page: form submission and display."""
    user = get_current_user()
    can_view_audit = has_permission("can_view_audit")

    if request.method == "POST":
        if not has_permission("can_request_access"):
            return "Access denied: you don't have permission to request access", 403

        device_id = request.form.get("device_id", "").strip()
        device_name = request.form.get("device_name", "").strip()
        attribute = request.form.get("attribute", "").strip()
        duration = _safe_int(request.form.get("duration"), 0)
        reason = request.form.get("reason", "").strip()

        error = _validate_request_fields(device_id, device_name, attribute, duration, reason)
        if error:
            logger.warning("Request validation failed for %s: %s", user, error)
            return error, 400

        with get_db() as conn:
            cursor = conn.execute(
                """INSERT INTO access_requests
                   (requester, device_id, device_name, profile, duration, reason)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user, device_id, device_name, attribute, duration, reason),
            )
            request_id = cursor.lastrowid

        log_audit(
            "access_request_created",
            target=device_name,
            details=f"Profile: {attribute}, Duration: {duration}min",
        )

        socketio.emit("new_request", {
            "id": request_id,
            "requester": user,
            "device_name": device_name,
        })

        return redirect(url_for("index"))

    # GET: show form
    force_refresh = request.args.get("refresh") == "1"
    devices = get_cached_devices(force_refresh=force_refresh)

    return render_template(
        "request.html",
        devices=devices,
        profiles=ACCESS_PROFILES,
        current_user=user,
        can_view_audit=can_view_audit,
        can_view_current_access=has_permission("can_view_current_access"),
        can_view_debug=has_permission("can_view_debug"),
    )


@app.route("/current-access")
@login_required
def current_access():
    """Show all active JIT access grants."""
    user = get_current_user()
    can_view_audit = has_permission("can_view_audit")
    can_view_current_access = has_permission("can_view_current_access")

    if not can_view_current_access:
        return "Access denied: you don't have permission to view current access", 403

    with get_db() as conn:
        rows = conn.execute(
            """SELECT id, requester, device_id, device_name, profile, approver, processed_at, duration
               FROM access_requests
               WHERE status = 'approved'
               ORDER BY processed_at DESC"""
        ).fetchall()

    now = datetime.now(timezone.utc)
    active_grants = []

    for row in rows:
        processed_at = row["processed_at"]
        if not processed_at:
            continue
        approved_time = datetime.fromisoformat(processed_at.replace("Z", "+00:00"))
        if approved_time.tzinfo is None:
            approved_time = approved_time.replace(tzinfo=timezone.utc)
        expires_at = approved_time + timedelta(minutes=row["duration"])

        if expires_at > now:
            active_grants.append({
                "id": row["id"],
                "requester": row["requester"],
                "device_id": row["device_id"],
                "device_name": row["device_name"],
                "profile": row["profile"],
                "approver": row["approver"],
                "approved_at": processed_at,
                "expires_at": expires_at.isoformat(),
                "duration": row["duration"],
            })

    return render_template(
        "current-access.html",
        active_grants=active_grants,
        current_user=user,
        can_approve=has_permission("can_approve_requests"),
        can_view_audit=can_view_audit,
        can_view_current_access=can_view_current_access,
        can_view_debug=has_permission("can_view_debug"),
    )


_VALID_PER_PAGE = (10, 25, 50, 100, 250, 500)

@app.route("/audit")
@login_required
def audit():
    """Audit log page with pagination and search."""
    user = get_current_user()
    can_view_audit = has_permission("can_view_audit")

    if not can_view_audit:
        return "Access denied: you don't have permission to view audit logs", 403

    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    try:
        per_page = int(request.args.get("per_page", AUDIT_PAGE_SIZE))
        if per_page not in _VALID_PER_PAGE:
            per_page = AUDIT_PAGE_SIZE
    except (ValueError, TypeError):
        per_page = AUDIT_PAGE_SIZE

    q = request.args.get("q", "").strip()

    if q:
        like = f"%{_escape_like(q)}%"
        where = r"""WHERE (event_type LIKE ? ESCAPE '\' OR user LIKE ? ESCAPE '\' OR target LIKE ? ESCAPE '\' OR details LIKE ? ESCAPE '\' OR ip_address LIKE ? ESCAPE '\')"""
        params_count = (like, like, like, like, like)
        params_rows = (like, like, like, like, like, per_page, (page - 1) * per_page)
        with get_db() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM audit_log {where}", params_count
            ).fetchone()[0]
            rows = conn.execute(
                f"""SELECT event_type, user, target, details, ip_address, timestamp
                   FROM audit_log {where}
                   ORDER BY timestamp DESC
                   LIMIT ? OFFSET ?""",
                params_rows,
            ).fetchall()
    else:
        offset = (page - 1) * per_page
        with get_db() as conn:
            total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            rows = conn.execute(
                """SELECT event_type, user, target, details, ip_address, timestamp
                   FROM audit_log
                   ORDER BY timestamp DESC
                   LIMIT ? OFFSET ?""",
                (per_page, offset),
            ).fetchall()

    audit_entries = [dict(r) for r in rows]
    total_pages = max(1, (total + per_page - 1) // per_page)
    # clamp page to valid range after we know total_pages
    if page > total_pages:
        page = total_pages

    return render_template(
        "audit.html",
        audit_entries=audit_entries,
        current_user=user,
        can_view_audit=can_view_audit,
        can_view_current_access=has_permission("can_view_current_access"),
        can_view_debug=has_permission("can_view_debug"),
        page=page,
        total_pages=total_pages,
        total_entries=total,
        page_size=per_page,
        valid_per_page=_VALID_PER_PAGE,
        q=q,
        retention_days=AUDIT_LOG_RETENTION_DAYS,
    )


@app.route("/activity")
@login_required
def activity():
    """User activity page: login history with pagination and search."""
    user = get_current_user()
    can_view_audit = has_permission("can_view_audit")

    if not can_view_audit:
        return "Access denied: you don't have permission to view user activity", 403

    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    try:
        per_page = int(request.args.get("per_page", AUDIT_PAGE_SIZE))
        if per_page not in _VALID_PER_PAGE:
            per_page = AUDIT_PAGE_SIZE
    except (ValueError, TypeError):
        per_page = AUDIT_PAGE_SIZE

    q = request.args.get("q", "").strip()

    if q:
        like = f"%{_escape_like(q)}%"
        where = r"WHERE (user LIKE ? ESCAPE '\' OR action LIKE ? ESCAPE '\' OR ip_address LIKE ? ESCAPE '\' OR user_agent LIKE ? ESCAPE '\' OR session_id LIKE ? ESCAPE '\')"
        params_count = (like, like, like, like, like)
        params_rows = (like, like, like, like, like, per_page, (page - 1) * per_page)
        with get_db() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM user_activity {where}", params_count
            ).fetchone()[0]
            rows = conn.execute(
                f"""SELECT user, action, ip_address, user_agent, session_id, capabilities, timestamp
                   FROM user_activity {where}
                   ORDER BY timestamp DESC
                   LIMIT ? OFFSET ?""",
                params_rows,
            ).fetchall()
    else:
        offset = (page - 1) * per_page
        with get_db() as conn:
            total = conn.execute("SELECT COUNT(*) FROM user_activity").fetchone()[0]
            rows = conn.execute(
                """SELECT user, action, ip_address, user_agent, session_id, capabilities, timestamp
                   FROM user_activity
                   ORDER BY timestamp DESC
                   LIMIT ? OFFSET ?""",
                (per_page, offset),
            ).fetchall()

    activity_entries = [dict(r) for r in rows]
    total_pages = max(1, (total + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages

    return render_template(
        "activity.html",
        activity_entries=activity_entries,
        current_user=user,
        can_view_audit=can_view_audit,
        can_view_current_access=has_permission("can_view_current_access"),
        can_view_debug=has_permission("can_view_debug"),
        page=page,
        total_pages=total_pages,
        total_entries=total,
        page_size=per_page,
        valid_per_page=_VALID_PER_PAGE,
        q=q,
        retention_days=AUDIT_LOG_RETENTION_DAYS,
    )


_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin_config():
    """Admin configuration page: approval rules and authorized approvers per profile."""
    user = get_current_user()
    if not has_permission("can_admin_config"):
        log_audit("permission_denied", target="/admin",
                  details="Missing can_admin_config")
        return "Access denied: can_admin_config capability required", 403

    errors = []
    success = None

    if request.method == "POST":
        for profile_obj in ACCESS_PROFILES:
            pid = profile_obj["id"]
            safe_id = pid.replace(":", "_").replace("-", "_")

            # Required approvals
            req_field = f"req_{safe_id}"
            raw = request.form.get(req_field, "").strip()
            n = _safe_int(raw)
            if n is None or n < 1 or n > 3:
                errors.append(f"{profile_obj['name']}: required approvals must be 1-3")
            else:
                now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                with get_db() as conn:
                    conn.execute(
                        """INSERT INTO approval_rules (profile, required_approvals, updated_by, updated_at)
                           VALUES (?, ?, ?, ?)
                           ON CONFLICT(profile) DO UPDATE SET
                             required_approvals = excluded.required_approvals,
                             updated_by = excluded.updated_by,
                             updated_at = excluded.updated_at""",
                        (pid, n, user, now_str),
                    )
                log_audit("approval_rule_updated", target=pid,
                          details=f"Required approvals set to {n} by {user}")

            # Authorized approvers (up to 3), each with an optional is_required flag
            new_approvers = []  # list of (email, is_required)
            seen_emails = []
            profile_errors = []
            for i in range(1, 4):
                val = request.form.get(f"approver_{safe_id}_{i}", "").strip().lower()
                if val:
                    if not _EMAIL_RE.match(val):
                        profile_errors.append(f"{profile_obj['name']}: '{val}' is not a valid email")
                    elif val not in seen_emails:
                        seen_emails.append(val)
                        is_req = request.form.get(f"required_{safe_id}_{i}") == "1"
                        new_approvers.append((val, is_req))

            errors.extend(profile_errors)

            if not profile_errors:
                with get_db() as conn:
                    conn.execute(
                        "DELETE FROM authorized_approvers WHERE profile = ?", (pid,)
                    )
                    for approver, is_req in new_approvers:
                        conn.execute(
                            """INSERT OR IGNORE INTO authorized_approvers
                               (profile, approver, is_required, added_by) VALUES (?, ?, ?, ?)""",
                            (pid, approver, 1 if is_req else 0, user),
                        )
                req_labels = [f"{e}{'*' if r else ''}" for e, r in new_approvers]
                log_audit("authorized_approvers_updated", target=pid,
                          details=f"Approvers set to [{', '.join(req_labels) or 'unrestricted'}] by {user}")

        if not errors:
            success = "Approval configuration saved."

    # Load current rules and authorized approvers
    rules = {}
    with get_db() as conn:
        for row in conn.execute(
            "SELECT profile, required_approvals, updated_by, updated_at FROM approval_rules"
        ):
            rules[row["profile"]] = dict(row)

    approvers_by_profile = {p["id"]: get_authorized_approvers(p["id"]) for p in ACCESS_PROFILES}

    # Which profiles have live DB overrides (written by a user, not seeded from config.py)
    overridden_profiles = {
        pid for pid, rule in rules.items()
        if rule.get("updated_by") and rule["updated_by"] != "config.py"
    }

    return render_template(
        "admin.html",
        profiles=ACCESS_PROFILES,
        rules=rules,
        approvers_by_profile=approvers_by_profile,
        default_required=DEFAULT_REQUIRED_APPROVALS,
        overridden_profiles=overridden_profiles,
        errors=errors,
        success=success,
        current_user=user,
        can_view_audit=has_permission("can_view_audit"),
        can_view_current_access=has_permission("can_view_current_access"),
        can_view_debug=has_permission("can_view_debug"),
    )


@app.route("/admin/export-config")
@login_required
def export_config():
    """Return a config.py snippet reflecting current DB approval rules."""
    if not has_permission("can_admin_config"):
        return "Access denied: can_admin_config capability required", 403

    lines = [
        "# Generated by Admin > Export - paste into config.py and commit to git",
        "ACCESS_PROFILES = [",
    ]
    for p in ACCESS_PROFILES:
        lines.append(f'    {{"id": {json.dumps(p["id"])}, "name": {json.dumps(p["name"])}}},')
    lines.append("]")
    lines.append("")
    lines.append("APPROVAL_RULES = {")

    for p in ACCESS_PROFILES:
        pid = p["id"]
        with get_db() as conn:
            rule_row = conn.execute(
                "SELECT required_approvals FROM approval_rules WHERE profile = ?", (pid,)
            ).fetchone()
        n = rule_row["required_approvals"] if rule_row else DEFAULT_REQUIRED_APPROVALS
        approvers = get_authorized_approvers(pid)
        lines.append(f'    {json.dumps(pid)}: {{')
        lines.append(f'        "required_approvals": {n},')
        if approvers:
            lines.append('        "authorized_approvers": [')
            for a in approvers:
                lines.append(f'            {{"email": {json.dumps(a["approver"])}, "required": {"True" if a["is_required"] else "False"}}},')
            lines.append('        ],')
        else:
            lines.append('        "authorized_approvers": [],')
        lines.append('    },')
    lines.append("}")

    snippet = "\n".join(lines)
    return Response(snippet, mimetype="text/plain",
                    headers={"Content-Disposition": "attachment; filename=config_export.py"})


@app.route("/debug")
@login_required
def debug():
    """Debug page: shows session info and permissions."""
    user = get_current_user()
    caps = get_user_capabilities()
    can_view_audit = has_permission("can_view_audit")
    can_view_debug = has_permission("can_view_debug")

    if not can_view_debug:
        return "Access denied: you don't have permission to view debug information", 403

    debug_info = {
        "current_user": user,
        "session_id": session.get("session_id", "Not set"),
        "remote_addr": get_client_ip(),
        "user_agent": request.headers.get("User-Agent"),
        "tailscale_user_header": request.headers.get("Tailscale-User-Login"),
        "capabilities_header": request.headers.get("Tailscale-App-Capabilities"),
        "parsed_capabilities": caps,
        "cap_domain": CAP_DOMAIN,
        "permissions": {
            "can_request_access": has_permission("can_request_access"),
            "can_approve_requests": has_permission("can_approve_requests"),
            "can_view_current_access": has_permission("can_view_current_access"),
            "can_view_audit": can_view_audit,
            "can_view_debug": can_view_debug,
            "can_admin_config": has_permission("can_admin_config"),
        },
    }

    return render_template(
        "debug.html",
        debug_info=debug_info,
        current_user=user,
        can_view_audit=can_view_audit,
        can_view_current_access=has_permission("can_view_current_access"),
        can_view_debug=can_view_debug,
    )


# ---------------------------------------------------------------------------
# Routes: API
# ---------------------------------------------------------------------------
@app.route("/api/devices")
@login_required
def get_devices():
    """Return list of Tailscale devices as JSON."""
    if not has_permission("can_request_access"):
        return jsonify({"error": "Permission denied"}), 403
    force_refresh = request.args.get("refresh") == "1"
    devices = get_cached_devices(force_refresh=force_refresh)
    if devices is not None:
        return jsonify({"devices": devices})
    return jsonify({"error": "Failed to fetch devices"}), 500


@app.route("/api/request", methods=["POST"])
@login_required
def submit_request():
    """Submit a new access request via JSON API."""
    if not has_permission("can_request_access"):
        return jsonify({"error": "Permission denied: can_request_access required"}), 403

    data = request.json
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    user = get_current_user()
    device_id = str(data.get("device_id", "")).strip()
    device_name = str(data.get("device_name", "")).strip()
    profile = str(data.get("profile", "")).strip()
    duration = _safe_int(data.get("duration"), 0)
    reason = str(data.get("reason", "")).strip()

    error = _validate_request_fields(device_id, device_name, profile, duration, reason)
    if error:
        return jsonify({"error": error}), 400

    with get_db() as conn:
        cursor = conn.execute(
            """INSERT INTO access_requests
               (requester, device_id, device_name, profile, duration, reason)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user, device_id, device_name, profile, duration, reason),
        )
        request_id = cursor.lastrowid

    log_audit(
        "access_request_created",
        target=device_name,
        details=f"Profile: {profile}, Duration: {duration}min",
    )

    socketio.emit("new_request", {
        "id": request_id,
        "requester": user,
        "device_name": device_name,
    })

    return jsonify({"status": "success", "request_id": request_id})


@app.route("/api/approve/<int:request_id>", methods=["POST"])
@login_required
def approve_request(request_id):
    """Cast an approval vote. Grants access when the required number of votes is reached."""
    if not has_permission("can_approve_requests"):
        log_audit("permission_denied", target=f"/api/approve/{request_id}",
                  details="Missing can_approve_requests")
        return jsonify({"error": "Permission denied"}), 403

    user = get_current_user()

    with get_db() as conn:
        row = conn.execute(
            "SELECT device_id, device_name, profile, duration, status, requester "
            "FROM access_requests WHERE id = ?",
            (request_id,),
        ).fetchone()

        if not row:
            return jsonify({"error": "Request not found"}), 404

        if row["status"] not in ("pending", "partially_approved"):
            return jsonify({"error": f"Request already {row['status']}"}), 409

        if not ALLOW_SELF_APPROVE and row["requester"] == user:
            return jsonify({"error": "You cannot approve your own request"}), 403

        device_id = row["device_id"]
        device_name = row["device_name"]
        profile = row["profile"]
        duration = row["duration"]

        # Fetch required and current vote state before recording new vote
        required = get_required_approvals(profile)
        authorized = get_authorized_approvers(profile)   # list of {approver, is_required}
        auth_emails = [a["approver"] for a in authorized]
        required_emails = [a["approver"] for a in authorized if a["is_required"]]
        current_voters = get_voters(conn, request_id)
        current_vote_count = get_vote_count(conn, request_id)

        # Check for duplicate vote
        if user in current_voters:
            return jsonify({"error": "You have already approved this request"}), 409

        # Authorized approvers restriction:
        # If a non-empty list is configured and this user is not on it, they can only
        # vote if there are not enough remaining authorized users to reach quorum alone.
        # This lets a non-authorized user fill a gap when e.g. 3 approvals are required
        # but only 2 authorized users are listed.
        if auth_emails and user not in auth_emails:
            auth_remaining = [e for e in auth_emails if e not in current_voters]
            votes_still_needed = required - current_vote_count
            if len(auth_remaining) >= votes_still_needed:
                log_audit("permission_denied", target=f"request/{request_id}",
                          details=f"Not an authorized approver for profile {profile}")
                return jsonify({"error": "You are not an authorized approver for this profile"}), 403

        # Record the vote, check quorum, and update status atomically
        conn.execute(
            "INSERT INTO approval_votes (request_id, voter) VALUES (?, ?)",
            (request_id, user),
        )

        vote_count = get_vote_count(conn, request_id)
        voters = get_voters(conn, request_id)
        missing_required = [e for e in required_emails if e not in voters]
        quorum_met = vote_count >= required and not missing_required

        if not quorum_met:
            conn.execute(
                "UPDATE access_requests SET status = 'partially_approved' WHERE id = ? AND status = 'pending'",
                (request_id,),
            )

    # DB connection is now committed. Handle the two outcomes.
    log_audit(
        "access_request_vote",
        target=device_name,
        details=f"Request #{request_id}: vote {vote_count}/{required} by {user}",
    )

    if not quorum_met:
        socketio.emit("request_vote", {
            "id": request_id,
            "voter": user,
            "vote_count": vote_count,
            "required": required,
            "voters": voters,
            "missing_required": missing_required,
        })
        logger.info("Request #%d vote %d/%d by %s (missing required: %s)",
                    request_id, vote_count, required, user, missing_required or "none")
        return jsonify({
            "status": "vote_recorded",
            "vote_count": vote_count,
            "required": required,
            "voters": voters,
            "missing_required": missing_required,
        })

    # Quorum reached - set posture attribute
    token = get_tailscale_token()
    if not token:
        return jsonify({"error": "Failed to get Tailscale access token"}), 500

    now_utc = datetime.now(timezone.utc)
    expiry_time = now_utc + timedelta(minutes=duration)
    expiry_str = expiry_time.isoformat()
    now_utc_str = now_utc.strftime("%Y-%m-%d %H:%M:%S")

    api_url = f"https://api.tailscale.com/api/v2/device/{device_id}/attributes/{profile}"
    headers_ts = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    approvers_str = ", ".join(voters)
    payload = {
        "value": True,
        "expiry": expiry_str,
        "comment": f"JIT access approved by {approvers_str}",
    }

    try:
        api_response = http_requests.post(api_url, headers=headers_ts, json=payload, timeout=15)
    except http_requests.RequestException as exc:
        logger.error("Tailscale API call failed: %s", exc)
        return jsonify({"error": "Failed to communicate with Tailscale API"}), 502

    if api_response.status_code not in (200, 201, 204):
        logger.error("Tailscale API error %d: %s", api_response.status_code, api_response.text)
        return jsonify({"error": "Tailscale API request failed"}), 500

    # Update DB: WHERE guards against TOCTOU race between final voters
    with get_db() as conn:
        cursor = conn.execute(
            """UPDATE access_requests
               SET status = 'approved', approver = ?, processed_at = ?
               WHERE id = ? AND status IN ('pending', 'partially_approved')""",
            (approvers_str, now_utc_str, request_id),
        )
        if cursor.rowcount == 0:
            logger.warning("Request #%d already fully processed (TOCTOU race)", request_id)
            return jsonify({"error": "Request was already processed"}), 409

    log_audit(
        "access_request_approved",
        target=device_name,
        details=f"Request #{request_id}: {profile} approved by {approvers_str}, expires at {expiry_str}",
    )

    try:
        socketio.emit("request_approved", {"id": request_id, "approver": approvers_str})
    except Exception:
        pass

    logger.info("Request #%d fully approved by [%s]: %s on %s expires %s",
                request_id, approvers_str, profile, device_name, expiry_str)

    return jsonify({
        "status": "approved",
        "vote_count": vote_count,
        "required": required,
        "voters": voters,
    })


@app.route("/api/deny/<int:request_id>", methods=["POST"])
@login_required
def deny_request(request_id):
    """Deny an access request."""
    if not has_permission("can_approve_requests"):
        log_audit("permission_denied", target=f"/api/deny/{request_id}",
                  details="Missing can_approve_requests")
        return jsonify({"error": "Permission denied"}), 403

    user = get_current_user()
    data = request.json or {}
    reason = str(data.get("reason", "No reason provided")).strip()

    if len(reason) > 1000:
        return jsonify({"error": "Denial reason too long"}), 400

    with get_db() as conn:
        row = conn.execute(
            "SELECT device_name, status FROM access_requests WHERE id = ?",
            (request_id,),
        ).fetchone()

        if not row:
            return jsonify({"error": "Request not found"}), 404

        if row["status"] not in ("pending", "partially_approved"):
            return jsonify({"error": f"Request already {row['status']}"}), 409

        device_name = row["device_name"]

        conn.execute(
            """UPDATE access_requests
               SET status = 'denied', approver = ?, denial_reason = ?, processed_at = ?
               WHERE id = ? AND status IN ('pending', 'partially_approved')""",
            (user, reason, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), request_id),
        )

    log_audit(
        "access_request_denied",
        target=device_name,
        details=f"Request #{request_id} denied by {user}: {reason}",
    )

    socketio.emit("request_denied", {"id": request_id, "approver": user})

    logger.info("Request #%d denied by %s: %s", request_id, user, reason)

    return jsonify({"status": "denied"})


@app.route("/api/revoke/<int:request_id>", methods=["POST"])
@login_required
def revoke_access(request_id):
    """Revoke an active access grant, removing the posture attribute immediately."""
    if not has_permission("can_approve_requests"):
        log_audit("permission_denied", target=f"/api/revoke/{request_id}",
                  details="Missing can_approve_requests")
        return jsonify({"error": "Permission denied"}), 403

    user = get_current_user()
    data = request.json or {}
    reason = str(data.get("reason", "")).strip()

    if not reason:
        return jsonify({"error": "Revocation reason is required"}), 400

    if len(reason) > 1000:
        return jsonify({"error": "Revocation reason too long"}), 400

    with get_db() as conn:
        row = conn.execute(
            "SELECT device_id, device_name, profile, duration, status, processed_at, requester "
            "FROM access_requests WHERE id = ?",
            (request_id,),
        ).fetchone()

        if not row:
            return jsonify({"error": "Request not found"}), 404

        if row["status"] != "approved":
            return jsonify({"error": f"Request is not active (status: {row['status']})"}), 409

        # Verify the grant hasn't already expired naturally
        if row["processed_at"]:
            try:
                processed_at = datetime.fromisoformat(row["processed_at"].replace("Z", "+00:00"))
                if processed_at.tzinfo is None:
                    processed_at = processed_at.replace(tzinfo=timezone.utc)
                expires_at = processed_at + timedelta(minutes=int(row["duration"]))
                if expires_at <= datetime.now(timezone.utc):
                    return jsonify({"error": "Grant has already expired"}), 409
            except (ValueError, AttributeError):
                pass

        device_id = row["device_id"]
        device_name = row["device_name"]
        profile = row["profile"]

    # Delete the posture attribute via Tailscale API
    token = get_tailscale_token()
    if not token:
        return jsonify({"error": "Failed to get Tailscale access token"}), 500

    api_url = f"https://api.tailscale.com/api/v2/device/{device_id}/attributes/{profile}"
    headers_ts = {"Authorization": f"Bearer {token}"}

    try:
        resp = http_requests.delete(api_url, headers=headers_ts, timeout=15)
    except http_requests.RequestException as exc:
        logger.error("Revoke API call failed for request #%d: %s", request_id, exc)
        return jsonify({"error": "Failed to communicate with Tailscale API"}), 502

    if resp.status_code not in (200, 204, 404):
        logger.error("Revoke API error %d for request #%d: %s",
                     resp.status_code, request_id, resp.text)
        return jsonify({"error": "Tailscale API request failed"}), 500

    # Update DB - WHERE guards against race with background worker
    with get_db() as conn:
        cursor = conn.execute(
            """UPDATE access_requests
               SET status = 'revoked', denial_reason = ?
               WHERE id = ? AND status = 'approved'""",
            (f"Revoked by {user}: {reason}", request_id),
        )
        if cursor.rowcount == 0:
            return jsonify({"error": "Request was already processed"}), 409

    log_audit(
        "access_revoked",
        target=device_name,
        details=f"Request #{request_id}: {profile} revoked by {user}: {reason}",
    )

    socketio.emit("request_revoked", {"id": request_id, "revoker": user})

    logger.info("Request #%d revoked by %s: %s", request_id, user, reason)

    return jsonify({"status": "revoked"})


# ---------------------------------------------------------------------------
# Health Check
# ---------------------------------------------------------------------------
@app.route("/healthz")
def healthz():
    """Health check endpoint for monitoring."""
    checks = {"status": "ok", "version": __version__}

    # Verify DB is accessible
    try:
        with get_db() as conn:
            conn.execute("SELECT 1").fetchone()
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {exc}"
        checks["status"] = "degraded"

    status_code = 200 if checks["status"] == "ok" else 503
    return jsonify(checks), status_code


# ---------------------------------------------------------------------------
# Background Worker: expiry + log pruning
# ---------------------------------------------------------------------------
_shutdown_event = threading.Event()


def prune_old_logs():
    """Delete audit_log and user_activity rows older than AUDIT_LOG_RETENTION_DAYS.
    Does nothing when retention is set to 0 (keep forever)."""
    if AUDIT_LOG_RETENTION_DAYS == 0:
        return
    cutoff = datetime.now(timezone.utc) - timedelta(days=AUDIT_LOG_RETENTION_DAYS)
    cutoff_str = cutoff.isoformat()
    try:
        with get_db() as conn:
            audit_deleted = conn.execute(
                "DELETE FROM audit_log WHERE timestamp < ?", (cutoff_str,)
            ).rowcount
            activity_deleted = conn.execute(
                "DELETE FROM user_activity WHERE timestamp < ?", (cutoff_str,)
            ).rowcount
        if audit_deleted or activity_deleted:
            logger.info(
                "Log pruning: removed %d audit + %d activity rows older than %d days",
                audit_deleted, activity_deleted, AUDIT_LOG_RETENTION_DAYS,
            )
    except Exception as exc:
        logger.error("Log pruning failed: %s", exc)


def revoke_expired_grants():
    """Find approved requests whose duration has elapsed and delete the posture attribute.
    Updates the DB row to status='expired' so the record remains for audit purposes."""
    now = datetime.now(timezone.utc)
    try:
        with get_db() as conn:
            rows = conn.execute(
                """SELECT id, device_id, device_name, profile, duration, processed_at, approver, requester
                   FROM access_requests
                   WHERE status = 'approved'"""
            ).fetchall()
    except Exception as exc:
        logger.error("Expiry check DB query failed: %s", exc)
        return

    if not rows:
        return

    token = get_tailscale_token()
    if not token:
        logger.warning("Expiry check: could not obtain Tailscale token; will retry next cycle")
        return

    headers_ts = {"Authorization": f"Bearer {token}"}

    for row in rows:
        if not row["processed_at"]:
            continue
        try:
            processed_at = datetime.fromisoformat(row["processed_at"].replace("Z", "+00:00"))
            if processed_at.tzinfo is None:
                processed_at = processed_at.replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            continue

        expiry = processed_at + timedelta(minutes=int(row["duration"]))
        if now < expiry:
            continue  # still valid

        # Grant has expired - delete the posture attribute
        device_id = row["device_id"]
        profile = row["profile"]
        api_url = f"https://api.tailscale.com/api/v2/device/{device_id}/attributes/{profile}"

        try:
            resp = http_requests.delete(api_url, headers=headers_ts, timeout=15)
        except http_requests.RequestException as exc:
            logger.error("Expiry revoke API call failed for request #%d: %s", row["id"], exc)
            continue  # leave as 'approved', retry next cycle

        if resp.status_code in (200, 204, 404):
            # 404 is fine - attribute already gone
            try:
                with get_db() as conn:
                    conn.execute(
                        """UPDATE access_requests SET status = 'expired'
                           WHERE id = ? AND status = 'approved'""",
                        (row["id"],),
                    )
                log_detail = (
                    f"Request #{row['id']}: {profile} on {row['device_name']} "
                    f"expired (approved by {row['approver'] or 'unknown'})"
                )
                with get_db() as conn:
                    conn.execute(
                        """INSERT INTO audit_log
                           (event_type, user, target, details, ip_address, user_agent)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        ("access_expired", row["requester"], row["device_name"],
                         log_detail, "", "background-worker"),
                    )
                logger.info("Expired grant revoked: request #%d (%s on %s)",
                            row["id"], profile, row["device_name"])
                try:
                    socketio.emit("request_expired", {"id": row["id"]})
                except Exception:
                    pass
            except Exception as exc:
                logger.error("Expiry DB update failed for request #%d: %s", row["id"], exc)
        else:
            logger.error(
                "Expiry revoke returned unexpected status %d for request #%d: %s",
                resp.status_code, row["id"], resp.text,
            )


def _background_worker():
    """Daemon thread: periodically revoke expired grants and prune old logs."""
    logger.info("Background worker started (interval: %ds)", EXPIRY_CHECK_INTERVAL)
    # Stagger initial run by a few seconds so startup isn't burdened
    _shutdown_event.wait(timeout=5)
    while not _shutdown_event.is_set():
        try:
            revoke_expired_grants()
            prune_old_logs()
        except Exception as exc:
            logger.error("Background worker unhandled exception: %s", exc)
        _shutdown_event.wait(timeout=EXPIRY_CHECK_INTERVAL)
    logger.info("Background worker stopped")


# ---------------------------------------------------------------------------
# Graceful Shutdown
# ---------------------------------------------------------------------------
def _shutdown_handler(signum, frame):
    """Handle SIGTERM/SIGINT for clean shutdown."""
    sig_name = signal.Signals(signum).name
    logger.info("Received %s: shutting down gracefully...", sig_name)
    _shutdown_event.set()
    sys.exit(0)


signal.signal(signal.SIGTERM, _shutdown_handler)
signal.signal(signal.SIGINT, _shutdown_handler)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
init_db()
prune_old_logs()  # prune at startup before serving requests
logger.info("Tailscale JIT Access v%s starting", __version__)
logger.info("Tailnet: %s | Cap domain: %s | DB: %s", TAILSCALE_TAILNET, CAP_DOMAIN, DB_PATH)
logger.info(
    "Audit retention: %s days | Page size: %d | Expiry check interval: %ds",
    AUDIT_LOG_RETENTION_DAYS if AUDIT_LOG_RETENTION_DAYS > 0 else "forever",
    AUDIT_PAGE_SIZE,
    EXPIRY_CHECK_INTERVAL,
)

# Start background worker as a daemon thread so it doesn't block clean shutdown
_worker_thread = threading.Thread(target=_background_worker, daemon=True, name="expiry-worker")
_worker_thread.start()

if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5000, debug=False, use_reloader=False)
