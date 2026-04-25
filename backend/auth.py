"""Authentication: SQLite user store, session helpers, and a login_required decorator."""
import os
import sqlite3
import secrets
from datetime import datetime
from functools import wraps

from flask import jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DB_PATH = os.path.join(DATA_DIR, "users.db")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL
            )
            """
        )


def user_count() -> int:
    with _connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def create_user(username: str, password: str) -> None:
    username = username.strip()
    if not username or not password:
        raise ValueError("username and password required")
    with _connect() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), datetime.utcnow().isoformat()),
        )


def verify_user(username: str, password: str) -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    return bool(row) and check_password_hash(row["password_hash"], password)


def bootstrap_admin() -> None:
    """On first run, seed an admin account from env or print generated credentials."""
    if user_count() > 0:
        return
    username = os.environ.get("SENTINEL_ADMIN_USER", "admin")
    password = os.environ.get("SENTINEL_ADMIN_PASSWORD")
    generated = False
    if not password:
        password = secrets.token_urlsafe(12)
        generated = True
    create_user(username, password)
    print("=" * 60, flush=True)
    print(" Wi-Fi Sentinel: admin account created", flush=True)
    print(f"   username: {username}", flush=True)
    if generated:
        print(f"   password: {password}    (one-time — save it now)", flush=True)
    else:
        print("   password: <from SENTINEL_ADMIN_PASSWORD>", flush=True)
    print("=" * 60, flush=True)


def login_required(view):
    """Reject unauthenticated requests with 401 JSON."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"error": "authentication required"}), 401
        return view(*args, **kwargs)
    return wrapped


def current_user() -> str | None:
    return session.get("user")
