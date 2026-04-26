"""SQLite persistence layer for scan sessions, networks, and threats."""
import os
import sqlite3
from datetime import datetime, timezone

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
DB_PATH = os.path.join(DATA_DIR, "sentinel.db")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                stopped_at TEXT,
                interface  TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS networks (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                ssid       TEXT,
                bssid      TEXT,
                security   TEXT,
                standard   TEXT,
                channel    INTEGER,
                signal     INTEGER,
                flagged    INTEGER,
                vendor     TEXT,
                first_seen TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                source     TEXT,
                target     TEXT,
                reason     TEXT,
                type       TEXT,
                timestamp  TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
            )
        """)


def create_session(interface: str) -> int:
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO scan_sessions (started_at, interface) VALUES (?, ?)",
            (datetime.now(timezone.utc).isoformat(), interface),
        )
        return cur.lastrowid


def close_session(session_id: int) -> None:
    if session_id is None:
        return
    with _connect() as conn:
        conn.execute(
            "UPDATE scan_sessions SET stopped_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), session_id),
        )


def save_network(session_id: int, network: dict) -> None:
    if session_id is None:
        return
    security = network.get("Security") or network.get("security", "")
    flagged = network.get("flagged")
    if flagged is None:
        flagged = "WEP" in security or "Open" in security
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO networks
                (session_id, ssid, bssid, security, standard, channel,
                 signal, flagged, vendor, first_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                network.get("SSID") or network.get("ssid"),
                network.get("BSSID") or network.get("bssid"),
                security or None,
                network.get("Standard") or network.get("standard"),
                network.get("Channel") or network.get("channel"),
                network.get("Signal") or network.get("signal"),
                int(bool(flagged)),
                network.get("vendor"),
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def save_threat(session_id: int, entry: dict, threat_type: str) -> None:
    if session_id is None:
        return
    reason = entry.get("reason")
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO threats (session_id, source, target, reason, type, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                entry.get("source"),
                entry.get("target"),
                str(reason) if reason is not None else None,
                threat_type,
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def get_sessions() -> list:
    with _connect() as conn:
        rows = conn.execute("""
            SELECT
                s.id, s.started_at, s.stopped_at, s.interface,
                COUNT(DISTINCT n.id) AS network_count,
                COUNT(DISTINCT t.id) AS threat_count
            FROM scan_sessions s
            LEFT JOIN networks n ON n.session_id = s.id
            LEFT JOIN threats  t ON t.session_id = s.id
            GROUP BY s.id
            ORDER BY s.started_at DESC
        """).fetchall()
        return [dict(r) for r in rows]


def get_session_networks(session_id: int) -> list:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM networks WHERE session_id = ? ORDER BY first_seen",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_session_threats(session_id: int) -> list:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM threats WHERE session_id = ? ORDER BY timestamp",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]
