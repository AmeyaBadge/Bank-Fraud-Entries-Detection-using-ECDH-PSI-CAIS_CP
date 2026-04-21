"""
bank_b/db_manager.py
Blacklist, PSI responses, and users DB operations for Bank B.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import sqlite3
from datetime import datetime
import config


def _get_conn():
    if config.DB_TYPE == "sqlite":
        db_path = config.BANK_B_DB_PATH
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn
    else:
        import mysql.connector
        conn = mysql.connector.connect(
            host=config.MYSQL_HOST, port=config.MYSQL_PORT,
            user=config.MYSQL_USER, password=config.MYSQL_PASSWORD,
            database=config.MYSQL_DB_BANK_B,
        )
        return conn


def init_db():
    conn = _get_conn()
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      VARCHAR(80) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role          VARCHAR(20) NOT NULL DEFAULT 'analyst',
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS blacklist (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_identifier   TEXT NOT NULL,
            identifier_type  VARCHAR(20) NOT NULL,
            normalized_value VARCHAR(255) UNIQUE NOT NULL,
            reason           TEXT,
            severity         VARCHAR(20) DEFAULT 'MEDIUM',
            reported_by      VARCHAR(100),
            created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS psi_responses (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      VARCHAR(36),
            querier_bank    VARCHAR(50),
            items_in_query  INTEGER,
            blacklist_size  INTEGER,
            responded_at    DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()
    print("[Bank B DB] Tables initialized.")


# ─── Users ────────────────────────────────────────────────────────────────────

def create_user(username: str, password_hash: str, role: str = "analyst"):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, password_hash, role)
    )
    conn.commit()
    conn.close()


def get_user(username: str) -> dict | None:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


# ─── Blacklist ────────────────────────────────────────────────────────────────

def add_blacklist_entry(
    raw_identifier: str,
    identifier_type: str,
    normalized_value: str,
    reason: str = None,
    severity: str = "MEDIUM",
    reported_by: str = None,
) -> bool:
    """Returns True if inserted, False if duplicate."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM blacklist WHERE normalized_value = ?", (normalized_value,))
    if cur.fetchone():
        conn.close()
        return False
    now = datetime.utcnow().isoformat()
    cur.execute("""
        INSERT INTO blacklist (raw_identifier, identifier_type, normalized_value, reason, severity, reported_by, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?)
    """, (raw_identifier, identifier_type, normalized_value, reason, severity, reported_by, now, now))
    conn.commit()
    conn.close()
    return True


def get_blacklist_entry_by_id(entry_id: int) -> dict | None:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM blacklist WHERE id = ?", (entry_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def delete_blacklist_entry(entry_id: int) -> bool:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM blacklist WHERE id = ?", (entry_id,))
    deleted = cur.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def get_all_blacklist_normalized() -> list:
    """Returns list of (id, normalized_value, severity, reason, identifier_type)."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, normalized_value, severity, reason, identifier_type, raw_identifier FROM blacklist ORDER BY id")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_blacklist_count() -> int:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM blacklist")
    count = cur.fetchone()[0]
    conn.close()
    return count


def get_blacklist_page(page: int = 1, per_page: int = 50) -> dict:
    conn = _get_conn()
    cur = conn.cursor()
    offset = (page - 1) * per_page
    cur.execute("SELECT COUNT(*) FROM blacklist")
    total = cur.fetchone()[0]
    cur.execute("SELECT * FROM blacklist ORDER BY created_at DESC LIMIT ? OFFSET ?", (per_page, offset))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"total": total, "page": page, "per_page": per_page, "entries": rows}


def get_critical_count() -> int:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM blacklist WHERE severity = 'CRITICAL'")
    count = cur.fetchone()[0]
    conn.close()
    return count


def get_last_updated() -> str | None:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT updated_at FROM blacklist ORDER BY updated_at DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


def get_severity_type_breakdown() -> list:
    """Returns [{identifier_type, severity, count}] for heatmap chart."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT identifier_type, severity, COUNT(*) as count
        FROM blacklist
        GROUP BY identifier_type, severity
        ORDER BY identifier_type, severity
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


# ─── PSI Responses ────────────────────────────────────────────────────────────

def log_psi_response(session_id: str, querier_bank: str, items_in_query: int, blacklist_size: int):
    conn = _get_conn()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute("""
        INSERT INTO psi_responses (session_id, querier_bank, items_in_query, blacklist_size, responded_at)
        VALUES (?,?,?,?,?)
    """, (session_id, querier_bank, items_in_query, blacklist_size, now))
    conn.commit()
    conn.close()


def get_psi_response_history(page: int = 1, per_page: int = 20) -> dict:
    conn = _get_conn()
    cur = conn.cursor()
    offset = (page - 1) * per_page
    cur.execute("SELECT COUNT(*) FROM psi_responses")
    total = cur.fetchone()[0]
    cur.execute("SELECT * FROM psi_responses ORDER BY responded_at DESC LIMIT ? OFFSET ?", (per_page, offset))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"total": total, "page": page, "per_page": per_page, "responses": rows}


def get_query_count_last_30_days() -> int:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT COUNT(*) FROM psi_responses
        WHERE responded_at >= datetime('now', '-30 days')
    """)
    count = cur.fetchone()[0]
    conn.close()
    return count
