"""
coordinator/db_manager.py
Session & node registry DB operations for the Coordinator service.
Supports SQLite (default) and MySQL.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import sqlite3
from datetime import datetime
import config


# ─── Connection Factory ────────────────────────────────────────────────────────

def _get_conn():
    if config.DB_TYPE == "sqlite":
        db_path = config.COORDINATOR_DB_PATH
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn
    else:
        import mysql.connector
        conn = mysql.connector.connect(
            host=config.MYSQL_HOST,
            port=config.MYSQL_PORT,
            user=config.MYSQL_USER,
            password=config.MYSQL_PASSWORD,
            database=config.MYSQL_DB_COORD,
        )
        return conn


# ─── Schema Init ──────────────────────────────────────────────────────────────

def init_db():
    """Create coordinator tables if they do not exist."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS nodes (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            node_name      VARCHAR(50) UNIQUE NOT NULL,
            node_url       VARCHAR(255) NOT NULL,
            api_key_hash   VARCHAR(255) NOT NULL,
            status         VARCHAR(20)  DEFAULT 'online',
            last_seen      DATETIME,
            registered_at  DATETIME     DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS psi_sessions (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id     VARCHAR(36) UNIQUE NOT NULL,
            querier_node   VARCHAR(50) NOT NULL,
            responder_node VARCHAR(50) NOT NULL,
            status         VARCHAR(20) DEFAULT 'pending',
            items_in_query INTEGER,
            matches_found  INTEGER,
            created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at   DATETIME
        );
    """)
    conn.commit()
    conn.close()
    print("[Coordinator DB] Tables initialized.")


# ─── Node Registry ────────────────────────────────────────────────────────────

def upsert_node(node_name: str, node_url: str, api_key_hash: str) -> dict:
    conn = _get_conn()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute("""
        INSERT INTO nodes (node_name, node_url, api_key_hash, status, last_seen, registered_at)
        VALUES (?, ?, ?, 'online', ?, ?)
        ON CONFLICT(node_name) DO UPDATE SET
            node_url     = excluded.node_url,
            api_key_hash = excluded.api_key_hash,
            status       = 'online',
            last_seen    = excluded.last_seen
    """, (node_name, node_url, api_key_hash, now, now))
    conn.commit()
    conn.close()
    return get_node(node_name)


def get_all_nodes() -> list:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM nodes ORDER BY registered_at")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_node(node_name: str) -> dict | None:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM nodes WHERE node_name = ?", (node_name,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def update_node_status(node_name: str, status: str):
    conn = _get_conn()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute(
        "UPDATE nodes SET status = ?, last_seen = ? WHERE node_name = ?",
        (status, now, node_name)
    )
    conn.commit()
    conn.close()


# ─── PSI Sessions ─────────────────────────────────────────────────────────────

def create_session(session_id: str, querier_node: str, responder_node: str, items_in_query: int = None) -> dict:
    conn = _get_conn()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute("""
        INSERT INTO psi_sessions (session_id, querier_node, responder_node, status, items_in_query, created_at)
        VALUES (?, ?, ?, 'pending', ?, ?)
    """, (session_id, querier_node, responder_node, items_in_query, now))
    conn.commit()
    conn.close()
    return get_session(session_id)


def get_session(session_id: str) -> dict | None:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM psi_sessions WHERE session_id = ?", (session_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def update_session(session_id: str, status: str, matches_found: int = None, items_in_query: int = None):
    conn = _get_conn()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    updates = ["status = ?", "completed_at = ?"]
    params = [status, now if status in ("completed", "failed") else None]
    if matches_found is not None:
        updates.append("matches_found = ?")
        params.append(matches_found)
    if items_in_query is not None:
        updates.append("items_in_query = ?")
        params.append(items_in_query)
    params.append(session_id)
    cur.execute(
        f"UPDATE psi_sessions SET {', '.join(updates)} WHERE session_id = ?",
        params
    )
    conn.commit()
    conn.close()


def get_sessions(page: int = 1, per_page: int = 20) -> dict:
    conn = _get_conn()
    cur = conn.cursor()
    offset = (page - 1) * per_page
    cur.execute("SELECT COUNT(*) FROM psi_sessions")
    total = cur.fetchone()[0]
    cur.execute(
        "SELECT * FROM psi_sessions ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (per_page, offset)
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"total": total, "page": page, "per_page": per_page, "sessions": rows}
