"""
bank_a/db_manager.py
Accounts, PSI runs, audit log DB operations for Bank A.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import sqlite3
from datetime import datetime
import config


def _get_conn():
    if config.DB_TYPE == "sqlite":
        db_path = config.BANK_A_DB_PATH
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
            database=config.MYSQL_DB_BANK_A,
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

        CREATE TABLE IF NOT EXISTS accounts (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_identifier   TEXT NOT NULL,
            identifier_type  VARCHAR(20) NOT NULL,
            normalized_value VARCHAR(255) UNIQUE NOT NULL,
            label            VARCHAR(255),
            created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS psi_runs (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id         VARCHAR(36) UNIQUE NOT NULL,
            celery_task_id VARCHAR(255),
            partner_bank   VARCHAR(50) DEFAULT 'bank_b',
            items_checked  INTEGER,
            matches_found  INTEGER,
            status         VARCHAR(20) DEFAULT 'pending',
            started_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at   DATETIME
        );

        CREATE TABLE IF NOT EXISTS psi_matches (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id     VARCHAR(36) NOT NULL,
            account_id INTEGER NOT NULL,
            severity   VARCHAR(20),
            reason     TEXT,
            found_at   DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()
    print("[Bank A DB] Tables initialized.")


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


# ─── Accounts ─────────────────────────────────────────────────────────────────

def insert_account(raw_identifier: str, identifier_type: str, normalized_value: str, label: str = None):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT OR IGNORE INTO accounts (raw_identifier, identifier_type, normalized_value, label) VALUES (?,?,?,?)",
        (raw_identifier, identifier_type, normalized_value, label)
    )
    conn.commit()
    conn.close()


def get_all_accounts() -> list:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM accounts ORDER BY id")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_account_count() -> int:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM accounts")
    count = cur.fetchone()[0]
    conn.close()
    return count


def get_account_by_id(account_id: int) -> dict | None:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM accounts WHERE id = ?", (account_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def find_account_by_normalized(normalized_value: str) -> dict | None:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM accounts WHERE normalized_value = ?", (normalized_value,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


# ─── PSI Runs ─────────────────────────────────────────────────────────────────

def create_psi_run(run_id: str, celery_task_id: str = None, items_checked: int = None) -> dict:
    conn = _get_conn()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO psi_runs (run_id, celery_task_id, items_checked, status, started_at) VALUES (?,?,?,'pending',?)",
        (run_id, celery_task_id, items_checked, now)
    )
    conn.commit()
    conn.close()
    return get_psi_run(run_id)


def update_psi_run(run_id: str, status: str, matches_found: int = None, items_checked: int = None, celery_task_id: str = None):
    conn = _get_conn()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    updates = ["status = ?"]
    params = [status]
    if status in ("completed", "failed"):
        updates.append("completed_at = ?")
        params.append(now)
    if matches_found is not None:
        updates.append("matches_found = ?")
        params.append(matches_found)
    if items_checked is not None:
        updates.append("items_checked = ?")
        params.append(items_checked)
    if celery_task_id is not None:
        updates.append("celery_task_id = ?")
        params.append(celery_task_id)
    params.append(run_id)
    cur.execute(f"UPDATE psi_runs SET {', '.join(updates)} WHERE run_id = ?", params)
    conn.commit()
    conn.close()


def get_psi_run(run_id: str) -> dict | None:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM psi_runs WHERE run_id = ?", (run_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_psi_runs(page: int = 1, per_page: int = 20) -> dict:
    conn = _get_conn()
    cur = conn.cursor()
    offset = (page - 1) * per_page
    cur.execute("SELECT COUNT(*) FROM psi_runs")
    total = cur.fetchone()[0]
    cur.execute("SELECT * FROM psi_runs ORDER BY started_at DESC LIMIT ? OFFSET ?", (per_page, offset))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"total": total, "page": page, "per_page": per_page, "runs": rows}


def get_run_count() -> int:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM psi_runs WHERE status = 'completed'")
    count = cur.fetchone()[0]
    conn.close()
    return count


def get_total_matches() -> int:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(DISTINCT account_id) FROM psi_matches")
    total = cur.fetchone()[0]
    conn.close()
    return total


def get_last_run_time() -> str | None:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT started_at FROM psi_runs ORDER BY started_at DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


# ─── PSI Matches ──────────────────────────────────────────────────────────────

def insert_psi_match(run_id: str, account_id: int, severity: str, reason: str):
    conn = _get_conn()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO psi_matches (run_id, account_id, severity, reason, found_at) VALUES (?,?,?,?,?)",
        (run_id, account_id, severity, reason, now)
    )
    conn.commit()
    conn.close()


def get_matches_for_run(run_id: str) -> list:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT m.*, a.raw_identifier, a.identifier_type
        FROM psi_matches m
        JOIN accounts a ON m.account_id = a.id
        WHERE m.run_id = ?
        ORDER BY m.found_at DESC
    """, (run_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_severity_distribution() -> dict:
    """Returns {severity: count} across all-time matches."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT severity, COUNT(*) as cnt FROM psi_matches GROUP BY severity")
    result = {row["severity"]: row["cnt"] for row in cur.fetchall()}
    conn.close()
    return result


def get_recent_run_match_counts(limit: int = 10) -> list:
    """Returns [{run_id, started_at, matches_found}] for chart."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT run_id, started_at, matches_found
        FROM psi_runs
        WHERE status = 'completed'
        ORDER BY started_at DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return list(reversed(rows))


def get_latest_run_id() -> str | None:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT run_id FROM psi_runs WHERE status='completed' ORDER BY completed_at DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None
