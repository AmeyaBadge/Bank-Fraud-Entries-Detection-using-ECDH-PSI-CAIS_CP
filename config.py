"""
config.py — Central environment configuration (single source of truth)
PSI Platform V2.0
"""

import os
import secrets

# ─── Database ────────────────────────────────────────────────────────────────
DB_TYPE = os.environ.get("DB_TYPE", "sqlite")  # 'sqlite' | 'mysql'

# SQLite paths (used when DB_TYPE == 'sqlite')
COORDINATOR_DB_PATH = os.environ.get("COORDINATOR_DB_PATH", "coordinator/coordinator.db")
BANK_A_DB_PATH      = os.environ.get("BANK_A_DB_PATH",      "bank_a/bank_a.db")
BANK_B_DB_PATH      = os.environ.get("BANK_B_DB_PATH",      "bank_b/bank_b.db")

# MySQL connection (only used when DB_TYPE == 'mysql')
MYSQL_HOST     = os.environ.get("MYSQL_HOST",     "localhost")
MYSQL_PORT     = int(os.environ.get("MYSQL_PORT", "3306"))
MYSQL_USER     = os.environ.get("MYSQL_USER",     "psi_user")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "PLACEHOLDER_MYSQL_PASSWORD")
MYSQL_DB_COORD = os.environ.get("MYSQL_DB_COORD", "psi_coordinator")
MYSQL_DB_BANK_A= os.environ.get("MYSQL_DB_BANK_A","psi_bank_a")
MYSQL_DB_BANK_B= os.environ.get("MYSQL_DB_BANK_B","psi_bank_b")

# ─── Service URLs & Ports ─────────────────────────────────────────────────────
COORDINATOR_URL  = os.environ.get("COORDINATOR_URL",  "http://127.0.0.1:5000")
BANK_A_URL       = os.environ.get("BANK_A_URL",       "http://127.0.0.1:5001")
BANK_B_URL       = os.environ.get("BANK_B_URL",       "http://127.0.0.1:5002")

COORDINATOR_PORT = int(os.environ.get("COORDINATOR_PORT", "5000"))
BANK_A_PORT      = int(os.environ.get("BANK_A_PORT",      "5001"))
BANK_B_PORT      = int(os.environ.get("BANK_B_PORT",      "5002"))

# ─── Authentication & Security ────────────────────────────────────────────────
# Shared M2M key: Bank A → Bank B PSI endpoint
PSI_API_KEY = os.environ.get("PSI_API_KEY", "changeme-bank-a-key")

# API key for Bank A / Bank B → Coordinator communication
COORDINATOR_API_KEY = os.environ.get("COORDINATOR_API_KEY", "changeme-coord-key")

# 32-byte hex key for AES-GCM encryption of severity/reason labels
# IMPORTANT: Generate a proper key before production use:
#   python -c "import secrets; print(secrets.token_hex(32))"
LABEL_ENCRYPTION_KEY = os.environ.get(
    "LABEL_ENCRYPTION_KEY",
    "PLACEHOLDER_32_BYTE_HEX_KEY_REPLACE_IN_PRODUCTION_0000000000000000"
)

# FastAPI session signing key
SESSION_SECRET_KEY = os.environ.get("SESSION_SECRET_KEY", secrets.token_hex(32))

# ─── PSI Parameters ───────────────────────────────────────────────────────────
PSI_MAX_SET_SIZE = int(os.environ.get("PSI_MAX_SET_SIZE", "50000"))
PSI_CURVE        = os.environ.get("PSI_CURVE", "P-256")

# ─── Bloom Filter (Bank B PSI-Lite) ──────────────────────────────────────────
BLOOM_FILTER_CAPACITY   = int(os.environ.get("BLOOM_FILTER_CAPACITY",   "100000"))
BLOOM_FILTER_ERROR_RATE = float(os.environ.get("BLOOM_FILTER_ERROR_RATE", "0.001"))

# ─── Celery / Redis ───────────────────────────────────────────────────────────
CELERY_BROKER_URL      = os.environ.get("CELERY_BROKER_URL",      "redis://localhost:6379/0")
CELERY_RESULT_BACKEND  = os.environ.get("CELERY_RESULT_BACKEND",  "redis://localhost:6379/0")

# ─── Default Credentials (demo only — change before any deployment) ───────────
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"
