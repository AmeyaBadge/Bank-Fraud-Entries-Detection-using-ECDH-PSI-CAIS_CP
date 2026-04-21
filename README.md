# Privacy-Preserving Fraud Detection Platform
## Version 2.0 — ECDH-PSI · FastAPI · Celery + Redis · Chart.js

> **Course Project — Cryptography & Information Security**
> *Demonstrates ECDH Private Set Intersection (PSI) for inter-bank fraud detection without sharing plaintext data.*

---

## Quick Start

```bash
# 1. Create & activate virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Initialize all three databases
python -c "from coordinator.db_manager import init_db; init_db()"
python -c "from bank_a.db_manager import init_db; init_db()"
python -c "from bank_b.db_manager import init_db; init_db()"

# 4. Generate synthetic data (10,000 Bank A accounts + 2,000 Bank B blacklist, 500 overlaps)
python -m data_generator.generate

# 5. Start Redis (WSL2 or Windows Redis port)
redis-server

# 6. Start Celery worker (new terminal)
celery -A celery_worker worker --loglevel=info

# 7. Start all three FastAPI services (three terminals)
python -m coordinator.app   # http://127.0.0.1:5000
python -m bank_a.app        # http://127.0.0.1:5001
python -m bank_b.app        # http://127.0.0.1:5002
```

**Default login:** `admin` / `admin123`

---

## Project Structure

```
ECDH_PSI_CAIS_CP/
├── coordinator/          # Coordinator service (port 5000)
│   ├── app.py
│   ├── db_manager.py
│   └── templates/index.html
├── bank_a/               # Bank A — Querier (port 5001)
│   ├── app.py
│   ├── db_manager.py
│   ├── tasks.py          # Celery async PSI task
│   └── templates/
│       ├── login.html
│       ├── dashboard.html
│       ├── history.html
│       └── lookup.html
├── bank_b/               # Bank B — Responder (port 5002)
│   ├── app.py
│   ├── db_manager.py
│   └── templates/
│       ├── login.html
│       └── dashboard.html
├── psi_core/             # Cryptography engine
│   ├── ecdh_engine.py    # ECDH-PSI over NIST P-256
│   ├── bloom_filter.py   # Bloom Filter for PSI-Lite
│   ├── crypto_utils.py   # AES-GCM label encryption
│   └── data_normalizer.py
├── data_generator/
│   ├── generate.py
│   └── seed_config.json
├── config.py             # Central configuration
├── celery_worker.py      # Celery worker entry point
└── requirements.txt
```

---

## Architecture

```
Browser
  │
  ├─▶ Bank A Dashboard (port 5001)
  │     │ Celery task enqueued
  │     ▼
  │   Celery Worker ──▶ Bank B /api/psi/exchange (port 5002)
  │     │                      │  Returns double-encrypted sets + encrypted labels
  │     ▼                      │
  │   Intersection computed ◀──┘
  │     │ Results written to Bank A DB
  │     ▼
  │   UI re-renders with match table + charts
  │
  ├─▶ Bank B Dashboard (port 5002)
  │     Blacklist management, CSV upload, query history
  │
  └─▶ Coordinator Dashboard (port 5000)
        Node registry, session feed, health monitoring
```

---

## Key Configuration (`config.py`)

| Variable | Default | Notes |
|---|---|---|
| `PSI_API_KEY` | `changeme-bank-a-key` | **Change before any deployment** |
| `COORDINATOR_API_KEY` | `changeme-coord-key` | **Change before any deployment** |
| `LABEL_ENCRYPTION_KEY` | placeholder | Generate: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `SESSION_SECRET_KEY` | auto-generated | Regenerated each restart (sessions invalidated) |
| `PSI_MAX_SET_SIZE` | 50000 | DDoS guard on payload size |
| `BLOOM_FILTER_ERROR_RATE` | 0.001 | 0.1% false positive rate |

Set via environment variables or edit `config.py` directly for local demo.

---

## Data Generator Options

```bash
python -m data_generator.generate              # Default (500 overlaps)
python -m data_generator.generate --overlap 750  # Custom overlap for bigger demo impact
python -m data_generator.generate --reset      # Wipe data and regenerate
```

---

## API Documentation

FastAPI auto-generates Swagger docs:
- Coordinator: http://127.0.0.1:5000/docs
- Bank A:       http://127.0.0.1:5001/docs
- Bank B:       http://127.0.0.1:5002/docs

---

## Security Model

- **ECDH-PSI over NIST P-256** — 128-bit security level, ~10× faster than 2048-bit DH
- **Zero plaintext transfer** — only EC points traverse the network
- **Ephemeral keys** — fresh random scalars per PSI session (perfect forward secrecy)
- **Invalid-curve attack prevention** — Bank B validates every received point lies on P-256
- **AES-GCM** — authenticated encryption for severity/reason metadata labels
- **Honest-but-Curious adversary model** — provably secure under ECDLP hardness assumption

---

*PSI Platform V2.0 — Cryptography & Information Security Course Project*
