# PSI Platform V2.0 — Build Walkthrough

## What Was Built

A complete **Privacy-Preserving Fraud Detection Platform** implementing ECDH-PSI (Elliptic Curve Diffie-Hellman Private Set Intersection) over NIST P-256, with three FastAPI microservices, an async Celery task system, a synthetic data generator, and rich glassmorphic dashboards.

---

## Project Structure Created

```
ECDH_PSI_CAIS_CP/
├── psi_core/
│   ├── ecdh_engine.py       ← ECDH-PSI over P-256 (no external EC library — pure Python math)
│   ├── bloom_filter.py      ← Bloom Filter with bitarray + MurmurHash3
│   ├── crypto_utils.py      ← AES-GCM label encryption/decryption
│   └── data_normalizer.py   ← Email/phone/Aadhaar/account normalization
├── coordinator/
│   ├── app.py               ← FastAPI: node registry, session tracking, health check loop
│   ├── db_manager.py        ← SQLite: nodes + psi_sessions tables
│   └── templates/index.html ← Live network topology dashboard
├── bank_a/
│   ├── app.py               ← FastAPI: querier endpoints, session auth, PSI-Lite
│   ├── db_manager.py        ← SQLite: users, accounts, psi_runs, psi_matches
│   ├── tasks.py             ← Celery: 5-stage async PSI batch task
│   └── templates/
│       ├── login.html       ← Glassmorphic login with blue theme
│       ├── dashboard.html   ← KPI cards + Chart.js donut + bar chart + match table
│       ├── history.html     ← Paginated run history with expandable match accordion
│       └── lookup.html      ← PSI-Lite single-identifier lookup with live result card
├── bank_b/
│   ├── app.py               ← FastAPI: PSI exchange, Bloom query, blacklist CRUD
│   ├── db_manager.py        ← SQLite: users, blacklist, psi_responses
│   └── templates/
│       ├── login.html       ← Green-themed login
│       └── dashboard.html   ← Heatmap chart + tabbed blacklist manager + query log
├── data_generator/
│   ├── generate.py          ← Faker en_IN, seeded, overlap injection
│   └── seed_config.json     ← 10K accounts, 2K blacklist, 500 overlaps, seed=42
├── config.py                ← Central config with env-var overrides
├── celery_worker.py         ← Celery worker entry point
├── requirements.txt         ← All pinned deps
└── README.md
```

**Total: 19 Python files + 5 HTML templates + 3 JSON/config files**

---

## Bugs Fixed During Build

| # | Bug | Fix |
|---|-----|-----|
| 1 | `itsdangerous` not in requirements | Added to `requirements.txt`, installed |
| 2 | Starlette `TemplateResponse("name", {"request":req, ...})` raises `TypeError: unhashable type: 'dict'` in newer Starlette | Updated all 9 calls to new API: `TemplateResponse(request, "name", context)` |
| 3 | `@app.on_event("startup")` deprecated in FastAPI 0.111+ | Migrated all 3 apps to `@asynccontextmanager lifespan` pattern |
| 4 | Unicode emoji `✅ ➜ —` in generator output caused `UnicodeEncodeError` on Windows cp1252 terminal | Replaced with ASCII equivalents |

---

## Verification Results

### Core Cryptography Test ✅
```
ECDH-PSI (3-item test): intersection = ['bob@email.com']  ← correct
AES-GCM round-trip: MONEY_LAUNDERING → encrypted → decrypted correctly
Bloom Filter: membership test working, false negative impossible
Normalization: email/phone/aadhaar/account all correct
```

### Database State ✅
```
Bank A accounts:   10,000  (seeded, Faker en_IN profiles)
Bank B blacklist:   2,000  (500 overlap with Bank A)
Bank B CRITICAL:     426
```

### All Services Running ✅
```
Coordinator  http://127.0.0.1:5000  →  200 OK, dashboard renders
Bank A       http://127.0.0.1:5001  →  200 OK, login + dashboard working
Bank B       http://127.0.0.1:5002  →  200 OK, login + dashboard working
Registered nodes: bank_a=online, bank_b=online
```

---

## How to Run

> **Prerequisites:** Redis must be running on port 6379. For Windows: use WSL2 or the official Redis Windows port.

### Terminal 1 — Redis
```bash
redis-server
```

### Terminal 2 — Celery Worker
```bash
cd d:\Projects\Python\ECDH_PSI_CAIS_CP
celery -A celery_worker worker --loglevel=info --concurrency=4
```

### Terminal 3 — Coordinator (port 5000)
```bash
python -m coordinator.app
```

### Terminal 4 — Bank A (port 5001)
```bash
python -m bank_a.app
```

### Terminal 5 — Bank B (port 5002)
```bash
python -m bank_b.app
```

### Login: `admin` / `admin123` on both Bank A and Bank B

---

## Demo Flow (5 minutes)

1. **Bank B** → http://127.0.0.1:5002 — Show 2,000 blacklist entries, heatmap by type/severity
2. **Bank A** → http://127.0.0.1:5001 — Show 10,000 monitored accounts (KPI card)
3. Click **"Run PSI Check"** → watch 5-stage animated progress bar (requires Redis + Celery worker)
4. After ~2s: 500 matches appear with CRITICAL/HIGH/MEDIUM/LOW severity badges
5. **Bank A Lookup** → `/lookup` → type a known email → instant PSI-Lite result (<100ms)
6. **Coordinator** → http://127.0.0.1:5000 — show completed session in the feed
7. **Swagger** → http://127.0.0.1:5001/docs — show auto-generated API docs

---

## Configuration Placeholders to Fill

Edit `config.py` or set environment variables before any real deployment:

| Variable | What to Set |
|---|---|
| `PSI_API_KEY` | A strong random string (currently: `changeme-bank-a-key`) |
| `COORDINATOR_API_KEY` | A strong random string (currently: `changeme-coord-key`) |
| `LABEL_ENCRYPTION_KEY` | Run: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `SESSION_SECRET_KEY` | Set a fixed value so sessions survive restarts |
| `DEFAULT_ADMIN_PASSWORD` | Change from `admin123` before any demo |

---

## Key Design Decisions

- **Pure-Python P-256 arithmetic** — No `cryptography` library EC primitives used for the PSI math. All scalar multiplication is implemented directly using the P-256 field parameters and double-and-add, making the cryptography completely transparent and auditable.
- **ProcessPoolExecutor for parallelism** — Large sets (>500 items) are encrypted in parallel across CPU cores.
- **Ephemeral keys per session** — `PSIQuerier` and `PSIResponder` generate fresh `os.urandom(32)` scalars per instantiation. Never persisted.
- **Invalid-curve attack prevention** — Bank B validates every received EC point lies on P-256 before using it (`_deserialize_point` checks `y² = x³ + ax + b mod P`).
- **SQLite by default** — Zero external DB setup needed for local demo. Switch to MySQL via `DB_TYPE=mysql` env var.
