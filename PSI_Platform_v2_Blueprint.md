# Privacy-Preserving Fraud Detection Platform
## Full-System Design & Implementation Blueprint
**Version 2.0 | Cryptography & Information Security — Course Project**
*Powered by ECDH-PSI • FastAPI • Celery + Redis • Chart.js*

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture](#2-system-architecture)
3. [Cryptography Engine — ECDH-PSI](#3-cryptography-engine--ecdh-psi)
4. [Coordinator Service](#4-coordinator-service-port-5000)
5. [Bank A Node — The Querier](#5-bank-a-node--the-querier-port-5001)
6. [Bank B Node — The Responder](#6-bank-b-node--the-responder-port-5002)
7. [Asynchronous Task System — Celery + Redis](#7-asynchronous-task-system--celery--redis)
8. [Synthetic Data Generator](#8-synthetic-data-generator)
9. [Frontend & Dashboards](#9-frontend--dashboards)
10. [Configuration & Environment](#10-configuration--environment)
11. [Local Setup & Run Guide](#11-local-setup--run-guide)
12. [Security Model](#12-security-model)
13. [Algorithm & Concept Glossary](#13-algorithm--concept-glossary)

---

## 1. Executive Summary

This document is the complete system design and implementation blueprint for Version 2.0 of the Privacy-Preserving Fraud Detection Platform. It describes every module, data flow, API contract, database schema, and UI component required to build a fully functional, showcase-grade local system.

The system solves a real-world problem in inter-bank fraud detection: two banks cannot share plaintext customer data due to GDPR and RBI data protection mandates. Using **Elliptic Curve Diffie-Hellman Private Set Intersection (ECDH-PSI)**, the platform allows Bank A to discover which of its customers appear on Bank B's fraud blacklist without either bank ever seeing the other's raw data.

> **Core Guarantee:** Zero plaintext customer data is ever transmitted over the network at any point during the PSI protocol.

### 1.1 What's New in Version 2.0

| Feature | V1 (Existing) | V2 (This Blueprint) |
|---|---|---|
| Cryptography Engine | DH-PSI over 2048-bit prime fields | ECDH-PSI over NIST P-256 curve (10–50x faster) |
| Web Framework | Flask (synchronous) | FastAPI (async, auto OpenAPI/Swagger docs) |
| Architecture | 2-node peer-to-peer (hardcoded) | 3-node: Coordinator + Bank A + Bank B |
| Task Execution | Synchronous (browser blocks) | Async via Celery + Redis (live progress bar) |
| Real-Time Lookup | Not implemented | PSI-Lite single-account endpoint (<100ms) |
| Test Data | Manual seed script | Faker-based synthetic generator (Indian profiles) |
| Dashboard | Bootstrap tables only | Bootstrap + Chart.js (donut, bar, heatmap charts) |

---

## 2. System Architecture

### 2.1 High-Level Architecture

Version 2.0 introduces a **three-node architecture**. A dedicated Coordinator service is added alongside the two bank nodes. Banks register themselves with the Coordinator on startup, and all PSI session lifecycle management flows through it. The bank nodes remain completely memory-isolated — they share no in-process state and communicate exclusively via JSON REST APIs over localhost.

**Node assignment:**
- **Coordinator Service — Port 5000.** Handles node registration, PSI session creation, health checks, and routing metadata.
- **Bank A Node — Port 5001.** The Querier. Holds customer accounts. Initiates PSI runs.
- **Bank B Node — Port 5002.** The Responder. Holds the fraud blacklist. Responds to PSI requests.

### 2.2 Folder Structure

```
/PSI_Platform_v2/
├── coordinator/
│   ├── app.py                  # FastAPI app — node registry, session management
│   ├── db_manager.py           # Session & node registry DB operations
│   └── templates/              # Coordinator dashboard (network topology view)
│       └── index.html
├── bank_a/
│   ├── app.py                  # FastAPI app — querier endpoints & UI routes
│   ├── db_manager.py           # Accounts, PSI runs, audit log DB operations
│   ├── tasks.py                # Celery task definitions (async PSI batch run)
│   └── templates/              # Bank A dashboard (Chart.js visualizations)
│       ├── login.html
│       ├── dashboard.html
│       ├── history.html
│       └── lookup.html
├── bank_b/
│   ├── app.py                  # FastAPI app — responder endpoints & UI routes
│   ├── db_manager.py           # Blacklist, PSI responses DB operations
│   └── templates/              # Bank B dashboard (blacklist mgmt, CSV upload)
│       ├── login.html
│       └── dashboard.html
├── psi_core/
│   ├── ecdh_engine.py          # ECDH-PSI querier/responder logic (NIST P-256)
│   ├── bloom_filter.py         # Probabilistic Bloom Filter (optimized from V1)
│   ├── crypto_utils.py         # EC point serialization, hashing helpers
│   └── data_normalizer.py      # Identifier normalization (unchanged from V1)
├── data_generator/
│   ├── generate.py             # Faker-based synthetic data generator
│   └── seed_config.json        # Configurable seed, overlap count, data type mix
├── config.py                   # Central environment configuration (single source of truth)
├── celery_worker.py            # Celery worker entry point
└── requirements.txt            # All Python dependencies with pinned versions
```

### 2.3 Module Interaction — Batch PSI Flow (Step-by-Step)

This sequence describes a complete batch PSI run from UI trigger to result display:

1. **Bank A user clicks "Run PSI Check"** on the dashboard.
2. **Bank A's FastAPI handler** validates the session and enqueues a Celery task. It immediately returns `{ "task_id": "uuid" }`. The browser does NOT block.
3. **The Celery worker** picks up the task. It fetches all accounts from Bank A's database via `db_manager.py` and normalizes them via `data_normalizer.py`.
4. **The worker** passes identifiers to `psi_core/ecdh_engine.py` (`PSIQuerier`). Each identifier is hashed to a point on the NIST P-256 elliptic curve and multiplied by Bank A's ephemeral private scalar: `P(X) * a`.
5. **The worker** serializes the EC points and sends them to Bank B's `/api/psi/exchange` endpoint via an authenticated HTTP POST with `X-PSI-API-Key` header.
6. **Bank B's `PSIResponder`** receives the payload. It double-multiplies Bank A's points: `(P(X)*a)*b`. It also encrypts its own blacklist: `P(Y)*b`. It returns both serialized point arrays alongside AES-GCM encrypted metadata labels.
7. **The Celery worker** receives Bank B's response. It double-multiplies Bank B's blacklist: `(P(Y)*b)*a`.
8. **Intersection:** Because `(P(X)*a)*b == (P(Y)*b)*a` if and only if `X == Y`, the worker computes the set intersection. Matched records are written to the `psi_matches` table. The PSI run record is updated to `completed`.
9. **The Bank A dashboard's polling loop** detects task completion via `GET /api/task-status/{task_id}` and re-renders the results table and all Chart.js visualizations automatically.

---

## 3. Cryptography Engine — ECDH-PSI

### 3.1 Why Elliptic Curves Over Prime Fields

Version 1 used modular exponentiation over a 2048-bit Diffie-Hellman prime group (RFC 3526). While cryptographically correct, this is slow: for a 10,000-item dataset, it requires 10,000 bignum exponentiations per party on 2048-bit integers, even with multiprocessing.

ECDH-PSI replaces modular exponentiation with **elliptic curve scalar multiplication** on the NIST P-256 curve. Security equivalence: 256-bit EC keys provide approximately the same security as 3072-bit RSA/DH keys — so V2 is more secure AND faster.

| Metric | V1: DH-PSI (RFC 3526) | V2: ECDH-PSI (P-256) |
|---|---|---|
| Private key size | 2048-bit integer | 256-bit scalar |
| Core operation | `H(x)^a mod p` (bignum exponentiation) | `H(x) * a` (EC scalar multiplication) |
| Speed (10K records) | ~11 seconds (with multiprocessing) | ~1.5 seconds (single process) |
| Security level | ~112-bit equivalent | ~128-bit equivalent |
| Library | Standard Python `math` | `cryptography` (PyCA) |
| Wire payload | Large integer JSON arrays | Compressed EC points (33 bytes each) |

### 3.2 The ECDH Commutativity Property

The mathematical foundation of PSI is the **commutativity of scalar multiplication** on elliptic curves. For a base point `P` derived from hashing an identifier, and private scalars `a` (Bank A) and `b` (Bank B):

```
(P * a) * b  ==  (P * b) * a
```

This means both parties can apply their private scalars in any order and reach the **exact same final EC point**. This is the property that makes the intersection comparison in Step 8 work with zero plaintext transfer.

### 3.3 `psi_core/ecdh_engine.py` — Class Design

#### Class: `PSIQuerier` (used by Bank A)

```python
class PSIQuerier:
    def __init__(self):
        # Generates a fresh random 256-bit ephemeral private scalar using os.urandom(32).
        # This key is NEVER stored to disk, never logged, never transmitted.
        ...

    def hash_to_curve(self, identifier: str) -> ECPoint:
        # Hashes a normalized string identifier using SHA-256, then maps
        # the digest to a valid P-256 point using the hash-to-curve method
        # (try-and-increment / RFC 9380 compatible).
        ...

    def encrypt_set(self, identifiers: list[str]) -> list[bytes]:
        # Applies hash_to_curve() + scalar multiplication by 'a' to each identifier.
        # Returns list of serialized compressed EC points (33 bytes each, base64 encoded).
        # Uses ProcessPoolExecutor to parallelize across CPU cores for sets > 1000 items.
        ...

    def double_encrypt_remote(self, remote_points: list[bytes]) -> list[bytes]:
        # Takes Bank B's P(Y)*b serialized points and multiplies by 'a'.
        # Produces (P(Y)*b)*a for intersection comparison.
        ...

    def find_intersection(
        self,
        double_enc_own: list[bytes],
        double_enc_remote: list[bytes],
        originals: list[str]
    ) -> list[str]:
        # Converts both double-encrypted lists to sets and computes Python set intersection.
        # Returns the original plaintext identifiers for the matched EC points.
        ...
```

#### Class: `PSIResponder` (used by Bank B)

```python
class PSIResponder:
    def __init__(self):
        # Generates its own fresh ephemeral private scalar 'b'.
        ...

    def process_query(self, querier_points: list[bytes]) -> list[bytes]:
        # Takes Bank A's P(X)*a points, multiplies by 'b'.
        # Returns (P(X)*a)*b — Bank A's set double-encrypted.
        ...

    def encrypt_blacklist(self, identifiers: list[str]) -> list[bytes]:
        # Encrypts Bank B's own blacklist identifiers.
        # Returns P(Y)*b for each entry.
        # Uses ProcessPoolExecutor for parallelism.
        ...
```

> **Important — Ephemeral Keys:** Both `PSIQuerier` and `PSIResponder` generate fresh ephemeral private keys per PSI session. Keys are never persisted to disk or database. This provides **perfect forward secrecy** — compromising a past session's key reveals nothing about future sessions.

### 3.4 `psi_core/crypto_utils.py`

Helper functions used by the engine:

- `serialize_point(point: ECPoint) -> bytes` — Compresses and serializes an EC point to 33 bytes.
- `deserialize_point(data: bytes) -> ECPoint` — Deserializes and validates a point lies on P-256.
- `encrypt_label(plaintext: str, key: bytes) -> str` — AES-GCM encryption for severity/reason metadata.
- `decrypt_label(ciphertext: str, key: bytes) -> str` — AES-GCM decryption for received labels.

### 3.5 `psi_core/data_normalizer.py`

Ensures that formatting differences in raw input don't break cryptographic matching. The same identifier must always produce the same EC point regardless of how it was entered.

```python
def normalize(raw_string: str, identifier_type: str) -> str:
    # 'email'          → lowercase, strip whitespace
    # 'phone'          → strip all non-numeric characters, remove leading country code
    # 'account_number' → strip all non-alphanumeric characters, uppercase
    # 'aadhaar'        → strip all non-numeric characters (12 digits only)
    ...
```

---

## 4. Coordinator Service (Port 5000)

### 4.1 Purpose & Responsibilities

The Coordinator is a **lightweight FastAPI service** that acts as the network's control plane. It does **NOT** participate in PSI cryptography — it has zero access to ciphertexts or customer data. Its sole responsibilities are:

- **Node Registry:** Maintaining a live record of which bank nodes are online, their URLs, and their hashed API keys.
- **Session Management:** Creating, tracking, and expiring PSI session records with unique session IDs (UUID4).
- **Health Monitoring:** Periodically pinging registered nodes and surfacing their status on the network topology dashboard.
- **Session Audit Trail:** Logging PSI session start/end events and item counts (no PII).

### 4.2 Coordinator API Endpoints

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| `POST` | `/api/nodes/register` | Bank node self-registers on startup (name, url, api_key_hash). | None (startup only) |
| `GET` | `/api/nodes` | Returns all registered nodes and their health status. | Coordinator API Key |
| `POST` | `/api/sessions` | Creates a new PSI session record, returns `session_id`. | Coordinator API Key |
| `PATCH` | `/api/sessions/{id}` | Updates session status: `running / completed / failed`. | Coordinator API Key |
| `GET` | `/api/sessions` | Paginated list of all past PSI sessions. | Coordinator API Key |
| `GET` | `/api/health` | Coordinator own liveness check. | None |
| `GET` | `/` | Network topology dashboard (HTML page). | Browser session |

### 4.3 Coordinator Database Schema

#### Table: `nodes`

| Column | Type | Description |
|---|---|---|
| `id` | `INTEGER PK` | Auto-increment primary key |
| `node_name` | `VARCHAR(50) UNIQUE` | e.g., `'bank_a'`, `'bank_b'` |
| `node_url` | `VARCHAR(255)` | Base URL including port, e.g., `http://127.0.0.1:5001` |
| `api_key_hash` | `VARCHAR(255)` | SHA-256 hash of the node's API key (never store plaintext) |
| `status` | `VARCHAR(20)` | `online / offline / degraded` |
| `last_seen` | `DATETIME` | Timestamp of last successful health ping |
| `registered_at` | `DATETIME` | First registration timestamp |

#### Table: `psi_sessions`

| Column | Type | Description |
|---|---|---|
| `id` | `INTEGER PK` | Auto-increment primary key |
| `session_id` | `VARCHAR(36) UNIQUE` | UUID4 — shared reference identifier across all three nodes |
| `querier_node` | `VARCHAR(50)` | FK reference to `nodes.node_name` |
| `responder_node` | `VARCHAR(50)` | FK reference to `nodes.node_name` |
| `status` | `VARCHAR(20)` | `pending / running / completed / failed` |
| `items_in_query` | `INTEGER` | Count of identifiers sent (just a number, no PII) |
| `matches_found` | `INTEGER` | Count of intersection results (NULL until completed) |
| `created_at` | `DATETIME` | Session creation timestamp |
| `completed_at` | `DATETIME` | Session completion timestamp (NULL until done) |

---

## 5. Bank A Node — The Querier (Port 5001)

### 5.1 Overview

Bank A represents the investigating financial institution. It holds a population of customer accounts it wishes to screen against Bank B's blacklist. Bank A **initiates** all PSI runs and is the **only party** that ever sees the final intersection results in plaintext.

### 5.2 Bank A API Endpoints

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| `POST` | `/api/psi/run-batch` | Enqueues Celery batch PSI task. Returns `{ task_id }` immediately. | Session cookie |
| `POST` | `/api/psi/lookup` | PSI-Lite: real-time single-account check. Returns match result. | Session cookie |
| `GET` | `/api/task-status/{task_id}` | Polls Celery task: `PENDING / PROGRESS / SUCCESS / FAILURE` + progress %. | Session cookie |
| `GET` | `/api/psi/history` | Paginated PSI run history records. | Session cookie |
| `POST` | `/ui/login` | Authenticates user, sets session cookie. | None |
| `POST` | `/ui/logout` | Clears session cookie. | Session cookie |
| `GET` | `/` | Bank A main dashboard (HTML). | Session cookie |
| `GET` | `/history` | PSI run history page (HTML). | Session cookie |
| `GET` | `/lookup` | Single account lookup page (HTML). | Session cookie |

### 5.3 Celery Batch Task — `task_run_psi_batch` (in `bank_a/tasks.py`)

This is the core async task. Its full execution flow:

1. Update Celery state → `PROGRESS 0%` — "Fetching accounts from database..."
2. Fetch all records from `accounts` table via `db_manager.get_all_accounts()`.
3. Normalize all identifiers via `data_normalizer.normalize()`.
4. Update Celery state → `PROGRESS 20%` — "Encrypting set with ECDH (NIST P-256)..."
5. Instantiate `PSIQuerier`. Call `querier.encrypt_set()` — spawns `ProcessPoolExecutor` workers.
6. Update Celery state → `PROGRESS 50%` — "Exchanging encrypted sets with Bank B..."
7. `POST` serialized EC points to Bank B's `/api/psi/exchange` with `X-PSI-API-Key` header. Include `session_id` from Coordinator.
8. Receive Bank B's response: `{ double_encrypted_query, encrypted_blacklist, encrypted_labels }`.
9. Update Celery state → `PROGRESS 75%` — "Computing intersection, writing results..."
10. Call `querier.double_encrypt_remote()` on `encrypted_blacklist`.
11. Call `querier.find_intersection()` — compare the two double-encrypted sets.
12. Decrypt `severity` / `reason` labels using `crypto_utils.decrypt_label()` with shared `LABEL_ENCRYPTION_KEY`.
13. Write results to `psi_runs` and `psi_matches` tables.
14. `PATCH /api/sessions/{session_id}` on Coordinator with `status=completed`, `matches_found=N`.
15. Return Celery result: `{ "status": "SUCCESS", "run_id": "uuid", "matches_found": N }`.

### 5.4 PSI-Lite — Real-Time Single Account Lookup (`/api/psi/lookup`)

Provides sub-100ms fraud screening for a single identifier. This is the endpoint a compliance officer's tool would call during customer onboarding.

**Key differences from batch PSI:**
- No Celery queue — the operation is synchronous since it involves only one EC point multiplication per side.
- Bank B uses a **pre-computed Bloom Filter** (rebuilt whenever the blacklist is updated) for near-instant membership testing, rather than re-encrypting the full blacklist per request.
- Bank B's `/api/psi/bloom-query` endpoint is called instead of `/api/psi/exchange`.

**Request body:**
```json
{
  "identifier": "john@email.com",
  "identifier_type": "email"
}
```

**Response body:**
```json
{
  "is_match": true,
  "lookup_id": "uuid4",
  "latency_ms": 87
}
```

Note: The response intentionally does NOT return severity or reason for PSI-Lite, to prevent Bank A from using single lookups to enumerate Bank B's blacklist metadata.

### 5.5 Bank A Database Schema

#### Table: `users`

| Column | Type | Notes |
|---|---|---|
| `id` | `INTEGER PK` | |
| `username` | `VARCHAR(80) UNIQUE NOT NULL` | |
| `password_hash` | `VARCHAR(255) NOT NULL` | Bcrypt via Werkzeug `generate_password_hash` |
| `role` | `VARCHAR(20) NOT NULL` | `'admin'` or `'analyst'` |
| `created_at` | `DATETIME` | |

#### Table: `accounts`

| Column | Type | Notes |
|---|---|---|
| `id` | `INTEGER PK` | |
| `raw_identifier` | `TEXT NOT NULL` | Original input before normalization (for UI display) |
| `identifier_type` | `VARCHAR(20) NOT NULL` | `'email'`, `'phone'`, `'account_number'`, `'aadhaar'` |
| `normalized_value` | `VARCHAR(255) UNIQUE NOT NULL` | Lowercased / stripped value used for EC hashing |
| `label` | `VARCHAR(255)` | Optional internal label (e.g., customer name — NOT ever shared) |
| `created_at` | `DATETIME` | |

#### Table: `psi_runs`

| Column | Type | Notes |
|---|---|---|
| `id` | `INTEGER PK` | |
| `run_id` | `VARCHAR(36) UNIQUE` | UUID4 — matches Coordinator `session_id` |
| `celery_task_id` | `VARCHAR(255)` | Celery task UUID for status polling |
| `partner_bank` | `VARCHAR(50)` | `'bank_b'` |
| `items_checked` | `INTEGER` | Total accounts in Bank A's set for this run |
| `matches_found` | `INTEGER` | Number of intersection hits |
| `status` | `VARCHAR(20)` | `pending / running / completed / failed` |
| `started_at` | `DATETIME` | |
| `completed_at` | `DATETIME` | NULL until task finishes |

#### Table: `psi_matches`

| Column | Type | Notes |
|---|---|---|
| `id` | `INTEGER PK` | |
| `run_id` | `VARCHAR(36)` | FK to `psi_runs.run_id` |
| `account_id` | `INTEGER` | FK to `accounts.id` — the matched Bank A account |
| `severity` | `VARCHAR(20)` | Decrypted from Bank B: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `reason` | `TEXT` | Decrypted reason label from Bank B |
| `found_at` | `DATETIME` | Timestamp of match discovery |

---

## 6. Bank B Node — The Responder (Port 5002)

### 6.1 Overview

Bank B is the central fraud authority. It maintains the master blacklist of known fraudulent identifiers annotated with severity levels and reason codes. Bank B responds to PSI exchange requests but **never learns which of its blacklist entries matched** — it only knows the count of items queried.

### 6.2 Bank B API Endpoints

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| `POST` | `/api/psi/exchange` | Core PSI endpoint. Receives Bank A's encrypted set, returns double-encrypted sets + labels. | `X-PSI-API-Key` header |
| `POST` | `/api/psi/bloom-query` | PSI-Lite. Receives single encrypted point, checks Bloom Filter, returns match boolean. | `X-PSI-API-Key` header |
| `POST` | `/api/blacklist/add` | Adds a single entry to the blacklist. | Session cookie (admin) |
| `POST` | `/api/blacklist/upload-csv` | Bulk CSV upload. Parses, normalizes, and batch-inserts entries. | Session cookie (admin) |
| `DELETE` | `/api/blacklist/{id}` | Removes a blacklist entry by ID. | Session cookie (admin) |
| `GET` | `/api/queries/history` | Paginated list of incoming PSI query logs. | Session cookie |
| `GET` | `/` | Bank B dashboard (HTML). | Session cookie |

### 6.3 PSI Exchange Handler — `/api/psi/exchange` (Security-Critical)

On receiving a request, the handler executes in this exact order:

1. Validate `X-PSI-API-Key` header. Reject with HTTP `403` if invalid.
2. Validate request body with Pydantic schema: `querier_bank` (str), `session_id` (UUID str), `encrypted_set` (list of base64 strings).
3. Check `len(encrypted_set) <= PSI_MAX_SET_SIZE` from `config.py`. Reject oversized payloads with HTTP `413`.
4. Deserialize each base64 string to an EC point. **Validate each point lies on P-256 curve.** Reject invalid points with HTTP `422` to prevent invalid-curve attacks.
5. Instantiate `PSIResponder`. Call `process_query()` on Bank A's points (double-encrypts them). Call `encrypt_blacklist()` on Bank B's blacklist. Both use `ProcessPoolExecutor`.
6. Encrypt `severity` and `reason` labels for matched metadata using `AES-GCM` with `LABEL_ENCRYPTION_KEY` from `config.py`.
7. Log query metadata to `psi_responses` table: `session_id`, `querier_bank`, `items_in_query` count, `blacklist_size`. **No actual identifiers are logged.**
8. Return JSON: `{ "double_encrypted_query": [...], "encrypted_blacklist": [...], "encrypted_labels": {...} }`.

### 6.4 CSV Bulk Upload — `/api/blacklist/upload-csv`

Accepts `multipart/form-data` with a `.csv` file. Expected CSV columns:

```
identifier, identifier_type, severity, reason, reported_by
```

Processing pipeline:
1. Parse CSV using Python's `csv` module. Skip header row.
2. Validate required columns are present. Return error report if missing.
3. For each row: call `data_normalizer.normalize()` → check for duplicates via `SELECT` on `normalized_value` → insert only new entries.
4. Return a summary JSON: `{ "inserted": N, "skipped_duplicates": M, "errors": [...] }`.

### 6.5 Bank B Database Schema

#### Table: `users`

| Column | Type | Notes |
|---|---|---|
| `id` | `INTEGER PK` | |
| `username` | `VARCHAR(80) UNIQUE NOT NULL` | |
| `password_hash` | `VARCHAR(255) NOT NULL` | |
| `role` | `VARCHAR(20) NOT NULL` | `'admin'` or `'analyst'` |
| `created_at` | `DATETIME` | |

#### Table: `blacklist`

| Column | Type | Notes |
|---|---|---|
| `id` | `INTEGER PK` | |
| `raw_identifier` | `TEXT NOT NULL` | Original input string |
| `identifier_type` | `VARCHAR(20) NOT NULL` | `'email'`, `'phone'`, `'account_number'`, `'aadhaar'` |
| `normalized_value` | `VARCHAR(255) UNIQUE NOT NULL` | Used for Bloom Filter insertion and EC hashing |
| `reason` | `TEXT` | Human-readable fraud reason. Encrypted in API responses. |
| `severity` | `VARCHAR(20)` | `'LOW'`, `'MEDIUM'`, `'HIGH'`, `'CRITICAL'` |
| `reported_by` | `VARCHAR(100)` | Source bank or department |
| `created_at` | `DATETIME` | |
| `updated_at` | `DATETIME` | Last modification timestamp |

#### Table: `psi_responses`

| Column | Type | Notes |
|---|---|---|
| `id` | `INTEGER PK` | |
| `session_id` | `VARCHAR(36)` | Matches Coordinator `psi_sessions.session_id` |
| `querier_bank` | `VARCHAR(50)` | Name of requesting bank node |
| `items_in_query` | `INTEGER` | Count of identifiers in Bank A's set (**no actual data stored**) |
| `blacklist_size` | `INTEGER` | Size of blacklist at time of response |
| `responded_at` | `DATETIME` | |

> **Privacy Note:** The `psi_responses` table intentionally has NO column to store Bank A's identifiers. Bank B is architecturally prevented from logging or retaining what it was queried against. This is a deliberate schema design decision.

---

## 7. Asynchronous Task System — Celery + Redis

### 7.1 Why Async Tasks

A batch PSI run on 10,000 accounts involves thousands of EC scalar multiplications plus a network round-trip to Bank B. A synchronous HTTP request would either timeout or freeze the browser. Celery solves this by making PSI runs true **background jobs**.

### 7.2 Component Roles

- **Redis:** Acts as both the Celery message broker (queues task messages) and the result backend (stores task state and results). Run on default port `6379`.
- **Celery Worker:** A separate Python process (`celery_worker.py`) that listens to the Redis queue and executes `psi_batch_run` tasks.
- **FastAPI Endpoint:** `/api/psi/run-batch` calls `task.delay()` and immediately returns `{ "task_id": "..." }` in under 50ms regardless of dataset size.
- **Polling Endpoint:** `GET /api/task-status/{task_id}` queries Celery's result backend and returns current state + progress percentage for the frontend progress bar.

### 7.3 Task Progress States

The Celery task uses `update_state()` to report fine-grained progress through named stages:

| Stage | Progress % | Status Message Displayed in UI |
|---|---|---|
| 1. Fetching accounts | 0–10% | Fetching accounts from database... |
| 2. Normalizing identifiers | 10–20% | Normalizing {N} identifiers... |
| 3. EC encryption (Bank A) | 20–50% | Encrypting set with ECDH (NIST P-256)... |
| 4. PSI Exchange (Bank B) | 50–75% | Exchanging encrypted sets with Bank B... |
| 5. Computing intersection | 75–100% | Computing intersection, writing results... |

### 7.4 `GET /api/task-status/{task_id}` — Response Schema

```json
{
  "task_id": "celery-uuid",
  "state": "PROGRESS",
  "progress": 65,
  "message": "Exchanging encrypted sets with Bank B...",
  "result": null
}
```

On completion (`state: "SUCCESS"`):
```json
{
  "task_id": "celery-uuid",
  "state": "SUCCESS",
  "progress": 100,
  "message": "Completed",
  "result": {
    "run_id": "session-uuid",
    "matches_found": 47,
    "items_checked": 10000,
    "duration_seconds": 1.8
  }
}
```

### 7.5 Run Commands

Three processes must be running simultaneously. Open three terminal windows:

```bash
# Terminal 1 — Start Redis
redis-server

# Terminal 2 — Start Celery Worker (from project root)
celery -A celery_worker worker --loglevel=info --concurrency=4

# Terminal 3 — Start all three FastAPI apps
python -m coordinator.app &
python -m bank_a.app &
python -m bank_b.app
```

---

## 8. Synthetic Data Generator

### 8.1 Purpose

The data generator creates **realistic, reproducible Indian banking profiles** for both nodes. It injects a controlled, known overlap between Bank A's customers and Bank B's blacklist, making PSI demo results predictable and verifiable on every run.

### 8.2 `seed_config.json`

```json
{
  "seed": 42,
  "bank_a_total_accounts": 10000,
  "bank_b_blacklist_size": 2000,
  "overlap_count": 500,
  "identifier_mix": {
    "email": 0.40,
    "phone": 0.35,
    "account_number": 0.15,
    "aadhaar": 0.10
  },
  "severity_distribution": {
    "CRITICAL": 0.10,
    "HIGH": 0.25,
    "MEDIUM": 0.40,
    "LOW": 0.25
  }
}
```

Change `seed` to get a different but equally reproducible dataset. The same seed always produces the exact same 10,000 profiles.

### 8.3 `generate.py` — Implementation Details

- **Seeded Faker instance:** `Faker('en_IN', seed=config['seed'])` ensures identical data on every run.
- **Indian profile realism:** `Faker('en_IN')` generates localized names (e.g., Priya Sharma, Rohit Verma), Indian mobile numbers (`+91 98XXXXXXXX`), and Indian email patterns.
- **Aadhaar-format IDs:** Generated as 12-digit numeric strings in `XXXX-XXXX-XXXX` format. These are NOT real Aadhaar numbers — purely synthetic identifiers.
- **Account numbers:** 16-digit numeric strings prefixed with a fictional bank code.
- **Overlap injection:** The first `overlap_count` entries of Bank A's set are intentionally duplicated into Bank B's blacklist with randomly assigned severity/reason codes. This guarantees a known ground truth for verifying PSI correctness.
- **Output:** Writes directly to both node databases via `db_manager.py` using batch `INSERT` statements. Prints a summary report after completion.

### 8.4 Running the Generator

```bash
# Default run (uses seed_config.json values)
python -m data_generator.generate

# Custom overlap for demo impact
python -m data_generator.generate --overlap 750

# Wipe and regenerate
python -m data_generator.generate --reset
```

### 8.5 Fraud Reason Codes Used

| Code | Description | Typical Severity |
|---|---|---|
| `MONEY_LAUNDERING` | Suspicious high-value transaction patterns | CRITICAL / HIGH |
| `IDENTITY_THEFT` | Account opened with stolen credentials | HIGH |
| `CHARGEBACK_FRAUD` | Excessive disputed transactions | MEDIUM |
| `PHISHING_OPERATOR` | Number associated with phishing campaigns | HIGH |
| `SYNTHETIC_IDENTITY` | Identity created from fabricated PII | CRITICAL |
| `ACCOUNT_TAKEOVER` | Unauthorized access to existing account | HIGH |
| `LOAN_DEFAULT` | Defaulted on multiple institutional loans | MEDIUM |
| `MULE_ACCOUNT` | Account used to funnel fraud proceeds | HIGH |

---

## 9. Frontend & Dashboards

### 9.1 Shared Design System

All three node UIs share a common design language. No build step or Node.js required — all assets loaded via CDN.

- **Framework:** Bootstrap 5.3 (CDN) + FontAwesome 6 icons
- **Charts:** Chart.js 4.x (CDN, vanilla JS)
- **Templates:** Jinja2 via FastAPI's `Jinja2Templates`
- **CSS Variables:** `--navy: #0A1628`, `--blue: #1A3A6B`, `--accent: #2563EB`, `--red: #DC2626`
- **Aesthetic:** Glassmorphic dark/light card layout from V1, extended with chart panels

### 9.2 Bank A Dashboard — Pages & Components

#### Main Dashboard (`/`)

- **KPI Cards Row:** Total Monitored Accounts | Total PSI Runs | Total Matches Found | Last Run Timestamp. Each card has an icon and subtle gradient background.
- **Live Progress Section:** Shown only when a PSI task is active. Displays an animated Bootstrap progress bar (0–100%) driven by polling `/api/task-status/{task_id}` every 2 seconds via `setInterval()`. Disappears on completion and triggers a page data refresh.
- **Run PSI Button:** Prominent CTA. On click: POSTs to `/api/psi/run-batch`, receives `task_id`, starts polling loop, shows progress section.
- **Match Results Table:** Displays the most recent PSI run's matched accounts. Columns: Identifier (masked — only last 4 chars shown), Type, Severity (color-coded badge: red/orange/yellow/green), Reason, Detected At. Sortable by severity.
- **Donut Chart (Chart.js):** Severity breakdown of all-time matches: CRITICAL (red), HIGH (orange), MEDIUM (yellow), LOW (green). Rendered in sidebar card.
- **Bar Chart (Chart.js):** Match count per PSI run over the last 10 runs. X-axis: run dates, Y-axis: match count. Visualizes fraud detection trend over time.

#### History Page (`/history`)

Paginated table of all PSI runs. Columns: Run ID (truncated UUID), Date, Accounts Checked, Matches Found, Duration (seconds), Status badge. Clicking a row expands an accordion section showing all matched identifiers for that run.

#### Single Lookup Page (`/lookup`)

A simple form with a text input (identifier value) and a dropdown (type: email / phone / account / aadhaar). On submit: POSTs to `/api/psi/lookup`. Result displayed inline with color-coded feedback:
- Green card: "✓ No Match — Account is Clean"
- Red card: "✗ MATCH FOUND — Flagged on Blacklist"

### 9.3 Bank B Dashboard — Pages & Components

#### Main Dashboard (`/`)

- **KPI Cards:** Total Blacklist Entries | Queries Received (last 30 days) | CRITICAL Entries Count | Last Updated Timestamp.
- **Blacklist Management Panel:** Two-tab layout.
  - *Tab 1 — Manual Entry:* Form fields: identifier value, type, severity dropdown, reason text, reported_by. Submit button calls `/api/blacklist/add`.
  - *Tab 2 — CSV Upload:* Drag-and-drop file zone. On file select: previews first 5 rows, shows column mapping. Submit button calls `/api/blacklist/upload-csv`. Displays insert/skip/error counts after completion.
- **Severity Heatmap (Chart.js):** Grouped bar chart showing blacklist entry count by `(identifier_type × severity)`. Instantly shows, for example, how many CRITICAL phone numbers vs CRITICAL emails exist.
- **Query History Log:** Paginated table of incoming PSI queries: session_id (truncated), querier_bank, items_in_query count, blacklist_size at time of query, timestamp. **No customer identifiers are shown** — by design.

### 9.4 Coordinator Dashboard (`/`)

Minimal network topology page:

- **Node Status Cards:** One card per registered node. Shows: name, URL, status indicator (animated green dot = online, red = offline), last_seen timestamp.
- **Session Feed:** Live table of the last 20 PSI sessions. Status badges: RUNNING (blue spinner), COMPLETED (green), FAILED (red). Auto-refreshes every 5 seconds.

---

## 10. Configuration & Environment

### 10.1 `config.py` — All Configuration Variables

| Variable | Default | Description |
|---|---|---|
| `DB_TYPE` | `'sqlite'` | `'sqlite'` for local dev, `'mysql'` for production |
| `COORDINATOR_URL` | `'http://127.0.0.1:5000'` | Base URL for the Coordinator service |
| `BANK_A_URL` | `'http://127.0.0.1:5001'` | Bank A base URL |
| `BANK_B_URL` | `'http://127.0.0.1:5002'` | Bank B base URL |
| `COORDINATOR_PORT` | `5000` | Coordinator FastAPI server port |
| `BANK_A_PORT` | `5001` | Bank A FastAPI server port |
| `BANK_B_PORT` | `5002` | Bank B FastAPI server port |
| `PSI_API_KEY` | `'changeme-bank-a-key'` | Shared API key for Bank A → Bank B M2M auth |
| `COORDINATOR_API_KEY` | `'changeme-coord-key'` | API key for node → Coordinator auth |
| `LABEL_ENCRYPTION_KEY` | 32-byte hex string | AES-GCM key for encrypting severity/reason labels |
| `PSI_MAX_SET_SIZE` | `50000` | Maximum items in a PSI request (DDoS guard) |
| `CELERY_BROKER_URL` | `'redis://localhost:6379/0'` | Redis connection string for Celery broker |
| `CELERY_RESULT_BACKEND` | `'redis://localhost:6379/0'` | Redis connection string for Celery results |
| `SESSION_SECRET_KEY` | random 32-byte hex | FastAPI session signing key |
| `PSI_CURVE` | `'P-256'` | Elliptic curve identifier |
| `BLOOM_FILTER_CAPACITY` | `100000` | Max entries for Bloom Filter (Bank B) |
| `BLOOM_FILTER_ERROR_RATE` | `0.001` | False positive rate for Bloom Filter (0.1%) |

### 10.2 `requirements.txt`

```
fastapi>=0.111.0
uvicorn[standard]>=0.30.0
jinja2>=3.1.0
python-multipart>=0.0.9
pydantic>=2.7.0
werkzeug>=3.0.0
cryptography>=42.0.0
celery[redis]>=5.4.0
redis>=5.0.0
requests>=2.31.0
mysql-connector-python>=9.0.0
faker>=25.0.0
bitarray>=2.9.0
mmh3>=4.1.0
```

---

## 11. Local Setup & Run Guide

### 11.1 Prerequisites

- Python 3.11 or higher
- Redis server installed and running on port 6379
  - **macOS:** `brew install redis && brew services start redis`
  - **Ubuntu/Debian:** `sudo apt install redis-server && sudo systemctl start redis`
  - **Windows:** Install WSL2 and run Redis inside it, or use the official Redis Windows port.
- Git (for cloning)

### 11.2 Step-by-Step Setup

**Step 1 — Clone and create virtual environment:**
```bash
git clone <repo_url> PSI_Platform_v2
cd PSI_Platform_v2
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
```

**Step 2 — Install all dependencies:**
```bash
pip install -r requirements.txt
```

**Step 3 — Initialize databases (SQLite — no MySQL needed for local demo):**
```bash
python -c "from coordinator.db_manager import init_db; init_db()"
python -c "from bank_a.db_manager import init_db; init_db()"
python -c "from bank_b.db_manager import init_db; init_db()"
```

**Step 4 — Generate synthetic data (seeds both nodes: 10,000 Bank A accounts + 2,000 Bank B blacklist entries, 500 known overlaps):**
```bash
python -m data_generator.generate
```

**Step 5 — Start Redis (new terminal):**
```bash
redis-server
```

**Step 6 — Start Celery worker (new terminal):**
```bash
celery -A celery_worker worker --loglevel=info
```

**Step 7 — Start the three FastAPI servers (three terminals or use `&`):**
```bash
python -m coordinator.app   # port 5000
python -m bank_a.app        # port 5001
python -m bank_b.app        # port 5002
```

**Step 8 — Open dashboards:**
```
Coordinator : http://127.0.0.1:5000
Bank A      : http://127.0.0.1:5001
Bank B      : http://127.0.0.1:5002
```

> **Default credentials for both Bank A and Bank B — Username:** `admin` **| Password:** `admin123`

### 11.3 Demo Script (Suggested Walkthrough)

1. Open **Bank B** dashboard → show the blacklist (2,000 entries, various severities).
2. Open **Bank A** dashboard → show 10,000 monitored accounts.
3. Click **"Run PSI Check"** on Bank A dashboard → watch the progress bar move through 5 stages.
4. After ~2 seconds: results appear — 500 matches with severity badges and reason codes.
5. Open **Bank A Lookup** page → type a known matched email → show instant PSI-Lite result (<100ms).
6. Open **Coordinator** dashboard → show the session log with the completed PSI session entry.
7. Open **FastAPI Swagger docs** at `http://127.0.0.1:5001/docs` → show auto-generated API documentation.

---

## 12. Security Model

### 12.1 Threat Model — Honest-but-Curious Adversary

The system is designed against an **Honest-but-Curious (semi-honest) adversary model**: each party follows the protocol steps correctly but will analyze all data they receive to learn as much as possible about the other party's data.

The ECDH-PSI protocol is **provably secure** under this model assuming the hardness of the Elliptic Curve Discrete Logarithm Problem (ECDLP).

### 12.2 Threat Mitigations

| Threat | Mitigation |
|---|---|
| Bank B learns Bank A's full customer list | Bank A sends only EC points `P(X)*a`. Without scalar `a`, Bank B cannot reverse these to plaintext. Computationally infeasible under ECDLP hardness. |
| Bank A learns Bank B's full blacklist | Bank B sends back EC points only. Bank A can only identify matches that correspond to identifiers it already holds — it cannot enumerate unknown blacklist entries. |
| Network eavesdropper intercepts PSI payload | All data in transit is cryptographic ciphertext (serialized EC points). A full packet capture reveals nothing about underlying identifiers. |
| Unauthorized node calls Bank B's PSI endpoint | `X-PSI-API-Key` header validation on every request to `/api/psi/exchange`. Invalid keys return HTTP 403 before any computation begins. |
| DDoS via giant PSI request payload | `PSI_MAX_SET_SIZE` config variable hard-limits payload. Oversized requests rejected with HTTP 413 before deserialization. |
| Invalid-curve point injection attack | Bank B validates every received EC point lies on P-256 before using it. Invalid points rejected with HTTP 422. |
| UI session hijacking | Session cookies signed with `SESSION_SECRET_KEY`. All state-changing endpoints require authenticated session. |

### 12.3 Known Limitations (Honest Scope for Demo)

- **Malicious Responder Attack:** A fully malicious Bank B could send a pre-computed encrypted list of all possible phone numbers to perform a dictionary attack and reconstruct Bank A's full customer set. Mitigating this requires Zero-Knowledge Proofs of set membership — out of scope for this project and unsolved in simple PSI variants.
- **No TLS in Local Mode:** Inter-node HTTP traffic is unencrypted in local demo mode. A production deployment would require HTTPS with valid TLS certificates on all services.
- **Single Shared API Key:** Current M2M auth uses one shared API key. A production system would use per-node asymmetric key pairs with certificate-based mutual authentication (mTLS).

---

## 13. Algorithm & Concept Glossary

| Term | Definition |
|---|---|
| **PSI — Private Set Intersection** | A cryptographic protocol allowing two parties to compute the intersection of their private datasets without revealing any elements that are NOT in the intersection. |
| **ECDH — Elliptic Curve Diffie-Hellman** | A key agreement protocol based on the difficulty of the Elliptic Curve Discrete Logarithm Problem (ECDLP). Used here for its commutative scalar multiplication property. |
| **NIST P-256** | A standardized elliptic curve (also called `secp256r1`) defined by NIST. Provides 128-bit security. Natively supported by Python's `cryptography` library. |
| **Hash-to-Curve** | The process of deterministically mapping an arbitrary string (like an email address) to a valid point on an elliptic curve, required before applying ECDH scalar multiplication. |
| **Scalar Multiplication** | The core EC operation: repeatedly adding a point P to itself k times, written as `k*P`. The discrete logarithm problem states: given `P` and `k*P`, finding `k` is computationally infeasible. |
| **Commutativity** | The property that `(P*a)*b == (P*b)*a` for EC scalar multiplication. The entire PSI intersection comparison depends on this property holding. |
| **Bloom Filter** | A space-efficient probabilistic data structure answering set membership queries in O(1) time with a configurable false positive rate and zero false negatives. Used in PSI-Lite for fast single-account lookups. |
| **Celery** | A distributed task queue for Python that runs computationally heavy operations as async background jobs in separate worker processes, decoupled from the web server. |
| **Ephemeral Key** | A cryptographic key generated fresh for each session and discarded immediately after use. Provides perfect forward secrecy. |
| **AES-GCM** | Advanced Encryption Standard in Galois/Counter Mode. An authenticated encryption scheme providing both confidentiality and integrity. Used to encrypt severity/reason metadata labels in PSI exchange responses. |
| **Honest-but-Curious** | A security model where parties are assumed to follow the protocol steps correctly but will attempt to learn as much as possible from every message they legitimately receive. |
| **Perfect Forward Secrecy** | A property where compromise of a long-term key does not compromise past session keys. Achieved here by using fresh ephemeral keys per PSI session. |

---

*End of Document — PSI Platform V2.0 System Blueprint*
