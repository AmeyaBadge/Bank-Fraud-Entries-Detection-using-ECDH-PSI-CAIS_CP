"""
bank_b/app.py
FastAPI Bank B Node — Responder endpoints and UI routes.
Runs on port 5002.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import csv, io, hashlib, uuid, json
from datetime import datetime

import uvicorn, requests
from fastapi import FastAPI, HTTPException, Request, Depends, Form, Header, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from werkzeug.security import generate_password_hash, check_password_hash
from pydantic import BaseModel

import config
import bank_b.db_manager as db
from psi_core.ecdh_engine import PSIResponder, _deserialize_point, P, N
from psi_core.bloom_filter import BloomFilter
from psi_core.data_normalizer import normalize
from psi_core.crypto_utils import encrypt_label

# ─── App Setup ────────────────────────────────────────────────────────────────

app = FastAPI(title="Bank B — PSI Responder", version="2.0.0")
app.add_middleware(SessionMiddleware, secret_key=config.SESSION_SECRET_KEY)

templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

# Global Bloom Filter (rebuilt on startup and after blacklist changes)
_bloom_filter: BloomFilter = None


def _rebuild_bloom():
    global _bloom_filter
    entries = db.get_all_blacklist_normalized()
    bf = BloomFilter(
        capacity=config.BLOOM_FILTER_CAPACITY,
        error_rate=config.BLOOM_FILTER_ERROR_RATE,
    )
    for entry in entries:
        bf.add(entry["normalized_value"])
    _bloom_filter = bf
    print(f"[Bank B] Bloom Filter rebuilt with {len(bf)} entries.")


@app.on_event("startup")
async def startup():
    db.init_db()
    if not db.get_user(config.DEFAULT_ADMIN_USERNAME):
        pw_hash = generate_password_hash(config.DEFAULT_ADMIN_PASSWORD)
        db.create_user(config.DEFAULT_ADMIN_USERNAME, pw_hash, "admin")
    _rebuild_bloom()
    _register_with_coordinator()


def _register_with_coordinator():
    try:
        api_key_hash = hashlib.sha256(config.PSI_API_KEY.encode()).hexdigest()
        requests.post(
            f"{config.COORDINATOR_URL}/api/nodes/register",
            json={"node_name": "bank_b", "node_url": config.BANK_B_URL, "api_key_hash": api_key_hash},
            timeout=5,
        )
    except Exception as e:
        print(f"[Bank B] Could not register with coordinator: {e}")


# ─── Auth Helpers ─────────────────────────────────────────────────────────────

def get_current_user(request: Request) -> dict:
    username = request.session.get("username")
    if not username:
        return None
    return db.get_user(username)


def require_auth(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_admin(request: Request):
    user = get_current_user(request)
    if not user or user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


def validate_psi_api_key(x_psi_api_key: str = Header(None)):
    if x_psi_api_key != config.PSI_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid PSI API key")
    return x_psi_api_key


# ─── Health ───────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "bank_b", "timestamp": datetime.utcnow().isoformat()}


# ─── Auth Routes ──────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/ui/login")
async def do_login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = db.get_user(username)
    if not user or not check_password_hash(user["password_hash"], password):
        return templates.TemplateResponse(request, "login.html", {"error": "Invalid credentials"})
    request.session["username"] = user["username"]
    request.session["role"] = user["role"]
    return RedirectResponse("/", status_code=303)


@app.post("/ui/logout")
async def do_logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ─── UI Routes ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, page: int = 1):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")
    bl_count      = db.get_blacklist_count()
    critical_count= db.get_critical_count()
    query_count   = db.get_query_count_last_30_days()
    last_updated  = db.get_last_updated()
    bl_data       = db.get_blacklist_page(page=page, per_page=50)
    heatmap_data  = db.get_severity_type_breakdown()
    query_history = db.get_psi_response_history(page=1, per_page=10)
    return templates.TemplateResponse(request, "dashboard.html", {
        "user": user,
        "bl_count": bl_count,
        "critical_count": critical_count,
        "query_count": query_count,
        "last_updated": last_updated,
        "entries": bl_data["entries"],
        "total_entries": bl_data["total"],
        "page": page,
        "heatmap_data": json.dumps(heatmap_data),
        "query_history": query_history["responses"],
    })


# ─── Blacklist Management API ─────────────────────────────────────────────────

class BlacklistAddRequest(BaseModel):
    identifier: str
    identifier_type: str
    severity: str = "MEDIUM"
    reason: str = ""
    reported_by: str = ""


@app.post("/api/blacklist/add")
async def add_blacklist(req: BlacklistAddRequest, request: Request):
    require_admin(request)
    try:
        norm = normalize(req.identifier, req.identifier_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    inserted = db.add_blacklist_entry(
        raw_identifier=req.identifier,
        identifier_type=req.identifier_type,
        normalized_value=norm,
        reason=req.reason,
        severity=req.severity.upper(),
        reported_by=req.reported_by,
    )
    if inserted:
        _rebuild_bloom()
        return {"message": "Entry added", "inserted": True}
    return {"message": "Duplicate — already exists", "inserted": False}


@app.post("/api/blacklist/upload-csv")
async def upload_csv(request: Request, file: UploadFile = File(...)):
    require_admin(request)
    content = await file.read()
    try:
        text = content.decode("utf-8-sig")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode CSV as UTF-8")

    reader = csv.DictReader(io.StringIO(text))
    required_cols = {"identifier", "identifier_type"}
    if not required_cols.issubset(set(reader.fieldnames or [])):
        raise HTTPException(
            status_code=400,
            detail=f"CSV must have columns: {required_cols}. Got: {reader.fieldnames}"
        )

    inserted = skipped = 0
    errors = []
    for i, row in enumerate(reader, start=2):
        try:
            norm = normalize(row["identifier"].strip(), row["identifier_type"].strip().lower())
            ok = db.add_blacklist_entry(
                raw_identifier=row["identifier"].strip(),
                identifier_type=row["identifier_type"].strip().lower(),
                normalized_value=norm,
                reason=row.get("reason", "").strip(),
                severity=(row.get("severity", "MEDIUM") or "MEDIUM").upper().strip(),
                reported_by=row.get("reported_by", "").strip(),
            )
            if ok:
                inserted += 1
            else:
                skipped += 1
        except Exception as e:
            errors.append(f"Row {i}: {e}")

    _rebuild_bloom()
    return {"inserted": inserted, "skipped_duplicates": skipped, "errors": errors}


@app.delete("/api/blacklist/{entry_id}")
async def delete_blacklist(entry_id: int, request: Request):
    require_admin(request)
    ok = db.delete_blacklist_entry(entry_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Entry not found")
    _rebuild_bloom()
    return {"message": "Deleted", "id": entry_id}


@app.get("/api/queries/history")
async def query_history(request: Request, page: int = 1):
    require_auth(request)
    return db.get_psi_response_history(page=page)


# ─── PSI Core API ─────────────────────────────────────────────────────────────

class PSIExchangeRequest(BaseModel):
    querier_bank: str
    session_id: str
    encrypted_set: list  # list of base64-encoded compressed EC points


@app.post("/api/psi/exchange")
async def psi_exchange(req: PSIExchangeRequest, _=Depends(validate_psi_api_key)):
    # 1. Size guard
    if len(req.encrypted_set) > config.PSI_MAX_SET_SIZE:
        raise HTTPException(status_code=413, detail=f"Payload exceeds PSI_MAX_SET_SIZE ({config.PSI_MAX_SET_SIZE})")

    # 2. Deserialize and validate every point is on P-256 (invalid-curve attack prevention)
    querier_points = []
    for i, pt_str in enumerate(req.encrypted_set):
        try:
            pt = _deserialize_point(pt_str.encode() if isinstance(pt_str, str) else pt_str)
            querier_points.append(pt_str)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Invalid EC point at index {i}: {e}")

    # 3. Fetch blacklist
    blacklist_entries = db.get_all_blacklist_normalized()
    blacklist_ids = [e["normalized_value"] for e in blacklist_entries]

    # 4. PSIResponder
    responder = PSIResponder()
    double_enc_query = responder.process_query([
        pt.encode() if isinstance(pt, str) else pt for pt in querier_points
    ])
    enc_blacklist = responder.encrypt_blacklist(blacklist_ids)

    # 5. Encrypt labels (severity + reason) per blacklist entry
    encrypted_labels = {}
    for entry, enc_pt in zip(blacklist_entries, enc_blacklist):
        enc_key = enc_pt.decode("utf-8") if isinstance(enc_pt, bytes) else enc_pt
        try:
            encrypted_labels[enc_key] = {
                "severity": encrypt_label(entry.get("severity") or "MEDIUM", config.LABEL_ENCRYPTION_KEY),
                "reason":   encrypt_label(entry.get("reason")   or "Fraud detected", config.LABEL_ENCRYPTION_KEY),
            }
        except Exception:
            encrypted_labels[enc_key] = {
                "severity": encrypt_label("MEDIUM", config.LABEL_ENCRYPTION_KEY),
                "reason":   encrypt_label("Fraud detected", config.LABEL_ENCRYPTION_KEY),
            }

    # 6. Log (no PII stored)
    db.log_psi_response(
        session_id=req.session_id,
        querier_bank=req.querier_bank,
        items_in_query=len(req.encrypted_set),
        blacklist_size=len(blacklist_ids),
    )

    # 7. Serialize response
    double_enc_query_str = [
        pt.decode("utf-8") if isinstance(pt, bytes) else pt
        for pt in double_enc_query
    ]
    enc_blacklist_str = [
        pt.decode("utf-8") if isinstance(pt, bytes) else pt
        for pt in enc_blacklist
    ]

    return {
        "double_encrypted_query": double_enc_query_str,
        "encrypted_blacklist": enc_blacklist_str,
        "encrypted_labels": encrypted_labels,
    }


class BloomQueryRequest(BaseModel):
    encrypted_point: str  # Bank A's P(X)*a base64 point
    querier_bank: str


@app.post("/api/psi/bloom-query")
async def bloom_query(req: BloomQueryRequest, _=Depends(validate_psi_api_key)):
    """
    PSI-Lite: checks if the given encrypted point (after Bank B processes it)
    appears in the pre-computed Bloom Filter.
    Bank B applies its scalar and checks the resulting point.
    """
    global _bloom_filter
    if _bloom_filter is None:
        _rebuild_bloom()

    # Re-encrypt Bank A's point with Bank B's scalar
    responder = PSIResponder()
    pt_bytes = req.encrypted_point.encode() if isinstance(req.encrypted_point, str) else req.encrypted_point
    try:
        double_enc = responder.process_query([pt_bytes])
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid EC point: {e}")

    # Get all normalized blacklist values and check via Bloom Filter
    # For PSI-Lite, we use the Bloom Filter on normalized_values directly
    # The proper PSI-Lite approach: Bank A hashes+encrypts the identifier,
    # Bank B checks it against Bloom Filter of its own encrypted blacklist.
    # Here we use a simplified but secure approach:
    # We check if the double-encrypted point matches any in our double-encrypted bloom set.
    
    # Actually, for PSI-Lite we use the Bloom Filter on normalized identifiers.
    # Bank B cannot reverse the point to plaintext, so we compare double-encrypted points.
    # We pre-encrypt the blacklist with the same responder scalar and build a fast set.
    enc_bl = responder.encrypt_blacklist(
        [e["normalized_value"] for e in db.get_all_blacklist_normalized()]
    )
    enc_bl_set = set(
        pt.decode("utf-8") if isinstance(pt, bytes) else pt for pt in enc_bl
    )
    double_enc_str = double_enc[0].decode("utf-8") if isinstance(double_enc[0], bytes) else double_enc[0]

    is_match = double_enc_str in enc_bl_set
    return {"is_match": is_match}


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("bank_b.app:app", host="127.0.0.1", port=config.BANK_B_PORT, reload=True)
