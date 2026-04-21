"""
bank_a/app.py
FastAPI Bank A Node — Querier endpoints and UI routes.
Runs on port 5001.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import uuid, hashlib, time, json
from contextlib import asynccontextmanager
from datetime import datetime

import httpx
import uvicorn
import requests
from fastapi import FastAPI, HTTPException, Request, Depends, Form, Header
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from werkzeug.security import generate_password_hash, check_password_hash
from pydantic import BaseModel

import config
import bank_a.db_manager as db
from bank_a.tasks import celery_app, task_run_psi_batch
from psi_core.data_normalizer import normalize
from psi_core.ecdh_engine import PSIQuerier

# ─── App Setup ────────────────────────────────────────────────────────────────

templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)


@asynccontextmanager
async def lifespan(app_: FastAPI):
    db.init_db()
    if not db.get_user(config.DEFAULT_ADMIN_USERNAME):
        pw_hash = generate_password_hash(config.DEFAULT_ADMIN_PASSWORD)
        db.create_user(config.DEFAULT_ADMIN_USERNAME, pw_hash, "admin")
    _register_with_coordinator()
    yield


app = FastAPI(title="Bank A — PSI Querier", version="2.0.0", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=config.SESSION_SECRET_KEY)


def _register_with_coordinator():
    try:
        api_key_hash = hashlib.sha256(config.PSI_API_KEY.encode()).hexdigest()
        requests.post(
            f"{config.COORDINATOR_URL}/api/nodes/register",
            json={"node_name": "bank_a", "node_url": config.BANK_A_URL, "api_key_hash": api_key_hash},
            timeout=5,
        )
    except Exception as e:
        print(f"[Bank A] Could not register with coordinator: {e}")


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


# ─── Health ───────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "bank_a", "timestamp": datetime.utcnow().isoformat()}


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
async def dashboard(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")
    account_count    = db.get_account_count()
    run_count        = db.get_run_count()
    total_matches    = db.get_total_matches()
    last_run         = db.get_last_run_time()
    severity_dist    = db.get_severity_distribution()
    run_chart_data   = db.get_recent_run_match_counts()
    latest_run_id    = db.get_latest_run_id()
    latest_matches   = db.get_matches_for_run(latest_run_id) if latest_run_id else []
    return templates.TemplateResponse(request, "dashboard.html", {
        "user": user,
        "account_count": account_count,
        "run_count": run_count,
        "total_matches": total_matches,
        "last_run": last_run,
        "severity_dist": json.dumps(severity_dist),
        "run_chart_data": json.dumps(run_chart_data),
        "latest_matches": latest_matches[:50],
        "latest_run_id": latest_run_id,
    })


@app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request, page: int = 1):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")
    data = db.get_psi_runs(page=page, per_page=20)
    return templates.TemplateResponse(request, "history.html", {
        "user": user,
        "runs": data["runs"],
        "total": data["total"],
        "page": page,
        "per_page": data["per_page"],
    })


@app.get("/lookup", response_class=HTMLResponse)
async def lookup_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login")
    return templates.TemplateResponse(request, "lookup.html", {"user": user, "result": None})


# ─── PSI API Endpoints ────────────────────────────────────────────────────────

@app.post("/api/psi/run-batch")
async def run_batch_psi(request: Request):
    user = require_auth(request)
    run_id = str(uuid.uuid4())
    # Create Coordinator session first
    session_id = run_id
    try:
        coord_resp = requests.post(
            f"{config.COORDINATOR_URL}/api/sessions",
            json={"querier_node": "bank_a", "responder_node": "bank_b"},
            headers={"x-api-key": config.COORDINATOR_API_KEY},
            timeout=10,
        )
        if coord_resp.ok:
            session_id = coord_resp.json().get("session_id", run_id)
    except Exception:
        pass  # coordinator unavailable — proceed with local run_id

    db.create_psi_run(run_id)
    task = task_run_psi_batch.delay(run_id, session_id)
    db.update_psi_run(run_id, "running", celery_task_id=task.id)
    return {"task_id": task.id, "run_id": run_id, "session_id": session_id}


@app.get("/api/task-status/{task_id}")
async def task_status(task_id: str, request: Request):
    require_auth(request)
    task = celery_app.AsyncResult(task_id)
    if task.state == "PENDING":
        return {"task_id": task_id, "state": "PENDING", "progress": 0, "message": "Waiting in queue...", "result": None}
    elif task.state == "PROGRESS":
        meta = task.info or {}
        return {"task_id": task_id, "state": "PROGRESS", "progress": meta.get("progress", 0), "message": meta.get("message", ""), "result": None}
    elif task.state == "SUCCESS":
        return {"task_id": task_id, "state": "SUCCESS", "progress": 100, "message": "Completed", "result": task.result}
    elif task.state == "FAILURE":
        return {"task_id": task_id, "state": "FAILURE", "progress": 0, "message": str(task.info), "result": None}
    else:
        return {"task_id": task_id, "state": task.state, "progress": 0, "message": "", "result": None}


class LookupRequest(BaseModel):
    identifier: str
    identifier_type: str


@app.post("/api/psi/lookup")
async def psi_lite_lookup(req: LookupRequest, request: Request):
    require_auth(request)
    start = time.time()
    try:
        norm = normalize(req.identifier, req.identifier_type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    querier = PSIQuerier()
    pt = querier.hash_to_curve(norm)
    from psi_core.ecdh_engine import _serialize_point, _scalar_mult
    encrypted_pt = _scalar_mult(querier._scalar, pt)
    serialized = _serialize_point(encrypted_pt)
    enc_str = serialized.decode("utf-8") if isinstance(serialized, bytes) else serialized

    try:
        resp = requests.post(
            f"{config.BANK_B_URL}/api/psi/bloom-query",
            json={"encrypted_point": enc_str, "querier_bank": "bank_a"},
            headers={"X-PSI-API-Key": config.PSI_API_KEY},
            timeout=10,
        )
        resp.raise_for_status()
        is_match = resp.json().get("is_match", False)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Bank B unreachable: {e}")

    latency_ms = round((time.time() - start) * 1000)
    lookup_id = str(uuid.uuid4())
    return {"is_match": is_match, "lookup_id": lookup_id, "latency_ms": latency_ms}


@app.get("/api/psi/history")
async def psi_history(request: Request, page: int = 1):
    require_auth(request)
    return db.get_psi_runs(page=page)


@app.get("/api/psi/run/{run_id}/matches")
async def get_run_matches(run_id: str, request: Request):
    require_auth(request)
    matches = db.get_matches_for_run(run_id)
    return {"run_id": run_id, "matches": matches}


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run("bank_a.app:app", host="127.0.0.1", port=config.BANK_A_PORT, reload=True)
