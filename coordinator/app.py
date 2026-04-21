"""
coordinator/app.py
FastAPI Coordinator Service — node registry, session management, health monitoring.
Runs on port 5000.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import hashlib
import uuid
import asyncio
from datetime import datetime

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, Header
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, HttpUrl

import config
import coordinator.db_manager as db

# ─── App Setup ────────────────────────────────────────────────────────────────

app = FastAPI(title="PSI Coordinator", version="2.0.0")

templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

# Initialize DB on startup
@app.on_event("startup")
async def startup():
    db.init_db()
    # Start periodic health-check loop
    asyncio.create_task(_health_check_loop())


# ─── Auth Helper ──────────────────────────────────────────────────────────────

def require_coordinator_api_key(x_api_key: str = Header(None)):
    if x_api_key != config.COORDINATOR_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid Coordinator API key")
    return x_api_key


# ─── Pydantic Schemas ─────────────────────────────────────────────────────────

class NodeRegisterRequest(BaseModel):
    node_name: str
    node_url: str
    api_key_hash: str  # SHA-256 hex digest of the node's API key


class SessionCreateRequest(BaseModel):
    querier_node: str
    responder_node: str
    items_in_query: int | None = None


class SessionUpdateRequest(BaseModel):
    status: str  # running | completed | failed
    matches_found: int | None = None
    items_in_query: int | None = None


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "coordinator", "timestamp": datetime.utcnow().isoformat()}


@app.post("/api/nodes/register", status_code=201)
async def register_node(req: NodeRegisterRequest):
    """Bank node self-registers on startup. No auth required (startup-only)."""
    node = db.upsert_node(req.node_name, req.node_url, req.api_key_hash)
    return {"message": "Node registered", "node": node}


@app.get("/api/nodes")
async def list_nodes(_=Depends(require_coordinator_api_key)):
    return {"nodes": db.get_all_nodes()}


@app.post("/api/sessions", status_code=201)
async def create_session(req: SessionCreateRequest, _=Depends(require_coordinator_api_key)):
    session_id = str(uuid.uuid4())
    session = db.create_session(session_id, req.querier_node, req.responder_node, req.items_in_query)
    return {"session_id": session_id, "session": session}


@app.patch("/api/sessions/{session_id}")
async def update_session(session_id: str, req: SessionUpdateRequest, _=Depends(require_coordinator_api_key)):
    existing = db.get_session(session_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Session not found")
    valid_statuses = {"running", "completed", "failed", "pending"}
    if req.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")
    db.update_session(session_id, req.status, req.matches_found, req.items_in_query)
    return {"message": "Session updated", "session_id": session_id}


@app.get("/api/sessions")
async def list_sessions(
    page: int = 1,
    per_page: int = 20,
    _=Depends(require_coordinator_api_key)
):
    return db.get_sessions(page, per_page)


# ─── Dashboard ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    nodes = db.get_all_nodes()
    sessions_data = db.get_sessions(page=1, per_page=20)
    return templates.TemplateResponse(request, "index.html", {
        "nodes": nodes,
        "sessions": sessions_data["sessions"],
    })


# ─── Background Health Check ──────────────────────────────────────────────────

async def _health_check_loop():
    """Pings all registered nodes every 30 seconds and updates their status."""
    await asyncio.sleep(5)  # initial delay
    while True:
        nodes = db.get_all_nodes()
        async with httpx.AsyncClient(timeout=5.0) as client:
            for node in nodes:
                try:
                    resp = await client.get(f"{node['node_url']}/api/health")
                    status = "online" if resp.status_code == 200 else "degraded"
                except Exception:
                    status = "offline"
                db.update_node_status(node["node_name"], status)
        await asyncio.sleep(30)


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "coordinator.app:app",
        host="127.0.0.1",
        port=config.COORDINATOR_PORT,
        reload=True,
        log_level="info",
    )
