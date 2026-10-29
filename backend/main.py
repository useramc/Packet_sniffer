"""
Pocket Packet Sniffer — backend entrypoint (Sprint 1 scaffolding).

Run locally:
    export PPS_JWT_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')
    pip install -r requirements.txt
    uvicorn main:app --reload

This only wires up authentication (PPS-F-021). Capture, Zeek, dashboard and
export routers land in later sprints per docs/INTERFACES.md and each
plug into this same app + the same `Depends(get_current_user)` pattern.
"""
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from auth import store
from auth.routes import get_current_user
from auth.routes import router as auth_router
from export_routes import router as export_router


@asynccontextmanager
async def lifespan(_app: FastAPI):
    store.init_db()
    yield


app = FastAPI(title="Pocket Packet Sniffer API", version="0.1.0", lifespan=lifespan)
app.include_router(auth_router)
app.include_router(export_router)


@app.get("/api/health")
def health():
    """Unauthenticated liveness check only — no session/capture data here."""
    return {"status": "ok"}


@app.get("/api/me")
def whoami(username: str = Depends(get_current_user)):
    """
    Reference example for teammates: any route that should require login
    takes `username: str = Depends(get_current_user)` as a parameter.
    Capture/dashboard/export routers (Sprint 2+) should follow this pattern.
    """
    return {"username": username}
