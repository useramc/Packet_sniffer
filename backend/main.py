"""
Pocket Packet Sniffer backend entrypoint.
Provides authentication and session-history APIs.
"""

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from auth import store
from auth.routes import get_current_user
from auth.routes import router as auth_router

from export_routes import router as export_router
from session_history import (
    add_session_tag,
    get_session,
    get_session_tags,
    list_sessions,
)

@asynccontextmanager
async def lifespan(_app: FastAPI):
    store.init_db()
    yield


app = FastAPI(
    title="Pocket Packet Sniffer API",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(auth_router)
app.include_router(export_router)


class SessionTagRequest(BaseModel):
    tag: str = Field(min_length=1, max_length=50)


@app.get("/api/health")
def health():
    """Unauthenticated liveness check."""
    return {"status": "ok"}


@app.get("/api/me")
def whoami(username: str = Depends(get_current_user)):
    """Return the authenticated user's username."""
    return {"username": username}


@app.get("/api/sessions")
def sessions(
    tag: str | None = None,
    limit: int = 100,
    username: str = Depends(get_current_user),
):
    """List historical sessions, optionally filtered by tag."""
    try:
        records = list_sessions(tag=tag, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail="Session history is unavailable.",
        ) from exc

    return {"count": len(records), "data": records}


@app.get("/api/sessions/{session_id}")
def session_details(
    session_id: str,
    username: str = Depends(get_current_user),
):
    """Retrieve one historical session."""
    try:
        record = get_session(session_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail="Session history is unavailable.",
        ) from exc

    if record is None:
        raise HTTPException(status_code=404, detail="Session not found.")

    return record


@app.post("/api/sessions/{session_id}/tags")
def create_session_tag(
    session_id: str,
    request: SessionTagRequest,
    username: str = Depends(get_current_user),
):
    """Add a tag to a historical session."""
    try:
        record = add_session_tag(session_id, request.tag)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail="Session history is unavailable.",
        ) from exc

    if record is None:
        raise HTTPException(status_code=404, detail="Session not found.")

    return {"session_id": session_id, "tags": record["tags"]}


@app.get("/api/sessions/{session_id}/tags")
def session_tags(
    session_id: str,
    username: str = Depends(get_current_user),
):
    """Retrieve tags associated with a historical session."""
    try:
        tags = get_session_tags(session_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail="Session history is unavailable.",
        ) from exc

    if tags is None:
        raise HTTPException(status_code=404, detail="Session not found.")

    return {"session_id": session_id, "tags": tags}
