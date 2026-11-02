"""Capture-owned HTTP adapter; authentication is supplied by the host application."""
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field

from .interfaces import CaptureError, list_interfaces
from .settings import load_settings, save_settings


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Start(Input):
    interface: str | None = Field(default=None, min_length=1)
    filter: str | None = None
    sessionName: str = Field(default="", max_length=256)


class Session(Input):
    sessionId: str = Field(min_length=1)


class Switch(Session):
    interface: str = Field(min_length=1)


class Settings(Input):
    interface: str = Field(min_length=1)
    filter: str = ""


class CaptureRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()

        async def handle(request):
            try:
                return await original(request)
            except RequestValidationError:
                return JSONResponse({"errorCode": "INVALID_REQUEST",
                                     "message": "Provide the documented capture request fields."}, status_code=400)
        return handle


def create_router(manager, settings_path: Path, authenticate):
    """Every route requires the host's existing authentication dependency."""
    router = APIRouter(prefix="/api/capture", tags=["capture"],
                       route_class=CaptureRoute,
                       dependencies=[Depends(authenticate)])

    def error(code, message, status):
        return JSONResponse({"errorCode": code, "message": message}, status_code=status)

    @router.get("/interfaces")
    def interfaces():
        try:
            return {"interfaces": [item.to_dict() for item in list_interfaces()]}
        except CaptureError as exc:
            return error("CAPTURE_UNAVAILABLE", str(exc), 503)

    @router.get("/status")
    def status():
        return manager.snapshot()

    @router.post("/start")
    def start(body: Start):
        with manager._lock:
            if manager._sniffer is not None:
                return error("INVALID_STATE", "Capture already active.", 409)
            try:
                if body.interface is None:
                    saved = load_settings(settings_path)
                    interface = saved["interface"]
                    bpf = saved["filter"] if body.filter is None else body.filter
                else:
                    interface, bpf = body.interface, body.filter or ""
                return manager.start(interface, bpf, body.sessionName)
            except CaptureError as exc:
                return error("CAPTURE_START_FAILED", str(exc), 400)

    @router.post("/stop")
    @router.post("/pause")
    @router.post("/resume")
    @router.post("/terminate")
    def control(body: Session, request: Request):
        action = request.url.path.rsplit("/", 1)[-1]
        with manager._lock:
            if manager.session_id != body.sessionId:
                return error("SESSION_NOT_FOUND", "Unknown capture session.", 404)
            try:
                return getattr(manager, action)()
            except CaptureError as exc:
                return error("CAPTURE_CONTROL_FAILED", str(exc), 409)

    @router.post("/switch")
    def switch(body: Switch):
        with manager._lock:
            if manager.session_id != body.sessionId:
                return error("SESSION_NOT_FOUND", "Unknown capture session.", 404)
            try:
                return manager.switch_interface(body.interface)
            except CaptureError as exc:
                return error("CAPTURE_SWITCH_FAILED", str(exc), 400)

    @router.get("/settings")
    def read_settings():
        with manager._lock:
            try:
                return load_settings(settings_path)
            except CaptureError as exc:
                return error("INVALID_SETTINGS", str(exc), 400)

    @router.put("/settings")
    def write_settings(body: Settings):
        with manager._lock:
            try:
                return save_settings(settings_path, body.interface, body.filter)
            except CaptureError as exc:
                return error("INVALID_SETTINGS", str(exc), 400)

    return router
