"""Run the existing backend plus capture routes without editing backend files."""
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from .api import create_router
from .session import CaptureSession


def create_app():
    # Match the backend's documented standalone import layout.
    backend = Path(__file__).resolve().parents[1] / "backend"
    if str(backend) not in sys.path:
        sys.path.insert(0, str(backend))
    from main import app
    from auth.routes import get_current_user

    if getattr(app.state, "capture_manager", None) is not None:
        return app
    data_dir = Path(os.environ.get("PPS_CAPTURE_DATA_DIR", "capture/data"))
    manager = CaptureSession(data_dir / "sessions")
    app.include_router(create_router(manager, data_dir / "settings.json", get_current_user))
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application):
        async with original_lifespan(application):
            try:
                yield
            finally:
                manager.terminate()

    app.router.lifespan_context = lifespan
    app.state.capture_manager = manager
    return app


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(create_app(), host="127.0.0.1", port=5000)
