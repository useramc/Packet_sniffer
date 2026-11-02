"""Atomic JSON settings persistence; never substitute a missing adapter/filter."""
import json
import os
import tempfile
from pathlib import Path

from .filters import validate_filter
from .interfaces import CaptureError, select_interface


def checked_settings(interface, bpf):
    if not isinstance(interface, str) or not interface:
        raise CaptureError("Settings require an exact interface identifier.")
    iface = select_interface(interface)
    return {"version": 1, "interface": iface.id, "filter": validate_filter(bpf, iface.id)}


def save_settings(path, interface, bpf=""):
    data = checked_settings(interface, bpf)
    path = Path(path)
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(data, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise CaptureError("Cannot save capture settings; check path and write permissions.") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return data


def load_settings(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CaptureError("Cannot read capture settings; check file path and JSON format.") from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise CaptureError("Unsupported capture settings version or format.")
    return checked_settings(data.get("interface"), data.get("filter", ""))


def start_saved(manager, path, session_name=""):
    data = load_settings(path)
    return manager.start(data["interface"], data["filter"], session_name)
