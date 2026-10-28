"""
Glue between the dashboard and the other PPS modules (docs/INTERFACES.md).

The dashboard only *imports public entry points* of the other modules:
  backend.auth.{store,security}   -> PPS-F-021 / PPS-SR-001 / PPS-SR-004
  backend.zeek_runner / parsers   -> PPS-F-006..007 (Zeek on a finished pcap)
  capture.interfaces              -> PPS-F-001 / PPS-F-004 (interface discovery)

No other module is modified. Backend / repo-root are appended to the END of
sys.path so the dashboard's own ``app`` module is never shadowed by backend/app.py.
"""
import os
import secrets
import sys
from pathlib import Path

DASHBOARD_DIR = Path(__file__).resolve().parent
REPO_ROOT = DASHBOARD_DIR.parent
DATA_DIR = Path(os.environ.get("PPS_DATA_DIR", DASHBOARD_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
try:
    os.chmod(DATA_DIR, 0o700)  # PPS-SR-003: captures, audit log and auth DB not world-readable
except OSError:
    pass

for p in (REPO_ROOT / "backend", REPO_ROOT):
    if str(p) not in sys.path:
        sys.path.append(str(p))

# PPS-SR-004: never hardcode secrets. If the operator did not export one,
# generate a random per-process secret (tokens simply expire on restart).
if not os.environ.get("PPS_JWT_SECRET"):
    os.environ["PPS_JWT_SECRET"] = secrets.token_hex(32)
os.environ.setdefault("PPS_AUTH_DB", str(DATA_DIR / "pps_auth.db"))

from auth import config as auth_config  # noqa: E402
from auth import security, store  # noqa: E402

try:  # capture module needs scapy only when actually used
    from capture.interfaces import CaptureError, list_interfaces, select_interface  # noqa: E402
    CAPTURE_IMPORTED = True
except Exception:  # pragma: no cover
    CAPTURE_IMPORTED = False

    class CaptureError(RuntimeError):
        pass

    def list_interfaces():
        raise CaptureError("Capture module unavailable.")

    def select_interface(identifier):
        raise CaptureError("Capture module unavailable.")


def detect_mode():
    """PPS_MODE=live|mock forces a mode; default 'auto' = live when capture works."""
    wanted = os.environ.get("PPS_MODE", "auto").lower()
    if wanted in ("live", "mock"):
        return wanted
    try:
        return "live" if CAPTURE_IMPORTED and list_interfaces() else "mock"
    except Exception:
        return "mock"


def zeek_status():
    try:
        from zeek_runner import find_zeek
        return {"available": True, "path": find_zeek()}
    except FileNotFoundError as exc:
        return {"available": False, "message": str(exc)}
    except Exception as exc:  # pragma: no cover
        return {"available": False, "message": str(exc)}


def read_zeek_tsv(path):
    """Parse a Zeek TSV log into a list of dicts (handles #fields header)."""
    fields, rows = [], []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line and not line.startswith("#") and fields:
                rows.append(dict(zip(fields, line.split("\t"), strict=False)))
    return rows
