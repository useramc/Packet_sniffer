"""Append-only audit log of administrative actions (PPS-SR-006).

Never records passwords, tokens or packet payloads (SAD 4.4).
"""
import json
import os
import threading
from datetime import UTC, datetime

from integration import DATA_DIR

AUDIT_FILE = DATA_DIR / "audit.log"
_lock = threading.Lock()


def log(event, user=None, **detail):
    entry = {"time": datetime.now(UTC).isoformat(timespec="seconds"),
             "event": event, "user": user, **detail}
    with _lock:
        new = not AUDIT_FILE.exists()
        with open(AUDIT_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        if new:
            try:
                os.chmod(AUDIT_FILE, 0o600)  # PPS-SR-003: not world-readable
            except OSError:
                pass


def tail(n=50):
    if not AUDIT_FILE.exists():
        return []
    with open(AUDIT_FILE, "r", encoding="utf-8") as fh:
        return [json.loads(x) for x in fh.readlines()[-n:]]
