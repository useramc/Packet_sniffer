"""Persistent session history and tagging for Zeek connection records."""

import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

_HISTORY_DIR = Path(
    os.environ.get(
        "PPS_SESSION_HISTORY_DIR",
        str(Path(__file__).resolve().parent / "session_history_data"),
    )
)
_HISTORY_FILE = _HISTORY_DIR / "sessions.json"
_LOCK = threading.RLock()


def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_sessions():
    if not _HISTORY_FILE.exists():
        return []

    try:
        data = json.loads(_HISTORY_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Session history could not be read.") from exc

    if not isinstance(data, list):
        raise RuntimeError("Session history data must be a list.")

    return data


def _write_sessions(sessions):
    _HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    temporary_file = _HISTORY_FILE.with_suffix(".tmp")
    temporary_file.write_text(
        json.dumps(sessions, indent=2),
        encoding="utf-8",
    )
    temporary_file.replace(_HISTORY_FILE)


def _valid_session_id(session_id):
    return isinstance(session_id, str) and bool(
        re.fullmatch(r"[a-f0-9]{32}", session_id)
    )


def record_sessions(records, capture_id=None):
    """Store valid Zeek connection records and return the stored sessions."""
    if not isinstance(records, list):
        raise ValueError("records must be a list.")

    stored = []
    timestamp = _now()

    with _LOCK:
        sessions = _read_sessions()

        for record in records:
            if not isinstance(record, dict):
                continue

            source_ip = record.get("source_ip")
            destination_ip = record.get("dest_ip")
            source_port = record.get("source_port")
            destination_port = record.get("dest_port")
            protocol = record.get("protocol")
            event_timestamp = record.get("timestamp")

            if not all(
                value is not None and str(value).strip()
                for value in (
                    source_ip,
                    destination_ip,
                    source_port,
                    destination_port,
                    protocol,
                    event_timestamp,
                )
            ):
                continue

            session = {
                "session_id": uuid.uuid4().hex,
                "capture_id": capture_id,
                "source_ip": str(source_ip),
                "source_port": source_port,
                "destination_ip": str(destination_ip),
                "destination_port": destination_port,
                "protocol": str(protocol),
                "timestamp": str(event_timestamp),
                "recorded_at": timestamp,
                "tags": [],
            }
            sessions.append(session)
            stored.append(session)

        if stored:
            _write_sessions(sessions)

    return stored


def list_sessions(tag=None, limit=100):
    """Return stored sessions, optionally filtered by tag."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer.")

    with _LOCK:
        sessions = _read_sessions()

    if tag is not None:
        if not isinstance(tag, str) or not tag.strip():
            raise ValueError("tag must be a non-empty string.")
        sessions = [
            session
            for session in sessions
            if tag.strip() in session.get("tags", [])
        ]

    sessions.sort(key=lambda item: item.get("recorded_at", ""), reverse=True)
    return sessions[:limit]


def get_session(session_id):
    """Retrieve one session by its identifier."""
    if not _valid_session_id(session_id):
        raise ValueError("Invalid session ID.")

    with _LOCK:
        sessions = _read_sessions()

    for session in sessions:
        if session.get("session_id") == session_id:
            return session

    return None


def add_session_tag(session_id, tag):
    """Add a tag to a session without creating duplicate tags."""
    if not _valid_session_id(session_id):
        raise ValueError("Invalid session ID.")

    if not isinstance(tag, str) or not tag.strip():
        raise ValueError("tag must be a non-empty string.")

    tag = tag.strip()
    if len(tag) > 50:
        raise ValueError("tag must be 50 characters or fewer.")

    with _LOCK:
        sessions = _read_sessions()

        for session in sessions:
            if session.get("session_id") == session_id:
                if tag not in session["tags"]:
                    session["tags"].append(tag)
                    _write_sessions(sessions)
                return session

    return None

def get_session_tags(session_id):
    """Return the tags associated with a session."""
    session = get_session(session_id)

    if session is None:
        return None

    tags = session.get("tags", [])
    return tags if isinstance(tags, list) else []