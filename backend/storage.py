"""Persistent storage and retention management for PCAP files and Zeek logs."""

import hashlib
import json
import os
import shutil
import time
import uuid
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent

STORAGE_DIR = Path(
    os.environ.get(
        "PACKET_STORAGE_DIR",
        str(BACKEND_DIR / "stored_captures"),
    )
).resolve()

RETENTION_DAYS = int(os.environ.get("PACKET_RETENTION_DAYS", "30"))

ALLOWED_CAPTURE_ID_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_-"
)


def _safe_id(capture_id):
    """Validate a capture identifier before using it in a filesystem path."""
    if not isinstance(capture_id, str) or not capture_id:
        raise ValueError("A capture ID is required.")

    if any(char not in ALLOWED_CAPTURE_ID_CHARS for char in capture_id):
        raise ValueError("Invalid capture ID.")

    return capture_id


def _capture_dir(capture_id):
    """Return the storage directory for a validated capture ID."""
    return STORAGE_DIR / _safe_id(capture_id)


def _sha256(path):
    """Calculate a file's SHA-256 checksum."""
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def store_capture(pcap_path, analysis_result):
    """Persist a PCAP and its generated Zeek logs with metadata."""
    source = Path(pcap_path).resolve()

    if not source.is_file():
        raise FileNotFoundError("The PCAP file does not exist.")

    if source.suffix.lower() not in {".pcap", ".pcapng"}:
        raise ValueError("Only .pcap and .pcapng files are supported.")

    if not isinstance(analysis_result, dict):
        raise ValueError("Analysis result must be a dictionary.")

    source_logs_dir = Path(
        analysis_result.get("output_dir", "")
    ).resolve()

    if not source_logs_dir.is_dir():
        raise FileNotFoundError(
            "The generated Zeek log directory does not exist."
        )

    log_files = [
        path
        for path in source_logs_dir.iterdir()
        if path.is_file() and path.suffix.lower() == ".log"
    ]

    if not log_files:
        raise FileNotFoundError("No Zeek log files were generated.")

    STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    capture_id = uuid.uuid4().hex
    destination = _capture_dir(capture_id)
    destination.mkdir(parents=False, exist_ok=False)

    try:
        stored_pcap = destination / source.name
        shutil.copy2(source, stored_pcap)

        stored_logs = destination / "zeek_logs"
        stored_logs.mkdir()

        for log_file in log_files:
            shutil.copy2(log_file, stored_logs / log_file.name)

        files = [stored_pcap, *sorted(stored_logs.iterdir())]

        metadata = {
            "capture_id": capture_id,
            "original_filename": source.name,
            "created_at": time.time(),
            "retention_days": RETENTION_DAYS,
            "pcap_file": stored_pcap.name,
            "logs_directory": "zeek_logs",
            "analysis": {
                "status": analysis_result.get("status", "success"),
                "elapsed_seconds": analysis_result.get("elapsed_seconds"),
            },
            "files": [
                {
                    "path": str(path.relative_to(destination)),
                    "size_bytes": path.stat().st_size,
                    "sha256": _sha256(path),
                }
                for path in files
            ],
        }

        metadata_path = destination / "metadata.json"
        metadata_path.write_text(
            json.dumps(metadata, indent=2),
            encoding="utf-8",
        )

        return get_capture(capture_id)

    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def list_captures():
    """List stored captures, newest first."""
    if not STORAGE_DIR.exists():
        return []

    captures = []

    for directory in STORAGE_DIR.iterdir():
        if not directory.is_dir():
            continue

        metadata_path = directory / "metadata.json"

        if not metadata_path.is_file():
            continue

        try:
            metadata = json.loads(
                metadata_path.read_text(encoding="utf-8")
            )

            captures.append(
                {
                    "capture_id": metadata["capture_id"],
                    "original_filename": metadata["original_filename"],
                    "created_at": metadata["created_at"],
                    "retention_days": metadata["retention_days"],
                    "files": metadata["files"],
                }
            )
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            continue

    return sorted(
        captures,
        key=lambda item: item["created_at"],
        reverse=True,
    )


def get_capture(capture_id):
    """Retrieve metadata for one stored capture."""
    directory = _capture_dir(capture_id)
    metadata_path = directory / "metadata.json"

    if not metadata_path.is_file():
        raise FileNotFoundError("Stored capture not found.")

    try:
        metadata = json.loads(
            metadata_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Stored capture metadata is unreadable.") from exc

    return metadata


def get_stored_file(capture_id, relative_path):
    """Resolve a stored file without allowing path traversal."""
    directory = _capture_dir(capture_id).resolve()
    candidate = (directory / relative_path).resolve()

    if candidate == directory or directory not in candidate.parents:
        raise ValueError("Invalid file path.")

    if not candidate.is_file():
        raise FileNotFoundError("Stored file not found.")

    return candidate


def verify_capture(capture_id):
    """Verify stored capture files against their recorded SHA-256 checksums."""
    metadata = get_capture(capture_id)
    results = []

    for entry in metadata.get("files", []):
        path = get_stored_file(capture_id, entry["path"])
        actual_hash = _sha256(path)
        actual_size = path.stat().st_size

        results.append(
            {
                "path": entry["path"],
                "exists": True,
                "size_matches": actual_size == entry["size_bytes"],
                "checksum_matches": actual_hash == entry["sha256"],
                "sha256": actual_hash,
            }
        )

    return {
        "capture_id": capture_id,
        "verified": bool(results)
        and all(
            item["size_matches"] and item["checksum_matches"]
            for item in results
        ),
        "files": results,
    }


def apply_retention(retention_days=None):
    """Delete stored captures older than the configured retention period."""
    days = RETENTION_DAYS if retention_days is None else retention_days

    if isinstance(days, bool) or not isinstance(days, (int, float)) or days <= 0:
        raise ValueError("Retention days must be a positive number.")

    if not STORAGE_DIR.exists():
        return {"deleted": [], "failed": []}

    cutoff = time.time() - days * 86400
    deleted = []
    failed = []

    for directory in STORAGE_DIR.iterdir():
        if not directory.is_dir():
            continue

        metadata_path = directory / "metadata.json"

        try:
            if metadata_path.is_file():
                metadata = json.loads(
                    metadata_path.read_text(encoding="utf-8")
                )
                created_at = float(metadata["created_at"])
            else:
                created_at = directory.stat().st_mtime

            if created_at < cutoff:
                shutil.rmtree(directory)
                deleted.append(directory.name)

        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            failed.append(
                {
                    "capture_id": directory.name,
                    "error": str(exc),
                }
            )

    return {"deleted": deleted, "failed": failed}
