"""Export stored packet captures and Zeek analysis logs."""

import csv
import io
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from auth.routes import get_current_user
import storage

router = APIRouter(
    prefix="/api/export",
    tags=["Export"],
    dependencies=[Depends(get_current_user)],
)


def _stored_files(capture_id):
    try:
        metadata = storage.get_capture(capture_id)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=404, detail="Capture not found") from exc

    files = metadata.get("files", [])
    if not isinstance(files, list):
        raise HTTPException(status_code=500, detail="Invalid capture metadata")

    return metadata, files


@router.post("/session/{capture_id}")
def export_session(capture_id: str, format: str):
    """Download a stored PCAP, a ZIP of Zeek logs, or CSV connection data."""
    if format not in {"pcap", "zeek-logs", "csv"}:
        raise HTTPException(
            status_code=400,
            detail="format must be pcap, zeek-logs, or csv",
        )

    metadata, files = _stored_files(capture_id)

    if format == "pcap":
        pcap_entry = next(
            (
                item for item in files
                if Path(item.get("path", "")).suffix.lower()
                in {".pcap", ".pcapng"}
            ),
            None,
        )
        if pcap_entry is None:
            raise HTTPException(status_code=404, detail="PCAP file not found")

        try:
            pcap_path = storage.get_stored_file(
                capture_id, pcap_entry["path"]
            )
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(
                status_code=404, detail="Stored PCAP file not found"
            ) from exc

        return FileResponse(
            path=str(pcap_path),
            filename=Path(pcap_entry["path"]).name,
            media_type="application/octet-stream",
        )

    log_entries = [
        item for item in files
        if Path(item.get("path", "")).suffix.lower() == ".log"
    ]

    if not log_entries:
        raise HTTPException(status_code=404, detail="Zeek logs not found")

    try:
        log_paths = [
            (
                entry,
                storage.get_stored_file(capture_id, entry["path"]),
            )
            for entry in log_entries
        ]
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(
            status_code=404, detail="A stored Zeek log was not found"
        ) from exc

    if format == "zeek-logs":
        archive = io.BytesIO()
        with zipfile.ZipFile(
            archive, mode="w", compression=zipfile.ZIP_DEFLATED
        ) as zipped:
            for entry, path in log_paths:
                zipped.write(path, arcname=Path(entry["path"]).name)

        archive.seek(0)
        return StreamingResponse(
            archive,
            media_type="application/zip",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{capture_id}-zeek-logs.zip"'
                )
            },
        )

    conn_log = next(
        (
            path for entry, path in log_paths
            if Path(entry["path"]).name == "conn.log"
        ),
        None,
    )
    if conn_log is None:
        raise HTTPException(
            status_code=404,
            detail="conn.log is required for CSV export",
        )

    fields = None
    output = io.StringIO(newline="")

    with conn_log.open("r", encoding="utf-8", errors="replace") as source:
        for line in source:
            if line.startswith("#fields"):
                fields = line.rstrip("\r\n").split("\t")[1:]
                break

    if not fields:
        raise HTTPException(
            status_code=422,
            detail="conn.log does not contain a valid #fields header",
        )

    writer = csv.writer(output)
    writer.writerow(fields)

    with conn_log.open("r", encoding="utf-8", errors="replace") as source:
        for line in source:
            if not line.strip() or line.startswith("#"):
                continue

            values = line.rstrip("\r\n").split("\t")
            if len(values) == len(fields):
                writer.writerow(values)

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{capture_id}-connections.csv"'
            )
        },
    )
