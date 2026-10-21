
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = PROJECT_ROOT / "backend" / "zeek_runs"


def find_zeek():
    """Find the installed Zeek executable."""
    configured = os.environ.get("ZEEK_BIN")

    for candidate in (configured, shutil.which("zeek"), "/opt/zeek/bin/zeek"):
        if candidate and Path(candidate).is_file():
            return str(candidate)

    raise FileNotFoundError(
        "Zeek not found. Set ZEEK_BIN to the Zeek executable path."
    )


def analyze_pcap(pcap_path):
    """Analyze a PCAP file and return the generated Zeek logs."""
    pcap_path = Path(pcap_path).resolve()

    if not pcap_path.is_file():
        raise FileNotFoundError("PCAP file not found.")

    if pcap_path.suffix.lower() not in {".pcap", ".pcapng"}:
        raise ValueError("Only .pcap and .pcapng files are supported.")

    output_dir = RUNS_DIR / uuid.uuid4().hex
    output_dir.mkdir(parents=True, exist_ok=False)

    started = time.monotonic()

    try:
        result = subprocess.run(
            [find_zeek(), "-C", "-r", str(pcap_path)],
            cwd=str(output_dir),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("Zeek analysis exceeded 30 seconds.") from exc

    elapsed = round(time.monotonic() - started, 3)

    if result.returncode != 0:
        raise RuntimeError(
            f"Zeek exited with code {result.returncode}: "
            f"{result.stderr[-2000:]}"
        )

    return {
        "status": "success",
        "elapsed_seconds": elapsed,
        "output_dir": str(output_dir),
        "log_files": sorted(p.name for p in output_dir.glob("*.log")),
        "stderr": result.stderr[-2000:],
    }
