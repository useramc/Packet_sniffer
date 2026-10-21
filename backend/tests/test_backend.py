
import os
import sys
from io import BytesIO
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app import app
from parsers.zeek_parser import ZeekLogParser


def test_health_endpoint():
    client = app.test_client()
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.get_json()["status"] == "success"


def test_conn_logs_endpoint():
    client = app.test_client()
    response = client.get("/api/logs/conn")

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert isinstance(data["data"], list)


def test_analyze_requires_pcap_file():
    client = app.test_client()
    response = client.post("/api/zeek/analyze")

    assert response.status_code == 400
    assert response.get_json()["status"] == "error"


def test_analyze_rejects_unsupported_file():
    client = app.test_client()
    response = client.post(
        "/api/zeek/analyze",
        data={"pcap": (BytesIO(b"test-data"), "capture.txt")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert response.get_json()["status"] == "error"


def test_parser_returns_list_for_sample_logs():
    logs_dir = BACKEND_DIR / "sample_logs"
    parser = ZeekLogParser(str(logs_dir))

    records = parser.parse_conn_log()

    assert isinstance(records, list)


def test_analyze_returns_generated_log_files(monkeypatch):
    import zeek_runner

    client = app.test_client()

    def fake_analyze_pcap(pcap_path):
        return {
            "status": "success",
            "elapsed_seconds": 0.1,
            "output_dir": "/tmp/zeek-test",
            "log_files": [
                "conn.log",
                "dns.log",
                "packet_filter.log",
            ],
            "stderr": "",
        }

    monkeypatch.setattr(
        zeek_runner,
        "analyze_pcap",
        fake_analyze_pcap,
    )

    response = client.post(
        "/api/zeek/analyze",
        data={
            "pcap": (
                BytesIO(b"fake-pcap-data"),
                "capture.pcap",
            ),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200

    result = response.get_json()
    assert result["status"] == "success"
    assert "conn.log" in result["log_files"]
    assert "dns.log" in result["log_files"]
    assert "packet_filter.log" in result["log_files"]
