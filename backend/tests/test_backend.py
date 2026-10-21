import sys
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
        data={"pcap": (None, "capture.txt")},
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert response.get_json()["status"] == "error"


def test_parser_returns_list_for_sample_logs():
    import os

    logs_dir = os.path.join(os.path.dirname(__file__), "..", "sample_logs")
    parser = ZeekLogParser(logs_dir)

    records = parser.parse_conn_log()

    assert isinstance(records, list)
