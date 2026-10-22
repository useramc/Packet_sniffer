import sys
from io import BytesIO
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

import app as app_module
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
    import os

    logs_dir = os.path.join(
        os.path.dirname(__file__), "..", "sample_logs"
    )
    parser = ZeekLogParser(logs_dir)

    records = parser.parse_conn_log()

    assert isinstance(records, list)


def test_analyze_returns_generated_log_files(monkeypatch):
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
        app_module,
        "analyze_pcap",
        fake_analyze_pcap,
    )

    response = client.post(
        "/api/zeek/analyze",
        data={
            "pcap": (BytesIO(b"fake-pcap-data"), "capture.pcap"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200

    result = response.get_json()
    assert result["status"] == "success"
    assert "conn.log" in result["log_files"]
    assert "dns.log" in result["log_files"]
    assert "packet_filter.log" in result["log_files"]


def test_analyze_uses_separate_output_directories(monkeypatch):
    client = app.test_client()
    output_dirs = iter(
        [
            "/tmp/zeek-run-one",
            "/tmp/zeek-run-two",
        ]
    )

    def fake_analyze_pcap(pcap_path):
        return {
            "status": "success",
            "elapsed_seconds": 0.1,
            "output_dir": next(output_dirs),
            "log_files": ["conn.log", "dns.log"],
            "stderr": "",
        }

    monkeypatch.setattr(
        app_module,
        "analyze_pcap",
        fake_analyze_pcap,
    )

    def upload_capture():
        return client.post(
            "/api/zeek/analyze",
            data={
                "pcap": (BytesIO(b"fake-pcap-data"), "capture.pcap"),
            },
            content_type="multipart/form-data",
        )

    first_response = upload_capture()
    second_response = upload_capture()

    assert first_response.status_code == 200
    assert second_response.status_code == 200

    first_result = first_response.get_json()
    second_result = second_response.get_json()

    assert first_result["output_dir"] == "/tmp/zeek-run-one"
    assert second_result["output_dir"] == "/tmp/zeek-run-two"
    assert first_result["output_dir"] != second_result["output_dir"]
