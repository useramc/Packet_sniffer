
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app import app
from parsers.zeek_parser import ZeekLogParser


def test_parse_conn_log_returns_normalized_records(tmp_path):
    log_content = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\t"
        "id.resp_h\tid.resp_p\tproto\tservice\tconn_state\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\t"
        "enum\tstring\tstring\n"
        "1.0\tC123\t192.168.1.10\t12345\t8.8.8.8\t53\t"
        "udp\tdns\tSF\n"
    )
    (tmp_path / "conn.log").write_text(log_content, encoding="utf-8")

    parser = ZeekLogParser(str(tmp_path))
    records = parser.parse_conn_log()

    assert len(records) == 1
    assert records[0]["uid"] == "C123"
    assert records[0]["source_ip"] == "192.168.1.10"
    assert records[0]["dest_ip"] == "8.8.8.8"
    assert records[0]["protocol"] == "udp"


def test_conn_logs_endpoint_returns_parsed_records(tmp_path, monkeypatch):
    log_content = (
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\t"
        "id.resp_h\tid.resp_p\tproto\tservice\tconn_state\n"
        "1.0\tC123\t192.168.1.10\t12345\t8.8.8.8\t53\t"
        "udp\tdns\tSF\n"
    )
    (tmp_path / "conn.log").write_text(log_content, encoding="utf-8")
    monkeypatch.setattr("app.ZEEK_LOGS_PATH", str(tmp_path))

    with app.test_client() as client:
        response = client.get("/api/logs/conn")

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert data["count"] == 1
    assert data["data"][0]["uid"] == "C123"
