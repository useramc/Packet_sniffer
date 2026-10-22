
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app import app
from parsers.zeek_parser import ZeekLogParser


def test_parse_conn_log_returns_normalized_records(tmp_path):
    log_file = tmp_path / "conn.log"
    log_file.write_text(
        "#separator \\x09\n"
        "#set_separator\t,\n"
        "#empty_field\t(empty)\n"
        "#unset_field\t-\n"
        "#path\tconn\n"
        "#open\t2026-10-22-00-00-00\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\t"
        "id.resp_p\tproto\tservice\tconn_state\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\t"
        "string\tstring\n"
        "1792660000.123\tC12345\t192.168.1.50\t54321\t"
        "8.8.8.8\t53\tudp\tdns\tSF\n",
        encoding="utf-8",
    )

    parser = ZeekLogParser(str(tmp_path))
    records = parser.parse_conn_log()

    assert len(records) == 1
    assert records[0]["timestamp"] == "1792660000.123"
    assert records[0]["uid"] == "C12345"
    assert records[0]["source_ip"] == "192.168.1.50"
    assert records[0]["source_port"] == "54321"
    assert records[0]["dest_ip"] == "8.8.8.8"
    assert records[0]["dest_port"] == "53"
    assert records[0]["protocol"] == "udp"
    assert records[0]["service"] == "dns"
    assert records[0]["state"] == "SF"


def test_conn_logs_endpoint_returns_parsed_records(tmp_path, monkeypatch):
    log_file = tmp_path / "conn.log"
    log_file.write_text(
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\t"
        "id.resp_p\tproto\tservice\tconn_state\n"
        "1792660000.123\tC12345\t192.168.1.50\t54321\t"
        "8.8.8.8\t53\tudp\tdns\tSF\n",
        encoding="utf-8",
    )

    monkeypatch.setattr("app.ZEEK_LOGS_PATH", str(tmp_path))

    client = app.test_client()
    response = client.get("/api/logs/conn")

    assert response.status_code == 200
    result = response.get_json()
    assert result["status"] == "success"
    assert result["count"] == 1
    assert result["data"][0]["protocol"] == "udp"
