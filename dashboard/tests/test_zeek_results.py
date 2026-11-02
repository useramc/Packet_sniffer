"""Zeek results reach the right session and the export explains every state (PPS-F-006..008)."""
import io
import zipfile
from pathlib import Path

import app as dashboard_app
import live_capture
import pytest
import zeek_runner
from analytics import Analytics
from integration import read_zeek_tsv

DASHBOARD = Path(__file__).resolve().parents[1]


class _FakeLive:
    """Stands in for LiveCapture: Stop reports a fixed Zeek result for the stopped session."""

    def __init__(self, result):
        self.result, self.zeek = result, {"status": "idle"}

    def stop(self, on_zeek=None):
        if on_zeek:
            on_zeek(self.result)


@pytest.fixture
def live_session(client, monkeypatch):
    """Starts a session, marks it live, returns (client, sid, set_stop_result)."""
    fake = _FakeLive({"status": "done", "log_files": []})
    monkeypatch.setattr(dashboard_app, "live", None)   # restored after the test
    # start in mock mode (no real sniffer) ...
    sid = client.post("/api/capture/start", json={"interface": "Wi-Fi"}).get_json()["sessionId"]
    dashboard_app.records[sid]["mode"] = "live"    # ... then behave like a live session
    dashboard_app.live = fake

    def set_result(result):
        fake.result = result
    return client, sid, set_result


def _export(client, sid):
    r = client.post(f"/api/export/session/{sid}", json={"format": "zeek-logs"})
    return r.status_code, r.get_json()


def test_running_session_says_stop_first(live_session):
    client, sid, _ = live_session
    code, body = _export(client, sid)
    assert code == 409 and body["message"] == "Stop the session to generate Zeek logs."


def test_zeek_not_installed_says_unavailable(live_session):
    client, sid, set_result = live_session
    set_result({"status": "unavailable", "message": "Zeek not found."})
    client.post("/api/capture/stop")
    code, body = _export(client, sid)
    assert code == 503 and body["message"].startswith("Zeek unavailable")


def test_zeek_finished_without_output_says_no_logs_yet(live_session):
    client, sid, set_result = live_session
    set_result({"status": "done", "log_files": [], "output_dir": ""})
    client.post("/api/capture/stop")
    code, body = _export(client, sid)
    assert code == 404 and body["message"].startswith("No Zeek logs yet")


def test_zeek_still_analysing_is_reported(live_session):
    client, sid, set_result = live_session
    set_result({"status": "running"})
    client.post("/api/capture/stop")
    code, body = _export(client, sid)
    assert code == 409 and "still analysing" in body["message"]


def test_stopped_session_exports_its_own_logs_after_a_new_session_starts(live_session, tmp_path):
    client, sid, set_result = live_session
    out = tmp_path / "run"
    out.mkdir()
    (out / "dns.log").write_text("#fields\tts\tquery\n1\texample.com\n", encoding="utf-8")
    set_result({"status": "done", "log_files": ["dns.log"], "output_dir": str(out)})
    client.post("/api/capture/stop")
    dashboard_app.live = None
    client.post("/api/capture/start", json={"interface": "Ethernet"})   # next session must not hide the result
    code, body = _export(client, sid)
    assert code == 200
    data = client._c.get(body["downloadUrl"]).data
    assert zipfile.ZipFile(io.BytesIO(data)).namelist() == ["dns.log"]


def test_badge_is_not_ready_when_zeek_is_missing(monkeypatch):
    monkeypatch.setattr(dashboard_app, "live", _FakeLive(None))
    monkeypatch.setattr(dashboard_app.integ, "zeek_status", lambda: {"available": False, "message": "Zeek not found."})
    assert dashboard_app.zeek_info()["status"] == "unavailable"
    monkeypatch.setattr(dashboard_app.integ, "zeek_status", lambda: {"available": True, "path": "zeek"})
    assert dashboard_app.zeek_info()["status"] == "idle"


# ------------------------------------------------------------- live driver
def test_late_zeek_result_goes_to_its_own_session_only(tmp_path, monkeypatch):
    old_pcap, new_pcap = tmp_path / "old.pcap", tmp_path / "new.pcap"
    out = tmp_path / "run"
    out.mkdir()
    (out / "notice.log").write_text("#fields\tts\tnote\tmsg\tsrc\n1\tX\tbad\t10.0.0.9\n", encoding="utf-8")
    monkeypatch.setattr(zeek_runner, "analyze_pcap",
                        lambda _p: {"output_dir": str(out), "log_files": ["notice.log"]})
    cap = live_capture.LiveCapture(Analytics())
    cap.pcap_path = new_pcap                     # a new session started while Zeek ran on the old one
    got = []
    cap._run_zeek(old_pcap, got.append)
    assert got[-1]["status"] == "done" and got[-1]["output_dir"] == str(out)
    assert cap.zeek == {"status": "idle"}        # header badge of the new session is untouched
    assert cap.analytics.alerts() == []          # old notices are not added to the new session


def test_stop_reports_unavailable_when_zeek_missing(tmp_path, monkeypatch):
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1")

    class _SyncThread:
        def __init__(self, target, args=(), daemon=None):
            self.target, self.args = target, args

        def start(self):
            self.target(*self.args)

    def missing():
        raise FileNotFoundError("Zeek not found.")
    monkeypatch.setattr(live_capture.threading, "Thread", _SyncThread)
    monkeypatch.setattr(zeek_runner, "find_zeek", missing)
    monkeypatch.setattr(zeek_runner, "RUNS_DIR", tmp_path / "runs")
    cap = live_capture.LiveCapture(Analytics())
    cap.pcap_path = pcap
    got = []
    cap.stop(on_zeek=got.append)
    assert [z["status"] for z in got] == ["running", "unavailable"]
    assert cap.zeek["status"] == "unavailable"
    assert not (tmp_path / "runs").exists()      # no empty run folder when Zeek is missing


def test_zeek_timeout_is_long_enough_and_configurable(monkeypatch):
    monkeypatch.delenv("ZEEK_TIMEOUT", raising=False)
    assert zeek_runner.zeek_timeout() >= 120     # 30 s was too short for a 15 MB capture via WSL
    monkeypatch.setenv("ZEEK_TIMEOUT", "300")
    assert zeek_runner.zeek_timeout() == 300
    for bad in ("abc", "0", "-5"):
        monkeypatch.setenv("ZEEK_TIMEOUT", bad)
        assert zeek_runner.zeek_timeout() == zeek_runner.DEFAULT_TIMEOUT


def test_export_message_is_shown_in_session_history():
    """The Zeek logs button reports its result next to the Session history table."""
    html = (DASHBOARD / "templates" / "index.html").read_text(encoding="utf-8")
    js = (DASHBOARD / "static" / "app.js").read_text(encoding="utf-8")
    assert html.index('id="sessions-body"') < html.index('id="sessions-message"')
    assert 'sessionsMessage(res.data.message' in js


# ------------------------------------------------------------ real Zeek run
def _zeek_installed():
    try:
        zeek_runner.find_zeek()
        return True
    except FileNotFoundError:
        return False


@pytest.mark.skipif(not _zeek_installed(), reason="Zeek is not installed (set ZEEK_BIN)")
def test_real_zeek_writes_conn_and_dns_logs_and_exports_them(live_session, tmp_path, monkeypatch):
    from scapy.all import DNS, DNSQR, IP, UDP, Ether, wrpcap

    pcap = tmp_path / "capture.pcap"
    wrpcap(str(pcap), [Ether() / IP(src="10.0.0.2", dst="10.0.0.53") / UDP(sport=40000, dport=53)
                       / DNS(rd=1, qd=DNSQR(qname="example.com"))])
    monkeypatch.setattr(zeek_runner, "RUNS_DIR", tmp_path / "runs")

    result = zeek_runner.analyze_pcap(pcap)
    out = Path(result["output_dir"])
    assert {"conn.log", "dns.log"} <= set(result["log_files"])
    assert read_zeek_tsv(out / "conn.log")[0]["id.resp_p"] == "53"
    assert read_zeek_tsv(out / "dns.log")[0]["query"] == "example.com"

    client, sid, set_result = live_session
    set_result({"status": "done", "log_files": result["log_files"], "output_dir": str(out)})
    client.post("/api/capture/stop")
    code, body = _export(client, sid)
    assert code == 200
    names = zipfile.ZipFile(io.BytesIO(client._c.get(body["downloadUrl"]).data)).namelist()
    assert {"conn.log", "dns.log"} <= set(names)
