"""/api/capture/start filter handling: presets map to BPF, invalid filters return a clear 400."""
import integration as integ
import live_capture
import pytest
from analytics import Analytics
from integration import CaptureError


def _compiler_available():
    try:
        from scapy.arch.common import compile_filter
        compile_filter("tcp", linktype=1)
        return True
    except Exception:
        return False


needs_libpcap = pytest.mark.skipif(not _compiler_available(), reason="Npcap/libpcap not installed")


def test_https_preset_is_stored_as_bpf(client):
    r = client.post("/api/capture/start", json={"interface": "Wi-Fi", "filter": "HTTPS"})
    assert r.status_code == 200
    sid = r.get_json()["sessionId"]
    assert client.get(f"/api/sessions/{sid}").get_json()["filter"] == "tcp port 443"


@needs_libpcap
def test_invalid_filter_is_rejected_with_clear_error(client):
    r = client.post("/api/capture/start", json={"interface": "Wi-Fi", "filter": "tcp port"})
    assert r.status_code == 400
    body = r.get_json()
    assert body["errorCode"] == "INVALID_FILTER"
    assert "Invalid BPF filter" in body["message"] and "HTTPS" in body["message"]
    assert client.get("/api/capture/status").get_json()["status"] == "idle"
    assert client.get("/api/sessions").get_json()["sessions"] == []


def test_invalid_filter_error_reaches_ui_without_starting(client, monkeypatch):
    def invalid(*_a, **_kw):
        raise CaptureError("Invalid BPF filter 'bogus' (syntax error).")
    monkeypatch.setattr(integ, "validate_filter", invalid)
    r = client.post("/api/capture/start", json={"interface": "Wi-Fi", "filter": "bogus"})
    assert r.status_code == 400 and r.get_json()["errorCode"] == "INVALID_FILTER"
    assert "bogus" in r.get_json()["message"]
    assert client.get("/api/capture/status").get_json()["status"] == "idle"


# ---------------------------------------------------------------- live driver
class _FakeIface:
    id = "wifi-0"


class _FakeSniffer:
    def __init__(self, **kwargs):
        self.kwargs, self.running = kwargs, False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


class _FakeWriter:
    def __init__(self, *_a, **_kw):
        pass

    def write(self, _pkt):
        pass

    def close(self):
        pass


@pytest.fixture
def fake_scapy(monkeypatch):
    import scapy.all as scapy_all
    made = []

    def sniffer(**kwargs):
        made.append(_FakeSniffer(**kwargs))
        return made[-1]

    monkeypatch.setattr(scapy_all, "AsyncSniffer", sniffer)
    monkeypatch.setattr(scapy_all, "PcapWriter", _FakeWriter)
    monkeypatch.setattr(live_capture, "select_interface", lambda _i: _FakeIface())
    monkeypatch.setattr(live_capture.time, "sleep", lambda _s: None)
    return made


@needs_libpcap
def test_live_capture_sniffs_https_as_port_443(tmp_path, fake_scapy, monkeypatch):
    from capture.filters import validate_filter
    monkeypatch.setattr(live_capture, "validate_filter", lambda bpf, _iface: validate_filter(bpf))
    cap = live_capture.LiveCapture(Analytics())
    cap.start(tmp_path, "Wi-Fi", "HTTPS")
    assert fake_scapy[0].kwargs["filter"] == "tcp port 443"
    cap._close()


@needs_libpcap
def test_live_capture_never_starts_sniffer_with_invalid_filter(tmp_path, fake_scapy, monkeypatch):
    from capture.filters import validate_filter
    monkeypatch.setattr(live_capture, "validate_filter", lambda bpf, _iface: validate_filter(bpf))
    cap = live_capture.LiveCapture(Analytics())
    with pytest.raises(CaptureError, match="Invalid BPF filter"):
        cap.start(tmp_path, "Wi-Fi", "https and")
    assert fake_scapy == [] and cap.sniffer is None
