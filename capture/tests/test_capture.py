"""Offline contract tests; never inspect or capture the test host's traffic."""

from types import SimpleNamespace

import pytest
from scapy.all import Ether, IP, Raw, UDP, rdpcap

from capture import interfaces, smoke
from capture.__main__ import main
from capture.interfaces import CaptureError, CaptureInterface


def test_discovery_preserves_windows_identifier(monkeypatch):
    adapter = SimpleNamespace(network_name=r"\Device\NPF_{sample}", name="Wi-Fi",
                              description="Wireless adapter", ips={4: ["192.0.2.1"], 6: ["2001:db8::1"]})
    provider = SimpleNamespace(reload=lambda: None, values=lambda: [adapter])
    monkeypatch.setattr(interfaces, "scapy_api", lambda: SimpleNamespace(conf=SimpleNamespace(ifaces=provider)))
    found = interfaces.list_interfaces()
    assert found[0].id == adapter.network_name
    assert found[0].addresses == ("192.0.2.1", "2001:db8::1")
    assert interfaces.select_interface(adapter.network_name) == found[0]
    with pytest.raises(CaptureError, match="unavailable"):
        interfaces.select_interface("Wi-Fi")


def test_no_interfaces_and_provider_failure(monkeypatch):
    provider = SimpleNamespace(reload=lambda: None, values=lambda: [])
    monkeypatch.setattr(interfaces, "scapy_api", lambda: SimpleNamespace(conf=SimpleNamespace(ifaces=provider)))
    assert interfaces.list_interfaces() == []
    with pytest.raises(CaptureError, match="unavailable"):
        interfaces.select_interface("eth0")

    def fail():
        raise OSError("provider unavailable")

    provider.reload = fail
    with pytest.raises(CaptureError, match="Npcap/libpcap"):
        interfaces.list_interfaces()


@pytest.fixture
def selected(monkeypatch):
    iface = CaptureInterface("test-adapter", "Test", "Offline", ())
    monkeypatch.setattr(smoke, "select_interface", lambda _: iface)
    return iface


def test_smoke_writes_readable_pcap_with_bounded_capture(tmp_path, monkeypatch, selected):
    from scapy import all as api

    packet = Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP() / Raw(b"PPS test")

    def fake_sniff(**kwargs):
        assert kwargs["iface"] == selected.id
        assert kwargs["timeout"] == 2
        assert kwargs["count"] == 3
        assert kwargs["store"] is False
        kwargs["prn"](packet)

    monkeypatch.setattr(api, "sniff", fake_sniff)
    output = tmp_path / "test.pcap"
    assert smoke.smoke_capture(selected.id, str(output), seconds=2, count=3) == 1
    saved = rdpcap(str(output))
    assert len(saved) == 1
    assert bytes(saved[0]) == bytes(packet)
    # A second run must not overwrite the first capture.
    original = output.read_bytes()
    with pytest.raises(CaptureError, match="writable new output"):
        smoke.smoke_capture(selected.id, str(output))
    assert output.read_bytes() == original


def test_idle_capture_is_valid_empty_pcap(tmp_path, monkeypatch, selected):
    from scapy import all as api

    monkeypatch.setattr(api, "sniff", lambda **_: None)
    output = tmp_path / "empty.pcap"
    assert smoke.smoke_capture(selected.id, str(output)) == 0
    assert len(rdpcap(str(output))) == 0


def test_permission_failure_closes_output(tmp_path, monkeypatch, selected):
    from scapy import all as api

    def fail(**_):
        raise PermissionError("capture denied")

    monkeypatch.setattr(api, "sniff", fail)
    output = tmp_path / "partial.pcap"
    with pytest.raises(CaptureError, match="permissions"):
        smoke.smoke_capture(selected.id, str(output))
    output.unlink()  # Windows refuses this if a writer/file handle leaked.


@pytest.mark.parametrize("seconds,count", [(0, 1), (61, 1), (float("nan"), 1), (1, 0), (1, 10001)])
def test_invalid_limits_rejected_before_discovery(seconds, count, tmp_path, monkeypatch):
    def unexpected(_):
        pytest.fail("must validate limits before touching interfaces")

    monkeypatch.setattr(smoke, "select_interface", unexpected)
    with pytest.raises(CaptureError, match="duration"):
        smoke.smoke_capture("test", str(tmp_path / "invalid.pcap"), seconds, count)


def test_cli_selection_error_is_actionable(monkeypatch, capsys):
    monkeypatch.setattr(interfaces, "list_interfaces", lambda: [])
    assert main(["select", "--interface", "missing"]) == 1
    assert "unavailable" in capsys.readouterr().err
