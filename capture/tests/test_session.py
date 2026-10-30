"""Offline capture boundary tests: real PCAP writer/reader, injected packets."""
from types import SimpleNamespace

import pytest
from scapy import all as scapy

from capture import session
from capture.interfaces import CaptureError, CaptureInterface


@pytest.fixture
def driver(tmp_path, monkeypatch):
    class Sniffer:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.running = False

        def start(self):
            self.running = True
            self.kwargs["started_callback"]()

        def stop(self, join=True):
            self.running = False

        def join(self):
            pass

    api = SimpleNamespace(PcapWriter=scapy.PcapWriter, AsyncSniffer=Sniffer)
    monkeypatch.setattr(session, "scapy_api", lambda: api)
    monkeypatch.setattr(session, "select_interface", lambda name: CaptureInterface(name, name, "lab", ()))
    return session.CaptureSession(tmp_path, ready_timeout=0.01)


def packet():
    return scapy.Ether() / scapy.IP(src="192.0.2.1", dst="192.0.2.2") / scapy.TCP(dport=80)


def test_wifi_pcap_round_trip(driver):
    started = driver.start("wifi-lab")
    assert started["status"] == "running"
    assert driver._sniffer.kwargs["iface"] == "wifi-lab"
    driver._sniffer.kwargs["prn"](packet())
    stopped = driver.stop()
    assert stopped["packets"] == 1
    assert bytes(scapy.rdpcap(stopped["pcapPath"])[0]) == bytes(packet())


def test_empty_pcap_and_exclusive_session_files(driver):
    first = driver.start("wifi-lab")["pcapPath"]
    driver.stop()
    assert len(scapy.rdpcap(first)) == 0
    second = driver.start("wifi-lab")["pcapPath"]
    driver.stop()
    assert first != second


def test_interface_error_before_file_creation(driver, monkeypatch):
    def missing(_):
        raise CaptureError("Interface unavailable")
    monkeypatch.setattr(session, "select_interface", missing)
    with pytest.raises(CaptureError, match="unavailable"):
        driver.start("missing")
    assert not list(driver.output_dir.glob("*.pcap"))


@pytest.mark.parametrize("interface", ["ethernet-lab", r"\Device\NPF_{ethernet-lab}"])
def test_ethernet_frames_and_adapter_identifiers(driver, interface):
    driver.start(interface)
    frames = [scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") /
              scapy.IP(src="192.0.2.1", dst="192.0.2.2") / scapy.UDP(dport=53) /
              scapy.Raw(bytes([i])) for i in range(5)]
    assert driver._sniffer.kwargs["iface"] == interface
    for frame in frames:
        driver._sniffer.kwargs["prn"](frame)
    result = driver.stop()
    assert [bytes(p) for p in scapy.rdpcap(result["pcapPath"])] == [bytes(p) for p in frames]
    assert result["packets"] == len(frames)


def test_ten_start_stop_cycles_preserve_all_delivered_packets(driver):
    paths = set()
    for _ in range(10):
        driver.start("wifi-lab", session_name="lab")
        with pytest.raises(CaptureError, match="already active"):
            driver.start("ethernet-lab")
        for _ in range(20):
            driver._on_packet(packet())
        result = driver.terminate()
        paths.add(result["pcapPath"])
        assert len(scapy.rdpcap(result["pcapPath"])) == 20
        assert result["sessionName"] == "lab"
        assert driver.stop()["status"] == "stopped"
    assert len(paths) == 10


def test_pause_resume_state_and_data(driver):
    with pytest.raises(CaptureError, match="running"):
        driver.pause()
    driver.start("wifi-lab")
    driver._on_packet(packet())
    assert driver.pause()["status"] == "paused"
    driver._on_packet(packet())
    assert driver.resume()["status"] == "running"
    driver._on_packet(packet())
    result = driver.stop()
    assert len(scapy.rdpcap(result["pcapPath"])) == 2


def test_startup_failure_closes_file_and_allows_retry(driver, monkeypatch):
    api = session.scapy_api()
    original = api.AsyncSniffer.start
    monkeypatch.setattr(api.AsyncSniffer, "start", lambda self: None)
    with pytest.raises(CaptureError, match="ready"):
        driver.start("wifi-lab")
    failed_path = driver.pcap_path
    failed_path.unlink()  # Detect leaked file handles on Windows.
    monkeypatch.setattr(api.AsyncSniffer, "start", original)
    driver.start("wifi-lab")
    driver.stop()


def test_writer_failure_surfaces_in_state(driver, monkeypatch):
    driver.start("wifi-lab")
    def full(_):
        raise OSError("disk full")
    monkeypatch.setattr(driver._writer, "write", full)
    driver._on_packet(packet())
    assert driver.snapshot()["status"] == "error"
    assert driver.terminate()["error"]
