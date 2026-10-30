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


def test_switch_preserves_old_pcap_and_starts_new_session(driver):
    old = driver.start("wifi-lab")
    driver._on_packet(packet())
    result = driver.switch_interface("ethernet-lab")
    assert result["interface"] == "ethernet-lab"
    assert result["sessionId"] != old["sessionId"]
    assert result["previousSession"]["status"] == "stopped"
    assert len(scapy.rdpcap(old["pcapPath"])) == 1
    driver._on_packet(packet())
    assert len(scapy.rdpcap(driver.stop()["pcapPath"])) == 1


def test_invalid_switch_preserves_running_session(driver, monkeypatch):
    before = driver.start("wifi-lab")
    def missing(_):
        raise CaptureError("Interface unavailable")
    monkeypatch.setattr(session, "select_interface", missing)
    with pytest.raises(CaptureError, match="unavailable"):
        driver.switch_interface("missing")
    assert driver.snapshot()["sessionId"] == before["sessionId"]
    assert driver.snapshot()["status"] == "running"
    driver.stop()


@pytest.mark.parametrize("expression", ["tcp port 80", "host 192.0.2.1", "udp", "port 53"])
def test_compiled_filter_is_passed_to_capture(driver, monkeypatch, expression):
    calls = []
    monkeypatch.setattr(session, "validate_filter", lambda expr, iface: calls.append((expr, iface)) or expr)
    driver.start("ethernet-lab", expression)
    assert calls == [(expression, "ethernet-lab")]
    assert driver._sniffer.kwargs["filter"] == expression
    driver.stop()


def test_invalid_filter_never_starts_unfiltered_capture(driver, monkeypatch):
    def invalid(*_):
        raise CaptureError("Invalid BPF filter")
    monkeypatch.setattr(session, "validate_filter", invalid)
    with pytest.raises(CaptureError, match="Invalid BPF"):
        driver.start("ethernet-lab", "invalid (")
    assert driver._sniffer is None
    assert not list(driver.output_dir.glob("*.pcap"))


@pytest.mark.parametrize("expression", [None, 123, "\x00", "a" * 4097])
def test_filter_input_validation(expression):
    from capture.filters import validate_filter
    with pytest.raises(CaptureError, match="filter must be text"):
        validate_filter(expression, "unused")


def test_worker_error_cannot_be_reported_as_successful_stop(driver):
    driver.start("wifi-lab")
    driver._sniffer.exception = OSError("adapter removed")
    assert driver.stop()["status"] == "error"


def test_packet_delivery_on_another_thread_can_stop_without_deadlock(driver):
    import threading
    driver.start("wifi-lab")
    delivery = threading.Thread(target=lambda: [driver._on_packet(packet()) for _ in range(30)])
    delivery.start()
    delivery.join(timeout=2)
    assert not delivery.is_alive()
    assert driver.stop()["packets"] == 30


def test_native_packet_linktype_not_forced_to_ethernet(driver):
    driver.start("wifi-lab")
    native = scapy.RadioTap() / scapy.Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                                         addr2="02:00:00:00:00:01", addr3="02:00:00:00:00:01")
    driver._on_packet(native)
    result = driver.stop()
    assert bytes(scapy.rdpcap(result["pcapPath"])[0]) == bytes(native)
