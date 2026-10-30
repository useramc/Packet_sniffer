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
