<<<<<<< HEAD
from helpers import load_ground_truth, wait_for_type


def test_tc_dash_02_hosts_arrive_within_5s(client, live_connect):
    ws = live_connect()
    client.post("/api/capture/start", json={"interface": "Wi-Fi"})
    message, waited = wait_for_type(ws, "hosts", 5)
    assert message is not None
    assert waited <= 5


def test_tc_dash_02_hosts_match_mock_data(running_client, live_connect):
    expected = load_ground_truth()["hosts"]
    ws = live_connect()
    message, _ = wait_for_type(ws, "hosts", 5)
    hosts = message["data"]["hosts"]
    assert [h["ip"] for h in hosts] == [h["ip"] for h in expected]
    assert [h["mac"] for h in hosts] == [h["mac"] for h in expected]


def test_tc_dash_02_packets_arrive_newest_first_and_capped(client, live_connect):
    ws = live_connect()
    client.post("/api/capture/start", json={"interface": "Wi-Fi"})
    message, waited = wait_for_type(ws, "packets", 5)
    packets = message["data"]["packets"]
    times = [p["time"] for p in packets]
    assert waited <= 5
    assert len(packets) <= 20
    assert times == sorted(times, reverse=True)
=======
import time

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from analytics import Analytics, vendor_for


def test_tc_dash_02_hosts_empty_when_idle(client):
    assert client.get("/api/hosts").get_json()["hosts"] == []


def test_tc_dash_02_hosts_have_required_fields(running_client):
    hosts = running_client.get("/api/hosts").get_json()["hosts"]
    assert hosts
    for h in hosts:
        for key in ("ip", "mac", "vendor", "protocol", "packets", "first_seen", "last_seen"):
            assert key in h


def test_tc_dash_02_new_host_appears_within_5s():
    # AC-PPS-F-012: a newly observed host is listed within 5 s (here: immediately).
    a = Analytics()
    start = time.perf_counter()
    a.ingest(Ether(src="b8:27:eb:11:22:33") / IP(src="192.168.1.77", dst="8.8.8.8") / TCP(dport=443))
    hosts = a.host_list()
    assert time.perf_counter() - start < 5
    h = next(x for x in hosts if x["ip"] == "192.168.1.77")
    assert h["mac"].lower() == "b8:27:eb:11:22:33" and h["vendor"] == "Raspberry Pi"
    assert h["protocol"] == "HTTPS"


def test_tc_dash_02_remote_host_gets_no_router_mac():
    a = Analytics()
    a.ingest(Ether(src="00:50:56:00:00:01") / IP(src="93.184.216.34", dst="192.168.1.5") / TCP(sport=80, dport=5555))
    remote = next(h for h in a.host_list() if h["ip"] == "93.184.216.34")
    assert remote["mac"] is None


def test_vendor_lookup_flags_randomized_macs():
    assert vendor_for("3E:7A:19:00:C2:88") == "Randomized / private MAC"
    assert vendor_for(None) is None
>>>>>>> develop
