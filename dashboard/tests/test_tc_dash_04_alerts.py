import time

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from analytics import Analytics
from integration import read_zeek_tsv


def test_tc_dash_04_alerts_have_severity_and_timestamp(running_client):
    alerts = running_client.get("/api/alerts").get_json()["alerts"]
    assert alerts
    for a in alerts:
        assert a["severity"] in ("high", "medium", "low")
        assert a["time"] and a["message"]


def test_tc_dash_04_port_scan_raises_high_alert_within_5s():
    a = Analytics()
    start = time.perf_counter()
    for port in range(1, 30):
        a.ingest(Ether() / IP(src="10.0.0.9", dst="10.0.0.1") / TCP(dport=port))
    alerts = a.alerts()
    assert time.perf_counter() - start < 5
    assert alerts[0]["severity"] == "high" and "port scan" in alerts[0]["message"]


def test_tc_dash_04_plaintext_credentials_are_masked():
    # PPS-SR-005: the secret itself must never reach the dashboard.
    a = Analytics()
    pkt = Ether() / IP(src="10.0.0.9", dst="10.0.0.80") / TCP(dport=80) / Raw(b"POST /login password=hunter2secret")
    a.ingest(pkt)
    alert = a.alerts()[0]
    assert alert["severity"] == "medium"
    assert "hunter2secret" not in str(alert)


def test_tc_dash_04_zeek_notice_log_becomes_alert(tmp_path):
    log = tmp_path / "notice.log"
    log.write_text("#fields\tts\tnote\tmsg\tsrc\n1697792400.1\tScan::Port_Scan\t10.0.0.9 scanned 20 ports\t10.0.0.9\n")
    a = Analytics()
    a.add_zeek_alerts(read_zeek_tsv(log))
    got = a.alerts()[0]
    assert got["severity"] == "high" and got["source"] == "zeek" and got["src"] == "10.0.0.9"
