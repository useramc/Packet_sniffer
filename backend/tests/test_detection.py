from datetime import datetime, timezone

from detection import detect_suspicious_traffic


def make_record(second, source_ip, dest_ip, dest_port):
    timestamp = datetime.fromtimestamp(
        second, tz=timezone.utc
    ).isoformat()

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "state": "SF",
    }


def test_detects_possible_port_scan():
    records = [
        make_record(
            1000 + index,
            "192.168.1.10",
            "192.168.1.20",
            port,
        )
        for index, port in enumerate([21, 22, 23, 80, 443])
    ]

    alerts = detect_suspicious_traffic(records)

    port_scan_alerts = [
        alert
        for alert in alerts
        if alert["alert_type"] == "possible_port_scan"
    ]

    assert len(port_scan_alerts) == 1

    alert = port_scan_alerts[0]

    assert alert["severity"] == "high"
    assert alert["source_ip"] == "192.168.1.10"
    assert alert["destination_ip"] == "192.168.1.20"
    assert alert["timestamp"]
    assert alert["details"]["port_count"] == 5


def test_normal_traffic_does_not_trigger_port_scan():
    records = [
        make_record(
            2000 + index,
            "192.168.1.10",
            "192.168.1.20",
            80,
        )
        for index in range(3)
    ]

    alerts = detect_suspicious_traffic(records)

    assert not any(
        alert["alert_type"] == "possible_port_scan"
        for alert in alerts
    )


def test_detects_repeated_connection_attempts():
    records = [
        make_record(
            3000 + index,
            "192.168.1.30",
            "192.168.1.40",
            443,
        )
        for index in range(20)
    ]

    alerts = detect_suspicious_traffic(records)

    repeated_alerts = [
        alert
        for alert in alerts
        if alert["alert_type"] == "repeated_connection_attempts"
    ]

    assert len(repeated_alerts) == 1

    alert = repeated_alerts[0]

    assert alert["severity"] == "medium"
    assert alert["source_ip"] == "192.168.1.30"
    assert alert["destination_ip"] == "192.168.1.40"
    assert alert["timestamp"]
    assert alert["details"]["connection_count"] == 20

