from helpers import load_ground_truth, wait_for_type


def test_tc_dash_04_alert_arrives_within_5s(client, live_connect):
    ws = live_connect()
    client.post("/api/capture/start", json={"interface": "Wi-Fi"})
    message, waited = wait_for_type(ws, "alerts", 5)
    assert message is not None
    assert waited <= 5
    assert len(message["data"]["alerts"]) > 0


def test_tc_dash_04_alert_severity_matches_mock_data(running_client, live_connect):
    expected = {a["message"]: a["severity"] for a in load_ground_truth()["alerts"]}
    ws = live_connect()
    message, _ = wait_for_type(ws, "alerts", 5)
    alerts = message["data"]["alerts"]
    assert len(alerts) == len(expected)
    for alert in alerts:
        assert alert["severity"] == expected[alert["message"]]
        assert alert["severity"] in ("critical", "high", "medium", "low")


def test_tc_dash_04_alerts_newest_first(running_client, live_connect):
    ws = live_connect()
    message, _ = wait_for_type(ws, "alerts", 5)
    times = [a["time"] for a in message["data"]["alerts"]]
    assert times == sorted(times, reverse=True)