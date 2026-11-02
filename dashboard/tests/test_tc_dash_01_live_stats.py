from helpers import load_ground_truth, wait_for_type


def within_5_percent(actual, expected):
    return abs(actual - expected) <= 0.05 * expected


def test_tc_dash_01_stats_has_required_fields(running_client):
    response = running_client.get("/api/stats")
    data = response.get_json()
    assert response.status_code == 200
    assert "packets_per_sec" in data
    assert "top_talkers" in data
    assert "protocols" in data


def test_tc_dash_01_stats_match_mock_data(running_client):
    expected = load_ground_truth()
    stats = running_client.get("/api/stats").get_json()
    assert within_5_percent(stats["packets_per_sec"], expected["packets_per_sec"])
    for name, count in expected["protocols"].items():
        assert within_5_percent(stats["protocols"][name], count)
    for exp, act in zip(expected["top_talkers"], stats["top_talkers"]):
        assert act["ip"] == exp["ip"]
        assert within_5_percent(act["packets"], exp["packets"])


def test_tc_dash_01_stats_refused_when_idle(client):
    response = client.get("/api/stats")
    assert response.status_code == 409
    assert response.get_json()["errorCode"] == "INVALID_STATE"


def test_tc_dash_01_stats_refused_when_paused(running_client):
    running_client.post("/api/capture/pause")
    response = running_client.get("/api/stats")
    assert response.status_code == 409
    assert response.get_json()["errorCode"] == "INVALID_STATE"


def test_tc_dash_01_stats_refused_when_stopped(running_client):
    running_client.post("/api/capture/stop")
    response = running_client.get("/api/stats")
    assert response.status_code == 409
    assert response.get_json()["errorCode"] == "INVALID_STATE"


def test_tc_dash_01_stats_pushed_at_least_every_2s(running_client, live_connect):
    ws = live_connect()
    first, _ = wait_for_type(ws, "snapshot", 5)
    second, gap = wait_for_type(ws, "snapshot", 5)
    assert first is not None
    assert second is not None
    assert gap <= 2.5  # 2s refresh + 0.5s tolerance for timing jitter


def test_tc_dash_01_stats_over_websocket_match_mock_data(running_client, live_connect):
    expected = load_ground_truth()
    ws = live_connect()
    message, _ = wait_for_type(ws, "snapshot", 5)
    stats = message["payload"]["stats"]
    assert within_5_percent(stats["packets_per_sec"], expected["packets_per_sec"])
    for name, count in expected["protocols"].items():
        assert within_5_percent(stats["protocols"][name], count)