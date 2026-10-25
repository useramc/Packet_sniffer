import json
from pathlib import Path

MOCK_FILE = Path(__file__).parent.parent / "mock" / "mock_data.json"


def load_ground_truth():
    with open(MOCK_FILE, "r") as f:
        return json.load(f)


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