import time


def do_action(client, url, body=None):
    start = time.perf_counter()
    client.post(url, json=body)
    status = client.get("/api/capture/status").get_json()["status"]
    return status, time.perf_counter() - start


def test_tc_dash_03_interfaces_listed(client):
    response = client.get("/api/interfaces")
    assert response.status_code == 200
    assert response.get_json()["interfaces"] == ["Wi-Fi", "Ethernet"]


def test_tc_dash_03_start_sets_running_within_2s(client):
    status, elapsed = do_action(client, "/api/capture/start", {"interface": "Wi-Fi"})
    assert status == "running"
    assert elapsed < 2


def test_tc_dash_03_pause_sets_paused_within_2s(running_client):
    status, elapsed = do_action(running_client, "/api/capture/pause")
    assert status == "paused"
    assert elapsed < 2


def test_tc_dash_03_resume_sets_running_within_2s(running_client):
    running_client.post("/api/capture/pause")
    status, elapsed = do_action(running_client, "/api/capture/resume")
    assert status == "running"
    assert elapsed < 2


def test_tc_dash_03_stop_sets_stopped_within_2s(running_client):
    status, elapsed = do_action(running_client, "/api/capture/stop")
    assert status == "stopped"
    assert elapsed < 2


def test_tc_dash_03_start_with_invalid_interface(client):
    response = client.post("/api/capture/start", json={"interface": "Bluetooth"})
    assert response.status_code == 400
    assert response.get_json()["errorCode"] == "INVALID_INTERFACE"
    assert client.get("/api/capture/status").get_json()["status"] == "idle"


def test_tc_dash_03_start_when_running_is_refused(running_client):
    response = running_client.post("/api/capture/start", json={"interface": "Wi-Fi"})
    assert response.status_code == 409
    assert response.get_json()["errorCode"] == "INVALID_STATE"


def test_tc_dash_03_pause_when_idle_is_refused(client):
    response = client.post("/api/capture/pause")
    assert response.status_code == 409
    assert response.get_json()["errorCode"] == "INVALID_STATE"


def test_tc_dash_03_stop_when_idle_is_refused(client):
    response = client.post("/api/capture/stop")
    assert response.status_code == 409
    assert response.get_json()["errorCode"] == "INVALID_STATE"


def test_tc_dash_03_resume_when_running_is_refused(running_client):
    response = running_client.post("/api/capture/resume")
    assert response.status_code == 409
    assert response.get_json()["errorCode"] == "INVALID_STATE"