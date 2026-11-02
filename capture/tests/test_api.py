"""Real auth/JWT + HTTP + real PCAP files; only the capture driver is injected."""
import secrets

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from scapy.all import rdpcap

from capture import api, settings, session
from capture.tests.test_session import driver, packet  # noqa: F401


@pytest.fixture
def client(driver, tmp_path, monkeypatch):  # noqa: F811 (imported pytest fixture)
    from backend.auth import config, store
    from backend.auth.routes import get_current_user, router
    monkeypatch.setattr(config, "JWT_SECRET", secrets.token_hex(32))
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setattr(settings, "select_interface", session.select_interface)
    monkeypatch.setattr(settings, "validate_filter", lambda bpf, iface: bpf)
    monkeypatch.setattr(session, "validate_filter", lambda bpf, iface: bpf)
    monkeypatch.setattr(api, "list_interfaces", lambda: [session.select_interface("wifi-lab")])
    store.init_db()
    app = FastAPI()
    app.include_router(router)
    app.include_router(api.create_router(driver, tmp_path / "settings.json", get_current_user))
    with TestClient(app) as http:
        password = secrets.token_urlsafe(20)
        assert http.post("/api/auth/setup", json={"username": "labuser", "password": password}).status_code == 201
        login = http.post("/api/auth/login", json={"username": "labuser", "password": password})
        token = login.json()["token"]
        yield http, {"Authorization": "Bearer " + token}, driver
    driver.terminate()


@pytest.mark.parametrize("method,path,body", [
    ("GET", "interfaces", None), ("GET", "status", None), ("GET", "settings", None),
    ("PUT", "settings", {"interface": "lab"}), ("POST", "start", {"interface": "lab"}),
    *[("POST", verb, {"sessionId": "unknown"}) for verb in ["stop", "pause", "resume", "terminate"]],
    ("POST", "switch", {"sessionId": "unknown", "interface": "lab"}),
])
def test_all_capture_endpoints_require_existing_auth(client, method, path, body):
    http, _, manager = client
    for headers in [{}, {"Authorization": "Bearer invalid"}]:
        assert http.request(method, "/api/capture/" + path, json=body, headers=headers).status_code == 401
    assert manager.session_id is None


def test_authenticated_capture_pause_switch_stop_and_pcap(client):
    http, headers, manager = client
    assert http.get("/api/capture/interfaces", headers=headers).json()["interfaces"][0]["id"] == "wifi-lab"
    started = http.post("/api/capture/start", headers=headers,
                        json={"interface": "wifi-lab", "sessionName": "Lab"})
    assert started.status_code == 200
    first = started.json()
    body = {"sessionId": first["sessionId"]}
    manager._on_packet(packet())
    assert http.post("/api/capture/start", headers=headers, json={"interface": "lab"}).status_code == 409
    assert http.post("/api/capture/pause", headers=headers, json=body).json()["status"] == "paused"
    manager._on_packet(packet())
    assert http.post("/api/capture/resume", headers=headers, json=body).json()["status"] == "running"
    switched = http.post("/api/capture/switch", headers=headers, json={**body, "interface": "ethernet-lab"}).json()
    assert len(rdpcap(first["pcapPath"])) == 1
    assert switched["previousSession"]["sessionId"] == first["sessionId"]
    assert http.post("/api/capture/stop", headers=headers, json=body).status_code == 404
    manager._on_packet(packet())
    stopped = http.post("/api/capture/stop", headers=headers, json={"sessionId": switched["sessionId"]})
    assert stopped.json()["status"] == "stopped"
    assert len(rdpcap(stopped.json()["pcapPath"])) == 1


def test_saved_settings_used_on_authenticated_start(client):
    http, headers, manager = client
    data = {"interface": "ethernet-lab", "filter": "tcp port 80"}
    assert http.put("/api/capture/settings", headers=headers, json=data).status_code == 200
    assert http.get("/api/capture/settings", headers=headers).json()["filter"] == data["filter"]
    started = http.post("/api/capture/start", headers=headers, json={"sessionName": "Restored"}).json()
    assert started["interface"] == data["interface"]
    assert manager._sniffer.kwargs["filter"] == data["filter"]
    assert http.post("/api/capture/terminate", headers=headers,
                     json={"sessionId": started["sessionId"]}).json()["status"] == "stopped"


def test_invalid_interface_filter_and_session_errors(client, monkeypatch):
    from capture.interfaces import CaptureError
    http, headers, manager = client
    assert http.post("/api/capture/stop", headers=headers, json={"sessionId": "unknown"}).status_code == 404
    def invalid(*_):
        raise CaptureError("Invalid BPF filter")
    monkeypatch.setattr(session, "validate_filter", invalid)
    result = http.post("/api/capture/start", headers=headers,
                       json={"interface": "wifi-lab", "filter": "bad ("})
    assert result.status_code == 400
    assert result.json()["errorCode"] == "CAPTURE_START_FAILED"
    assert manager.session_id is None


def test_invalid_request_returns_capture_error_envelope(client):
    http, headers, _ = client
    response = http.post("/api/capture/start", headers=headers, json={"interface": 123})
    assert response.status_code == 400
    assert response.json()["errorCode"] == "INVALID_REQUEST"


def test_capture_launcher_reuses_backend_auth_and_lifespan(tmp_path):
    import os
    import subprocess
    import sys
    env = {**os.environ, "PPS_JWT_SECRET": secrets.token_hex(32),
           "PPS_AUTH_DB": str(tmp_path / "launcher.db"),
           "PPS_CAPTURE_DATA_DIR": str(tmp_path / "capture")}
    script = """
from capture.server import create_app
from fastapi.testclient import TestClient
app = create_app()
assert create_app() is app
with TestClient(app) as client:
    assert client.get('/api/health').status_code == 200
    assert client.get('/api/capture/status').status_code == 401
    assert client.post('/api/auth/login', json={}).status_code == 422
assert app.state.capture_manager.status == 'stopped'
"""
    result = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
