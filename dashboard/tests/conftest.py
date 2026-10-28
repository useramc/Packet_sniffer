import threading

import pytest
from simple_websocket import Client
from werkzeug.serving import make_server

import app as dashboard_app


@pytest.fixture
def client():
    dashboard_app.session.update(
        {"status": "idle", "sessionId": None, "startedAt": None, "count": 0}
    )
    return dashboard_app.app.test_client()


@pytest.fixture
def running_client(client):
    client.post("/api/capture/start", json={"interface": "Wi-Fi"})
    return client


@pytest.fixture
def live_connect(client):
    """Starts the app on a free port and returns connect(token) to open /ws/live."""
    server = make_server("127.0.0.1", 0, dashboard_app.app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    opened = []

    def connect(token="placeholder-token"):
        url = f"ws://127.0.0.1:{server.server_port}/ws/live"
        if token is not None:
            url += f"?token={token}"
        ws = Client.connect(url)
        opened.append(ws)
        return ws

    yield connect

    for ws in opened:
        try:
            ws.close()
        except Exception:
            pass
    server.shutdown()
    thread.join()