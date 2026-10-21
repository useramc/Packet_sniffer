import pytest

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