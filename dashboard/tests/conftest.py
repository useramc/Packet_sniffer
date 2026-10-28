import os
import tempfile

# Must be set before `app` is imported: deterministic demo data, throwaway secrets/db.
_tmp = tempfile.mkdtemp(prefix="pps-test-")
os.environ["PPS_MODE"] = "mock"
os.environ["PPS_JWT_SECRET"] = "test-secret-not-for-production-0123456789abcdef"
os.environ["PPS_AUTH_DB"] = os.path.join(_tmp, "auth.db")
os.environ["PPS_DATA_DIR"] = _tmp

import pytest  # noqa: E402

import app as dashboard_app  # noqa: E402
from integration import security, store  # noqa: E402

USER, PASSWORD = "analyst", "correct-horse-battery"


class AuthedClient:
    """Flask test client that sends the Bearer token like the browser does."""

    def __init__(self, client, token):
        self._c, self.token = client, token

    def _kw(self, kw):
        kw.setdefault("headers", {})["Authorization"] = f"Bearer {self.token}"
        return kw

    def get(self, *a, **kw):
        return self._c.get(*a, **self._kw(kw))

    def post(self, *a, **kw):
        return self._c.post(*a, **self._kw(kw))

    def patch(self, *a, **kw):
        return self._c.patch(*a, **self._kw(kw))


@pytest.fixture
def raw_client():
    """Unauthenticated client with a clean state and one admin account."""
    dashboard_app.reset_state()
    with store._conn() as conn:
        conn.execute("DELETE FROM users")
    store.create_user(USER, security.hash_password(PASSWORD))
    return dashboard_app.app.test_client()


@pytest.fixture
def client(raw_client):
    token, _ = security.create_access_token(USER)
    return AuthedClient(raw_client, token)


@pytest.fixture
def running_client(client):
    client.post("/api/capture/start", json={"interface": "Wi-Fi"})
    return client
