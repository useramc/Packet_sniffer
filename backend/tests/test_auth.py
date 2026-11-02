"""
Covers TC-SEC-01 (credential hashing) and TC-AUTH-01 (protected access -> 401)
from the SRS RTM (Section 8), plus the first-run setup flow (PPS-SR-004).
"""
from fastapi.testclient import TestClient

from auth import store
from main import app

client = TestClient(app)


def test_health_is_unauthenticated():
    resp = client.get("/api/health")
    assert resp.status_code == 200


def test_protected_route_rejects_unauthenticated_request():
    # AC-PPS-F-021 / TC-AUTH-01
    resp = client.get("/api/me")
    assert resp.status_code == 401


def test_setup_creates_admin_and_returns_token():
    resp = client.post("/api/auth/setup", json={"username": "admin", "password": "correct-horse-battery"})
    assert resp.status_code == 201
    body = resp.json()
    assert body.get("token")
    assert "expiresAt" in body


def test_setup_refuses_once_a_user_already_exists():
    client.post("/api/auth/setup", json={"username": "admin", "password": "correct-horse-battery"})
    resp = client.post("/api/auth/setup", json={"username": "someone-else", "password": "another-password"})
    assert resp.status_code == 403


def test_password_is_never_stored_in_plaintext():
    # AC-PPS-SR-001
    client.post("/api/auth/setup", json={"username": "admin", "password": "correct-horse-battery"})
    row = store.get_user("admin")
    assert row["password_hash"] != "correct-horse-battery"
    assert row["password_hash"].startswith("$2b$")  # bcrypt hash prefix


def test_login_with_correct_credentials_succeeds():
    client.post("/api/auth/setup", json={"username": "admin", "password": "correct-horse-battery"})
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "correct-horse-battery"})
    assert resp.status_code == 200
    assert "token" in resp.json()


def test_login_with_wrong_password_returns_401():
    client.post("/api/auth/setup", json={"username": "admin", "password": "correct-horse-battery"})
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password"})
    assert resp.status_code == 401


def test_login_with_unknown_username_returns_401_not_404():
    # Same failure shape as wrong password, so the endpoint doesn't leak
    # whether a username exists.
    resp = client.post("/api/auth/login", json={"username": "nobody", "password": "whatever123"})
    assert resp.status_code == 401


def test_valid_token_grants_access_to_protected_route():
    creds = {"username": "admin", "password": "correct-horse-battery"}
    # pragma: allowlist nextline secret
    client.post("/api/auth/setup", json={"username": "admin", "password": "correct-horse-battery"})
    client.post("/api/auth/setup", json=creds)
    login_resp = client.post("/api/auth/login", json=creds)
    token = login_resp.json()["token"]
    resp = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["username"] == "admin"


def test_garbage_token_is_rejected():
    resp = client.get("/api/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401
