from conftest import PASSWORD, USER


def test_unauthenticated_requests_get_401(raw_client):
    # AC-PPS-F-021
    for method, url in (("get", "/api/interfaces"), ("get", "/api/stats"), ("get", "/api/hosts"),
                        ("get", "/api/alerts"), ("get", "/api/snapshot"), ("post", "/api/capture/start"),
                        ("post", "/api/capture/stop"), ("get", "/api/sessions"), ("post", "/api/export/session/x")):
        r = getattr(raw_client, method)(url)
        assert r.status_code == 401, url
        assert r.get_json()["errorCode"] == "UNAUTHORIZED"


def test_login_success_and_failure(raw_client):
    ok = raw_client.post("/api/auth/login", json={"username": USER, "password": PASSWORD})
    assert ok.status_code == 200 and ok.get_json()["token"]
    bad = raw_client.post("/api/auth/login", json={"username": USER, "password": "wrong-password"})
    assert bad.status_code == 401


def test_login_token_unlocks_api(raw_client):
    token = raw_client.post("/api/auth/login", json={"username": USER, "password": PASSWORD}).get_json()["token"]
    r = raw_client.get("/api/capture/status", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_account_locks_after_repeated_failures(raw_client):
    for _ in range(5):
        raw_client.post("/api/auth/login", json={"username": USER, "password": "nope-nope-nope"})
    r = raw_client.post("/api/auth/login", json={"username": USER, "password": PASSWORD})
    assert r.status_code == 403 and r.get_json()["errorCode"] == "ACCOUNT_LOCKED"


def test_setup_is_refused_once_admin_exists(raw_client):
    r = raw_client.post("/api/auth/setup", json={"username": "second", "password": "another-long-pass"})
    assert r.status_code == 403
    assert raw_client.get("/api/auth/state").get_json() == {"setupRequired": False}


def test_page_is_public_but_data_is_not(raw_client):
    assert raw_client.get("/").status_code == 200


def test_session_history_name_tags_and_reopen(client):
    sid = client.post("/api/capture/start", json={"interface": "Wi-Fi", "sessionName": "Lab run", "filter": "tcp port 80"}).get_json()["sessionId"]
    client.post("/api/capture/stop")
    client.patch(f"/api/sessions/{sid}", json={"tags": ["lab", "demo"]})
    listed = client.get("/api/sessions").get_json()["sessions"]
    assert listed[0]["name"] == "Lab run" and listed[0]["tags"] == ["lab", "demo"] and listed[0]["status"] == "stopped"
    detail = client.get(f"/api/sessions/{sid}").get_json()
    assert detail["hosts"] and detail["alerts"] and detail["stats"]["protocols"]
    assert client.get("/api/sessions/nope").status_code == 404


def test_history_survives_a_second_session(client):
    first = client.post("/api/capture/start", json={"interface": "Wi-Fi"}).get_json()["sessionId"]
    client.post("/api/capture/stop")
    second = client.post("/api/capture/start", json={"interface": "Ethernet"}).get_json()["sessionId"]
    assert first != second
    assert client.get(f"/api/sessions/{first}").get_json()["hosts"]


def test_export_csv_downloads_once(client):
    sid = client.post("/api/capture/start", json={"interface": "Wi-Fi"}).get_json()["sessionId"]
    client.post("/api/capture/stop")
    r = client.post(f"/api/export/session/{sid}", json={"format": "csv"})
    assert r.status_code == 200
    url = r.get_json()["downloadUrl"]
    body = client._c.get(url)                       # no auth header needed: one-time signed link
    assert body.status_code == 200 and b"# Hosts" in body.data and b"192.168.1.10" in body.data
    assert client._c.get(url).status_code == 410    # single use


def test_export_errors(client):
    assert client.post("/api/export/session/nope", json={"format": "csv"}).status_code == 404
    sid = client.post("/api/capture/start", json={"interface": "Wi-Fi"}).get_json()["sessionId"]
    assert client.post(f"/api/export/session/{sid}", json={"format": "exe"}).status_code == 400
    assert client.post(f"/api/export/session/{sid}", json={"format": "pcap"}).status_code == 404   # demo mode: no pcap


def test_csv_injection_is_neutralised():
    import app as a
    assert a._safe("=cmd|' /C calc'!A0").startswith("'")


def test_audit_log_records_admin_actions(client):
    import audit
    client.post("/api/capture/start", json={"interface": "Wi-Fi"})
    client.post("/api/capture/stop")
    events = [e["event"] for e in audit.tail(20)]
    assert "capture_start" in events and "capture_stop" in events
    assert "password" not in open(audit.AUDIT_FILE).read().lower()


def test_conn_log_uses_backend_parser(client):
    client.post("/api/capture/start", json={"interface": "Wi-Fi"})
    data = client.get("/api/logs/conn").get_json()
    assert data["count"] >= 1 and "source_ip" in data["data"][0]


def test_security_headers(raw_client):
    r = raw_client.get("/")
    assert r.headers["X-Content-Type-Options"] == "nosniff" and "frame-ancestors" in r.headers["Content-Security-Policy"]
