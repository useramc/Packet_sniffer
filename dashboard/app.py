"""
Pocket Packet Sniffer - Dashboard Backend API + Frontend host (PPS-F-011..014, PPS-F-016..017, PPS-F-021).

Modes (PPS_MODE=auto|live|mock):
  live - real capture (capture module + Scapy), live Analytics, Zeek on stop
  mock - deterministic data from mock/mock_data.json (demo / CI / no privileges)
Auth, audit logging, WebSocket push, session history and export are identical in both.
"""
import csv
import io
import json
import os
import random
import secrets
import time
import zipfile
from collections import OrderedDict
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import audit
import integration as integ
from analytics import Analytics
from flask import Flask, Response, g, jsonify, render_template, request, send_file
from integration import CaptureError, security, store

try:
    from flask_sock import Sock
except ImportError:  # polling fallback in the UI keeps working
    Sock = None

app = Flask(__name__)
MOCK_FILE = Path(__file__).parent / "mock" / "mock_data.json"
SESSIONS_DIR = integ.DATA_DIR / "sessions"

MODE = integ.detect_mode()
MOCK_INTERFACES = ["Wi-Fi", "Ethernet"]
INTERFACES = MOCK_INTERFACES                      # kept for backwards compatibility with tests
analytics = Analytics()
live = None
if MODE == "live":
    from live_capture import LiveCapture
    live = LiveCapture(analytics)

session = {"status": "idle", "sessionId": None, "startedAt": None, "count": 0}
records = OrderedDict()                           # sessionId -> record (history, PPS-F-017)
downloads = {}                                    # one-time export tokens
failed_logins = {}


# ------------------------------------------------------------------ helpers
def load_mock_data():
    with open(MOCK_FILE, "r") as f:
        return json.load(f)


def error(code, message, http_status):
    return jsonify({"errorCode": code, "message": message}), http_status


def reset_state():
    """Used by tests: forget sessions, analytics and lockouts."""
    session.update({"status": "idle", "sessionId": None, "startedAt": None, "count": 0})
    records.clear(); downloads.clear(); failed_logins.clear(); analytics.reset()


def user_from_token(token):
    try:
        return security.decode_access_token(token)
    except Exception:
        return None


def auth_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        header = request.headers.get("Authorization", "")
        user = user_from_token(header[7:]) if header.startswith("Bearer ") else None
        if not user:
            return error("UNAUTHORIZED", "Authentication required", 401)
        g.user = user
        return fn(*a, **kw)
    return wrapper


@app.after_request
def secure_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; frame-ancestors 'none'")
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# --------------------------------------------------------------- data views
def zeek_info():
    return live.zeek if live else {"status": "mock"}


def current_data():
    """(stats, hosts, alerts) for the active / most recent session."""
    if session["status"] == "idle":
        return None, [], []
    if MODE == "live":
        return analytics.stats(), analytics.host_list(), analytics.alerts()
    d = load_mock_data()
    pps = d["packets_per_sec"]
    if session["status"] == "running":
        pps = round(pps * random.uniform(0.97, 1.03))   # stays within the 5 % AC of PPS-F-011
    stats = {"packets_per_sec": pps, "top_talkers": d["top_talkers"], "protocols": d["protocols"]}
    return stats, d["hosts"], list(reversed(d["alerts"]))


def build_snapshot():
    stats, hosts, alerts = current_data()
    return {"status": session["status"], "sessionId": session["sessionId"],
            "startedAt": session["startedAt"], "mode": MODE, "stats": stats,
            "hosts": hosts, "alerts": alerts, "zeek": zeek_info()}


def freeze_current():
    rec = records.get(session["sessionId"])
    if rec and rec["snapshot"] is None and session["status"] != "idle":
        stats, hosts, alerts = current_data()
        rec["snapshot"] = {"stats": stats, "hosts": hosts, "alerts": alerts, "zeek": zeek_info()}


def session_view(rec, detail=False):
    is_current = rec["id"] == session["sessionId"]
    out = {k: rec[k] for k in ("id", "name", "tags", "interface", "filter", "startedAt", "stoppedAt", "mode")}
    out["status"] = session["status"] if is_current else "stopped"
    out["hasPcap"] = bool(rec["dir"] and (Path(rec["dir"]) / "capture.pcap").exists())
    if detail:
        if is_current:
            stats, hosts, alerts = current_data()
            out.update(stats=stats, hosts=hosts, alerts=alerts, zeek=zeek_info())
        else:
            out.update(rec["snapshot"] or {})
    return out


def change_status(allowed_from, new_status):
    if session["status"] not in allowed_from:
        return error("INVALID_STATE",
                     f"Cannot go to '{new_status}' from '{session['status']}'", 409)
    session["status"] = new_status
    return jsonify({"status": new_status})


# ---------------------------------------------------------------- pages/meta
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/mock")
def mock():
    return jsonify(load_mock_data())


@app.route("/api/config")
def config():
    return jsonify({"mode": MODE, "websocket": Sock is not None,
                    "zeek": integ.zeek_status() if MODE == "live" else {"available": False, "message": "Demo mode"}})


# --------------------------------------------------------------------- auth
@app.route("/api/auth/state")
def auth_state():
    return jsonify({"setupRequired": not store.has_any_user()})


def _token_response(username, status=200):
    token, expires = security.create_access_token(username)
    return jsonify({"token": token, "expiresAt": expires.isoformat()}), status


@app.route("/api/auth/setup", methods=["POST"])
def auth_setup():
    data = request.get_json(silent=True) or {}
    username, password = str(data.get("username", "")).strip(), str(data.get("password", ""))
    if store.has_any_user():
        return error("SETUP_DONE", "Setup already completed. An administrator account exists.", 403)
    if not 3 <= len(username) <= 64 or not 8 <= len(password) <= 128:
        return error("INVALID_INPUT", "Username needs 3+ characters and password 8+ characters.", 400)
    store.create_user(username, security.hash_password(password))
    audit.log("admin_created", username)
    return _token_response(username, 201)


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}
    username, password = str(data.get("username", "")), str(data.get("password", ""))
    count, first = failed_logins.get(username, (0, time.time()))
    if time.time() - first > 300:
        count, first = 0, time.time()
    if count >= 5:
        audit.log("login_locked", username)
        return error("ACCOUNT_LOCKED", "Too many failed attempts. Try again in a few minutes.", 403)
    user = store.get_user(username)
    if user is None or not security.verify_password(password, user["password_hash"]):
        failed_logins[username] = (count + 1, first)
        audit.log("login_failed", username)
        return error("INVALID_CREDENTIALS", "Invalid credentials", 401)
    failed_logins.pop(username, None)
    audit.log("login_ok", username)
    return _token_response(username)


# ------------------------------------------------------ capture / session ctl
@app.route("/api/interfaces")
@auth_required
def get_interfaces():
    if MODE == "live":
        try:
            found = integ.list_interfaces()
        except CaptureError as exc:
            return error("CAPTURE_UNAVAILABLE", str(exc), 503)
        return jsonify({"interfaces": [i.id for i in found],
                        "details": [{"id": i.id, "name": i.name, "description": i.description,
                                     "addresses": list(i.addresses)} for i in found]})
    return jsonify({"interfaces": MOCK_INTERFACES,
                    "details": [{"id": n, "name": n, "description": "Demo interface", "addresses": []}
                                for n in MOCK_INTERFACES]})


@app.route("/api/capture/status")
@auth_required
def get_status():
    return jsonify({"status": session["status"], "sessionId": session["sessionId"],
                    "startedAt": session["startedAt"]})


@app.route("/api/snapshot")
@auth_required
def get_snapshot():
    return jsonify(build_snapshot())


@app.route("/api/capture/start", methods=["POST"])
@auth_required
def start_capture():
    data = request.get_json(silent=True) or {}
    iface = data.get("interface")
    bpf = str(data.get("filter") or "").strip()
    if MODE == "live":
        try:
            integ.select_interface(str(iface))
        except CaptureError as exc:
            return error("INVALID_INTERFACE", str(exc), 400)
    elif iface not in MOCK_INTERFACES:
        return error("INVALID_INTERFACE", "Unknown network interface", 400)
    if session["status"] in ("running", "paused"):
        return error("INVALID_STATE", "Capture already running", 409)

    freeze_current()
    session["count"] += 1
    started = datetime.now()
    sid = (f"S{started:%Y%m%d-%H%M%S}" if MODE == "live" else f"mock-{session['count']:03d}")
    sdir = SESSIONS_DIR / sid if MODE == "live" else None
    if MODE == "live":
        analytics.reset()
        try:
            live.start(sdir, iface, bpf)
        except CaptureError as exc:
            return error("CAPTURE_FAILED", str(exc), 500)
    name = str(data.get("sessionName") or "").strip()[:80] or f"Session {session['count']}"
    session.update(status="running", sessionId=sid, startedAt=started.isoformat(timespec="seconds"))
    records[sid] = {"id": sid, "name": name, "tags": [], "interface": iface, "filter": bpf,
                    "startedAt": session["startedAt"], "stoppedAt": None, "mode": MODE,
                    "dir": str(sdir) if sdir else None, "snapshot": None}
    audit.log("capture_start", getattr(g, "user", None), session=sid, interface=iface, filter=bpf)
    return jsonify({"sessionId": sid, "status": "running", "startedAt": session["startedAt"]})


@app.route("/api/capture/stop", methods=["POST"])
@auth_required
def stop_capture():
    result = change_status(("running", "paused"), "stopped")
    if isinstance(result, tuple):
        return result
    rec = records.get(session["sessionId"])
    if rec:
        rec["stoppedAt"] = datetime.now().isoformat(timespec="seconds")
    if live:
        live.stop()
    audit.log("capture_stop", g.user, session=session["sessionId"])
    return result


@app.route("/api/capture/pause", methods=["POST"])
@auth_required
def pause_capture():
    result = change_status(("running",), "paused")
    if live and not isinstance(result, tuple):
        live.pause()
    return result


@app.route("/api/capture/resume", methods=["POST"])
@auth_required
def resume_capture():
    result = change_status(("paused",), "running")
    if live and not isinstance(result, tuple):
        live.resume()
    return result


# ---------------------------------------------- stats / hosts / alerts / logs
@app.route("/api/stats")
@auth_required
def get_stats():
    if session["status"] != "running":
        return error("INVALID_STATE", "No active capture session", 409)
    return jsonify(current_data()[0])


@app.route("/api/hosts")
@auth_required
def get_hosts():
    return jsonify({"hosts": current_data()[1]})


@app.route("/api/alerts")
@auth_required
def get_alerts():
    return jsonify({"alerts": current_data()[2]})


@app.route("/api/logs/conn")
@auth_required
def conn_logs():
    """Zeek conn.log records via the backend's ZeekLogParser (PPS-F-007/009)."""
    from parsers.zeek_parser import ZeekLogParser
    logs_dir = None
    z = zeek_info()
    if z.get("output_dir") and (Path(z["output_dir"]) / "conn.log").exists():
        logs_dir = z["output_dir"]
    elif MODE == "mock":
        logs_dir = str(integ.REPO_ROOT / "backend" / "sample_logs")
    if not logs_dir:
        return error("NO_DATA", "No Zeek conn.log available for this session yet", 404)
    rows = ZeekLogParser(logs_dir).parse_conn_log()
    return jsonify({"count": len(rows), "data": rows[:500]})


# ----------------------------------------------------------------- sessions
@app.route("/api/sessions")
@auth_required
def list_sessions():
    return jsonify({"sessions": [session_view(r) for r in reversed(records.values())]})


@app.route("/api/sessions/<sid>")
@auth_required
def get_session(sid):
    rec = records.get(sid)
    if not rec:
        return error("NOT_FOUND", "Session not found", 404)
    return jsonify(session_view(rec, detail=True))


@app.route("/api/sessions/<sid>", methods=["PATCH"])
@auth_required
def tag_session(sid):
    rec = records.get(sid)
    if not rec:
        return error("NOT_FOUND", "Session not found", 404)
    data = request.get_json(silent=True) or {}
    if "name" in data:
        rec["name"] = str(data["name"]).strip()[:80] or rec["name"]
    if "tags" in data and isinstance(data["tags"], list):
        rec["tags"] = [str(t).strip()[:24] for t in data["tags"] if str(t).strip()][:8]
    audit.log("session_update", g.user, session=sid)
    return jsonify(session_view(rec))


# ------------------------------------------------------------------- export
def _safe(cell):
    s = "" if cell is None else str(cell)
    return "'" + s if s[:1] in "=+-@\t\r" else s      # CSV-injection guard


def build_csv(rec):
    d = session_view(rec, detail=True)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["# Session", d["id"], d["name"], d["interface"], d["startedAt"], d["stoppedAt"] or ""])
    stats = d.get("stats") or {}
    w.writerow([]); w.writerow(["# Stats"]); w.writerow(["packets_per_sec", stats.get("packets_per_sec", "")])
    w.writerow(["protocol", "packets"])
    for k, v in (stats.get("protocols") or {}).items():
        w.writerow([_safe(k), v])
    w.writerow(["top_talker_ip", "packets"])
    for t in stats.get("top_talkers") or []:
        w.writerow([_safe(t["ip"]), t["packets"]])
    w.writerow([]); w.writerow(["# Hosts"])
    w.writerow(["ip", "mac", "vendor", "protocol", "packets", "first_seen", "last_seen"])
    for h in d.get("hosts") or []:
        w.writerow([_safe(h.get(c)) for c in ("ip", "mac", "vendor", "protocol", "packets", "first_seen", "last_seen")])
    w.writerow([]); w.writerow(["# Alerts"])
    w.writerow(["time", "severity", "message", "src", "detail", "source"])
    for a in d.get("alerts") or []:
        w.writerow([_safe(a.get(c)) for c in ("time", "severity", "message", "src", "detail", "source")])
    return buf.getvalue().encode("utf-8")


def _register_download(data, filename, mime, path=None):
    token = secrets.token_urlsafe(24)
    expires = datetime.now() + timedelta(minutes=5)
    downloads[token] = {"data": data, "path": path, "filename": filename, "mime": mime, "expires": expires}
    return token, expires


@app.route("/api/export/session/<sid>", methods=["POST"])
@auth_required
def export_session(sid):
    rec = records.get(sid)
    if not rec:
        return error("NOT_FOUND", "Session not found", 404)
    fmt = (request.get_json(silent=True) or {}).get("format")
    if fmt == "csv":
        token, exp = _register_download(build_csv(rec), f"{sid}.csv", "text/csv")
    elif fmt == "pcap":
        p = Path(rec["dir"] or "") / "capture.pcap"
        if not rec["dir"] or not p.exists():
            return error("NO_DATA", "No PCAP exists for this session (demo mode or purged).", 404)
        token, exp = _register_download(None, f"{sid}.pcap", "application/vnd.tcpdump.pcap", path=str(p))
    elif fmt == "zeek-logs":
        zeek = session_view(rec, detail=True).get("zeek") or {}
        out = Path(zeek.get("output_dir") or "")
        logs = sorted(out.glob("*.log")) if zeek.get("output_dir") and out.is_dir() else []
        if not logs:
            return error("NO_DATA", "No Zeek logs for this session (Zeek unavailable or still running).", 404)
        mem = io.BytesIO()
        with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as z:
            for p in logs:
                z.write(p, p.name)
        token, exp = _register_download(mem.getvalue(), f"{sid}-zeek-logs.zip", "application/zip")
    else:
        return error("INVALID_FORMAT", "format must be 'pcap', 'zeek-logs' or 'csv'", 400)
    audit.log("export", g.user, session=sid, format=fmt)
    return jsonify({"downloadUrl": f"/api/download/{token}", "expiresAt": exp.isoformat(timespec="seconds")})


@app.route("/api/download/<token>")
def download(token):
    item = downloads.pop(token, None)             # single use
    if not item or item["expires"] < datetime.now():
        return error("EXPIRED", "Download link expired or already used", 410)
    if item["path"]:
        return send_file(item["path"], mimetype=item["mime"], as_attachment=True, download_name=item["filename"])
    return Response(item["data"], mimetype=item["mime"],
                    headers={"Content-Disposition": f'attachment; filename="{item["filename"]}"'})


# ---------------------------------------------------------------- websocket
if Sock is not None:
    sock = Sock(app)

    @sock.route("/ws/live")
    def ws_live(ws):
        if not user_from_token(request.args.get("token", "")):
            ws.close(reason=1008, message="unauthorized")
            return
        try:
            while True:
                ws.send(json.dumps({"type": "snapshot", "payload": build_snapshot()}))
                ws.receive(timeout=1)             # doubles as the 1 s tick; raises when client leaves
        except Exception:
            pass


def main():
    store.init_db()
    cert, key = os.environ.get("PPS_TLS_CERT"), os.environ.get("PPS_TLS_KEY")
    ctx = (cert, key) if cert and key else None     # PPS-SR-002: HTTPS when certs are supplied
    app.run(host=os.environ.get("PPS_HOST", "127.0.0.1"), port=int(os.environ.get("PPS_PORT", "5000")),
            debug=False, threaded=True, ssl_context=ctx)


store.init_db()
if __name__ == "__main__":
    main()
