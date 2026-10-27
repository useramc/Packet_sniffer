import json
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
MOCK_FILE = Path(__file__).parent / "mock" / "mock_data.json"

INTERFACES = ["Wi-Fi", "Ethernet"]
MAX_PACKETS = 20
session = {"status": "idle", "sessionId": None, "startedAt": None, "count": 0}


def load_mock_data():
    with open(MOCK_FILE, "r") as f:
        return json.load(f)


def error(code, message, http_status):
    return jsonify({"errorCode": code, "message": message}), http_status


def change_status(allowed_from, new_status):
    if session["status"] not in allowed_from:
        return error(
            "INVALID_STATE",
            f"Cannot go to '{new_status}' from '{session['status']}'",
            409,
        )
    session["status"] = new_status
    return jsonify({"status": new_status})


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/mock")
def mock():
    return jsonify(load_mock_data())


@app.route("/api/interfaces")
def get_interfaces():
    return jsonify({"interfaces": INTERFACES})


@app.route("/api/capture/status")
def get_status():
    return jsonify({
        "status": session["status"],
        "sessionId": session["sessionId"],
        "startedAt": session["startedAt"],
    })

@app.route("/api/stats")
def get_stats():
    if session["status"] != "running":
        return error("INVALID_STATE", "No active capture session", 409)
    data = load_mock_data()
    return jsonify({
        "packets_per_sec": data["packets_per_sec"],
        "top_talkers": data["top_talkers"],
        "protocols": data["protocols"],
    })

@app.route("/api/hosts")
def get_hosts():
    if session["status"] != "running":
        return error("INVALID_STATE", "No active capture session", 409)
    return jsonify({"hosts": load_mock_data()["hosts"]})


@app.route("/api/packets")
def get_packets():
    if session["status"] != "running":
        return error("INVALID_STATE", "No active capture session", 409)
    packets = load_mock_data()["packets"]
    packets = sorted(packets, key=lambda packet: packet["time"], reverse=True)
    return jsonify({"packets": packets[:MAX_PACKETS]})

@app.route("/api/alerts")
def get_alerts():
    if session["status"] != "running":
        return error("INVALID_STATE", "No active capture session", 409)
    alerts = load_mock_data()["alerts"]
    alerts = sorted(alerts, key=lambda alert: alert["time"], reverse=True)
    return jsonify({"alerts": alerts})

@app.route("/api/capture/start", methods=["POST"])
def start_capture():
    data = request.get_json(silent=True) or {}
    if data.get("interface") not in INTERFACES:
        return error("INVALID_INTERFACE", "Unknown network interface", 400)
    if session["status"] in ("running", "paused"):
        return error("INVALID_STATE", "Capture already running", 409)
    session["count"] += 1
    session["status"] = "running"
    session["sessionId"] = f"mock-{session['count']:03d}"
    session["startedAt"] = datetime.now().isoformat(timespec="seconds")
    return jsonify({
        "sessionId": session["sessionId"],
        "status": session["status"],
        "startedAt": session["startedAt"],
    })


@app.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    return change_status(("running", "paused"), "stopped")


@app.route("/api/capture/pause", methods=["POST"])
def pause_capture():
    return change_status(("running",), "paused")


@app.route("/api/capture/resume", methods=["POST"])
def resume_capture():
    return change_status(("paused",), "running")


if __name__ == "__main__":
    app.run(debug=True)