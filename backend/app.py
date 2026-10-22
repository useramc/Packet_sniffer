import os
from pathlib import Path
from tempfile import TemporaryDirectory

from flask import Flask, jsonify, request

from parsers.zeek_parser import ZeekLogParser
from zeek_runner import analyze_pcap

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ZEEK_LOGS_PATH = os.path.join(BASE_DIR, "sample_logs")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "success",
        "message": "Packet Sniffer API is running",
        "logs_dir": ZEEK_LOGS_PATH,
    }), 200


@app.route("/api/logs/conn", methods=["GET"])
def get_connection_logs():
    parser = ZeekLogParser(ZEEK_LOGS_PATH)
    logs = parser.parse_conn_log()

    return jsonify({
        "status": "success",
        "count": len(logs),
        "data": logs,
    }), 200


@app.route("/api/zeek/analyze", methods=["POST"])
def analyze_capture():
    uploaded_file = request.files.get("pcap")

    if uploaded_file is None or not uploaded_file.filename:
        return jsonify({
            "status": "error",
            "message": "Upload a PCAP file using the 'pcap' field.",
        }), 400

    filename = Path(uploaded_file.filename).name

    if Path(filename).suffix.lower() not in {".pcap", ".pcapng"}:
        return jsonify({
            "status": "error",
            "message": "Only .pcap and .pcapng files are supported.",
        }), 400

    try:
        with TemporaryDirectory(prefix="zeek-pcap-") as temp_dir:
            pcap_path = Path(temp_dir) / filename
            uploaded_file.save(str(pcap_path))

            result = analyze_pcap(pcap_path)

        return jsonify(result), 200

    except (FileNotFoundError, ValueError) as exc:
        return jsonify({
            "status": "error",
            "message": str(exc),
        }), 400

    except TimeoutError as exc:
        return jsonify({
            "status": "error",
            "message": str(exc),
        }), 504

    except RuntimeError as exc:
        return jsonify({
            "status": "error",
            "message": str(exc),
        }), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)