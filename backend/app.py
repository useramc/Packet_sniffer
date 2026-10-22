import os

from flask import Flask, jsonify
from parsers.zeek_parser import ZeekLogParser

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ZEEK_LOGS_PATH = os.path.join(BASE_DIR, "sample_logs") 

@app.route("/api/logs/conn", methods=["GET"])
def get_connection_logs():
    parser = ZeekLogParser(ZEEK_LOGS_PATH)
    logs = parser.parse_conn_log()
    return jsonify({"status": "success", "count": len(logs), "data": logs}), 200

if __name__ == "__main__":
    app.run(debug=True, port=5000)