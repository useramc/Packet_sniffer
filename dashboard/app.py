import json
from pathlib import Path

from flask import Flask, jsonify, render_template

app = Flask(__name__)
MOCK_FILE = Path(__file__).parent / "mock" / "mock_data.json"


def load_mock_data():
    with open(MOCK_FILE, "r") as f:
        return json.load(f)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/mock")
def mock():
    return jsonify(load_mock_data())


if __name__ == "__main__":
    app.run(debug=True)