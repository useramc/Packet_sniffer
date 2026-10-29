import json
import time
from pathlib import Path

MOCK_FILE = Path(__file__).parent.parent / "mock" / "mock_data.json"


def load_ground_truth():
    with open(MOCK_FILE, "r") as f:
        return json.load(f)


def wait_for_type(ws, msg_type, timeout):
    """Wait for the first message of the given type.
    Returns (message, seconds_waited). message is None if the timeout is reached."""
    start = time.perf_counter()
    while True:
        remaining = timeout - (time.perf_counter() - start)
        if remaining <= 0:
            return None, time.perf_counter() - start
        text = ws.receive(timeout=remaining)
        if text:
            message = json.loads(text)
            if message["type"] == msg_type:
                return message, time.perf_counter() - start