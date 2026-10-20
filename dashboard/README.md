# Dashboard – Setup

## Files
- `requirements.txt` (repo root): Flask 3.1.3 and pytest 9.1.1, pinned.
- `pytest.ini` (repo root): tells pytest to look in `dashboard/tests`.
- `.gitignore` (repo root): ignores `.venv/`, `__pycache__/`, `.pytest_cache/`.

## Commands (Windows, run from repo root `Packet_sniffer/`)
| Step | Command | Output |
|---|---|---|
| Create virtual environment | `python -m venv .venv` | `.venv/` folder |
| Activate it | `.venv\Scripts\activate` | `(.venv)` appears in the prompt |
| Install packages | `pip install -r requirements.txt` | Flask and pytest installed |
| Run tests | `pytest -v` | `2 passed` |

# PPS-5 – Dashboard Skeleton

## Functions (`app.py`)

### `load_mock_data()`
- **Input arguments:** none
- **Output:** a Python dictionary read from `mock/mock_data.json`

### `index()`  → route `GET /`
- **Input arguments:** none
- **Output:** the HTML page `templates/index.html` with four empty labelled panels: Session Controls, Live Traffic Statistics, Hosts, Alerts

### `mock()`  → route `GET /api/mock`
- **Input arguments:** none
- **Output:** the mock data as JSON, with keys `packets_per_sec`, `top_talkers`, `protocols`, `hosts`, `alerts`

# PPS-F-013 – Session Controls

Session state is kept in memory and resets when Flask restarts.
States: `idle`, `running`, `paused`, `stopped`.
All errors return `{ "errorCode": ..., "message": ... }`.

## Functions (`app.py`)

### `error(code, message, http_status)`
- **Input arguments:** `code` (str), `message` (str), `http_status` (int)
- **Output:** JSON `{errorCode, message}` with the given HTTP status

### `change_status(allowed_from, new_status)`
- **Input arguments:** `allowed_from` (tuple of states), `new_status` (str)
- **Output:** `{status}` if the current state is allowed; otherwise error `INVALID_STATE` (409)

### `get_interfaces()` → `GET /api/interfaces`
- **Input arguments:** none
- **Output:** `{interfaces: ["Wi-Fi", "Ethernet"]}`

### `get_status()` → `GET /api/capture/status`
- **Input arguments:** none
- **Output:** `{status, sessionId, startedAt}`

### `start_capture()` → `POST /api/capture/start`
- **Input arguments:** JSON body `{interface}`
- **Output:** `{sessionId, status, startedAt}`
- **Errors:** `INVALID_INTERFACE` (400), `INVALID_STATE` (409, if already running or paused)

### `stop_capture()` → `POST /api/capture/stop`
- **Input arguments:** none
- **Output:** `{status: "stopped"}`
- **Errors:** `INVALID_STATE` (409, if not running or paused)

### `pause_capture()` → `POST /api/capture/pause`
- **Input arguments:** none
- **Output:** `{status: "paused"}`
- **Errors:** `INVALID_STATE` (409, if not running)

### `resume_capture()` → `POST /api/capture/resume`
- **Input arguments:** none
- **Output:** `{status: "running"}`
- **Errors:** `INVALID_STATE` (409, if not paused)

## Functions (`templates/index.html`, JavaScript)

### `loadInterfaces()`
- **Input arguments:** none
- **Output:** fills the interface dropdown from `/api/interfaces`

### `refreshStatus()`
- **Input arguments:** none
- **Output:** reads `/api/capture/status` and calls `updateControls()`. Runs every 1 second.

### `updateControls(status)`
- **Input arguments:** `status` (str)
- **Output:** shows the status, enables or disables the dropdown and buttons, and switches the Pause button to "Resume" when paused

### `sendAction(url, body)`
- **Input arguments:** `url` (str), `body` (object, optional)
- **Output:** sends a POST request, shows the error message if one is returned, then refreshes the status