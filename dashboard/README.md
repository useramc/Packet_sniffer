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

# PPS-F-011 – Live Traffic Statistics

Stats come from the static `mock/mock_data.json`, so the values do not change.
The panel is refreshed by polling every 2 seconds.

## Functions (`app.py`)

### `get_stats()` → `GET /api/stats`
- **Input arguments:** none
- **Output:** `{packets_per_sec, top_talkers, protocols}`
  - `packets_per_sec`: number
  - `top_talkers`: list of `{ip, packets}`
  - `protocols`: map of protocol name to packet count
- **Errors:** `INVALID_STATE` (409) if the session status is not `running`

## Functions (`templates/index.html`, JavaScript)

### `showStats(data)`
- **Input arguments:** `data` (object returned by `/api/stats`)
- **Output:** fills the packets/sec value, the top talkers table and the protocol breakdown table, and shows the stats section

### `refreshStats()`
- **Input arguments:** none
- **Output:**
  - `running`: fetches `/api/stats` and calls `showStats()`
  - `paused`: does nothing, so the last values stay on screen
  - `idle` or `stopped`: hides the tables and shows "No active session"

  Runs every 2 seconds, and right after every button action.

# PPS-F-014 – Alert Panel

Alerts come from the static `mock/mock_data.json`. The panel is refreshed by polling every 2 seconds.

## Functions (`app.py`)

### `get_alerts()` → `GET /api/alerts`
- **Input arguments:** none
- **Output:** `{alerts: [...]}`, newest first (sorted by `time`). Each alert is `{severity, message, time}`.
- **Errors:** `INVALID_STATE` (409) if the session status is not `running`

## Functions (`templates/index.html`, JavaScript)

### `showAlerts(data)`
- **Input arguments:** `data` (object returned by `/api/alerts`)
- **Output:** builds one card per alert showing a colored severity label, the message and the timestamp. Colors: critical = red, high = orange, medium = yellow, low = green.

### `refreshAlerts()`
- **Input arguments:** none
- **Output:**
  - `running`: fetches `/api/alerts` and calls `showAlerts()`
  - `paused`: does nothing, so the last alerts stay on screen
  - `idle` or `stopped`: hides the cards and shows "No active session"

  Runs every 2 seconds, and right after every button action.

# PPS-F-012 – Active Hosts and Packet List

Hosts and packets come from the static `mock/mock_data.json`. Both tables are refreshed by polling every 2 seconds.
The packet list is capped at the latest 20 rows (`MAX_PACKETS` in `app.py`).

## Functions (`app.py`)

### `get_hosts()` → `GET /api/hosts`
- **Input arguments:** none
- **Output:** `{hosts: [...]}`. Each host is `{ip, mac, vendor, protocol, packets, first_seen}`; `mac` can be `null`.
- **Errors:** `INVALID_STATE` (409) if the session status is not `running`

### `get_packets()` → `GET /api/packets`
- **Input arguments:** none
- **Output:** `{packets: [...]}`, newest first, at most 20. Each packet is `{time, src_ip, dst_ip, protocol, src_port, dst_port, length}`; ports can be `null`.
- **Errors:** `INVALID_STATE` (409) if the session status is not `running`

## Functions (`templates/index.html`, JavaScript)

### `renderHosts()`
- **Input arguments:** none (uses the stored host list and the search box text)
- **Output:** fills the Active Hosts table with the hosts whose IP, MAC, vendor or protocol contains the search text (case-insensitive). A missing MAC is shown as "N/A". Runs on every keystroke in the search box.

### `showPackets(data)`
- **Input arguments:** `data` (object returned by `/api/packets`)
- **Output:** fills the Captured Packets table. A missing port is shown as "N/A".

### `refreshHosts()`
- **Input arguments:** none
- **Output:**
  - `running`: fetches `/api/hosts` and `/api/packets`, then calls `renderHosts()` and `showPackets()`
  - `paused`: does nothing, so the last values stay on screen
  - `idle` or `stopped`: hides the tables and shows "No active session"

  Runs every 2 seconds, and right after every button action.

# PPS-9 – Live Data over WebSocket

The WebSocket replaces polling for the four data panels (stats, hosts, packets, alerts).
The REST endpoints (`/api/stats`, `/api/hosts`, `/api/packets`, `/api/alerts`) still exist.
Session status and the session buttons still use REST (status is polled every 1 second).
Data comes from the static `mock/mock_data.json`. Uses the `flask-sock` library.

## Functions (`app.py`)

### `build_live_messages()`
- **Input arguments:** none
- **Output:** a list of 4 messages, each `{type, data}`:
  - `stats`: `{packets_per_sec, top_talkers, protocols}`
  - `hosts`: `{hosts: [...]}`
  - `packets`: `{packets: [...]}`, newest first, at most 20
  - `alerts`: `{alerts: [...]}`, newest first

### `live(ws)` → WebSocket `/ws/live`
- **Input arguments:** `ws` (the WebSocket connection, provided by flask-sock). Any text the client sends (e.g. "refresh") triggers an immediate push.
- **Output:**
  - `running`: sends the 4 messages from `build_live_messages()` as JSON text every 2 seconds (`PUSH_INTERVAL`)
  - `paused`, `idle` or `stopped`: sends nothing. The connection stays open.

## Functions (`templates/index.html`, JavaScript)

### `connectLive()`
- **Input arguments:** none
- **Output:** opens the WebSocket to `/ws/live`. Sets the "Live updates" label to `connected` or `disconnected`. Reconnects every 2 seconds after the connection closes.

### `handleLiveMessage(message)`
- **Input arguments:** `message` (object `{type, data}`)
- **Output:** calls `showStats()`, `showHosts()`, `showPackets()` or `showAlerts()` by `type`. Ignores the message unless the status is `running` or `paused`.

### `showHosts(data)`
- **Input arguments:** `data` (object `{hosts: [...]}`)
- **Output:** stores the hosts, calls `renderHosts()` and shows the hosts panel content

### `showNoSession(status)`
- **Input arguments:** `status` (str)
- **Output:** for `idle` or `stopped`, hides the stats, hosts and alerts content and shows "No active session". For `running` or `paused`, does nothing, so the last values stay on screen.

# Dashboard – Placeholder Auth Token

The page sends a placeholder token when it opens the live connection: `/ws/live?token=placeholder-token`.
The server only checks that a token is present. It does not validate the value.
The placeholder will be replaced by the real token from `/api/auth/login` later.

## Functions (`app.py`)

### `live(ws)` → WebSocket `/ws/live` (updated)
- **Input arguments:** `ws` (the WebSocket connection), and the query parameter `token` in the URL
- **Output:**
  - `token` missing or empty: closes the connection immediately with code 1008 ("Missing token")
  - `token` present: behaves as described in the PPS-9 section

## Functions (`templates/index.html`, JavaScript)

### `connectLive()` (updated)
- **Input arguments:** none
- **Output:** opens the WebSocket to `/ws/live?token=<PLACEHOLDER_TOKEN>`. Constant `PLACEHOLDER_TOKEN` is defined at the top of the script.