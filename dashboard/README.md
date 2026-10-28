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

# Dashboard v2 – integrated with Auth, Capture, Zeek and Export

The dashboard is now wired to the real modules instead of mock-only data. Nothing outside `dashboard/` was changed.

## Run
```
pip install -r requirements.txt            # repo root
pip install -r dashboard/requirements.txt
cd dashboard
python app.py                              # http://127.0.0.1:5000
```
First visit shows **Create administrator** (PPS-SR-004: no default password). Afterwards: **Sign in**.

| Env var | Purpose |
|---|---|
| `PPS_MODE` | `auto` (default: live if capture works, else demo data), `live`, `mock` |
| `PPS_JWT_SECRET` | JWT signing secret. If unset a random per-process one is generated (sessions end on restart) |
| `PPS_TLS_CERT` / `PPS_TLS_KEY` | Serve HTTPS (PPS-SR-002) |
| `PPS_HOST` / `PPS_PORT` | Bind address (default `127.0.0.1:5000`) |
| `PPS_DATA_DIR` | Sessions (pcap), audit log, auth DB (default `dashboard/data/`) |
| `ZEEK_BIN` | Path to Zeek (used by `backend/zeek_runner.py`) |
| `PPS_OUI_FILE` | Optional Wireshark `manuf` file for full MAC-vendor lookup |

Live capture needs Npcap (Windows) or libpcap (Linux) and Administrator/root rights. Capture only networks you own or may test.

## What is integrated
| Dashboard feature | Uses | Requirement |
|---|---|---|
| Login / first-run setup, 401 on unauthenticated access, lockout after 5 failures | `backend/auth` (bcrypt + JWT, SQLite) | PPS-F-021, SR-001, SR-004 |
| Interface list, interface validation | `capture/interfaces.py` | PPS-F-001, F-004 |
| Start / pause / resume / stop with BPF filter, PCAP written per session | Scapy `AsyncSniffer` + `PcapWriter` (`live_capture.py`) | PPS-F-002, F-005, F-013, F-020 |
| Live stats, protocol breakdown, top talkers, packets/sec chart | `analytics.py` (Normalizer role) | PPS-F-009, F-011 |
| Hosts: IP, MAC, vendor (OUI), protocol, packets, search | `analytics.py` (Device Profiler role) | PPS-F-010, F-012 |
| Alerts: port-scan and plaintext-credential detection, plus Zeek `notice.log` after Stop | `analytics.py`, `backend/zeek_runner.py` | PPS-F-008, F-014 |
| Redaction of captured secrets in alert details | `analytics.py` | PPS-SR-005 |
| Session naming / tags / history / re-open | `app.py` `/api/sessions` | PPS-F-017 |
| Export CSV / PCAP / Zeek logs (one-time 5-minute link) | `/api/export/session/{id}` | PPS-F-016 |
| `/ws/live` push every second, polling fallback | `flask-sock` | PPS-NF-001 |
| Audit log (`data/audit.log`, mode 600) | `audit.py` | PPS-SR-006 |
| Zeek `conn.log` records | `backend/parsers/zeek_parser.py` via `/api/logs/conn` | PPS-F-007, F-009 |

## New / changed endpoints (all require `Authorization: Bearer <token>` except those marked public)
`GET /api/auth/state` (public), `POST /api/auth/setup` (public, first run only), `POST /api/auth/login` (public),
`GET /api/config`, `GET /api/snapshot`, `GET /api/hosts`, `GET /api/alerts`, `GET /api/logs/conn`,
`GET /api/sessions`, `GET|PATCH /api/sessions/{id}`, `POST /api/export/session/{id}` `{format}`,
`GET /api/download/{token}` (public, one-time), `WS /ws/live?token=`.
`GET /api/interfaces` now also returns `details: [{id, name, description, addresses}]`. Errors keep the `{errorCode, message}` envelope.

## Tests
`pytest` from the repo root: 40 tests. TC-DASH-02 and TC-DASH-04 are no longer skipped.
Tests force `PPS_MODE=mock` and a throwaway auth DB.
