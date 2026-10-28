# Dashboard Tests – PPS-10 (Test Environment Setup)

## Functions

### `test_python_runs()`
- **Input arguments:** none
- **Output:** passes if basic Python code runs (`1 + 1 == 2`)

### `test_flask_imports()`
- **Input arguments:** none
- **Output:** passes if Flask is installed and a Flask app object can be created

# PPS-11 – Dashboard Test Cases (TC-DASH-01..04)

Run from the repo root: `pytest -v -rs`
Expected result: 28 passed, 0 skipped (takes about 10 seconds).

## Fixtures (`conftest.py`)

### `client()`
- **Input arguments:** none
- **Output:** a Flask test client with the session reset to `idle`

### `running_client(client)`
- **Input arguments:** `client` fixture
- **Output:** the same test client with a session already started on "Wi-Fi" (state `running`)

### `live_connect(client)`
- **Input arguments:** `client` fixture
- **Output:** a function `connect(token="placeholder-token")` that starts the app on a free local port and opens a WebSocket to `/ws/live`. Pass `token=None` for no token. Connections and the server are closed automatically after the test.

## TC-DASH-01 – Live traffic statistics (`test_tc_dash_01_live_stats.py`)

Helper functions:
- `load_ground_truth()` – input: none; output: dictionary read from `mock/mock_data.json`
- `within_5_percent(actual, expected)` – input: two numbers; output: `True` if `actual` is within 5% of `expected`

| Test function | Input arguments | Output (pass condition) |
|---|---|---|
| `test_tc_dash_01_stats_has_required_fields` | `running_client` | `/api/stats` returns 200 with `packets_per_sec`, `top_talkers`, `protocols` |
| `test_tc_dash_01_stats_match_mock_data` | `running_client` | packets/sec, protocol counts and top talkers are within 5% of the mock file |
| `test_tc_dash_01_stats_refused_when_idle` | `client` | `/api/stats` returns 409 `INVALID_STATE` |
| `test_tc_dash_01_stats_refused_when_paused` | `running_client` | `/api/stats` returns 409 `INVALID_STATE` after pause |
| `test_tc_dash_01_stats_refused_when_stopped` | `running_client` | `/api/stats` returns 409 `INVALID_STATE` after stop |
| `test_tc_dash_01_stats_pushed_at_least_every_2s` | `running_client`, `live_connect` | two consecutive `stats` pushes arrive no more than 2.5s apart (2s + 0.5s tolerance) |
| `test_tc_dash_01_stats_over_websocket_match_mock_data` | `running_client`, `live_connect` | packets/sec and protocol counts pushed over the WebSocket are within 5% of the mock file |

## TC-DASH-02 – Hosts (`test_tc_dash_02_hosts.py`)

| Test function | Input arguments | Output (pass condition) |
|---|---|---|
| `test_tc_dash_02_hosts_arrive_within_5s` | `client`, `live_connect` | after Start, a `hosts` message arrives within 5s |
| `test_tc_dash_02_hosts_match_mock_data` | `running_client`, `live_connect` | pushed hosts have the same IPs and MACs as the mock file |
| `test_tc_dash_02_packets_arrive_newest_first_and_capped` | `client`, `live_connect` | a `packets` message arrives within 5s, newest first, at most 20 rows |

## TC-DASH-03 – Session controls (`test_tc_dash_03_session_controls.py`)

Helper function:
- `do_action(client, url, body=None)` – input: test client, URL (str), optional JSON body; output: tuple `(status, elapsed_seconds)`, where status is read from `/api/capture/status`

| Test function | Input arguments | Output (pass condition) |
|---|---|---|
| `test_tc_dash_03_interfaces_listed` | `client` | 200 and list `["Wi-Fi", "Ethernet"]` |
| `test_tc_dash_03_start_sets_running_within_2s` | `client` | status `running`, elapsed < 2s |
| `test_tc_dash_03_pause_sets_paused_within_2s` | `running_client` | status `paused`, elapsed < 2s |
| `test_tc_dash_03_resume_sets_running_within_2s` | `running_client` | status `running`, elapsed < 2s |
| `test_tc_dash_03_stop_sets_stopped_within_2s` | `running_client` | status `stopped`, elapsed < 2s |
| `test_tc_dash_03_start_with_invalid_interface` | `client` | 400 `INVALID_INTERFACE`, status stays `idle` |
| `test_tc_dash_03_start_when_running_is_refused` | `running_client` | 409 `INVALID_STATE` |
| `test_tc_dash_03_pause_when_idle_is_refused` | `client` | 409 `INVALID_STATE` |
| `test_tc_dash_03_stop_when_idle_is_refused` | `client` | 409 `INVALID_STATE` |
| `test_tc_dash_03_resume_when_running_is_refused` | `running_client` | 409 `INVALID_STATE` |

## TC-DASH-04 – Alerts (`test_tc_dash_04_alerts.py`)

| Test function | Input arguments | Output (pass condition) |
|---|---|---|
| `test_tc_dash_04_alert_arrives_within_5s` | `client`, `live_connect` | after Start, an `alerts` message with at least one alert arrives within 5s |
| `test_tc_dash_04_alert_severity_matches_mock_data` | `running_client`, `live_connect` | each alert's severity equals the mock file's and is critical, high, medium or low |
| `test_tc_dash_04_alerts_newest_first` | `running_client`, `live_connect` | alerts are sorted newest first |

# PPS-22 – Live Connection Token (`test_live_connection_token.py`)

Helper module `helpers.py`:
- `load_ground_truth()` – input: none; output: dictionary read from `mock/mock_data.json`
- `wait_for_type(ws, msg_type, timeout)` – input: WebSocket, message type (str), timeout in seconds; output: tuple `(message, seconds_waited)`, where `message` is `None` on timeout

| Test function | Input arguments | Output (pass condition) |
|---|---|---|
| `test_live_token_missing_closes_connection` | `live_connect` | the server closes a connection opened without a token |
| `test_live_token_empty_closes_connection` | `live_connect` | the server closes a connection opened with an empty token |
| `test_live_token_present_keeps_connection_open` | `running_client`, `live_connect` | with a token, a `stats` message arrives |