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
Expected result: 17 passed, 3 skipped.

## Fixtures (`conftest.py`)

### `client()`
- **Input arguments:** none
- **Output:** a Flask test client with the session reset to `idle`

### `running_client(client)`
- **Input arguments:** `client` fixture
- **Output:** the same test client with a session already started on "Wi-Fi" (state `running`)

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

## TC-DASH-02 – Hosts (`test_tc_dash_02_hosts.py`)

| Test function | Input arguments | Output |
|---|---|---|
| `test_tc_dash_02_new_host_appears_within_5s` | none | skipped until PPS-F-012 is implemented |

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

| Test function | Input arguments | Output |
|---|---|---|
| `test_tc_dash_04_alert_card_appears_within_5s` | none | skipped until PPS-F-014 is implemented |
| `test_tc_dash_04_alert_card_shows_correct_severity` | none | skipped until PPS-F-014 is implemented |