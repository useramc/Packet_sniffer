# Test Execution Log – TC-DASH-01..04 (PPS-22)

- **Build under test:** dashboard on branch `feature/PPS-22-execute-dashboard-tests`
- **Data source:** mock data (`dashboard/mock/mock_data.json`). The real Zeek pipeline is not connected.
- **Requirements covered:** PPS-F-011 (TC-DASH-01), PPS-F-012 (TC-DASH-02), PPS-F-013 (TC-DASH-03), PPS-F-014 (TC-DASH-04)

## Execution runs

| Run | Executed by | Date | Environment | Procedure | Result |
|---|---|---|---|---|---|
| 1 (automated) | Hamza | 2026-10-28 | Windows 10, Python 3.13.5 | `pytest -v -rs` | 28 passed, 0 failed, 0 skipped (all runs) |
| 2 (manual) | Hamza | 2026-10-28 | Windows 10, browser: | Manual checks M-01..M-08 below | 8 passed, 0 failed |

## Automated results

| Test case | Test function | Expected | Run 1 | Run 2 |
|---|---|---|---|---|
| TC-DASH-01 | `test_tc_dash_01_stats_has_required_fields` | `/api/stats` returns the 3 fields while running | P | |
| TC-DASH-01 | `test_tc_dash_01_stats_match_mock_data` | stats within 5% of the mock file | P | P |
| TC-DASH-01 | `test_tc_dash_01_stats_refused_when_idle` | 409 `INVALID_STATE` | P | P |
| TC-DASH-01 | `test_tc_dash_01_stats_refused_when_paused` | 409 `INVALID_STATE` | P | P |
| TC-DASH-01 | `test_tc_dash_01_stats_refused_when_stopped` | 409 `INVALID_STATE` | P | P |
| TC-DASH-01 | `test_tc_dash_01_stats_pushed_at_least_every_2s` | consecutive pushes at most 2.5s apart | P | P |
| TC-DASH-01 | `test_tc_dash_01_stats_over_websocket_match_mock_data` | pushed stats within 5% of the mock file | P | P |
| TC-DASH-02 | `test_tc_dash_02_hosts_arrive_within_5s` | hosts pushed within 5s of Start | P |  P|
| TC-DASH-02 | `test_tc_dash_02_hosts_match_mock_data` | same IPs and MACs as the mock file | P | P |
| TC-DASH-02 | `test_tc_dash_02_packets_arrive_newest_first_and_capped` | packets within 5s, newest first, at most 20 | P | P |
| TC-DASH-03 | `test_tc_dash_03_interfaces_listed` | list is Wi-Fi, Ethernet | P | P |
| TC-DASH-03 | `test_tc_dash_03_start_sets_running_within_2s` | status `running` in under 2s | P | P |
| TC-DASH-03 | `test_tc_dash_03_pause_sets_paused_within_2s` | status `paused` in under 2s | P | P |
| TC-DASH-03 | `test_tc_dash_03_resume_sets_running_within_2s` | status `running` in under 2s | P | P |
| TC-DASH-03 | `test_tc_dash_03_stop_sets_stopped_within_2s` | status `stopped` in under 2s | P | P |
| TC-DASH-03 | `test_tc_dash_03_start_with_invalid_interface` | 400 `INVALID_INTERFACE`, stays `idle` | P | P |
| TC-DASH-03 | `test_tc_dash_03_start_when_running_is_refused` | 409 `INVALID_STATE` | P | P |
| TC-DASH-03 | `test_tc_dash_03_pause_when_idle_is_refused` | 409 `INVALID_STATE` | P | P |
| TC-DASH-03 | `test_tc_dash_03_stop_when_idle_is_refused` | 409 `INVALID_STATE` | P | P |
| TC-DASH-03 | `test_tc_dash_03_resume_when_running_is_refused` | 409 `INVALID_STATE` | P | P |
| TC-DASH-04 | `test_tc_dash_04_alert_arrives_within_5s` | alerts pushed within 5s of Start | P | P |
| TC-DASH-04 | `test_tc_dash_04_alert_severity_matches_mock_data` | severities match the mock file | P | P |
| TC-DASH-04 | `test_tc_dash_04_alerts_newest_first` | alerts sorted newest first | P | P |
| Live token | `test_live_token_missing_closes_connection` | connection closed | P | P |
| Live token | `test_live_token_empty_closes_connection` | connection closed | P | P |
| Live token | `test_live_token_present_keeps_connection_open` | stats received | P | P |

## Manual checks (to be executed by the tester)

Preparation for every check: run `python dashboard/app.py`, open `http://127.0.0.1:5000/`, press F12 and open Network → WS → `live` → Messages. Set Result to P or F and note anything unexpected. If a check fails, log it in `defect_reports.md`.

### M-01 (TC-DASH-01): stats refresh
1. Select "Wi-Fi" and click Start.
2. Watch the Live Traffic Statistics panel and the `stats` frames in the WS Messages tab.

**Expected:** the panel shows packets/sec 245, a top talkers table (2 rows) and a protocol table (TCP 120, UDP 40, ICMP 5). A new `stats` frame arrives at least every 2 seconds.
**Actual:** Correct **Result:** ☐ P  **Tester / date:** Hamza / 2026-10-28

### M-02 (TC-DASH-01): stats on pause and stop
1. With a running session, click Pause, then Resume, then Stop.

**Expected:** on Pause no new frames arrive and the values stay on screen. On Resume frames resume. On Stop the panel shows "No active session".
**Actual:** Correct **Result:** ☐ P  **Tester / date:** Hamza / 2026-10-28

### M-03 (TC-DASH-01): live connection label and token
1. Check the "Live updates" label, and the WS URL in the Headers tab.
2. Stop Flask with Ctrl+C, then start it again.

**Expected:** label shows "connected", and the URL ends with `?token=placeholder-token`. After Ctrl+C the label shows "disconnected", and after restart it returns to "connected" within about 2 seconds.
**Actual:** Correct **Result:** ☐ P  **Tester / date:** Hamza / 2026-10-28

### M-04 (TC-DASH-02): hosts and packets tables
1. Click Start and look at the Hosts panel.

**Expected:** within 5 seconds the Active Hosts table shows 3 hosts (192.168.1.10, .25, .40), the third with MAC "N/A". The Captured Packets table shows 6 rows, newest first, and the ICMP row shows "N/A" for both ports.
**Actual:** Correct **Result:** ☐ P  **Tester / date:** Hamza / 2026-10-28

### M-05 (TC-DASH-02): host search
1. With a running session, type `dell`, then `icmp`, then clear the search box.

**Expected:** `dell` leaves only the Dell host, `icmp` only the ICMP host, and clearing shows all 3. The packets table never changes.
**Actual:** Correct **Result:** ☐ P  **Tester / date:** Hamza / 2026-10-28

### M-06 (TC-DASH-03): session controls
1. Open the interface dropdown. Click Start, Pause, Resume, then Stop.

**Expected:** the dropdown lists Wi-Fi and Ethernet. After Start, Status shows `running` within 2 seconds and the dropdown and Start are disabled. After Pause, Status shows `paused` and the button reads "Resume". After Resume, Status shows `running`. After Stop, Status shows `stopped` and the dropdown and Start are enabled again.
**Actual:** Correct **Result:** ☐ P  **Tester / date:** Hamza / 2026-10-28

### M-07 (TC-DASH-04): alert cards
1. Click Start and look at the Alerts panel.

**Expected:** within 5 seconds four cards appear, newest first: critical "Possible data exfiltration" 10:04:30 (red), medium "Unusual DNS query volume" 10:03:15 (yellow), high "Possible port scan" 10:02:00 (orange), low "New device joined the network" 10:01:45 (green). Each card shows the severity label, the message and the timestamp.
**Actual:** Correct **Result:** ☐ P  **Tester / date:** Hamza / 2026-10-28

### M-08 (TC-DASH-04): alerts on pause and stop
1. With a running session, click Pause, then Stop.

**Expected:** on Pause the cards stay on screen. On Stop the panel shows "No active session".
**Actual:** Correct **Result:** ☐ P  **Tester / date:** Hamza / 2026-10-28

## Known limitations of this execution

- The "within 5% of Zeek/pcap ground truth" criterion (PPS-F-011) cannot be verified. The mock data is static, so the tests compare only against the mock file.
- The 2-second refresh test allows a 0.5s tolerance for timing jitter.
- The "within 5 seconds" tests measure how fast the data is delivered from Start, not how fast a real host or alert is detected.
- The token is a placeholder, and the server only checks that it is present.
- TC-UX-01 (responsive layout) is covered by PPS-23, and TC-PERF-01 (latency under load) by PPS-24.