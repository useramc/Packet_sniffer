# Chengapa capture Sprint 2 validation

Date: 30 October 2026. Environment: Windows, Python 3.14, Scapy 2.6.1, pytest 8.3.3, Ruff 0.11.13.

Commands: `python -m ruff check capture` and `python -m pytest capture/tests -q`.
Result: Ruff passed; 41 offline tests passed. No traffic was captured from the host.

| Story | Requirement / test | Verified offline | Acceptance still pending |
|---|---|---|---|
| PPS-40 | PPS-F-001 / TC-CAP-01 | exact selection, real PCAP round-trip, native frame linktype | physical Wi-Fi traffic and Wireshark |
| PPS-41 | PPS-F-003 / TC-CAP-03 | Ethernet frames/MACs/payloads, Windows adapter IDs | physical mirror/tap traffic and Wireshark |
| PPS-42 | PPS-F-002,020 / TC-CAP-02, TC-SYS-03 | ten start/stop cycles, pause/resume, failure cleanup, worker/write error reporting | actual start <=5s, OS packet-loss integrity, authenticated TC-SYS-02 |
| PPS-43 | PPS-F-004 / TC-CAP-04 | independent old/new PCAPs, invalid destination preserves state | physical switch <=3s |
| PPS-44 | PPS-F-005 / TC-CAP-05 | compiler-boundary validation, exact forwarding, rejection before startup | real BPF compilation/matching/exclusion: Npcap/libpcap unavailable locally |
| PPS-45 | PPS-F-018 / TC-SYS-01 | atomic persistence, restore/apply, corrupt/unavailable/invalid settings rejection | complete live settings-to-session run |

41 passes describe module checks, not full acceptance-test passes. Physical, timing, Linux runtime, authenticated dashboard and four-hour reliability checks have not been executed. Keep acceptance/RTM statuses pending until their evidence exists. Existing CI includes Windows and Linux capture jobs; remote CI must still run on the PRs.

## Integration boundary

All changes are within capture/. The dashboard's existing LiveCapture is unchanged and does not automatically use CaptureSession or saved settings. The backend/security owner must call the public capture API through the existing authenticated application boundary for TC-SYS-02. Module use and PCAP handoff are documented in capture/README.md; no teammate's modules, shared contracts or CI were edited.
