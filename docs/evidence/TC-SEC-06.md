# TC-SEC-06: Audit-log verification

| Field | Value |
|---|---|
| Requirement | PPS-F-021 / audit logging |
| Story | #54 |
| Branch | `feature/PPS-F-021-auth-audit-evidence` |
| Date | 2026-10-30 |
| Tester | Chinmayi Hebbar A M |
| Log file | `dashboard/data/audit.log` (one JSON object per line) |

## Objective
Show that security-relevant events are recorded with a timestamp and user, and that the log never contains passwords, tokens or secrets.

## Checks

### 1. Events recorded
`type dashboard\data\audit.log` shows entries for:

| Event | Example fields |
|---|---|
| `admin_created` | time, user |
| `login_ok` | time, user |
| `login_fail` (after a wrong password) | time |
| `capture_start` | time, user, session, interface, filter |
| `capture_stop` | time, user, session |
| `export` | time, user, session, format (csv/pcap) |
| `session_update` | time, user, session |

Each entry has an ISO-8601 UTC timestamp. The failed-login attempt was verified in the log after submitting a wrong password.
Evidence: `sec06-audit-log.png`

**Result: PASS.**

### 2. No secrets in the log
```
findstr /i "password token bearer secret jwt" dashboard\data\audit.log
```
No lines were returned.
Evidence: `sec06-no-secrets.png`

**Result: PASS.**

### 3. Log protection
The log lives in `dashboard\data`, which is restricted to the owner, SYSTEM and Administrators (see TC-SEC-03) and is excluded from Git.

**Result: PASS.**

## Notes
- The log is append-only text and has no retention or purge policy yet (PPS-F-015 / NF-006 remain open).

## Conclusion
Logins, captures, exports and session changes are audited with user and time, and no credentials or tokens are written to the log.
