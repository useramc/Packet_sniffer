# TC-SEC-03: Captured-data access restriction and file permission audit

| Field | Value |
|---|---|
| Requirement | PPS-SR-003 |
| Story | #52 |
| Branch | `feature/PPS-SR-003-file-permissions` |
| Date | 2026-10-30 |
| Tester | Chinmayi Hebbar A M |
| Environment | Windows, Python 3.12.6, venv `.venv`, Flask dashboard on `http://127.0.0.1:5000` |

## Objective
Show that captured data, the audit log and the auth database are not readable by other users or by unauthenticated clients, and are not committed to Git.

## Checks

### 1. Folder permissions (before)
`dashboard\data` inherited `Authenticated Users (M)` and `Users (RX)` from its parent, so any local account could read captured data.
Evidence: `sec03-icacls-before.png`

**Result: FAIL (finding).**

### 2. Fix
- `integration.py` now calls `_restrict_dir(DATA_DIR)` at start-up.
- Windows: `icacls <dir> /inheritance:r /grant:r <user>:(OI)(CI)F *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F` (owner, SYSTEM, Administrators; language-independent SIDs).
- Other systems: `chmod 700`.
- Failures never stop the app.
- Unit tests: `dashboard/tests/test_data_dir_permissions.py` (the POSIX-mode test is skipped on Windows).

### 3. Folder permissions (after)
```
data BUILTIN\Administrators:(OI)(CI)(F)
     NT AUTHORITY\SYSTEM:(OI)(CI)(F)
     CHINMAYI-HEBBAR\Chinmayi Hebbar A M:(OI)(CI)(F)

Successfully processed 1 files; Failed processing 0 files
```
Only the owner, SYSTEM and Administrators have access. The app was started after the change and the ACL stayed the same.
Evidence: `sec03-icacls-after.png`

**Result: PASS.**

### 4. Single-use export download
An export link for session `S20261030-104545` was requested while signed in, then fetched twice without a new request.

| Fetch | Status |
|---|---|
| First | 200 |
| Second (same token) | 410 GONE |

Evidence: `sec03-download-410.png`

**Result: PASS.**

### 5. Data excluded from Git
`git check-ignore -v` confirms `dashboard/data/audit.log` and `dashboard/data/pps_auth.db` are ignored.
Evidence: `sec03-gitignore.png`

**Result: PASS.**

### 6. Regression
`python -m pytest`: **47 passed, 1 skipped** (the skipped test is POSIX-only).

## Notes
- Bandit reports one extra Low finding for the `subprocess` call in `_restrict_dir`. It uses a fixed argument list with no shell and no user-controlled input.
- Known gap: PCAP files committed earlier remain in Git history and contain other students' MAC/IP addresses. This is tracked separately.

## Conclusion
PPS-SR-003 is met on Windows after the fix. The inherited-permissions finding was corrected and verified, export links are single-use, and captured data is not tracked by Git.
