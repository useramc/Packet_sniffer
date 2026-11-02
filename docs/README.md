# Pocket Packet Sniffer

A small network-monitoring tool for students and small labs. It captures live traffic, shows it on a web dashboard, flags suspicious activity (port scans, plaintext credentials) and can hand a finished capture to [Zeek](https://zeek.org) for deeper protocol logs.

Built for the Software Engineering course project (SRS/SAD requirement IDs `PPS-F-*`, `PPS-SR-*`, `PPS-NF-*`).

## Features

- **Live capture** on a chosen network interface (Scapy + Npcap/libpcap) with an optional capture filter.
- **Dashboard** (Flask): packets per second, protocol breakdown, top talkers, host table with MAC vendor lookup, alerts, session history.
- **Detection**: port-scan detection and plaintext-credential detection (credentials are masked before they are shown or stored).
- **Sessions**: start, pause, resume and stop; rename and tag sessions; export as CSV or PCAP through single-use download links.
- **Zeek integration**: Zeek runs on the finished PCAP of a session and its logs are shown in the dashboard.
- **Security**: bcrypt password hashing, JWT sign-in, audit log, optional HTTPS, owner-only data folder, security headers and a CSV-injection guard.

## Architecture

```
 Network ──► capture/ (Scapy) ──► dashboard/ (Flask + WebSocket) ──► Browser
                                      │  ▲
                                      │  └── backend/auth (bcrypt, JWT, SQLite users)
                                      ▼
                              backend/ (storage, log rotation, Zeek runner/parsers)
                                      │
                                      └──► Zeek (on the finished PCAP)
```

| Folder | Purpose |
|---|---|
| `capture/` | Interface discovery, packet capture, filters, capture sessions and API |
| `backend/` | Authentication, storage, log rotation, Zeek runner and parsers |
| `dashboard/` | Flask app, live WebSocket feed, analytics, audit log, web UI and tests |
| `docs/` | Interfaces, evidence (`docs/evidence/TC-*.md` with screenshots) and project documents |

## Requirements

- Python 3.12
- Windows: [Npcap](https://npcap.com) (needed for live capture). Linux/macOS: libpcap and root/administrator rights for capture.
- Zeek (optional): only needed for the Zeek logs feature.

## Quick start (Windows)

```powershell
git clone https://github.com/useramc/Packet_sniffer.git
cd Packet_sniffer
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt   # use the requirements file(s) in the repo
cd dashboard
python app.py
```

Open <http://127.0.0.1:5000>. On the first run the dashboard asks you to create the admin account; after that, sign in with it.

Run the terminal as Administrator if no interfaces appear or capture fails.

## Configuration

All settings are environment variables.

| Variable | Purpose | Default |
|---|---|---|
| `PPS_MODE` | `live` or `mock` (demo data); `auto` picks live when capture works | `auto` |
| `PPS_JWT_SECRET` | Secret used to sign tokens. Set it for stable sign-in across restarts | random per run |
| `PPS_DATA_DIR` | Folder for the audit log, auth database and captures | `dashboard/data` |
| `PPS_AUTH_DB` | Path of the auth database | `<data dir>/pps_auth.db` |
| `PPS_TLS_CERT`, `PPS_TLS_KEY` | Certificate and key to serve the dashboard over HTTPS | unset (HTTP) |
| `PPS_OUI_FILE` | MAC-vendor (OUI) list | built in |
| `ZEEK_BIN` | Full path of the Zeek executable | looked up on `PATH` |

Example (PowerShell):

```powershell
$env:PPS_DATA_DIR = "D:\pps-data"
$env:PPS_JWT_SECRET = "<a long random string>"
python app.py
```

## Using it

1. Choose an interface, optionally enter a capture filter, and press **Start**.
2. The filter uses BPF syntax, for example `tcp port 443`, `port 53` or `arp`.
3. Watch traffic, hosts and alerts update live. **Pause**, **Resume** or **Stop** at any time.
4. In **Session history** you can open, rename or tag a session, and export it as **CSV** or **PCAP**.
5. After a session is **stopped**, press **Zeek logs** to see Zeek's output for its PCAP.

## Zeek

Zeek runs on the **finished PCAP** of a stopped session, not on live traffic. Install Zeek and set `ZEEK_BIN` to the executable. Zeek has no official native Windows build; on Windows run it through WSL or Docker with a small wrapper script and point `ZEEK_BIN` at it. If Zeek is missing the dashboard shows "Zeek unavailable" and everything else keeps working.

## Security

| Requirement | What is done | Evidence |
|---|---|---|
| Authentication (PPS-F-021) | Every `/api` route needs a JWT except config, auth state, setup, login and single-use download links | `docs/evidence/TC-AUTH-01.md` |
| HTTPS (PPS-SR-002) | Optional TLS through `PPS_TLS_CERT` / `PPS_TLS_KEY` | `docs/evidence/TC-SEC-02.md` |
| Data access (PPS-SR-003) | Data folder restricted to the owner (icacls on Windows, `chmod 700` elsewhere); exports are single-use and expire after 5 minutes | `docs/evidence/TC-SEC-03.md` |
| No hard-coded secrets (PPS-SR-004) | Secret scan in CI; the JWT secret comes from the environment | CI "Secret scan" job |
| Audit log | Logins, failed logins, captures and exports, with no passwords or tokens | `docs/evidence/TC-SEC-06.md` |

To reset the account, stop the app, delete `dashboard/data/pps_auth.db` (or the file named by `PPS_AUTH_DB`) and start it again.

## Tests

```powershell
.venv\Scripts\activate
python -m pytest
```

`pytest.ini` runs the dashboard tests. Backend and capture tests live in `backend/tests` and `capture/tests`; run them by passing the folder, for example `python -m pytest backend/tests`.

## Known limitations

- Zeek runs only on finished PCAPs; there is no live Zeek analysis yet.
- Detection runs in Python, not as Zeek scripts.
- There is no retention or purge policy for captures.
- Session history is held in memory (new sessions are saved; see the session-history work in progress).
- A single shared admin account; no roles.
- HTTPS is off unless you configure a certificate.
- Passwords longer than 72 bytes are truncated by bcrypt.
- Earlier PCAPs remain in Git history.

## Contributing

- Branches: `feature/...` → pull request into `develop`; `develop` → `main` through a reviewed pull request.
- Every pull request needs green CI (Backend, Dashboard, Secret scan) and one approval.
- Reference the story in the PR description (`Closes #N`).
- Never commit captures, `*.pcap` files, the auth database or secrets.


