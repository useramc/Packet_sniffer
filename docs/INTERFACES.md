# Pocket Packet Sniffer — System Integration Interfaces

**PPS-12 / PPS-NF-005** — defines the module boundaries and interface
contracts referenced by the SAD (Section 3.3–3.4, 4.3) and the SRS RTM
(Section 8), so each module owner can build and test against a fixed
contract instead of each other's in-progress code.

Status: v0.1 (Sprint 1 draft). Update this file in the same PR as any
change to a request/response shape below — it is the source of truth,
not the code.

---

## 1. Module boundaries (who owns what)

| Layer | Module | Owner (SRS Appendix A) | Requirement IDs |
|---|---|---|---|
| Capture | Interface Discovery, Capture Manager, Capture Filter | Network Capture Engineer | PPS-F-001..005, PPS-F-018, PPS-F-020 |
| Analysis | Zeek Adapter, Detection Engine, Normalizer, Device Profiler | Packet Analysis Engineer | PPS-F-006..010, PPS-F-015..017 |
| Presentation | Dashboard Backend API, Dashboard Frontend | Dashboard & QA Engineer | PPS-F-011..014 |
| Integration/Security | Auth Module, Audit Logger, CI, cross-module wiring | Team Lead | PPS-F-021, PPS-SR-001..006, PPS-NF-005 |

Each module talks to the others **only** through the contracts below —
never by importing another module's internals directly. This is what
makes PPS-NF-005 (documented interfaces) testable.

---

## 2. REST API contracts

All endpoints are prefixed `/api`. All responses are JSON. All
protected endpoints require `Authorization: Bearer <token>` (see
`backend/auth/routes.py`, PPS-F-021) and return `401` if missing/invalid.

### 2.1 Auth (implemented — PPS-15)

| Endpoint | Method | Request | Response | Errors |
|---|---|---|---|---|
| `/api/auth/setup` | POST | `{ username, password }` | `{ token, expiresAt }` | `403` if an admin already exists |
| `/api/auth/login` | POST | `{ username, password }` | `{ token, expiresAt }` | `401` invalid credentials |

### 2.2 Capture (owner: Network Capture Engineer — not yet implemented)

| Endpoint | Method | Request | Response | Errors |
|---|---|---|---|---|
| `/api/capture/interfaces` | GET | — | `{ interfaces: [{ id, name, type: "wifi"\|"ethernet" }] }` | `401` |
| `/api/capture/start` | POST | `{ interface, filter, sessionName }` | `{ sessionId, status, startedAt }` | `401`, `400` invalid interface/filter, `409` already running |
| `/api/capture/stop` | POST | `{ sessionId }` | `{ sessionId, status: "stopped" }` | `401`, `404` unknown session |

### 2.3 Analysis / alerts (owner: Packet Analysis Engineer — not yet implemented)

| Endpoint | Method | Request | Response | Errors |
|---|---|---|---|---|
| `/api/sessions/{id}/stats` | GET | — | `{ packetsPerSec, topTalkers[], protocolBreakdown{} }` | `401`, `404` |
| `/api/sessions/{id}/devices` | GET | — | `{ devices: [{ mac, vendor, ip, protocol }] }` | `401`, `404` |
| `/api/sessions/{id}/alerts` | GET | — | `{ alerts: [{ severity, message, timestamp }] }` | `401`, `404` |

### 2.4 Export / sessions (owner: Packet Analysis Engineer — not yet implemented)

| Endpoint | Method | Request | Response | Errors |
|---|---|---|---|---|
| `/api/export/session/{id}` | POST | `{ format: "pcap"\|"zeek-logs"\|"csv" }` | `{ downloadUrl, expiresAt }` | `401`, `404`, `410` expired/purged |

### 2.5 Health (implemented — PPS-15, unauthenticated)

| Endpoint | Method | Response |
|---|---|---|
| `/api/health` | GET | `{ status: "ok" }` |

---

## 3. WebSocket channel

`/ws/live` — server push only, after connecting with
`?token=<jwt>` as a query param (browsers can't set custom headers on
the WS handshake). Pushes one JSON message per event:

```json
{ "type": "stats",  "payload": { "packetsPerSec": 42, "topTalkers": [...] } }
{ "type": "device",  "payload": { "mac": "...", "vendor": "...", "ip": "..." } }
{ "type": "alert",   "payload": { "severity": "high", "message": "...", "timestamp": "..." } }
```

Owner: Dashboard & QA Engineer (backend push) + Packet Analysis Engineer
(producing `alert`/`device` events from Detection Engine / Device Profiler).

---

## 4. Internal (non-HTTP) interfaces

These are Python-level contracts between modules running in the same
process — still worth fixing now so Sprint 2 integration isn't a
guessing game.

| From → To | Call shape | Notes |
|---|---|---|
| Capture Manager → Zeek Adapter | `feed_pcap(session_id: str, pcap_path: str) -> None` | Capture Manager writes pcap to disk/pipe; Zeek Adapter tails it |
| Zeek Adapter → Detection Engine | `on_zeek_event(session_id: str, log_type: str, record: dict) -> None` | One call per parsed Zeek log line |
| Detection Engine → Backend API | `raise_alert(session_id: str, severity: str, message: str) -> None` | Backend pushes to `/ws/live` |
| Normalizer → Device Profiler | `normalized_packet: dict -> device_record: dict` | Adds `vendor` via OUI lookup |
| Any module → Storage Manager | `save(session_id: str, kind: "pcap"\|"log"\|"meta", data) -> None` | Single write path, so retention/rotation (PPS-NF-006) lives in one place |

**Rule:** if your module needs something from another module that
isn't listed here, add it to this table in your PR rather than reaching
into that module's internals directly.

---

## 5. Error envelope (applies to all REST endpoints)

```json
{ "errorCode": "INVALID_INTERFACE", "message": "Interface 'eth9' not found" }
```

No sensitive data (passwords, tokens, raw packet payloads) in `message`
— see SAD Section 4.4.

---

## 6. Change process

1. Propose the contract change in this file first, in your feature branch.
2. Tag the PR with the module(s) it affects.
3. Team Lead reviews for consistency with this doc before merging to `develop`.
