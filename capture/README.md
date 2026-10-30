# Capture setup and interface discovery

Sprint 1 implementation for PPS-38 and PPS-39. This package lists and validates
host interfaces and provides a bounded setup diagnostic that writes PCAP files.
The application session manager, interface switching, filters, saved settings,
and HTTP integration belong to later stories PPS-40 through PPS-45.

## Setup

Run commands from the repository root with Python 3.12 (matching backend CI).

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r capture/requirements-dev.txt
.\.venv\Scripts\python.exe -m capture interfaces
```

Install Npcap from https://npcap.com/#download before live capture. Restart the
terminal after installation. If Npcap is installed with administrator-only access,
run the diagnostic from an elevated PowerShell. Discovery alone does not prove
that the current user has permission to open an adapter.

Linux (Debian/Ubuntu example):

```sh
sudo apt-get install python3-venv libpcap0.8
python3 -m venv .venv
.venv/bin/python -m pip install -r capture/requirements-dev.txt
.venv/bin/python -m capture interfaces
```

Linux packet sockets normally require root or CAP_NET_RAW; use a controlled test
machine and the explicit venv interpreter for the smoke diagnostic. Some capture
modes also need CAP_NET_ADMIN. Do not grant capabilities to the shared system
Python executable. This package does not install drivers or change permissions.

## Select an interface

```sh
python -m capture interfaces
python -m capture select --interface "<id from interfaces output>"
```

Use the exact `id` from JSON, not the display name. Windows typically uses an NPF
identifier; Linux typically uses a name such as `eth0` or `wlan0`. Discovery keeps
all provider adapters, including loopback/virtual adapters; it does not guess the
adapter's medium from its name. An empty list is valid and cannot be selected.
Selection rechecks discovery and fails if an adapter disappeared. It never starts
capture or falls back to the OS default interface.

Python integration contract:

```python
from capture.interfaces import CaptureError, list_interfaces, select_interface

adapters = [adapter.to_dict() for adapter in list_interfaces()]
selected = select_interface(adapters[0]["id"])  # caller must handle an empty list
# selected.id is suitable for Scapy's iface parameter.
```

`CaptureInterface` has `id`, `name`, `description`, and `addresses`. CLI commands
write JSON to stdout and actionable failures to stderr with exit status 1.
Argparse usage errors use status 2. The CLI runs on the host; future HTTP routes
must use the backend's existing authentication dependency.

## Smoke capture

Only run against authorized test traffic. Choose the adapter explicitly and
generate a small amount of traffic using a test device while the command runs.

```sh
python -m capture smoke --interface "<id>" --seconds 5 --count 100 --output capture/test.pcap
```

On Linux use `sudo .venv/bin/python -m capture smoke ...` if required. The command
stops at the first of its time or packet limits (maximum 60 seconds/10000 packets),
streams packets to disk without storing a packet list, and refuses to overwrite
an existing file. Open the result in Wireshark and check the expected test traffic.
Zero packets produces a valid empty PCAP; this is not proof of successful traffic
capture. OS/permission failures leave any partial file for diagnosis. Generated
PCAPs are ignored within `/capture` and must not be committed.

The PCAP can later be passed to `backend.zeek_runner.analyze_pcap` through the
team's integration layer. Zeek installation and analysis remain in PPS-29; this
module does not change the analysis/authentication/dashboard code.

## Verification

```sh
python -m pytest capture/tests -v
python -m ruff check capture
```

Tests use synthetic packets and fake discovery/sniff providers; they never open
a live capture socket. They verify Windows identifier preservation, missing
adapters, provider/permission failures, bounded capture, file integrity, empty
PCAPs, and overwrite protection. The dedicated capture CI runs these tests on
Windows and Linux. Record real adapter selection and authorized live-capture
results on both OSes separately for TC-COMP-01 and capture acceptance evidence;
mocked tests alone do not establish full Windows/Linux runtime compatibility.


## PPS-40 reusable capture service

`from capture.session import CaptureSession` provides `start(interface, bpf="", session_name="")`, `snapshot()` and `stop()`. Pass an exact discovered interface ID and a writable output directory to the constructor. Each start creates an exclusive UUID-named PCAP; stop joins delivery and flushes the file. The returned `pcapPath` is the handoff for the analysis owner to call the existing `feed_pcap(session_id, pcap_path)` contract. The service imports no teammate module and exposes no unauthenticated HTTP routes. Backend owners keep authentication at the API boundary.

TC-CAP-01 offline evidence: injected synthetic Ethernet-encapsulated Wi-Fi traffic round-trips byte-for-byte through the real Scapy PCAP writer/reader. This does not prove capture on a physical Wi-Fi adapter, timing, Wireshark UI validation or authenticated dashboard integration. Execute those on authorized lab traffic before acceptance sign-off.

## PPS-41 Ethernet capture

Use the same `CaptureSession` with the exact Ethernet adapter ID; no Wi-Fi-specific mode or default adapter is substituted. Normal managed Wi-Fi and Ethernet expose Ethernet frames; native monitor mode is not required. Windows NPF identifiers are preserved. For other hosts' traffic use the authorized switch mirror/tap arrangement in TC-CAP-03; an ordinary switched port cannot see all peer traffic.

TC-CAP-03 offline evidence: multiple synthetic Ethernet frames, MAC addresses and payloads survive PCAP round-trip with Linux-style and Windows-style adapter identifiers. Physical mirrored-port traffic and Wireshark UI validation remain lab checks. Pass the stopped session's sessionId/pcapPath to the analysis owner's existing contract; retention/export remain with that owner.

## PPS-42 session lifecycle contract

`pause()` stops recording new arrivals, `resume()` records subsequent arrivals, and `terminate()` safely delegates to `stop()`. Paused packets are intentionally excluded. `snapshot()` reports sessionId, sessionName, startedAt (UTC), status, interface, filter, packets, pcapPath and operational error. Calls are serialized; stop joins packet delivery before closing its writer. Repeated stop is safe; duplicate start and invalid transitions raise CaptureError. Storage errors become visible error state rather than silently dropping packets.

TC-CAP-02 / TC-SYS-03 offline evidence covers ten repeated sessions with all 20 injected packets in each file, no overwrites, pause/resume and startup cleanup. The socket readiness callback is used instead of an arbitrary sleep. Physical start within 5 seconds, OS packet-loss measurement and four-hour TC-REL-01 are not established by injected tests. TC-SYS-02 authenticated dashboard checks remain pending: the existing dashboard driver is unchanged and does not automatically use this new service. Integrators can call this public API after existing token checks; no authentication code is duplicated here.

## PPS-43 interface switching

`switch_interface(new_id)` validates the destination, stops/flushed the current session, and starts a new session preserving filter and display name. The result includes `previousSession` with the old closed PCAP path and a fresh sessionId/pcapPath for the new interface. A missing destination leaves the old session running; driver/start failures after stop leave an explicit error state and the previous PCAP intact. Backend owners can expose this method through their existing authenticated controls.

TC-CAP-04 offline checks validate independent, readable old/new PCAPs and invalid-destination behavior. The SRS 3-second real-interface switching limit still requires lab measurement; thread readiness has a 2-second budget, but OS socket teardown/setup time is not guaranteed by that budget.

## PPS-44 BPF filtering

Pass a BPF expression to `start(interface_id, bpf='tcp port 80')`. The capture service compiles it through Npcap/libpcap before opening a file or starting a sniffer, then passes the unchanged expression to Scapy's capture socket. Invalid expressions, missing compilers, non-text inputs and embedded NULs fail closed with CaptureError; there is no unfiltered fallback. Switching revalidates the filter against the destination interface. Empty/whitespace filter means intentionally unfiltered capture.

TC-CAP-05 offline checks cover forwarding protocol/host/port expressions and rejection before capture startup. This host has no Npcap/libpcap provider, so real BPF matching/exclusion remains pending lab execution: generate matching TCP port 80 and nonmatching UDP/other-port traffic, capture with tcp port 80, inspect every record and compare with the generated traffic. Port 80 is a port match, not proof of HTTP payload classification.
