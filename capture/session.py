"""Reusable capture service. No dashboard, authentication or analysis imports."""

import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .interfaces import CaptureError, scapy_api, select_interface
from .filters import validate_filter


class CaptureSession:
    """One exclusive PCAP per session; caller owns authentication and retention."""

    def __init__(self, output_dir, *, ready_timeout=2.0):
        self.output_dir = Path(output_dir)
        self.ready_timeout = ready_timeout
        self._lock = threading.RLock()
        self._packet_lock = threading.Lock()
        self._sniffer = None
        self._writer = None
        self._error = None
        self.status = "idle"
        self.session_id = None
        self.pcap_path = None
        self.packets = 0
        self.interface = None
        self.filter = ""
        self.started_at = None
        self.session_name = ""

    def snapshot(self):
        with self._lock, self._packet_lock:
            if self._sniffer is not None and getattr(self._sniffer, "exception", None):
                self.status = "error"
                self._error = "Capture worker failed; stop capture and check interface/driver."
            return {"sessionId": self.session_id, "status": self.status,
                    "sessionName": self.session_name,
                    "startedAt": self.started_at, "interface": self.interface,
                    "filter": self.filter, "packets": self.packets,
                    "pcapPath": str(self.pcap_path) if self.pcap_path else None,
                    "error": self._error}

    def _on_packet(self, packet):
        with self._packet_lock:
            if self._writer is not None and self.status == "running":
                try:
                    self._writer.write(packet)
                    self.packets += 1
                except Exception:
                    self._error = "PCAP write failed; stop capture and check available storage."
                    self.status = "error"

    def start(self, interface, bpf="", session_name=""):
        """Ready means the capture socket is open, not merely thread-created."""
        with self._lock:
            if self._sniffer is not None:
                raise CaptureError("Capture already active; stop it before starting another session.")
            iface = select_interface(interface)
            bpf = validate_filter(bpf, iface.id)
            api = scapy_api()
            stream = None
            try:
                self.output_dir.mkdir(parents=True, exist_ok=True)
                self.session_id = uuid.uuid4().hex
                self.pcap_path = self.output_dir / (self.session_id + ".pcap")
                stream = self.pcap_path.open("xb")
                self._writer = api.PcapWriter(stream, sync=True)
                self.interface, self.filter = iface.id, bpf
                self.session_name = session_name
                self.packets, self._error = 0, None
                self.started_at = datetime.now(timezone.utc).isoformat()
                ready = threading.Event()
                self._sniffer = api.AsyncSniffer(
                    iface=iface.id, filter=bpf or None, store=False,
                    prn=self._on_packet, started_callback=ready.set)
                self.status = "running"
                self._sniffer.start()
                if not ready.wait(self.ready_timeout) or not self._sniffer.running:
                    raise CaptureError("Capture socket did not become ready; check interface, permissions and Npcap/libpcap.")
                return self.snapshot()
            except Exception as exc:
                try:
                    self.stop()
                finally:
                    if stream is not None:
                        stream.close()
                    self.status = "error"
                if isinstance(exc, CaptureError):
                    raise
                raise CaptureError("Capture failed; check output storage, interface, permissions and Npcap/libpcap.") from exc

    def pause(self):
        with self._lock, self._packet_lock:
            if self.status != "running":
                raise CaptureError("Only a running capture can be paused.")
            self.status = "paused"
        return self.snapshot()

    def resume(self):
        with self._lock, self._packet_lock:
            if self.status != "paused":
                raise CaptureError("Only a paused capture can be resumed.")
            self.status = "running"
        return self.snapshot()

    def terminate(self):
        """Safe application termination follows the same flush/join path as stop."""
        return self.stop()

    def switch_interface(self, interface):
        """Validate the destination before stopping; keep each interface in its own file."""
        with self._lock:
            select_interface(interface)
            validate_filter(self.filter, interface)
            if self.status not in {"running", "paused"}:
                raise CaptureError("Start a capture before switching interfaces.")
            bpf, name = self.filter, self.session_name
            previous = self.stop()
            current = self.start(interface, bpf, name)
            current["previousSession"] = previous
            return current

    def stop(self):
        """Join packet delivery before flushing and closing its output."""
        with self._lock:
            if self._sniffer is not None:
                if getattr(self._sniffer, "exception", None):
                    self._error = "Capture worker failed; check interface/driver."
                try:
                    if self._sniffer.running:
                        self._sniffer.stop(join=True)
                    else:
                        self._sniffer.join()
                except Exception as exc:
                    if getattr(getattr(self._sniffer, "thread", None), "is_alive", lambda: False)():
                        raise CaptureError("Capture thread did not stop; retry stop before starting another session.") from exc
                self._sniffer = None
            with self._packet_lock:
                if self._writer is not None:
                    try:
                        if not self._writer.header_present:
                            self._writer.write_header(None)
                        self._writer.close()
                    except OSError as exc:
                        self._error = "PCAP flush failed; check storage before reusing this session."
                        self.status = "error"
                        raise CaptureError(self._error) from exc
                    finally:
                        self._writer = None
                self.status = "error" if self._error else "stopped"
            return self.snapshot()
