"""
Live capture driver used by the dashboard in 'live' mode.

Wraps the capture module's interface validation (select_interface) with a
Scapy AsyncSniffer that writes a PCAP (PPS-F-001/002/005, PPS-F-020) and feeds
Analytics. Zeek is run on the finished PCAP in a background thread
(PPS-F-006..008) so Stop never blocks the UI.
"""
import logging
import threading
import time
from pathlib import Path

from analytics import Analytics
from integration import CaptureError, read_zeek_tsv, select_interface, validate_filter

logger = logging.getLogger(__name__)


class LiveCapture:
    def __init__(self, analytics: Analytics):
        self.analytics = analytics
        self.sniffer = None
        self.writer = None
        self.paused = False
        self.pcap_path = None
        self.zeek = {"status": "idle"}
        self._lock = threading.Lock()

    def start(self, session_dir: Path, interface_id: str, bpf: str = ""):
        iface = select_interface(interface_id)
        # Map presets (HTTPS -> tcp port 443) and compile with libpcap so an
        # invalid filter is rejected here instead of capturing nothing.
        bpf = validate_filter(bpf or "", iface.id)
        from scapy import all as api
        session_dir.mkdir(parents=True, exist_ok=True)
        self.pcap_path = session_dir / "capture.pcap"
        self.writer = api.PcapWriter(str(self.pcap_path), sync=True)
        self.paused = False
        self.zeek = {"status": "idle"}
        try:
            self.sniffer = api.AsyncSniffer(iface=iface.id, filter=bpf or None, store=False, prn=self._on_packet)
            self.sniffer.start()
            time.sleep(0.6)                      # surface permission / bad-filter errors now
            if not self.sniffer.running:
                raise CaptureError("Capture could not start. Run with capture privileges "
                                   "(Administrator / root) and check the filter and Npcap/libpcap.")
        except CaptureError:
            self._close()
            raise
        except Exception as exc:
            self._close()
            raise CaptureError(f"Capture failed to start: {exc}") from exc

    def _on_packet(self, pkt):
        if self.paused:
            return
        try:
            with self._lock:
                if self.writer:
                    self.writer.write(pkt)
            self.analytics.ingest(pkt)
        except Exception:
            logger.exception('Failed to process captured packet')

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False

    def _close(self):
        try:
            if self.sniffer is not None and self.sniffer.running:
                self.sniffer.stop()
        except Exception:
            logger.exception('Failed to stop packet sniffer')
        with self._lock:
            if self.writer:
                self.writer.close()
                self.writer = None
        self.sniffer = None

    def stop(self, on_zeek=None):
        """Stop capturing and run Zeek on this session's PCAP in the background.

        on_zeek(status) receives every Zeek status change for *this* PCAP, so the
        result is stored with the session that produced it even if a new session
        has started by the time Zeek finishes.
        """
        self._close()
        pcap = self.pcap_path
        if pcap and pcap.exists():
            self._set_zeek(pcap, on_zeek, {"status": "running"})
            threading.Thread(target=self._run_zeek, args=(pcap, on_zeek), daemon=True).start()
        else:
            self._set_zeek(pcap, on_zeek, {"status": "done", "log_files": [],
                                           "message": "No PCAP was written for this session."})

    def _set_zeek(self, pcap, on_zeek, status):
        if pcap == self.pcap_path:               # still the latest session -> header badge
            self.zeek = status
        if on_zeek:
            on_zeek(status)

    def _run_zeek(self, pcap, on_zeek=None):
        try:
            from zeek_runner import analyze_pcap
            result = analyze_pcap(pcap)
            out = Path(result["output_dir"])
            notices = read_zeek_tsv(out / "notice.log") if (out / "notice.log").exists() else []
            conns = len(read_zeek_tsv(out / "conn.log")) if (out / "conn.log").exists() else 0
            if pcap == self.pcap_path:           # never add old notices to a newer session
                self.analytics.add_zeek_alerts(notices)
            status = {"status": "done", "log_files": result["log_files"], "output_dir": str(out),
                      "connections": conns, "notices": len(notices)}
        except FileNotFoundError as exc:
            status = {"status": "unavailable", "message": str(exc)}
        except Exception as exc:
            logger.exception('Zeek analysis failed')
            status = {"status": "error", "message": str(exc)[:300]}
        self._set_zeek(pcap, on_zeek, status)
