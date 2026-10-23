"""A bounded setup diagnostic, not the application's session manager."""

import math
from pathlib import Path

from .interfaces import CaptureError, scapy_api, select_interface


def smoke_capture(identifier: str, output: str, seconds: float = 5, count: int = 100) -> int:
    if not math.isfinite(seconds) or not 0 < seconds <= 60 or not 1 <= count <= 10000:
        raise CaptureError("Use a duration from 0 to 60 seconds (exclusive of zero) and 1 to 10000 packets.")
    interface = select_interface(identifier)
    api = scapy_api()
    path = Path(output)
    if path.suffix.lower() != ".pcap":
        raise CaptureError("Output must have a .pcap extension.")
    packets_written = 0
    # Exclusive creation prevents a diagnostic from overwriting an existing capture.
    try:
        with path.open("xb") as stream:
            with api.PcapWriter(stream, sync=True) as writer:

                def write_packet(packet):
                    nonlocal packets_written
                    writer.write(packet)
                    packets_written += 1

                api.sniff(iface=interface.id, timeout=seconds, count=count,
                          store=False, prn=write_packet)
                if not packets_written:
                    writer.write_header(None)
    except (OSError, RuntimeError, api.Scapy_Exception) as exc:
        raise CaptureError(
            "Capture failed. Check adapter availability, Npcap/libpcap, capture permissions, "
            "and a writable new output path. Any partial PCAP is kept for diagnosis."
        ) from exc
    return packets_written
