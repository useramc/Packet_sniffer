"""Turn capture filter text into BPF and compile it with libpcap/Npcap.

Users may type a friendly preset name (``HTTPS``, ``DNS`` ...) instead of raw
BPF; presets are mapped to the equivalent expression. Anything else must be
valid BPF. Invalid filters are rejected with a clear message and are never
downgraded to "no filter" or passed through to a sniffer that would silently
capture nothing.
"""
import re

from .interfaces import CaptureError

MAX_FILTER_LENGTH = 4096
DLT_EN10MB = 1  # Ethernet link type: lets libpcap compile without opening an adapter

# Friendly names (case-insensitive, whole expression) -> BPF.
FRIENDLY_FILTERS = {
    "arp": "arp",
    "dhcp": "udp port 67 or udp port 68",
    "dns": "port 53",
    "ftp": "tcp port 20 or tcp port 21",
    "http": "tcp port 80",
    "https": "tcp port 443",
    "icmp": "icmp",
    "icmpv6": "icmp6",
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ip6",
    "ntp": "udp port 123",
    "smtp": "tcp port 25",
    "ssh": "tcp port 22",
    "tcp": "tcp",
    "tls": "tcp port 443",
    "udp": "udp",
}

PRESET_HINT = ", ".join(name.upper() for name in sorted(FRIENDLY_FILTERS))


def normalize_filter(expression):
    """Check the text and map a friendly preset name to its BPF expression."""
    if not isinstance(expression, str) or len(expression) > MAX_FILTER_LENGTH or "\x00" in expression:
        raise CaptureError(
            f"Capture filter must be text without NUL bytes, at most {MAX_FILTER_LENGTH} characters.")
    text = expression.strip()
    return FRIENDLY_FILTERS.get(text.lower(), text)


def _libpcap_reason(exc):
    match = re.search(r"\(([^()]*)\)\s*$", str(exc))
    return match.group(1) if match else "syntax error"


def validate_filter(expression, interface=None, require_compiler=True):
    """Return the BPF expression to capture with, or raise CaptureError.

    ``require_compiler=False`` accepts the (normalized) text when libpcap/Npcap
    is not installed, for callers that never actually capture (demo mode).
    """
    bpf = normalize_filter(expression)
    if not bpf:
        return ""
    try:
        from ctypes import byref

        from scapy.arch.common import compile_filter
        from scapy.libs.winpcapy import pcap_freecode
    except (ImportError, OSError) as exc:
        if not require_compiler:
            return bpf
        raise CaptureError("Cannot check the capture filter: install Npcap/libpcap.") from exc
    try:
        if interface:
            program = compile_filter(bpf, iface=interface)
        else:
            program = compile_filter(bpf, linktype=DLT_EN10MB)
    except ImportError as exc:
        if not require_compiler:
            return bpf
        raise CaptureError("Cannot check the capture filter: install Npcap/libpcap.") from exc
    except Exception as exc:
        if "compile filter" not in str(exc):  # e.g. adapter could not be opened
            raise CaptureError(
                "Could not check the capture filter on this interface; "
                "check permissions and Npcap/libpcap.") from exc
        raise CaptureError(
            f"Invalid BPF filter {expression.strip()!r} ({_libpcap_reason(exc)}). "
            f"Use BPF syntax such as 'tcp port 443', or a preset: {PRESET_HINT}.") from exc
    pcap_freecode(byref(program))
    return bpf
