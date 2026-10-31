"""Compile BPF with libpcap/Npcap; never downgrade invalid filters to no filter."""
from .interfaces import CaptureError


def validate_filter(expression, interface):
    if not isinstance(expression, str) or len(expression) > 4096 or "\x00" in expression:
        raise CaptureError("Capture filter must be text without NUL bytes, at most 4096 characters.")
    if not expression.strip():
        return ""
    try:
        from scapy.arch.common import compile_filter
        from scapy.libs.winpcapy import pcap_freecode
        program = compile_filter(expression, iface=interface)
        from ctypes import byref
        pcap_freecode(byref(program))
    except Exception as exc:
        raise CaptureError("Invalid BPF filter or unavailable compiler; check expression and install Npcap/libpcap.") from exc
    return expression
