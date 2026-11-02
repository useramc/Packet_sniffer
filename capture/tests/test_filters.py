"""Capture filter presets and BPF validation (HTTPS must not silently capture nothing)."""
import pytest

from capture import filters
from capture.filters import normalize_filter, validate_filter
from capture.interfaces import CaptureError


def _compiler_available():
    try:
        from scapy.arch.common import compile_filter
        compile_filter("tcp", linktype=filters.DLT_EN10MB)
        return True
    except Exception:
        return False


needs_libpcap = pytest.mark.skipif(not _compiler_available(), reason="Npcap/libpcap not installed")


@pytest.mark.parametrize("text, expected", [
    ("HTTPS", "tcp port 443"),
    ("https", "tcp port 443"),
    ("  Https ", "tcp port 443"),
    ("HTTP", "tcp port 80"),
    ("DNS", "port 53"),
    ("ARP", "arp"),
    ("ICMP", "icmp"),
    ("tcp port 8080", "tcp port 8080"),   # real BPF passes through unchanged
    ("", ""),
])
def test_friendly_names_map_to_bpf(text, expected):
    assert normalize_filter(text) == expected


def test_empty_filter_means_capture_everything():
    assert validate_filter("   ") == ""


@needs_libpcap
def test_https_preset_compiles_to_port_443():
    assert validate_filter("HTTPS") == "tcp port 443"


@needs_libpcap
@pytest.mark.parametrize("expression", ["tcp port 443", "port https", "udp and port 53"])
def test_valid_bpf_is_accepted(expression):
    assert validate_filter(expression) == expression


@needs_libpcap
@pytest.mark.parametrize("expression", ["tcp port", "bad (", "https and", "HTTPS or DNS"])
def test_invalid_bpf_is_rejected_with_clear_message(expression):
    with pytest.raises(CaptureError) as info:
        validate_filter(expression)
    message = str(info.value)
    assert "Invalid BPF filter" in message and repr(expression) in message
    assert "HTTPS" in message and "tcp port 443" in message   # tells the user what to type instead


def test_missing_compiler_is_an_error_unless_not_required(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def no_scapy(name, *args, **kwargs):
        if name.startswith("scapy"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_scapy)
    with pytest.raises(CaptureError, match="install Npcap"):
        validate_filter("HTTPS")
    assert validate_filter("HTTPS", require_compiler=False) == "tcp port 443"
