"""Use Scapy's OS-specific provider without guessing adapter identifiers."""

from dataclasses import asdict, dataclass


class CaptureError(RuntimeError):
    """An actionable capture setup or interface error."""


def scapy_api():
    try:
        from scapy import all as api
    except ImportError as exc:
        raise CaptureError("Install capture dependencies: python -m pip install -r capture/requirements.txt") from exc
    return api


@dataclass(frozen=True)
class CaptureInterface:
    """id is the exact identifier to pass to Scapy, including Windows NPF IDs."""

    id: str
    name: str
    description: str
    addresses: tuple[str, ...]

    def to_dict(self):
        return asdict(self)


def list_interfaces() -> list[CaptureInterface]:
    api = scapy_api()
    try:
        api.conf.ifaces.reload()
        result = []
        for iface in api.conf.ifaces.values():
            identifier = str(iface.network_name)
            if identifier:
                result.append(CaptureInterface(
                    id=identifier,
                    name=str(iface.name or identifier),
                    description=str(iface.description or ""),
                    addresses=tuple(sorted({ip for group in iface.ips.values() for ip in group if ip})),
                ))
        return sorted(result, key=lambda item: (item.name, item.id))
    except (OSError, RuntimeError) as exc:
        raise CaptureError("Cannot discover adapters. Check Npcap/libpcap installation and OS permissions.") from exc


def select_interface(identifier: str) -> CaptureInterface:
    """Validate against fresh discovery; never silently fall back to a default."""
    for iface in list_interfaces():
        if iface.id == identifier:
            return iface
    raise CaptureError(f"Interface {identifier!r} is unavailable. Run python -m capture interfaces again.")
