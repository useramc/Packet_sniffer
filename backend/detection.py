from collections import defaultdict
from datetime import datetime, timezone


def _parse_timestamp(value):
    """Convert a timestamp to Unix time."""
    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        pass

    try:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _format_timestamp(value):
    """Format a Unix timestamp as an ISO 8601 UTC timestamp."""
    return (
        datetime.fromtimestamp(value, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def detect_suspicious_traffic(
    records,
    port_scan_threshold=5,
    window_seconds=60,
    connection_threshold=20,
):
    """Detect possible port scans and repeated connection attempts."""
    if port_scan_threshold < 2:
        raise ValueError("port_scan_threshold must be at least 2")

    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    if connection_threshold < 1:
        raise ValueError("connection_threshold must be positive")

    grouped_connections = defaultdict(list)

    for record in records:
        if not isinstance(record, dict):
            continue

        source_ip = record.get("source_ip")
        dest_ip = record.get("dest_ip")
        dest_port = record.get("dest_port")
        timestamp = _parse_timestamp(record.get("timestamp"))

        if not source_ip or not dest_ip or timestamp is None:
            continue

        try:
            dest_port = int(dest_port)
        except (TypeError, ValueError):
            continue

        if not 1 <= dest_port <= 65535:
            continue

        grouped_connections[(source_ip, dest_ip)].append({
            "timestamp": timestamp,
            "dest_port": dest_port,
        })

    alerts = []

    for (source_ip, dest_ip), events in grouped_connections.items():
        events.sort(key=lambda event: event["timestamp"])

        # Detect connections to multiple destination ports.
        left = 0
        port_counts = defaultdict(int)
        max_ports = set()
        max_end_time = None

        for event in events:
            port_counts[event["dest_port"]] += 1

            while (
                event["timestamp"] - events[left]["timestamp"]
                > window_seconds
            ):
                old_port = events[left]["dest_port"]
                port_counts[old_port] -= 1

                if port_counts[old_port] == 0:
                    del port_counts[old_port]

                left += 1

            if len(port_counts) > len(max_ports):
                max_ports = set(port_counts)
                max_end_time = event["timestamp"]

        if len(max_ports) >= port_scan_threshold:
            alerts.append({
                "alert_type": "possible_port_scan",
                "source_ip": source_ip,
                "destination_ip": dest_ip,
                "severity": "high",
                "timestamp": _format_timestamp(max_end_time),
                "description": (
                    f"Source contacted {len(max_ports)} distinct "
                    f"destination ports within {window_seconds} seconds."
                ),
                "details": {
                    "distinct_ports": sorted(max_ports),
                    "port_count": len(max_ports),
                    "window_seconds": window_seconds,
                },
            })

        # Detect repeated connections within the configured time window.
        left = 0
        max_count = 0
        max_end_time = None

        for right, event in enumerate(events):
            while (
                event["timestamp"] - events[left]["timestamp"]
                > window_seconds
            ):
                left += 1

            count = right - left + 1

            if count > max_count:
                max_count = count
                max_end_time = event["timestamp"]

        if max_count >= connection_threshold:
            alerts.append({
                "alert_type": "repeated_connection_attempts",
                "source_ip": source_ip,
                "destination_ip": dest_ip,
                "severity": "medium",
                "timestamp": _format_timestamp(max_end_time),
                "description": (
                    f"Source made {max_count} connection attempts "
                    f"within {window_seconds} seconds."
                ),
                "details": {
                    "connection_count": max_count,
                    "window_seconds": window_seconds,
                },
            })

    return alerts
