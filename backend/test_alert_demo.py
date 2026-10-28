from datetime import datetime, timezone

from detection import detect_suspicious_traffic

records = []

ports = [21, 22, 23, 80, 443]

for index, port in enumerate(ports):
    timestamp = datetime.fromtimestamp(
        1000 + index, tz=timezone.utc
    ).isoformat()

    records.append({
        "timestamp": timestamp,
        "source_ip": "192.168.1.10",
        "dest_ip": "192.168.1.20",
        "dest_port": port,
        "state": "SF",
    })

alerts = detect_suspicious_traffic(records)

print("Alerts generated:", len(alerts))

for alert in alerts:
    print(alert)
