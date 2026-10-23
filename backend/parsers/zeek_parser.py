
import os


class ZeekLogParser:
    """Parse Zeek TSV logs and normalize their records."""

    LOG_TYPES = ("conn", "dns", "http", "ssl", "weird")

    def __init__(self, logs_dir):
        self.logs_dir = logs_dir

    def parse_log(self, log_type):
        """Parse a supported Zeek log and return normalized records."""
        if log_type not in self.LOG_TYPES:
            raise ValueError(f"Unsupported Zeek log type: {log_type}")

        log_path = os.path.join(self.logs_dir, f"{log_type}.log")

        if not os.path.isfile(log_path):
            return []

        fields = []
        parsed_records = []
        empty_field = "(empty)"
        unset_field = "-"

        with open(log_path, "r", encoding="utf-8") as file:
            for raw_line in file:
                line = raw_line.rstrip("\r\n")

                if not line:
                    continue

                if line.startswith("#empty_field"):
                    parts = line.split("\t", 1)
                    if len(parts) == 2:
                        empty_field = parts[1]
                    continue

                if line.startswith("#unset_field"):
                    parts = line.split("\t", 1)
                    if len(parts) == 2:
                        unset_field = parts[1]
                    continue

                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                    continue

                if line.startswith("#"):
                    continue

                if not fields:
                    continue

                values = line.split("\t")

                if len(values) != len(fields):
                    continue

                record = dict(zip(fields, values, strict=False))

                record = {
                    key: (
                        None if value in (empty_field, unset_field) else value
                    )
                    for key, value in record.items()
                }

                normalized_record = {
                    "timestamp": record.get("ts"),
                    "uid": record.get("uid"),
                    "event_type": log_type,
                    "source_ip": record.get("id.orig_h"),
                    "source_port": record.get("id.orig_p"),
                    "dest_ip": record.get("id.resp_h"),
                    "dest_port": record.get("id.resp_p"),
                    "protocol": record.get("proto"),
                    "service": record.get("service"),
                    "state": record.get("conn_state"),
                    "details": record,
                }

                parsed_records.append(normalized_record)

        return parsed_records

    def parse_conn_log(self):
        """Maintain compatibility with the existing connection API."""
        return self.parse_log("conn")

    def parse_all_logs(self):
        """Parse all supported log files that exist in the directory."""
        results = {}

        for log_type in self.LOG_TYPES:
            log_path = os.path.join(self.logs_dir, f"{log_type}.log")

            if os.path.isfile(log_path):
                results[log_type] = self.parse_log(log_type)

        return results
