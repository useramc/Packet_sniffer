import os


class ZeekLogParser:
    def __init__(self, logs_dir):
        self.logs_dir = logs_dir

    def parse_conn_log(self):
        log_path = os.path.join(self.logs_dir, "conn.log")

        # Create a sample log when no connection log exists.
        if not os.path.exists(log_path):
            os.makedirs(self.logs_dir, exist_ok=True)

            mock_data = (
                "#separator \t\n"
                "#set_separator\t,\n"
                "#empty_field\t(empty)\n"
                "#unset_field\t-\n"
                "#path\tconn\n"
                "#open\t2026-10-20-12-00-00\n"
                "#fields\tts\tuid\tid.orig_h\tid.orig_p\t"
                "id.resp_h\tid.resp_p\tproto\tservice\tduration\t"
                "orig_bytes\tresp_bytes\tconn_state\n"
                "#types\ttime\tstring\taddr\tport\taddr\tport\t"
                "string\tstring\tinterval\tcount\tcount\tstring\n"
                "1697792400.123\tC12345\t192.168.1.50\t54321\t"
                "8.8.8.8\t53\tudp\tdns\t0.015\t75\t132\tSF\n"
                "1697792405.456\tC12346\t192.168.1.50\t51234\t"
                "142.250.190.46\t443\ttcp\tssl\t1.234\t540\t1820\tSF\n"
            )

            with open(log_path, "w", encoding="utf-8") as file:
                file.write(mock_data)

            print(f"Auto-created mock log file at: {log_path}")

        parsed_records = []

        with open(log_path, "r", encoding="utf-8") as file:
            fields = []

            for line in file:
                line = line.strip()

                if not line:
                    continue

                if line.startswith("#fields"):
                    fields = line.split()[1:]
                    continue

                if line.startswith("#"):
                    continue

                values = line.split()

                if fields and len(fields) <= len(values):
                    record = dict(zip(fields, values, strict=False))

                    normalized_record = {
                        "timestamp": record.get("ts"),
                        "uid": record.get("uid"),
                        "source_ip": record.get("id.orig_h"),
                        "source_port": record.get("id.orig_p"),
                        "dest_ip": record.get("id.resp_h"),
                        "dest_port": record.get("id.resp_p"),
                        "protocol": record.get("proto"),
                        "service": record.get("service"),
                        "state": record.get("conn_state"),
                    }

                    parsed_records.append(normalized_record)

        return parsed_records