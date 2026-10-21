import os

class ZeekLogParser:
    def __init__(self, logs_dir):
        self.logs_dir = logs_dir

    def parse_conn_log(self):
        log_path = os.path.join(self.logs_dir, "conn.log")
        
        # Auto-create the directory and mock log file if it doesn't exist
        if not os.path.exists(log_path):
            os.makedirs(self.logs_dir, exist_ok=True)
            mock_data = (
                "#separator \t\n"
                "#set_separator	,\n"
                "#empty_field	(empty)\n"
                "#unset_field	-\n"
                "#path	conn\n"
                "#open	2026-10-20-12-00-00\n"
                "#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state\n"
                "#types	time	string	addr	port	addr	port	string	string	interval	count	count	string\n"
                "1697792400.123	C12345	192.168.1.50	54321	8.8.8.8	53	udp	dns	0.015	75	132	SF\n"
                "1697792405.456	C12346	192.168.1.50	51234	142.250.190.46	443	tcp	ssl	1.234	540	1820	SF\n"
            )
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(mock_data)
            print(f"Auto-created mock log file at: {log_path}")

        parsed_records = []
        with open(log_path, "r", encoding="utf-8") as f:
            fields = []
            for line in f:
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
                    record = dict(zip(fields, values))
                    normalized_record = {
                        "timestamp": record.get("ts"),
                        "uid": record.get("uid"),
                        "source_ip": record.get("id.orig_h"),
                        "source_port": record.get("id.orig_p"),
                        "dest_ip": record.get("id.resp_h"),
                        "dest_port": record.get("id.resp_p"),
                        "protocol": record.get("proto"),
                        "service": record.get("service"),
                        "state": record.get("conn_state")
                    }
                    parsed_records.append(normalized_record)
                    
        return parsed_records