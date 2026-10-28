"""
Normalizer + Device Profiler + lightweight Detection for the live dashboard
(PPS-F-009, PPS-F-010, PPS-F-011, PPS-F-012, PPS-F-014, PPS-SR-005).

Consumes scapy packets, keeps thread-safe counters and exposes the same
shapes as dashboard/mock/mock_data.json, so the UI cannot tell mock from live.
Zeek's notice.log is merged in via add_zeek_alerts() once analysis finishes.
"""
import ipaddress
import os
import threading
import time
from collections import Counter, deque
from datetime import datetime

# Small built-in OUI table; set PPS_OUI_FILE to a Wireshark "manuf" file for full coverage.
_OUI = {
    "00:50:56": "VMware", "00:0C:29": "VMware", "08:00:27": "VirtualBox",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:15:5D": "Microsoft Hyper-V", "52:54:00": "QEMU/KVM", "00:16:3E": "Xen",
    "00:E0:4C": "Realtek", "00:1B:21": "Intel", "00:03:93": "Apple",
}
_SERVICES = {53: "DNS", 80: "HTTP", 443: "HTTPS"}
_PLAINTEXT_PORTS = {21, 23, 80, 110, 143}
_CRED_MARKERS = (b"password=", b"passwd=", b"authorization: basic", b"pass ")
SCAN_THRESHOLD, SCAN_WINDOW, ALERT_COOLDOWN = 15, 10, 60


def _load_oui_file():
    path = os.environ.get("PPS_OUI_FILE")
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split("\t")
                if len(parts) >= 2 and len(parts[0]) == 8 and parts[0].count(":") == 2:
                    _OUI[parts[0].upper()] = parts[-1].strip()


_load_oui_file()


def vendor_for(mac):
    if not mac:
        return None
    mac = mac.upper()
    if mac == "FF:FF:FF:FF:FF:FF":
        return "Broadcast"
    if _OUI.get(mac[:8]):
        return _OUI[mac[:8]]
    try:
        if int(mac[:2], 16) & 0x02:
            return "Randomized / private MAC"
    except ValueError:
        pass
    return "Unknown vendor"


def _is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _iso(ts=None):
    return datetime.fromtimestamp(ts or time.time()).isoformat(timespec="seconds")


class Analytics:
    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self.total = 0
            self.window = deque()             # packet timestamps (last 2 s)
            self.protocols = Counter()
            self.talkers = Counter()
            self.hosts = {}
            self.alert_list = []
            self._scan = {}                   # src -> deque[(ts, (dst, dport))]
            self._cooldown = {}

    # ---- ingest -------------------------------------------------------
    def ingest(self, pkt, ts=None):
        ts = ts or time.time()
        info = self._decode(pkt)
        if info is None:
            return
        with self._lock:
            self.total += 1
            self.window.append(ts)
            while self.window and ts - self.window[0] > 2:
                self.window.popleft()
            self.protocols[info["protocol"]] += 1
            if info["src"]:
                self.talkers[info["src"]] += 1
                self._touch_host(info["src"], info["src_mac"], info["protocol"], ts, True)
            if info["dst"] and _is_private(info["dst"]):
                self._touch_host(info["dst"], None, info["protocol"], ts, False)
            self._detect(info, ts)

    @staticmethod
    def _decode(pkt):
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import ARP, Ether
        mac = pkt[Ether].src if pkt.haslayer(Ether) else None
        info = {"src_mac": mac, "src": None, "dst": None, "dport": None, "payload": b"", "protocol": "Other"}
        if pkt.haslayer(ARP):
            info.update(src=pkt[ARP].psrc, dst=pkt[ARP].pdst, protocol="ARP")
            return info
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6] if pkt.haslayer(IPv6) else None
        if ip is None:
            return info if mac else None
        info.update(src=ip.src, dst=ip.dst)
        for layer, name in ((TCP, "TCP"), (UDP, "UDP")):
            if pkt.haslayer(layer):
                dport, sport = pkt[layer].dport, pkt[layer].sport
                info["dport"] = dport
                info["protocol"] = _SERVICES.get(dport) or _SERVICES.get(sport) or name
                if name == "TCP":
                    info["payload"] = bytes(pkt[TCP].payload)[:512]
                return info
        if pkt.haslayer(ICMP) or ip.__class__.__name__ == "IPv6" and ip.nh == 58:
            info["protocol"] = "ICMP"
        return info

    def _touch_host(self, ip, mac, proto, ts, is_src):
        h = self.hosts.get(ip)
        if h is None:
            h = self.hosts[ip] = {"ip": ip, "mac": None, "vendor": None, "protocol": proto,
                                  "protocols": set(), "packets": 0,
                                  "first_seen": _iso(ts), "last_seen": _iso(ts)}
        if mac and _is_private(ip) and not h["mac"]:     # L2 src of remote IPs is the router
            h["mac"], h["vendor"] = mac, vendor_for(mac)
        h["protocols"].add(proto)
        h["protocol"] = proto
        h["last_seen"] = _iso(ts)
        if is_src:
            h["packets"] += 1

    # ---- detection ----------------------------------------------------
    def _detect(self, info, ts):
        src, dst, dport = info["src"], info["dst"], info["dport"]
        if dport is not None and src:
            q = self._scan.setdefault(src, deque())
            q.append((ts, (dst, dport)))
            while q and ts - q[0][0] > SCAN_WINDOW:
                q.popleft()
            if len({t for _, t in q}) >= SCAN_THRESHOLD:
                self._alert("high", f"Possible port scan from {src}", src, ts, key=("scan", src),
                            detail=f"{len({t for _, t in q})} distinct host/port targets in {SCAN_WINDOW}s")
        if dport in _PLAINTEXT_PORTS and info["payload"]:
            low = info["payload"].lower()
            if any(m in low for m in _CRED_MARKERS):
                # PPS-SR-005: never store or show the captured secret itself.
                self._alert("medium", f"Plaintext credentials sent to {dst}:{dport}", src, ts,
                            key=("cred", src, dst), detail="Credential values masked (****)")

    def _alert(self, severity, message, src, ts, key, detail="", source="detection"):
        if ts - self._cooldown.get(key, 0) < ALERT_COOLDOWN:
            return
        self._cooldown[key] = ts
        self.alert_list.append({"id": len(self.alert_list) + 1, "severity": severity, "message": message,
                                "time": _iso(ts), "src": src, "detail": detail, "source": source})

    def add_zeek_alerts(self, notices):
        """notices: rows from Zeek notice.log (ts, note, msg, src)."""
        with self._lock:
            for n in notices:
                note = n.get("note", "Zeek::Notice")
                sev = "high" if "Scan" in note else "medium"
                try:
                    ts = float(n.get("ts", time.time()))
                except ValueError:
                    ts = time.time()
                self.alert_list.append({
                    "id": len(self.alert_list) + 1, "severity": sev,
                    "message": note.replace("::", " - ").replace("_", " "),
                    "time": _iso(ts), "src": n.get("src") if n.get("src") != "-" else None,
                    "detail": (n.get("msg") or "")[:200] if "Password" not in note else "Masked",
                    "source": "zeek"})

    # ---- views --------------------------------------------------------
    def stats(self):
        with self._lock:
            now = time.time()
            recent = sum(1 for t in self.window if now - t <= 2)
            return {"packets_per_sec": round(recent / 2),
                    "top_talkers": [{"ip": ip, "packets": c} for ip, c in self.talkers.most_common(5)],
                    "protocols": dict(self.protocols.most_common()),
                    "total_packets": self.total}

    def host_list(self):
        with self._lock:
            out = []
            for h in sorted(self.hosts.values(), key=lambda x: -x["packets"]):
                out.append({**h, "protocols": sorted(h["protocols"])})
            return out

    def alerts(self):
        with self._lock:
            return list(reversed(self.alert_list))
