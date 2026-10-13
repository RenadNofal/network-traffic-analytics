"""Generate synthetic network flow logs for the Network Traffic Analytics project."""
import csv, random
from datetime import datetime, timedelta

random.seed(42)
START = datetime(2026, 10, 5)
DAYS = 7

# Internal devices (name, ip, how "chatty" they are)
devices = [
    ("FILE-SERVER-01", "10.0.1.10", 8), ("WEB-SERVER-01", "10.0.1.20", 6),
    ("DB-SERVER-01", "10.0.1.30", 5), ("BACKUP-NAS", "10.0.1.40", 4),
    ("PRINTER-2F", "10.0.2.50", 1), ("CAMERA-LOBBY", "10.0.2.60", 2),
] + [(f"LAPTOP-{i:02d}", f"10.0.3.{100+i}", 2) for i in range(1, 21)]
external = ["8.8.8.8", "1.1.1.1", "142.250.80.46", "52.96.12.34", "151.101.1.69",
            "104.16.132.229", "13.107.42.14", "185.199.108.153"]
services = [("HTTPS", 443, "TCP", 45), ("DNS", 53, "UDP", 20), ("HTTP", 80, "TCP", 8),
            ("SSH", 22, "TCP", 5), ("SMB", 445, "TCP", 8), ("MySQL", 3306, "TCP", 6),
            ("NTP", 123, "UDP", 3), ("RDP", 3389, "TCP", 3), ("ICMP", 0, "ICMP", 2)]

def hour_weight(ts):
    h, weekend = ts.hour, ts.weekday() >= 5
    base = 1.0 if 9 <= h <= 17 else (0.4 if 7 <= h <= 20 else 0.15)
    if h in (10, 14): base *= 1.6          # mid-morning / afternoon peaks
    return base * (0.35 if weekend else 1.0)

rows, fid = [], 1
for minute in range(DAYS * 24 * 60):
    ts = START + timedelta(minutes=minute)
    n = int(random.gauss(6, 2) * hour_weight(ts))
    if ts.hour == 2 and ts.minute < 30: n += 25  # nightly backup window
    for _ in range(max(n, 0)):
        name, src, _w = random.choices(devices, weights=[d[2] for d in devices])[0]
        svc, port, proto, _ = random.choices(services, weights=[s[3] for s in services])[0]
        if ts.hour == 2 and ts.minute < 30 and random.random() < 0.6:
            name, src, svc, port, proto = "BACKUP-NAS", "10.0.1.40", "SMB", 445, "TCP"
            dst = "10.0.1.10"; sent = random.randint(5_000_000, 50_000_000)
        else:
            dst = random.choice(external) if svc in ("HTTPS", "HTTP", "DNS", "NTP") else \
                  random.choice(["10.0.1.10", "10.0.1.20", "10.0.1.30"])
            sent = int(random.lognormvariate(8, 1.8))
        recv = int(sent * random.uniform(0.5, 6)) if svc in ("HTTPS", "HTTP") else int(sent * random.uniform(0.2, 1.5))
        action = "DENY" if (svc in ("RDP", "SSH") and random.random() < 0.15) else "ALLOW"
        rows.append([fid, ts.replace(second=random.randint(0, 59)).isoformat(sep=" "), name, src,
                     random.randint(49152, 65535), dst, port, proto, svc,
                     sent, recv, max(1, (sent + recv) // 1400), random.randint(1, 30000), action])
        fid += 1

# Inject a suspicious port scan: one laptop hits many ports, mostly denied
scan_start = START + timedelta(days=3, hours=23, minutes=12)
for i, port in enumerate(range(1, 1025)):
    ts = scan_start + timedelta(seconds=i // 4)
    rows.append([fid, ts.isoformat(sep=" "), "LAPTOP-13", "10.0.3.113", random.randint(49152, 65535),
                 "10.0.1.30", port, "TCP", "UNKNOWN", 60, 0, 1, random.randint(1, 5),
                 "DENY" if random.random() < 0.95 else "ALLOW"])
    fid += 1

rows.sort(key=lambda r: r[1])
with open("../data/network_traffic_logs.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["flow_id", "event_time", "device_name", "src_ip", "src_port", "dst_ip", "dst_port",
                "protocol", "service", "bytes_sent", "bytes_received", "packets", "duration_ms", "action"])
    w.writerows(rows)
print(len(rows), "rows written")
