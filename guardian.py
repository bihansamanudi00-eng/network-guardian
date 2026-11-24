import os
import sys
import time
import queue
import sqlite3
import threading
from collections import defaultdict, Counter
from datetime import datetime

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, get_if_list, conf

ML_IMPORT_ERROR = None
try:
    import joblib
    import pandas as pd
    from sklearn.ensemble import IsolationForest
except Exception as exc:
    joblib = None
    pd = None
    IsolationForest = None
    ML_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

from config import (
    WINDOW_SECONDS, PORT_SCAN_THRESHOLD, REPEATED_DNS_THRESHOLD,
    MAX_DOMAIN_LENGTH, MAX_LABEL_LENGTH, MAX_SUBDOMAINS,
    SUSPICIOUS_KEYWORDS, MIN_TRAINING_ROWS, MODEL_PATH, DATABASE_PATH,
)

FEATURES = [
    "packet_count", "average_packet_size", "maximum_packet_size",
    "tcp_count", "udp_count", "icmp_count", "unique_destination_ports",
    "dns_query_count", "syn_count",
]

def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def db_connect():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH, timeout=10, check_same_thread=False)
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS traffic_features (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, source_ip TEXT,
            packet_count INTEGER, average_packet_size REAL,
            maximum_packet_size INTEGER, tcp_count INTEGER,
            udp_count INTEGER, icmp_count INTEGER,
            unique_destination_ports INTEGER, dns_query_count INTEGER,
            syn_count INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, severity TEXT, alert_type TEXT,
            source_ip TEXT, details TEXT
        )
    """)
    conn.commit()
    return conn

def list_capture_interfaces():
    # Scapy's libpcap-backed names are what sniff(iface=...) expects on Windows.
    try:
        return [(str(x.name), str(x.description or x.name)) for x in conf.ifaces.values()]
    except Exception:
        return [(str(x), str(x)) for x in get_if_list()]

def ip_pair(pkt):
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return None, None

def dns_domain(pkt):
    try:
        if DNS in pkt and pkt[DNS].qd and DNSQR in pkt:
            q = pkt[DNS].qd.qname
            if isinstance(q, bytes):
                q = q.decode("utf-8", errors="ignore")
            return str(q).rstrip(".").lower()
    except Exception:
        pass
    return None

class NetworkGuardian:
    def __init__(self, event_queue):
        self.events = event_queue
        self.stop_event = threading.Event()
        self.thread = None
        self.running = False
        self.lock = threading.Lock()
        # SQLite connection is shared by the GUI and capture worker.
        # Serialize every database operation with this dedicated lock.
        self.db_lock = threading.RLock()
        self.current = {}
        self.packet_total = 0
        self.started = None
        self.model = None
        self.model_status = "Not trained – rule-based detection is active"
        self.load_model()
        self.db = db_connect()

    def load_model(self):
        if joblib and os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                self.model_status = "Trained Isolation Forest model loaded"
            except Exception as e:
                self.model_status = f"Could not load model: {e}"

    def start(self, iface):
        if self.running:
            return
        self.stop_event.clear()
        self.packet_total = 0
        self.running = True
        self.started = time.time()
        self.thread = threading.Thread(target=self._capture_loop, args=(iface,), daemon=True)
        self.thread.start()
        self.events.put(("status", f"Monitoring on: {iface}"))

    def stop(self):
        self.stop_event.set()
        self.running = False
        self.events.put(("status", "Stopping capture…"))

    def _capture_loop(self, iface):
        try:
            while not self.stop_event.is_set():
                sniff(
                    iface=iface,
                    prn=self._packet_callback,
                    store=False,
                    timeout=1,
                    stop_filter=lambda _: self.stop_event.is_set()
                )
                self._flush_old_windows()
            self._flush_all()
        except Exception as e:
            self.running = False
            self.events.put(("error", f"Packet capture failed: {e}\n\nTry running the launcher as Administrator and check that Npcap is installed."))
        finally:
            self.running = False
            self.events.put(("status", "Monitoring stopped"))

    def _packet_callback(self, pkt):
        src, dst = ip_pair(pkt)
        if not src:
            return
        size = len(pkt)
        proto = "OTHER"
        dport = None
        syn = 0
        if TCP in pkt:
            proto = "TCP"
            dport = int(pkt[TCP].dport)
            syn = 1 if (int(pkt[TCP].flags) & 0x02 and not (int(pkt[TCP].flags) & 0x10)) else 0
        elif UDP in pkt:
            proto = "UDP"
            dport = int(pkt[UDP].dport)
        elif ICMP in pkt:
            proto = "ICMP"

        domain = dns_domain(pkt)
        t = time.time()
        with self.lock:
            row = self.current.get(src)
            if row is None:
                row = {
                    "start": t, "source_ip": src, "packet_count": 0,
                    "total_size": 0, "maximum_packet_size": 0,
                    "tcp_count": 0, "udp_count": 0, "icmp_count": 0,
                    "ports": set(), "dns_query_count": 0, "syn_count": 0,
                    "domains": Counter(), "targets": set(),
                }
                self.current[src] = row
            row["packet_count"] += 1
            row["total_size"] += size
            row["maximum_packet_size"] = max(row["maximum_packet_size"], size)
            if proto in ("TCP", "UDP", "ICMP"):
                row[proto.lower() + "_count"] += 1
            if dport is not None:
                row["ports"].add(dport)
            row["syn_count"] += syn
            row["targets"].add(dst)
            if domain:
                row["dns_query_count"] += 1
                row["domains"][domain] += 1
            self.packet_total += 1
            self.events.put(("packet", self.packet_total))

    def _flush_old_windows(self):
        t = time.time()
        ready = []
        with self.lock:
            for src, row in list(self.current.items()):
                if t - row["start"] >= WINDOW_SECONDS:
                    ready.append(row)
                    del self.current[src]
        for row in ready:
            self._process_window(row)

    def _flush_all(self):
        with self.lock:
            rows = list(self.current.values())
            self.current.clear()
        for row in rows:
            self._process_window(row)

    def _process_window(self, row):
        count = row["packet_count"]
        features = {
            "packet_count": count,
            "average_packet_size": round(row["total_size"] / max(count, 1), 2),
            "maximum_packet_size": row["maximum_packet_size"],
            "tcp_count": row["tcp_count"],
            "udp_count": row["udp_count"],
            "icmp_count": row["icmp_count"],
            "unique_destination_ports": len(row["ports"]),
            "dns_query_count": row["dns_query_count"],
            "syn_count": row["syn_count"],
        }
        stamp = now_text()
        src = row["source_ip"]
        with self.db_lock:
            self.db.execute(
                """INSERT INTO traffic_features
                (timestamp,source_ip,packet_count,average_packet_size,maximum_packet_size,
                 tcp_count,udp_count,icmp_count,unique_destination_ports,dns_query_count,syn_count)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (stamp, src, features["packet_count"], features["average_packet_size"],
                 features["maximum_packet_size"], features["tcp_count"], features["udp_count"],
                 features["icmp_count"], features["unique_destination_ports"],
                 features["dns_query_count"], features["syn_count"])
            )
            self.db.commit()

        summary = {"timestamp": stamp, "source_ip": src, **features}
        self.events.put(("traffic", summary))

        if features["unique_destination_ports"] >= PORT_SCAN_THRESHOLD:
            self.add_alert("HIGH", "Possible port scan",
                           f"{features['unique_destination_ports']} unique destination ports observed in a {WINDOW_SECONDS}-second window.",
                           src)
        for domain, repeats in row["domains"].items():
            if repeats >= REPEATED_DNS_THRESHOLD:
                self.add_alert("MEDIUM", "Repeated DNS queries",
                               f"Domain {domain} queried {repeats} times in one window.", src)
            reasons = []
            if len(domain) > MAX_DOMAIN_LENGTH:
                reasons.append("domain is unusually long")
            labels = domain.split(".")
            if any(len(x) > MAX_LABEL_LENGTH for x in labels):
                reasons.append("a domain label is unusually long")
            if len(labels) - 2 > MAX_SUBDOMAINS:
                reasons.append("many subdomains")
            if any(k in domain for k in SUSPICIOUS_KEYWORDS):
                reasons.append("contains a suspicious keyword")
            if reasons:
                self.add_alert("MEDIUM", "Suspicious DNS pattern",
                               f"{domain}: {', '.join(reasons)}. This heuristic is not proof of maliciousness.", src)

        if self.model is not None and pd is not None:
            try:
                frame = pd.DataFrame([[features[x] for x in FEATURES]], columns=FEATURES)
                prediction = int(self.model.predict(frame)[0])
                if prediction == -1:
                    self.add_alert("MEDIUM", "ML traffic anomaly",
                                   "Isolation Forest marked this traffic window as unusual. Investigate; this is not proof of an attack.", src)
            except Exception as e:
                self.events.put(("status", f"ML prediction skipped: {e}"))

    def add_alert(self, severity, alert_type, details, src):
        stamp = now_text()
        with self.db_lock:
            self.db.execute(
                "INSERT INTO alerts (timestamp,severity,alert_type,source_ip,details) VALUES (?,?,?,?,?)",
                (stamp, severity, alert_type, src, details)
            )
            self.db.commit()
        self.events.put(("alert", {
            "timestamp": stamp, "severity": severity, "alert_type": alert_type,
            "source_ip": src, "details": details
        }))

    def recent_alerts(self, limit=100):
        with self.db_lock:
            return self.db.execute(
                "SELECT timestamp,severity,alert_type,source_ip,details FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()

    def recent_traffic(self, limit=100):
        with self.db_lock:
            return self.db.execute(
                """SELECT timestamp,source_ip,packet_count,tcp_count,udp_count,icmp_count,
                unique_destination_ports,dns_query_count FROM traffic_features ORDER BY id DESC LIMIT ?"""
            ).fetchall()

    def train_model(self):
        if IsolationForest is None or pd is None or joblib is None:
            detail = ML_IMPORT_ERROR or "One or more ML packages could not be imported."
            raise RuntimeError(
                "The machine-learning dependencies are unavailable in this Python environment. "
                f"Import details: {detail}\n"
                "Close Network Guardian and run launch_network_guardian.bat again."
            )
        with self.db_lock:
            rows = self.db.execute(
                "SELECT " + ",".join(FEATURES) + " FROM traffic_features"
            ).fetchall()
        if len(rows) < MIN_TRAINING_ROWS:
            raise RuntimeError(
                f"Only {len(rows)} traffic feature records are stored. At least {MIN_TRAINING_ROWS} are required. "
                "Collect normal traffic for longer, across several sessions, then try again."
            )
        frame = pd.DataFrame(rows, columns=FEATURES).fillna(0)
        model = IsolationForest(n_estimators=150, contamination=0.05, random_state=42)
        model.fit(frame)
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(model, MODEL_PATH)
        self.model = model
        self.model_status = f"Isolation Forest trained using {len(rows)} traffic windows"
        return self.model_status


    def close(self):
        self.stop()
        with self.db_lock:
            try:
                self.db.close()
            except Exception:
                pass
