import time, queue, threading, collections
from utils import persist_event
from sklearn.ensemble import IsolationForest
import numpy as np
from rules.rule_engine import RuleEngine

class Detector(threading.Thread):
    def __init__(self, conn, evtq: queue.Queue, thresholds: dict, anomaly_cfg: dict, alerter, logger, network_rules_cfg=None, rules_file="rules/rules.yaml"):
        super().__init__(name="Detector", daemon=True)
        self.conn = conn
        self.q = evtq
        self.thresholds = thresholds
        self.alerter = alerter
        self.log = logger

        self.enable_if = anomaly_cfg.get("enable_isolation_forest", True)
        self.warmup_minutes = float(anomaly_cfg.get("warmup_minutes", 5))
        self.contamination = float(anomaly_cfg.get("contamination", 0.02))
        self._start_time = time.time()
        self._if_model = None
        self._if_buffer = []

        self.proc_spawns = collections.deque(maxlen=120)
        self.file_events = collections.deque(maxlen=600)
        self.net_packets = collections.deque(maxlen=600)

        self.network_rules_cfg = network_rules_cfg or {}
        self.rule_engine = RuleEngine(rules_file)

    def _is_internal_ip(self, ip: str) -> bool:
        return isinstance(ip, str) and (ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."))

    def _should_ignore_packet(self, evt: dict) -> bool:
        # Only decide for network packets
        if evt.get("source") != "network" or evt.get("type") != "packet":
            return False

        # If rules explicitly want ICMP/HTTP/HTTPS, honor them
        proto = evt.get("proto")
        dport = evt.get("dport", 0)

        # If ICMP and alert_icmp true -> do not ignore
        if proto == 1:
            return not self.network_rules_cfg.get("alert_icmp", False)

        # If HTTP and alert_http true -> do not ignore
        if proto == 6 and dport == 80:
            return not self.network_rules_cfg.get("alert_http", False)

        # If HTTPS and alert_https true -> do not ignore
        if proto == 6 and dport == 443:
            return not self.network_rules_cfg.get("alert_https", False)

        # ignore internal IPs by default
        if ("src" in evt and self._is_internal_ip(evt["src"])) or ("dst" in evt and self._is_internal_ip(evt["dst"])):
            return True

        # Default: ignore other network traffic unless configured otherwise
        return True

    def _features(self, evt):
        if evt.get("source") == "system":
            return [float(evt.get("cpu", 0.0)), float(evt.get("mem", 0.0)), float(len(evt.get("new_processes", [])))]
        if evt.get("source") == "network":
            return [float(evt.get("len", 0.0)), float(evt.get("dport", 0) or 0), float(evt.get("proto", 0) or 0)]
        if evt.get("source") == "file":
            et = evt.get("type")
            enc = {"created":1, "modified":2, "deleted":3}.get(et, 0)
            return [float(enc), 0.0, 0.0]
        if evt.get("source") == "log":
            return [0.0, 0.0, 0.0]
        return [0.0, 0.0, 0.0]

    def _train_if_needed(self):
        if not self.enable_if:
            return
        elapsed_min = (time.time() - self._start_time) / 60.0
        if elapsed_min < self.warmup_minutes:
            return
        if self._if_model is None and len(self._if_buffer) >= 200:
            X = np.array(self._if_buffer, dtype=float)
            self._if_model = IsolationForest(contamination=self.contamination, random_state=42)
            self._if_model.fit(X)
            self._if_buffer = []

    def _maybe_alert(self, summary, details, severity="WARNING"):
        persist_event(self.conn, details.get("source","unknown"), severity, summary, details)
        self.alerter.alert(summary, details, severity)

    def run(self):
        while True:
            evt = self.q.get()
            if evt is None:
                break

            # Evaluate custom rules first (logs + network)
            try:
                custom_alerts = self.rule_engine.evaluate(evt)
                for alert in custom_alerts:
                    msg = f"[RULE] {alert['rule']} (EventID: {alert.get('event_id')})"
                    self.alerter.alert(msg, alert['event'], alert.get('level', 'WARNING'))
            except Exception:
                pass

            # Skip network packets deemed normal by config
            if evt.get("source") == "network" and self._should_ignore_packet(evt):
                continue

            now = time.time()
            if evt.get("source") == "system" and evt.get("new_processes"):
                for _ in evt["new_processes"]:
                    self.proc_spawns.append(now)
            if evt.get("source") == "file":
                self.file_events.append(now)
            if evt.get("source") == "network" and evt.get("type") == "packet":
                self.net_packets.append(now)

            if evt.get("source") == "system":
                if evt.get("cpu", 0) >= self.thresholds.get("cpu_percent_high", 95):
                    self._maybe_alert("High CPU usage", evt, "WARNING")
                if evt.get("mem", 0) >= self.thresholds.get("mem_percent_high", 95):
                    self._maybe_alert("High memory usage", evt, "WARNING")

            cutoff = now - 60
            if len([t for t in self.proc_spawns if t >= cutoff]) >= self.thresholds.get("proc_spawn_rate_per_minute", 100):
                self._maybe_alert("Process spawn burst", {"source":"system"}, "CRITICAL")
            if len([t for t in self.file_events if t >= cutoff]) >= self.thresholds.get("file_event_burst_per_minute", 1000):
                self._maybe_alert("File modification burst", {"source":"file"}, "CRITICAL")
            if len([t for t in self.net_packets if t >= cutoff]) >= self.thresholds.get("net_conn_burst_per_minute", 2000):
                self._maybe_alert("Network packet burst", {"source":"network"}, "CRITICAL")

            vec = self._features(evt)
            elapsed_min = (now - self._start_time) / 60.0
            if self.enable_if and (self._if_model is None) and elapsed_min < self.warmup_minutes:
                self._if_buffer.append(vec)
            self._train_if_needed()

            if self._if_model is not None:
                try:
                    pred = self._if_model.predict([vec])[0]
                    if int(pred) == -1:
                        self._maybe_alert("Anomalous event (IsolationForest)", evt, "WARNING")
                except Exception:
                    pass
