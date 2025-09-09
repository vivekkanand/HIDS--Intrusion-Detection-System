import os, time, queue, platform, threading
from utils import StoppableThread

class LogCollector(StoppableThread):
    def __init__(self, evtq: queue.Queue, log_sources=None, source="system"):
        super().__init__(name="LogCollector", daemon=True)
        self.q = evtq
        self.source = source
        self.log_sources = log_sources or []
        self.os_type = platform.system().lower()

    def run(self):
        if "windows" in self.os_type:
            threading.Thread(target=self._collect_windows_events, daemon=True).start()
        elif "linux" in self.os_type:
            # start tailing common auth logs if present
            for p in ["/var/log/auth.log", "/var/log/secure"]:
                if os.path.exists(p):
                    threading.Thread(target=self._tail_file, args=(p,), daemon=True).start()
        # fallback: any user-specified paths
        for path in self.log_sources:
            if os.path.exists(path):
                threading.Thread(target=self._tail_file, args=(path,), daemon=True).start()

        while not self.stopped():
            time.sleep(1)

    def _collect_windows_events(self):
        try:
            import win32evtlog
            log_type = "Security"
            server = "localhost"
            hand = win32evtlog.OpenEventLog(server, log_type)
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            while not self.stopped():
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    time.sleep(1)
                    continue
                for ev_obj in events:
                    try:
                        event_id = ev_obj.EventID & 0xFFFF
                        message = " ".join([str(i) for i in (ev_obj.StringInserts or [])])
                        self.q.put({
                            "source": self.source,
                            "type": "log",
                            "event_id": event_id,
                            "message": message,
                            "channel": log_type
                        })
                    except Exception:
                        continue
        except Exception as e:
            print(f"[LogCollector] Windows log error: {e}")

    def _tail_file(self, path):
        event_id = 0
        try:
            with open(path, "r", errors="ignore") as f:
                f.seek(0, os.SEEK_END)
                while not self.stopped():
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    event_id += 1
                    self.q.put({
                        "source": self.source,
                        "type": "log",
                        "event_id": event_id,
                        "message": line.strip(),
                        "path": path
                    })
        except Exception as e:
            print(f"[LogCollector] Failed to read {path}: {e}")
