import os, sqlite3, json, time, queue, threading, logging, pathlib

def ensure_dirs(path: str):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)

def setup_logger(level: str = "INFO"):
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        format="%(asctime)s | %(levelname)s | %(threadName)s | %(message)s"
    )
    return logging.getLogger("ai-sec-monitor")

def open_db(db_path: str):
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "ts REAL, source TEXT, severity TEXT, summary TEXT, details TEXT)"
    )
    conn.commit()
    return conn

def persist_event(conn, source: str, severity: str, summary: str, details: dict):
    payload = json.dumps(details, ensure_ascii=False)
    conn.execute(
        "INSERT INTO events (ts, source, severity, summary, details) VALUES (?,?,?,?,?)",
        (time.time(), source, severity, summary, payload),
    )
    conn.commit()

class StoppableThread(threading.Thread):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()
