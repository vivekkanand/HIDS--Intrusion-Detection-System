import os, queue, time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from utils import StoppableThread
from pathlib import Path

class _Handler(FileSystemEventHandler):
    def __init__(self, q: queue.Queue, root: str, ignore_paths=None):
        self.q = q
        self.root = root
        self.ignore_paths = [os.path.abspath(p) for p in (ignore_paths or [])]

    def on_any_event(self, event):
        abspath = os.path.abspath(event.src_path)
        for ip in self.ignore_paths:
            if abspath.startswith(ip):
                return  # skip ignored paths
        self.q.put({
            "source": "file",
            "type": event.event_type,
            "is_directory": event.is_directory,
            "path": abspath,
            "root": self.root,
        })

class FileCollector(StoppableThread):
    def __init__(self, evtq: queue.Queue, paths):
        super().__init__(name="FileCollector", daemon=True)
        self.q = evtq
        self.paths = [os.path.expanduser(p) for p in paths]
        self.observer = Observer()
        # Ignore monitor's own data folder and caches
        self.ignore_paths = [
            os.path.abspath(os.path.join(os.getcwd(), "data")),
            os.path.abspath(os.path.join(os.getcwd(), "__pycache__")),
        ]

    def run(self):
        for p in self.paths:
            root = str(Path(p).resolve())
            self.observer.schedule(
                _Handler(self.q, root, ignore_paths=self.ignore_paths),
                path=root,
                recursive=True
            )
        self.observer.start()
        try:
            while not self.stopped():
                time.sleep(0.5)
        finally:
            self.observer.stop()
            self.observer.join()
