import time, psutil, queue
from utils import StoppableThread

class SystemCollector(StoppableThread):
    def __init__(self, evtq: queue.Queue, sample_seconds: int = 5):
        super().__init__(name="SystemCollector", daemon=True)
        self.q = evtq
        self.sample = sample_seconds
        self.prev_pids = set()

    def run(self):
        while not self.stopped():
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            pids = set(psutil.pids())
            new_proc = list(pids - self.prev_pids) if self.prev_pids else []
            self.prev_pids = pids

            self.q.put({
                "source": "system",
                "type": "resource",
                "cpu": cpu,
                "mem": mem,
                "new_processes": new_proc,
            })
            time.sleep(self.sample)
