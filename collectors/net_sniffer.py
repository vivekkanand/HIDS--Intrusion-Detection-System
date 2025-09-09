from utils import StoppableThread
import queue
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

class NetSniffer(StoppableThread):
    def __init__(self, evtq: queue.Queue, bpf_filter: str = "", iface: str = ""):
        super().__init__(name="NetSniffer", daemon=True)
        self.q = evtq
        self.filter = bpf_filter or None
        self.iface = iface or None

    def run(self):
        if not SCAPY_OK:
            self.q.put({
                "source": "network",
                "type": "error",
                "message": "Scapy not available; install dependencies and run with admin/root."
            })
            return

        def cb(pkt):
            try:
                info = {"source": "network", "type": "packet", "len": len(pkt)}
                if IP in pkt:
                    ip = pkt[IP]
                    info.update({"src": ip.src, "dst": ip.dst, "proto": int(ip.proto)})
                if TCP in pkt:
                    tcp = pkt[TCP]
                    info.update({"sport": int(tcp.sport), "dport": int(tcp.dport), "l4": "TCP"})
                elif UDP in pkt:
                    udp = pkt[UDP]
                    info.update({"sport": int(udp.sport), "dport": int(udp.dport), "l4": "UDP"})
                elif ICMP in pkt:
                    info.update({"l4": "ICMP"})
                self.q.put(info)
            except Exception:
                pass

        sniff(prn=cb, store=False, filter=self.filter, iface=self.iface)
