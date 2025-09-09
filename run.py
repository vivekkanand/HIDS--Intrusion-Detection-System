import argparse, os, yaml, queue, time
from utils import ensure_dirs, setup_logger, open_db
from collectors.system_collector import SystemCollector
from collectors.file_collector import FileCollector
from collectors.net_sniffer import NetSniffer
from collectors.log_collector import LogCollector
from detectors.anomaly import Detector
from alerting.alerter import Alerter

def main():
    ap = argparse.ArgumentParser(description="AI Sec Monitor")
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args()

    with open(args.config, "r") as f:
        cfg = yaml.safe_load(f)

    log = setup_logger(cfg.get("log_level","INFO"))
    data_dir = cfg.get("data_dir","./data")
    ensure_dirs(data_dir)
    conn = open_db(cfg.get("sqlite_path", f"{data_dir}/events.db"))

    evtq = queue.Queue(maxsize=10000)

    # collectors
    sys_col = SystemCollector(evtq, cfg.get("system_sample_seconds",5)); sys_col.start()
    file_paths = cfg.get("file_watch_paths", [])
    file_col = FileCollector(evtq, file_paths); file_col.start()

    net_cfg = cfg.get("network", {})
    if net_cfg.get("enabled", True):
        net = NetSniffer(evtq, net_cfg.get("bpf_filter",""), net_cfg.get("iface","")); net.start()
    else:
        net = None

    # Log collector (auto OS-aware) - also accepts manual list in config.yaml 'log_sources'
    log_sources = cfg.get("log_sources", [])
    log_col = LogCollector(evtq, log_sources); log_col.start()

    # alerter + detector
    alerter = Alerter(cfg.get("alerting", {}), log)
    det = Detector(conn, evtq, cfg.get("thresholds", {}), cfg.get("anomaly", {}), alerter, log, network_rules_cfg=cfg.get("network_rules", {}), rules_file="rules/rules.yaml")
    det.start()

    log.info("AI Sec Monitor running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Stopping...")
        sys_col.stop(); file_col.stop(); log_col.stop()
        if net: net.stop()
        evtq.put(None)
        time.sleep(1)
        log.info("Stopped.")

if __name__ == "__main__":
    main()
