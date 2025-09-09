import yaml, os

class RuleEngine:
    def __init__(self, rules_file="rules/rules.yaml"):
        rules_file = os.path.expanduser(rules_file)
        if not os.path.exists(rules_file):
            self.rules = {}
            return
        with open(rules_file, "r") as f:
            self.rules = yaml.safe_load(f) or {}

    def evaluate(self, event: dict):
        alerts = []
        # network rules
        if event.get("source") == "network":
            for rule in self.rules.get("network_rules", []):
                try:
                    # evaluate condition with event dict as locals
                    if eval(rule["condition"], {}, event):
                        alerts.append({
                            "rule": rule["name"],
                            "level": rule["level"],
                            "event_id": event.get("event_id"),
                            "event": event
                        })
                except Exception:
                    continue
        # system rules (logs)
        if event.get("source") == "system":
            for rule in self.rules.get("system_rules", []):
                try:
                    if eval(rule["condition"], {}, event):
                        alerts.append({
                            "rule": rule["name"],
                            "level": rule["level"],
                            "event_id": event.get("event_id"),
                            "event": event
                        })
                except Exception:
                    continue
        return alerts
