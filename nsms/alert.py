import json, os, time, threading

class Alerter:
    def __init__(self, alerts_path="data/alerts.jsonl"):
        self.alerts_path = alerts_path
        os.makedirs(os.path.dirname(alerts_path), exist_ok=True)
        self._lock = threading.Lock()

    def emit(self, alert: dict):
        alert = dict(alert)
        alert["ts"] = alert.get("time", time.time())
        line = json.dumps(alert, ensure_ascii=False)
        with self._lock:
            with open(self.alerts_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        # Console summary
        sev = alert.get("severity", "info").upper()
        kind = alert.get("kind", "event")
        msg = alert.get("msg", "")
        print(f"[{sev}] {kind}: {msg}")
