![NSMS dashboard](docs/dashboard.png)

# NSMS — Python Network Security Monitoring System (starter)

This is a minimal, local-only Python NSM sensor with basic detectors:
- TCP SYN port scan
- DNS tunneling / suspicious domain heuristic

It captures packets with **Scapy**, evaluates rules, and writes alerts to `data/alerts.jsonl`.
A simple **Streamlit** dashboard is provided to visualize alerts.

> ⚠️ Packet capture requires admin privileges:
> - **Linux/macOS:** run with `sudo`
> - **Windows:** install [Npcap](https://nmap.org/npcap/), then run an elevated PowerShell/CMD

## Quickstart

```bash
# 1) Create & activate a venv (recommended)
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2) Install deps
pip install -r requirements.txt

# 3) (Linux/macOS) list interfaces
python -m scapy.all
# Or: ip link / ifconfig / Get-NetAdapter

# 4) Run the sensor (replace -i with your interface)
sudo python nsms/main.py -i eth0

# Optional: filter only what you need (BPF syntax)
sudo python nsms/main.py -i eth0 --bpf "tcp or udp"

# 5) View the live dashboard in another terminal
streamlit run nsms/dash_app.py
```

## Project Layout

```
nsms/
  __init__.py
  main.py
  config.py
  capture.py
  detect.py
  alert.py
  storage.py
  dash_app.py
config.yaml
requirements.txt
data/
  alerts.jsonl   (created on first alert)
```

## Next steps / ideas

- Add detectors: brute-force login (syslog ingest), TLS SNI anomaly, HTTP UA blacklist.
- Add threat intel matching (IP/domain lists).
- Forward alerts to Slack, email, or SIEM (Splunk HEC, Elastic).
- Persist flows/metrics in SQLite and enrich with GeoIP.
