#!/usr/bin/env python3
"""
NSMS main entrypoint — starts packet capture and runs detectors.
Safe printing (no weird escapes) + clean indentation.
Works whether run as `python nsms/main.py` or `python -m nsms.main`.
"""

import argparse
import sys

# Be robust to how the script is launched: relative OR absolute imports
try:
    from .config import load_config
    from .capture import start_capture
    from .alert import Alerter
    from .detect import PortScanDetector, DNSTunnelDetector
except ImportError:  # running as a plain script
    from nsms.config import load_config
    from nsms.capture import start_capture
    from nsms.alert import Alerter
    from nsms.detect import PortScanDetector, DNSTunnelDetector


def main():
    parser = argparse.ArgumentParser(
        description="NSMS — Python Network Security Monitoring System (starter)"
    )
    parser.add_argument(
        "-c", "--config", default="config.yaml", help="Path to config.yaml"
    )
    parser.add_argument(
        "-i", "--interface", required=True, help="Interface to sniff (e.g., eth0, en0)"
    )
    parser.add_argument(
        "--bpf", default=None, help='BPF filter (e.g., "tcp or udp or port 53")'
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    bpf = args.bpf or cfg.get("capture", {}).get("bpf_filter", "tcp or udp or port 53")

    alerter = Alerter()

    def emit(alert):
        alerter.emit(alert)

    port_scan = PortScanDetector(cfg.get("detectors", {}).get("port_scan", {}), emit)
    dns_tunnel = DNSTunnelDetector(cfg.get("detectors", {}).get("dns_tunnel", {}), emit)

    def on_event(ev):
        port_scan.process(ev)
        dns_tunnel.process(ev)

    print(f"[*] Starting capture on {args.interface} with filter: {bpf}")
    print("[*] Press Ctrl+C to stop.")
    try:
        start_capture(args.interface, bpf, on_event)
    except PermissionError:
        print(
            "[!] Permission denied. Try:\n"
            "- Linux/macOS: sudo python nsms/main.py -i <iface>\n"
            "- Windows: Run as Administrator and install Npcap"
        )
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
