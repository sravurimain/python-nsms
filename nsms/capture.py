import time
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR

def start_capture(interface: str, bpf_filter: str, callback):
    """Start live capture and call `callback(event_dict)` per packet."""
    def _handle(pkt):
        try:
            event = {
                "ts": time.time(),
                "l2_len": len(pkt) if hasattr(pkt, '__len__') else None
            }
            if IP in pkt:
                ip = pkt[IP]
                event.update({
                    "src": ip.src, "dst": ip.dst, "proto": ip.proto
                })
            if TCP in pkt:
                t = pkt[TCP]
                flags = int(t.flags)
                event.update({
                    "l4": "tcp", "sport": t.sport, "dport": t.dport,
                    "tcp_flags": flags, "syn": bool(flags & 0x02), "ack": bool(flags & 0x10)
                })
            elif UDP in pkt:
                u = pkt[UDP]
                event.update({"l4": "udp", "sport": u.sport, "dport": u.dport})

            # DNS parsing (either UDP or TCP)
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                q = pkt[DNSQR]
                try:
                    qname = q.qname.decode(errors="ignore").rstrip(".")
                except Exception:
                    qname = str(q.qname)
                event.update({
                    "dns_qname": qname,
                    "dns_qtype": int(getattr(q, "qtype", 0)) if hasattr(q, "qtype") else None
                })
            callback(event)
        except Exception as e:
            # swallow parse issues, but you could log
            pass

    sniff(iface=interface, prn=_handle, store=0, filter=bpf_filter)
