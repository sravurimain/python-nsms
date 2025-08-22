import time, math, collections

def shannon_entropy(s: str):
    if not s:
        return 0.0
    freq = collections.Counter(s)
    total = len(s)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())

class PortScanDetector:
    def __init__(self, cfg, emit):
        self.enabled = cfg.get("enabled", True)
        self.window = cfg.get("window_seconds", 20)
        self.syn_only = cfg.get("syn_only", True)
        self.unique_dports_threshold = cfg.get("unique_dports_threshold", 30)
        self.min_total_syn = cfg.get("min_total_syn", 50)
        self.history = collections.deque()  # (ts, src, dst, dport, syn)
        self.per_src_ports = collections.defaultdict(set)
        self.per_src_syn_count = collections.Counter()
        self.emit = emit

    def _evict_old(self, now):
        cutoff = now - self.window
        while self.history and self.history[0][0] < cutoff:
            _, src, _, dport, syn = self.history.popleft()
            if dport in self.per_src_ports[src]:
                # Rebuild set occasionally is fine; minimal precision loss acceptable
                pass
            # Full rebuild of sets would be costly; we'll lazy-recompute when checking

    def _recompute_sets(self):
        self.per_src_ports.clear()
        self.per_src_syn_count.clear()
        for ts, src, dst, dport, syn in self.history:
            self.per_src_ports[src].add(dport)
            if syn:
                self.per_src_syn_count[src] += 1

    def process(self, ev):
        if not self.enabled:
            return
        if ev.get("l4") != "tcp":
            return
        is_syn = bool(ev.get("syn", False))
        if self.syn_only and not is_syn:
            return

        now = ev.get("ts", time.time())
        src, dst, dport = ev.get("src"), ev.get("dst"), ev.get("dport")
        if not (src and dst and dport):
            return

        self.history.append((now, src, dst, dport, is_syn))
        self._evict_old(now)
        # Cheap lazy recompute once per N events could be added; for simplicity do each time
        self._recompute_sets()

        uniq = len(self.per_src_ports[src])
        total_syn = self.per_src_syn_count[src]
        if uniq >= self.unique_dports_threshold and total_syn >= self.min_total_syn:
            self.emit({
                "kind": "port_scan",
                "severity": "high",
                "msg": f"Possible TCP SYN port scan from {src} (unique dports={uniq}, syns={total_syn} in {self.window}s)",
                "src": src,
                "metrics": {"unique_dports": uniq, "total_syn": total_syn, "window": self.window},
                "time": now
            })
            # Reset counts for src to avoid spamming
            self.per_src_ports[src].clear()
            self.per_src_syn_count[src] = 0


class DNSTunnelDetector:
    def __init__(self, cfg, emit):
        self.enabled = cfg.get("enabled", True)
        self.window = cfg.get("window_seconds", 60)
        self.min_queries_per_src = cfg.get("min_queries_per_src", 40)
        self.min_entropy = cfg.get("min_entropy", 3.8)
        self.min_qname_len = cfg.get("min_qname_len", 45)
        self.heavy_txt_threshold = cfg.get("heavy_txt_threshold", 10)

        self.history = collections.deque() # (ts, src, qname, qtype, entropy, qlen)
        self.per_src_counts = collections.Counter()
        self.per_src_txt = collections.Counter()
        self.emit = emit

    def _evict_old(self, now):
        cutoff = now - self.window
        while self.history and self.history[0][0] < cutoff:
            ts, src, qn, qt, ent, ql = self.history.popleft()
            self.per_src_counts[src] -= 1
            if qt == 16:  # TXT
                self.per_src_txt[src] -= 1
            if self.per_src_counts[src] <= 0:
                self.per_src_counts.pop(src, None)
            if self.per_src_txt[src] <= 0:
                self.per_src_txt.pop(src, None)

    def process(self, ev):
        if not self.enabled:
            return
        if ev.get("dns_qname") is None:
            return
        now = ev.get("ts", time.time())
        src = ev.get("src")
        qname = ev.get("dns_qname") or ""
        qtype = int(ev.get("dns_qtype") or 0)
        ent = shannon_entropy(qname)
        qlen = len(qname)

        self.history.append((now, src, qname, qtype, ent, qlen))
        self.per_src_counts[src] += 1
        if qtype == 16:
            self.per_src_txt[src] += 1
        self._evict_old(now)

        vol = self.per_src_counts[src]
        txt = self.per_src_txt[src]
        if vol >= self.min_queries_per_src and ent >= self.min_entropy and qlen >= self.min_qname_len:
            self.emit({
                "kind": "dns_tunnel",
                "severity": "medium",
                "msg": f"Suspicious DNS from {src} (QPS={vol}/{self.window}s, ent~{ent:.2f}, len={qlen}, TXT={txt})",
                "src": src,
                "metrics": {"qps_window": self.window, "q_count": vol, "entropy": ent, "qname_len": qlen, "txt_count": txt},
                "qname_sample": qname,
                "time": now
            })
        elif txt >= self.heavy_txt_threshold:
            self.emit({
                "kind": "dns_tunnel",
                "severity": "low",
                "msg": f"Heavy DNS TXT queries from {src} (TXT={txt} in {self.window}s)",
                "src": src,
                "metrics": {"txt_count": txt, "window": self.window},
                "time": now
            })
