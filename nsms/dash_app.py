import streamlit as st
import json, time, os
from collections import Counter, defaultdict
from datetime import datetime

st.set_page_config(page_title="NSMS Alerts", layout="wide")

ALERTS_PATH = "data/alerts.jsonl"

st.title("NSMS — Alerts Dashboard")

placeholder = st.empty()

def load_alerts():
    items = []
    if not os.path.exists(ALERTS_PATH):
        return items
    with open(ALERTS_PATH, "r", encoding="utf-8") as f:
        for line in f:
            try:
                items.append(json.loads(line))
            except:
                pass
    return items

def summarize(alerts):
    by_kind = Counter(a.get("kind","unknown") for a in alerts)
    by_sev = Counter(a.get("severity","info") for a in alerts)
    latest = sorted(alerts, key=lambda a: a.get("ts",0), reverse=True)[:50]
    return by_kind, by_sev, latest

refresh = st.sidebar.slider("Auto-refresh (seconds)", 0, 10, 3)

while True:
    alerts = load_alerts()
    by_kind, by_sev, latest = summarize(alerts)

    with placeholder.container():
        col1, col2, col3 = st.columns(3)
        col1.metric("Total alerts", len(alerts))
        col2.metric("Kinds", len(by_kind))
        col3.metric("Severities", len(by_sev))

        st.subheader("By Kind")
        st.write({k:int(v) for k,v in by_kind.items()})

        st.subheader("By Severity")
        st.write({k.upper():int(v) for k,v in by_sev.items()})

        st.subheader("Latest 50 alerts")
        for a in latest:
            ts = datetime.fromtimestamp(a.get("ts",0)).strftime("%Y-%m-%d %H:%M:%S")
            st.write(f"**[{a.get('severity','info').upper()}] {a.get('kind','event')}** — {a.get('msg','')}")
            st.caption(f"{ts} • src={a.get('src','?')}")

    if refresh <= 0:
        break
    time.sleep(refresh)
