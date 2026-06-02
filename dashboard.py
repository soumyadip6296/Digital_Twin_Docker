import streamlit as st
import asyncio
import websockets
import json
import time
import pandas as pd

# --- Page Config ---
st.set_page_config(page_title="Digital Twin AI Defense", page_icon="🛡️", layout="wide")
st.title("🛡️ Digital Twin SDN: Autonomous AI Defense")

API_URI = "ws://host.docker.internal:8000/ws/ui_stream"

# --- Stateless WebSocket Fetcher ---
async def fetch_network_state():
    try:
        async with websockets.connect(API_URI, close_timeout=1) as ws:
            state = await asyncio.wait_for(ws.recv(), timeout=2.0)
            return json.loads(state)
    except Exception as e:
        return None

# Fetch the live data
state = asyncio.run(fetch_network_state())

if not state:
    st.warning("⚠️ Waiting for connection to AI Brain... Make sure core_api.py is running.")
    time.sleep(2)
    st.rerun()

# --- 1. Top Metrics Row ---
metrics = state.get("metrics", {})
conf = metrics.get("confidence", 0.0)

st.subheader("Live Telemetry & AI Status")
col1, col2, col3, col4 = st.columns(4)

conf_color = "🔴 DANGER" if conf > 0.35 else ("🟡 WARNING" if conf > 0.15 else "🟢 SECURE")

col1.metric("AI Attack Confidence", f"{conf * 100:.1f}%", conf_color)
col2.metric("Queue Latency (s)", f"{metrics.get('latency', 0.0):.4f}")
col3.metric("Throughput (Bytes)", f"{metrics.get('throughput', 0)}")
col4.metric("Active Nodes", len(state.get("topology", {})))

# --- 2. Active Mitigations ---
blocked = state.get("blocked_ips", [])
if blocked:
    st.error(f"🚨 **ACTIVE MITIGATION:** The AI has severed connection to the following attackers: {', '.join(blocked)}")
else:
    st.success("✅ Network is stable. No active mitigations.")

st.markdown("---")

# --- 3. Auto-Discovered Network Topology ---
st.subheader("🗺️ Auto-Discovered Network Map")
topology = state.get("topology", {})

if topology:
    topo_data = []
    for ip, data in topology.items():
        topo_data.append({
            "Node IP Address": ip,
            "Hardware MAC Address": data.get("mac", "Unknown"),
            "Last Seen (Monotonic)": round(data.get("last_seen", 0), 2)
        })
    df = pd.DataFrame(topo_data)
    st.table(df)
else:
    st.info("📡 Scanning network... Waiting for ARP broadcasts to discover nodes.")

# Auto-Refresh Loop
time.sleep(1)
st.rerun()