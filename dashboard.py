import streamlit as st
import asyncio
import websockets
import json
import time
import pandas as pd

# --- Page Config ---
st.set_page_config(
    page_title="Digital Twin AI Defense", 
    page_icon="🛡️", 
    layout="wide"
)

st.title("🛡️ Digital Twin SDN: Autonomous AI Defense")

# Ensure this matches the URI in your core_api.py
API_URI = "ws://host.docker.internal:8000/ws/ui_stream"

# --- WebSocket Fetcher ---
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

# Dynamic color logic for threat level
conf_color = "🔴 DANGER" if conf > 0.35 else ("🟡 WARNING" if conf > 0.15 else "🟢 SECURE")

col1.metric("AI Attack Confidence", f"{conf * 100:.1f}%", conf_color)
col2.metric("Queue Latency (s)", f"{metrics.get('latency', 0.0):.4f}")
col3.metric("Throughput (Bytes)", f"{metrics.get('throughput', 0)}")
col4.metric("Active Nodes", len(state.get("topology", {})))

# --- 2. Active Mitigations ---
blocked = state.get("blocked_ips", [])
if blocked:
    st.error(f"🚨 **ACTIVE MITIGATION:** AI has blocked access for: {', '.join(blocked)}")
else:
    st.success("✅ Network is stable. No active mitigations.")

st.markdown("---")

# --- 3. Auto-Discovered Network Map ---
st.subheader("🗺️ Active Network Nodes")
topology = state.get("topology", {})

if topology:
    topo_data = []
    for ip, data in topology.items():
        # Calculate time since last activity
        last_seen = data.get("last_seen", time.monotonic())
        time_ago = round(time.monotonic() - last_seen, 1)
        
        topo_data.append({
            "Node IP Address": ip,
            "Last Activity (s)": time_ago
        })
    
    df = pd.DataFrame(topo_data)
    # Display table without index for cleaner look
    st.table(df.set_index("Node IP Address"))
else:
    st.info("📡 Scanning network traffic... Waiting for packets to identify active nodes.")

# Auto-Refresh Loop
time.sleep(1)
st.rerun()