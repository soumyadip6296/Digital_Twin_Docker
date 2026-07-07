import streamlit as st
import requests
import time
import os
import pandas as pd

st.set_page_config(page_title="Digital Twin AI Defense", page_icon="🛡️", layout="wide")
st.title("🛡️ Digital Twin SDN: Autonomous AI Defense")

# Use environment variable for API URL, default to Docker Compose service name
API_URI = os.getenv("API_URI", "http://core_api:8000/api/state")

if "last_update" not in st.session_state:
    st.session_state.last_update = time.time()

def fetch_network_state():
    try:
        response = requests.get(API_URI, timeout=2.0)
        if response.status_code == 200:
            return response.json()
        return None
    except requests.exceptions.RequestException:
        return None

# Fetch state
state = fetch_network_state()

if not state:
    st.warning("⚠️ Waiting for connection to AI Brain... Make sure core_api is running.")
    st.info(f"Attempting to connect to: {API_URI}")
    time.sleep(1)
else:
    metrics = state.get("metrics", {})
    conf = metrics.get("confidence", 0.0)

    st.subheader("Live Telemetry & AI Status")
    col1, col2, col3, col4 = st.columns(4)

    conf_color = "🔴 DANGER" if conf > 0.35 else ("🟡 WARNING" if conf > 0.15 else "🟢 SECURE")

    col1.metric("AI Attack Confidence", f"{conf * 100:.1f}%", conf_color)
    col2.metric("Queue Latency (s)", f"{metrics.get('latency', 0.0):.4f}")
    col3.metric("Throughput (Bytes)", f"{metrics.get('throughput', 0)}")
    col4.metric("Active Nodes", len(state.get("topology", {})))

    blocked = state.get("blocked_ips", [])
    if blocked:
        st.error(f"🚨 **ACTIVE MITIGATION:** The AI has severed connection to the following attackers: {', '.join(blocked)}")
    else:
        st.success("✅ Network is stable. No active mitigations.")

    st.markdown("---")

    st.subheader("🗺️ Auto-Discovered Network Map")
    topology = state.get("topology", {})

    # --- THE ANNOTATION DICTIONARY ---
    KNOWN_NODES = {
        "172.20.0.10": "🌐 WAN Router",
        "172.20.0.50": "💀 External Attacker",
        "10.199.2.10": "🔀 LAN 1 Gateway",
        "10.199.2.20": "🔌 LAN Switch 1",
        "10.199.2.100": "🖥️ Web Server 1 (Nginx)",
        "10.199.3.10": "🔀 LAN 2 Gateway",
        "10.199.3.20": "🔌 LAN Switch 2",
        "10.199.3.100": "🖥️ Web Server 2 (Python)"
    }

    if topology:
        topo_data = []
        for ip, data in topology.items():
            # Automatically annotate the role based on the dictionary
            node_role = KNOWN_NODES.get(ip, "❓ Unknown Node")
            
            topo_data.append({
                "Device Role": node_role,
                "Node IP Address": ip,
                "Hardware MAC Address": data.get("mac", "Unknown"),
                "Last Seen (Monotonic)": round(data.get("last_seen", 0), 2)
            })
        
        # Upgraded to an interactive dataframe instead of a static table
        df = pd.DataFrame(topo_data)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("📡 Scanning network... Waiting for traffic to discover nodes.")

# Manual refresh button
col_refresh = st.columns([1, 10])
with col_refresh[0]:
    if st.button("🔄 Refresh"):
        st.rerun()

st.caption("Auto-refreshes every 2 seconds. Press Refresh to update immediately.")