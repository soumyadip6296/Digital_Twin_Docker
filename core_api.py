import os
import json
import asyncio
import numpy as np
import torch
import torch.nn as nn
import joblib
from collections import deque
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from stable_baselines3 import PPO

# --- IMPORTING YOUR MODULAR ACTUATOR ---
from openflow_actuator import switch_route

# =============================================================================
# 1. MODEL ARCHITECTURES (Unchanged)
# =============================================================================
class RobustLSTMAutoencoder(nn.Module):
    def __init__(self, input_dim=40, hidden_dim=64):
        super().__init__()
        self.encoder = nn.LSTM(input_dim, hidden_dim, num_layers=2, batch_first=True, dropout=0.2)
        self.decoder_lstm = nn.LSTM(hidden_dim, hidden_dim, num_layers=2, batch_first=True, dropout=0.2)
        self.output_layer = nn.Linear(hidden_dim, input_dim)

    def forward(self, x):
        _, (hidden, _) = self.encoder(x)
        hidden_repeated = hidden[-1].repeat(x.size(1), 1, 1).permute(1, 0, 2)
        decoded, _ = self.decoder_lstm(hidden_repeated)
        return self.output_layer(decoded)

class RobustTrafficForecaster(nn.Module):
    def __init__(self, input_dim=1, hidden_dim=64, num_layers=2):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, dropout=0.2)
        self.linear = nn.Linear(hidden_dim, 1)

    def forward(self, x):
        out, _ = self.lstm(x)
        return self.linear(out[:, -1, :])

# =============================================================================
# 2. APP & MODEL LOADING
# =============================================================================
app = FastAPI(title="Digital Twin API (Topology & UI Enabled)")
device = torch.device("cpu")
MDL = "models"

print("🧠 Booting AI Architecture...")
try:
    obs_scaler = joblib.load(f"{MDL}/observer_scaler.pkl")
    prophet_scaler = joblib.load(f"{MDL}/prophet_scaler.pkl")
    analyst_scaler = joblib.load(f"{MDL}/analyst_scaler.pkl")
    analyst_model = joblib.load(f"{MDL}/analyst_model.pkl")

    with open(f"{MDL}/analyst_cluster_map.json", "r") as _f:
        cluster_map = json.loads(_f.read())

    raw_threshold = joblib.load(f"{MDL}/observer_threshold.pkl")
    obs_threshold = float(np.percentile(raw_threshold, 95) if hasattr(raw_threshold, "__len__") else raw_threshold)

    observer = RobustLSTMAutoencoder().to(device)
    observer.load_state_dict(torch.load(f"{MDL}/observer_model.pth", map_location=device))
    observer.eval()

    prophet = RobustTrafficForecaster().to(device)
    prophet.load_state_dict(torch.load(f"{MDL}/prophet_model.pth", map_location=device))
    prophet.eval()

    manager = PPO.load(f"{MDL}/manager_model.zip", device="cpu")
    print("✅ All 4 AI Tiers Loaded Successfully!")
except Exception as e:
    raise RuntimeError(f"❌ Model load failed: {e}")

# =============================================================================
# 3. MASTER STATE & UI BROADCASTER
# =============================================================================
MASTER_STATE = {
    "topology": {},
    "metrics": {"confidence": 0.0, "latency": 0.0, "throughput": 0},
    "blocked_ips": []
}

ui_clients = set()

@app.websocket("/ws/ui_stream")
async def ui_endpoint(websocket: WebSocket):
    await websocket.accept()
    ui_clients.add(websocket)
    print("🖥️  UI Dashboard Connected!")
    try:
        # Send initial state immediately
        await websocket.send_json(MASTER_STATE)
        while True:
            await websocket.receive_text() # Keep connection alive
    except WebSocketDisconnect:
        ui_clients.remove(websocket)
        print("🖥️  UI Dashboard Disconnected.")

# =============================================================================
# 4. LIVE TELEMETRY ENDPOINT
# =============================================================================
@app.websocket("/ws/network_state")
async def live_network_endpoint(websocket: WebSocket):
    await websocket.accept()
    print("🔌 Live Sniffer connected. Awaiting traffic...")

    seq_buf = deque(maxlen=10)
    vol_buf = deque([0.0]*60, maxlen=60)
    conf_buf = deque(maxlen=5)
    adaptive_baseline = {"ema": obs_threshold * 0.5, "n": 0, "last_cluster": 0, "cluster_stable_count": 0}
    blocked_ips = set()
    last_action = 0

    try:
        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)
            
            src_ip = payload.get("src_ip", "0.0.0.0")
            
            # --- UPDATE TOPOLOGY STATE ---
            if "topology_nodes" in payload:
                MASTER_STATE["topology"].update(payload["topology_nodes"])

            legacy_input = np.zeros((1, 40), dtype=np.float32)
            
            q_latency = payload.get("queue_latency", 0.0)
            q_volume = payload.get("queue_volume", 0.0)
            throughput = payload.get("throughput", 0)
            
            legacy_input[0, 0] = q_latency                           
            legacy_input[0, 1] = q_volume                            
            legacy_input[0, 5] = payload.get("max_packet_length", 0) 
            legacy_input[0, 6] = payload.get("min_packet_length", 0) 
            legacy_input[0, 13] = throughput      
            legacy_input[0, 30] = payload.get("fin_count", 0)        
            legacy_input[0, 31] = payload.get("syn_count", 0)        
            legacy_input[0, 32] = payload.get("rst_count", 0)        
            legacy_input[0, 33] = payload.get("psh_count", 0)        
            legacy_input[0, 34] = payload.get("ack_count", 0)        
            legacy_input[0, 35] = payload.get("urg_count", 0)        
            legacy_input[0, 37] = payload.get("avg_packet_size", 0)  

            scaled_feat = obs_scaler.transform(legacy_input)[0]
            vol_clean = float(np.nan_to_num(np.log1p(q_volume), nan=0.0, posinf=0.0, neginf=0.0))
            vol_scaled = float(prophet_scaler.transform([[vol_clean]])[0][0])
            
            seq_buf.append(scaled_feat)
            vol_buf.append(vol_scaled)

            if len(seq_buf) < 10:
                continue

            # --- INFERENCE ---
            in_seq = torch.tensor(np.array([list(seq_buf)]), dtype=torch.float32).to(device)
            v_seq = torch.tensor(np.array([list(vol_buf)]), dtype=torch.float32).unsqueeze(-1).to(device)

            with torch.no_grad():
                reconstruction = observer(in_seq)
                mae = torch.abs(reconstruction - in_seq).mean().item()
                forecast_raw = prophet(v_seq).item()
                forecast_deviation = abs(forecast_raw - vol_scaled)
                an_in = analyst_scaler.transform(legacy_input)
                cluster_id = int(analyst_model.predict(an_in)[0])
                traffic_type = 1.0 if cluster_map.get(str(cluster_id), "") == "Video/Heavy" else 0.0

            # --- CONFIDENCE MATRICES ---
            ema = adaptive_baseline["ema"]
            if mae < obs_threshold:
                ema = 0.02 * mae + 0.98 * ema
                adaptive_baseline["ema"] = ema
            current_thresh = max(obs_threshold * 0.5, min(obs_threshold * 1.5, ema * 4.0))

            sig_mae = min(mae / (current_thresh + 1e-9), 1.0)
            sig_fcst = min(forecast_deviation / (obs_threshold * 5 + 1e-9), 1.0)
            sig_lat = min(max((q_latency - 0.02) / 0.08, 0), 1.0)
            
            base_conf = (0.45 * sig_mae) + (0.25 * sig_fcst) + (0.30 * sig_lat)
            conf_buf.append(base_conf)
            sustained_confidence = float(np.mean(conf_buf))

            state = np.array([[q_latency, 0.05, mae, base_conf, traffic_type, float(last_action)]], dtype=np.float32)

            action, _ = manager.predict(state, deterministic=True)
            last_action = int(action[0])

            # --- UPDATE MASTER UI STATE ---
            MASTER_STATE["metrics"] = {
                "confidence": round(sustained_confidence, 3),
                "latency": round(q_latency, 4),
                "throughput": throughput
            }
            MASTER_STATE["blocked_ips"] = list(blocked_ips)

            # Broadcast to UI
            dead_clients = set()
            for client in ui_clients:
                try:
                    await client.send_json(MASTER_STATE)
                except:
                    dead_clients.add(client)
            ui_clients.difference_update(dead_clients)

            # --- ACTUATION ---
            if last_action == 1 and src_ip not in blocked_ips and src_ip != "10.199.1.20":
                if sustained_confidence > 0.35 or (sig_lat > 0.5 and max(conf_buf) > 0.28):
                    blocked_ips.add(src_ip)
                    MASTER_STATE["blocked_ips"] = list(blocked_ips)
                    
                    # --- CALLING YOUR openflow_actuator.py HERE ---
                    asyncio.create_task(asyncio.to_thread(switch_route, 1, src_ip))
                    
                    await websocket.send_json({"status": "blocked", "ip": src_ip})
            # 🟢 OPTIONAL: Automatic Healing / Unblocking
            elif last_action == 0 and src_ip in blocked_ips:
                blocked_ips.remove(src_ip)
                MASTER_STATE["blocked_ips"] = list(blocked_ips)
                # Call switch_route with 0 to clear the drop rule
                asyncio.create_task(asyncio.to_thread(switch_route, 0, src_ip))
                print(f"🟢 [AI HEAL] Traffic normalized. Restoring flow for {src_ip}")                    

    except WebSocketDisconnect:
        print("❌ Live Sniffer Disconnected.")
    except Exception as e:
        print(f"⚠️ Pipeline Error: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)