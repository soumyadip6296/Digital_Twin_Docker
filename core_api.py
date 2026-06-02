"""
core_api.py  —  Digital Twin SDN — AI Inference Engine
=======================================================
Improvements over previous version
------------------------------------
1. FIXED  Inference throttle was a no-op — heavy block now correctly gated
2. FIXED  seq_buffer / vol_buffer used O(n) list.pop(0) → deque(maxlen=N)
3. NEW    Observer uses MAE + error trend
4. NEW    Prophet computes forecast DEVIATION vs actual, not just raw output
5. NEW    Analyst tracks cluster transitions — sudden shift = anomaly signal
6. NEW    Unified attack_confidence score [0..1] combining all 4 AI signals
7. NEW    Temporal consistency gate — sustained confidence > 0.5 required
8. NEW    Adaptive baseline threshold — EMA of recent benign errors
9. NEW    Richer RL state vector (6-dim)
10. NEW   NormalRouter gains packet-RATE z-score for PortScan / sweep detection
11. KEPT  Tornado WebSocketClosedError catch
12. KEPT  Broadcast throttle (every 5th packet)
"""

import asyncio
import os
try:
    from openflow_actuator import switch_route
    ACTUATOR_AVAILABLE = True
except ImportError:
    ACTUATOR_AVAILABLE = False

import json
import numpy as np
import torch
import torch.nn as nn
import joblib
from collections import deque
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

import logging
import time
from stable_baselines3 import PPO

from telemetry_logger import log_transition

try:
    from tornado.websocket import WebSocketClosedError as _TornadoWSClosed
except ImportError:
    _TornadoWSClosed = ConnectionResetError


# =============================================================================
# 1.  MODEL ARCHITECTURES  (unchanged — must match saved weights)
# =============================================================================

class RobustLSTMAutoencoder(nn.Module):
    def __init__(self, input_dim=40, hidden_dim=64):
        super().__init__()
        self.encoder      = nn.LSTM(input_dim, hidden_dim, num_layers=2,
                                    batch_first=True, dropout=0.2)
        self.decoder_lstm = nn.LSTM(hidden_dim, hidden_dim, num_layers=2,
                                    batch_first=True, dropout=0.2)
        self.output_layer = nn.Linear(hidden_dim, input_dim)

    def forward(self, x):
        _, (hidden, _)    = self.encoder(x)
        hidden_repeated   = hidden[-1].repeat(x.size(1), 1, 1).permute(1, 0, 2)
        decoded, _        = self.decoder_lstm(hidden_repeated)
        return self.output_layer(decoded)


class RobustTrafficForecaster(nn.Module):
    def __init__(self, input_dim=1, hidden_dim=64, num_layers=2):
        super().__init__()
        self.lstm   = nn.LSTM(input_dim, hidden_dim, num_layers,
                              batch_first=True, dropout=0.2)
        self.linear = nn.Linear(hidden_dim, 1)

    def forward(self, x):
        out, _ = self.lstm(x)
        return self.linear(out[:, -1, :])


# =============================================================================
# 2.  ENHANCED NORMAL ROUTER
#     Three independent detectors:
#       A) Rolling-average latency threshold (catches congestion / DoS)
#       B) Volume z-score spike       (catches large-packet floods)
#       C) Packet-RATE z-score        (catches PortScan / sweep — many tiny pkts)
#     Hysteresis on both alert→clear transitions to avoid flapping.
# =============================================================================

class NormalRouter:
    LATENCY_THRESHOLD    = 0.08    # s — rolling avg above this → alert
    VOLUME_ZSCORE_THRESH = 2.5     # std-devs above rolling mean → flood flag
    RATE_ZSCORE_THRESH   = 3.0     # std-devs above rolling pkt-rate → scan flag
    WINDOW               = 30      # rolling window (packets)
    CLEAR_HYSTERESIS     = 0.6     # fraction of threshold required to clear alert

    def __init__(self):
        self._lat_window  = deque(maxlen=self.WINDOW)
        self._vol_window  = deque(maxlen=self.WINDOW)
        self._rate_window = deque(maxlen=self.WINDOW)
        self._last_action = 0
        self._pkt_times   = deque(maxlen=self.WINDOW + 1)   # for rate calculation

    def decide(self, lat_a: float, lat_b: float, volume: float,
               timestamp: float = None) -> dict:
        import time as _time
        now = timestamp if timestamp is not None else _time.monotonic()

        self._lat_window.append(lat_a)
        self._vol_window.append(volume)
        self._pkt_times.append(now)

        # ── A) Latency alert ────────────────────────────────────────────────
        avg_lat   = float(np.mean(self._lat_window))
        lat_alert = avg_lat > self.LATENCY_THRESHOLD

        # ── B) Volume z-score ───────────────────────────────────────────────
        vol_z = 0.0
        if len(self._vol_window) >= 5:
            vol_mean = float(np.mean(self._vol_window))
            vol_std  = float(np.std(self._vol_window))  or 1.0
            vol_z    = (volume - vol_mean) / vol_std
        vol_alert = vol_z > self.VOLUME_ZSCORE_THRESH

        # ── C) Packet-rate z-score (catches PortScan / slowloris) ──────────
        pkt_rate = 0.0
        rate_z   = 0.0
        if len(self._pkt_times) >= 3:
            elapsed  = max(self._pkt_times[-1] - self._pkt_times[0], 1e-6)
            pkt_rate = (len(self._pkt_times) - 1) / elapsed
            self._rate_window.append(pkt_rate)
        if len(self._rate_window) >= 5:
            r_mean  = float(np.mean(self._rate_window))
            r_std   = float(np.std(self._rate_window)) or 1.0
            rate_z  = (pkt_rate - r_mean) / r_std
        rate_alert = rate_z > self.RATE_ZSCORE_THRESH

        is_attack = lat_alert or vol_alert or rate_alert

        # ── Routing with hysteresis ─────────────────────────────────────────
        if is_attack:
            action = 1
        elif (avg_lat < self.LATENCY_THRESHOLD * self.CLEAR_HYSTERESIS
              and vol_z  < self.VOLUME_ZSCORE_THRESH  * self.CLEAR_HYSTERESIS
              and rate_z < self.RATE_ZSCORE_THRESH    * self.CLEAR_HYSTERESIS):
            action = 0
        else:
            action = self._last_action   # stay put until clearly safe

        self._last_action = action
        return {
            "route":      action,
            "is_attack":  is_attack,
            "lat_score":  round(avg_lat, 5),
            "vol_zscore": round(vol_z,   3),
            "rate_zscore":round(rate_z,  3),
        }


# =============================================================================
# 3.  APP + MODEL LOADING
# =============================================================================

app    = FastAPI(title="Digital Twin API")
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"⚡ Hardware Accelerator in use: {device.type.upper()}")
print("🧠 Loading AI Brains & Configs...")
MDL = "models"

try:
    obs_scaler     = joblib.load(f"{MDL}/observer_scaler.pkl")
    prophet_scaler = joblib.load(f"{MDL}/prophet_scaler.pkl")
    analyst_scaler = joblib.load(f"{MDL}/analyst_scaler.pkl")
    analyst_model  = joblib.load(f"{MDL}/analyst_model.pkl")

    with open(f"{MDL}/analyst_cluster_map.json", "r") as _f:
        cluster_map = _f.read()
    cluster_map = json.loads(cluster_map)

    raw_threshold = joblib.load(f"{MDL}/observer_threshold.pkl")
    obs_threshold = float(
        np.percentile(raw_threshold, 95)
        if hasattr(raw_threshold, "__len__") else raw_threshold
    )
    print(f"   Observer anomaly threshold (95th pct): {obs_threshold:.6f}")

    observer = RobustLSTMAutoencoder().to(device)
    observer.load_state_dict(
        torch.load(f"{MDL}/observer_model.pth", map_location=device))
    observer.eval()

    prophet = RobustTrafficForecaster().to(device)
    prophet.load_state_dict(
        torch.load(f"{MDL}/prophet_model.pth", map_location=device))
    prophet.eval()

    import gymnasium as gym
    from gymnasium import spaces

    class DummyEnv(gym.Env):
        def __init__(self):
            super().__init__()
            self.observation_space = spaces.Box(low=-np.inf, high=np.inf, shape=(6,), dtype=np.float32)
            self.action_space = spaces.Discrete(2)
        def step(self, action):
            return np.zeros(6, dtype=np.float32), 0.0, False, False, {}
        def reset(self, seed=None, options=None):
            return np.zeros(6, dtype=np.float32), {}

    env = DummyEnv()

    try:
        model_path = f"{MDL}/manager_model.zip"
        manager = PPO.load(model_path, device="cpu")
        last_model_update = os.path.getmtime(model_path)
        print("✅ Pre-trained Manager Model loaded successfully.")
    except Exception as e:
        print(f"⚠️ Model load failed (Corrupted or Missing): {e}")
        print("⚠️ Initializing a fresh, untrained fallback model to keep the API online...")
        # Note: Ensure env is properly defined before this step, or pass the correct observation space
        manager = PPO("MlpPolicy", env, verbose=0, device="cpu")
        last_model_update = time.time()

    print("✅ All Systems Online.")

except FileNotFoundError as e:
    raise RuntimeError(
        f"❌ Model file missing: {e}\n"
        "Please run your training scripts before starting the API."
    ) from e

# Total number of clusters available (for normalised cluster-id feature)
N_CLUSTERS = max(1, len(cluster_map))


# =============================================================================
# 4.  AI INFERENCE HELPER
#     Encapsulates ALL four AI brains into one callable that returns a rich
#     result dict.  Both /ws/network and /ws/compare call this so the logic
#     is never duplicated.
# =============================================================================

def _ai_inference(
    features:    np.ndarray,   # shape (1, 40)  — already nan_to_num'd
    raw_vol:     float,
    lat_a:       float,
    lat_b:       float,
    seq_buf:     deque,        # deque(maxlen=10) of scaled feature vectors
    vol_buf:     deque,        # deque(maxlen=60) of scaled volume scalars
    err_buf:     deque,        # deque(maxlen=10) of recent MAE errors
    conf_buf:    deque,        # deque(maxlen=5)  of recent confidence scores
    last_action: int,
    adaptive_baseline: dict,   # mutable dict: {"ema": float, "n": int}
) -> dict:
    """
    Run full AI pipeline and return a comprehensive result dict.
    Assumes seq_buf already has the current packet appended.
    Returns lightweight defaults if seq_buf not yet full.
    """
    if len(seq_buf) < 10:
        return dict(
            route=0, is_attack=False, attack_confidence=0.0,
            error=0.0, error_delta=0.0, forecast_deviation=0.0,
            cluster_id=0, cluster_transition=False, traffic_type=0.0,
            forecast_raw=0.0,forecast_valid=True,
        )

    # ── Prepare tensors ──────────────────────────────────────────────────────
    in_seq = torch.tensor(
        np.array([list(seq_buf)]), dtype=torch.float32).to(device)
    v_seq  = torch.tensor(
        np.array([list(vol_buf)]), dtype=torch.float32
    ).unsqueeze(-1).to(device)

    with torch.no_grad():
        # ── Observer: reconstruction error (MAE, MSE, max-feature, trend) ──
        reconstruction = observer(in_seq)              # (1, 10, 40)
        abs_err        = torch.abs(reconstruction - in_seq)
        mae            = abs_err.mean().item()



        # Error trend: how fast is error rising?
        err_buf.append(mae)
        if len(err_buf) >= 3:
            error_delta = float(np.polyfit(range(len(err_buf)),
                                           list(err_buf), 1)[0])
        else:
            error_delta = 0.0

        # ── Prophet: forecast vs actual deviation ───────────────────────────
        forecast_raw = prophet(v_seq).item()         # raw scaled volume
        # inverse-transform to get actual volume units
        forecast_valid = True
        actual_vol_scaled = vol_buf[-1]
        forecast_deviation = abs(forecast_raw - actual_vol_scaled)

        # ── Analyst: cluster ID + transition detection ───────────────────────
        an_in      = analyst_scaler.transform(features)
        cluster_id = int(analyst_model.predict(an_in)[0])

        # Traffic type from cluster map
        cluster_label = cluster_map.get(str(cluster_id), "Unknown")
        traffic_type  = 1.0 if cluster_label == "Video/Heavy" else 0.0

        # Cluster transition: debounced to suppress noisy cluster models.
        # Observed rate without debounce: >50% of packets flagged as transitions
        # on all-benign data, artificially inflating attack_confidence by ~5%.
        # Fix: require the previous cluster to be stable for >= 5 consecutive
        # inference calls before declaring a real transition.
        CLUSTER_DEBOUNCE   = 5
        prev_cluster       = adaptive_baseline.get("last_cluster", cluster_id)
        prev_stable_count  = adaptive_baseline.get("cluster_stable_count", 0)

        if cluster_id == prev_cluster:
            stable_count       = min(prev_stable_count + 1, CLUSTER_DEBOUNCE + 1)
            cluster_transition = False
        else:
            cluster_transition = (prev_stable_count >= CLUSTER_DEBOUNCE)
            stable_count       = 1   # reset — new cluster epoch begins

        adaptive_baseline["last_cluster"]        = cluster_id
        adaptive_baseline["cluster_stable_count"] = stable_count

    # ── Adaptive threshold (EMA of recent benign errors) ────────────────────
    # Only update baseline when we're fairly confident there's no attack
    ema   = adaptive_baseline.get("ema",  obs_threshold * 0.5)
    n     = adaptive_baseline.get("n",    0)
    alpha = 0.02   # slow EMA — adapts over ~50 packets
    if mae < obs_threshold:    # only learn from apparent benign traffic
        ema = alpha * mae + (1 - alpha) * ema
        n  += 1
    adaptive_baseline["ema"] = ema
    adaptive_baseline["n"]   = n
    adaptive_threshold = max(obs_threshold * 0.5,
                             min(obs_threshold * 1.5, ema * 4.0))

    # ── Unified attack confidence [0..1] ─────────────────────────────────────
    # Four independent signals, each normalised then combined with weights
    #   w1 Observer MAE          0.35  (primary anomaly detector)
    #   w2 Observer error trend  0.15  (rising = more suspicious)
    #   w3 Forecast deviation    0.20  (volume behaving unexpectedly)
    #   w4 Latency spike         0.20  (raw latency > normal range)
    #   w5 Cluster transition    0.10  (sudden traffic pattern shift)

    sig_mae    = min(mae    / (adaptive_threshold + 1e-9),       1.0)
    sig_trend  = min(max(error_delta / (adaptive_threshold * 0.1 + 1e-9), 0), 1.0)
    sig_fcst   = min(forecast_deviation / (obs_threshold * 5 + 1e-9), 1.0)
    sig_lat    = min(max((lat_a - 0.02) / 0.08, 0),              1.0)

    # FIX: Compute base confidence WITHOUT cluster signal first.
    # Then only add sig_clust when the other signals are already elevated
    # (base_conf > 0.15). On all-benign Monday data the cluster model was
    # firing on 54% of packets, each adding 0.10 → persistent false
    # '73% confidence + 🔀 pattern shift' banner on normal traffic.
    # Gating it means a random cluster flip in calm traffic contributes 0.
    base_conf  = (
        0.35 * sig_mae   +
        0.15 * sig_trend +
        0.20 * sig_fcst  +
        0.30 * sig_lat       # raised from 0.20 to keep weights summing to 1.0
    )
    sig_clust  = 1.0 if (cluster_transition and base_conf > 0.15) else 0.0

    attack_confidence = base_conf + 0.10 * sig_clust
    attack_confidence = min(attack_confidence, 1.0)   # clamp after bonus

    # ── Temporal consistency — dual-mode gate ───────────────────────────────
    # SUSTAINED mode: mean(conf_buf) > 0.35
    #   Catches multi-packet bursts. Resistant to single-packet noise.
    #
    # SPIKE mode: peak_confidence > 0.28 AND sig_lat > 0.5
    #   Catches isolated attack packets (lat_a=0.95 → sig_lat=1.0).
    #   FIX: The bare 'peak > 0.28' gate was causing 60% FPR on all-benign
    #   Monday data because the LSTM/forecast signals generate base_conf
    #   ~0.20-0.30 on novel benign flows — exactly the same range as a lat-
    #   only attack packet.  No threshold can cleanly separate them.
    #   Solution: anchor the spike gate to sig_lat directly.  The latency
    #   signal is the only one with zero overlap between benign and attack:
    #     Attack: lat_a=0.95s → sig_lat=(0.95-0.02)/0.08=1.0 > 0.5  ✓
    #     Benign: lat_a≈0.01-0.03s → sig_lat=0.0-0.13 < 0.5       ✓
    conf_buf.append(attack_confidence)
    sustained_confidence = float(np.mean(conf_buf))
    peak_confidence      = float(max(conf_buf))
    lat_spike            = sig_lat > 0.5   # lat_a > ~0.06s
    is_attack = (sustained_confidence > 0.35) or (lat_spike and peak_confidence > 0.28)

    # ── RL Manager state (6-dim — must match training observation space) ──────
    # NOTE: The PPO model was trained on exactly 6 features. The richer signals
    # (error_delta, forecast_deviation, attack_confidence, cluster signals) are
    # used above for is_attack detection but cannot be added here without
    # retraining the manager model.
    state = np.array([
        lat_a,             # primary link latency
        lat_b,             # backup link latency
        mae,               # LSTM reconstruction error (best single proxy)
        attack_confidence, # unified confidence score (replaces raw forecast_norm)
        traffic_type,      # 0=normal / 1=heavy (from analyst cluster)
        float(last_action),# routing hysteresis
    ], dtype=np.float32)

    rl_action, _ = manager.predict(state, deterministic=True)
    action = int(rl_action)
    # Calculate a basic reward for continuous learning
    current_volume = raw_vol  # payload "volume" is the canonical traffic-volume signal
    reward = -1.0 if (current_volume > 1500 and action == 0) else 1.0
    # Log asynchronously
    log_transition(state, action, reward)

    return dict(
        route              = action,
        is_attack          = is_attack,
        attack_confidence  = round(attack_confidence,     4),
        error              = round(mae,                   6),
        error_delta        = round(error_delta,           6),
        forecast_deviation = round(forecast_deviation,    4),
        forecast_valid     = forecast_valid,
        cluster_id         = cluster_id,
        cluster_transition = cluster_transition,
        traffic_type       = traffic_type,
        forecast_raw       = round(forecast_raw,          4),
    )


# =============================================================================
# 5.  SHARED PACKET SANITISATION HELPER
# =============================================================================

def _sanitise(payload: dict):
    feat_list = payload.get("features", [])
    raw_features = np.array(feat_list).reshape(1, -1) if feat_list else np.zeros((1, 0))

    features = np.nan_to_num(raw_features, nan=0.0, posinf=0.0, neginf=0.0)
    if features.shape != (1, 40):
        return {"error": "bad_payload", "expected_shape": 40}
    raw_vol      = float(payload.get("volume", 0))
    vol_clean    = float(np.nan_to_num(np.log1p(raw_vol), nan=0.0, posinf=0.0, neginf=0.0))
    scaled_feat  = obs_scaler.transform(features)[0]
    vol_scaled   = float(prophet_scaler.transform([[vol_clean]])[0][0])
    return features, raw_vol, scaled_feat, vol_scaled


# =============================================================================
# 6.  WEBSOCKET ENDPOINTS
# =============================================================================

connected_dashboards: set[WebSocket] = set()
connected_topology_dashboards: set[WebSocket] = set()

# FIX: Only one compare session should be active at a time.  Two simultaneous
# sessions (e.g. two browser tabs, or a Start after Reset before the old thread
# exited) share the same per-endpoint model state buffers which causes corrupted
# metrics.  Track the active session and close the old one before accepting a new.
_active_compare_ws: WebSocket | None = None


global_packets_received = 0
packet_timestamps = deque(maxlen=10000)

@app.get("/health")
def get_health():
    now = time.time()
    recent_packets = sum(1 for ts in packet_timestamps if now - ts <= 10.0)
    pps_10s = recent_packets / 10.0
    active_ws_clients = len(connected_dashboards) + len(connected_topology_dashboards)
    return {
        "device": device.type,
        "packets_received": global_packets_received,
        "pps_10s": pps_10s,
        "active_ws_clients": active_ws_clients,
        "queue_depth": 0,
        "obs_threshold": obs_threshold
    }

@app.websocket("/ws/dashboard")
async def dashboard_endpoint(websocket: WebSocket, client_id: str = None):
    await websocket.accept()
    connected_dashboards.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_dashboards.discard(websocket)
    except json.JSONDecodeError:
        pass
    except Exception:
        logging.error("Unexpected WS error", exc_info=True)
        connected_dashboards.discard(websocket)



@app.websocket("/ws/live_topology")
async def live_topology_endpoint(websocket: WebSocket, client_id: str = None):
    await websocket.accept()
    connected_topology_dashboards.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_topology_dashboards.discard(websocket)
    except json.JSONDecodeError:
        pass
    except Exception:
        logging.error("Unexpected WS error", exc_info=True)
        connected_topology_dashboards.discard(websocket)


# ---------------------------------------------------------------------------
# /ws/network  —  live routing endpoint used by app_architect / network_bridge
# ---------------------------------------------------------------------------
@app.websocket("/ws/network")
async def network_endpoint(websocket: WebSocket):
    await websocket.accept()
    print("🔗 Network Generator Connected!")

    seq_buf  = deque(maxlen=10)
    vol_buf  = deque(maxlen=60)
    err_buf  = deque(maxlen=10)
    conf_buf = deque(maxlen=5)
    adaptive = {}
    last_action = 0
    pkt_count   = 0
    blocked_ips = set()
    # Pre-fill vol_buf so prophet always gets a full sequence
    vol_buf.extend([0.0] * 60)

    try:
        while True:
            data    = await websocket.receive_text()
            payload = json.loads(data)
            pkt_count += 1

            global global_packets_received
            global_packets_received += 1
            packet_timestamps.append(time.time())
            sanitise_result = _sanitise(payload)
            if isinstance(sanitise_result, dict):
                await websocket.send_json(sanitise_result)
                continue
            features, raw_vol, scaled_feat, vol_scaled = sanitise_result
            seq_buf.append(scaled_feat)
            vol_buf.append(vol_scaled)

            # --- AI INFERENCE ---
            route_res = _ai_inference(
                features    = features,
                raw_vol     = raw_vol,
                lat_a       = float(payload.get("lat_a", 0.01)),
                lat_b       = float(payload.get("lat_b", 0.05)),
                seq_buf     = seq_buf,
                vol_buf     = vol_buf,
                err_buf     = err_buf,
                conf_buf    = conf_buf,
                last_action = last_action,
                adaptive_baseline = adaptive,
            )
            route = route_res["route"]
            result = route_res

            # Extract the source IP from the payload
            src_ip = payload.get("src_ip", "172.20.0.10")

            # FIX 3: Remove redundant hardcoded volume/latency thresholds.
            # Trust the PPO model's decision entirely.

            # --- OPENFLOW ACTUATION (NON-BLOCKING) ---
            if route == 1 and ACTUATOR_AVAILABLE and os.getenv("ENABLE_ACTUATION") == "true":
                if src_ip not in blocked_ips:
                    blocked_ips.add(src_ip)
                    print(f"🚨 AI DETECTED ATTACK! Mitigating IP: {src_ip}")

                    # FIX 2: Fire the SSH actuator in a background thread so it doesn't freeze the FastAPI WebSocket
                    asyncio.create_task(asyncio.to_thread(switch_route, 1, src_ip))
            elif route == 0 and ACTUATOR_AVAILABLE and os.getenv("ENABLE_ACTUATION") == "true":
                if src_ip in blocked_ips:
                    blocked_ips.remove(src_ip)
                    asyncio.create_task(asyncio.to_thread(switch_route, 0, src_ip))

            last_action = result["route"]

            # Respond to injector immediately with routing decision
            await websocket.send_json({"route": result["route"]})

            # Throttle dashboard broadcasts — every 5th packet
            if pkt_count % 5 != 0:
                continue

            broadcast_payload = {
                "route":             result["route"],
                "is_attack":         result["is_attack"],
                "attack_confidence": result["attack_confidence"],
                "error":             result["error"],
                "error_delta":       result["error_delta"],
                "forecast_deviation":result["forecast_deviation"],
                "cluster_id":        result["cluster_id"],
                "traffic_type":      result["traffic_type"],
                "forecast":          result["forecast_raw"],
                "forecast_vol":      result["forecast_raw"],
                "lat_a":             float(payload.get("lat_a", 0.01)),
                "lat_b":             float(payload.get("lat_b", 0.05)),
                "obs_threshold":     obs_threshold,
            }
            dead = set()
            for dash in list(connected_dashboards):
                try:
                    await dash.send_json(broadcast_payload)
                except (WebSocketDisconnect, json.JSONDecodeError):
                    dead.add(dash)
                except Exception:
                    logging.error("Unexpected WS error", exc_info=True)
                    dead.add(dash)
            connected_dashboards.difference_update(dead)
            dead_topo = set()
            for dash in list(connected_topology_dashboards):
                try:
                    await dash.send_json({"route": result["route"], "is_attack": result["is_attack"]})
                except (WebSocketDisconnect, json.JSONDecodeError):
                    dead_topo.add(dash)
                except Exception:
                    logging.error("Unexpected WS error", exc_info=True)
                    dead_topo.add(dash)
            connected_topology_dashboards.difference_update(dead_topo)


    except WebSocketDisconnect:
        print("Network Generator Disconnected.")


# ---------------------------------------------------------------------------
# /ws/compare  —  head-to-head AI vs NormalRouter comparison
#
# Payload in:
#   { features, volume, lat_a, lat_b, ground_truth_attack: bool }
#
# Payload out:
#   {
#     packet_index, ground_truth,
#     ai:     { route, is_attack, attack_confidence, error, error_delta,
#               forecast_deviation, cluster_id, cluster_transition,
#               traffic_type },
#     normal: { route, is_attack, lat_score, vol_zscore, rate_zscore }
#   }
# ---------------------------------------------------------------------------
@app.websocket("/ws/compare")
async def compare_endpoint(websocket: WebSocket):
    global _active_compare_ws

    # FIX: If a previous compare session is still open (e.g. from a second
    # browser tab or a rapid Reset→Start), close it before accepting the new
    # one.  This prevents two threads from sharing the same inference state
    # and producing corrupted / interleaved metrics.
    if _active_compare_ws is not None:
        try:
            await _active_compare_ws.close(code=1001,
                reason="Superseded by new compare session")
        except Exception:

            pass  # already closed — ignore
        print("⚠️  Previous compare session closed (superseded).")

    await websocket.accept()
    _active_compare_ws = websocket
    print("⚔️  Comparison session started!")

    seq_buf = deque(maxlen=10)
    vol_buf = deque(maxlen=60)
    err_buf = deque(maxlen=10)
    conf_buf = deque(maxlen=5)
    adaptive = {}
    last_action = 0
    normal_router = NormalRouter()
    packet_index  = 0

    # Inference throttle: run heavy AI every N packets; buffer still updated every packet
    INFER_EVERY    = 3
    last_ai_result = dict(
        route=0, is_attack=False, attack_confidence=0.0,
        error=0.0, error_delta=0.0, forecast_deviation=0.0,
        cluster_id=0, cluster_transition=False, traffic_type=0.0,
        forecast_valid=True,
    )

    # Pre-fill vol_buf
    vol_buf.extend([0.0] * 60)

    try:
        while True:
            data    = await websocket.receive_text()
            payload = json.loads(data)

            ground_truth = bool(payload.get("ground_truth_attack", False))
            lat_a        = float(payload.get("lat_a", 0.01))
            lat_b        = float(payload.get("lat_b", 0.05))

            global global_packets_received
            global_packets_received += 1
            packet_timestamps.append(time.time())
            sanitise_result = _sanitise(payload)
            if isinstance(sanitise_result, dict):
                await websocket.send_json(sanitise_result)
                continue
            features, raw_vol, scaled_feat, vol_scaled = sanitise_result

            # Always update buffers so sequence context stays fresh
            seq_buf.append(scaled_feat)
            vol_buf.append(vol_scaled)

            # Normal Router — runs every packet (it's lightweight)
            sim_time = packet_index * 0.01
            normal_result = normal_router.decide(lat_a=lat_a, lat_b=lat_b,
                                                  volume=raw_vol, timestamp=sim_time)

            # AI Router — full inference only every INFER_EVERY packets
            run_inference = (packet_index % INFER_EVERY == 0)
            if run_inference:
                ai_result = _ai_inference(
                    features    = features,
                    raw_vol     = raw_vol,
                    lat_a       = lat_a,
                    lat_b       = lat_b,
                    seq_buf     = seq_buf,
                    vol_buf     = vol_buf,
                    err_buf     = err_buf,
                    conf_buf    = conf_buf,
                    last_action = last_action,
                    adaptive_baseline = adaptive,
                )
                last_action    = ai_result["route"]
                last_ai_result = ai_result
            else:
                ai_result = last_ai_result

            # FIX: Wrap send_json so a superseded session exits cleanly.
            # When a new connection arrives the server closes this socket with
            # 1001. If this coroutine is mid-loop it will hit send_json on the
            # already-closed socket → RuntimeError crashes the uvicorn worker.
            # Catching it here lets the session end silently instead.
            try:
                response = {
                    "packet_index": packet_index,
                    "ground_truth": ground_truth,
                    "ai": {
                        "route": ai_result["route"],
                        "is_attack": ai_result["is_attack"],
                        "attack_confidence": ai_result["attack_confidence"],
                        "error": ai_result["error"],
                        "error_delta": ai_result["error_delta"],
                        "forecast_deviation": ai_result["forecast_deviation"],
                        "forecast_valid": ai_result["forecast_valid"],
                        "cluster_id": ai_result["cluster_id"],
                        "cluster_transition": ai_result["cluster_transition"],
                        "traffic_type": ai_result["traffic_type"]
                    },
                    "normal": {
                        "route": normal_result["route"],
                        "is_attack": normal_result["is_attack"],
                        "lat_score": normal_result["lat_score"],
                        "vol_zscore": normal_result["vol_zscore"],
                        "rate_zscore": normal_result["rate_zscore"]
                    }
                }
                await websocket.send_json(response)
            except (RuntimeError, WebSocketDisconnect):
                # Socket was closed (superseded by a newer session) — exit cleanly
                break

            packet_index += 1

    except WebSocketDisconnect:
        print("⚔️  Comparison session ended.")
    finally:
        # FIX: Clear the global tracker so the next session can connect cleanly.
        # (global declared once at the top of this function — no repeat needed)
        if _active_compare_ws is websocket:
            _active_compare_ws = None


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
