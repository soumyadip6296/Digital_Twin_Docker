import asyncio
import websockets
import json
import os
import queue
import threading
import time
from collections import OrderedDict
from scapy.all import sniff, IP, TCP

# Target API
URI = "ws://host.docker.internal:8000/ws/network_state"
# Sniff on all interfaces by default, or specify via env var
IFACE = os.getenv("IFACE", None)

# Shared queue to move packets from the Scapy thread to the Asyncio thread
# maxsize parsed from env
maxsize = int(os.getenv("PACKET_QUEUE_MAXSIZE", "10000"))
packet_queue = queue.Queue(maxsize=maxsize)

# --- Live TCP Latency Tracking ---
ema_latency = 0.01  # Default to 10ms
expected_acks = {}  # Dictionary to track packet transmission times
last_cleanup_time = time.monotonic()
MAX_TRACK_SIZE = 5000  # Prevent OOM memory leaks during a SYN flood
# Our DMZ LAN and OpenWrt Gateway subnets
SDN_PREFIXES = ("10.0.", "172.20.")

# Flow tracking with max size to prevent OOM
flows = OrderedDict()
MAX_FLOWS_SIZE = 5000

def packet_handler(pkt):
    """Callback for Scapy to process packets and calculate real-time
    TCP RTT & Congestion.
    """
    global ema_latency

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # FIX: Keep tracking scoped to the SDN topology to avoid host noise
        if not (src_ip.startswith(SDN_PREFIXES) or
                dst_ip.startswith(SDN_PREFIXES)):
            return

        pkt_len = len(pkt)
        protocol = pkt[IP].proto
        reported_ip = src_ip  # Default to the current packet's source

        flow_key = (src_ip, dst_ip)
        if flow_key not in flows:
            if len(flows) >= MAX_FLOWS_SIZE:
                flows.popitem(last=False)
            flows[flow_key] = {
                'min_packet_length': float('inf'),
                'max_packet_length': 0,
                'syn_count': 0,
                'ack_count': 0,
                'fin_count': 0,
                'rst_count': 0,
                'psh_count': 0,
                'urg_count': 0,
                'last_seen': time.monotonic()
            }
        else:
            # Move to end to mark as recently used
            flows.move_to_end(flow_key)
            flows[flow_key]['last_seen'] = time.monotonic()

        current_flow = flows[flow_key]
        if pkt_len < current_flow['min_packet_length']: current_flow['min_packet_length'] = pkt_len
        if pkt_len > current_flow['max_packet_length']: current_flow['max_packet_length'] = pkt_len

        # --- LIVE TCP RTT / CONGESTION CALCULATION ---
        if TCP in pkt:
            tcp_layer = pkt[TCP]
            current_time = time.monotonic()

            flags = tcp_layer.flags
            if 'S' in flags: current_flow['syn_count'] += 1
            if 'A' in flags: current_flow['ack_count'] += 1
            if 'F' in flags: current_flow['fin_count'] += 1
            if 'R' in flags: current_flow['rst_count'] += 1
            if 'P' in flags: current_flow['psh_count'] += 1
            if 'U' in flags: current_flow['urg_count'] += 1

            global last_cleanup_time
            # TTL Cleanup: Every 10 seconds, remove packets waiting for an ACK for over 3 seconds
            if current_time - last_cleanup_time > 10.0:
                stale_keys = [
                    k for k, v in expected_acks.items()
                    if (current_time - (v[0] if isinstance(v, tuple) else v)) > 3.0
                ]
                for k in stale_keys:
                    del expected_acks[k]

                # Cleanup stale flows as well (older than 60 seconds)
                stale_flows = [
                    fk for fk, fv in flows.items()
                    if current_time - fv['last_seen'] > 60.0
                ]
                for fk in stale_flows:
                    del flows[fk]

                last_cleanup_time = current_time

            # 1. Process ACKs
            is_ack = bool(tcp_layer.flags & 0x10)
            if is_ack:
                ack_key = (src_ip, dst_ip, tcp_layer.sport,
                           tcp_layer.dport, tcp_layer.ack)
                tracked_ack = expected_acks.pop(ack_key, None)

                if tracked_ack is not None:
                    sent_time, original_src = tracked_ack
                    rtt = current_time - sent_time
                    rtt = min(rtt, 2.0)
                    ema_latency = (0.8 * ema_latency) + (0.2 * rtt)
                    # FIX: Prevent blocking our own protected servers and
                    # gateway. If the original packet came from our SDN,
                    # the attacker
                    # is the current ACKer.
                    if original_src.startswith(SDN_PREFIXES):
                        reported_ip = src_ip
                    else:
                        reported_ip = original_src

            # 2. Track any packet requiring an ACK (payload or SYN flag)
            payload_len = len(tcp_layer.payload)
            is_syn = bool(tcp_layer.flags & 0x02)

            if payload_len > 0 or is_syn:
                # FIX: Correct TCP sequence math for SYN + Payload
                # (TCP Fast Open)
                seq_next = (tcp_layer.seq + payload_len + (1 if is_syn else 0))
                track_key = (dst_ip, src_ip, tcp_layer.dport,
                             tcp_layer.sport, seq_next)

                if len(expected_acks) >= MAX_TRACK_SIZE:
                    expected_acks.pop(next(iter(expected_acks)))
                # FIX: Store both the timestamp AND the sender's IP
                expected_acks[track_key] = (current_time, src_ip)

        # --- BUILD AI PAYLOAD ---
        features = [0.0] * 40
        features[0] = float(protocol)
        features[1] = float(pkt_len)

        payload = {
            "features": features,
            "volume": float(pkt_len),
            "ground_truth_attack": False,
            # 🔴 LIVE PHYSICAL LATENCY (Network + Buffer Bloat)
            "lat_a": round(ema_latency, 4),
            "lat_b": 0.05,
            # Uses tracked attacker IP if this is a turnaround ACK
            "src_ip": reported_ip,
            "min_packet_length": current_flow['min_packet_length'],
            "max_packet_length": current_flow['max_packet_length'],
            "syn_count": current_flow['syn_count'],
            "ack_count": current_flow['ack_count'],
            "fin_count": current_flow['fin_count'],
            "rst_count": current_flow['rst_count'],
            "psh_count": current_flow['psh_count'],
            "urg_count": current_flow['urg_count']
        }
        try:
            packet_queue.put_nowait(payload)
        except queue.Full:
            pass


def run_sniffer():
    """Runs the Scapy sniffer in a blocking background thread."""
    iface_str = IFACE if IFACE else 'ALL'
    print(f"🕵️  Starting live packet sniffer on interface: {iface_str}")
    sniff(iface=IFACE, filter="ip", prn=packet_handler, store=False)


async def stream_to_api():
    """Async loop to pull from the queue and send to the API."""
    while True:
        try:
            print("🔗 Connecting to Digital Twin API...")
            async with websockets.connect(URI) as websocket:
                print("✅ Connected! Streaming live packets...")
                while True:
                    # Non-blocking queue check
                    if not packet_queue.empty():
                        payload = packet_queue.get()
                        await websocket.send(json.dumps(payload))
                        # Receive AI route decision
                        response = await asyncio.wait_for(
                            websocket.recv(), timeout=5.0
                        )
                        decision = json.loads(response)

                        route = decision.get("route")
                        if route is None:
                            print(f"⚠️ Unexpected API response: {decision}")
                            continue

                        route_str = {
                            0: "Traffic Allowed",
                            1: "IP Blocked (Mitigating)"
                        }.get(route, f"Unknown ({route})")
                        vol = payload['volume']
                        print(f"📡 Sent {vol} bytes | AI Route: {route_str}")
                    else:
                        await asyncio.sleep(0.01)  # Yield to event loop

        except asyncio.CancelledError:
            raise
        except (asyncio.TimeoutError, OSError,
                websockets.exceptions.WebSocketException) as e:
            print(f"⚠️ API Connection lost ({e}). Retrying in 5s...")
            await asyncio.sleep(5)


if __name__ == "__main__":
    # Start Scapy in a background thread so it doesn't block Asyncio
    sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
    sniffer_thread.start()

    # Start the Async WebSocket stream
    try:
        asyncio.run(stream_to_api())
    except KeyboardInterrupt:
        print("\n🛑 Shutting down live bridge.")
