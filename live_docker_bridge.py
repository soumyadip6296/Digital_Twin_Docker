import asyncio
import websockets
import json
import os
import queue
import threading
import time
from scapy.all import sniff, IP, TCP, ARP, Ether

# --- UPDATED: Docker-to-Windows API Routing ---
URI = os.getenv("API_URI", "ws://host.docker.internal:8000/ws/network_state")
IFACE = os.getenv("IFACE", None) # Let Scapy choose the default if None
maxsize = int(os.getenv("PACKET_QUEUE_MAXSIZE", "10000"))
packet_queue = queue.Queue(maxsize=maxsize)

# --- TRACKING ---
ema_latency = 0.01
expected_acks = {}
last_cleanup_time = time.monotonic()
MAX_TRACK_SIZE = 5000

# !!! CHANGE THIS: Match your actual subnet !!!
SDN_PREFIXES = ("10.199.",) 

flow_stats = {}
MAX_FLOWS = 1000 
discovered_nodes = {} 

def packet_handler(pkt):
    global ema_latency, last_cleanup_time, flow_stats, discovered_nodes

    current_time = time.monotonic()

    # --- TOPOLOGY DISCOVERY ---
    # Simplified: If we see an IP, we track it as a node
    if IP in pkt:
        src_ip = pkt[IP].src
        if src_ip.startswith(SDN_PREFIXES):
            discovered_nodes[src_ip] = {"last_seen": current_time}
    
    # Ignore non-IP traffic
    if IP not in pkt:
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    # Only track traffic within our specific Gateway network
    if not (src_ip.startswith(SDN_PREFIXES) or dst_ip.startswith(SDN_PREFIXES)):
        return

    pkt_len = len(pkt)
    reported_ip = src_ip  

    # --- Feature Tracking (The AI needs these counts!) ---
    if src_ip not in flow_stats:
        if len(flow_stats) >= MAX_FLOWS:
            flow_stats.pop(next(iter(flow_stats)))
        flow_stats[src_ip] = {
            'min_packet_length': pkt_len, 'max_packet_length': pkt_len,
            'syn_count': 0, 'ack_count': 0, 'fin_count': 0,
            'rst_count': 0, 'psh_count': 0, 'urg_count': 0,
            'total_bytes': 0, 'packet_count': 0
        }

    stats = flow_stats[src_ip]
    stats['total_bytes'] += pkt_len
    stats['packet_count'] += 1
    if pkt_len < stats['min_packet_length']: stats['min_packet_length'] = pkt_len
    if pkt_len > stats['max_packet_length']: stats['max_packet_length'] = pkt_len

    # --- TCP Flags (Crucial for DDoS Detection) ---
    if TCP in pkt:
        tcp_layer = pkt[TCP]
        flags = tcp_layer.flags
        if 'S' in flags: stats['syn_count'] += 1
        if 'A' in flags: stats['ack_count'] += 1
        if 'F' in flags: stats['fin_count'] += 1
        if 'R' in flags: stats['rst_count'] += 1
        if 'P' in flags: stats['psh_count'] += 1
        if 'U' in flags: stats['urg_count'] += 1

    # --- ENRICHED AI PAYLOAD ---
    avg_pkt_size = stats['total_bytes'] / stats['packet_count'] if stats['packet_count'] > 0 else pkt_len

    payload = {
        "src_ip": reported_ip,
        "queue_latency": round(ema_latency, 4),
        "queue_volume": float(stats['packet_count']),
        "throughput": float(stats['total_bytes']),
        "avg_packet_size": round(avg_pkt_size, 2),
        "active_flows": len(flow_stats),
        "min_packet_length": float(stats['min_packet_length']),
        "max_packet_length": float(stats['max_packet_length']),
        "syn_count": float(stats['syn_count']),
        "ack_count": float(stats['ack_count']),
        "fin_count": float(stats['fin_count']),
        "rst_count": float(stats['rst_count']),
        "psh_count": float(stats['psh_count']),
        "urg_count": float(stats['urg_count']),
        "topology_nodes": discovered_nodes
    }
    
    try:
        packet_queue.put_nowait(payload)
    except queue.Full:
        pass

def run_sniffer():
    print(f"🕵️  Starting Gateway Sniffer on {IFACE if IFACE else 'default interface'}")
    # Gateway model: We need to see all IP traffic passing through the bridge
    sniff(iface=IFACE, filter="ip", prn=packet_handler, store=False)

async def stream_to_api():
    while True:
        try:
            async with websockets.connect(URI) as websocket:
                print("✅ Connected to AI Brain!")
                while True:
                    if not packet_queue.empty():
                        payload = packet_queue.get()
                        await websocket.send(json.dumps(payload))
                        # Check for AI commands (if your AI sends back a 'block' command)
                        try:
                            response = await asyncio.wait_for(websocket.recv(), timeout=0.01)
                            decision = json.loads(response)
                            if decision.get("status") == "blocked":
                                print(f"🛑 AI BLOCKED IP: {decision.get('ip')}")
                        except asyncio.TimeoutError:
                            pass
                    await asyncio.sleep(0.01)
        except Exception as e:
            print(f"⚠️ Connection error: {e}. Retrying...")
            await asyncio.sleep(5)

if __name__ == "__main__":
    sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
    sniffer_thread.start()
    asyncio.run(stream_to_api())