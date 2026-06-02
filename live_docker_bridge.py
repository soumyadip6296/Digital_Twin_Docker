import asyncio
import websockets
import json
import os
import queue
import threading
import time
from scapy.all import sniff, IP, TCP, ARP, Ether

# --- UPDATED: Docker-to-Windows API Routing ---
# Uses host.docker.internal to bypass the WSL boundary
URI = os.getenv("API_URI", "ws://host.docker.internal:8000/ws/network_state")

IFACE = os.getenv("IFACE", None)
maxsize = int(os.getenv("PACKET_QUEUE_MAXSIZE", "10000"))
packet_queue = queue.Queue(maxsize=maxsize)

# --- Live Tracking Variables ---
ema_latency = 0.01  # Default to 10ms
expected_acks = {}
last_cleanup_time = time.monotonic()
MAX_TRACK_SIZE = 5000
SDN_PREFIXES = ("10.0.", "172.20.")

# --- NEW: Feature & Topology Trackers ---
flow_stats = {}
MAX_FLOWS = 1000  # Prevent memory leaks

discovered_nodes = {}  # Format: { "IP": {"mac": "...", "last_seen": timestamp} }

def packet_handler(pkt):
    global ema_latency, last_cleanup_time, flow_stats, discovered_nodes

    current_time = time.monotonic()

    # --- TOPOLOGY DISCOVERY: ARP TRACKING ---
    # Catch ARP Broadcasts (New nodes announcing themselves) - Layer 2
    if ARP in pkt and pkt[ARP].op in (1, 2):  # 1 = who-has, 2 = is-at
        node_ip = pkt[ARP].psrc
        node_mac = pkt[ARP].hwsrc
        if node_ip.startswith(SDN_PREFIXES):
            discovered_nodes[node_ip] = {"mac": node_mac, "last_seen": current_time}
        return  # ARP packets have no IP/TCP payload to process below

    # If it's not an IP packet, drop it
    if IP not in pkt:
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    # --- TOPOLOGY DISCOVERY: ETHERNET MAC TRACKING ---
    # Catch MACs from standard IP traffic
    if Ether in pkt:
        src_mac = pkt[Ether].src
        if src_ip.startswith(SDN_PREFIXES):
            discovered_nodes[src_ip] = {"mac": src_mac, "last_seen": current_time}

    # Keep tracking scoped to the SDN topology
    if not (src_ip.startswith(SDN_PREFIXES) or dst_ip.startswith(SDN_PREFIXES)):
        return

    pkt_len = len(pkt)
    reported_ip = src_ip  

    # --- Extract and Track Packet & Flag Features ---
    if src_ip not in flow_stats:
        if len(flow_stats) >= MAX_FLOWS:
            flow_stats.pop(next(iter(flow_stats))) # Remove oldest flow
            
        flow_stats[src_ip] = {
            'min_packet_length': pkt_len,
            'max_packet_length': pkt_len,
            'syn_count': 0, 'ack_count': 0, 'fin_count': 0,
            'rst_count': 0, 'psh_count': 0, 'urg_count': 0,
            'total_bytes': 0, 'packet_count': 0
        }

    # Update flow metrics
    stats = flow_stats[src_ip]
    stats['total_bytes'] += pkt_len
    stats['packet_count'] += 1
    if pkt_len < stats['min_packet_length']: stats['min_packet_length'] = pkt_len
    if pkt_len > stats['max_packet_length']: stats['max_packet_length'] = pkt_len

    # --- LIVE TCP RTT & CONGESTION CALCULATION ---
    if TCP in pkt:
        tcp_layer = pkt[TCP]
        flags = tcp_layer.flags

        # Extract TCP Flags for the Legacy ISCX Models
        if 'S' in flags: stats['syn_count'] += 1
        if 'A' in flags: stats['ack_count'] += 1
        if 'F' in flags: stats['fin_count'] += 1
        if 'R' in flags: stats['rst_count'] += 1
        if 'P' in flags: stats['psh_count'] += 1
        if 'U' in flags: stats['urg_count'] += 1

        # TTL Cleanup for ACKs
        if current_time - last_cleanup_time > 10.0:
            stale_keys = [
                k for k, v in expected_acks.items()
                if (current_time - (v[0] if isinstance(v, tuple) else v)) > 3.0
            ]
            for k in stale_keys:
                del expected_acks[k]
            last_cleanup_time = current_time

        # 1. Process ACKs
        is_ack = bool(flags & 0x10)
        if is_ack:
            ack_key = (src_ip, dst_ip, tcp_layer.sport, tcp_layer.dport, tcp_layer.ack)
            tracked_ack = expected_acks.pop(ack_key, None)

            if tracked_ack is not None:
                sent_time, original_src = tracked_ack
                rtt = min(current_time - sent_time, 2.0)
                ema_latency = (0.8 * ema_latency) + (0.2 * rtt)
                
                if original_src.startswith(SDN_PREFIXES):
                    reported_ip = src_ip
                else:
                    reported_ip = original_src

        # 2. Track requiring ACKs
        payload_len = len(tcp_layer.payload)
        is_syn = bool(flags & 0x02)

        if payload_len > 0 or is_syn:
            seq_next = (tcp_layer.seq + payload_len + (1 if is_syn else 0))
            track_key = (dst_ip, src_ip, tcp_layer.dport, tcp_layer.sport, seq_next)

            if len(expected_acks) >= MAX_TRACK_SIZE:
                expected_acks.pop(next(iter(expected_acks)))
            expected_acks[track_key] = (current_time, src_ip)

    # --- BUILD ENRICHED AI PAYLOAD ---
    avg_pkt_size = stats['total_bytes'] / stats['packet_count'] if stats['packet_count'] > 0 else pkt_len

    payload = {
        "src_ip": reported_ip,
        
        # Base physical metrics
        "queue_latency": round(ema_latency, 4),
        "queue_volume": float(stats['packet_count']),
        "throughput": float(stats['total_bytes']),
        "avg_packet_size": round(avg_pkt_size, 2),
        "active_flows": len(flow_stats),
        "drop_rate": 0.0,

        # New Granular Features (For padding the 40-Dimension array)
        "min_packet_length": float(stats['min_packet_length']),
        "max_packet_length": float(stats['max_packet_length']),
        "syn_count": float(stats['syn_count']),
        "ack_count": float(stats['ack_count']),
        "fin_count": float(stats['fin_count']),
        "rst_count": float(stats['rst_count']),
        "psh_count": float(stats['psh_count']),
        "urg_count": float(stats['urg_count']),

        # --- NEW: Attach Topology State ---
        "topology_nodes": discovered_nodes
    }
    
    try:
        packet_queue.put_nowait(payload)
    except queue.Full:
        pass


def run_sniffer():
    iface_str = IFACE if IFACE else 'ALL'
    print(f"🕵️  Starting live packet sniffer on interface: {iface_str}")
    # filter="ip or arp" ensures we catch Layer 2 ARP broadcasts along with Layer 3 IP
    sniff(iface=IFACE, filter="ip or arp", prn=packet_handler, store=False)


async def stream_to_api():
    while True:
        try:
            print(f"🔗 Connecting to AI API at {URI} ...")
            async with websockets.connect(URI) as websocket:
                print("✅ Connected! Streaming live enriched packets + topology...")
                while True:
                    if not packet_queue.empty():
                        payload = packet_queue.get()
                        await websocket.send(json.dumps(payload))
                        
                        try:
                            # Use a non-blocking fast timeout for high-throughput
                            response = await asyncio.wait_for(websocket.recv(), timeout=0.1)
                            decision = json.loads(response)
                            if decision.get("status") == "blocked":
                                print(f"🛑 AI BLOCKED IP: {decision.get('ip')}")
                        except asyncio.TimeoutError:
                            pass # No action needed, keep sending packets
                    else:
                        await asyncio.sleep(0.01)

        except asyncio.CancelledError:
            raise
        except (asyncio.TimeoutError, OSError, websockets.exceptions.WebSocketException) as e:
            print(f"⚠️ API Connection lost ({e}). Retrying in 5s...")
            await asyncio.sleep(5)


if __name__ == "__main__":
    sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
    sniffer_thread.start()

    try:
        asyncio.run(stream_to_api())
    except KeyboardInterrupt:
        print("\n🛑 Shutting down live bridge.")