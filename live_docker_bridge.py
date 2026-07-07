import asyncio
import websockets
import json
import os
import queue
import threading
import time
from collections import OrderedDict
from scapy.all import sniff, IP, TCP, ARP, Ether

URI = os.getenv("API_URI", "ws://127.0.0.1:8000/ws/network_state")
IFACE = None
#IFACE = os.getenv("IFACE", None)
maxsize = int(os.getenv("PACKET_QUEUE_MAXSIZE", "10000"))
packet_queue = queue.Queue(maxsize=maxsize)

ema_latency = 0.01  
expected_acks = {}
last_cleanup_time = time.monotonic()
MAX_TRACK_SIZE = 5000

# FIX: Matched to the docker-compose subnets
SDN_PREFIXES = ("10.199.", "172.20.")

# Flow tracking with max size to prevent OOM
flows = OrderedDict()
flow_stats = {}  # Track per-IP statistics
MAX_FLOWS_SIZE = 5000
discovered_nodes = {}  # Track discovered network nodes

def packet_handler(pkt):
    """Callback for Scapy to process packets and calculate real-time
    TCP RTT & Congestion.
    """
    global ema_latency, last_cleanup_time

    if IP not in pkt:
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    # FIX: Keep tracking scoped to the SDN topology to avoid host noise
    if not (src_ip.startswith(SDN_PREFIXES) or dst_ip.startswith(SDN_PREFIXES)):
        return

    # Track discovered nodes
    if src_ip.startswith(SDN_PREFIXES):
        if src_ip not in discovered_nodes:
            discovered_nodes[src_ip] = {"mac": "unknown", "last_seen": time.monotonic()}
        discovered_nodes[src_ip]["last_seen"] = time.monotonic()

    pkt_len = len(pkt)
    protocol = pkt[IP].proto
    reported_ip = src_ip  # Default to the current packet's source

    # Initialize per-IP stats
    if src_ip not in flow_stats:
        flow_stats[src_ip] = {
            'total_bytes': 0,
            'packet_count': 0,
            'min_packet_length': float('inf'),
            'max_packet_length': 0,
            'syn_count': 0,
            'ack_count': 0,
            'fin_count': 0,
            'rst_count': 0,
            'psh_count': 0,
            'urg_count': 0
        }

    stats = flow_stats[src_ip]
    stats['total_bytes'] += pkt_len
    stats['packet_count'] += 1
    if pkt_len < stats['min_packet_length']: 
        stats['min_packet_length'] = pkt_len
    if pkt_len > stats['max_packet_length']: 
        stats['max_packet_length'] = pkt_len

    # --- LIVE TCP RTT / CONGESTION CALCULATION ---
    if TCP in pkt:
        tcp_layer = pkt[TCP]
        current_time = time.monotonic()

        flags = tcp_layer.flags
        if 'S' in flags: stats['syn_count'] += 1
        if 'A' in flags: stats['ack_count'] += 1
        if 'F' in flags: stats['fin_count'] += 1
        if 'R' in flags: stats['rst_count'] += 1
        if 'P' in flags: stats['psh_count'] += 1
        if 'U' in flags: stats['urg_count'] += 1

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
                ip for ip, st in flow_stats.items()
                if current_time - st.get('last_updated', current_time) > 60.0
            ]
            for ip in stale_flows:
                del flow_stats[ip]

            last_cleanup_time = current_time

        # 1. Process ACKs
        is_ack = bool(tcp_layer.flags & 0x10)
        if is_ack:
            ack_key = (src_ip, dst_ip, tcp_layer.sport, tcp_layer.dport, tcp_layer.ack)
            tracked_ack = expected_acks.pop(ack_key, None)

            if tracked_ack is not None:
                sent_time, original_src = tracked_ack
                rtt = current_time - sent_time
                rtt = min(rtt, 2.0)
                ema_latency = (0.8 * ema_latency) + (0.2 * rtt)
                if original_src.startswith(SDN_PREFIXES):
                    reported_ip = src_ip
                else:
                    reported_ip = original_src

        # 2. Track any packet requiring an ACK (payload or SYN flag)
        payload_len = len(tcp_layer.payload)
        is_syn = bool(tcp_layer.flags & 0x02)

        if payload_len > 0 or is_syn:
            seq_next = (tcp_layer.seq + payload_len + (1 if is_syn else 0))
            track_key = (dst_ip, src_ip, tcp_layer.dport, tcp_layer.sport, seq_next)

            if len(expected_acks) >= MAX_TRACK_SIZE:
                expected_acks.pop(next(iter(expected_acks)))
            expected_acks[track_key] = (current_time, src_ip)

    # Update last seen time
    stats['last_updated'] = time.monotonic()

    avg_pkt_size = stats['total_bytes'] / stats['packet_count'] if stats['packet_count'] > 0 else pkt_len

    payload = {
        "src_ip": reported_ip,
        "queue_latency": round(ema_latency, 4),
        "queue_volume": float(stats['packet_count']),
        "throughput": float(stats['total_bytes']),
        "avg_packet_size": round(avg_pkt_size, 2),
        "active_flows": len(flow_stats),
        "drop_rate": 0.0,
        "min_packet_length": float(stats['min_packet_length']) if stats['min_packet_length'] != float('inf') else 0.0,
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
    print("🕵️ Starting live packet sniffer...")
    try:
        sniff(iface=IFACE, filter="ip or arp", prn=packet_handler, store=False)
    except Exception as e:
        print(f"❌ Sniffer error: {e}")


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
                    else:
                        await asyncio.sleep(0.01)

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
