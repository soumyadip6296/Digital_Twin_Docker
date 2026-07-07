import docker
import time

def switch_route(action_type, target_ip):
    """
    Connects to the virtual WAN router via Docker socket and injects iptables firewall rules.
    """
    try:
        # Connect to the local Docker daemon
        client = docker.from_env()
        router = client.containers.get("wan_router")
        
        if action_type == 1:
            print(f"🧱 [FIREWALL] Executing BLOCK rule for IP: {target_ip}")
            # Insert a rule at the top of the FORWARD chain to drop all packets from this IP
            block_cmd = f"sh -c 'iptables -I FORWARD -s {target_ip} -j DROP'"
            router.exec_run(block_cmd)
            
        elif action_type == 0:
            print(f"🟢 [FIREWALL] Executing ALLOW rule for IP: {target_ip}")
            # Delete the drop rule from the FORWARD chain (Auto-Heal)
            allow_cmd = f"sh -c 'iptables -D FORWARD -s {target_ip} -j DROP'"
            router.exec_run(allow_cmd)
            
        elif action_type == 2:
            print(f"🔀 [ROUTER] Diverting traffic from {target_ip} to backup node.")
            # Placeholder for load balancing logic
            
    except Exception as e:
        print(f"⚠️ [ACTUATOR ERROR] Failed to communicate with router: {e}")