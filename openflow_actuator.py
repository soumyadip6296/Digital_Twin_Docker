import subprocess
import ipaddress

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def block_attacker(target_ip):
    """Uses iptables to drop all traffic from the attacker IP at the gateway."""
    if not is_valid_ip(target_ip):
        print(f"⚠️ ACTUATOR ERROR: Invalid IP address: {target_ip}")
        return

    print(f"🛡️ ACTUATOR: Blocking IP {target_ip} at the Gateway Firewall!")
    # -A = Append (Add) rule
    cmd = f'docker exec gateway iptables -A FORWARD -s {target_ip} -j DROP'
    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"✅ Successfully blocked {target_ip}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to block attacker: {e}")

def unblock_attacker(target_ip):
    """Removes the drop rule from the gateway firewall."""
    if not is_valid_ip(target_ip):
        return

    print(f"🟢 ACTUATOR: Restoring traffic flow for {target_ip}.")
    # -D = Delete rule
    cmd = f'docker exec gateway iptables -D FORWARD -s {target_ip} -j DROP'
    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"✅ Successfully unblocked {target_ip}")
    except subprocess.CalledProcessError as e:
        # If the rule didn't exist, it might throw an error, so we catch it
        print(f"⚠️ Mitigation already removed or rule not found: {e}")

def switch_route(route_id, target_ip):
    """Adapter function mapping the AI routing decision to firewall rules."""
    if route_id == 1:
        block_attacker(target_ip)
    else:
        unblock_attacker(target_ip)