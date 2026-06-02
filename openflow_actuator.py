import ipaddress
import subprocess


def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def block_attacker(target_ip):
    """Injects an OpenFlow rule to drop all traffic from the target IP."""
    if not is_valid_ip(target_ip):
        print(f"⚠️ ACTUATOR ERROR: Invalid IP address: {target_ip}")
        return

    print(f"🛡️ ACTUATOR: Blocking IP {target_ip} at the Edge Switch!")
    try:
        cmd = f'docker exec core_switch sh -c "ovs-ofctl del-flows br-core ip,nw_src={target_ip} && ovs-ofctl add-flow br-core priority=100,ip,nw_src={target_ip},actions=drop"'
        subprocess.run(cmd, shell=True, check=True)
        print(f"✅ Successfully blocked {target_ip} via Docker Exec")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to block attacker: {e}")


def unblock_attacker(target_ip):
    """Removes the drop rule to restore normal traffic."""
    if not is_valid_ip(target_ip):
        return

    print(f"🟢 ACTUATOR: Restoring traffic flow for {target_ip}.")
    try:
        cmd = f'docker exec core_switch sh -c "ovs-ofctl del-flows br-core ip,nw_src={target_ip}"'
        subprocess.run(cmd, shell=True, check=True)
        print(f"✅ Successfully unblocked {target_ip}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to unblock attacker: {e}")


def switch_route(route_id, target_ip="172.20.0.10"):
    """Adapter function mapping the AI routing decision to firewall rules."""
    if route_id == 1:
        block_attacker(target_ip)
    else:
        unblock_attacker(target_ip)
