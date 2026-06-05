import ipaddress
import subprocess

# Define the new multi-switch topology
SWITCHES = [
    {"container": "lan_switch1", "bridge": "br-lan1"},
    {"container": "lan_switch2", "bridge": "br-lan2"}
]

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def block_attacker(target_ip):
    if not is_valid_ip(target_ip):
        print(f"⚠️ ACTUATOR ERROR: Invalid IP address: {target_ip}")
        return

    print(f"🛡️ ACTUATOR: Distributing block for IP {target_ip} across edge switches!")
    for switch in SWITCHES:
        try:
            cmd = f'docker exec {switch["container"]} sh -c "ovs-ofctl del-flows {switch["bridge"]} ip,nw_src={target_ip} && ovs-ofctl add-flow {switch["bridge"]} priority=100,ip,nw_src={target_ip},actions=drop"'
            subprocess.run(cmd, shell=True, check=True)
            print(f"✅ Successfully blocked {target_ip} on {switch['container']}")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to block attacker on {switch['container']}: {e}")

def unblock_attacker(target_ip):
    if not is_valid_ip(target_ip):
        return

    print(f"🟢 ACTUATOR: Restoring traffic flow for {target_ip}.")
    for switch in SWITCHES:
        try:
            cmd = f'docker exec {switch["container"]} sh -c "ovs-ofctl del-flows {switch["bridge"]} ip,nw_src={target_ip}"'
            subprocess.run(cmd, shell=True, check=True)
            print(f"✅ Successfully unblocked {target_ip} on {switch['container']}")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to unblock attacker on {switch['container']}: {e}")

def switch_route(route_id, target_ip):
    if route_id == 1:
        block_attacker(target_ip)
    else:
        unblock_attacker(target_ip)