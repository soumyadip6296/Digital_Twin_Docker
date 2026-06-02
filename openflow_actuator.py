import paramiko
import ipaddress


def run_ssh_command(cmd):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname="127.0.0.1", port=2222, username="root", password="password")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        error = stderr.read().decode().strip()
        if error:
            print(f"⚠️ ACTUATOR ERROR: {error}")
        ssh.close()
    except Exception as e:
        print(f"⚠️ SSH CONNECTION ERROR: {e}")

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
    cmd = f'ovs-ofctl del-flows br0 "ip,nw_src={target_ip}" && ovs-ofctl add-flow br0 "priority=100,ip,nw_src={target_ip},actions=drop"'
    run_ssh_command(cmd)


def unblock_attacker(target_ip):
    """Removes the drop rule to restore normal traffic."""
    if not is_valid_ip(target_ip):
        return

    print(f"🟢 ACTUATOR: Restoring traffic flow for {target_ip}.")
    cmd = f'ovs-ofctl del-flows br0 "ip,nw_src={target_ip}"'
    run_ssh_command(cmd)


def switch_route(route_id, target_ip="172.20.0.10"):
    """Adapter function mapping the AI routing decision to firewall rules."""
    if route_id == 1:
        block_attacker(target_ip)
    else:
        unblock_attacker(target_ip)
