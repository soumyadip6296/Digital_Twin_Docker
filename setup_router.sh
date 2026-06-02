#!/bin/sh

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# Clean up any stale OVS files
rm -rf /var/run/openvswitch /etc/openvswitch/conf.db

# Start OVS database server
mkdir -p /var/run/openvswitch
ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
ovsdb-server --remote=punix:/var/run/openvswitch/db.sock --pidfile --detach
ovs-vsctl --no-wait init

# Start OVS vswitchd (userspace only)
ovs-vswitchd --pidfile --detach --disable-system
sleep 2

# Create bridge with netdev datapath
ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

# Attach physical interfaces (eth0=WAN, eth1=Transit)
ovs-vsctl add-port br0 eth0
ovs-vsctl add-port br0 eth1

# Save interface names for reference
echo "eth0" > /wan_if.txt
echo "eth1" > /lan_if.txt

# Move IPs from the physical interfaces to the bridge
ip addr flush dev eth0
ip addr flush dev eth1
ip addr add 172.20.0.2/16 dev br0
ip addr add 10.0.0.1/24 dev br0
ip link set br0 up

# Basic NORMAL flow
ovs-ofctl add-flow br0 "priority=0,actions=NORMAL"

# Set root password
echo "root:password" | chpasswd

# Add static routes to downstream networks
ip route add 10.0.10.0/24 via 10.0.0.2
ip route add 10.0.20.0/24 via 10.0.0.2

# ---- Generate Dropbear host keys ----
mkdir -p /etc/dropbear
dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key
dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key

echo "✅ Router with OVS userspace ready"