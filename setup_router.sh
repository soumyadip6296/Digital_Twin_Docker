#!/bin/sh

# Enable IP forwarding inside kernel namespace
sysctl -w net.ipv4.ip_forward=1

# Clean up any stale OVS instances
rm -rf /var/run/openvswitch /etc/openvswitch/conf.db
mkdir -p /var/run/openvswitch
ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
ovsdb-server --remote=punix:/var/run/openvswitch/db.sock --pidfile --detach
ovs-vsctl --no-wait init
ovs-vswitchd --pidfile --detach --disable-system
sleep 2

# Core Architecture Isolation Fix:
# To maintain proper routing levels, eth0 and eth1 should be treated as separate layer interfaces.
ip link set eth0 up
ip link set eth1 up

# Add custom network routing targets pointing back to the core switch distributions
ip route add 10.199.2.0/24 via 10.199.1.20
ip route add 10.199.3.0/24 via 10.199.1.20

# Set local configurations
echo "root:password" | chpasswd

mkdir -p /etc/dropbear
dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key 2>/dev/null
dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key 2>/dev/null
dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null

# Start SSH daemon service container connection points
dropbear -R -E -p 22

echo "✅ Level 0 Router Stack configuration completed successfully."
tail -f /dev/null