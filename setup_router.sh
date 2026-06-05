#!/bin/sh

# Enable IP forwarding inside kernel namespace
sysctl -w net.ipv4.ip_forward=1

# Bring up interfaces attached by Docker
ip link set eth0 up  # wan_net
ip link set eth1 up  # lan1_net
ip link set eth2 up  # lan2_net

# NAT for outbound traffic so internal servers can communicate back to the Host/WAN
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# Set local configurations for SSH
echo "root:password" | chpasswd

mkdir -p /etc/dropbear
dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key 2>/dev/null
dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key 2>/dev/null
dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null

# Start SSH daemon service
dropbear -R -E -p 22

echo "✅ Multi-Tier WAN Router configuration completed successfully."
tail -f /dev/null