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

# Generate SSH keys if they don't exist
mkdir -p /etc/dropbear
[ ! -f /etc/dropbear/dropbear_rsa_host_key ] && dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
[ ! -f /etc/dropbear/dropbear_ecdsa_host_key ] && dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key
[ ! -f /etc/dropbear/dropbear_ed25519_host_key ] && dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key

echo "✅ Multi-Tier WAN Router configuration completed successfully."

# Start SSH daemon in foreground (do not background)
exec dropbear -F -E -p 22
