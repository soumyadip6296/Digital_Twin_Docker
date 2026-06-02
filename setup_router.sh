#!/bin/sh

# 1. Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# 2. Reset and set default firewall rules
iptables -F
iptables -t nat -F
iptables -P FORWARD ACCEPT # Allow traffic to flow
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT

# 3. Security Hardening
echo "root:password" | chpasswd
# (Keep SSH if you really need it, otherwise remove this block)
echo "✅ Gateway Firewall Stack configured. AI Defense is ready to inject rules."
tail -f /dev/null