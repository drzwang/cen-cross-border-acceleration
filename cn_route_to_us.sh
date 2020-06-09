#!/bin/bash -e

# Check required environment variable
if [ -z $ECS_CN_SECONDARY_IP ]; then
	echo "Please set ECS_CN_SECONDARY_IP."
	echo "Example:"
	echo "ECS_CN_SECONDARY_IP=192.168.0.2 ./cn_route_to_us.sh"
	exit 1
fi

echo
echo "This script configures Secondary Private IP Address and iptables nat table to route VPN client traffic to the US via CEN."
echo

apt-get install -y traceroute

VPNIPPOOL="10.10.0.0/16"
ETH0ORSIMILAR=$(ip route get 8.8.8.8 | awk -- '{printf $5}')

echo
echo "--- Configuration: Secondary IP Address ---"
echo

PREFIXLENGTH=$(curl -s http://100.100.100.200/latest/meta-data/vswitch-cidr-block | grep -P '\d+$' -o)
cat << EOF > /etc/netplan/99-eth0.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: yes
      dhcp6: no
      addresses:
        - ${ECS_CN_SECONDARY_IP}/${PREFIXLENGTH}
EOF
netplan apply
sleep 5
ip addr |grep inet

echo
echo "--- Configuring NAT rules ---"
echo
# Flush POSTROUTING chain for nat table
iptables -t nat -F POSTROUTING
# Use SNAT to forward non-IPsec traffic from ECS_CN_SECONDARY_IP
iptables -t nat -A POSTROUTING -s $VPNIPPOOL -o $ETH0ORSIMILAR -m policy --pol ipsec --dir out -j ACCEPT
iptables -t nat -A POSTROUTING -s $VPNIPPOOL -o $ETH0ORSIMILAR -j SNAT --to-source $ECS_CN_SECONDARY_IP
iptables -t nat -L
iptables-save > /etc/iptables/rules.v4

echo
echo "--- Verifying routing: traceroute -s ${ECS_CN_SECONDARY_IP} 8.8.8.8 ---"
echo
traceroute -s $ECS_CN_SECONDARY_IP 8.8.8.8