#!/bin/bash -e

# Check required environment variable
if [ -z $VPC_CN_CIDR ]; then
	echo "Please set VPC_CN_CIDR."
	echo "Example:"
	echo "VPC_CN_CIDR=192.168.0.0/24 ./us_config_nat.sh"
	exit 1
fi
LOCAL_CIDR=$(curl -s http://100.100.100.200/latest/meta-data/vpc-cidr-block)
LOCAL_IP=$(curl -s http://100.100.100.200/latest/meta-data/private-ipv4)

echo
echo "--- Enabling IPv4 forwarding ---"
echo
echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
sysctl -p

echo
echo "--- Installing iptables-services---"
echo
yum install -y iptables-services
systemctl enable iptables
systemctl start iptables

echo
echo "--- Clearing iptables ---"
echo
iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT
iptables -F
iptables -t nat -F
iptables -t mangle -F
echo "-----------"
echo "iptables -L"
echo "-----------"
iptables -L

echo
echo "--- Adding our NAT rules ---"
echo
iptables -t nat -A POSTROUTING -d 100.64.0.0/10 -j RETURN
iptables -t nat -A POSTROUTING -s $LOCAL_CIDR -j SNAT --to-source $LOCAL_IP
iptables -t nat -A POSTROUTING -s $VPC_CN_CIDR -j SNAT --to-source $LOCAL_IP
echo "------------------"
echo "iptables -L -t nat"
echo "------------------"
iptables -L -t nat

echo
echo "--- Saving iptables rules ---"
echo
iptables-save > /etc/sysconfig/iptables

echo "Done."
