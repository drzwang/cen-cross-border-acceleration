#!/bin/bash -e

# Check required environment variable
if [ -z $VPC_CN_CIDR ]; then
	echo "Please set VPC_CN_CIDR."
	echo "Example:"
	echo "VPC_CN_CIDR=192.168.0.0/24 ./us_config_nat.sh"
	exit 1
fi

echo
echo "--- Installing squid ---"
echo
yum install -y squid

# edit squid.conf
# make sure squid is listening on IPv4 (default seems IPv6 only)
sed -i 's/^http_port.*/http_port 0.0.0.0:3128/' /etc/squid/squid.conf
# add "acl ecs-cn-vpn src <VPC_CN_CIDR>" before the first acl line
sed -i '0,/^acl /s%%acl ecs-cn-vpn src '"$VPC_CN_CIDR"'\n&%' /etc/squid/squid.conf
# add "http_access allow ecs-cn-vpn" after the "INSERT YOUR OWN RULE" comment
sed -i '/INSERT YOUR OWN RULE/a http_access allow ecs-cn-vpn' /etc/squid/squid.conf


# Enable and start squid
systemctl enable squid
systemctl start squid
systemctl status squid

echo "Done."
