#!/bin/bash -e

# github.com/jawj/IKEv2-setup
# Copyright (c) 2015 – 2018 George MacKerron
# Released under the MIT licence: http://opensource.org/licenses/mit-license

# Check required environment variable
if [ -z $ECS_US_SQUID_IP]; then
	echo "Please set ECS_US_SQUID_IP."
	echo "Example:"
	echo "ECS_US_SQUID_IP=172.16.0.1 ./cn_config_vpn.sh"
	exit 1
fi

echo
echo "This script configurs Alibaba Cloud ECS instance as IKEv2 VPN server"
echo "It is based on https://github.com/jawj/IKEv2-setup with changes."
echo

function exit_badly {
  echo $1
  exit 1
}

[[ $(lsb_release -rs) == "18.04" ]] || exit_badly "This script is for Ubuntu 18.04 only, aborting (if you know what you're doing, delete this check)."
[[ $(id -u) -eq 0 ]] || exit_badly "Please re-run as root (e.g. sudo ./path/to/this/script)"

echo "--- Updating and installing software ---"
echo

export DEBIAN_FRONTEND=noninteractive

# see https://github.com/jawj/IKEv2-setup/issues/66 and https://bugs.launchpad.net/subiquity/+bug/1783129
# note: software-properties-common is required for add-apt-repository
apt-get -o Acquire::ForceIPv4=true update
apt-get -o Acquire::ForceIPv4=true install -y software-properties-common
add-apt-repository universe
add-apt-repository restricted
add-apt-repository multiverse

apt-get -o Acquire::ForceIPv4=true --with-new-pkgs upgrade -y
apt autoremove -y

apt-get -o Acquire::ForceIPv4=true install -y language-pack-en strongswan strongswan-pki libstrongswan-standard-plugins strongswan-libcharon libcharon-standard-plugins libcharon-extra-plugins moreutils iptables-persistent unattended-upgrades dnsutils uuid-runtime

echo
echo "--- Configuration: VPN settings ---"
echo

ETH0ORSIMILAR=$(ip route get 8.8.8.8 | awk -- '{printf $5}')
echo "Network interface: ${ETH0ORSIMILAR}"
PRIVATE_IP=$(curl -s http://100.100.100.200/latest/meta-data/private-ipv4)
EIP=$(curl -s http://100.100.100.200/latest/meta-data/eipv4)
echo "External IP: ${EIP}"
VPNHOST=${EIP}
VPNUSERNAME="demovpnuser"
VPNPASSWORD="Very_Very_Strong"
VPNDNS='1.1.1.1,1.0.0.1'
echo "VPN DNS: ${VPNDNS}"
VPNIPPOOL="10.10.0.0/16"
echo "VPN IP Pool: ${VPNIPPOOL}"

echo
echo "--- Configuring firewall ---"
echo

# firewall
# https://www.strongswan.org/docs/LinuxKongress2009-strongswan.pdf
# https://wiki.strongswan.org/projects/strongswan/wiki/ForwardingAndSplitTunneling
# https://www.zeitgeist.se/2013/11/26/mtu-woes-in-ipsec-tunnels-how-to-fix/

iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

iptables -F
iptables -t nat -F
iptables -t mangle -F

# INPUT

# accept anything already accepted
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# accept anything on the loopback interface
iptables -A INPUT -i lo -j ACCEPT

# drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# rate-limit repeated new requests from same IP to any ports
iptables -I INPUT -i $ETH0ORSIMILAR -m state --state NEW -m recent --set
iptables -I INPUT -i $ETH0ORSIMILAR -m state --state NEW -m recent --update --seconds 300 --hitcount 60 -j DROP

# accept (non-standard) SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# accept ICMP
iptables -A INPUT -p icmp -j ACCEPT

# accept HTTP from VPN client for retrieving PAC file
iptables -A INPUT -p tcp --dport 80 -s 10.10.0.0/16 -j ACCEPT

# VPN

# accept IPSec/NAT-T for VPN (ESP not needed with forceencaps, as ESP goes inside UDP)
iptables -A INPUT -p udp --dport  500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT

# forward VPN traffic anywhere
iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s $VPNIPPOOL -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d $VPNIPPOOL -j ACCEPT

# reduce MTU/MSS values for dumb VPN clients
iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s $VPNIPPOOL -o $ETH0ORSIMILAR -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360

# masquerade VPN traffic over eth0 etc. exempt IPsec traffic from masquerading
iptables -t nat -A POSTROUTING -s $VPNIPPOOL -o $ETH0ORSIMILAR -m policy --pol ipsec --dir out -j ACCEPT 
iptables -t nat -A POSTROUTING -s $VPNIPPOOL -o $ETH0ORSIMILAR -j MASQUERADE

# fall through to drop any other input and forward traffic
iptables -A INPUT   -j DROP
iptables -A FORWARD -j DROP

echo "iptables rules:"
echo
iptables -L

echo
echo "iptables nat table rules:"
echo
iptables -t nat -L

debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean true"
debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean true"
dpkg-reconfigure iptables-persistent


echo
echo "--- Configuring RSA certificates ---"
echo

mkdir -p /root/vpn-pems
cd /root/vpn-pems
ipsec pki --gen --type rsa --size 4096 --outform pem > vpn-ca-key.pem
ipsec pki --self --in vpn-ca-key.pem --type rsa --dn "CN=VPN Server root CA" --ca --lifetime 3650 --outform pem > vpn-ca-cert.pem
ipsec pki --gen --size 4096 --type rsa --outform pem > vpn-server-key.pem
ipsec pki --pub --in vpn-server-key.pem --type rsa | ipsec pki --issue --lifetime 1825 --cacert vpn-ca-cert.pem --cakey vpn-ca-key.pem --dn "CN=${VPNHOST}" --san ${VPNHOST} --flag serverAuth --flag ikeIntermediate --outform pem > vpn-server-cert.pem
chmod 400 *
openssl x509 -outform der -in vpn-ca-cert.pem -out vpn-ca-cert.crt
cp vpn-ca-cert.pem /etc/ipsec.d/cacerts
cp vpn-server-cert.pem /etc/ipsec.d/certs
cp vpn-server-key.pem /etc/ipsec.d/private
cd ~

echo
echo "--- Configuring VPN ---"
echo

# ip_forward is for VPN
# ip_no_pmtu_disc is for UDP fragmentation
# others are for security

grep -Fq 'jawj/IKEv2-setup' /etc/sysctl.conf || echo '
# https://github.com/jawj/IKEv2-setup
net.ipv4.ip_forward = 1
net.ipv4.ip_no_pmtu_disc = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
' >> /etc/sysctl.conf

sysctl -p

# these ike and esp settings are tested on Mac 10.14, iOS 12 and Windows 10
# iOS and Mac with appropriate configuration profiles use AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_521 
# Windows 10 uses AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_384

echo "config setup
  strictcrlpolicy=yes
  uniqueids=never

conn roadwarrior
  auto=add
  compress=no
  type=tunnel
  keyexchange=ikev2
  fragmentation=yes
  forceencaps=yes
  ike=aes256gcm16-prfsha384-ecp521,aes256gcm16-prfsha384-ecp384!
  esp=aes256gcm16-ecp521,aes256gcm16-ecp384!
  dpdaction=clear
  dpddelay=900s
  rekey=no
  left=%any
  leftid=${VPNHOST}
  leftcert=vpn-server-cert.pem
  leftsendcert=always
  leftsubnet=0.0.0.0/0
  right=%any
  rightid=%any
  rightauth=eap-mschapv2
  eap_identity=%any
  rightdns=${VPNDNS}
  rightsourceip=${VPNIPPOOL}
  rightsendcert=never
" > /etc/ipsec.conf

echo "${VPNHOST} : RSA \"vpn-server-key.pem\"
${VPNUSERNAME} : EAP \""${VPNPASSWORD}"\"
" > /etc/ipsec.secrets

echo
echo "First VPN user created:"
echo "Username: ${VPNUSERNAME}"
echo "Password: ${VPNPASSWORD}"
echo

ipsec restart

echo
echo "--- Locale, hostname, unattended upgrades ---"
echo

/usr/sbin/update-locale LANG=en_GB.UTF-8

sed -r \
-e 's|^//Unattended-Upgrade::MinimalSteps "true";$|Unattended-Upgrade::MinimalSteps "true";|' \
-e 's|^//Unattended-Upgrade::Mail "root";$|Unattended-Upgrade::Mail "root";|' \
-e 's|^//Unattended-Upgrade::Automatic-Reboot "false";$|Unattended-Upgrade::Automatic-Reboot "true";|' \
-e 's|^//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|' \
-e 's|^//Unattended-Upgrade::Automatic-Reboot-Time "02:00";$|Unattended-Upgrade::Automatic-Reboot-Time "03:00";|' \
-i /etc/apt/apt.conf.d/50unattended-upgrades

echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
' > /etc/apt/apt.conf.d/10periodic

service unattended-upgrades restart

echo
echo "--- Installing lighttpd for PAC file ---"
echo
apt-get install -y lighttpd
cp /etc/lighttpd/lighttpd.conf /etc/lighttpd/lighttpd.conf.default

# create PAC file
cat << EOT > /var/www/html/example.pac
function FindProxyForURL(url, host) {
    return "PROXY ${ECS_US_SQUID_IP}:3128";
}
EOT

# enable and start lighttpd
systemctl enable lighttpd
systemctl start lighttpd

echo
echo "--- Creating configuration files ---"
echo

mkdir -p /root/vpn-instructions
cd /root/vpn-instructions
cp /root/vpn-pems/vpn-ca-cert.crt .

cat << EOF > vpn-ios-or-mac.mobileconfig
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
<plist version='1.0'>
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>IKEv2</key>
      <dict>
        <key>AuthenticationMethod</key>
        <string>None</string>
        <key>ChildSecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>DiffieHellmanGroup</key>
          <integer>21</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>DeadPeerDetectionRate</key>
        <string>Medium</string>
        <key>DisableMOBIKE</key>
        <integer>0</integer>
        <key>DisableRedirect</key>
        <integer>0</integer>
        <key>EnableCertificateRevocationCheck</key>
        <integer>0</integer>
        <key>EnablePFS</key>
        <true/>
        <key>ExtendedAuthEnabled</key>
        <true/>
        <key>IKESecurityAssociationParameters</key>
        <dict>
          <key>EncryptionAlgorithm</key>
          <string>AES-256-GCM</string>
          <key>IntegrityAlgorithm</key>
          <string>SHA2-384</string>
          <key>DiffieHellmanGroup</key>
          <integer>21</integer>
          <key>LifeTimeInMinutes</key>
          <integer>1440</integer>
        </dict>
        <key>RemoteAddress</key>
        <string>${VPNHOST}</string>
        <key>RemoteIdentifier</key>
        <string>${VPNHOST}</string>
        <key>UseConfigurationAttributeInternalIPSubnet</key>
        <integer>0</integer>
      </dict>
      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key>
        <integer>1</integer>
      </dict>
      <key>PayloadDescription</key>
      <string>Configures VPN settings</string>
      <key>PayloadDisplayName</key>
      <string>VPN</string>
      <key>PayloadIdentifier</key>
      <string>com.apple.vpn.managed.$(uuidgen)</string>
      <key>PayloadType</key>
      <string>com.apple.vpn.managed</string>
      <key>PayloadUUID</key>
      <string>$(uuidgen)</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>Proxies</key>
      <dict>
        <key>HTTPEnable</key>
        <integer>0</integer>
        <key>HTTPSEnable</key>
        <integer>0</integer>
        <key>ProxyAutoConfigEnable</key>
        <integer>1</integer>
        <key>ProxyAutoConfigURLString</key>
        <string>http://${PRIVATE_IP}/example.pac</string>
      </dict>
      <key>UserDefinedName</key>
      <string>${VPNHOST}</string>
      <key>VPNType</key>
      <string>IKEv2</string>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>IKEv2 VPN configuration (${VPNHOST})</string>
  <key>PayloadIdentifier</key>
  <string>com.mackerron.vpn.$(uuidgen)</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>$(uuidgen)</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
EOF

cat << EOF > vpn-ubuntu-client.sh
#!/bin/bash -e
if [[ \$(id -u) -ne 0 ]]; then echo "Please run as root (e.g. sudo ./path/to/this/script)"; exit 1; fi

read -p "VPN username (same as entered on server): " VPNUSERNAME
while true; do
read -s -p "VPN password (same as entered on server): " VPNPASSWORD
echo
read -s -p "Confirm VPN password: " VPNPASSWORD2
echo
[ "\$VPNPASSWORD" = "\$VPNPASSWORD2" ] && break
echo "Passwords didn't match -- please try again"
done

apt-get install -y curl strongswan libstrongswan-standard-plugins libcharon-extra-plugins
apt-get install -y libcharon-standard-plugins || true  # 17.04+ only

cp vpn-ca-cert.crt /etc/ipsec.d/cacerts/

grep -Fq 'jawj/IKEv2-setup' /etc/ipsec.conf || echo "
# https://github.com/jawj/IKEv2-setup
conn ikev2vpn
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev2
        ike=aes256gcm16-prfsha384-ecp521!
        esp=aes256gcm16-ecp521!
        leftsourceip=%config
        leftauth=eap-mschapv2
        eap_identity=\${VPNUSERNAME}
        right=${VPNHOST}
        rightauth=pubkey
        rightid=${VPNHOST}
        rightsubnet=0.0.0.0/0
        auto=add  # or auto=start to bring up automatically
" >> /etc/ipsec.conf

grep -Fq 'jawj/IKEv2-setup' /etc/ipsec.secrets || echo "
# https://github.com/jawj/IKEv2-setup
\${VPNUSERNAME} : EAP \"\${VPNPASSWORD}\"
" >> /etc/ipsec.secrets

ipsec restart
sleep 5  # is there a better way?

echo "Bringing up VPN ..."
ipsec up ikev2vpn
ipsec statusall

echo
echo "To disconnect: ipsec down ikev2vpn"
echo "To resconnect: ipsec up ikev2vpn"
echo "To connect automatically: change auto=add to auto=start in /etc/ipsec.conf"
EOF

UUID=$(uuid -v4)
cat << EOF > vpn-android-profile.sswan
{
    "uuid": "${UUID}",
    "name": "${VPNHOST}",
    "type": "ikev2-eap",
    "remote": {
        "addr": "${VPNHOST}",
        "cert": "VPN Server root CA" 
    }
}
EOF

# create PAC file
cat << EOT > vpn-android.pac
function FindProxyForURL(url, host) {
  if (isResolvable(host))
    return "DIRECT";
  else
    return "PROXY ${ECS_US_SQUID_IP}:3128";
}
EOT

cat << EOF > vpn-instructions.txt
== VPN Users ==

One VPN user has been created:
Username: "${VPNUSERNAME}"
Password: "${VPNPASSWORD}"

Add or change VPN users in /etc/ipsec.secrets
The line format for each user is:

someusername : EAP "somepassword"

Edit usernames and passwords as you see fit (but don not touch the first line, which specifies the server certificate). 
Save the change and let strongSwan pick up the change by:

ipsec secrets

== VPN Client: iOS and macOS ==

Download vpn-ios-or-mac.mobileconfig to your iOS or macOS device. Simply open this to install. You will be asked for your device PIN or password, and your VPN username and password, not necessarily in that order.

== Windows ==

This configuration supports Windows 10. Download vpn-ca-cert.crt and save to your Downloads folder, then open Administrater PowerShell (right click Start button, select Windows PowerShell (Admin), click Yes in the User Account Control window), copy the following four commands and paste in the "Administrator: Windows PowerShell" window and press Enter:

certutil –addstore -enterprise –f "Root" ~\Downloads\vpn-ca-cert.crt

Add-VpnConnection -Name "${VPNHOST}" -ServerAddress "${VPNHOST}" -TunnelType IKEv2 -EncryptionLevel Maximum -AuthenticationMethod EAP  -RememberCredential

Set-VpnConnectionIPsecConfiguration -ConnectionName "${VPNHOST}" -AuthenticationTransformConstants GCMAES256 -CipherTransformConstants GCMAES256 -EncryptionMethod GCMAES256 -IntegrityCheckMethod SHA384 -DHGroup ECP384 -PfsGroup ECP384 -Force

Set-VpnConnectionProxy -Name "${VPNHOST}" -AutoConfigurationScript "http://${PRIVATE_IP}/example.pac"

# Run the following command to retain access to the local network (e.g. printers, file servers) while the VPN is connected.
# On a home network, you probably want this. On a public network, you probably don't.

Set-VpnConnection -Name "${VPNHOST}" -SplitTunneling \$True


== VPN Client: Android ==

Download the latest strongSwan apk (verion 1.8.0 or later) at https://download.strongswan.org/Android/ and install.
Open the strongSwan app, select "CA certificates" in the three dots menu, press the three dots again and select "Import cerficiate", locate vpn-ca-cert.crt and press "IMPORT CERTIFICATE".
Go back to the app frontpage, select "Import VPN profile" in the three dots menu, locate vpn-android-profile.sswan, enter VPN username and password.

Go to Android Connections => WiFi, open the settings of the WiFi network, select Advanced => Proxy, change to "Auto-config" and provide the PAC web address https://pac-bucket.oss-cn-shanghai.aliyuncs.com/vpn-android.pac, save.


== VPN Client: Ubuntu ==

A bash script to set up strongSwan as a VPN client is generated as vpn-ubuntu-client.sh. You will need to download it along with vpn-ca-cert.crt and save them in the same directory. chmod +x vpn-ubuntu-client.sh and then run the script as root.

EOF

echo
echo "--- How to connect ---"
echo
echo "Connection instructions can be found in /root/vpn-instructions"

# necessary for IKEv2?
# Windows: https://support.microsoft.com/en-us/kb/926179
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent += AssumeUDPEncapsulationContextOnSendRule, DWORD = 2
