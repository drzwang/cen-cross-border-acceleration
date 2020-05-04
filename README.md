This is a reference solution for accelerating access of websites/SaaS hosted in different region/country using **Alibaba Cloud CEN (Cloud Enterprise Network)** which provides reliable full-mesh cross-border network connection with low-latency and flexible bandwidth control.  
[Ref] https://www.alibabacloud.com/campaign/cloud-enterprise-network  
Multi-national companies and organizations can leverage this solution to enable their overseas employees, branch offices or members maintain productivity with their daily business operations and routines.

In this example, a pair of Linux servers are deployed in Alibaba Cloud VPCs, one in China Shanghai region running strongSwan as an IKEv2 server, the other in US Silicon Valley region running squid proxy server. The two VPCs are interconnected via Alibaba Cloud CEN.  

<img alt="Architecture diagram" src="https://github.com/drzwang/cen-cross-border-acceleration/raw/master/ikev2_cen_squid.png">

Two scripts ([us_config_squid.sh](https://github.com/drzwang/cen-cross-border-acceleration/blob/master/us_config_squid.sh) and [cn_config_vpn.sh](https://github.com/drzwang/cen-cross-border-acceleration/blob/master/cn_config_vpn.sh)) are included to configure squid and strongSwan respectively. Instructions and profiles are generated for end users to configure VPN client on their iOS, macOS, Windows, Android and Linux devices.

**Note**: A whitelist of destination domains **must** be configured for squid proxy server to ensure compliance to local regulation.

## Steps to build up this solution:

## 1. Create VPC and VSwitch  

1.1 Create VPC *vpc-us* and vswitch in US Silicon Vallery Zone B or US Virginia Zone A.  

1.2 Create VPC *vpc-cn* and vswitch in China Shanghai Zone G.  
**Make sure vpc-cn and vpc-us CIDRs do not overlap.**  

## 2. Configure CEN  

2.1 Create CEN instance and attach *vpc-us*  
[Ref] https://www.alibabacloud.com/help/doc-detail/128625.htm  

2.2 Attach *vpc-cn* to CEN  
[Ref] https://www.alibabacloud.com/help/doc-detail/128653.htm  

2.3 Create ECS instance *ecs-us-squid*  
[Ref] https://www.alibabacloud.com/help/doc-detail/128675.htm  
- Pay-As-You-Go, US Silicon Vallery Zone B or Virginia Zone A
- t6 or t5 type, 1 GiB Memory (For production, use c6 or g6 instances instead)
- CentOS 7.6
- Select *vpc-us* and vswitch
- Assign Public IP Address, Pay-By-Traffic, bandwidth 5Mbps  

2.4 Create ECS instance *ecs-cn-vpn*  
[Ref] https://www.alibabacloud.com/help/doc-detail/128675.htm  
- Pay-As-You-Go, China Shanghai Zone G
- t6 or t5 type, 1 GiB Memory (For production, use c6 or g6 instances instead)
- Ubuntu 18.04
- Select *vpc-cn* and vswitch
- Assign Public IP Address, Pay-By-Traffic, bandwidth as needed (**equal to CEN bandwidth as in 2.6**)  

2.5 Verify CEN connectivity by ping *ecs-us-squid* from *ecs-cn-vpn*, and vice versa  

2.6 Purchase CEN bandwidth package and assign region connection  
[Ref] https://www.alibabacloud.com/help/doc-detail/128675.htm  
- CEN bandwidth package:  
  - Areas to be connected: **Mainland China** and **North America**
  - Bandwidth: As needed.
- Region connection:
  - Connected regions: **China Shanghai** and **US Sillicon Valley** or **US Virginia**
  - Bandwidth: Assign all available bandwidth  

## 3. Configure US ECS instance *ecs-us-squid*

3.1 Add Security Group rule  
[Ref] https://www.alibabacloud.com/help/doc-detail/25471.htm  
- Allow inbound all protocols from *vpc-cn* CIDR  

3.2 Install and configure squid  
```
[root@ecs-us-squid ~]# VPC_CN_CIDR=192.168.0.0/24 ./us_config_squid.sh
```
**Replace "192.168.0.0/24" with the actual CIDR of *vpc-cn*.**  

## 4. Configure China ECS instance *ecs-cn-vpn*

4.1 Convert public IP to EIP  
[Ref] https://www.alibabacloud.com/help/doc-detail/61290.htm

4.2 Add two Security Group rules  
[Ref] https://www.alibabacloud.com/help/doc-detail/25471.htm
- Allow inbound UDP port 500 from 0.0.0.0/0
- Allow inbound UDP port 4500 from 0.0.0.0/0

4.3 Configure strongSwan for IKEv2 VPN  
```
root@ecs-cn-vpn:~# ECS_US_SQUID_IP=172.16.0.1 ./cn_config_vpn.sh
```
**Replace "172.16.0.1" with the actual private IP of *ecs-us-squid*.**  

The following files will be generated under /root/vpn-instruction:
- **vpn-instructions.txt:** General client device configuration instructions.
- **vpn-ca-cert.crt:** VPN Server CA Certificate. 
- **vpn-ios-or-mac.mobileconfig:** VPN profile for iOS and macOS.
- **vpn-android-profile.sswan:** VPN profile for Android strongSwan app.
- **vpn-android.pac:** Proxy PAC file for Android.
- **vpn-ubuntu-client.sh:** Configuration script for Ubuntu Linux.

4.4 Upload PAC file to OSS bucket  
**This step is only needed when there are Android clients.**  
Create an OSS bucket in China Shanghai region, upload file */root/vpn-instructions/vpn-android.pac* to the bucket root, change the file ACL to "Public Read", take note of the URL of the file, eg.  
https://pac-bucket.oss-cn-shanghai.aliyuncs.com/vpn-android.pac  
Update the PAC web address at the end of "VPN Client: Android" section in */root/vpn-instructions/vpn-instructions.txt* to the actual URL of the example.pac file.

4.5 Verify VPN connection  
Download all generated files under */root/vpn-instruction* to client device. Configure a VPN client following vpn-instructions.txt.   Establish and verify VPN connection. Open browser and visit whatsmyip.net to verify client external IP is the ecs-us-squid EIP.

## Notes
- In order to support Windows 7 client, the ike and esp parameters in strongSwan /etc/ipsec.conf needs to include weaker ciphers eg. aes256-sha1:
```
ike=aes256-sha1-modp1024,aes256gcm16-prfsha384-ecp521,aes256gcm16-prfsha384-ecp384!
esp=aes256-sha1,aes256gcm16-ecp521,aes256gcm16-ecp384!
```
