#!/bin/sh
# /usr/local/sbin/start_hostapd.sh
# 2014-04-15 by zimon ät iki.fi
#
# See also http://www.sentabi.com/sharing-wireless-using-hostapd-on-fedora-17/

# IDEV is the device which has (workin) Internet address. 
# WDEV is the name of the wlan-device (see iwconfig)
IDEV=eth1
WDEV=wlp0s26f7u1

systemctl stop firewalld.service

iwconfig $WDEV txpower auto

# IP-address space from where we give dynamic IP-addresses.
# Check the address range matches the ones in /etc/dnsmasq.d/wlan-ap.conf
ifconfig $WDEV 10.240.47.1/24 up

#iptables -F
#iptables -X
#iptables -t nat -F
#iptables -t nat -X

#iptables -I INPUT -i $WDEV -j ACCEPT

#echo "1" > /proc/sys/net/ipv4/ip_forward

#route add -net 192.168.2.0 netmask 255.255.255.0 gw 192.168.2.254
#route add -net 10.240.47.0/24 gw 10.240.47.1

#iptables -t nat -A POSTROUTING -j MASQUERADE
#iptables -I FORWARD -i $IDEV -o $WDEV -j ACCEPT
#iptables -I FORWARD -i $WDEV -o $IDEV -j ACCEPT

#service NetworkManager stop

#systemctl restart dnsmasq
#systemctl restart hostapd

