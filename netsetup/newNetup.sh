#!/bin/sh
##############################
### USER DEFINED VARIABLES ###
##############################
# IDEV is the device which has a (working) IP address. 
IDEV=em1
# WDEV is the name of the wlan-device (see iwconfig)
WDEV=wlp0s26f7u1

# The IP for this machine on the new, internal network
intIP=192.168.10.1/24

# Default Access mode for the firewall.
# DROP will enable the firewall with inclusive rules, while ACCEPT will disable it
firewallMode=ACCEPT
# Allowed Firewall ports and Types
tcpPortsIn="22 80 443"
tcpPortsOut="22 80 443"
udpPortsIn="43"
udpPortsOut="43"
icmpTypes="8"
##############################
### USER DEFINED VARIABLES ###
##############################

systemctl stop firewalld.service

iwconfig $WDEV txpower auto

# IP-address space from where we give dynamic IP-addresses.
ifconfig $WDEV $intIP up

iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

iptables -I INPUT -i $WDEV -j ACCEPT

echo "1" > /proc/sys/net/ipv4/ip_forward

#route add -net 192.168.2.0 netmask 255.255.255.0 gw 192.168.2.254
#route add -net 10.240.47.0/24 gw 10.240.47.1

iptables -t nat -A POSTROUTING -j MASQUERADE

iptables -P FORWARD $firewallMode
if [ "$firewallMode" == "DROP" ]
then
	iptables -N TCP
	iptables -A TCP
	iptables -N UDP
	iptables -A UDP
	iptables -N ICMP
	iptables -A ICMP

	iptables -A FORWARD -p tcp -j TCP
	iptables -A FORWARD -p udp -j UDP
	iptables -A FORWARD -p icmp -j ICMP

	for varname in $tcpPortsIn
	do
		iptables -A TCP -i $WDEV -o $IDEV -p tcp --sport $varname -m state --state NEW,ESTABLISHED -j NFQUEUE --queue-num 0
		iptables -A TCP -i $IDEV -o $WDEV -p tcp --dport $varname -m state --state NEW,ESTABLISHED -j NFQUEUE --queue-num 1
	done

	for varname in $tcpPortsOut
	do
		iptables -A TCP -i $IDEV -o $WDEV -p tcp --sport $varname -m state --state NEW,ESTABLISHED -j NFQUEUE --queue-num 1
		iptables -A TCP -i $WDEV -o $IDEV -p tcp --dport $varname -m state --state NEW,ESTABLISHED -j NFQUEUE --queue-num 0
	done

	for varname in $udpPortsIn
	do
		iptables -A UDP -i $WDEV -o $IDEV -p udp --sport $varname -m state --state NEW,ESTABLISHED -j NFQUEUE --queue-num 0
		iptables -A UDP -i $IDEV -o $WDEV -p udp --dport $varname -m state --state NEW,ESTABLISHED -j NFQUEUE --queue-num 1
	done

	for varname in $udpPortsOut
	do
		iptables -A UDP -i $IDEV -o $WDEV -p udp --sport $varname -m state --state NEW,ESTABLISHED -j NFQUEUE --queue-num 1
		iptables -A UDP -i $WDEV -o $IDEV -p udp --dport $varname -m state --state NEW,ESTABLISHED -j NFQUEUE --queue-num 0
	done

	for varname in $icmpTypes
	do
		iptables -A ICMP -i $IDEV -o $WDEV -p icmp --icmp-type $varname -m state --state NEW,ESTABLISHED -j NFQUEUE --queue-num 0
		iptables -A ICMP -i $WDEV -o $IDEV -p icmp --icmp-type $varname -m state --state NEW,ESTABLISHED -j NFQUEUE --queue-num 1
	done
else
	iptables -A FORWARD -i $IDEV -o $WDEV -j NFQUEUE --queue-num 0
	iptables -A FORWARD -i $WDEV -o $IDEV -j NFQUEUE --queue-num 1
fi

#service NetworkManager stop

dnsmasq -C ./dnsmasq.conf
sleep 2
hostapd -B ./hostapd.conf
