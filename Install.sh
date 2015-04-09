#!/bin/sh

if [ ! -x "$(command -v ifconfig 2>&1)" ]
then
	printf "You do not appear to have ifconfig installed.\n"
	printf "ifconfig must be installed to initialize network setup.\n"
	exit 1
fi

if [ ! -x "$(command -v hostapd 2>&1)" ]
then
	yum install hostapd -y
fi

if [ ! -x "$(command -v dnsmasq 2>&1)" ]
then
	yum install dnsmasq -y
fi

yum install libnfnetlink -y
