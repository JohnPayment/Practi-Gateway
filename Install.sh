#!/bin/sh

if [ ! -x "$(command -v yum 2>&1)" ]
then
	printf "You do not appear to have yum installed.\n"
	printf "This install script uses yum extensively and will not run without it.\n"
	exit 1
fi

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

if [ ! -x "$(command -v g++ 2>&1)" ]
then
	yum install gcc-c++ -y
fi

yum install libnfnetlink -y
