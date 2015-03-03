#!/bin/sh
# $1 - internal interface
# $2 - internal ip
# $3 - external interface

if [ ! -x "$(command -v ifconfig 2>&1)" ]
then
printf "You do not appear to have ifconfig installed.\n"
printf "ifconfig must be installed to initialize network setup.\n"
exit 1
fi

if [ ! -x "$(command -v hostapd 2>&1)" ]
then
printf "You do not appear to have hostapd installed.\n"
printf "hostapd is used for access point authentication and must be installed for the access point to function.\n"
exit 1
fi

if [ ! -x "$(command -v dnsmasq 2>&1)" ]
then
printf "You do not appear to have dnsmasq installed.\n"
printf "dnsmasq is used for assigning IP addresses to clients and must be installed for the access point to function.\n"
exit 1
fi
