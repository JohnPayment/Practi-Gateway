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

gate = route -n | grep \"$3\" | grep 'UG[ \t]' | awk '{print $2}' | awk '{split($1,array,"\n")} END{print array[1]}'
range = route -n | grep "em1" | grep 'UG[ \t]' | awk '{print $2}' | awk '{split($1,array,"\n")} END{print array[1]}' | awk '{split($1,array,".")} END{print array[1]"."array[2]"."array[3]".0"}'
access = $1 | awk '{split($1,array,".")} END{print array[1]"."array[2]"."array[3]".1"}'

ifconfig $1 up $access netmask 255.255.255.0
sleep 2

sysctl -w net.ipv4.ip_forward=1

route add -net $range netmask 255.255.255.0 gw $gate
route add -net $2/24 gw $gate

iptables -F
iptables -t nat -F
iptables -X
iptables -t nat -X
iptables -t nat -A POSTROUTING -o $3 -j MASQUERADE
iptables -A FORWARD -i $1 -j ACCEPT

service NetworkManager stop
