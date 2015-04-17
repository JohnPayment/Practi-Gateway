==============
   OVERVIEW
==============
Pacti-Gateway is a software suite which combines hostapd, dnsmasq, iptables, shell scripts and 
C Code to provide a single source for turning a linux machine into a wireless network gateway.
In addition to basic authentication, DHCP and routing functionality, it also provides a network
firewall, customizable logging capabilities and an experimental Payload Replacement module.

==============
 INSTALLATION
==============
If you are running a fedora machine or a machine which has yum installed:
-------------------------------------------------------------------------
1. Run the included install script called "install.sh" to install all necessary libraries
   for building and running the Practi-Gateway program suite.

If you are running another distribution:
----------------------------------------
Please note that this program suite has not been tested on other distributions and as such
may require additional work to get running on them.

The following applications and libraries must be installed for the Practi-Gateway suite to
run properly.
	1. ifconfig
	|--> Used to enable the wireless interface and set its IP address
	2. iptables
	|--> Used to act as a firewall for the network
	|--> Used to enable network forwarding/masquerade
	|--> Used to pass packets to userspace for logging and payload replacement
	3. hostapd
	|--> Used for wireless network authentication, including WPA/2 password management
	4. dnsmasq
	|--> Used to provide DHCP Services to network clients (IE. Providing IP Addresses)
	|--> Acts as a DNS Server for the internal network
	5. gcc-c++
	|--> Used to compile the project
	5. libnfnetlink
	|--> Used to access packets passed from iptables in userspace

==============
 CONFIG FILES
==============
Multiple-File Values:
---------------------
The following values are ones which must be synchronous over more than 1 file.

WLAN Interface - This is the interface name for the wireless network interface from which your 
|                network will be broadcast. The same interface must be defined in each of these
|                Variables.
|-->newNetup.sh  : WDEV
|-->hostapd.conf : interface
|-->dnsmasq.conf : interface

Internal IP - This is the IP Address Range used by the internal network. When defining the 
|             Gateway address, it must be defined such that it exists within the network mask.
|             For example, A mask of 192.168.0.0/24 must have a host address between
|             192.168.0.1 and 192.168.0.254
|-->newNetup.sh  : intIP (Gateway Address)
|-->dnsmasq.conf : dhcp-range (Network Mask)

config:
-------
These values are used by the compiled program and mostly have to do with directory information for
rule and log data. These are white-space sensitive and including any whitespace on the front or
back of any directories may result in an error in reading that directory.

logging-filter     - Takes a directory/file location for the logging rules file.
repo-filter        - Takes a directory/file location for the payload replacement rules file.
logging            - Takes "on" or "off". Controls whether or not logging is enabled.
smartlookup        - Takes "on" or "off". Controls whether or not smart logging is enabled.
                     Smartlogging will not run if logging is disabled.
whois-dir          - Takes a directory location for where stored whois results should be written 
                     to a read from.
ports              - Takes a directory/file location for the port use association file.
payloadreplacement - Takes "on" or "off". Controls whether or not payload replacement is enabled.

newNetup.sh:
------------
This file controls two aspects of the program suite. First of all, it is used for initialization
of the network interface and port forwarding and as such takes several variables used for that
purpose. Second of all, it controls whether or not the firewall is active and, in cases where it
is, provides an interface for implementing firewall rules.

IDEV - The external network interface. This should typically be connected to an existing router.
WDEV - The internal network interface. This should be a wireless interface and will act as the
       Gateway for the new network.
intIP - This is the gatway ip address for the internal network, which will be assigned to WDEV.

firewallMode - Takes "ACCEPT" and "DROP". ACCEPT will disable the firewall, while DROP will run
               it as an inclusive firewall where only explicitly specified ports and types are
               allowed.
tcpPortsIn   - A list of allowed TCP ports for incoming DST and outgoing SRC
tcpPortsOut  - A list of allowed TCP ports for incoming SRC and outgoing DST
udpPortsIn   - A list of allowed UDP ports for incoming DST and outgoing SRC
udpPortsOut  - A list of allowed UDP ports for incoming SRC and outgoing DST
icmpTypes    - A list of allowed ICMP types

hostapd.conf:
-------------
This file is the config file for hostapd, which chiefly manages authentication to the wireless
network. Noted below are the configuration variables that are relevant to this project. Changing
other variables may result in unexpected behaviour and is not advised for people unfamiliar with
the software.

It is very important that no non-comment lines end in a blank space. The parser used by
hostapd is sensitive to this and it may not work correctly if it encounters lines ending in white
space.

wpa            - This sets the wpa mode. 0 is disabled. 1 is wpa1 2 is wpa2. 3 is supposed to
                 support both wpa1 and wpa2, but in practice this usually results in hostapd not
                 working properly. It is advised that only 0 (for disabled) and 2 (for wpa2 
                 enabled) be used.
wpa_passphrase - This specifies the passphrase used for authentication with the network.
                 This may not contain spaces or special characters and should be between
                 8 and 63 characters long.
interface      - This is the name of the wireless interface on which the network is being
                 broadcast. This should be the same as equivalent values in the newNetup.sh and
                 dnsmasq.conf files.
channel        - This is the wireless channel. Any value between 1 and 9 is valid, with the one
                 that has the least competing local traffic usually being ideal. 0 should have it
                 automatically pick the least busy channel on startup, but in practice this will
                 usually result in hostapd crashing.
ssid           - The ssid of the network. It may not have spaces or special characters and may be
                 no larger than 32 characters.

dnsmasq.conf:
-------------
This is the config file for dnsmasq, which acts as both a dns server and a DHCP server for the
server. The variables noted below are those most relevant to configuration of dnsmasq within the
scope of this project.

interface  - This is the name of the wireless interface on which the network is being
             broadcast. This should be the same as equivalent values in the newNetup.sh and
             hostapd.conf files.
dhcp-range - This specifies 3 important aspects of the dhcp functionality. First of all, it
             defines a range of ip addresses which can be allocated to clients on the network.
             Second of all, it defines the network mask. Note that both the previous range and
             the gateway ip address defined within newNetup.sh must be within this mask, but also
             that the gateway IP address does NOT need to be within the ip assignment range.
             Finally, this defines the maximum amount of time an IP address remains valid, before
             a client must be assigned a new one.

Logging Rules:
--------------
This is a file whose location is defined within config. By default it is ./filter/logger, which
defines several example rules.

A logging rule can be specified to apply to incoming packets (those entering the network), 
outgoing packets (those exiting the network) and packets going both ways using IN, OUT and BOTH,
respectively. The declaration of one of these three at the start of a line indicates a new rule,
while an underscore "_" indicates an additional sub-rule and LOG indicates one or more logging
parameter. each sub-rule declared used "_" is in a boolean AND relationship with every other
sub rule. In other words, they must all be true in order for the rule to be valid and the packet
to be logged. Conversely, more than 1 comparator on the same line will be treated as a boolean OR
and if any one of them is true, that sub-rule will be valid. Comments are also supported by
starting a line with "#".

Each rule line may only define one protocol at a time, with this definition also implicitly
acting as a rule that a valid packet must contain that protocol. Supported protocols include
IP, TCP, UDP and ICMP.

Fields declared on a LOG line are used to determine which header values should be logged from
valid packets. Like with rule lines, this must declare a protocol, with multiple protocol
headers requiring multiple lines. Unlike rule lines, this does not block packets which do not
contain the protocol you define. Regardless of what is defined here, the raw payload of a packet
will always be logged.

The following comparators are supported:
== : equals
!= : not equals
>> : greater than
>= : greater than or equal
<< : less than
<= : less than or equal

The following are supported values which can be compared:
IP   - PROTOCOL : The protocol as defined within the IP Header
     - SRC : The source IP address defined in the IP Header
     - DST : The destination IP address defined in the IP Header
TPC  - SRC : The source port defined in the TCP Header
     - DST : The destination port defined in the TCP Header
UDP  - SRC : The source port defined in the UDP Header
     - DST : The destination port defined in the UDP Header
ICMP - TYPE : The ICMP Type defined in the ICMP Header
     - CODE : The ICMP Code defined in the ICMP Header

Valid LOG fields:
IP   - VERSION
     - HLEN
     - TOS
     - TLEN
     - ID
     - FLAGS
     - FRAG
     - TTL
     - PROTOCOL
     - CHKSUM
     - SRC
     - DST

TCP  - SRC
     - DST
     - SEQ
     - ACK
     - FLAGS
     - WINDOW
     - CHKSUM
     - URG

UDP  - SRC
     - DST
     - LEN
     - CHKSUM

ICMP - TYPE
     - CODE
     - CHKSUM

examples:
# Packet must have a src ip of 10.240.47.106 AND a dst ip of 216.58.216.163
# It will log src and dst port of TCP packets, but will log src and dst IP of any packet that
# passes the rule
OUT IP SRC == 10.240.47.106
_   IP DST == 216.58.216.163
LOG IP SRC DST
LOG TCP SRC DST

# Packet must have a src ip of 10.240.47.106 OR a dst ip of 216.58.216.163
IN IP SRC == 10.240.47.106 DST == 216.58.216.163

# The first line of this rule is redundant, as declaring TCP on the second line is functionally
# equivalent.
IN IP PROTOCOL == 6
_  TCP DST == 43

# This rule will never find a valid packet, as in order for a packet to be valid it must have both
# The UDP and the TCP protocol.
BOTH UDP SRC == 0
_    TCP SRC == 0

Payload Replacement Rules:
--------------------------
This is a file whose location is defined within config. By default it is ./filter/replacer, which
defines an example rule.

The syntax for payload replacement is largely the same as that for Logging, with the following
exceptions:

 - Payload Replacement does not support the "BOTH" case, but must use only either "IN" or "OUT".
 - instead of defining which fields to be logged with a "LOG" line, payload replacement has a
   "REP" line which defines a file with which to replace the payload.

The specified file can have any content including being completely empty, but in the case of large
files only the first 4000 bytes will be read. Normally, the entire read segment will be written
into the payload. However, TCP packets with options defined may ignore the last few bytes, if the
size is close to the 4000 byte limit.

