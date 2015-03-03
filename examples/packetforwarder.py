import os
from scapy.all import *

'''USER-DEFINED VARIABLE SECTION'''
external = "em1" #The name of the network interface.
internal = "wlp0s26f7u1"
externalIP = "192.168.2.10" #The IP of the DNS server from which the target machine receives DNS responses
internalIP = "10.240.47.106" #The URL to which the target should be redirected
'''END OF USER-DEFINED VARIABLES'''

def main():
	packetFilter = "ip"

	pid = os.fork()
	try:
		if pid == 0:
			print "running out to in"
			sniff(filter=packetFilter, iface=external, prn=Responder2())
		else:
			print "running in to out"
			sniff(filter=packetFilter, iface=internal, prn=Responder())
	except KeyboardInterrupt:
		print "Quitting"

def Responder():
	def getResponse(packet):
		if packet.haslayer(IP):
			if packet[Ether].src != "ac:9e:17:5b:9b:82":
				spoofedResponse = packet
				spoofedResponse[IP].src = externalIP
				spoofedResponse[Ether].src = "00:22:15:f8:c3:42"
				spoofedResponse[Ether].dst = "20:76:00:d2:34:40"

				del spoofedResponse[IP].chksum
				if spoofedResponse.haslayer(TCP):
					del spoofedResponse[TCP].chksum
				elif spoofedResponse.haslayer(UDP):
					del spoofedResponse[UDP].chksum
				elif spoofedResponse.haslayer(ICMP):
					del spoofedResponse[ICMP].chksum

				#spoofedResponse.show2()
				sendp(spoofedResponse, iface=external, verbose=0)
			return

	return getResponse

def Responder2():
	def getResponse(packet):
		if packet.haslayer(IP):
			if packet[Ether].src != "00:22:15:f8:c3:42":
				spoofedResponse = packet
				spoofedResponse[IP].dst = internalIP
				spoofedResponse[Ether].src = "ac:9e:17:5b:9b:82"
				spoofedResponse[Ether].dst = "d0:df:9a:0d:49:63"

				del spoofedResponse[IP].chksum
				if spoofedResponse.haslayer(TCP):
					del spoofedResponse[TCP].chksum
				elif spoofedResponse.haslayer(UDP):
					del spoofedResponse[UDP].chksum
				elif spoofedResponse.haslayer(ICMP):
					del spoofedResponse[ICMP].chksum

				#spoofedResponse.show2()
				sendp(spoofedResponse, iface=internal, verbose=0)
			return

	return getResponse

def usage():
	print(" Usage: ./dnsSpoofer")
	print(" e.g. ./dnsSpoof -inter eth0 -spoof 129.168.0.1")
	print("      ./dnsSpoof -inter eth1 -spoof 127.0.0.1 -ip 192.168.0.25 -url https://www.google.ca")
	print("User-Defined Variables should be set to customize use experience.")

main()

