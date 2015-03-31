# USER-DEFINED VARIABLES
# These variables can be defined either before running or during regular opperations
# "any" indicates that any value will be expected. In other words, the variable is not used for
# filtering. A value other than this will filter out all logs which do not have that field
# containing that exact phrase.
#
# In the case of flag fields, specifying the name of a flag will include only packets which have
# that flag set.
sourcefiles = ["input.log", "output.log"]

ipsrc = ["any"]
ipdst = ["any"]
protocol = ["any"]

srcport = ["any"]
dstport = ["any"]
tcpFlags = ["any"]

icmpType = ["any"]
icmpCode = ["any"]
# END OF USER-DEFINED VARIABLES SECTION

def runFilter():
	packets = []
	for log in sourcefiles:
		with open(log, 'r') as lf:
			packet = ""
			initkeepers = [False]*8
			for i in ipsrc:
				if i == "any":
					initkeepers[0] = True
					break
			for i in ipdst:
				if i == "any":
					initkeepers[1] = True
					break
			for i in protocol:
				if i == "any":
					initkeepers[2] = True
					break
			for i in srcport:
				if i == "any":
					initkeepers[3] = True
					break
			for i in dstport:
				if i == "any":
					initkeepers[4] = True
					break
			for i in tcpFlags:
				if i == "any":
					initkeepers[5] = True
					break
			for i in icmpType:
				if i == "any":
					initkeepers[6] = True
					break
			for i in icmpCode:
				if i == "any":
					initkeepers[7] = True
					break

			for line in lf.readline():
				if "**Packet**" in line:
					keepers = initkeepers
					packets.append(packet)
					for pline in packets[-1].split('\n'):
						if "Source IP" in pline && !keepers[0]:
							for i in ipsrc:
								if i in pline:
									keepers[0] = True
									break
						if "Destination IP" in pline && !keepers[1]:
							for i in ipdst:
								if i in pline:
									keepers[1] = True
									break
						if "Protocol" in pline && !keepers[2]:
							for i in protocol:
								if i in pline:
									keepers[2] = True
									break

						if "Source Port" in pline && !keepers[3]:
							for i in srcport:
								if i in pline:
									keepers[3] = True
									break
						if "Destination Port" in pline && !keepers[4]:
							for i in dstport:
								if i in pline:
									keepers[4] = True
									break
						if "Flag" in pline && !keepers[5]:
							for i in tcpFlags:
								if i in pline && "1" in pline:
									keepers[5] = True
									break

						if "Type" in pline && !keepers[6]:
							for i in icmpType:
								if i in pline:
									keepers[6] = True
									break
						if "Code" in pline && !keepers[7]:
							for i in icmpCode:
								if i in pline:
									keepers[7] = True
									break
					for k in keepers:
						if !k:
							packets.remove(packet)
							break
					packet = ""
					
				else:
					packet += line
	while True:
		print(packets.count() + " packets found.\n")
		print("0. Display Packets\n")
		print("1. Print selection to file\n")
		print("2. Return to filter selection\n")

		choice = raw_input()

		if '0' in choice:
			index = 0
			for packet in packets:
				index += 1
				os.system("clear")
				print("\n####################\n")
				print("Packet " + index + " of " + packets.count() + "\n")
				print("####################\n")
				print(packet)
				condition = raw_input("Press Enter to continue. Press \'Q\' to exit.")
				if "q" in condition or "Q" in condition:
					break
		elif '1' in choice:
			filename = raw_input("Input File Name: ")
			with open(filename, "w") as wfile:
				index = 0
				for packet in packets:
					index += 1
					wfile.write("\n####################\n")
					wfile.write("Packet " + index + " of " + packets.count() + "\n")
					wfile.write("####################\n")
					wfile.write(packet)
		elif '2' in choice:
			break

def addParam():
	print("Select the field to which you would like to add a parameter:\n")
	print("0. Source File\n")
	print("1. IP Source Address\n")
	print("2. IP Destnication Address\n")
	print("3. Transport-Layer Protocol\n")
	print("4. Source Port\n")
	print("5. Destination Port\n")
	print("6. TCP Flags\n")
	print("7. ICMP Type\n")
	print("8. ICMP Code\n")

	choice = raw_input()
	param = raw_input("Input new Parameter: ")
	if(choice == '0'):
		sourcefiles.append(param)
	elif(choice == '1'):
		ipsrc.append(param)
	elif(choice == '2'):
		ipdst.append(param)
	elif(choice == '3'):
		protocol.append(param)
	elif(choice == '4'):
		srcPort.append(param)
	elif(choice == '5'):
		dstPort.append(param)
	elif(choice == '6'):
		tcpFlags.append(param)
	elif(choice == '7'):
		icmpType.append(param)
	elif(choice == '8'):
		icmpCode.append(param)
	else:
		print("No valid field selected.")

def removeParam():
	print("Select the field to which you would like to remove a parameter:\n")
	print("0. Source File\n")
	print("1. IP Source Address\n")
	print("2. IP Destnication Address\n")
	print("3. Transport-Layer Protocol\n")
	print("4. Source Port\n")
	print("5. Destination Port\n")
	print("6. TCP Flags\n")
	print("7. ICMP Type\n")
	print("8. ICMP Code\n")

	choice = raw_input()
	param = raw_input("Input Parameter to be removed: ")
	if(choice == '0'):
		sourcefiles.remove(param)
	elif(choice == '1'):
		ipsrc.remove(param)
	elif(choice == '2'):
		ipdst.remove(param)
	elif(choice == '3'):
		protocol.remove(param)
	elif(choice == '4'):
		srcPort.remove(param)
	elif(choice == '5'):
		dstPort.remove(param)
	elif(choice == '6'):
		tcpFlags.remove(param)
	elif(choice == '7'):
		icmpType.remove(param)
	elif(choice == '8'):
		icmpCode.remove(param)
	else:
		print("No valid field selected.")

def main():
	while True:
		os.system("clear")
		print("R - run script\n")
		print("A - Add Parameter\n")
		print("X - Remove Parameter\n")
		print("Q - Quit\n")
		print("\nFilter Parameters")
		print("\n==Source Files==")
		for i in sourcefiles:
			print("\""i + "\" ")
		print("\n==IP Source Addresses==")
		for i in ipsrc:
			print("\""i + "\" ")
		print("\n==IP Destination Addresses==")
		for i in ipdst:
			print("\""i + "\" ")
		print("\n==Transport-Layer Protocols==")
		for i in protocol:
			print("\""i + "\" ")
		print("\n==Source Port==")
		for i in srcport:
			print("\""i + "\" ")
		print("\n==Destination Port==")
		for i in dstport:
			print("\""i + "\" ")
		print("\n==TCP Flags==")
		for i in tcpFlags:
			print("\""i + "\" ")
		print("\n==ICMP Types==")
		for i in icmpType:
			print("\""i + "\" ")
		print("\n==ICMP CODES==")
		for i in icmpCode:
			print("\""i + "\" ")

		choice = raw_input()
		if choice == 'R' or choice == 'r':
		elif choice == 'A' or choice == 'a':
			addParam()
		elif choice == 'X' or choice == 'x':
			removeParam()
		elif choice == 'Q' or choice == 'q':
			break
		else:
			print("Invalid input\n")
		print("Press enter to continue. . .")
		raw_input()
main()


