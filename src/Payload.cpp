#include "Payload.h"

using namespace std;

// Forward Declarations
unsigned short in_cksum(unsigned short *ptr, int nbytes);

// Structs
/* From synhose.c by knight */
struct pseudo_header
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
} pseudo_header;

// Logging Variables
vector<protoRule> inprRules;
vector<protoRule> outprRules;

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	loadPayloadRules()
-- DATE:		2015-03-30
-- PARAMETERS:	const char* file - A string containing the name of the file to be opened.
-- RETURN:		void
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		This loads the rules that determine which packets should have their payload
--				replaced.
------------------------------------------------------------------------------------------------
*/
void loadPayloadRules(const char* file)
{
	ifstream logRules(file);
	if(logRules.fail())
	{
		cout << "No log file at: " << file << endl;
		return;
	}
	if(logRules.is_open() == true)
	{
		string data;
		protoRule *lastRule = NULL;
		while(getline(logRules, data))
		{
			vector<string> words;
			string_split(data, ' ', words);
			for(size_t i = 0; i < words.size(); ++i)
			{
				// Stops reading line when # is found
				if(words[i].find("#") != string::npos)
				{
					break;
				}
				// Starting new rule chains
				if(words[i].find("in") != string::npos)
				{
					protoRule newRule = {};
					inprRules.push_back(newRule);
					lastRule = &(inprRules.back());
				} else if(words[i].find("out") != string::npos)
				{
					protoRule newRule = {};
					outprRules.push_back(newRule);
					lastRule = &(outprRules.back());
				} else if(words[i].find("_") != string::npos)
				{
					lastRule->nextRule = (protoRule*)malloc(sizeof(protoRule));
					lastRule = lastRule->nextRule;
					memset(lastRule, 0, sizeof(protoRule));
				// Setting the Protocol of the current rule
				} else if(words[i].find("ip") != string::npos)
				{
					lastRule->protocol = protocols::ip;
				} else if(words[i].find("tcp") != string::npos)
				{
					lastRule->protocol = protocols::tcp;
				} else if(words[i].find("udp") != string::npos)
				{
					lastRule->protocol = protocols::udp;
				} else if(words[i].find("icmp") != string::npos)
				{
					lastRule->protocol = protocols::icmp;
				} else if(words[i].find("flags") != string::npos)
				{
					if(i+2 > words.size())
					{
						break;
					}
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->field[j] == 0)
						{
							switch(lastRule->protocol)
							{
								case protocols::ip: lastRule->field[j] = ipFields::flags; break;
								case protocols::tcp: lastRule->field[j] = tcpFields::flags; break;
								case protocols::dns: lastRule->field[j] = dnsFields::flags; break;
							}
							lastRule->value[j] = int(std::strtol(words[i+2].c_str(), 0, 10));
							break;
						}
					}
				} else if(words[i].find("protocol") != string::npos)
				{
					if(i+2 > words.size())
					{
						break;
					}
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->field[j] == 0)
						{
							lastRule->field[j] = ipFields::protocol;
							lastRule->value[j] = int(std::strtol(words[i+2].c_str(), 0, 10));
							break;
						}
					}
				} else if(words[i].find("src") != string::npos)
				{
					if(i+2 > words.size())
					{
						break;
					}
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->field[j] == 0)
						{
							switch(lastRule->protocol)
							{
								case protocols::ip: 
									lastRule->field[j] = ipFields::src;
									lastRule->value[j] = inet_addr(words[i+2].c_str());
									break;
								case protocols::tcp: 
									lastRule->field[j] = tcpFields::src;
									lastRule->value[j] = int(std::strtol(words[i+2].c_str(), 0, 10));
									break;
								case protocols::udp: 
									lastRule->field[j] = udpFields::src;
									lastRule->value[j] = int(std::strtol(words[i+2].c_str(), 0, 10));
									break;
							}
							break;
						}
					}
				} else if(words[i].find("dst") != string::npos)
				{
					if(i+2 > words.size())
					{
						break;
					}
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->field[j] == 0)
						{
							switch(lastRule->protocol)
							{
								case protocols::ip: 
									lastRule->field[j] = ipFields::dst;
									lastRule->value[j] = inet_addr(words[i+2].c_str());
									break;
								case protocols::tcp: 
									lastRule->field[j] = tcpFields::dst;
									lastRule->value[j] = int(std::strtol(words[i+2].c_str(), 0, 10));
									break;
								case protocols::udp: 
									lastRule->field[j] = udpFields::dst;
									lastRule->value[j] = int(std::strtol(words[i+2].c_str(), 0, 10));
									break;
							}
							break;
						}
					}
				// TCP fields
				} else if(words[i].find("type") != string::npos)
				{
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->field[j] == 0)
						{
							lastRule->field[j] = icmpFields::type;
							lastRule->value[j] = int(std::strtol(words[i+2].c_str(), 0, 10));
							break;
						}
					}
				} else if(words[i].find("code") != string::npos)
				{
					if(i+2 > words.size())
					{
						break;
					}
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->field[j] == 0)
						{
							lastRule->field[j] = icmpFields::code;
							lastRule->value[j] = int(std::strtol(words[i+2].c_str(), 0, 10));
							break;
						}
					}
				// Comparators + value management
				} else if(words[i].find("==") != string::npos)
				{
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->comparason[j] == 0)
						{
							lastRule->comparason[j] = comparators::equal;
							break;
						}
					}
				} else if(words[i].find("!=") != string::npos)
				{
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->comparason[j] == 0)
						{
							lastRule->comparason[j] = comparators::not_equal;
							break;
						}
					}
				} else if(words[i].find(">>") != string::npos)
				{
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->comparason[j] == 0)
						{
							lastRule->comparason[j] = comparators::greater;
							break;
						}
					}
				} else if(words[i].find(">=") != string::npos)
				{
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->comparason[j] == 0)
						{
							lastRule->comparason[j] = comparators::greater_equal;
							break;
						}
					}
				} else if(words[i].find("<<") != string::npos)
				{
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->comparason[j] == 0)
						{
							lastRule->comparason[j] = comparators::less;
							break;
						}
					}
				} else if(words[i].find("<=") != string::npos)
				{
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->comparason[j] == 0)
						{
							lastRule->comparason[j] = comparators::less_equal;
							break;
						}
					}
				} else if(words[i].find("rep") != string::npos)
				{
					if(lastRule->logRule == NULL)
					{
						lastRule->logRule = (logRule*)malloc(sizeof(payload));
						memset(lastRule->logRule, 0, sizeof(payload));
					}
					++i;

					// File IO c Style for easier byte-accuracy control
					FILE* fp;
					fp = fopen(words[i].c_str(), "rb");
					size_t j = 0;
					while((((payload*)(lastRule->logRule))->buffer[j] = fgetc(fp)) != EOF && j < 4000)
					{
						++j;
					}
					((payload*)(lastRule->logRule))->payloadSize = j;
					fclose(fp);
				}
			}
		}
		logRules.close();
	}
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	unloadPayloadRules()
-- DATE:		2015-03-30
-- PARAMETERS:	N/A
-- RETURN:		void
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		Cleans up potentially malloced memory within the Rules vectors.
------------------------------------------------------------------------------------------------
*/
void unloadPayloadRules()
{
	protoRule *rulePointer = 0;
	for(size_t i = 0; i < inprRules.size(); ++i)
	{
		rulePointer = inprRules[i].nextRule;
		cleanRuleChain(rulePointer);
	}

	for(size_t i = 0; i < outprRules.size(); ++i)
	{
		rulePointer = outprRules[i].nextRule;
		cleanRuleChain(rulePointer);
	}
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	IncomingReplacement()
-- DATE:		2015-03-30
-- PARAMETERS:	const unsigned char *packetData - The raw packet data
--				size_t packetsize - The total size of the packet data
-- RETURN:		The new size of the packetData. 0 If there is no change.
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		Checks incoming packets for whether they should have their payload replaced.
------------------------------------------------------------------------------------------------
*/
size_t IncomingReplacement(unsigned char *packetData, size_t packetSize)
{
	payload* rule;
	for(size_t i = 0; i < inprRules.size(); ++i)
	{
		rule = (payload*) checkRule(&(inprRules[i]), (recv_tcp*)packetData, packetSize);
		if(rule != NULL)
		{
			return replacePayload(rule, packetData, packetSize);
		}
	}
	return packetSize;
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	OutgoingReplacement()
-- DATE:		2015-03-30
-- PARAMETERS:	const unsigned char *packetData - The raw packet data
--				size_t packetsize - The total size of the packet data
-- RETURN:		The new size of the packetData.
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		Checks outgoing packets for whether they should have their payload replaced.
------------------------------------------------------------------------------------------------
*/
size_t OutgoingReplacement(unsigned char *packetData, size_t packetSize)
{
	payload* rule;
	for(size_t i = 0; i < outprRules.size(); ++i)
	{
		rule = (payload*) checkRule(&(outprRules[i]), (recv_tcp*)packetData, packetSize);
		if(rule != NULL)
		{
			return replacePayload(rule, packetData, packetSize);
		}
	}
	return packetSize;
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	replacePayload()
-- DATE:		2015-03-30
-- PARAMETERS:	payload* load - Pointer to structure defining the new payload
--				unsigned char *packetData - Pointer to the packetData
--				size_t packetSize - The total size of the packet in bytes
-- RETURN:		The new packetSize.
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		replaces the payload of the packet and recalculates checksums.
------------------------------------------------------------------------------------------------
*/
size_t replacePayload(payload* load, unsigned char *packetData, size_t packetSize)
{
	if(load != NULL)
	{
		size_t ipSize = sizeof(struct iphdr);
		size_t tcpSize = sizeof(struct tcphdr);
		size_t udpSize = sizeof(struct udphdr);
		size_t icmpSize = sizeof(struct icmphdr);

		unsigned char protocol = 0;
		size_t payloadOffset = 0;
		switch(((iphdr*)packetData)->protocol)
		{
			case 6: //TCP
				protocol = protocols::tcp;
				payloadOffset = ipSize + tcpSize;
				break;
			case 17: // UDP
				protocol = protocols::udp;
				payloadOffset = ipSize + udpSize;
				break;
			case 1: // ICMP
				protocol = protocols::icmp;
				payloadOffset = ipSize + icmpSize;
				break;
			default:
				protocol = protocols::ip;
				payloadOffset = ipSize;
		}

		realloc(packetData, payloadOffset + load->payloadSize);
		memcpy((packetData + payloadOffset), load->buffer, load->payloadSize);

		((iphdr*)packetData)->tot_len = payloadOffset + load->payloadSize;
		((iphdr*)packetData)->check = 0;
		((iphdr*)packetData)->check = in_cksum((unsigned short *)packetData, 20);

		/*switch(protocol)
		{
			case protocols::tcp:
				pseudo_header.source_address = (iphdr*)packetData->saddr;
				pseudo_header.dest_address = (iphdr*)packetData->daddr;
				pseudo_header.placeholder = 0;
				pseudo_header.protocol = IPPROTO_TCP;
				pseudo_header.tcp_length = htons(20);
				((tcphdr*)(packetData + ipSize))->check = in_cksum((unsigned short *)&pseudo_header, 32);
				break;
			case protocols::udp:
				pseudo_header.source_address = (iphdr*)packetData->saddr;
				pseudo_header.dest_address = (iphdr*)packetData->daddr;
				pseudo_header.placeholder = 0;
				pseudo_header.protocol = IPPROTO_UDP;
				pseudo_header.tcp_length = htons(8);
				((udphdr*)(packetData + ipSize))->check = in_cksum((unsigned short *)&pseudo_header, 20);
				break;
		}*/

		return payloadOffset + load->payloadSize;
	}

	return packetSize;
}

// clipped from ping.c
// I had made superficial formatting changes to the below (mostly comments) so as to preserve line space

/* Copyright (c)1987 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * dupliated in all such forms and that any documentation, advertising 
 * materials, and other materials related to such distribution and use
 * acknowledge that the software was developed by the University of
 * California, Berkeley. The name of the University may not be used
 * to endorse or promote products derived from this software without
 * specific prior written permission. THIS SOFTWARE IS PROVIDED ``AS
 * IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
 * WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHATIBILITY AND 
 * FITNESS FOR A PARTICULAR PURPOSE
 */
unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register long    sum;     // assumes long == 32 bits

	u_short          oddbyte;
	register u_short answer;  // assumes u_short == 16 bits

	/*
	 * Our algorithm is simple, using a 32-bit accumulator (sum),
	 * we add sequential 16-bit words to it, and at the end, fold back
	 * all the carry bits from the top 16 bits into the lower 16 bits.
	 */
	sum = 0;
	while (nbytes > 1)  
	{
		sum += *ptr++;
		nbytes -= 2;
	}

	// mop up an odd byte, if necessary
	if(nbytes == 1) 
	{
		oddbyte = 0;                             // make sure top half is zero
		*((u_char *) &oddbyte) = *(u_char *)ptr; // one byte only
		sum += oddbyte;
	}

	// Add back carry outs from top 16 bits to low 16 bits.
	sum  = (sum >> 16) + (sum & 0xffff); // add high-16 to low-16
	sum += (sum >> 16);	                 // add carry
	answer = ~sum;                       // ones-complement, then truncate to 16 bits
	return(answer);
}

// This takes a host name and converts it to an usable address
// This is unchanged from Rowland's work, who himself got it from an unknown source
unsigned int host_convert(char *hostname)
{
	static struct in_addr i;
	struct hostent *h;
	i.s_addr = inet_addr(hostname);
	if(i.s_addr == -1)
	{
		h = gethostbyname(hostname);
		if(h == NULL)
		{
			fprintf(stderr, "cannot resolve %s\n", hostname);
			exit(0);
		}
		bcopy(h->h_addr, (char *)&i.s_addr, h->h_length);
	}
	return i.s_addr;
} /* end resolver */

