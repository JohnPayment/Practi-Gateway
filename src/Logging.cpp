#include "Logging.h"

using namespace std;

// Forward Declarations

// Logging Variables
vector<protoRule> bothRules;
vector<protoRule> inRules;
vector<protoRule> outRules;

queue<packet> inPackets;
queue<packet> outPackets;

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	loadRules()
-- DATE:		2015-03-13
-- PARAMETERS:	const char* file - A string containing the name of the file to be opened.
-- RETURN:		void
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		This loads the rules that determine what is to be logged and from which
--				packets using the rules set in the file whose name is provided.
------------------------------------------------------------------------------------------------
*/
void loadLoggingRules(const char* file)
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
					inRules.push_back(newRule);
					lastRule = &(inRules.back());
				} else if(words[i].find("out") != string::npos)
				{
					protoRule newRule = {};
					outRules.push_back(newRule);
					lastRule = &(outRules.back());
				} else if(words[i].find("both") != string::npos)
				{
					protoRule newRule = {};
					bothRules.push_back(newRule);
					lastRule = &(bothRules.back());
				// Creating a new rule within the current rule chain
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
				} else if(words[i].find("dns") != string::npos)
				{
					lastRule->protocol = protocols::dns;
				} else if(words[i].find("http") != string::npos)
				{
					lastRule->protocol = protocols::http;
				// Setting up the rule parameters
				// IP fields
				} else if(words[i].find("version") != string::npos)
				{
					if(i+2 > words.size())
					{
						break;
					}
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->field[j] == 0)
						{
							lastRule->field[j] = ipFields::version;
							lastRule->value[j] = int(std::strtol(words[i+2].c_str(), 0, 10));
							break;
						}
					}
				} else if(words[i].find("tos") != string::npos)
				{
					if(i+2 > words.size())
					{
						break;
					}
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->field[j] == 0)
						{
							lastRule->field[j] = ipFields::tos;
							lastRule->value[j] = int(std::strtol(words[i+2].c_str(), 0, 10));
							break;
						}
					}
				} else if(words[i].find("id") != string::npos)
				{
					if(i+2 > words.size())
					{
						break;
					}
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->field[j] == 0)
						{
							lastRule->field[j] = ipFields::id;
							lastRule->value[j] = int(std::strtol(words[i+2].c_str(), 0, 10));
							break;
						}
					}
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
				} else if(words[i].find("ttl") != string::npos)
				{
					if(i+2 > words.size())
					{
						break;
					}
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->field[j] == 0)
						{
							lastRule->field[j] = ipFields::ttl;
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
				} else if(words[i].find("seq") != string::npos)
				{
					if(i+2 > words.size())
					{
						break;
					}
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->field[j] == 0)
						{
							lastRule->field[j] = tcpFields::seq;
							lastRule->value[j] = int(std::strtol(words[i+2].c_str(), 0, 10));
							break;
						}
					}
				} else if(words[i].find("ack") != string::npos)
				{
					if(i+2 > words.size())
					{
						break;
					}
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->field[j] == 0)
						{
							lastRule->field[j] = tcpFields::ack;
							lastRule->value[j] = int(std::strtol(words[i+2].c_str(), 0, 10));
							break;
						}
					}
				// UDP Fields
				} else if(words[i].find("len") != string::npos)
				{
					if(i+2 > words.size())
					{
						break;
					}
					for(int j = 0; j < 4; ++j)
					{
						if(lastRule->field[j] == 0)
						{
							lastRule->field[j] = udpFields::len;
							lastRule->value[j] = int(std::strtol(words[i+2].c_str(), 0, 10));
							break;
						}
					}
				// ICMP Fields
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
				} else if(words[i].find("log") != string::npos)
				{
					unsigned char protocol = 0;
					if(lastRule->logRule == NULL)
					{
						lastRule->logRule = (logRule*)malloc(sizeof(logRule));
						memset(lastRule->logRule, 0, sizeof(logRule));
					}
					++i;
					if(words[i].find("ip") != string::npos)
					{
						protocol = protocols::ip;
					} else if(words[i].find("tcp") != string::npos)
					{
						protocol = protocols::tcp;
					} else if(words[i].find("udp") != string::npos)
					{
						protocol = protocols::udp;
					} else if(words[i].find("icmp") != string::npos)
					{
						protocol = protocols::icmp;
					} else if(words[i].find("dns") != string::npos)
					{
						protocol = protocols::dns;
					}
					++i;

					for(; i < words.size(); ++i)
					{
						switch(protocol)
						{
							case protocols::ip:
								if(words[i].find("version") != string::npos)
								{
									lastRule->logRule->ip |= ipFields::version;
								} else if(words[i].find("hlen") != string::npos)
								{
									lastRule->logRule->ip |= ipFields::hlen;
								} else if(words[i].find("tos") != string::npos)
								{
									lastRule->logRule->ip |= ipFields::tos;
								} else if(words[i].find("tlen") != string::npos)
								{
									lastRule->logRule->ip |= ipFields::tlen;
								} else if(words[i].find("id") != string::npos)
								{
									lastRule->logRule->ip |= ipFields::id;
								} else if(words[i].find("flags") != string::npos)
								{
									lastRule->logRule->ip |= ipFields::flags;
								} else if(words[i].find("frag") != string::npos)
								{
									lastRule->logRule->ip |= ipFields::frag;
								} else if(words[i].find("ttl") != string::npos)
								{
									lastRule->logRule->ip |= ipFields::ttl;
								} else if(words[i].find("protocol") != string::npos)
								{
									lastRule->logRule->ip |= ipFields::protocol;
								} else if(words[i].find("chksum") != string::npos)
								{
									lastRule->logRule->ip |= ipFields::chksum;
								} else if(words[i].find("src") != string::npos)
								{
									lastRule->logRule->ip |= ipFields::src;
								} else if(words[i].find("dst") != string::npos)
								{
									lastRule->logRule->ip |= ipFields::dst;
								}
								break;
							case protocols::tcp:
								if(words[i].find("src") != string::npos)
								{
									lastRule->logRule->tcp |= tcpFields::src;
								} else if(words[i].find("dst") != string::npos)
								{
									lastRule->logRule->tcp |= tcpFields::dst;
								} else if(words[i].find("seq") != string::npos)
								{
									lastRule->logRule->tcp |= tcpFields::seq;
								} else if(words[i].find("ack") != string::npos)
								{
									lastRule->logRule->tcp |= tcpFields::ack;
								} else if(words[i].find("offset") != string::npos)
								{
									lastRule->logRule->tcp |= tcpFields::offset;
								} else if(words[i].find("reserved") != string::npos)
								{
									lastRule->logRule->tcp |= tcpFields::reserved;
								} else if(words[i].find("flags") != string::npos)
								{
									lastRule->logRule->tcp |= tcpFields::flags;
								} else if(words[i].find("window") != string::npos)
								{
									lastRule->logRule->tcp |= tcpFields::window;
								} else if(words[i].find("chksum") != string::npos)
								{
									lastRule->logRule->tcp |= tcpFields::chksum;
								} else if(words[i].find("urg") != string::npos)
								{
									lastRule->logRule->tcp |= tcpFields::urg;
								}
								break;
							case protocols::udp:
								if(words[i].find("src") != string::npos)
								{
									lastRule->logRule->udp |= udpFields::src;
								} else if(words[i].find("dst") != string::npos)
								{
									lastRule->logRule->udp |= udpFields::dst;
								} else if(words[i].find("len") != string::npos)
								{
									lastRule->logRule->udp |= udpFields::len;
								} else if(words[i].find("chksum") != string::npos)
								{
									lastRule->logRule->udp |= udpFields::chksum;
								}
								break;
							case protocols::icmp:
								if(words[i].find("type") != string::npos)
								{
									lastRule->logRule->icmp |= icmpFields::type;
								} else if(words[i].find("code") != string::npos)
								{
									lastRule->logRule->icmp |= icmpFields::code;
								} else if(words[i].find("chksum") != string::npos)
								{
									lastRule->logRule->icmp |= icmpFields::chksum;
								}
								break;
							case protocols::dns:
								if(words[i].find("id") != string::npos)
								{
									lastRule->logRule->dns |= dnsFields::id;
								} else if(words[i].find("opcode") != string::npos)
								{
									lastRule->logRule->dns |= dnsFields::opcode;
								} else if(words[i].find("flags") != string::npos)
								{
									lastRule->logRule->dns |= dnsFields::flags;
								} else if(words[i].find("rcode") != string::npos)
								{
									lastRule->logRule->dns |= dnsFields::rcode;
								} else if(words[i].find("questions") != string::npos)
								{
									lastRule->logRule->dns |= dnsFields::questions;
								} else if(words[i].find("answers") != string::npos)
								{
									lastRule->logRule->dns |= dnsFields::answers;
								} else if(words[i].find("authresources") != string::npos)
								{
									lastRule->logRule->dns |= dnsFields::authresources;
								} else if(words[i].find("addresources") != string::npos)
								{
									lastRule->logRule->dns |= dnsFields::addresources;
								}
								break;
						}
					}
				}
			}
		}
		logRules.close();
	}
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	cleanRuleChain()
-- DATE:		2015-03-13
-- PARAMETERS:	protoRule *rule - A pointer to a protoRule structure
-- RETURN:		void
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		This is a recursive function used for cleaning rules chains created within the 
--				protoRule structure.
------------------------------------------------------------------------------------------------
*/
void cleanRuleChain(protoRule *rule)
{
	if(rule != NULL)
	{
		if(rule->nextRule != NULL)
		{
			cleanRuleChain(rule->nextRule);
			free(rule->nextRule);
		}
		if(rule->logRule != NULL)
		{
			free(rule->logRule);
		}
	}
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	unloadRules()
-- DATE:		2015-03-13
-- PARAMETERS:	N/A
-- RETURN:		void
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		Cleans up potentially malloced memory within the Rules vectors.
------------------------------------------------------------------------------------------------
*/
void unloadRules()
{
	protoRule *rulePointer = 0;
	for(size_t i = 0; i < inRules.size(); ++i)
	{
		rulePointer = inRules[i].nextRule;
		cleanRuleChain(rulePointer);
	}

	for(size_t i = 0; i < outRules.size(); ++i)
	{
		rulePointer = outRules[i].nextRule;
		cleanRuleChain(rulePointer);
	}

	for(size_t i = 0; i < bothRules.size(); ++i)
	{
		rulePointer = bothRules[i].nextRule;
		cleanRuleChain(rulePointer);
	}
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	pushInputQueue()
-- DATE:		2015-03-10
-- PARAMETERS:	const unsigned char *packetData - The raw packet data
--				size_t packetsize - The total size of the packet data
-- RETURN:		void
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		This pushes packet data into the in Queue, which handles traffic received from
--				the external network.
------------------------------------------------------------------------------------------------
*/
void pushInputQueue(const unsigned char *packetData, size_t packetSize)
{
	struct packet newPacket;
	newPacket.packetSize = packetSize;
	memcpy(&(newPacket.packet), packetData, packetSize);
	inPackets.push(newPacket);
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	pushOutputQueue()
-- DATE:		2015-03-10
-- PARAMETERS:	const unsigned char *packetData - The raw packet data
--				size_t packetsize - The total size of the packet data
-- RETURN:		void
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		This pushes packet data into the in Queue, which handles traffic received from
--				the internal network.
------------------------------------------------------------------------------------------------
*/
void pushOutputQueue(const unsigned char *packetData, size_t packetSize)
{
	struct packet newPacket;
	newPacket.packetSize = packetSize;
	memcpy(&(newPacket.packet), packetData, packetSize);
	outPackets.push(newPacket);
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION:	incomingLog()
-- DATE:		2015-03-13
-- PARAMETERS:	void* var - This isn't used. It is necessary for multithreading.
-- RETURN:		void* - This isn't used. The function will always return 0.
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		This is a multithreading function which checks if packets on the inQueue match
--				any logging rules and, if so, logs their data according to those rules. 
------------------------------------------------------------------------------------------------
*/
void* incomingLog(void* var)
{
	logRule* rule = NULL;
	logRule cRule;
	while(true)
	{
		if(inPackets.size() > 0)
		{
			memset(&cRule, 0, sizeof(cRule));
			for(size_t i = 0; i < inRules.size(); ++i)
			{
				rule = checkRule(&(inRules[i]), &(inPackets.front().packet), inPackets.front().packetSize);
				if(rule != NULL)
				{
					cRule.ip |= rule->ip;
					cRule.tcp |= rule->tcp;
					cRule.udp |= rule->udp;
					cRule.icmp |= rule->icmp;
					cRule.dns |= rule->dns;
				}
			}
			for(size_t i = 0; i < bothRules.size(); ++i)
			{
				rule = checkRule(&(bothRules[i]), &(inPackets.front().packet), inPackets.front().packetSize);
				if(rule != NULL)
				{
					cRule.ip |= rule->ip;
					cRule.tcp |= rule->tcp;
					cRule.udp |= rule->udp;
					cRule.icmp |= rule->icmp;
					cRule.dns |= rule->dns;
				}
			}
			if((cRule.ip | cRule.tcp | cRule.udp | cRule.icmp | cRule.dns) != 0)
			{
				logPacket(&cRule, &(inPackets.front()), "logs/input.log");
			}
			inPackets.pop();
		}
	}
	return 0;
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION:	outgoingLog()
-- DATE:		2015-03-13
-- PARAMETERS:	void* var - This isn't used. It is necessary for multithreading.
-- RETURN:		void* - This isn't used. The function will always return 0.
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		This is a multithreading function which checks if packets on the outQueue match
--				any logging rules and, if so, logs their data according to those rules. 
------------------------------------------------------------------------------------------------
*/
void* outgoingLog(void* var)
{
	logRule* rule = NULL;
	logRule cRule;
	while(true)
	{
		if(outPackets.size() > 0)
		{
			memset(&cRule, 0, sizeof(cRule));
			for(size_t i = 0; i < outRules.size(); ++i)
			{
				rule = checkRule(&(outRules[i]), &(outPackets.front().packet), outPackets.front().packetSize);
				if(rule != NULL)
				{
					cRule.ip |= rule->ip;
					cRule.tcp |= rule->tcp;
					cRule.udp |= rule->udp;
					cRule.icmp |= rule->icmp;
					cRule.dns |= rule->dns;
				}
			}
			for(size_t i = 0; i < bothRules.size(); ++i)
			{
				rule = checkRule(&(bothRules[i]), &(outPackets.front().packet), outPackets.front().packetSize);
				if(rule != NULL)
				{
					cRule.ip |= rule->ip;
					cRule.tcp |= rule->tcp;
					cRule.udp |= rule->udp;
					cRule.icmp |= rule->icmp;
					cRule.dns |= rule->dns;
				}
			}
			if((cRule.ip | cRule.tcp | cRule.udp | cRule.icmp | cRule.dns) != 0)
			{
				logPacket(&cRule, &(outPackets.front()), "logs/output.log");
			}
			outPackets.pop();
		}
	}
	return 0;
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	checkRule()
-- DATE:		2015-03-16
-- PARAMETERS:	protoRule* rule - The rule to be checked
--				const unsigned char *packetData - The raw packet data
--				size_t packetsize - The total size of the packet data
-- RETURN:		Returns a pointer to the logging rule if the packet matches the rule. Otherwise
--				it returns NULL.
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		This function takes a rule and the packet data and does tests to check whether
--				The packet matches the rule.
------------------------------------------------------------------------------------------------
*/
logRule* checkRule(protoRule* rule, struct recv_tcp *packetData, size_t packetSize)
{
	protoRule* nextRule = rule;
	while(nextRule != NULL)
	{
		if(nextRule->protocol == protocols::ip)
		{
			for(int i = 0; i < 4; ++i)
			{
				switch(nextRule->field[i])
				{
					case ipFields::version:
						switch(nextRule->comparason[i])
						{
							case comparators::equal:
								if(nextRule->value[i] == packetData->ip.version)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::not_equal:
								if(nextRule->value[i] != packetData->ip.version)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::less:
								if(nextRule->value[i] > packetData->ip.version)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::less_equal:
								if(nextRule->value[i] >= packetData->ip.version)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::greater:
								if(nextRule->value[i] < packetData->ip.version)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::greater_equal:
								if(nextRule->value[i] <= packetData->ip.version)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
						}
						break;
					case ipFields::id:
						switch(nextRule->comparason[i])
						{
							case comparators::equal:
								if(nextRule->value[i] == ntohs(packetData->ip.id))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::not_equal:
								if(nextRule->value[i] != ntohs(packetData->ip.id))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::less:
								if(nextRule->value[i] > ntohs(packetData->ip.id))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::less_equal:
								if(nextRule->value[i] >= ntohs(packetData->ip.id))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::greater:
								if(nextRule->value[i] < ntohs(packetData->ip.id))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::greater_equal:
								if(nextRule->value[i] <= ntohs(packetData->ip.id))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
						}
						break;
					case ipFields::flags:
						switch(nextRule->comparason[i])
						{
							case comparators::equal:
								if((nextRule->value[i] & 0x07) == (ntohs(packetData->ip.frag_off) >> 13))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::not_equal:
								if((nextRule->value[i] & 0x07) != (ntohs(packetData->ip.frag_off) >> 13))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::less:
								if((nextRule->value[i] & 0x07) > (ntohs(packetData->ip.frag_off) >> 13))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::less_equal:
								if((nextRule->value[i] & 0x07) >= (ntohs(packetData->ip.frag_off) >> 13))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::greater:
								if((nextRule->value[i] & 0x07) < (ntohs(packetData->ip.frag_off) >> 13))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::greater_equal:
								if((nextRule->value[i] & 0x07) <= (ntohs(packetData->ip.frag_off) >> 13))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
						}
						break;
					case ipFields::ttl:
						switch(nextRule->comparason[i])
						{
							case comparators::equal:
								if(nextRule->value[i] == packetData->ip.ttl)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::not_equal:
								if(nextRule->value[i] != packetData->ip.ttl)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::less:
								if(nextRule->value[i] > packetData->ip.ttl)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::less_equal:
								if(nextRule->value[i] >= packetData->ip.ttl)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::greater:
								if(nextRule->value[i] < packetData->ip.ttl)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::greater_equal:
								if(nextRule->value[i] <= packetData->ip.ttl)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
						}
						break;
					case ipFields::protocol:
						switch(nextRule->comparason[i])
						{
							case comparators::equal:
								if(nextRule->value[i] == packetData->ip.protocol)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::not_equal:
								if(nextRule->value[i] != packetData->ip.protocol)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::less:
								if(nextRule->value[i] > packetData->ip.protocol)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::less_equal:
								if(nextRule->value[i] >= packetData->ip.protocol)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::greater:
								if(nextRule->value[i] < packetData->ip.protocol)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::greater_equal:
								if(nextRule->value[i] <= packetData->ip.protocol)
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
						}
						break;
					case ipFields::src:
						switch(nextRule->comparason[i])
						{
							case comparators::equal:
								if(ntohl(nextRule->value[i]) == ntohl(packetData->ip.saddr))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::not_equal:
								if(ntohl(nextRule->value[i]) != ntohl(packetData->ip.saddr))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::less:
								if(ntohl(nextRule->value[i]) > ntohl(packetData->ip.saddr))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::less_equal:
								if(ntohl(nextRule->value[i]) >= ntohl(packetData->ip.saddr))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::greater:
								if(ntohl(nextRule->value[i]) < ntohl(packetData->ip.saddr))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::greater_equal:
								if(ntohl(nextRule->value[i]) <= ntohl(packetData->ip.saddr))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
						}
						break;
					case ipFields::dst:
						switch(nextRule->comparason[i])
						{
							case comparators::equal:
								if(ntohl(nextRule->value[i]) == ntohl(packetData->ip.daddr))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::not_equal:
								if(ntohl(nextRule->value[i]) != ntohl(packetData->ip.daddr))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::less:
								if(ntohl(nextRule->value[i]) > ntohl(packetData->ip.daddr))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::less_equal:
								if(ntohl(nextRule->value[i]) >= ntohl(packetData->ip.daddr))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::greater:
								if(ntohl(nextRule->value[i]) < ntohl(packetData->ip.daddr))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
							case comparators::greater_equal:
								if(ntohl(nextRule->value[i]) <= ntohl(packetData->ip.daddr))
								{
									continue;
								} else
								{
									return NULL;
								}
								break;
						}
						break;
				}
			}
		} else if(nextRule->protocol == protocols::tcp)
		{
			if(packetData->ip.protocol == 6)
			{
				for(int i = 0; i < 4; ++i)
				{
					switch(nextRule->field[i])
					{
						case tcpFields::src:
							switch(nextRule->comparason[i])
							{
								case comparators::equal:
									if(nextRule->value[i] == ntohs(packetData->tcp.source))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::not_equal:
									if(nextRule->value[i] != ntohs(packetData->tcp.source))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::less:
									if(nextRule->value[i] > ntohs(packetData->tcp.source))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::less_equal:
									if(nextRule->value[i] >= ntohs(packetData->tcp.source))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::greater:
									if(nextRule->value[i] < ntohs(packetData->tcp.source))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::greater_equal:
									if(nextRule->value[i] <= ntohs(packetData->tcp.source))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
							}
							break;
						case tcpFields::dst:
							switch(nextRule->comparason[i])
							{
								case comparators::equal:
									if(nextRule->value[i] == ntohs(packetData->tcp.dest))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::not_equal:
									if(nextRule->value[i] != ntohs(packetData->tcp.dest))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::less:
									if(nextRule->value[i] > ntohs(packetData->tcp.dest))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::less_equal:
									if(nextRule->value[i] >= ntohs(packetData->tcp.dest))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::greater:
									if(nextRule->value[i] < ntohs(packetData->tcp.dest))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::greater_equal:
									if(nextRule->value[i] <= ntohs(packetData->tcp.dest))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
							}
							break;
						case tcpFields::seq:
							switch(nextRule->comparason[i])
							{
								case comparators::equal:
									if(nextRule->value[i] == ntohs(packetData->tcp.seq))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::not_equal:
									if(nextRule->value[i] != ntohs(packetData->tcp.seq))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::less:
									if(nextRule->value[i] > ntohs(packetData->tcp.seq))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::less_equal:
									if(nextRule->value[i] >= ntohs(packetData->tcp.seq))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::greater:
									if(nextRule->value[i] < ntohs(packetData->tcp.seq))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::greater_equal:
									if(nextRule->value[i] <= ntohs(packetData->tcp.seq))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
							}
							break;
						case tcpFields::ack:
							switch(nextRule->comparason[i])
							{
								case comparators::equal:
									if(nextRule->value[i] == ntohs(packetData->tcp.ack_seq))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::not_equal:
									if(nextRule->value[i] != ntohs(packetData->tcp.ack_seq))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::less:
									if(nextRule->value[i] > ntohs(packetData->tcp.ack_seq))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::less_equal:
									if(nextRule->value[i] >= ntohs(packetData->tcp.ack_seq))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::greater:
									if(nextRule->value[i] < ntohs(packetData->tcp.ack_seq))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::greater_equal:
									if(nextRule->value[i] <= ntohs(packetData->tcp.ack_seq))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
							}
							break;
						case tcpFields::flags:
							break;
					}
				}
			} else
			{
				return NULL;
			}
		} else if(nextRule->protocol == protocols::udp)
		{
			if(packetData->ip.protocol == 17)
			{
				for(int i = 0; i < 4; ++i)
				{
					switch(nextRule->field[i])
					{
						case udpFields::src:
							switch(nextRule->comparason[i])
							{
								case comparators::equal:
									if(nextRule->value[i] == ntohs(((udphdr*)(&packetData->tcp))->source))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::not_equal:
									if(nextRule->value[i] != ntohs(((udphdr*)(&packetData->tcp))->source))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::less:
									if(nextRule->value[i] > ntohs(((udphdr*)(&packetData->tcp))->source))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::less_equal:
									if(nextRule->value[i] >= ntohs(((udphdr*)(&packetData->tcp))->source))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::greater:
									if(nextRule->value[i] < ntohs(((udphdr*)(&packetData->tcp))->source))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::greater_equal:
									if(nextRule->value[i] <= ntohs(((udphdr*)(&packetData->tcp))->source))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
							}
							break;
						case udpFields::dst:
							switch(nextRule->comparason[i])
							{
								case comparators::equal:
									if(nextRule->value[i] == ntohs(((udphdr*)(&packetData->tcp))->dest))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::not_equal:
									if(nextRule->value[i] != ntohs(((udphdr*)(&packetData->tcp))->dest))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::less:
									if(nextRule->value[i] > ntohs(((udphdr*)(&packetData->tcp))->dest))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::less_equal:
									if(nextRule->value[i] >= ntohs(((udphdr*)(&packetData->tcp))->dest))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::greater:
									if(nextRule->value[i] < ntohs(((udphdr*)(&packetData->tcp))->dest))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::greater_equal:
									if(nextRule->value[i] <= ntohs(((udphdr*)(&packetData->tcp))->dest))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
							}
							break;
						case udpFields::len:
							switch(nextRule->comparason[i])
							{
								case comparators::equal:
									if(nextRule->value[i] == ntohs(((udphdr*)(&packetData->tcp))->len))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::not_equal:
									if(nextRule->value[i] != ntohs(((udphdr*)(&packetData->tcp))->len))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::less:
									if(nextRule->value[i] > ntohs(((udphdr*)(&packetData->tcp))->len))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::less_equal:
									if(nextRule->value[i] >= ntohs(((udphdr*)(&packetData->tcp))->len))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::greater:
									if(nextRule->value[i] < ntohs(((udphdr*)(&packetData->tcp))->len))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
								case comparators::greater_equal:
									if(nextRule->value[i] <= ntohs(((udphdr*)(&packetData->tcp))->len))
									{
										continue;
									} else
									{
										return NULL;
									}
									break;
							}
							break;
					}
				}
			} else
			{
				return NULL;
			}
		} else if(nextRule->protocol == protocols::icmp)
		{
			if(packetData->ip.protocol == 1)
			{
				for(int i = 0; i < 4; ++i)
				{
					switch(nextRule->field[i])
					{
						case icmpFields::type:
							break;
						case icmpFields::code:
							break;
					}
				}
			} else
			{
				return NULL;
			}
		} else if(nextRule->protocol == protocols::dns)
		{
		} else if(nextRule->protocol == protocols::http)
		{
		}

		if(nextRule->nextRule != NULL)
		{
			nextRule = nextRule->nextRule;
		} else
		{
			return nextRule->logRule;
		}
	}

	return NULL;
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	logPacket()
-- DATE:		2015-03-16
-- PARAMETERS:	logRule* rule - Pointer to structure defining which elements should be logged
--				struct packet* pckt - The raw packet data
-- RETURN:		void
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		Logs the data stored in pckt based upon the passed in rules.
------------------------------------------------------------------------------------------------
*/
void logPacket(logRule* rule, struct packet* pckt, const char* fileName)
{
	if(rule != NULL)
	{
		ofstream logFile(fileName, ios_base::out);
		logFile << "\n\n*************************Packet***************************" << endl;
		//ip
		if(rule->ip != 0)
		{
			struct sockaddr_in address;
	
			logFile << endl;
			logFile << "IP Header" << endl;
			if(rule->ip & ipFields::version)
				logFile << "   |-IP Version         : " << (unsigned int)pckt->packet.ip.version << endl;
			if(rule->ip & ipFields::hlen)
				logFile << "   |-IP Header Length   : " << (unsigned int)pckt->packet.ip.ihl << " DWORDS or " << ((unsigned int)(pckt->packet.ip.ihl))*4 << " Bytes " << endl;
			if(rule->ip & ipFields::tos)
				logFile << "   |-Type Of Service    : " << (unsigned int)pckt->packet.ip.tos << endl;
			if(rule->ip & ipFields::tlen)
				logFile << "   |-IP Total Length    : " << ntohs(pckt->packet.ip.tot_len) <<" Bytes(Size of Packet)" << endl;
			if(rule->ip & ipFields::id)
				logFile << "   |-Identification     : " << ntohs(pckt->packet.ip.id) << endl;
			if(rule->ip & ipFields::flags)
			{
				unsigned short flag = (ntohs(pckt->packet.ip.frag_off) >> 13);
				logFile << "   |-Reserved ZERO Flag : " << ((flag & 0x04) == 0x04) << endl;
				logFile << "   |-Dont Fragment Flag : " << ((flag & 0x02) == 0x02) << endl;
				logFile << "   |-More Fragment Flag : " << ((flag & 0x01) == 0x01) << endl;
			}
			if(rule->ip & ipFields::ttl)
				logFile << "   |-Fragment offset    : " << (ntohs(pckt->packet.ip.frag_off) & 0x1FFF) << endl;
			if(rule->ip & ipFields::ttl)
				logFile << "   |-TTL                : " << (unsigned int)pckt->packet.ip.ttl << endl;
			if(rule->ip & ipFields::protocol)
				logFile << "   |-Protocol           : " << (unsigned int)pckt->packet.ip.protocol << endl;
			if(rule->ip & ipFields::chksum)
				logFile << "   |-Checksum           : " << ntohs(pckt->packet.ip.check) << endl;
			if(rule->ip & ipFields::src)
			{
				address.sin_addr.s_addr = pckt->packet.ip.saddr;
				logFile << "   |-Source IP          : " << inet_ntoa(address.sin_addr) << endl;
			}
			if(rule->ip & ipFields::dst)
			{
				address.sin_addr.s_addr = pckt->packet.ip.daddr;
				logFile << "   |-Destination IP     : " << inet_ntoa(address.sin_addr) << endl;
			}
		}
		//tcp
		if(rule->tcp != 0 && pckt->packet.ip.protocol == 6)
		{
			logFile << endl;
			logFile << "TCP Header" << endl;
			if(rule->tcp & tcpFields::src)
				logFile << "   |-Source Port          : " << ntohs(pckt->packet.tcp.source) << endl;
			if(rule->tcp & tcpFields::dst)
				logFile << "   |-Destination Port     : " << ntohs(pckt->packet.tcp.dest) << endl;
			if(rule->tcp & tcpFields::seq)
				logFile << "   |-Sequence Number      : " << ntohl(pckt->packet.tcp.seq) << endl;
			if(rule->tcp & tcpFields::ack)
				logFile << "   |-Acknowledge Number   : " << ntohl(pckt->packet.tcp.ack_seq) << endl;
			if(rule->tcp & tcpFields::flags)
			{
				logFile << "   |-Urgent Flag          : " << (unsigned int)pckt->packet.tcp.urg << endl;
				logFile << "   |-Acknowledgement Flag : " << (unsigned int)pckt->packet.tcp.ack << endl;
				logFile << "   |-Push Flag            : " << (unsigned int)pckt->packet.tcp.psh << endl;
				logFile << "   |-Reset Flag           : " << (unsigned int)pckt->packet.tcp.rst << endl;
				logFile << "   |-Synchronise Flag     : " << (unsigned int)pckt->packet.tcp.syn << endl;
				logFile << "   |-Finish Flag          : " << (unsigned int)pckt->packet.tcp.fin << endl;
			}
			if(rule->tcp & tcpFields::window)
				logFile << "   |-Window               : " << ntohs(pckt->packet.tcp.window) << endl;
			if(rule->tcp & tcpFields::chksum)
				logFile << "   |-Checksum             : " << ntohs(pckt->packet.tcp.check) << endl;
			if(rule->tcp & tcpFields::urg)
				logFile << "   |-Urgent Pointer       : " << pckt->packet.tcp.urg_ptr << endl;
		}
		//udp
		if(rule->udp != 0 && pckt->packet.ip.protocol == 17)
		{
			struct udphdr *udph = (struct udphdr*)&(pckt->packet.tcp);

			logFile << endl;
			logFile << "UDP Header" << endl;
			if(rule->udp & udpFields::src)
				logFile << "   |-Source Port      : " << ntohs(udph->source) << endl;
			if(rule->udp & udpFields::dst)
				logFile << "   |-Destination Port : " << ntohs(udph->dest) << endl;
			if(rule->udp & udpFields::len)
				logFile << "   |-UDP Length       : " << ntohs(udph->len) << endl;
			if(rule->udp & udpFields::chksum)
				logFile << "   |-UDP Checksum     : " << ntohs(udph->check) << endl;
		}
		//icmp
		if(rule->icmp != 0 && pckt->packet.ip.protocol == 1)
		{
			struct icmphdr *icmph = (struct icmphdr*)&(pckt->packet.tcp);

			logFile << endl;
			logFile << "ICMP Header" << endl;
			if(rule->icmp & icmpFields::type)
			{
				logFile << "   |-Type     : " << (unsigned int)(icmph->type);
			
				if((unsigned int)(icmph->type) == 11)
				{
					logFile << "  (TTL Expired)" << endl;
				} else if((unsigned int)(icmph->type) == 0)
				{
					logFile << "  (ICMP Echo Reply)" << endl;
				}
			}

			if(rule->icmp & icmpFields::code)
				logFile << "   |-Code     :  " << (unsigned int)(icmph->code) << endl;
			if(rule->icmp & icmpFields::chksum)
				logFile << "   |-Checksum : " << ntohs(icmph->checksum) << endl;
		}
		//dns
		if(rule->dns != 0)
		{
		}

		logFile << endl << "###############################################################" << endl;
		logFile.close();
	}
}

