#ifndef LOGGING_H
#define LOGGING_H
#include "Config.h"
#include "whois.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

#include <sys/socket.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>	
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <arpa/inet.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <queue>
#include <vector>

//Enums
namespace protocols
{
	enum protocols
	{
		none = 0,
		ip = 1,
		tcp,
		udp,
		icmp,
		dns,
		http
	};
}

namespace ipFields
{
	enum ipFields
	{
		version = 1,
		hlen = 2,
		tos = 4,
		tlen = 8,
		id = 16,
		flags = 32,		// Search Param
		frag = 64,
		ttl = 128,
		protocol = 256,	// Search Param
		chksum = 512,
		src = 1024,		// Search Param
		dst = 2048		// Search Param
	};
}

namespace tcpFields
{
	enum tcpFields
	{
		src = 1,		// Search Param
		dst = 2,		// Search Param
		seq = 4,
		ack = 8,
		offset = 16,
		reserved = 32,
		flags = 64,		// Search Param
		window = 128,
		chksum = 256,
		urg = 512
	};
}

namespace udpFields
{
	enum udpFields
	{
		src = 1,		// Search Param
		dst = 2,		// Search Param
		len = 4,
		chksum = 6
	};
}

namespace icmpFields
{
	enum icmpFields
	{
		type = 1,		// Search Param
		code = 2,		// Search Param
		chksum = 4
	};
}

namespace dnsFields
{
	enum dnsFields
	{
		id = 1,
		opcode = 2,
		flags = 4,
		rcode = 8,
		questions = 16,
		answers = 32,
		authresources = 64,
		addresources = 128
	};
}

namespace comparators
{
	enum comparators
	{
		equal = 1,
		not_equal,
		greater,
		greater_equal,
		less,
		less_equal
	};
}

// Structures
struct logRule
{
	unsigned short ip;

	unsigned short tcp;
	unsigned char udp;
	unsigned char icmp;
	
	unsigned short dns;
};

struct protoRule
{
	unsigned int value[4];
	unsigned int field[4];
	unsigned char protocol;
	unsigned char comparason[4];
	struct protoRule* nextRule;
	struct logRule* logRule;
};

struct recv_tcp
{
	struct iphdr ip;
	struct tcphdr tcp;
	char buffer[4000];
};

struct packet
{
	size_t packetSize;
	struct recv_tcp packet;
};


// Functions
void loadLoggingRules(const char* file);
void unloadLoggingRules();
void cleanRuleChain(protoRule *rule);

void pushInputQueue(const packet *packetData);
void pushOutputQueue(const packet *packetData);

void* incomingLog(void* var);
void* outgoingLog(void* var);
logRule* checkRule(protoRule* rule, struct recv_tcp *packetData, size_t packetSize);

void logPacket(logRule* rule, struct packet* pckt, const char* fileName);

#endif
