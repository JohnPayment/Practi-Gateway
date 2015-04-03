#ifndef PAYLOAD_H
#define PAYLOAD_H
#include "Config.h"
#include "Logging.h"

// Structures
struct payload
{
	size_t payloadSize;
	char buffer[4000];
};

// Functions
void loadPayloadRules(const char* file);
void unloadPayloadRules();

size_t IncomingReplacement(packet *packetData);
size_t OutgoingReplacement(packet *packetData);
logRule* checkRule(protoRule* rule, struct recv_tcp *packetData, size_t packetSize);

size_t replacePayload(payload* load, packet *packetData);

#endif
