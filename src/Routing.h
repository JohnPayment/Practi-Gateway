#ifndef ROUTING_H
#define ROUTING_H
#include "Config.h"
#include "Logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#include <sys/socket.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>	
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <arpa/inet.h>

#include <libnetfilter_queue/libnetfilter_queue.h>


//#include <netinet/if_ether.h>
//#include <net/ethernet.h>
//#include <linux/ip.h>


void rSetup();

void* incomingMasq(void* var);
void* outgoingMasq(void* var);

#endif
