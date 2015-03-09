#ifndef ROUTING_H
#define ROUTING_H
#include "Config.h"
#include<sys/socket.h>
#include <pthread.h>
#include <unistd.h>

#include <queue>

void rSetup();

void* incomingMasq(void* var);
void* outgoingMasq(void* var);

#endif
