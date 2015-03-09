#include "Routing.h"

using namespace std;

void* incomingPreprocess(void* var);
pthread_mutex_t iPreMutex = PTHREAD_MUTEX_INITIALIZER;

// Structs
struct packetData
{
	unsigned char* buffer;
	size_t dataSize;
};

// Routing Globals
queue<packetData> packetQueue;

void rSetup()
{
	cout << "do stuff";
}

void* incomingMasq(void* var)
{
	pthread_t preThread;
	int errno;

	size_t dataSize;
	
	struct sockaddr saddr;
	socklen_t saddrSize;

	if((errno=pthread_create(&preThread, NULL, &incomingPreprocess, NULL)) != 0)
	{
		// Put logging here
		//printf("Thread creation failed: %d\n", rc1);
	}
		
	unsigned char* buffer = (unsigned char *)(malloc(65536));
	

	int rawSocket = socket(AF_INET, SOCK_RAW, 6);
	if(rawSocket < 0)
	{
		//Print the error with proper message
		perror("Socket Error");
		return 0;
	}

	while(1)
	{
		saddrSize = sizeof(saddr);
		//Receive a packet
		dataSize = recvfrom(rawSocket, buffer, 65536, 0, &saddr, &saddrSize);
		if(dataSize < 0)
		{
			return 0;
		}

		struct packetData data;
		data.buffer = (unsigned char*)(malloc(dataSize));
		memcpy(data.buffer, buffer, dataSize);
		data.dataSize = dataSize;
		
		pthread_mutex_lock(&iPreMutex);
		packetQueue.push(data);
		pthread_mutex_unlock(&iPreMutex);
	}

	close(rawSocket);
	free(buffer);

	pthread_join(preThread, NULL);
	return 0;
}

void* outgoingMasq(void* var)
{
	return 0;
}

void* incomingPreprocess(void* var)
{
	while(true)
	{
		if(packetQueue.size() > 0)
		{
			pthread_mutex_lock(&iPreMutex);
			free(packetQueue.front().buffer);
			packetQueue.pop();
			pthread_mutex_unlock(&iPreMutex);
		}
	}
	return 0;
}

