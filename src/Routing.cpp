#include "Routing.h"

using namespace std;

// Forward Declarations
static int incomingPreprocess(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
static int outgoingPreprocess(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

// Prebuild functions for handling host names and checksums
unsigned short in_cksum(unsigned short *ptr, int nbytes);
unsigned int host_convert(char *hostname);

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	rSetup()
-- REVISION:	2015-03-10
-- PARAMETERS:	N/A
-- RETURN:		void
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		Sets up the logging threads if logging is enabled.
------------------------------------------------------------------------------------------------
*/
void rSetup()
{
	pthread_t incomingThread;
	pthread_t outgoingThread;
	int errno;

	if (config::logging())
	{
		if((errno=pthread_create(&incomingThread, NULL, &incomingLog, NULL)) != 0)
		{
			cout << "Creation of incoming packet logger failed" << endl;
		}
		if((errno=pthread_create(&outgoingThread, NULL, &outgoingLog, NULL)) != 0)
		{
			cout << "Creation of outgoing packet logger failed" << endl;
		}
	}
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	incomingMasq()
-- DATE:		2015-03-09
-- PARAMETERS:	void* var - This isn't used. It is necessary for multithreading.
-- RETURN:		void* - This isn't used. The function will always return 0.
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		This retrieves packets bound for the internal network from netfilter and passes
--				the data to a packet handler.
------------------------------------------------------------------------------------------------
*/
void* incomingMasq(void* var)
{
	struct nfq_handle *nfqHandle;
	struct nfq_q_handle *queueHandle;
	//struct nfnl_handle *nh;
	int fd;
	int dataSize;
	char buffer[4096];// __attribute__ ((aligned));

	// Opening nfq Library
	nfqHandle = nfq_open();
	if (!nfqHandle) 
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	// Making sure that the nfq Handle isn't already bound to anything
	if (nfq_unbind_pf(nfqHandle, AF_INET) < 0) 
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	// Binding the nfq Handle using AF_NET
	if (nfq_bind_pf(nfqHandle, AF_INET) < 0) 
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	// Binding the Queue Handle Queue #0
	queueHandle = nfq_create_queue(nfqHandle, 0, &incomingPreprocess, NULL);
	if (!queueHandle) 
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	// Setting Queue to store entire packet
	if (nfq_set_mode(queueHandle, NFQNL_COPY_PACKET, 0xffff) < 0) 
	{
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(nfqHandle);

	while ((dataSize = recv(fd, buffer, sizeof(buffer), 0)) && dataSize >= 0) 
	{
		// Handling new packet
		nfq_handle_packet(nfqHandle, buffer, dataSize);
	}

	// Unbinding Queue
	nfq_destroy_queue(queueHandle);

	// Close nfq Handle
	nfq_close(nfqHandle);
	return 0;
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	outgoingMasq()
-- DATE:		2015-03-09
-- PARAMETERS:	void* var - This isn't used. It is necessary for multithreading.
-- RETURN:		void* - This isn't used. The function will always return 0.
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		This retrieves packets bound for the external network from netfilter and passes
--				the data to a packet handler.
------------------------------------------------------------------------------------------------
*/
void* outgoingMasq(void* var)
{
	struct nfq_handle *nfqHandle;
	struct nfq_q_handle *queueHandle;
	//struct nfnl_handle *nh;
	int fd;
	int dataSize;
	char buffer[4096];// __attribute__ ((aligned));

	// Opening nfq Library
	nfqHandle = nfq_open();
	if (!nfqHandle) 
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	// Making sure that the nfq Handle isn't already bound to anything
	if (nfq_unbind_pf(nfqHandle, AF_INET) < 0) 
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	// Binding the nfq Handle using AF_NET
	if (nfq_bind_pf(nfqHandle, AF_INET) < 0) 
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	// Binding the Queue Handle Queue #1
	queueHandle = nfq_create_queue(nfqHandle, 1, &outgoingPreprocess, NULL);
	if (!queueHandle) 
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	// Setting Queue to store entire packet
	if (nfq_set_mode(queueHandle, NFQNL_COPY_PACKET, 0xffff) < 0) 
	{
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(nfqHandle);

	while ((dataSize = recv(fd, buffer, sizeof(buffer), 0)) && dataSize >= 0) 
	{
		// Handling new packet
		nfq_handle_packet(nfqHandle, buffer, dataSize);
	}

	// Unbinding Queue
	nfq_destroy_queue(queueHandle);

	// Close nfq Handle
	nfq_close(nfqHandle);
	return 0;
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	incomingPreprocess()
-- DATE:		2015-03-10
-- PARAMETERS:	struct nfq_q_handle *qh
--				struct nfgenmsg *nfmsg
--				struct nfq_data *nfa - This is a pointer used for accessing nfq functions.
--				void* data - This is the raw data of the packet
-- RETURN:		static int - returns the return value from nfq_set_validation
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		This function extracts addition needed data about the packet and passes it all
--				to whichever modules are currently loaded. It then validates the packet for
--				forwarding, including any changes which may have been made by modules.
------------------------------------------------------------------------------------------------
*/
static int incomingPreprocess(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *msgPacketHandler;
	int ret;
	unsigned char *packetData;

	msgPacketHandler = nfq_get_msg_packet_hdr(nfa);
	if (msgPacketHandler) 
	{
		id = ntohl(msgPacketHandler->packet_id);
	}

	ret = nfq_get_payload(nfa, &packetData);
	if (ret >= 0)
	{
		if(config::logging() || config::payloadReplacement())
		{
			struct packet newPacket;
			newPacket.packetSize = ret;
			memcpy(&(newPacket.packet), packetData, ret);

			if (config::logging())
			{
				pushInputQueue(&newPacket);
			}
			if (config::payloadReplacement())
			{
				ret = IncomingReplacement(&newPacket);
				return nfq_set_verdict(qh, id, NF_ACCEPT, newPacket.packetSize, (const unsigned char*)&(newPacket.packet));
			}
		}
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

/*
-----------------------------------------------------------------------------------------------
-- FUNCTION: 	outgoingPreprocess()
-- DATE:		2015-03-10
-- PARAMETERS:	struct nfq_q_handle *qh
--				struct nfgenmsg *nfmsg
--				struct nfq_data *nfa - This is a pointer used for accessing nfq functions.
--				void* data - This is the raw data of the packet
-- RETURN:		static int - returns the return value from nfq_set_validation
-- DESIGNER:	John Payment
-- PROGRAMMER:	John Payment
-- NOTES:		This function extracts addition needed data about the packet and passes it all
--				to whichever modules are currently loaded. It then validates the packet for
--				forwarding, including any changes which may have been made by modules.
------------------------------------------------------------------------------------------------
*/
static int outgoingPreprocess(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *msgPacketHandler;
	int ret;
	unsigned char *packetData;

	msgPacketHandler = nfq_get_msg_packet_hdr(nfa);
	if (msgPacketHandler) 
	{
		id = ntohl(msgPacketHandler->packet_id);
	}

	ret = nfq_get_payload(nfa, &packetData);
	if (ret >= 0)
	{
		if(config::logging() || config::payloadReplacement())
		{
			struct packet newPacket;
			newPacket.packetSize = ret;
			memcpy(&(newPacket.packet), packetData, ret);

			if (config::logging())
			{
				pushOutputQueue(&newPacket);
			}
			if (config::payloadReplacement())
			{
				ret = OutgoingReplacement(&newPacket);
				return nfq_set_verdict(qh, id, NF_ACCEPT, newPacket.packetSize, (const unsigned char*)&(newPacket.packet));
			}
		}
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}
