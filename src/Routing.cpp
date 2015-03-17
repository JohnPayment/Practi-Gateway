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
	char buffer[4096] __attribute__ ((aligned));

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
	char buffer[4096] __attribute__ ((aligned));

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
	struct nfqnl_msg_packet_hw *hwPacketHandler;
	//u_int32_t mark,ifi; 
	int ret;
	unsigned char *packetData;

	msgPacketHandler = nfq_get_msg_packet_hdr(nfa);
	if (msgPacketHandler) 
	{
		id = ntohl(msgPacketHandler->packet_id);
		//printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(msgPacketHandler->hw_protocol), msgPacketHandler->hook, id);
	}

	hwPacketHandler = nfq_get_packet_hw(nfa);
	if (hwPacketHandler) 
	{
		//int i, hlen = ntohs(hwPacketHandler->hw_addrlen);

		/*printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
		{
			printf("%02x:", hwPacketHandler->hw_addr[i]);
		}
		printf("%02x ", hwPacketHandler->hw_addr[hlen-1]);*/
	}

	ret = nfq_get_payload(nfa, &packetData);
	if (ret >= 0)
	{
		//struct sockaddr_in source,dest;
		//source.sin_addr.s_addr = ((struct iphdr *)packetData)->saddr;
		//dest.sin_addr.s_addr = ((struct iphdr *)packetData)->daddr;
		//printf("payload_len=%d ", ret);
		//printf("Src Adr: %s ", inet_ntoa(source.sin_addr));
		//printf("Dst Adr: %s ", inet_ntoa(dest.sin_addr));

		if (config::logging())
		{
			pushInputQueue(packetData, ret);
		}
	}

	//fputc('\n', stdout);

	return nfq_set_verdict(qh, id, NF_ACCEPT, ret, packetData);
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
	struct nfqnl_msg_packet_hw *hwPacketHandler;
	//u_int32_t mark,ifi; 
	int ret;
	unsigned char *packetData;

	msgPacketHandler = nfq_get_msg_packet_hdr(nfa);
	if (msgPacketHandler) 
	{
		id = ntohl(msgPacketHandler->packet_id);
	}

	hwPacketHandler = nfq_get_packet_hw(nfa);
	if (hwPacketHandler) 
	{
		//int i, hlen = ntohs(hwPacketHandler->hw_addrlen);
	}

	ret = nfq_get_payload(nfa, &packetData);
	if (ret >= 0)
	{
		//struct sockaddr_in source,dest;
		//source.sin_addr.s_addr = ((struct iphdr *)packetData)->saddr;
		//dest.sin_addr.s_addr = ((struct iphdr *)packetData)->daddr;

		if (config::logging())
		{
			pushOutputQueue(packetData, ret);
		}
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, ret, packetData);
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

