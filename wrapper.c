/**
* PPP to Ethernet Wrapper
* @author huangty
* @date Jun. 2011
* @detail: 
*	1. bind to ppp0 
*	2. create a virtual interface (ex: veth1)
*   3. grab packets from ppp0, add a ethernet header, send it to veth1
* based on the code from: http://www.security-freak.net/architecture/ArpDos.c
**/

#include<strings.h>
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<sys/types.h>
#include<sys/ipc.h>
#include<sys/msg.h>
#include<net/if_arp.h>
#include<arpa/inet.h>
#include<netinet/ether.h>

/* Global */
char *interface_in;
char *interface_out;


/* Raw socket creation/read/write code */

int CreateRawSocket(int domain, int protocol)
{
	int rawsock;

	if((rawsock = socket(domain, SOCK_RAW, htons(protocol)))== -1) //@huangty: del htons
	{
		perror("Error creating raw socket: ");
		exit(-1);
	}

	return rawsock;
}

int BindRawSocketToInterface(char *device, int rawsock, int protocol)
{
	
	struct sockaddr_ll sll;
	struct ifreq ifr;

	bzero(&sll, sizeof(sll));
	bzero(&ifr, sizeof(ifr));
	
	/* First Get the Interface Index  */
	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if (setsockopt(rawsock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) 
	{
		perror("Error binding raw socket to the interface\n");
		close(rawsock); 
	}
	
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
	{
		printf("Error getting Interface index !\n");
		exit(-1);
	}
	// Bind our raw socket to this interface
	if(protocol != 0){
		sll.sll_family = AF_PACKET;
		sll.sll_ifindex = ifr.ifr_ifindex;
		sll.sll_protocol = htons(protocol); //@huangty, del htons
		if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
		{
			perror("Error binding raw socket to interface at bind\n");
			exit(-1);
		}
	}
	return 1;
}


int SendRawPacket(int rawsock, unsigned char *pkt, int pkt_len)
{
	int sent= 0;

	/* A simple write on the socket ..thats all it takes ! */

	if((sent = write(rawsock, pkt, pkt_len)) != pkt_len)
	{
		/* Error */
		printf("Could only send %d bytes of packet of length %d\n", sent, pkt_len);
		printf("Error no: %s\n", strerror(errno));
		return 0;
	}

	return 1;
}


void PrintPacketInHex(unsigned char *packet, int len)
{
	unsigned char *p = packet;
	printf("\n\n---------Packet---Starts----\n\n");
	while(len--)
	{
		printf("%.2x ", *p);
		p++;
	}
	printf("\n\n--------Packet---Ends-----\n\n");
}

unsigned int getIPAddr(char *interface){
	struct ifreq ifr;
	int fd;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd); 
	
	//printf("%s: %s\n", interface, inet_ntoa( ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr ));
	return inet_addr(inet_ntoa( ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr) );
}
/* Ethernet and Arp specific headers ripped from the packet injection tutorial */

#define VETH0_MAC "82:67:9e:07:15:30"
#define VETH1_MAC "a2:4d:4a:8f:e6:a3"

typedef struct EthernetHeader{

	unsigned char destination[6]; 
	unsigned char source[6];
	unsigned short protocol;

} EthernetHeader;

typedef struct ArpHeader{

	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned char hard_addr_len;
	unsigned char prot_addr_len;
	unsigned short opcode;
	unsigned char source_hardware[6];
	unsigned char source_ip[4];
	unsigned char dest_hardware[6];
	unsigned char dest_ip[4];
}ArpHeader;

typedef struct IpHeader {
 unsigned char ip_hl:4, ip_v:4; /* this means that each member is 4 bits */
 unsigned char ip_tos;
 unsigned short int ip_len;
 unsigned short int ip_id;
 unsigned short int ip_off;
 unsigned char ip_ttl;
 unsigned char ip_p;
 unsigned short int ip_sum;
 unsigned int ip_src;
 unsigned int ip_dst;
}IpHeader; /* total ip header length: 20 bytes (=160 bits) */



/* Sniffer Thread */

#define MAX_PACKETS 1
#define BUF_SIZE 2048

void *sniffer_thread(void *arg)
{
	int raw_ppp, raw_veth;
	unsigned char packet_buffer[BUF_SIZE]; 
	int len;
	struct sockaddr_ll packet_info;
	int packet_info_size = sizeof(packet_info_size);
	int counter = MAX_PACKETS;
	EthernetHeader *ethernet_header;
	IpHeader *ip_header;
	ArpHeader *arp_header;
	unsigned int ppp_ip;
	unsigned char *pkt;
	struct iphdr *linux_iphdr;


	
	printf("inside sniffer thread\n");
	ppp_ip = getIPAddr(interface_in);
	/* create the raw socket*/
	raw_ppp = CreateRawSocket(PF_PACKET, ETH_P_ALL);
	raw_veth = CreateRawSocket(PF_PACKET, ETH_P_ALL);

	/* Bind socket to interface */
	BindRawSocketToInterface(interface_in, raw_ppp, ETH_P_ALL);
	BindRawSocketToInterface(interface_out, raw_veth, ETH_P_ALL);

	/* Start Sniffing and print Hex of every packet */
	while(1)
	{
		printf("waiting for packets to come in .... \n");
		bzero(packet_buffer, BUF_SIZE);
		if((len = recvfrom(raw_ppp, packet_buffer, BUF_SIZE, 0, (struct sockaddr*)&packet_info, &packet_info_size)) == -1)
		{
			perror("Recv from returned -1: ");
			exit(-1);
		}
		else
		{
			//printf("received raw socket!\n");
			//if(len < sizeof(EthernetHeader) + sizeof(ArpHeader))
			if(len < sizeof(IpHeader))
			{
				printf("Short packet\n");
				continue;
			}

			/* Packet has been received successfully !! */
			/* Check if it is IP */
			ip_header = (IpHeader *)packet_buffer;
			if(ip_header->ip_dst != ppp_ip){ //the destination is not to the ppp, no need to forward to veth
				continue;
			}
			
			/* Send the packet to the injector for modification */
			int pkt_len = (len + sizeof(EthernetHeader));
			pkt = (unsigned char *)malloc(len + sizeof(EthernetHeader));
			memcpy(pkt+sizeof(EthernetHeader), packet_buffer, len);
			
			/*faking the ethernet header*/
			ethernet_header = (EthernetHeader *)pkt;
			memcpy(ethernet_header->source , (void *)ether_aton(VETH1_MAC), 6);
			memcpy(ethernet_header->destination , (void *)ether_aton(VETH0_MAC), 6);
			ethernet_header->protocol =  htons(ETH_P_IP);
			counter-- ;

			if( SendRawPacket(raw_veth, pkt, pkt_len) ){
				//	printf("SNIFFER: Forword the IP Packet to Host \n");
			}else{
					printf("SNIFFER: Fail to forward the IP Packet to Host\n");
			}

			/* Print packet in hex */
			//PrintPacketInHex(pkt, (len + sizeof(EthernetHeader)));
		}
	}
	close(raw_ppp);
	close(raw_veth);
}


/* Injector Thread */

void *injector_thread(void *arg)
{
	int raw_ppp, raw_veth;
	unsigned char packet_buffer[BUF_SIZE]; 
	int len;
	struct sockaddr_ll packet_info;
	int packet_info_size = sizeof(packet_info_size);
	int counter = MAX_PACKETS;
	EthernetHeader *ethernet_header;
	IpHeader *ip_header;
	ArpHeader *arp_header;
	unsigned char *pkt;
	unsigned char temp[6];
	unsigned int ppp_ip = getIPAddr(interface_in);


	printf("inside injector thread\n");

	/* create the raw socket*/
	raw_ppp = CreateRawSocket(AF_INET, IPPROTO_RAW);
	int tmp = 1;
	if( setsockopt(raw_ppp, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0){
		perror("setsockopt:");
		exit(-1);
	}
	/*if( (raw_ppp = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) <0 ){
		perror("socket():");
		exit(1);
	}*/

	raw_veth = CreateRawSocket(PF_PACKET, ETH_P_ALL);

	/* Bind socket to interface */
	BindRawSocketToInterface(interface_in, raw_ppp, 0);
	BindRawSocketToInterface(interface_out, raw_veth, ETH_P_ALL);

	/* Start Sniffing and print Hex of every packet */
	while(1)
	{
		printf("waiting for packets to come in .... \n");
		bzero(packet_buffer, BUF_SIZE);
		if((len = recvfrom(raw_veth, packet_buffer, BUF_SIZE, 0, (struct sockaddr*)&packet_info, &packet_info_size)) == -1)
		{
			perror("Recv from returned -1: ");
			exit(-1);
		}
		else
		{
			printf("INJECTOR: received raw socket from veth0!\n");
			
			if(len < sizeof(EthernetHeader))
			{
				printf("Short packet\n");
				continue;
			}

			/* Packet has been received successfully !! */
			/* Check if it is IP */
			ethernet_header = (EthernetHeader *)packet_buffer;
			
			if(ethernet_header->protocol == htons(ETH_P_ARP)){
				if(len < (sizeof(EthernetHeader) + sizeof(ArpHeader)) ){
					printf("Malformat ARP\n");
				}
				printf("Got an ARP!\n\n\n");
				arp_header = (ArpHeader *)(packet_buffer + sizeof(EthernetHeader));
				memcpy(ethernet_header->destination, ethernet_header->source, 6);
				memcpy(ethernet_header->source , (void *)ether_aton(VETH1_MAC), 6);
				arp_header->opcode = htons(ARPOP_REPLY);
				memcpy(temp, arp_header->source_ip, 4);
				memcpy(arp_header->source_ip, arp_header->dest_ip, 4);
				memcpy(arp_header->dest_ip, temp, 4);
				if(SendRawPacket(raw_veth, packet_buffer, sizeof(EthernetHeader) + sizeof(ArpHeader)) ){
						printf("INJECTOR: Fake the arp reply\n");
				}else{
						printf("INJECTOR: Fail to send the arp reply\n");
				}
				continue;
			}
			
			/* Send the packet to the injector for modification */
			int pkt_len = (len - sizeof(EthernetHeader));
			pkt = (unsigned char *)malloc(len - sizeof(EthernetHeader));
			memcpy(pkt, packet_buffer+sizeof(EthernetHeader), pkt_len);
			ip_header = (IpHeader *) pkt;
			if(ip_header->ip_src != ppp_ip){ //the destination is not to the ppp, no need to forward to veth
				continue;
			}
			
			counter-- ;
			
			struct sockaddr_in sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr = ip_header->ip_dst;

			/*if( SendRawPacket(raw_ppp, pkt, pkt_len) ){
					printf("INJECTOR: Forword the IP Packet to PPP \n");
			}else{
					printf("INJECTOR: Fail to forward the IP Packet to PPP\n");
			}*/
			if (sendto(raw_ppp, pkt, pkt_len, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0){
				PrintPacketInHex(pkt, pkt_len);
				perror("sendto");
				continue;
			}else{
					printf("INJECTOR: Forword the IP Packet to PPP \n");
			}

			/* Print packet in hex */		
			//PrintPacketInHex(pkt, pkt_len);
		}
	}
	close(raw_ppp);
	close(raw_veth);

}


/* The main function */

int main(int argc, char **argv)
{
	/* Assign the Interface e.g. eth0 */
	interface_in = argv[1];
	interface_out = argv[2];
	if(argc != 3){
		printf("usage: %s interface_in interface_out", argv[0]);
		return 0;	
	}

	/* The Thread Ids */
	pthread_t sniffer;
	pthread_t injector;


	/* Start the threads - Pass them the message queue id as argument */
	if((pthread_create(&sniffer, NULL, sniffer_thread)) != 0)
	{
		printf("Error creating Sniffer thread - Exiting\n");
		exit(-1);
	}

	if((pthread_create(&injector, NULL, injector_thread)) != 0)
	{
		printf("Error creating Injector thread - Exiting\n");
		exit(-1);
	}

	/* Wait for the threads to exit */
	pthread_join(sniffer);
	pthread_join(injector);

	return 0;
}

