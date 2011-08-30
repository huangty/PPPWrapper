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

#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/ipc.h>
//#include <sys/msg.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

/* Global */
char *interface_in;
char *interface_out;
unsigned int ppp_ip;

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
	
	printf("%s: %s\n", interface, inet_ntoa( ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr ));
	return inet_addr(inet_ntoa( ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr) );
}

void print_ip(int ip, char* ip_string)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;       
	sprintf(ip_string, "%d.%d.%d.%d\0", bytes[0], bytes[1], bytes[2], bytes[3]); 
	return;
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



/* Sniffer Thread -- get packets from PPP, pass it to Veth*/

#define MAX_PACKETS 1
#define BUF_SIZE 2048

void *sniffer_thread(void *arg)
{
	int raw_ppp;
	int raw_veth;
	unsigned char packet_buffer[BUF_SIZE]; 
	int len;
	struct sockaddr_ll packet_info;
	int packet_info_size = sizeof(packet_info_size);
	int counter = MAX_PACKETS;
	EthernetHeader *ethernet_header;
	IpHeader *ip_header;
	ArpHeader *arp_header;
	unsigned char *pkt;
	struct iphdr *linux_iphdr;

	/* create the raw socket*/
	raw_ppp = CreateRawSocket(PF_PACKET, ETH_P_ALL);
	raw_veth = CreateRawSocket(PF_PACKET, ETH_P_ALL);

	/* Bind socket to interface */
	BindRawSocketToInterface(interface_in, raw_ppp, ETH_P_ALL);
	BindRawSocketToInterface(interface_out, raw_veth, ETH_P_ALL);

	
	printf("inside sniffer thread\n");
	//ppp_ip = getIPAddr(interface_in);
	
	/* Start Sniffing and print Hex of every packet */
	while(1)
	{
		printf("SNIFFER: waiting for packets to come in from PPP.... \n");
		bzero(packet_buffer, BUF_SIZE);
		if((len = recvfrom(raw_ppp, packet_buffer, BUF_SIZE, 0, (struct sockaddr*)&packet_info, &packet_info_size)) == -1)
		{
			perror("Recv from PPP returned -1: ");
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
			if(ip_header->ip_dst != ppp_ip || ip_header->ip_src == ppp_ip ){ 
				//the destination is not to the ppp, no need to forward to veth or, the src is ppp then will loop
				continue;
			}			
			
			
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
					printf("SNIFFER: Forword the IP Packet to Host \n");
			}else{
					printf("SNIFFER: Fail to forward the IP Packet to Host\n");
			}

			/* Print packet in hex */
			//PrintPacketInHex(pkt, (len + sizeof(EthernetHeader)));
		}
	}
	close(raw_ppp);
	close(raw_veth);
	pthread_exit(NULL);
}


/* Injector Thread -- forward packet from the host (veth) to ppp */

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
	//unsigned int ppp_ip = getIPAddr(interface_in);
	
	char ip_string[10]="\0";


	printf("inside injector thread\n");

	/* create the raw socket*/
	raw_ppp = CreateRawSocket(AF_INET, IPPROTO_RAW);
	int tmp = 1;
	if( setsockopt(raw_ppp, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0){
		perror("setsockopt:");
		exit(-1);
	}
	raw_veth = CreateRawSocket(PF_PACKET, ETH_P_ALL);

	/* Bind socket to interface */
	BindRawSocketToInterface(interface_in, raw_ppp, 0);
	BindRawSocketToInterface(interface_out, raw_veth, ETH_P_ALL);

	/* Start Sniffing and print Hex of every packet */
	while(1)
	{
		printf("INJECTOR: waiting for packets to come in .... \n");
		bzero(packet_buffer, BUF_SIZE);
		if((len = recvfrom(raw_veth, packet_buffer, BUF_SIZE, 0, (struct sockaddr*)&packet_info, &packet_info_size)) == -1)
		{
			perror("Recv from veth returned -1: ");
			exit(-1);
		}
		else
		{
			printf("INJECTOR: received raw socket from %s\n", interface_out);
			
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
				arp_header = (ArpHeader *)(packet_buffer + sizeof(EthernetHeader));
				if( arp_header->opcode == htons(ARPOP_REQUEST)){
					printf("Got an ARP Request!\n\n\n");
					memcpy(ethernet_header->destination, ethernet_header->source, 6);
					memcpy(ethernet_header->source , (void *)ether_aton(VETH1_MAC), 6);
					arp_header->opcode = htons(ARPOP_REPLY);
					memcpy(arp_header->dest_hardware, arp_header->source_hardware, 6);
					memcpy(arp_header->source_hardware, (void *)ether_aton(VETH1_MAC), 6);
					memcpy(temp, arp_header->source_ip, 4);
					memcpy(arp_header->source_ip, arp_header->dest_ip, 4);
					memcpy(arp_header->dest_ip, temp, 4);
					if(SendRawPacket(raw_veth, packet_buffer, sizeof(EthernetHeader) + sizeof(ArpHeader)) ){
							printf("INJECTOR: Fake the arp reply\n");
					}else{
							printf("INJECTOR: Fail to send the arp reply\n");
					}
				}
				continue;
			}
			
			
			int pkt_len = (len - sizeof(EthernetHeader));
			pkt = (unsigned char *)malloc(len - sizeof(EthernetHeader));
			memcpy(pkt, packet_buffer+sizeof(EthernetHeader), pkt_len);
			ip_header = (IpHeader *) pkt;
			
	
			/*print_ip(ppp_ip, ip_string);
			printf("PPP_IP = %s\n", ip_string);
		    print_ip(ip_header->ip_src, ip_string);
		    printf("Packet IP = %s\n", ip_string);*/

			if(ip_header->ip_src != ppp_ip){ //the source is not set as ppp, no need to inject to PPP
				continue;
			}
			
			//counter-- ;
			
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
				printf("INJECTOR: Fail to send packets to PPP interface \n");
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
	pthread_exit(NULL);
}

void thread_termination_handler(int signo){
    if (signo == SIGINT) {
        printf("Ctrl+C detected !!! \n");
	}
    (void)signo;
}

/* The main function */
int main(int argc, char **argv)
{
	/* Assign the Interface e.g. eth0 */
	interface_in = argv[1];
	interface_out = argv[2];
	if(argc != 4){
		printf("usage: %s interface_ppp interface_veth ppp_ip", argv[0]);
		return 0;	
	}
	ppp_ip = inet_addr(argv[3]);

	char ip_string[10] = "\0";
	print_ip(ppp_ip, ip_string);
	printf("PPP_IP = %s\n", ip_string);
	
	/* The Thread Ids */
	pthread_t sniffer;
	pthread_t injector;
	
	/*Signal Handling*/
	sigset_t mask, old_mask;
	siginfo_t info;
	/* Create a mask holding only SIGINT - ^C Interrupt */
	sigemptyset( &mask );
	sigaddset( &mask, SIGINT );
	/* Set the mask for our main thread to include SIGINT */
	pthread_sigmask( SIG_BLOCK, &mask, &old_mask);


	/* Start the threads - Pass them the message queue id as argument */
	if((pthread_create(&sniffer, NULL, sniffer_thread, NULL)) != 0)
	{
		printf("Error creating Sniffer thread - Exiting\n");
		exit(-1);
	}

	if((pthread_create(&injector, NULL, injector_thread, NULL)) != 0)
	{
		printf("Error creating Injector thread - Exiting\n");
		exit(-1);
	}
	
	// Install the signal handler for SIGINT.
    struct sigaction s;
    s.sa_handler = thread_termination_handler;
    sigemptyset(&s.sa_mask);
    s.sa_flags = 0;
    sigaction(SIGINT, &s, NULL);

    // Restore the old signal mask only for this thread.
    pthread_sigmask(SIG_SETMASK, &old_mask, NULL);

	/* Wait for the threads to exit */
	pthread_join(sniffer, NULL);
	pthread_join(injector, NULL);

   // Done.
    puts("Terminated.");
	return 0;
}

