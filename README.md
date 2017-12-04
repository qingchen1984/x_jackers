# x_jackers

This project was part of the Hacking course at Ecole polytechnique (INF474X).

Team Mates:
- VincentCodeur
- armand33 
- toroloco

1.Find our code
You can find our full code whenever you want on our public repo: https://github.com/armand33/x_jackers 

2. Compilation
Prerequisites : you need to have libpcap (http://www.tcpdump.org/) and libnet (http://libnet.sourceforge.net/) installed in order to compile this program.
You can compile the MAC flooder with
make flood
You can compile the ARP flooder with
make arpflooder
You can compile the DNS hijacker with
make dns
You can compile the ARP spoofer with
make arpspoofer
And you can
make all


3.Utilisation
To perform a MAC flooding attack, type: 
	./MACFlooder <number of messages>
which will send the defined number of messages on the network with random IP and layer 2 addresses.	
To perform an ARP flooding attack type:
	./ARPFlooder <number of messages>
which will send the defined number of random ARP gratuitous messages.
To perform a DNS hijacking attack, type: 
	./DNSHijacker [<IP addr answered> [<IP addr to target>]]> 
The two arguments are optional, but in order to use the second one you have to specify the first one. 
The first argument is the IP adress to where you redirect your victims, whatever is the website they are trying to visit. By default it is 129.104.30.29 (polytechnique's website). The second one is the IP address of your victim, if you want it to be a unique person on the network.
To perform an ARP spoofing attack, type
	./ARPspoofing <IP addr>
which will send gratuitous ARP with the specified IP address on link layer broadcast, until you stop it with ^C.
