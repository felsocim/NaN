#include "../include/capture.h"

pcap_t * get_online_capture(char * device, char * filter) {
	char * dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if(device == NULL) {
		dev = pcap_lookupdev(errbuf);
		if(dev == NULL) {
			fprintf(stderr, "Could not find the default network device: %s\n", errbuf);
			return NULL;
		}
	} else {
		pcap_if_t * interfaces, *temp;
		if(pcap_findalldevs(&interfaces, errbuf) == -1) {
			fprintf(stderr, "Error listing network interfaces: %s\n", errbuf);
			return NULL;
		}
		
		temp = interfaces;
		
		while(temp != NULL) {
			if(strcmp(temp->name, device) == 0) {
				dev = device;
			}
			temp = temp->next;
		}
	}
	
	if(dev == NULL) {
		fprintf(stderr, "The requested interface was not found on your system!\n");
		return NULL;
	}
	
	pcap_t * capture = pcap_open_live(dev, MAX_SNAPLEN, 0, 0, errbuf);
	if(capture == NULL) {
		fprintf(stderr, "Could not open live capture on device '%s': %s\n", dev, errbuf);
		return NULL;
	}
	
	// Debug
	printf("Capture created for device: %s\n", dev);
	
	return capture;
}

void process_ethernet(const struct ether_header * header) {
	const struct ether_addr * src, *dst;
	src = (struct ether_addr *) (header->ether_dhost);
	dst = (struct ether_addr *) (header->ether_shost);
	
	char * source = malloc(16), * destination = malloc(16);
	
	source = strcpy(source, ether_ntoa(src));
	destination = strcpy(destination, ether_ntoa(dst));	
	
	// For testing purposes only
	printf("Ethernet packet: @source = %s, @destination = %s, eq? %d\n", source, destination, (header->ether_dhost == header->ether_shost));
	
	free(source); free(destination);
	
	//if(header->ether_type = ETHERTYPE_IP) {
		//const struct ip * iph = (struct ip *) (header + sizeof(struct ether_header))
}

//void process_ip(const struct ip * header) {
	

void process_packet(u_char * args, const struct pcap_pkthdr * header, const u_char * packet) {
	const struct ether_header * ethernet = (struct ether_header *) (packet);
	process_ethernet(ethernet);
}

int init_capture(pcap_t * capture, int nb_packets) {
	// Debug
	printf("Starting loop\n");
	return pcap_loop(capture, nb_packets, process_packet, NULL);
}
