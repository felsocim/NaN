#include "../include/capture.h"

pcap_t * get_online_capture(char * device, char * filter) {
	char * dev = NULL;
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

#if DEBUG
	printf("Capture created for device: %s\n", dev);
#endif
	
	return capture;
}

pcap_t * get_offline_capture(char * trace) {
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_t * capture = pcap_open_offline(trace, errbuf);
	if(capture == NULL) {
		fprintf(stderr, "Could not open offline capture from trace file '%s': %s\n", trace, errbuf);
		return NULL;
	}
	
	// Debug
	printf("Capture created from file: %s\n", trace);
	
	return capture;
}

void process_ip(const u_char * packet) {
	// IP header parsing
	const struct ip * header = (struct ip *) (packet + sizeof(struct ether_header));
	
	// IP packet information extraction
	char * source = NULL, * destination = NULL;
	switch(header->ip_v) {
		case 4:
			source = malloc(INET_ADDRSTRLEN);
			destination = malloc(INET_ADDRSTRLEN);

			if(inet_ntop(AF_INET, &header->ip_src, source, INET_ADDRSTRLEN) == NULL)
				failwith("Failed to convert source IP address to string");
			if(inet_ntop(AF_INET, &header->ip_dst, destination, INET_ADDRSTRLEN) == NULL)
				failwith("Failed to convert destination IP address to string");

			printf("IP from %s to %s\n", source, destination);

			free(source);
			free(destination);			
			break;
		default:
			break;
	}
}

void process_packet(u_char * args, const struct pcap_pkthdr * header, const u_char * packet) {
	// Ethernet header parsing
	const struct ether_header * ethernet = (struct ether_header *) (packet);
	const struct ether_addr * src = (struct ether_addr *) (ethernet->ether_shost);
	const struct ether_addr * dst = (struct ether_addr *) (ethernet->ether_dhost);
	
	// Ethernet packet information processing
	char * source = malloc(MAC_ADDR_LENGTH);
	char * destination = malloc(MAC_ADDR_LENGTH);

	source = strcpy(source, ether_ntoa(src));
	destination = strcpy(destination, ether_ntoa(dst));	

	// Print out ethernet packet information
	// printf("Ethernet: from %s to %s\n", source, destination);

	switch(ntohs(ethernet->ether_type)) {
		case ETHERTYPE_IP: //IP packet
			process_ip(packet);
			break;
		default:
			break;
	}

	// Memory free
	free(source); 
	free(destination);
}

int init_capture(pcap_t * capture, int nb_packets) {
	// Debug
	printf("Starting loop\n");
	return pcap_loop(capture, nb_packets, process_packet, NULL);
}
