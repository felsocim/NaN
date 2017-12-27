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

	pcap_t * capture = pcap_open_live(dev, MAX_SNAPSHOT_LENGTH, 0, 0, errbuf);
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

void got_packet(u_char * args, const struct pcap_pkthdr * header, const u_char * packet) {
	// Ethernet header parsing
	const struct ether_header * ethernet = (struct ether_header *) (packet);
	const struct ether_addr * src = (struct ether_addr *) (ethernet->ether_shost);
	const struct ether_addr * dst = (struct ether_addr *) (ethernet->ether_dhost);

	// Ethernet packet information processing
	char * source = malloc(MAC_ADDRESS_LENGTH);
	char * destination = malloc(MAC_ADDRESS_LENGTH);

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

int init_capture(pcap_t * capture, int nb_packets, u_char verbosity) {
#if DEBUG == 1
	printf("Starting pcap loop with verbosity level set to %u\n", verbosity);
#endif
	return pcap_loop(capture, nb_packets, got_packet, &verbosity);
}
