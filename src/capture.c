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
  char * source = NULL, * destination = NULL;

  if(*args > VERBOSITY_LOW) {
    const struct ether_addr * src = (struct ether_addr *) (ethernet->ether_shost);
  	const struct ether_addr * dst = (struct ether_addr *) (ethernet->ether_dhost);

  	// Ethernet packet information processing
  	source = (char *) malloc((MAC_ADDRESS_LENGTH + 1) * sizeof(char));
  	destination = (char *) malloc((MAC_ADDRESS_LENGTH + 1) * sizeof(char));

    if(source == NULL)
      failwith("Failed to reserve memory for MAC source address");

    if(destination == NULL)
      failwith("Failed to reserve memory for MAC destination address");

  	source = strcpy(source, ether_ntoa(src));
  	destination = strcpy(destination, ether_ntoa(dst));
  }

  // Extract frame's timestamp
  struct tm * timestamp = localtime(&header->ts.tv_sec);

  if(timestamp == NULL)
    failwith("Failed to extract date/time information from time value structure");

  char * timestring = (char *) malloc(MAX_TIMESTAMP_LENGTH * sizeof(char));
  char * datetime = (char *) malloc(MAX_TIMESTAMP_LENGTH * sizeof(char));

  if(timestring == NULL)
    failwith("Failed to reserve memory for timestamp string");

  if(datetime == NULL)
    failwith("Failed to reserve memory for final date/time string");

  size_t r_code = strftime(timestring, MAX_TIMESTAMP_LENGTH, "%d/%m/%Y %H:%M:%S", timestamp);

  if(r_code < 1 || r_code >= MAX_TIMESTAMP_LENGTH)
    failwith("Failed to format time stamp to human readable string");

  r_code = snprintf(datetime, MAX_TIMESTAMP_LENGTH, "%s.%06ld", timestring, header->ts.tv_usec);

  if(r_code < 1 || r_code >= MAX_TIMESTAMP_LENGTH)
    failwith("Failed to increase timestamp string's precision");

	// Print ethernet packet information
	switch(*args) {
    case VERBOSITY_LOW:
      printf("%s ", datetime);
      break;
    case VERBOSITY_MEDIUM:
      printf("%s:\nETH %s > %s\n", datetime, source, destination);
      break;
    case VERBOSITY_HIGH:
      printf("%s \"Ethernet frame\" from %s to %s\n", datetime, source, destination);
      break;
    default:
      failwith("Unknown verbosity level detected");
  }

  // Used memory free
  if(*args > VERBOSITY_LOW) {
    free(source);
  	free(destination);
  }

  free(timestring);

  // Process overlying protocols' headers
	switch(ntohs(ethernet->ether_type)) {
		case ETHERTYPE_IP: //IPv4
			process_ipv4(packet, *args);
			break;
    case ETHERTYPE_IPV6: //IPv6
			process_ipv6(packet, *args);
			break;
    case ETHERTYPE_ARP:
      process_arp(packet, False, *args);
      break;
    case ETHERTYPE_REVARP:
      process_arp(packet, True, *args);
      break;
		default:
      printf("unknown packet type (0x%04x)\n", ntohs(ethernet->ether_type));
			break;
	}
}

int init_capture(pcap_t * capture, int nb_packets, u_char verbosity) {
#if DEBUG == 1
	printf("Starting pcap loop with verbosity level set to %c\n", verbosity);
#endif
	return pcap_loop(capture, nb_packets, got_packet, &verbosity);
}
