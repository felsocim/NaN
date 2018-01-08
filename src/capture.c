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
		fprintf(stderr, "Could not open live capture on device '%s': %s\n", device, errbuf);
		return NULL;
	}

	printf("Capture created for device: %s\n", dev);

  if(filter != NULL) {
    set_filter(capture, filter, device, errbuf);
  }

	return capture;
}

pcap_t * get_offline_capture(char * trace) {
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t * capture = pcap_open_offline(trace, errbuf);
	if(capture == NULL) {
		fprintf(stderr, "Could not open offline capture from trace file '%s': %s\n", trace, errbuf);
		return NULL;
	}

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
  free(datetime);

  u_int16_t type = ntohs(ethernet->ether_type);

  // Process overlying protocols' headers
	switch(type) {
		case ETHERTYPE_IP: // Internet Protocol of version 4
			process_ipv4(packet, *args);
			break;
    case ETHERTYPE_IPV6: // Internet Protocol of version 6
			process_ipv6(packet, *args);
			break;
    case ETHERTYPE_ARP: // Address Resolution Protocol
      process_arp(packet, false, *args);
      break;
    case ETHERTYPE_REVARP: // Reverse Address Resolution Protocol
      process_arp(packet, true, *args);
      break;
		default: // Unsupported packet types
      printf("%sunsupported EtherType [value: 0x%X]", (*args == VERBOSITY_HIGH ? "  └─ " : ""), type);
      if(type >= 0 && type <= 0x05DC)
        printf(" (IEEE802.3 Ethernet II length)\n");
      else
        printf("\n");
			break;
	}

  if(*args > VERBOSITY_LOW)
    printf("\n");
}

int init_capture(pcap_t * capture, int nb_packets, u_char verbosity) {
	printf("Starting pcap loop with verbosity level set to %c\n\n", verbosity);
	return pcap_loop(capture, nb_packets, got_packet, &verbosity);
}

void set_filter(pcap_t * capture, char * filter, char * device, char * errbuf) {
  if(capture == NULL)
    failwith("Failed to set given filter! Capture cannot be NULL");

  if(filter == NULL)
    failwith("Failed to set given filter! Filter string cannot be empty nor NULL");

  if(device == NULL)
    failwith("Failed to set given filter! Device name cannot be empty nor NULL");

  struct bpf_program fltr;
  bpf_u_int32 subnet_mask, ip;

  if(pcap_lookupnet(device, &ip, &subnet_mask, errbuf) == -1) {
    fprintf(stderr, "Could not get network information for device '%s': %s\n", device, errbuf);
    exit(EXIT_FAILURE);
  }

  if(pcap_compile(capture, &fltr, filter, 0, ip) == -1) {
    fprintf(stderr, "Could not compile provided filter! Check your syntax, plase: %s\n", pcap_geterr(capture));
    exit(EXIT_FAILURE);
  }

  if(pcap_setfilter(capture, &fltr) == -1) {
    fprintf(stderr, "Could not set compiled filter: %s\n", pcap_geterr(capture));
    exit(EXIT_FAILURE);
  }

  printf("Filter '%s' set for live capture on device %s\n", filter, device);
}
