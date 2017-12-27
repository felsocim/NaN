#include "../include/process.h"

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
