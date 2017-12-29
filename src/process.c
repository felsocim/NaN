#include "../include/process.h"

void process_ipv4(const u_char * packet, u_char verbosity) {
	// IP header parsing
	const struct ip * header = (struct ip *) (packet + sizeof(struct ether_header));

	// IP addresses extraction
	char * source = (char *) malloc((INET_ADDRSTRLEN + 1) * sizeof(char));
  char * destination = (char *) malloc((INET_ADDRSTRLEN + 1) * sizeof(char));

	if(source == NULL)
    failwith("Failed to reserve memory for IP source address");

  if(destination == NULL)
    failwith("Failed to reserve memory for IP destination address");

	if(inet_ntop(AF_INET, &header->ip_src, source, INET_ADDRSTRLEN) == NULL)
		failwith("Failed to convert source IP address to string");
	if(inet_ntop(AF_INET, &header->ip_dst, destination, INET_ADDRSTRLEN) == NULL)
		failwith("Failed to convert destination IP address to string");

  // IP flags extraction
  char flags[IPV4_PACKET_FLAGS_LENGTH] = "---\0";
  u_short offset = ntohs(header->ip_off);

  if(offset & IP_RF) {
    flags[0] = 'R';
  }

  if(offset & IP_DF) {
    flags[1] = 'D';
  }

  if(offset & IP_MF) {
    flags[2] = 'M';
  }

  // Print IP packet information
  switch(verbosity) {
    case VERBOSITY_LOW:
      printf("IP %s > %s [%s] \n", source, destination, flags);
      break;
    case VERBOSITY_MEDIUM:
      printf("IP %s > %s [%s] id %u\n", source, destination, flags, header->ip_id);
      break;
    case VERBOSITY_HIGH:
      printf("  └─ \"IP version 4\" from %s to %s\n", source, destination);
      printf("    ├─ Type of service: %u\n", header->ip_tos);
      printf("    ├─ Total length: %u\n", header->ip_len);
      printf("    ├─ Identification: %u\n", header->ip_id);
      printf("    ├─ Flags: %s\n", flags);
      printf("    ├─ Time to live: %u\n", header->ip_ttl);
      printf("    └─ Checksum: %u\n", header->ip_sum);
      break;
    default:
      failwith("Unknown verbosity level detected");
  }

  // Used memory free
	free(source);
	free(destination);
}

void process_ipv6(const u_char * packet, u_char verbosity) {
	// IP header parsing
	const struct ip6_hdr * header = (struct ip6_hdr *) (packet + sizeof(struct ether_header));

	// IP addresses extraction
	char * source = (char *) malloc((INET6_ADDRSTRLEN + 1) * sizeof(char));
  char * destination = (char *) malloc((INET6_ADDRSTRLEN + 1) * sizeof(char));

	if(source == NULL)
    failwith("Failed to reserve memory for IP source address");

  if(destination == NULL)
    failwith("Failed to reserve memory for IP destination address");

	if(inet_ntop(AF_INET6, &header->ip6_src, source, INET6_ADDRSTRLEN) == NULL)
		failwith("Failed to convert source IP address to string");
	if(inet_ntop(AF_INET6, &header->ip6_dst, destination, INET6_ADDRSTRLEN) == NULL)
		failwith("Failed to convert destination IP address to string");

  // Print IP packet information
  switch(verbosity) {
    case VERBOSITY_LOW:
      printf("IPv6 %s > %s \n", source, destination);
      break;
    case VERBOSITY_MEDIUM:
      printf("IPv6 %s > %s \n", source, destination);
      break;
    case VERBOSITY_HIGH:
      printf("  └─ \"IP version 6\" from %s to %s\n", source, destination);
      printf("    ├─ Flow: %u\n", header->ip6_flow);
      printf("    ├─ Payload length: %u\n", header->ip6_plen);
      printf("    ├─ Next header: %u\n", header->ip6_nxt);
      printf("    └─ Hop limit: %u\n", header->ip6_hlim);
      break;
    default:
      failwith("Unknown verbosity level detected");
  }

  // Used memory free
	free(source);
	free(destination);
}
