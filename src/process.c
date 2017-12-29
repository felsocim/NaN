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

void process_arp(const u_char * packet, Bool reverse, u_char verbosity) {
  // ARP header parsing
	const struct ether_arp * header = (struct ether_arp *) (packet + sizeof(struct ether_header));

  Bool unsupported = False;

  unsigned short int operation = ntohs(header->arp_op);

  // Select hardware type
  switch(ntohs(header->arp_hrd)) {
    case ARPHRD_ETHER: // Ethernet type address resolution packet
      if(ntohs(header->arp_pro) == ETHERTYPE_IP || ARP_GET_TYPE(operation) == ARP_UNKNOWN) {
        char * hw_source = (char *) malloc((MAC_ADDRESS_LENGTH + 1) * sizeof(char));
        char * hw_destination = (char *) malloc((MAC_ADDRESS_LENGTH + 1) * sizeof(char));

        if(hw_source == NULL)
          failwith("Failed to reserve memory for hardware source address");

        if(hw_destination == NULL)
          failwith("Failed to reserve memory for hardware destination address");

        hw_source = strcpy(hw_source, ether_ntoa((struct ether_addr *) header->arp_sha));
        hw_destination = strcpy(hw_destination, ether_ntoa((struct ether_addr *) header->arp_tha));

        u_int32_t ips = DESERIALIZE_UINT32(header->arp_spa);
        u_int32_t ipd = DESERIALIZE_UINT32(header->arp_tpa);

        struct in_addr s_ips, s_ipd;
        s_ips.s_addr = ips;
        s_ipd.s_addr = ipd;

        char * ip_source = (char *) malloc((INET_ADDRSTRLEN + 1) * sizeof(char));
        char * ip_destination = (char *) malloc((INET_ADDRSTRLEN + 1) * sizeof(char));

      	if(ip_source == NULL)
          failwith("Failed to reserve memory for internet protocol source address");

        if(ip_destination == NULL)
          failwith("Failed to reserve memory for internet protocol destination address");

        if(inet_ntop(AF_INET, &s_ips, ip_source, INET_ADDRSTRLEN) == NULL)
      		failwith("Failed to convert source IP address to string");
      	if(inet_ntop(AF_INET, &s_ipd, ip_destination, INET_ADDRSTRLEN) == NULL)
      		failwith("Failed to convert destination IP address to string");

        switch(verbosity) {
          case VERBOSITY_LOW:
            if(ARP_GET_TYPE(operation) == ARP_REQUEST)
              printf("%s who has %s tell %s\n", (reverse ? "rarp" : "arp"), ip_destination, ip_source);
            else
              printf("%s reply %s is-at %s\n", (reverse ? "rarp" : "arp"), ip_source, hw_source);
            break;
          case VERBOSITY_MEDIUM:
            if(ARP_GET_TYPE(operation) == ARP_REQUEST)
              printf("%s who has %s (%s) tell %s (%s)\n", (reverse ? "rarp" : "arp"), ip_destination, hw_destination, ip_source, hw_source);
            else
              printf("%s reply %s is-at %s\n", (reverse ? "rarp" : "arp"), ip_source, hw_source);
            break;
          case VERBOSITY_HIGH:
            printf("  └─ \"%sAddress Resolution Protocol packet\"\n", (reverse ? "Reverse " : ""));
            printf("    ├─ Hardware type: Ethernet 10/100Mbps (%u)\n", ntohs(header->arp_hrd));
            printf("    ├─ Protocol type: IPv4 (%04x)\n", ntohs(header->arp_pro));
            printf("    ├─ Hardware address length: %u\n", header->arp_hln);
            printf("    ├─ Protocol address length: %u\n", header->arp_pln);
            printf("    ├─ Operation: %s (%u)\n", (ARP_GET_TYPE(operation) == ARP_REQUEST ? "request" : "reply"), header->arp_op);
            printf("    ├─ Sender hardware address: %s\n", hw_source);
            printf("    ├─ Sender protocol address: %s\n", ip_source);
            printf("    ├─ Target hardware address: %s\n", hw_destination);
            printf("    └─ Target protocol address: %s\n", ip_destination);
            break;
          default:
            failwith("Unknown verbosity level");
        }

        // Used memory free
        free(hw_source);
        free(hw_destination);
        free(ip_source);
        free(ip_destination);
      } else {
        unsupported = True;
      }
      break;
    // Eventually add support for other hardware types
    default:
      unsupported = True;
      break;
  }

  if(unsupported) {
    printf("unsupported address resolution packet\n");
  }
}
