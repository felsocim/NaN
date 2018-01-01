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

  u_int16_t identification = ntohs(header->ip_id);

  // Print IP packet information
  switch(verbosity) {
    case VERBOSITY_LOW:
      printf("IP %s > %s [%s] ", source, destination, flags);
      break;
    case VERBOSITY_MEDIUM:
      printf("IP %s > %s [%s] id %u\n", source, destination, flags, identification);
      break;
    case VERBOSITY_HIGH:
      printf("  └─ \"IP version 4\" from %s to %s\n", source, destination);
      printf("    ├─ IHL: %u\n", ntohs(header->ip_hl));
      printf("    ├─ Type of service: %u\n", header->ip_tos);
      printf("    ├─ Total length: %u bytes\n", ntohs(header->ip_len));
      printf("    ├─ Identification: %u\n", identification);
      printf("    ├─ Flags: %s\n", flags);
      printf("    ├─ Fragment offset: %u\n", ntohs(header->ip_tos & IP_OFFMASK));
      printf("    ├─ Time to live: %u\n", header->ip_ttl);
      printf("    └─ Header checksum: 0x%X\n", ntohs(header->ip_sum));
      break;
    default:
      failwith("Unknown verbosity level detected");
  }

  switch(header->ip_p) {
    case PROTO_TCP:
      process_tcp(packet, False, verbosity);
      break;
    case PROTO_UDP:
      process_udp(packet, False, verbosity);
      break;
    case PROTO_SCTP:
      // TODO: Call protocol tratment function
      break;
    default:
      break;
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
      printf("IPv6 %s > %s ", source, destination);
      break;
    case VERBOSITY_MEDIUM:
      printf("IPv6 %s > %s \n", source, destination);
      break;
    case VERBOSITY_HIGH:
      printf("  └─ \"IP version 6\" from %s to %s\n", source, destination);
      printf("    ├─ Traffic class: %u\n", (header->ip6_flow << 4) >> 20);
      printf("    ├─ Flow: %u\n", ntohs(header->ip6_flow << 12));
      printf("    ├─ Payload length: %u bytes\n", ntohs(header->ip6_plen));
      printf("    └─ Hop limit: %u\n", header->ip6_hlim);
      break;
    default:
      failwith("Unknown verbosity level detected");
  }

  switch(header->ip6_nxt) {
    case PROTO_TCP:
      process_tcp(packet, True, verbosity);
      break;
    case PROTO_UDP:
      process_udp(packet, True, verbosity);
      break;
    case PROTO_SCTP:
      // TODO: Call protocol tratment function
      break;
    default:
      break;
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
            printf("    ├─ Hardware address length: %u bytes\n", header->arp_hln);
            printf("    ├─ Protocol address length: %u bytes\n", header->arp_pln);
            printf("    ├─ Operation: %s (%u)\n", (ARP_GET_TYPE(operation) == ARP_REQUEST ? "request" : "reply"), operation);
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

void process_udp(const u_char * packet, Bool ipv6, u_char verbosity) {
	// UDP header parsing
	const struct udphdr * header = (struct udphdr *) (packet + sizeof(struct ether_header) + (ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip)));

  u_int16_t source = ntohs(header->source),
    destination = ntohs(header->dest),
    length = ntohs(header->len),
    checksum = ntohs(header->check);

  switch(verbosity) {
    case VERBOSITY_LOW:
      printf("udp src %u, dst %u \n", source, destination);
      break;
    case VERBOSITY_MEDIUM:
      printf("udp src %u, dst %u, len %u\n", source, destination, length);
      break;
    case VERBOSITY_HIGH:
      printf("    └─ \"UDP datagram\" from port %u to port %u\n", source, destination);
      printf("      ├─ Length (datagram's header including payload): %u bytes\n", length);
      printf("      └─ Checksum: 0x%X\n", checksum);
      break;
    default:
      failwith("Unknown verbosity level detected");
  }

  switch(destination) {
    case PROTO_FTP:
			// TODO: Call protocol tratment function
			break;
    case PROTO_SSH:
			// TODO: Call protocol tratment function
			break;
    case PROTO_TELNET:
			// TODO: Call protocol tratment function
			break;
    case PROTO_SMTP:
			// TODO: Call protocol tratment function
			break;
    case PROTO_BOOTPS:
			// TODO: Call protocol tratment function
			break;
    case PROTO_BOOTPC:
			// TODO: Call protocol tratment function
			break;
    case PROTO_WWW:
			// TODO: Call protocol tratment function
			break;
    case PROTO_IMAP:
			// TODO: Call protocol tratment function
			break;
    case PROTO_IMAP3:
			// TODO: Call protocol tratment function
			break;
    case PROTO_IMAPS:
			// TODO: Call protocol tratment function
			break;
    case PROTO_POP2:
			// TODO: Call protocol tratment function
			break;
    case PROTO_POP3:
			// TODO: Call protocol tratment function
			break;
    case PROTO_POPS:
			// TODO: Call protocol tratment function
			break;
  }
}

void process_tcp(const u_char * packet, Bool ipv6, u_char verbosity) {
	// TCP header parsing
	const struct tcphdr * header = (struct tcphdr *) (packet + sizeof(struct ether_header) + (ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip)));

  u_int16_t source = ntohs(header->th_sport),
    destination = ntohs(header->th_dport);

  u_int32_t sequence = ntohs(header->th_seq),
    acknowledgement = ntohs(header->th_ack);

  u_int8_t offset = header->th_off;

  u_int16_t window = ntohs(header->th_win),
    checksum = ntohs(header->th_sum),
    urgent_pointer = ntohs(header->th_urp);

  switch(verbosity) {
    case VERBOSITY_LOW:
      printf("tcp src %u, dst %u, ack %u ", source, destination, acknowledgement);
      break;
    case VERBOSITY_MEDIUM:
      printf("tcp src %u, dst %u, ack %u, seq %u ", source, destination, acknowledgement, sequence);
      break;
    case VERBOSITY_HIGH:
      printf("      └─ \"TCP packet\" from port %u to port %u\n", source, destination);
      printf("        ├─ Sequence number: %u \n", sequence);
      printf("        ├─ Acknowledgement number: %u\n", acknowledgement);
      printf("        ├─ Data offset: %u\n", offset);
      printf("        ├─ Window: %u\n", window);
      printf("        ├─ Checksum: 0x%X\n", checksum);
      printf("        ├─ Urgent pointer: 0x%X\n", urgent_pointer);
      printf("        %s Flags: ", (offset > 5 ? "├─" : "└─"));
      break;
    default:
      failwith("Unknown verbosity level detected");
  }

  if(header->th_flags & TH_FIN)
    printf("FIN ");
  if(header->th_flags & TH_SYN)
    printf("SYN ");
  if(header->th_flags & TH_RST)
    printf("RST ");
  if(header->th_flags & TH_PUSH)
    printf("PSH ");
  if(header->th_flags & TH_ACK)
    printf("ACK ");
  if(header->th_flags & TH_URG)
    printf("URG ");
  if ((header->th_flags == 0 || header->th_flags > 63) && verbosity == VERBOSITY_HIGH)
    printf("none");

  printf("\n");

  if(offset > 5 && verbosity == VERBOSITY_HIGH) {
    printf("        └─ Options: ");
    u_int8_t * options = ((u_int8_t *) header) + 20;
    u_int8_t * eol = options + ((offset - 5) * 4);

    while((eol - options) > 0) {
      switch(*options) {
        case TCPOPT_NOP:
          printf("no-operation ");
          options += 1;
          break;
        case TCPOPT_MSS:
          options += 2;
          printf("maximum-segment-size %u byte(s) ", ntohs((u_int16_t)*options));
          options += 2;
          break;
        case TCPOPT_WS:
          options += 2;
          printf("window-scale %u ", *options);
          options += 1;
          break;
        case TCPOPT_SACK:
          printf("sack-permitted ");
          options += 1;
          break;
        case TCPOPT_TSTMP:
          options += 2;
          printf("echo+timestamp %u", (u_int32_t)(*options));
          options += 4;
          printf(" %u ", (u_int32_t)(*options));
          options += 4;
          break;
        default:
          options += 1;
          options += *options;
          break;
      }
    }

    printf("\n");
  }

  switch(destination) {
    case PROTO_FTP:
			// TODO: Call protocol tratment function
			break;
    case PROTO_SSH:
			// TODO: Call protocol tratment function
			break;
    case PROTO_TELNET:
			// TODO: Call protocol tratment function
			break;
    case PROTO_SMTP:
			// TODO: Call protocol tratment function
			break;
    case PROTO_BOOTPS:
			// TODO: Call protocol tratment function
			break;
    case PROTO_BOOTPC:
			// TODO: Call protocol tratment function
			break;
    case PROTO_WWW:
			// TODO: Call protocol tratment function
			break;
    case PROTO_IMAP:
			// TODO: Call protocol tratment function
			break;
    case PROTO_IMAP3:
			// TODO: Call protocol tratment function
			break;
    case PROTO_IMAPS:
			// TODO: Call protocol tratment function
			break;
    case PROTO_POP2:
			// TODO: Call protocol tratment function
			break;
    case PROTO_POP3:
			// TODO: Call protocol tratment function
			break;
    case PROTO_POPS:
			// TODO: Call protocol tratment function
			break;
  }
}
