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
    case PROTO_BOOTPC:
			process_bootp(packet, sizeof(struct ether_header) + (ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip)) + sizeof(struct udphdr), verbosity);
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

void process_bootp(const u_char * packet, long int offset, u_char verbosity) {
  const struct bootp * data = (struct bootp *) (packet + offset);
  char * ciaddr = NULL,
    * yiaddr = NULL,
    * siaddr = NULL,
    * giaddr = NULL,
    * chaddr = NULL;

  switch(verbosity) {
    case VERBOSITY_LOW:
      printf("bootp op %u server %s, file %s\n", data->bp_op, data->bp_sname, data->bp_file);
      break;
    case VERBOSITY_MEDIUM:
      printf("bootp transaction 0x%X, op %u server %s, file %s, started %u sec(s) ago\n", ntohs(data->bp_xid), data->bp_op, data->bp_sname, data->bp_file, ntohs(data->bp_secs));
      break;
    case VERBOSITY_HIGH:
      ciaddr = (char *) malloc((INET_ADDRSTRLEN + 1) * sizeof(char));

      if(ciaddr == NULL)
        failwith("Failed to reserve memory for client IP address");

      yiaddr = (char *) malloc((INET_ADDRSTRLEN + 1) * sizeof(char));

      if(yiaddr == NULL)
        failwith("Failed to reserve memory for 'your' IP address");

      siaddr = (char *) malloc((INET_ADDRSTRLEN + 1) * sizeof(char));

      if(siaddr == NULL)
        failwith("Failed to reserve memory for source IP address");

      giaddr = (char *) malloc((INET_ADDRSTRLEN + 1) * sizeof(char));

      if(giaddr == NULL)
        failwith("Failed to reserve memory for gateway IP address");

      chaddr = (char *) malloc((MAC_ADDRESS_LENGTH + 1) * sizeof(char));

      if(chaddr == NULL)
        failwith("Failed to reserve memory for client hardware address");

      if(inet_ntop(AF_INET, &data->bp_ciaddr, ciaddr, INET_ADDRSTRLEN) == NULL)
    		failwith("Failed to convert client IP address to string");

      if(inet_ntop(AF_INET, &data->bp_yiaddr, yiaddr, INET_ADDRSTRLEN) == NULL)
    		failwith("Failed to convert 'your' IP address to string");

      if(inet_ntop(AF_INET, &data->bp_siaddr, siaddr, INET_ADDRSTRLEN) == NULL)
    		failwith("Failed to convert source IP address to string");

      if(inet_ntop(AF_INET, &data->bp_giaddr, giaddr, INET_ADDRSTRLEN) == NULL)
    		failwith("Failed to convert gateway IP address to string");

      if((chaddr = strcpy(chaddr, ether_ntoa((struct ether_addr *)data->bp_chaddr))) == NULL)
        failwith("Failed to convert client's hardware address to string");

      printf("        └─ \"BOOTP message\"\n");
      printf("          ├─ Operation code: %u\n", data->bp_op);
      printf("          ├─ Hardware address type: 0x%X\n", data->bp_htype);
      printf("          ├─ Hardware address length: %u byte(s)\n", data->bp_hlen);
      printf("          ├─ Gateway hops: %u\n", data->bp_hops);
      printf("          ├─ Transaction identifier: 0x%X\n", ntohs(data->bp_xid));
      printf("          ├─ Seconds since boot began: %u\n", ntohs(data->bp_secs));
      printf("          ├─ Flags: 0x%X\n", ntohs(data->bp_flags));
      printf("          ├─ Client's IP address: %s\n", ciaddr);
      printf("          ├─ 'Your' IP address: %s\n", yiaddr);
      printf("          ├─ Source IP address: %s\n", siaddr);
      printf("          ├─ Gateway IP address: %s\n", giaddr);
      printf("          ├─ Client's hardware address: %s\n", chaddr);
      printf("          ├─ Server host name: %s\n", data->bp_sname);
      printf("          ├─ Boot file name: %s\n", data->bp_file);
      printf("          └─ Vendor specific:");

      u_int8_t magic[4] = VM_RFC1048;

      if(data->bp_vend[0] == magic[0] && data->bp_vend[1] == magic[1] && data->bp_vend[2] == magic[2] && data->bp_vend[3] == magic[3]) {
        int i = 4;
        u_int8_t type = 0, length = 0;

        while(type != TAG_END && i < 64) {
          type = data->bp_vend[i];
          length = data->bp_vend[i + 1];

          switch(type){
            case TAG_DHCP_MESSAGE: // DHCP message
              if(length == 1) {
                switch(data->bp_vend[i + 2]) {
                  case DHCPDISCOVER:
                    printf(" DHCP/Discover");
                    break;
                  case DHCPOFFER:
                    printf(" DHCP/Offer");
                    break;
                  case DHCPREQUEST:
                    printf(" DHCP/Request");
                    break;
                  case DHCPDECLINE:
                    printf(" DHCP/Decline");
                    break;
                  case DHCPACK:
                    printf(" DHCP/ACK");
                    break;
                  case DHCPNAK:
                    printf(" DHCP/NAK");
                    break;
                  case DHCPRELEASE:
                    printf(" DHCP/Release");
                    break;
                  case DHCPINFORM:
                    printf(" DHCP/Inform");
                    break;
                  case DHCPLEASEQUERY:
                    printf(" DHCP/Lease Query");
                    break;
                  case DHCPLEASEUNASSIGNED:
                    printf(" DHCP/Lease Unassigned");
                    break;
                  case DHCPLEASEUNKNOWN:
                    printf(" DHCP/Lease Unknown");
                    break;
                  case DHCPLEASEACTIVE:
                    printf(" DHCP/Lease Active");
                    break;
                  case DHCPBULKLEASEQUERY:
                    printf(" DHCP/Bulk Lease Query");
                    break;
                  case DHCPLEASEQUERYDONE:
                    printf(" DHCP/Lease Query Done");
                    break;
                  case DHCPACTIVELEASEQUERY:
                    printf(" DHCP/Active Lease Query");
                    break;
                  case DHCPLEASEQUERYSTATUS:
                    printf(" DHCP/Lease Query Status");
                    break;
                  case DHCPTLS:
                    printf(" DHCP/TLS");
                    break;
                  default:
                    printf(" DHCP/Unknown (%u)", data->bp_vend[i + 2]);
                }
              } else {
                failwith("DHCP message length value mismatch. It should be '1'");
              }
              break;
            default:
              printf(" %u-%u-", type, length);

              int j = 0;

              for(j = i + 2; j < length; j++) {
                printf("%c", (data->bp_vend[j] > 32 ? data->bp_vend[j] : '.'));
              }
              break;
          }

          i += length + 2;
        }
      }

      printf("\n");

      free(ciaddr);
      free(yiaddr);
      free(siaddr);
      free(giaddr);
      free(chaddr);
      break;
  }
}

void process_bootp_vsopt(u_int8_t type, u_int8_t length, u_int8_t value[]) {
  switch(type) {
    case TAG_SUBNET_MASK:
      printf(" subnet-mask");
      if(verbosity == VERBOSITY_HIGH)
        list_ip(length, value);
      break;
    case TAG_TIME_OFFSET:
      printf(" tag-time-offset");
      if(verbosity == VERBOSITY_HIGH) {
        printf(" %d", (int32_t) DESERIALIZE_UINT32(value));
      }
      break;
    case TAG_GATEWAY:
      printf(" router");
      if(verbosity == VERBOSITY_HIGH)
        list_ip(length, value);
      break;
    case TAG_TIME_SERVER:
    case TAG_NAME_SERVER:
    case TAG_DOMAIN_SERVER:
    case TAG_LOG_SERVER:
    case TAG_COOKIE_SERVER:
    case TAG_LPR_SERVER:
    case TAG_IMPRESS_SERVER:
    case TAG_RLP_SERVER:
    case TAG_HOSTNAME:
    case TAG_BOOTSIZE:
    case TAG_REQUESTED_IP:
    case TAG_IP_LEASE:
    case TAG_OPT_OVERLOAD:
    case TAG_TFTP_SERVER:
    case TAG_BOOTFILENAME:
    case TAG_DHCP_MESSAGE:
    case TAG_SERVER_ID:
    case TAG_PARM_REQUEST:
    case TAG_MESSAGE:
    case TAG_MAX_MSG_SIZE:
    case TAG_RENEWAL_TIME:
    case TAG_REBIND_TIME:
    case TAG_VENDOR_CLASS:
    case TAG_CLIENT_ID:
    default:
  }
}
