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
      process_tcp(packet, False, ntohs(header->ip_len) - sizeof(struct ip), verbosity);
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
      process_tcp(packet, True, ntohs(header->ip6_plen) - sizeof(struct ip6_hdr), verbosity);
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

void process_tcp(const u_char * packet, Bool ipv6, u_short length, u_char verbosity) {
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

    while((eol - options) >= 0) {
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

  switch (source) {
    case PROTO_SMTP:
      if(length - (offset * 4) > 0)
        process_smtp(packet, sizeof(struct ether_header) + (ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip)) + (offset * 4), length - (offset * 4), 'S', verbosity);
      break;
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
      //printf("%u - %u = %u\n", length, (offset * 4), length - (offset * 4));
      if(length - (offset * 4) > 0)
			   process_smtp(packet, sizeof(struct ether_header) + (ipv6 ? sizeof(struct ip6_hdr) : sizeof(struct ip)) + (offset * 4), length - (offset * 4), 'C', verbosity);
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
  struct bootp * data = (struct bootp *) (packet + offset);
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
      printf("          ├─ Transaction identifier: 0x%X\n", ntohl(data->bp_xid));
      printf("          ├─ Seconds since boot began: %u\n", ntohs(data->bp_secs));
      printf("          ├─ Flags: 0x%X\n", ntohs(data->bp_flags));
      printf("          ├─ Client's IP address: %s\n", ciaddr);
      printf("          ├─ 'Your' IP address: %s\n", yiaddr);
      printf("          ├─ Source IP address: %s\n", siaddr);
      printf("          ├─ Gateway IP address: %s\n", giaddr);
      printf("          ├─ Client's hardware address: %s\n", chaddr);
      printf("          ├─ Server host name: %s\n", data->bp_sname);
      printf("          ├─ Boot file name: %s\n", data->bp_file);
      printf("          └─ Vendor specific\n");

      u_int8_t magic[4] = VM_RFC1048;

      if(data->bp_vend[0] == magic[0] && data->bp_vend[1] == magic[1] && data->bp_vend[2] == magic[2] && data->bp_vend[3] == magic[3]) {
        u_int i = 4, temp = 0;
        u_int8_t overload = 0;
        Bool overloaded = False;

        while(data->bp_vend[i] != TAG_END) {
          if(data->bp_vend[i] == TAG_PAD)
            temp = i + 1;
          else
            temp = i + data->bp_vend[i + 1] + 2;
          if(data->bp_vend[i] == TAG_OPT_OVERLOAD) {
            overload = data->bp_vend[i + 2];
            overloaded = True;
          }
          process_bootp_vsopt(data->bp_vend, i, (overloaded ? False : (data->bp_vend[temp] == TAG_END)), verbosity);
          i = temp;
        }

        u_int8_t * array = NULL;
        Bool iterate = False;

        switch(overload) {
          case 1:
            array = data->bp_file;
          case 2:
            array = data->bp_sname;
            break;
          case 3:
            array = data->bp_file;
            iterate = True;
            break;
          default:
            break;
        }

        if(overload) {
          i = 0;
          temp = 0;
          while(array[i] != TAG_END) {
            if(array[i] == TAG_PAD)
              temp = i + 1;
            else
              temp = i + array[i + 1] + 2;
            process_bootp_vsopt(array, i, (iterate ? False : (array[temp] == TAG_END)), verbosity);
            i = temp;
          }
          if(iterate) {
            i = 0;
            temp = 0;
            array = data->bp_sname;
            while(array[i] != TAG_END) {
              if(array[i] == TAG_PAD)
                temp = i + 1;
              else
                temp = i + array[i + 1] + 2;
              process_bootp_vsopt(array, i, (array[temp] == TAG_END), verbosity);
              i = temp;
            }
          }
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

void process_bootp_vsopt(u_int8_t value[], u_int offset, Bool last, u_char verbosity) {
  u_int8_t type = value[offset];
  u_int8_t length = 0;
  if(type != TAG_PAD) {
    length = value[offset + 1];
  }
  printf("            %s─ ", (last ? "└" : "├"));
  switch(type) {
    case TAG_PAD:
      printf("padding (0x00)");
      break;
    case TAG_SUBNET_MASK:
      printf("subnet-mask");
      break;
    case TAG_GATEWAY:
      printf("router");
      break;
    case TAG_TIME_SERVER:
      printf("time-server");
      break;
    case TAG_NAME_SERVER:
      printf("name-server");
      break;
    case TAG_DOMAIN_SERVER:
      printf("domain-server");
      break;
    case TAG_LOG_SERVER:
      printf("log-server");
      break;
    case TAG_COOKIE_SERVER:
      printf("cookie-server");
      break;
    case TAG_LPR_SERVER:
      printf("LPR-server");
      break;
    case TAG_IMPRESS_SERVER:
      printf("impress-server");
      break;
    case TAG_RLP_SERVER:
      printf("resource-location-server");
      break;
    case TAG_HOSTNAME:
      printf("host-name");
      break;
    case TAG_BOOTSIZE:
      printf("boot-file-size");
      if(verbosity == VERBOSITY_HIGH)
        printf(" %uB", ntohs((u_int16_t) DESERIALIZE_UINT8TO16(value, offset + 2)));
      break;
    case TAG_REQUESTED_IP:
      printf("requested-ip");
      if(verbosity == VERBOSITY_HIGH)
        list_ip(length, value, offset + 2);
      break;
    case TAG_IP_LEASE:
      printf("ip-lease-time");
      if(verbosity == VERBOSITY_HIGH)
        printf(" %us", ntohl((u_int32_t) DESERIALIZE_UINT8TO32(value, offset + 2)));
      break;
    case TAG_OPT_OVERLOAD:
      printf("option-overload");
      if(verbosity == VERBOSITY_HIGH)
        printf(" %u", value[offset + 2]);
      break;
    case TAG_TFTP_SERVER:
      printf("tftp-server-name");
      break;
    case TAG_BOOTFILENAME:
      printf("boot-file-name");
      break;
    case TAG_DHCP_MESSAGE:
      switch(value[offset + 2]) {
        case DHCPDISCOVER:
          printf("DHCP/Discover");
          break;
        case DHCPOFFER:
          printf("DHCP/Offer");
          break;
        case DHCPREQUEST:
          printf("DHCP/Request");
          break;
        case DHCPDECLINE:
          printf("DHCP/Decline");
          break;
        case DHCPACK:
          printf("DHCP/ACK");
          break;
        case DHCPNAK:
          printf("DHCP/NAK");
          break;
        case DHCPRELEASE:
          printf("DHCP/Release");
          break;
        case DHCPINFORM:
          printf("DHCP/Inform");
          break;
        case DHCPLEASEQUERY:
          printf("DHCP/Lease Query");
          break;
        case DHCPLEASEUNASSIGNED:
          printf("DHCP/Lease Unassigned");
          break;
        case DHCPLEASEUNKNOWN:
          printf("DHCP/Lease Unknown");
          break;
        case DHCPLEASEACTIVE:
          printf("DHCP/Lease Active");
          break;
        case DHCPBULKLEASEQUERY:
          printf("DHCP/Bulk Lease Query");
          break;
        case DHCPLEASEQUERYDONE:
          printf("DHCP/Lease Query Done");
          break;
        case DHCPACTIVELEASEQUERY:
          printf("DHCP/Active Lease Query");
          break;
        case DHCPLEASEQUERYSTATUS:
          printf("DHCP/Lease Query Status");
          break;
        case DHCPTLS:
          printf("DHCP/TLS");
          break;
        default:
          printf("DHCP/Unknown (%u)", value[offset + 2]);
          break;
      }
      break;
    case TAG_SERVER_ID:
      printf("server-id");
      break;
    case TAG_PARM_REQUEST:
      printf("parameter-request-list");
      if(verbosity == VERBOSITY_HIGH) {
        int i = 0;
        printf(" 0x%X", value[offset + 2]);
        for(i = offset + 3; i < offset + 3 + length; i++)
          printf(", 0x%X", value[i]);
      }
      break;
    case TAG_MESSAGE:
      printf("message");
      break;
    case TAG_MAX_MSG_SIZE:
      printf("maximum-dhcp-message-size");
      if(verbosity == VERBOSITY_HIGH)
        printf(" %u", ntohs((u_int16_t) DESERIALIZE_UINT8TO16(value, offset + 2)));
      break;
    case TAG_RENEWAL_TIME:
      printf("renewal-time-value");
      if(verbosity == VERBOSITY_HIGH)
        printf(" %us", ntohl((u_int32_t) DESERIALIZE_UINT8TO32(value, offset + 2)));
      break;
    case TAG_REBIND_TIME:
      printf("rebinding-time-value");
      if(verbosity == VERBOSITY_HIGH)
        printf(" %us", ntohl((u_int32_t) DESERIALIZE_UINT8TO32(value, offset + 2)));
      break;
    case TAG_VENDOR_CLASS:
      printf("vendor-class-identifier");
      break;
    case TAG_CLIENT_ID:
      printf("client-id");
      if(verbosity == VERBOSITY_HIGH) {
        printf(" ");
        int k = offset + 2, m = 0;
        char * addr = NULL;
        struct ether_addr hwa;
        while(k < offset + 2 + length) {
          switch(value[k]) {
            case 0: // string
              for(m = k + 1; m < k + length; m++)
                printf("%c", value[m]);
              k += length;
              break;
            case 1: // Ethernet MAC address
              for(m = 0; m < ETH_ALEN; m++)
                hwa.ether_addr_octet[m] = value[k + 1 + m];
              addr = mactos(&hwa);
              printf("%s", addr);
              free(addr);
              k += 1 + ETH_ALEN;
              break;
            default:
              printf("unsupported-identifier-format");
              k += 1 + value[k + 1];
              break;
          }
        }
      }
      break;
    default:
      printf("unknown(%u, %u, ", type, length);
      int j = 0;
      for(j = offset + 2; j < offset + 2 + length; j++) {
        printf("%c", (value[j] > 31 && value[j] < 128 ? value[j] : '.'));
      }
      printf(")");
      break;
  }

  if((type >= TAG_GATEWAY && type <= TAG_RLP_SERVER) || type == TAG_SERVER_ID || type == TAG_SUBNET_MASK) {
    if(verbosity == VERBOSITY_HIGH)
      printf(" ");
      list_ip(length, value, offset + 2);
  }

  if(type == TAG_HOSTNAME || type == TAG_TFTP_SERVER || type == TAG_BOOTFILENAME || type == TAG_MESSAGE || type == TAG_VENDOR_CLASS) {
    if(verbosity == VERBOSITY_HIGH) {
      char * name = (char *) malloc((length + 1) * sizeof(char));
      if(name == NULL)
        failwith("Failed to reserve memory for server name");
      int i = 0;
      for(i = 0; i < length; i++)
        name[i] = value[offset + 2 + i];
      name[length] = '\0';
      printf(" %s", name);
      free(name);
    }
  }

  printf("\n");
}

void process_smtp(const u_char * packet, long int offset, u_short size, u_char source, u_char verbosity) {
  u_char * data = (u_char *) (packet + offset);
  u_short i = 0;

  switch (verbosity) {
    case VERBOSITY_LOW:
    case VERBOSITY_MEDIUM:
      printf("smtp %c > %c", source, (source == 'C' ? 'S' : 'C'));
      break;
    case VERBOSITY_HIGH:
      printf("          └─ \"SMTP message from %s to %s\"\n", (source == 'C' ? "client" : "server"), (source == 'C' ? "server" : "client"));
      printf("            └─ Content: ");
      printf("\n              - ");
      for(i = 0; i < size; i++) {
        if(data[i] == 0x0A && (i + 1) < size)
          printf("\n              - ");
        else if(data[i] != 0x0D)
          printf("%c", data[i]);
      }
      break;
    default:
      failwith("Unknown verbosity level detected");
  }

  printf("\n");
}
