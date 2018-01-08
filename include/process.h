#ifndef __PROCESS_H
#define __PROCESS_H

#define IPV4_PACKET_FLAGS_LENGTH 4

#define VERBOSITY_LOW 0x31
#define VERBOSITY_MEDIUM 0x32
#define VERBOSITY_HIGH 0x33

// ARP message types and macro
#define ARP_REQUEST 0
#define ARP_REPLY 1
#define ARP_UNKNOWN 2
#define ARP_GET_TYPE(_OP_CODE) ((_OP_CODE == ARPOP_REQUEST || _OP_CODE == ARPOP_RREQUEST) ? ARP_REQUEST : ((_OP_CODE == ARPOP_REPLY || _OP_CODE == ARPOP_RREPLY) ? ARP_REPLY : ARP_UNKNOWN))

// Protocol identifiers
#define PROTO_TCP 0x06
#define PROTO_UDP 0x11

// Protocol ports
#define PROTO_FTPC 21
#define PROTO_FTPD 20
#define PROTO_TELNET 23
#define PROTO_SMTP 25
#define PROTO_DNS 53
#define PROTO_BOOTPS 67
#define PROTO_BOOTPC 68
#define PROTO_HTTP 80
#define PROTO_IMAP 143
#define PROTO_POP3 110

// TCP options
#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_MSS 2
#define TCPOPT_WS 3
#define TCPOPT_SACK 4
#define TCPOPT_TSTMP 8

// Shared flags
#define TP_COMMAND 0x1
#define TP_REPLY 0x2
#define TP_DATA 0x4
#define TP_CLIENT 0x8
#define TP_SERVER 0x10

#define HTTP_VALID_METHODS_ARRAY { "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT" }
#define HTTP_VALID_METHODS_COUNT 8

// Telnet control characters
#define TELNETCTC_NOP 241
#define TELNETCTC_DM 242
#define TELNETCTC_IP 244
#define TELNETCTC_AO 245
#define TELNETCTC_AYT 246
#define TELNETCTC_EC 247
#define TELNETCTC_EL 248
#define TELNETCTC_GA 249
#define TELNETCTC_SB 250
#define TELNETCTC_SE 240
#define TELNETCTC_WILL 251
#define TELNETCTC_WONT 252
#define TELNETCTC_DO 253
#define TELNETCTC_DONT 254
#define TELNETCTC_IAC 255

// Telnet options
#define TELNETOPT_ECHO 1
#define TELNETOPT_SUPPRESS_GO_AHEAD 3
#define TELNETOPT_STATUS 5
#define TELNETOPT_TIMING_MARK 6
#define TELNETOPT_TERMINAL_TYPE 24
#define TELNETOPT_WINDOW_SIZE 31
#define TELNETOPT_TERMINAL_SPEED 32
#define TELNETOPT_REMOTE_FLOW_CONTROL 33
#define TELNETOPT_LINE_MODE 34
#define TELNETOPT_X_DISPLAY_LOCATION 35
#define TELNETOPT_ENVIRONMENT_VARIABLES 36
#define TELNETOPT_AUTHENTICATION_OPTION 37
#define TELNETOPT_ENCRYPTION_OPTION 38
#define TELNETOPT_NEW_ENVIRONMENT_VARIABLES 39

// Set this value to 'true' to enable extended DNS packet analysis in high verbosity mode
// WARNING: This capability is disabled by default as its result may contain some mistakes
#define __EXTENDED_DNS false

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "common.h"
#include "useful.h"
#include "bootp.h"
#include "dns.h"

void process_ipv4(const u_char *, u_char);
void process_ipv6(const u_char *, u_char);
void process_arp(const u_char *, bool, u_char);
void process_udp(const u_char *, bool, u_char);
void process_tcp(const u_char *, bool, u_short, u_char);
void process_bootp(const u_char *, long int, u_char);
void process_bootp_vsopt(u_int8_t[], u_int, bool, u_char);
void process_smtp_ftp_pop_imap(const u_char *, char *, char *, long int, u_short, u_char, u_char);
void process_http(const u_char *, long int, u_short, u_char, u_char);
void process_telnet(const u_char *, long int, u_short, u_char, u_char);
void process_dns(const u_char *, long int, u_short, u_char, u_char);

#if __EXTENDED_DNS == true
void process_dns_sections(u_char *, u_short[], u_char *);
int print_dns_section_entry(u_char *, int);
int print_dns_simple(u_char *, int);
#endif

#endif // __PROCESS_H
