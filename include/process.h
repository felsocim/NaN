#ifndef __PROCESS_H
#define __PROCESS_H

#define MAC_ADDRESS_LENGTH 16
#define IPV4_PACKET_FLAGS_LENGTH 4

#define VERBOSITY_LOW 0x31
#define VERBOSITY_MEDIUM 0x32
#define VERBOSITY_HIGH 0x33

#define ARP_REQUEST 0
#define ARP_REPLY 1
#define ARP_UNKNOWN 2
#define ARP_GET_TYPE(_OP_CODE) ((_OP_CODE == ARPOP_REQUEST || _OP_CODE == ARPOP_RREQUEST) ? ARP_REQUEST : ((_OP_CODE == ARPOP_REPLY || _OP_CODE == ARPOP_RREPLY) ? ARP_REPLY : ARP_UNKNOWN))

#if __BYTE_ORDER == __LITTLE_ENDIAN
  #define DESERIALIZE_UINT32(_UINT8_ARRAY) (0x0 | _UINT8_ARRAY[3] << 24 | _UINT8_ARRAY[2] << 16 | _UINT8_ARRAY[1] << 8 | _UINT8_ARRAY[0])
#else
  #define DESERIALIZE_UINT32(_UINT8_ARRAY) (0x0 | _UINT8_ARRAY[0] << 24 | _UINT8_ARRAY[1] << 16 | _UINT8_ARRAY[2] << 8 | _UINT8_ARRAY[3])
#endif

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include "common.h"

void process_ipv4(const u_char *, u_char);
void process_ipv6(const u_char *, u_char);
void process_arp(const u_char *, Bool, u_char);

#endif // __PROCESS_H
