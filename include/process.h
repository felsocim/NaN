#ifndef __PROCESS_H
#define __PROCESS_H

#define IPV4_PACKET_FLAGS_LENGTH 4

#define VERBOSITY_LOW 0x31
#define VERBOSITY_MEDIUM 0x32
#define VERBOSITY_HIGH 0x33

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "common.h"

void process_ipv4(const u_char * packet, u_char verbosity);

#endif // __PROCESS_H
