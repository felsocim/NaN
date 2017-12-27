#ifndef __CAPTURE_H
#define __CAPTURE_H

#define MAX_SNAPSHOT_LENGTH 1600
#define MAC_ADDRESS_LENGTH 16
#define VERBOSITY_LOW 0x31
#define VERBOSITY_MEDIUM 0x32
#define VERBOSITY_HIGH 0x33

#include <pcap.h>

#include "common.h"
#include "process.h"

pcap_t * get_online_capture(char * device, char * filter);
pcap_t * get_offline_capture(char * trace);
void got_packet(u_char * args, const struct pcap_pkthdr * header, const u_char * packet);
int init_capture(pcap_t * capture, int nb_packets, u_char verbosity);

#endif
