#ifndef __CAPTURE_H
#define __CAPTURE_H
#define MAX_SNAPLEN 1600
#define NB_PACKETS 0
#define MAC_ADDR_LENGTH 16
#define VL_LOW 0x31
#define VL_MEDIUM 0x32
#define VL_HIGH 0x33

#include <unistd.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "common.h"

pcap_t * get_online_capture(char * device, char * filter);
pcap_t * get_offline_capture(char * trace);
void process_ip(const u_char * packet);
void process_packet(u_char * args, const struct pcap_pkthdr * header, const u_char * packet);
int init_capture(pcap_t * capture, int nb_packets, u_char verbosity);

#endif
