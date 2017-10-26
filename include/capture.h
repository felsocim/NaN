#ifndef __CAPTURE_H
#define __CAPTURE_H
#define MAX_SNAPLEN 1600
#define NB_PACKETS 0

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

pcap_t * get_online_capture(char * device, char * filter);
void process_ethernet(const u_char * packet);
void process_ip(const u_char * packet);
void process_packet(u_char * args, const struct pcap_pkthdr * header, const u_char * packet);
int init_capture(pcap_t * capture, int nb_packets);

#endif
