#ifndef __CAPTURE_H
#define __CAPTURE_H

#define MAX_SNAPSHOT_LENGTH 1600
#define MAX_TIMESTAMP_LENGTH 64

#include <time.h>
#include <netinet/ether.h>
#include <pcap.h>

#include "common.h"
#include "process.h"

pcap_t * get_online_capture(char *, char *);
pcap_t * get_offline_capture(char *);
void got_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
int init_capture(pcap_t *, int, u_char);
void set_filter(pcap_t *, char *, char *, char *);

#endif
