#ifndef __PROCESS_H
#define __PROCESS_H

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "common.h"

void process_ip(const u_char * packet);

#endif // __PROCESS_H
