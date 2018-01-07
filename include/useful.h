#ifndef __USEFUL_H
#define __USEFUL_H

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "common.h"

#define MAC_ADDRESS_LENGTH 17

#if __BYTE_ORDER == __LITTLE_ENDIAN
  #define DESERIALIZE_UINT8TO32(_UINT8_ARRAY, OFFSET) (0x0 | _UINT8_ARRAY[OFFSET + 3] << 24 | _UINT8_ARRAY[OFFSET + 2] << 16 | _UINT8_ARRAY[OFFSET + 1] << 8 | _UINT8_ARRAY[OFFSET + 0])
  #define DESERIALIZE_UINT8TO16(_UINT8_ARRAY, OFFSET) (0x0 | _UINT8_ARRAY[OFFSET + 1] << 8 | _UINT8_ARRAY[OFFSET + 0])
#else
  #define DESERIALIZE_UINT8TO32(_UINT8_ARRAY, OFFSET) (0x0 | _UINT8_ARRAY[OFFSET + 0] << 24 | _UINT8_ARRAY[OFFSET + 1] << 16 | _UINT8_ARRAY[OFFSET + 2] << 8 | _UINT8_ARRAY[OFFSET + 3])
  #define DESERIALIZE_UINT8TO16(_UINT8_ARRAY, OFFSET) (0x0 | _UINT8_ARRAY[OFFSET + 0] << 8 | _UINT8_ARRAY[OFFSET + 1])
#endif

char * iptos(struct in_addr *);
char * mactos(struct ether_addr *);
void list_ip(u_int8_t, u_int8_t[], u_int);
bool is_printable(u_char);
void printc(u_char);

#endif // __USEFUL_H
