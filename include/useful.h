#ifndef __USEFUL_H
#define __USEFUL_H

#if __BYTE_ORDER == __LITTLE_ENDIAN
  #define DESERIALIZE_UINT8TO32(_UINT8_ARRAY, OFFSET) (0x0 | _UINT8_ARRAY[OFFSET + 3] << 24 | _UINT8_ARRAY[OFFSET + 2] << 16 | _UINT8_ARRAY[OFFSET + 1] << 8 | _UINT8_ARRAY[OFFSET + 0])
#else
  #define DESERIALIZE_UINT8TO32(_UINT8_ARRAY, OFFSET) (0x0 | _UINT8_ARRAY[OFFSET + 0] << 24 | _UINT8_ARRAY[OFFSET + 1] << 16 | _UINT8_ARRAY[OFFSET + 2] << 8 | _UINT8_ARRAY[OFFSET + 3])
#endif

char * iptos(struct in_addr *);
void list_ip(u_int8_t, u_int8_t[]);

#endif // __USEFUL_H
