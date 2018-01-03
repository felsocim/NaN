#include "../include/useful.h"

char * iptos(struct in_addr * address) {
  char * addr = (char *) malloc((INET_ADDRSTRLEN + 1) * sizeof(char));
  if(addr == NULL)
    failwith("Failed to reserve memory for an IP address string");
  if(inet_ntop(AF_INET, address, addr, INET_ADDRSTRLEN) == NULL)
    failwith("Failed to convert given IP address to string");
  return addr;
}

void list_ip(u_int8_t size, u_int8_t values[], u_int start_at) {
  int i = 0;
  struct in_addr addr;
  char * addr_string = NULL;
  for(i = start_at; i < start_at + size; i += 4) {
    addr.s_addr = (in_addr_t) DESERIALIZE_UINT8TO32(values, i);
    addr_string = iptos(&addr);
    printf("%s%s", addr_string, (i + 4 == start_at + size ? "" : ", "));
    free(addr_string);
    addr_string = NULL;
  }
}
