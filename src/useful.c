#include "../include/useful.h"

char * iptos(struct in_addr * address) {
  char * addr = (char *) malloc((INET_ADDRSTRLEN + 1) * sizeof(char));
  if(addr == NULL)
    failwith("Failed to reserve memory for an IP address string");
  if(inet_ntop(AF_INET, &address, addr, INET_ADDRSTRLEN) == NULL)
    failwith("Failed to convert given IP address to string");
  return addr;
}

void list_ip(u_int8_t size, u_int8_t values[]) {
  int i = 0;
  struct in_addr addr;
  char * addr_string = NULL;
  for(i = 0; i < length; i += 4) {
    addr.s_addr = (in_addr_t) DESERIALIZE_UINT8TO32(value, i);
    addr_string = iptos(raddr);
    printf("%s%s", addr_string, (i + 4 == length ? "" : ", "));
    free(addr_string);
    addr_string = NULL;
  }
}
