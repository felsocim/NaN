#include "../include/useful.h"

// Converts an IP address to string
char * iptos(struct in_addr * address) {
  char * addr = (char *) malloc((INET_ADDRSTRLEN + 1) * sizeof(char));
  if(addr == NULL)
    failwith("Failed to reserve memory for an IP address string");
  if(inet_ntop(AF_INET, address, addr, INET_ADDRSTRLEN) == NULL)
    failwith("Failed to convert given IP address to string");
  return addr;
}

// Converts a MAC address to string
char * mactos(struct ether_addr * address) {
  char * addr = (char *) malloc((MAC_ADDRESS_LENGTH + 1) * sizeof(char));
  if(addr == NULL)
    failwith("Failed to reserve memory for a MAC address string");
  addr = strcpy(addr, ether_ntoa(address));
  if(addr == NULL)
    failwith("Failed to convert a MAC address to string");
  return addr;
}

// Extracts and displays a list of IP adresses from a data array
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

bool is_printable(u_char __c) {
  return (__c > 31 && __c < 127);
}

// Prints a character if it's printable, prints a point otherwise (or nothing if it is a '\r' or a '\n')
void printc(u_char __c) {
  if(__c == 0xA || __c == 0xD)
    return;

  if(is_printable(__c))
    printf("%c", __c);
  else
    printf(".");
}

// Prints a binary data line respecting 80th column limit
void printdl(u_char buffer[], int begin_at, int end_before, int padding) {
  int i = 0, count = 0;
  printf("%*c", padding, ' ');
  for(i = begin_at; i < end_before; i++) {
    if(buffer[i] == '\n' || count > (80 - padding)) {
      printf("\n%*c", padding, ' ');
      count = 0;
    }
    printc(buffer[i]);
    count++;
  }
}
