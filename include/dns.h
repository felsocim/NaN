#ifndef __DNS_H
#define __DNS_H

//DNS header structure
struct dns
{
  unsigned short id; // identification number
#if __BYTE_ORDER == __LITTLE_ENDIAN
  unsigned char rd :1; // recursion desired
  unsigned char tc :1; // truncated message
  unsigned char aa :1; // authoritive answer
  unsigned char opcode :4; // purpose of message
  unsigned char qr :1; // query/response flag

  unsigned char rcode :4; // response code
  unsigned char cd :1; // checking disabled
  unsigned char ad :1; // authenticated data
  unsigned char z :1; // its z! reserved
  unsigned char ra :1; // recursion available
#elif __BYTE_ORDER == __BIG_ENDIAN
  unsigned char qr :1; // query/response flag
  unsigned char opcode :4; // purpose of message
  unsigned char aa :1; // authoritive answer
  unsigned char tc :1; // truncated message
  unsigned char rd :1; // recursion desired

  unsigned char ra :1; // recursion available
  unsigned char z :1; // its z! reserved
  unsigned char ad :1; // authenticated data
  unsigned char cd :1; // checking disabled
  unsigned char rcode :4; // response code
#else
#error "Failed to determine your system's endianess!"
#endif
  unsigned short q_count; // number of question entries
  unsigned short ans_count; // number of answer entries
  unsigned short auth_count; // number of authority entries
  unsigned short res_count; // number of resource entries
};

#define DNS_HEADER_LENGTH ((int) sizeof(struct dns))

// Operation codes
#define DNS_OPCODE_QUERY 0
#define DNS_OPCODE_IQUERY 1
#define DNS_OPCODE_STATUS 2

// Response codes
#define DNS_RCODE_NO_ERROR_CONDITION 0
#define DNS_RCODE_FORMAT_ERROR 1
#define DNS_RCODE_SERVER_FAILURE 2
#define DNS_RCODE_NAME_ERROR 3
#define DNS_RCODE_NOT_IMPLEMENTED 4
#define DNS_RCODE_REFUSED 5

#if __EXTENDED_DNS == true
#define DNS_OFFSET_MASK 0b0011111111111111
#endif

#endif // __DNS_H
