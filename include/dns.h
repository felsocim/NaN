#ifndef __DNS_H
#define __DNS_H

// TODO: Generalize structure fields order (little and big endian)

//DNS header structure
struct dns
{
    unsigned short id; // identification number

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

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short res_count; // number of resource entries
};

#define DNS_OPCODE_QUERY 0
#define DNS_OPCODE_IQUERY 1
#define DNS_OPCODE_STATUS 2

#define DNS_RCODE_NO_ERROR_CONDITION 0
#define DNS_RCODE_FORMAT_ERROR 1
#define DNS_RCODE_SERVER_FAILURE 2
#define DNS_RCODE_NAME_ERROR 3
#define DNS_RCODE_NOT_IMPLEMENTED 4
#define DNS_RCODE_REFUSED 5

#endif // __DNS_H
