/* @(#) $Header: /tcpdump/master/tcpdump/bootp.h,v 1.11 2001/01/09 07:39:13 fenner Exp $ (LBL) */
/*
 * Bootstrap Protocol (BOOTP).  RFC951 and RFC1048.
 *
 * This file specifies the "implementation-independent" BOOTP protocol
 * information which is common to both client and server.
 *
 * Copyright 1988 by Carnegie Mellon.
 *
 * Permission to use, copy, modify, and distribute this program for any
 * purpose and without fee is hereby granted, provided that this copyright
 * and permission notice appear on all copies and supporting documentation,
 * the name of Carnegie Mellon not be used in advertising or publicity
 * pertaining to distribution of the program without specific prior
 * permission, and notice be given in supporting documentation that copying
 * and distribution is by permission of Carnegie Mellon and Stanford
 * University.  Carnegie Mellon makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */


struct bootp {
	u_int8_t	bp_op;		/* packet opcode type */
	u_int8_t	bp_htype;	/* hardware addr type */
	u_int8_t	bp_hlen;	/* hardware addr length */
	u_int8_t	bp_hops;	/* gateway hops */
	u_int32_t	bp_xid;		/* transaction ID */
	u_int16_t	bp_secs;	/* seconds since boot began */
	u_int16_t	bp_flags;	/* flags: 0x8000 is broadcast */
	struct in_addr	bp_ciaddr;	/* client IP address */
	struct in_addr	bp_yiaddr;	/* 'your' IP address */
	struct in_addr	bp_siaddr;	/* server IP address */
	struct in_addr	bp_giaddr;	/* gateway IP address */
	u_int8_t	bp_chaddr[16];	/* client hardware address */
	u_int8_t	bp_sname[64];	/* server host name */
	u_int8_t	bp_file[128];	/* boot file name */
	u_int8_t	bp_vend[64];	/* vendor-specific area */
};

/*
 * UDP port numbers, server and client.
 */
#define	IPPORT_BOOTPS		67
#define	IPPORT_BOOTPC		68

#define BOOTREPLY		2
#define BOOTREQUEST		1

/*
 * Vendor magic cookie (v_magic) for RFC1048
 */
#define VM_RFC1048	{ 99, 130, 83, 99 }

/*
 * RFC1048 tag values used to specify what information is being supplied in
 * the vendor field of the packet.
 */

#define TAG_PAD			((u_int8_t)   0)
#define TAG_SUBNET_MASK		((u_int8_t)   1)
#define TAG_GATEWAY		((u_int8_t)   3)
#define TAG_TIME_SERVER		((u_int8_t)   4)
#define TAG_NAME_SERVER		((u_int8_t)   5)
#define TAG_DOMAIN_SERVER	((u_int8_t)   6)
#define TAG_LOG_SERVER		((u_int8_t)   7)
#define TAG_COOKIE_SERVER	((u_int8_t)   8)
#define TAG_LPR_SERVER		((u_int8_t)   9)
#define TAG_IMPRESS_SERVER	((u_int8_t)  10)
#define TAG_RLP_SERVER		((u_int8_t)  11)
#define TAG_HOSTNAME		((u_int8_t)  12)
#define TAG_BOOTSIZE		((u_int8_t)  13)
#define TAG_END			((u_int8_t) 255)

/* DHCP options */
#define	TAG_REQUESTED_IP	((u_int8_t)  50)
#define	TAG_IP_LEASE		((u_int8_t)  51)
#define	TAG_OPT_OVERLOAD	((u_int8_t)  52)
#define	TAG_TFTP_SERVER		((u_int8_t)  66)
#define	TAG_BOOTFILENAME	((u_int8_t)  67)
#define	TAG_DHCP_MESSAGE	((u_int8_t)  53)
#define	TAG_SERVER_ID		((u_int8_t)  54)
#define	TAG_PARM_REQUEST	((u_int8_t)  55)
#define	TAG_MESSAGE		((u_int8_t)  56)
#define	TAG_MAX_MSG_SIZE	((u_int8_t)  57)
#define	TAG_RENEWAL_TIME	((u_int8_t)  58)
#define	TAG_REBIND_TIME		((u_int8_t)  59)
#define	TAG_VENDOR_CLASS	((u_int8_t)  60)
#define	TAG_CLIENT_ID		((u_int8_t)  61)

/* DHCP Message types (values for TAG_DHCP_MESSAGE option) */
#define DHCPDISCOVER	1
#define DHCPOFFER	2
#define DHCPREQUEST	3
#define DHCPDECLINE	4
#define DHCPACK		5
#define DHCPNAK		6
#define DHCPRELEASE	7
#define DHCPINFORM	8
#define DHCPFORCERENEW 9
#define DHCPLEASEQUERY 10
#define DHCPLEASEUNASSIGNED 11
#define DHCPLEASEUNKNOWN 12
#define DHCPLEASEACTIVE 13
#define DHCPBULKLEASEQUERY 14
#define DHCPLEASEQUERYDONE 15
#define DHCPACTIVELEASEQUERY 16
#define DHCPLEASEQUERYSTATUS 17
#define DHCPTLS 18
