#ifndef FR_NET_H
#define FR_NET_H
/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 of the
 *   License as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file include/net.h
 * @brief Structures and functions for parsing raw network packets.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2014 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */

/*
 *	If we don't have libpcap, we still need an enumeration of link layers.
 */
#ifdef HAVE_LIBPCAP
#  include <pcap.h>
#else
typedef enum {
	DLT_RAW,
	DLT_NULL,
	DLT_LOOP,
	DLT_EN10MB,
	DLT_LINUX_SLL,
	DLT_PFLOG
} fr_dlt;
#endif

/*
 *	The number of bytes in an ethernet (MAC) address.
 */
#define ETHER_ADDR_LEN 	6

/*
 *	Length of a DEC/Intel/Xerox or 802.3 Ethernet header.
 *	Note that some compilers may pad "struct ether_header" to
 *	a multiple of 4 *bytes, for example, so "sizeof (struct
 *	ether_header)" may not give the right answer.
 *
 *	6 Byte SRC, 6 Byte DST, 2 Byte Ether type, 4 Byte CVID, 4 Byte SVID
 */
#define ETHER_HDR_LEN	22
#define IP_HDR_LEN	60

/*
 *	The number of bytes in a RADIUS packet header.
 */
#define RADIUS_HDR_LEN	20

/*
 *	RADIUS packet length.
 *	RFC 2865, Section 3., subsection 'length' says:
 *	" ... and maximum length is 4096."
 */
#define MAX_RADIUS_LEN	4096
#define MIN_RADIUS_LEN	20


#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)       ((ip)->ip_vhl & 0x0f)

#define IP_VHL(v, hl) ((v & 0x0f) << 4) | (hl & 0x0f)

#define	I_DF		0x4000		//!< Dont fragment flag.
#define IP_MF		0x2000		//!< More fragments flag.
#define IP_OFFMASK	0x1fff		//!< Mask for fragmenting bits.

/*
 *	Structure of a DEC/Intel/Xerox or 802.3 Ethernet header.
 */
typedef struct CC_HINT(__packed__) ethernet_header {
	uint8_t		ether_dst[ETHER_ADDR_LEN];
	uint8_t		ether_src[ETHER_ADDR_LEN];
	uint16_t	ether_type;
} ethernet_header_t;

/*
 *	Structure of an internet header, naked of options.
 */
typedef struct CC_HINT(__packed__) ip_header {
	uint8_t		ip_vhl;		//!< Header length, version.

	uint8_t		ip_tos;		//!< Type of service.
	uint16_t	ip_len;		//!< Total length.
	uint16_t	ip_id;		//!< identification.
	uint16_t	ip_off;		//!< Fragment offset field.

	uint8_t		ip_ttl;		//!< Time To Live.
	uint8_t		ip_p;		//!< Protocol.
	uint16_t	ip_sum;		//!< Checksum.
	struct in_addr	ip_src, ip_dst;	//!< Src and Dst address
} ip_header_t;

typedef struct CC_HINT(__packed__) ip_header6 {
	uint32_t	ip_vtcfl;	//!< Version, traffic class, flow label.
	uint16_t	ip_len;		//!< Payload length

	uint8_t		ip_next;	//!< Next header (protocol)
	uint8_t		ip_hopl;	//!< IP Hop Limit

	struct in6_addr ip_src, ip_dst;	//!< Src and Dst address
} ip_header6_t;

/*
 *	UDP protocol header.
 *	Per RFC 768, September, 1981.
 */
typedef struct CC_HINT(__packed__) udp_header {
	uint16_t	src;		//!< Source port.
	uint16_t	dst;		//!< Destination port.
	uint16_t	len;		//!< UDP length.
	uint16_t	checksum;	//!< UDP checksum.
} udp_header_t;

typedef struct CC_HINT(__packed__) radius_packet_t {
	uint8_t		code;
	uint8_t		id;
	uint8_t		length[2];
	uint8_t		vector[AUTH_VECTOR_LEN];
	uint8_t		data[];
} radius_packet_t;

bool		fr_link_layer_supported(int link_layer);
ssize_t		fr_link_layer_offset(uint8_t const *data, size_t len, int link_layer);
uint16_t	fr_udp_checksum(uint8_t const *data, uint16_t len, uint16_t checksum,
			 	struct in_addr const src_addr, struct in_addr const dst_addr);
uint16_t	fr_iph_checksum(uint8_t const *data, uint8_t ihl);
#endif /* FR_NET_H */
