#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Structures and functions for parsing raw network packets
 *
 * @file src/lib/util/net.h
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2014 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(net_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_LIBPCAP
#  include <pcap.h>
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/ethernet/ethernet.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/hash.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/table.h>

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>

/*
 *	If we don't have libpcap, we still need an enumeration of link layers.
 */
#ifndef HAVE_LIBPCAP
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
#define RADIUS_HEADER_LENGTH	20

/*
 *	RADIUS packet length.
 *	RFC 2865, Section 3., subsection 'length' says:
 *	" ... and maximum length is 4096."
 */
#define MAX_RADIUS_LEN	4096
#define MIN_RADIUS_LEN	20
#define RADIUS_AUTH_VECTOR_LENGTH	16


#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)       ((ip)->ip_vhl & 0x0f)

#define IP_VHL(v, hl) ((v & 0x0f) << 4) | (hl & 0x0f)

#define	I_DF		0x4000		//!< Dont fragment flag.
#define IP_MF		0x2000		//!< More fragments flag.
#define IP_OFFMASK	0x1fff		//!< Mask for fragmenting bits.

/*
 *	Structure of an internet header, naked of options.
 */
typedef struct CC_HINT(__packed__) {
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

typedef struct CC_HINT(__packed__) {
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
typedef struct CC_HINT(__packed__) {
	uint16_t	src;		//!< Source port.
	uint16_t	dst;		//!< Destination port.
	uint16_t	len;		//!< UDP length.
	uint16_t	checksum;	//!< UDP checksum.
} udp_header_t;

extern fr_table_num_sorted_t const fr_net_ip_proto_table[];
extern size_t fr_net_ip_proto_table_len;
extern fr_table_num_sorted_t const fr_net_sock_type_table[];
extern size_t fr_net_sock_type_table_len;
extern fr_table_num_sorted_t const fr_net_af_table[];
extern size_t fr_net_af_table_len;

uint16_t	fr_udp_checksum(uint8_t const *data, uint16_t len, uint16_t checksum,
			 	struct in_addr const src_addr, struct in_addr const dst_addr);
int		fr_udp_header_check(uint8_t const *data, uint16_t remaining, ip_header_t const *ip);
uint16_t	fr_ip_header_checksum(uint8_t const *data, uint8_t ihl);

/** Write out an unsigned 16bit integer in wire format (big endian)
 *
 * @param[out] out	Where to write the integer.
 * @param[in] num	to encode.
 */
static inline void fr_net_from_uint16(uint8_t out[static sizeof(uint16_t)], uint16_t num)
{
	out[0] = (num >> 8) & 0xff;
	out[1] = num & 0xff;
}

/** Write out an unsigned 32bit integer in wire format (big endian)
 *
 * @param[out] out	Where to write the integer.
 * @param[in] num	to encode.
 */
static inline void fr_net_from_uint32(uint8_t out[static sizeof(uint32_t)], uint32_t num)
{
	fr_net_from_uint16(out, (uint16_t) (num >> 16));
	fr_net_from_uint16(out + sizeof(uint16_t), (uint16_t) num);
}

/** Write out an unsigned 64bit integer in wire format (big endian)
 *
 * @param[out] out	Where to write the integer.
 * @param[in] num	to encode.
 */
static inline void fr_net_from_uint64(uint8_t out[static sizeof(uint64_t)], uint64_t num)
{
	fr_net_from_uint32(out, (uint32_t)(num >> 32));
	fr_net_from_uint32(out + sizeof(uint32_t), (uint32_t)num);
}

/** Write out an unsigned 64bit integer in wire format using the fewest bytes possible
 *
 * @param[out] out	Where to write big endian encoding of num.
 *			Should be at least 8 bytes.
 * @param[in] num	Number to encode.
 * @return the number of bytes written to out.
 */
static inline size_t fr_net_from_uint64v(uint8_t out[static sizeof(uint64_t)], uint64_t num)
{
	size_t ret;
	/*
	 *	Special case for zero.
	 */
	if (num == 0) {
		out[0] = 0;
		return 1;
	}

	ret = ROUND_UP_DIV((size_t)fr_high_bit_pos(num), 8);
	num = ntohll(num);
	memcpy(out, ((uint8_t *)&num) + (sizeof(uint64_t) - ret), ret);	/* aligned */

	return ret;
}

/** Read an unsigned 16bit integer from wire format (big endian)
 *
 * @param[in] data	To convert to a 16bit unsigned integer of native endianness.
 * @return a 16 bit unsigned integer of native endianness.
 */
static inline uint16_t fr_net_to_uint16(uint8_t const data[static sizeof(uint16_t)])
{
	return (((uint16_t)data[0]) << 8) | data[1];
}

/** Read an unsigned 32bit integer from wire format (big endian)
 *
 * @param[in] data	To convert to a 32bit unsigned integer of native endianness.
 * @return a 32 bit unsigned integer of native endianness.
 */
static inline uint32_t fr_net_to_uint32(uint8_t const data[static sizeof(uint32_t)])
{
	return ((uint32_t)fr_net_to_uint16(data) << 16) | fr_net_to_uint16(data + sizeof(uint16_t));
}

/** Read an unsigned 64bit integer from wire format (big endian)
 *
 * @param[in] data	To convert to a 64bit unsigned integer of native endianness.
 * @return a 64 bit unsigned integer of native endianness.
 */
static inline uint64_t fr_net_to_uint64(uint8_t const data[static sizeof(uint64_t)])
{
	return ((uint64_t)fr_net_to_uint32(data) << 32) | fr_net_to_uint32(data + sizeof(uint32_t));
}

/** Read an unsigned 64bit integer from wire format (big endian) with a variable length encoding
 *
 * @param[in] data	Buffer containing the number.
 * @param[in] data_len	Length of number.
 * @return a 64 bit unsigned integer of native endianness.
 */
static inline uint64_t fr_net_to_uint64v(uint8_t const *data, size_t data_len)
{
	uint64_t num = 0;

	if (unlikely(data_len > sizeof(uint64_t))) return 0;

	/*
	 *	Copy at an offset into memory
	 *	allocated for the uin64_t
	 */
	memcpy(((uint8_t *)&num) + (sizeof(uint64_t) - data_len), data, data_len);	/* aligned */
	return ntohll(num);
}
#ifdef __cplusplus
}
#endif
