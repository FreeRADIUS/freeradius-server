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

/**
 * $Id$
 *
 * @file protocols/dhcpv4/dhcpv4.h
 * @brief Implementation of the DHCPv4 protocol.
 *
 * @copyright 2008 The FreeRADIUS server project
 * @copyright 2008 Alan DeKok (aland@deployingradius.com)
 */
RCSIDH(dhcp_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/pcap.h>
#include <freeradius-devel/util/packet.h>
#include <freeradius-devel/protocol/dhcpv4/rfc2131.h>

#define DHCP_CHADDR_LEN	(16)
#define DHCP_SNAME_LEN	(64)
#define DHCP_FILE_LEN	(128)
#define DHCP_VEND_LEN	(308)
#define DHCP_OPTION_MAGIC_NUMBER (0x63825363)

typedef enum {
	FR_DHCP_INVALID = 0,
	FR_DHCP_DISCOVER = 1,
	FR_DHCP_OFFER =	2,
	FR_DHCP_REQUEST	= 3,
	FR_DHCP_DECLINE	= 4,
	FR_DHCP_ACK = 5,
	FR_DHCP_NAK = 6,
	FR_DHCP_RELEASE = 7,
	FR_DHCP_INFORM = 8,
	FR_DHCP_FORCE_RENEW = 9,
	FR_DHCP_LEASE_QUERY = 10,
	FR_DHCP_LEASE_UNASSIGNED = 11,
	FR_DHCP_LEASE_UNKNOWN = 12,
	FR_DHCP_LEASE_ACTIVE = 13,
	FR_DHCP_BULK_LEASE_QUERY = 14,
	FR_DHCP_LEASE_QUERY_DONE = 15,
	FR_DHCP_CODE_MAX = 16,
	FR_DHCP_DO_NOT_RESPOND = 256,
} fr_dhcpv4_packet_code_t;

#define FR_DHCP_PACKET_CODE_VALID(_code) (((_code) > 0) && ((_code) < FR_DHCP_CODE_MAX))

/** subtype values for DHCPv4 and DHCPv6
 *
 */
enum {
	FLAG_ENCODE_NONE = 0,				//!< no particular encoding for DHCPv6 strings
	FLAG_ENCODE_DNS_LABEL,				//!< encode as DNS label
	FLAG_ENCODE_SPLIT_PREFIX,			//!< encode IPv4 prefixes as Policy-Filter, split into IP/mask
	FLAG_ENCODE_BITS_PREFIX,			//!< encode IPv4 prefixes as prefix bits, followed by IP.
	FLAG_ENCODE_BOOL_EXISTS,			//!< bool as existence checks
};

#define da_is_dns_label(_da) (!(_da)->flags.extra && ((_da)->flags.subtype == FLAG_ENCODE_DNS_LABEL))
#define da_is_split_prefix(_da) (!(_da)->flags.extra && ((_da)->flags.subtype == FLAG_ENCODE_SPLIT_PREFIX))
#define da_is_bits_prefix(_da) (!(_da)->flags.extra && ((_da)->flags.subtype == FLAG_ENCODE_BITS_PREFIX))
#define da_is_bool_exists(_da) (!(_da)->flags.extra && ((_da)->flags.subtype == FLAG_ENCODE_BOOL_EXISTS))

typedef struct {
	uint8_t		opcode;
	uint8_t		htype;
	uint8_t		hlen;
	uint8_t		hops;
	uint32_t	xid;	/* 4 */
	uint16_t	secs;	/* 8 */
	uint16_t	flags;
	uint32_t	ciaddr;	/* 12 */
	uint32_t	yiaddr;	/* 16 */
	uint32_t	siaddr;	/* 20 */
	uint32_t	giaddr;	/* 24 */
	uint8_t		chaddr[DHCP_CHADDR_LEN]; /* 28 */
	uint8_t		sname[DHCP_SNAME_LEN]; /* 44 */
	uint8_t		file[DHCP_FILE_LEN]; /* 108 */
	uint32_t	option_format; /* 236 */
	uint8_t		options[DHCP_VEND_LEN];
} dhcp_packet_t;

/*
 *	Some clients silently ignore responses less than 300 bytes.
 */
#define MIN_PACKET_SIZE		(244)
#define DEFAULT_PACKET_SIZE	(300)
#define MAX_PACKET_SIZE		(1500 - 40)
#define DHCPV4_MAX_ATTRIBUTES	255

#define DHCP_OPTION_FIELD	(0)
#define DHCP_FILE_FIELD	  	(1)
#define DHCP_SNAME_FIELD  	(2)

#define FR_DHCP_OPTION_82 (82)
#define DHCP_PACK_OPTION1(x,y) ((x) | ((y) << 8))
#define DHCP_UNPACK_OPTION1(x) (((x) & 0xff00) >> 8)

#ifndef INADDR_BROADCAST
#  define INADDR_BROADCAST INADDR_NONE
#endif
#define ETH_ADDR_LEN   6

#if defined(HAVE_LIBPCAP) || defined(HAVE_LINUX_IF_PACKET_H)
#  define ETH_TYPE_IP    0x0800
#  define IP_HDR_SIZE    20
#  define UDP_HDR_SIZE   8
#endif

extern fr_dict_attr_t const		**dhcp_header_attrs[];
extern size_t			 	dhcp_header_attrs_len;
extern char const			*dhcp_message_types[];
extern int				dhcp_header_sizes[];
extern uint8_t				eth_bcast[ETH_ADDR_LEN];
extern HIDDEN fr_dict_attr_t const 	*dhcp_option_82;

#ifdef HAVE_LINUX_IF_PACKET_H
#  define ETH_HDR_SIZE   14
/* Discard raw packets which we are not interested in. Allow to trace why we discard. */
#  define DISCARD_RP(...) { \
	if (fr_debug_lvl > 2) { \
		fprintf(stdout, "dhcpclient: discarding received packet: "); \
		fprintf(stdout, ## __VA_ARGS__); \
		fprintf(stdout, "\n"); \
	} \
	fr_radius_packet_free(&packet); \
	return NULL; \
}
#endif

/** Used as the decoder ctx
 *
 */
typedef struct {
	fr_dict_attr_t const *root;
	uint8_t		*buffer;		//! for coalescing concatenated options
	TALLOC_CTX	*tmp_ctx;		//!< for temporary things cleaned up during decoding
} fr_dhcpv4_ctx_t;

/*
 *	base.c
 */
int8_t		fr_dhcpv4_attr_cmp(void const *a, void const *b);

bool		fr_dhcpv4_ok(uint8_t const *data, ssize_t data_len, uint8_t *message_type, uint32_t *xid);
fr_radius_packet_t	*fr_dhcpv4_packet_alloc(uint8_t const *data, ssize_t data_len);
bool 		fr_dhcpv4_is_encodable(void const *item, void const *uctx);
void		*fr_dhcpv4_next_encodable(fr_dlist_head_t *list, void *to_eval, void *uctx);
ssize_t		fr_dhcpv4_encode(uint8_t *buffer, size_t buflen, dhcp_packet_t *original, int code, uint32_t xid, fr_pair_list_t *vps);
ssize_t		fr_dhcpv4_encode_dbuff(fr_dbuff_t *dbuff, dhcp_packet_t *original, int code, uint32_t xid, fr_pair_list_t *vps);
int		fr_dhcpv4_global_init(void);
void		fr_dhcpv4_global_free(void);
void		fr_dhcpv4_print_hex(FILE *fp, uint8_t const *packet, size_t packet_len);

/*
 *	decode.c
 */
ssize_t		fr_dhcpv4_decode_option(TALLOC_CTX *ctx, fr_pair_list_t *out,
					uint8_t const *data, size_t len, void *decode_ctx) CC_HINT(nonnull);

/*
 *	encode.c
 */
ssize_t		fr_dhcpv4_encode_option(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, void *encode_ctx);

/*
 *	packet.c
 */
uint8_t const	*fr_dhcpv4_packet_get_option(dhcp_packet_t const *packet, size_t packet_size, fr_dict_attr_t const *da);

int		fr_dhcpv4_decode(TALLOC_CTX *ctx, fr_pair_list_t *out,
				 uint8_t const *data, size_t data_len, unsigned int *code);

int		fr_dhcpv4_packet_encode(fr_radius_packet_t *packet, fr_pair_list_t *list);

#ifdef HAVE_LINUX_IF_PACKET_H
/*
 *	raw.c
 */
#include <linux/if_packet.h>
int		fr_dhcpv4_raw_socket_open(struct sockaddr_ll *p_ll, int iface_index);

int		fr_dhcpv4_raw_packet_send(int sockfd, struct sockaddr_ll *p_ll,
					  fr_radius_packet_t *packet, fr_pair_list_t *list);

fr_radius_packet_t	*fr_dhcpv4_raw_packet_recv(int sockfd, struct sockaddr_ll *p_ll,
						  fr_radius_packet_t *request, fr_pair_list_t *list);
#endif

/*
 *	pcap.c
 */
#ifdef HAVE_LIBPCAP
/*
 *	Use fr_pcap_init and fr_pcap_open to create/open handles.
 */
fr_radius_packet_t	*fr_dhcpv4_pcap_recv(fr_pcap_t *pcap);

int		fr_dhcpv4_pcap_send(fr_pcap_t *pcap, uint8_t *dst_ether_addr, fr_radius_packet_t *packet);
#endif

/*
 *	udp.c
 */
fr_radius_packet_t	*fr_dhcpv4_udp_packet_recv(int sockfd);
int		fr_dhcpv4_udp_packet_send(fr_radius_packet_t *packet);

#ifdef __cplusplus
}
#endif
