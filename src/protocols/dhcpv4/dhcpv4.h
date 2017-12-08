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
#ifndef _FR_DHCPV4_H
#define _FR_DHCPV4_H
/**
 * $Id$
 *
 * @file protocols/dhcpv4/dhcpv4.h
 * @brief Implementation of the DHCPv4 protocol.
 *
 * @copyright 2008  The FreeRADIUS server project
 * @copyright 2008  Alan DeKok <aland@deployingradius.com>
 */
RCSIDH(dhcp_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/pcap.h>

#define DHCP_CHADDR_LEN	(16)
#define DHCP_SNAME_LEN	(64)
#define DHCP_FILE_LEN	(128)
#define DHCP_VEND_LEN	(308)
#define DHCP_OPTION_MAGIC_NUMBER (0x63825363)

/*
 *	This is a horrible hack.
 */
#define FR_DHCPV4_OFFSET		(1024)

typedef enum {
	FR_DHCPV4_DISCOVER = (FR_DHCPV4_OFFSET + 1),
	FR_DHCPV4_OFFER =	(FR_DHCPV4_OFFSET + 2),
	FR_DHCPV4_REQUEST	= (FR_DHCPV4_OFFSET+ 3),
	FR_DHCPV4_DECLINE	= (FR_DHCPV4_OFFSET + 4),
	FR_DHCPV4_ACK = (FR_DHCPV4_OFFSET + 5),
	FR_DHCPV4_NAK = (FR_DHCPV4_OFFSET + 6),
	FR_DHCPV4_RELEASE = (FR_DHCPV4_OFFSET + 7),
	FR_DHCPV4_INFORM = (FR_DHCPV4_OFFSET + 8),
	FR_DHCPV4_FORCE_RENEW = (FR_DHCPV4_OFFSET + 9),
	FR_DHCPV4_LEASE_QUERY = (FR_DHCPV4_OFFSET + 10),
	FR_DHCPV4_LEASE_UNASSIGNED = (FR_DHCPV4_OFFSET + 11),
	FR_DHCPV4_LEASE_UNKNOWN = (FR_DHCPV4_OFFSET + 12),
	FR_DHCPV4_LEASE_ACTIVE = (FR_DHCPV4_OFFSET + 13),
	FR_DHCPV4_BULK_LEASE_QUERY = (FR_DHCPV4_OFFSET + 14),
	FR_DHCPV4_LEASE_QUERY_DONE = (FR_DHCPV4_OFFSET + 15),
	FR_DHCPV4_MAX = (FR_DHCPV4_OFFSET + 16)
} fr_dhcpv4_codes_t;

typedef struct dhcp_packet_t {
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

#define DHCP_MAGIC_VENDOR (54)

/*
 *	Some clients silently ignore responses less than 300 bytes.
 */
#define MIN_PACKET_SIZE		(244)
#define DEFAULT_PACKET_SIZE	(300)
#define MAX_PACKET_SIZE		(1500 - 40)

#define DHCP_OPTION_FIELD	(0)
#define DHCP_FILE_FIELD	  	(1)
#define DHCP_SNAME_FIELD  	(2)

#define FR_DHCPV4_OPTION_82 (82)
#define DHCP_PACK_OPTION1(x,y) ((x) | ((y) << 8))
#define DHCP_BASE_ATTR(x) (x & 0xff)
#define DHCP_UNPACK_OPTION1(x) (((x) & 0xff00) >> 8)

#define FR_DHCPV4_MESSAGE_TYPE   (53)
#define FR_DHCPV4_YOUR_IP_ADDRESS (264)
#define FR_DHCPV4_SUBNET_MASK    (1)
#define FR_DHCPV4_IP_ADDRESS_LEASE_TIME (51)

#ifndef INADDR_BROADCAST
#  define INADDR_BROADCAST INADDR_NONE
#endif

#if defined(HAVE_PCAP_H) || defined(HAVE_LINUX_IF_PACKET_H)
#  define ETH_TYPE_IP    0x0800
#  define IP_HDR_SIZE    20
#  define UDP_HDR_SIZE   8
#  define ETH_ADDR_LEN   6
#endif

extern char const *dhcp_header_names[];
extern char const *dhcp_message_types[];
extern int dhcp_header_sizes[];
extern uint8_t eth_bcast[ETH_ADDR_LEN];
extern fr_dict_attr_t const *dhcp_option_82;

#ifdef HAVE_LINUX_IF_PACKET_H
#  define ETH_HDR_SIZE   14
/* Discard raw packets which we are not interested in. Allow to trace why we discard. */
#  define DISCARD_RP(...) { \
	if (fr_debug_lvl > 2) { \
		fprintf(stdout, "dhcpclient: discarding received packet: "); \
		fprintf(stdout, ## __VA_ARGS__); \
		fprintf(stdout, "\n"); \
	} \
	fr_radius_free(&packet); \
	return NULL; \
}
#endif

/** Used as the decoder ctx
 *
 */
typedef struct {
	fr_dict_attr_t const *root;
} fr_dhcp_decoder_ctx_t;

RADIUS_PACKET *fr_dhcpv4_udp_packet_recv(int sockfd);
int fr_dhcpv4_udp_packet_send(RADIUS_PACKET *packet);

/*
 *	base.c
 */
int8_t		fr_dhcpv4_attr_cmp(void const *a, void const *b);

RADIUS_PACKET	*fr_dhcpv4_packet_ok(uint8_t const *data, ssize_t data_len, fr_ipaddr_t src_ipaddr,
				     uint16_t src_port, fr_ipaddr_t dst_ipaddr, uint16_t dst_port);

int		fr_dhcpv4_init(void);

/*
 *	decode.c
 */
ssize_t		fr_dhcpv4_decode_option(TALLOC_CTX *ctx, vp_cursor_t *cursor,
					uint8_t const *data, size_t len, void *decoder_ctx);

/*
 *	encode.c
 */
ssize_t		fr_dhcpv4_encode_option(uint8_t *out, size_t outlen,
					vp_cursor_t *cursor, void *encoder_ctx);

/*
 *	packet.c
 */
uint8_t const	*fr_dhcpv4_packet_get_option(dhcp_packet_t const *packet, size_t packet_size, unsigned int option);

int		fr_dhcpv4_packet_decode(RADIUS_PACKET *packet);

int		fr_dhcpv4_packet_encode(RADIUS_PACKET *packet);

#ifdef HAVE_LINUX_IF_PACKET_H
/*
 *	raw.c
 */
#include <linux/if_packet.h>
int		fr_dhcpv4_raw_socket_open(struct sockaddr_ll *p_ll, int iface_index);

int		fr_dhcpv4_raw_packet_send(int sockfd, struct sockaddr_ll *p_ll, RADIUS_PACKET *packet);

RADIUS_PACKET	*fr_dhcv4_raw_packet_recv(int sockfd, struct sockaddr_ll *p_ll, RADIUS_PACKET *request);
#endif

/*
 *	pcap.c
 */
#ifdef HAVE_PCAP_H
/*
 *	Use fr_pcap_init and fr_pcap_open to create/open handles.
 */
RADIUS_PACKET	*fr_dhcpv4_pcap_recv(fr_pcap_t *pcap);

int		fr_dhcpv4_pcap_send(fr_pcap_t *pcap, uint8_t *dst_ether_addr, RADIUS_PACKET *packet);
#endif

/*
 *	udp.c
 */
int		fr_dhcpv4_udp_add_arp_entry(int fd, char const *interface, fr_ipaddr_t const *ip, uint8_t macaddr[6]);
#ifdef __cplusplus
}
#endif

#endif /* _FR_DHCPV4_H */
