#ifndef FR_DHCP_H
#define FR_DHCP_H

/*
 * dhcp.h	Structures and prototypes for DHCP.
 *		Why DHCP in a RADIUS server?
 *		Why not?
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2008 The FreeRADIUS server project
 * Copyright 2008 Alan DeKok <aland@deployingradius.com>
 */
RCSIDH(dhcp_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	Not for production use.
 */
RADIUS_PACKET *fr_dhcp_recv_socket(int sockfd);
int fr_dhcp_send_socket(RADIUS_PACKET *packet);

#ifdef HAVE_PCAP_H
typedef struct fr_pcap fr_pcap_t;
RADIUS_PACKET *fr_dhcp_recv_pcap(fr_pcap_t *pcap);
int fr_dhcp_send_pcap(fr_pcap_t *pcap, uint8_t *dst_ether_addr, RADIUS_PACKET *packet);
#endif

int fr_dhcp_add_arp_entry(int fd, char const *interface, VALUE_PAIR *hwvp, VALUE_PAIR *clvp);

int8_t fr_dhcp_attr_cmp(void const *a, void const *b);
ssize_t fr_dhcp_encode_option(TALLOC_CTX *ctx, uint8_t *out, size_t outlen, vp_cursor_t *cursor);
int fr_dhcp_encode(RADIUS_PACKET *packet);
ssize_t fr_dhcp_decode_options(TALLOC_CTX *ctx, VALUE_PAIR **out, uint8_t const *data, size_t len);
int fr_dhcp_decode(RADIUS_PACKET *packet);

#ifdef HAVE_LINUX_IF_PACKET_H
#include <linux/if_packet.h>
int fr_socket_packet(int iface_index, struct sockaddr_ll *p_ll);
int fr_dhcp_send_raw_packet(int sockfd, struct sockaddr_ll *p_ll, RADIUS_PACKET *packet);
RADIUS_PACKET *fr_dhcp_recv_raw_packet(int sockfd, struct sockaddr_ll *p_ll, RADIUS_PACKET *request);
#endif

/*
 *	This is a horrible hack.
 */
#define PW_DHCP_OFFSET		(1024)

typedef enum {
	PW_DHCP_DISCOVER = (PW_DHCP_OFFSET + 1),
	PW_DHCP_OFFER =	(PW_DHCP_OFFSET + 2),
	PW_DHCP_REQUEST	= (PW_DHCP_OFFSET+ 3),
	PW_DHCP_DECLINE	= (PW_DHCP_OFFSET + 4),
	PW_DHCP_ACK = (PW_DHCP_OFFSET + 5),
	PW_DHCP_NAK = (PW_DHCP_OFFSET + 6),
	PW_DHCP_RELEASE = (PW_DHCP_OFFSET + 7),
	PW_DHCP_INFORM = (PW_DHCP_OFFSET + 8),
	PW_DHCP_FORCE_RENEW = (PW_DHCP_OFFSET + 9),
	PW_DHCP_LEASE_QUERY = (PW_DHCP_OFFSET + 10),
	PW_DHCP_LEASE_UNASSIGNED = (PW_DHCP_OFFSET + 11),
	PW_DHCP_LEASE_UNKNOWN = (PW_DHCP_OFFSET + 12),
	PW_DHCP_LEASE_ACTIVE = (PW_DHCP_OFFSET + 13),
	PW_DHCP_BULK_LEASE_QUERY = (PW_DHCP_OFFSET + 14),
	PW_DHCP_LEASE_QUERY_DONE = (PW_DHCP_OFFSET + 15),
	PW_DHCP_MAX = (PW_DHCP_OFFSET + 16)
} fr_dhcp_codes_t;

extern char const *dhcp_header_names[];
extern char const *dhcp_message_types[];

#define DHCP_MAGIC_VENDOR (54)

#define PW_DHCP_OPTION_82 (82)
#define DHCP_PACK_OPTION1(x,y) ((x) | ((y) << 8))
#define DHCP_BASE_ATTR(x) (x & 0xff)
#define DHCP_UNPACK_OPTION1(x) (((x) & 0xff00) >> 8)

#define PW_DHCP_MESSAGE_TYPE   (53)
#define PW_DHCP_YOUR_IP_ADDRESS (264)
#define PW_DHCP_SUBNET_MASK    (1)
#define PW_DHCP_IP_ADDRESS_LEASE_TIME (51)

#ifdef __cplusplus
}
#endif

#endif /* FR_DHCP_H */
