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
#ifndef _FR_DHCP_H
#define _FR_DHCP_H
/**
 * $Id$
 *
 * @file include/dhcp.h
 * @brief Implementation of the DHCPv4 protocol.
 *
 * @copyright 2008  The FreeRADIUS server project
 * @copyright 2008  Alan DeKok <aland@deployingradius.com>
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

RADIUS_PACKET	*fr_dhcp_recv_pcap(fr_pcap_t *pcap);

int		fr_dhcp_send_pcap(fr_pcap_t *pcap, uint8_t *dst_ether_addr, RADIUS_PACKET *packet);
#endif

int		fr_dhcp_add_arp_entry(int fd, char const *interface, VALUE_PAIR *hwvp, VALUE_PAIR *clvp);

int8_t		fr_dhcp_attr_cmp(void const *a, void const *b);

ssize_t		fr_dhcp_encode_option(uint8_t *out, size_t outlen, vp_cursor_t *cursor, void *encoder_ctx);

int		fr_dhcp_encode(RADIUS_PACKET *packet);

ssize_t		fr_dhcp_decode_option(TALLOC_CTX *ctx, vp_cursor_t *cursor,
				      fr_dict_attr_t const *parent, uint8_t const *data, size_t len,
				      void *decoder_ctx);

int		fr_dhcp_decode(RADIUS_PACKET *packet);

#ifdef HAVE_LINUX_IF_PACKET_H
#include <linux/if_packet.h>
int		fr_socket_packet(int iface_index, struct sockaddr_ll *p_ll);

int		fr_dhcp_send_raw_packet(int sockfd, struct sockaddr_ll *p_ll, RADIUS_PACKET *packet);

RADIUS_PACKET	*fr_dhcp_recv_raw_packet(int sockfd, struct sockaddr_ll *p_ll, RADIUS_PACKET *request);
#endif

int		dhcp_init(void);

/*
 *	This is a horrible hack.
 */
#define FR_DHCP_OFFSET		(1024)

typedef enum {
	FR_DHCP_DISCOVER = (FR_DHCP_OFFSET + 1),
	FR_DHCP_OFFER =	(FR_DHCP_OFFSET + 2),
	FR_DHCP_REQUEST	= (FR_DHCP_OFFSET+ 3),
	FR_DHCP_DECLINE	= (FR_DHCP_OFFSET + 4),
	FR_DHCP_ACK = (FR_DHCP_OFFSET + 5),
	FR_DHCP_NAK = (FR_DHCP_OFFSET + 6),
	FR_DHCP_RELEASE = (FR_DHCP_OFFSET + 7),
	FR_DHCP_INFORM = (FR_DHCP_OFFSET + 8),
	FR_DHCP_FORCE_RENEW = (FR_DHCP_OFFSET + 9),
	FR_DHCP_LEASE_QUERY = (FR_DHCP_OFFSET + 10),
	FR_DHCP_LEASE_UNASSIGNED = (FR_DHCP_OFFSET + 11),
	FR_DHCP_LEASE_UNKNOWN = (FR_DHCP_OFFSET + 12),
	FR_DHCP_LEASE_ACTIVE = (FR_DHCP_OFFSET + 13),
	FR_DHCP_BULK_LEASE_QUERY = (FR_DHCP_OFFSET + 14),
	FR_DHCP_LEASE_QUERY_DONE = (FR_DHCP_OFFSET + 15),
	FR_DHCP_MAX = (FR_DHCP_OFFSET + 16)
} fr_dhcp_codes_t;

extern char const *dhcp_header_names[];
extern char const *dhcp_message_types[];

#define DHCP_MAGIC_VENDOR (54)

#define FR_DHCP_OPTION_82 (82)
#define DHCP_PACK_OPTION1(x,y) ((x) | ((y) << 8))
#define DHCP_BASE_ATTR(x) (x & 0xff)
#define DHCP_UNPACK_OPTION1(x) (((x) & 0xff00) >> 8)

#define FR_DHCP_MESSAGE_TYPE   (53)
#define FR_DHCP_YOUR_IP_ADDRESS (264)
#define FR_DHCP_SUBNET_MASK    (1)
#define FR_DHCP_IP_ADDRESS_LEASE_TIME (51)

#ifdef __cplusplus
}
#endif

#endif /* _FR_DHCP_H */
