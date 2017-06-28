/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file dhcp/dhcp.c
 * @brief Functions to send/receive dhcp packets.
 *
 * @copyright 2008 The FreeRADIUS server project
 * @copyright 2008 Alan DeKok <aland@deployingradius.com>
 */
RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/net.h>
#include <freeradius-devel/pcap.h>

#ifndef __MINGW32__
#  include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif

#ifdef HAVE_LINUX_IF_PACKET_H
#  include <linux/if_packet.h>
#  include <linux/if_ether.h>
#endif

#ifndef __MINGW32__
#  include <net/if_arp.h>
#endif

typedef struct dhcp_option_t {
	uint8_t		code;
	uint8_t		length;
} dhcp_option_t;

/*
 *	INADDR_ANY : 68 -> INADDR_BROADCAST : 67	DISCOVER
 *	INADDR_BROADCAST : 68 <- SERVER_IP : 67		OFFER
 *	INADDR_ANY : 68 -> INADDR_BROADCAST : 67	REQUEST
 *	INADDR_BROADCAST : 68 <- SERVER_IP : 67		ACK
 */
char const *dhcp_header_names[] = {
	"DHCP-Opcode",
	"DHCP-Hardware-Type",
	"DHCP-Hardware-Address-Length",
	"DHCP-Hop-Count",
	"DHCP-Transaction-Id",
	"DHCP-Number-of-Seconds",
	"DHCP-Flags",
	"DHCP-Client-IP-Address",
	"DHCP-Your-IP-Address",
	"DHCP-Server-IP-Address",
	"DHCP-Gateway-IP-Address",
	"DHCP-Client-Hardware-Address",
	"DHCP-Server-Host-Name",
	"DHCP-Boot-Filename",

	NULL
};

char const *dhcp_message_types[] = {
	"invalid",
	"DHCP-Discover",
	"DHCP-Offer",
	"DHCP-Request",
	"DHCP-Decline",
	"DHCP-Ack",
	"DHCP-NAK",
	"DHCP-Release",
	"DHCP-Inform",
	"DHCP-Force-Renew",
	"DHCP-Lease-Query",
	"DHCP-Lease-Unassigned",
	"DHCP-Lease-Unknown",
	"DHCP-Lease-Active",
	"DHCP-Bulk-Lease-Query",
	"DHCP-Lease-Query-Done"
};

#define DHCP_MAX_MESSAGE_TYPE (sizeof(dhcp_message_types) / sizeof(dhcp_message_types[0]))

int dhcp_header_sizes[] = {
	1,			/* op */
	1,			/* htype */
	1,			/* hlen */
	1,			/* hops */
	4,			/* xid */
	2,			/* secs */
	2,			/* flags */
	4,			/* ciaddr */
	4,			/* yiaddr */
	4,			/* siaddr */
	4,			/* giaddr */
	DHCP_CHADDR_LEN,	/* chaddr */
	DHCP_SNAME_LEN,		/* sname */
	DHCP_FILE_LEN		/* file */
};

fr_dict_attr_t const *dhcp_option_82;

/** Resolve/cache attributes in the DHCP dictionary
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dhcpv4_init(void)
{
	dhcp_option_82 = fr_dict_attr_by_num(NULL, DHCP_MAGIC_VENDOR, FR_DHCP_OPTION_82);
	if (!dhcp_option_82) {
		fr_strerror_printf("Missing dictionary attribute for DHCP-Option-82");
		return -1;
	}

	return 0;
}

int8_t fr_dhcp_attr_cmp(void const *a, void const *b)
{
	VALUE_PAIR const *my_a = a;
	VALUE_PAIR const *my_b = b;
	fr_dict_attr_t const *a_82, *b_82;

	VERIFY_VP(my_a);
	VERIFY_VP(my_b);

	/*
	 *	We can only use attribute numbers if we know they're
	 *	not nested attributes.
	 *
	 *	@fixme We should be able to use my_a->da->parent->flags.is_root,
	 *	but the DHCP attributes are hacked into the server under a vendor
	 *	dictionary, so we can't.
	 */

	/*
	 *	DHCP-Message-Type is first, for simplicity.
	 */
	if (((my_a->da->parent->type != FR_TYPE_TLV) && (my_a->da->attr == FR_DHCP_MESSAGE_TYPE)) &&
	    ((my_b->da->parent->type == FR_TYPE_TLV) || (my_b->da->attr != FR_DHCP_MESSAGE_TYPE))) return -1;
	if (((my_a->da->parent->type == FR_TYPE_TLV) || (my_a->da->attr != FR_DHCP_MESSAGE_TYPE)) &&
	    ((my_b->da->parent->type != FR_TYPE_TLV) && (my_b->da->attr == FR_DHCP_MESSAGE_TYPE))) return +1;

	/*
	 *	Relay-Agent is last.
	 *
	 *	Check if either of the options are descended from option 82.
	 */
	a_82 = fr_dict_parent_common(dhcp_option_82, my_a->da, true);
	b_82 = fr_dict_parent_common(dhcp_option_82, my_b->da, true);
	if (a_82 && !b_82) return +1;
	if (!a_82 && !b_82) return -1;

	return fr_pair_cmp_by_parent_num_tag(my_a, my_b);
}


/** Check reveived DHCP request is valid and build RADIUS_PACKET structure if it is
 *
 * @param data pointer to received packet.
 * @param data_len length of received data.
 * @param src_ipaddr source ip address.
 * @param src_port source port address.
 * @param dst_ipaddr destination ip address.
 * @param dst_port destination port address.
 *
 * @return
 *	- RADIUS_PACKET pointer if valid
 *	- NULL if invalid
 */
RADIUS_PACKET *fr_dhcp_packet_ok(uint8_t const *data, ssize_t data_len, fr_ipaddr_t src_ipaddr,
				 uint16_t src_port, fr_ipaddr_t dst_ipaddr, uint16_t dst_port)
{
	uint32_t	magic;
	uint8_t const	*code;
	int		pkt_id;
	RADIUS_PACKET	*packet;
	size_t		hlen;

	if (data_len < MIN_PACKET_SIZE) {
		fr_strerror_printf("DHCP packet is too small (%zu < %d)", data_len, MIN_PACKET_SIZE);
		return NULL;
	}

	if (data_len > MAX_PACKET_SIZE) {
		fr_strerror_printf("DHCP packet is too large (%zx > %d)", data_len, MAX_PACKET_SIZE);
		return NULL;
	}

	if (data[1] > 1) {
		fr_strerror_printf("DHCP can only process ethernet requests, not type %02x", data[1]);
		return NULL;
	}

	hlen = data[2];
	if ((hlen != 0) && (hlen != 6)) {
		fr_strerror_printf("Ethernet HW length incorrect.  Expected 6 got %zu", hlen);
		return NULL;
	}

	memcpy(&magic, data + 236, 4);
	magic = ntohl(magic);
	if (magic != DHCP_OPTION_MAGIC_NUMBER) {
		fr_strerror_printf("BOOTP not supported");
		return NULL;
	}

	/*
	 *	Create unique keys for the packet.
	 */
	memcpy(&magic, data + 4, 4);
	pkt_id = ntohl(magic);

	code = fr_dhcpv4_packet_get_option((dhcp_packet_t const *) data, data_len, FR_DHCP_MESSAGE_TYPE);
	if (!code) {
		fr_strerror_printf("No message-type option was found in the packet");
		return NULL;
	}

	if ((code[1] < 1) || (code[2] == 0) || (code[2] >= DHCP_MAX_MESSAGE_TYPE)) {
		fr_strerror_printf("Unknown value %d for message-type option", code[2]);
		return NULL;
	}

	/* Now that checks are done, allocate packet */
	packet = fr_radius_alloc(NULL, false);
	if (!packet) {
		fr_strerror_printf("Failed allocating packet");
		return NULL;
	}

	packet->data_len = data_len;
	packet->code = code[2] | FR_DHCP_OFFSET;
	packet->id = pkt_id;

	packet->dst_port = dst_port;
	packet->src_port = src_port;

	packet->src_ipaddr = src_ipaddr;
	packet->dst_ipaddr = dst_ipaddr;

	/*
	 *	Create a unique vector from the MAC address and the
	 *	DHCP opcode.  This is a hack for the RADIUS
	 *	infrastructure in the rest of the server.
	 *
	 *	Note: data[2] == 6, which is smaller than
	 *	sizeof(packet->vector)
	 *
	 *	FIXME:  Look for client-identifier in packet,
	 *      and use that, too?
	 */
	memset(packet->vector, 0, sizeof(packet->vector));
	memcpy(packet->vector, data + 28, hlen);
	packet->vector[hlen] = packet->code & 0xff;

	/*
	 *	FIXME: for DISCOVER / REQUEST: src_port == dst_port + 1
	 *	FIXME: for OFFER / ACK       : src_port = dst_port - 1
	 */

	/*
	 *	Unique keys are xid, client mac, and client ID?
	 */
	return packet;
}

