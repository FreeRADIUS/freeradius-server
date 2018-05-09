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
 * @file protocols/dhcpv4/base.c
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

uint8_t	eth_bcast[ETH_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

fr_dict_attr_t const *dhcp_option_82;

int8_t fr_dhcpv4_attr_cmp(void const *a, void const *b)
{
	VALUE_PAIR const *my_a = a, *my_b = b;
	fr_dict_attr_t const *a_82, *b_82;

	VP_VERIFY(my_a);
	VP_VERIFY(my_b);

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

/** Check received DHCP request is valid and build RADIUS_PACKET structure if it is
 *
 * @param data pointer to received packet.
 * @param data_len length of received data, and then length of the actual DHCP data.
 * @param[out] message_type where the message type will be stored (if used)
 * @param[out] xid where the xid will be stored (if used)
 *
 * @return
 *	- true if the packet is well-formed
 *	- false if it's a bad packet
 */
bool fr_dhcpv4_ok(uint8_t const *data, ssize_t data_len, uint8_t *message_type, uint32_t *xid)
{
	uint32_t	magic;
	uint8_t const	*code;
	size_t		hlen;

	if (data_len < MIN_PACKET_SIZE) {
		fr_strerror_printf("DHCP packet is too small (%zu < %d)", data_len, MIN_PACKET_SIZE);
		return false;
	}

	if (data_len > MAX_PACKET_SIZE) {
		fr_strerror_printf("DHCP packet is too large (%zx > %d)", data_len, MAX_PACKET_SIZE);
		return false;
	}

	if (data[1] > 1) {
		fr_strerror_printf("DHCP can only process ethernet requests, not type %02x", data[1]);
		return false;
	}

	hlen = data[2];
	if ((hlen != 0) && (hlen != 6)) {
		fr_strerror_printf("Ethernet HW length incorrect.  Expected 6 got %zu", hlen);
		return false;
	}

	memcpy(&magic, data + 236, 4);
	magic = ntohl(magic);
	if (magic != DHCP_OPTION_MAGIC_NUMBER) {
		fr_strerror_printf("BOOTP not supported");
		return false;
	}

	code = fr_dhcpv4_packet_get_option((dhcp_packet_t const *) data, data_len, FR_DHCP_MESSAGE_TYPE);
	if (!code) {
		fr_strerror_printf("No message-type option was found in the packet");
		return false;
	}

	if ((code[1] < 1) || (code[2] == 0) || (code[2] >= DHCP_MAX_MESSAGE_TYPE)) {
		fr_strerror_printf("Unknown value %d for message-type option", code[2]);
		return false;
	}

	/*
	 *	@todo - data_len MAY be larger than the data in the
	 *	packet.  In which case, we should update data_len with
	 *	the true size of the packet.
	 */

	if (message_type) *message_type = code[2];

	if (xid) {
		memcpy(&magic, data + 4, 4);
		*xid = ntohl(magic);
	}

	return true;
}

ssize_t fr_dhcpv4_encode(uint8_t *buffer, size_t buflen, int code, uint32_t xid, VALUE_PAIR *vps)
{
	uint8_t		*p;
	fr_cursor_t	cursor;
	VALUE_PAIR	*vp;
	uint32_t	lvalue;
	uint16_t	svalue;
	size_t		dhcp_size;
	ssize_t		len;

	p = buffer;

	if (buflen < DEFAULT_PACKET_SIZE) return -1;

	/*
	 *	@todo: Make this work again.
	 */
#if 0
	mms = DEFAULT_PACKET_SIZE; /* maximum message size */

	/*
	 *	Clients can request a LARGER size, but not a
	 *	smaller one.  They also cannot request a size
	 *	larger than MTU.
	 */

	/* DHCP-DHCP-Maximum-Msg-Size */
	vp = fr_pair_find_by_num(vps, DHCP_MAGIC_VENDOR, FR_DHCP_DHCP_MAXIMUM_MSG_SIZE, TAG_ANY);
	if (vp && (vp->vp_uint32 > mms)) {
		mms = vp->vp_uint32;

		if (mms > MAX_PACKET_SIZE) mms = MAX_PACKET_SIZE;
	}
#endif

	vp = fr_pair_find_by_num(vps, DHCP_MAGIC_VENDOR, FR_DHCP_OPCODE, TAG_ANY);
	if (vp) {
		*p++ = vp->vp_uint32 & 0xff;
	} else {
		*p++ = 1;	/* client message */
	}

	/* DHCP-Hardware-Type */
	if ((vp = fr_pair_find_by_num(vps, DHCP_MAGIC_VENDOR, FR_DHCP_HARDWARE_TYPE, TAG_ANY))) {
		*p = vp->vp_uint8;
	}
	p += 1;

	/* DHCP-Hardware-Address-len */
	if ((vp = fr_pair_find_by_num(vps, DHCP_MAGIC_VENDOR, FR_DHCP_HARDWARE_ADDRESS_LENGTH, TAG_ANY))) {
		*p = vp->vp_uint8;
	}
	p += 1;

	/* DHCP-Hop-Count */
	if ((vp = fr_pair_find_by_num(vps, DHCP_MAGIC_VENDOR, FR_DHCP_HOP_COUNT, TAG_ANY))) {
		*p = vp->vp_uint8;
	}
	p++;

	/* DHCP-Transaction-Id */
	lvalue = htonl(xid);
	memcpy(p, &lvalue, 4);
	p += 4;

	/* DHCP-Number-of-Seconds */
	if ((vp = fr_pair_find_by_num(vps, DHCP_MAGIC_VENDOR, FR_DHCP_NUMBER_OF_SECONDS, TAG_ANY))) {
		svalue = htons(vp->vp_uint16);
		memcpy(p, &svalue, 2);
	}
	p += 2;

	/* DHCP-Flags */
	if ((vp = fr_pair_find_by_num(vps, DHCP_MAGIC_VENDOR, FR_DHCP_FLAGS, TAG_ANY))) {
		svalue = htons(vp->vp_uint16);
		memcpy(p, &svalue, 2);
	}
	p += 2;

	/* DHCP-Client-IP-Address */
	if ((vp = fr_pair_find_by_num(vps, DHCP_MAGIC_VENDOR, FR_DHCP_CLIENT_IP_ADDRESS, TAG_ANY))) {
		memcpy(p, &vp->vp_ipv4addr, 4);
	}
	p += 4;

	/* DHCP-Your-IP-address */
	if ((vp = fr_pair_find_by_num(vps, DHCP_MAGIC_VENDOR, FR_DHCP_YOUR_IP_ADDRESS, TAG_ANY))) {
		lvalue = vp->vp_ipv4addr;
	} else {
		lvalue = htonl(INADDR_ANY);
	}
	memcpy(p, &lvalue, 4);
	p += 4;

	/* DHCP-Server-IP-Address */
	vp = fr_pair_find_by_num(vps, DHCP_MAGIC_VENDOR, FR_DHCP_SERVER_IP_ADDRESS, TAG_ANY);
	if (vp) {
		lvalue = vp->vp_ipv4addr;
	} else {
		lvalue = htonl(INADDR_ANY);
	}
	memcpy(p, &lvalue, 4);
	p += 4;

	/*
	 *	DHCP-Gateway-IP-Address
	 */
	if ((vp = fr_pair_find_by_num(vps, DHCP_MAGIC_VENDOR, FR_DHCP_GATEWAY_IP_ADDRESS, TAG_ANY))) {
		lvalue = vp->vp_ipv4addr;
	} else {
		lvalue = htonl(INADDR_ANY);
	}
	memcpy(p, &lvalue, 4);
	p += 4;

	/* DHCP-Client-Hardware-Address */
	if ((vp = fr_pair_find_by_num(vps, DHCP_MAGIC_VENDOR, FR_DHCP_CLIENT_HARDWARE_ADDRESS, TAG_ANY))) {
		if (vp->vp_type == FR_TYPE_ETHERNET) {
			/*
			 *	Ensure that we mark the packet as being Ethernet.
			 */
			buffer[1] = 1;	/* Hardware address type = Ethernet */
			buffer[2] = 6;	/* Hardware address length = 6 */

			memcpy(p, vp->vp_ether, sizeof(vp->vp_ether));
		} /* else ignore it */
	}
	p += DHCP_CHADDR_LEN;

	/* DHCP-Server-Host-Name */
	if ((vp = fr_pair_find_by_num(vps, DHCP_MAGIC_VENDOR, FR_DHCP_SERVER_HOST_NAME, TAG_ANY))) {
		if (vp->vp_length > DHCP_SNAME_LEN) {
			memcpy(p, vp->vp_strvalue, DHCP_SNAME_LEN);
		} else {
			memcpy(p, vp->vp_strvalue, vp->vp_length);
		}
	}
	p += DHCP_SNAME_LEN;

	/*
	 *	Copy over DHCP-Boot-Filename.
	 *
	 *	FIXME: This copy should be delayed until AFTER the options
	 *	have been processed.  If there are too many options for
	 *	the packet, then they go into the sname && filename fields.
	 *	When that happens, the boot filename is passed as an option,
	 *	instead of being placed verbatim in the filename field.
	 */

	/* DHCP-Boot-Filename */
	vp = fr_pair_find_by_num(vps, DHCP_MAGIC_VENDOR, FR_DHCP_BOOT_FILENAME, TAG_ANY);
	if (vp) {
		if (vp->vp_length > DHCP_FILE_LEN) {
			memcpy(p, vp->vp_strvalue, DHCP_FILE_LEN);
		} else {
			memcpy(p, vp->vp_strvalue, vp->vp_length);
		}
	}
	p += DHCP_FILE_LEN;

	/* DHCP magic number */
	lvalue = htonl(DHCP_OPTION_MAGIC_NUMBER);
	memcpy(p, &lvalue, 4);
	p += 4;

	p[0] = 0x35;		/* DHCP-Message-Type */
	p[1] = 1;
	p[2] = code;
	p += 3;

	/*
	 *  Pre-sort attributes into contiguous blocks so that fr_dhcpv4_encode_option
	 *  operates correctly. This changes the order of the list, but never mind...
	 */
	fr_pair_list_sort(&vps, fr_dhcpv4_attr_cmp);
	fr_cursor_init(&cursor, &vps);

	/*
	 *  Each call to fr_dhcpv4_encode_option will encode one complete DHCP option,
	 *  and sub options.
	 */
	while ((vp = fr_cursor_current(&cursor))) {
		len = fr_dhcpv4_encode_option(p, buflen - (p - buffer), &cursor, NULL);
		if (len < 0) break;
		p += len;
	};

	p[0] = 0xff;		/* end of option option */
	p[1] = 0x00;
	p += 2;
	dhcp_size = p - buffer;

	/*
	 *	FIXME: if (dhcp_size > mms),
	 *	  then we put the extra options into the "sname" and "file"
	 *	  fields, AND set the "end option option" in the "options"
	 *	  field.  We also set the "overload option",
	 *	  and put options into the "file" field, followed by
	 *	  the "sname" field.  Where each option is completely
	 *	  enclosed in the "file" and/or "sname" field, AND
	 *	  followed by the "end of option", and MUST be followed
	 *	  by padding option.
	 *
	 *	Yuck.  That sucks...
	 */
	if (dhcp_size < DEFAULT_PACKET_SIZE) {
		memset(buffer + dhcp_size, 0,
		       DEFAULT_PACKET_SIZE - dhcp_size);
		dhcp_size = DEFAULT_PACKET_SIZE;
	}

	return dhcp_size;
}


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
