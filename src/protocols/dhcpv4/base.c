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
 * @copyright 2008 Alan DeKok (aland@deployingradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/pcap.h>
#include "attrs.h"

static uint32_t instance_count = 0;

typedef struct {
	uint8_t		code;
	uint8_t		length;
} dhcp_option_t;

fr_dict_t const *dict_dhcpv4;

extern fr_dict_autoload_t dhcpv4_dict[];
fr_dict_autoload_t dhcpv4_dict[] = {
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ NULL }
};

fr_dict_attr_t const *attr_dhcp_boot_filename;
fr_dict_attr_t const *attr_dhcp_client_hardware_address;
fr_dict_attr_t const *attr_dhcp_client_ip_address;
fr_dict_attr_t const *attr_dhcp_flags;
fr_dict_attr_t const *attr_dhcp_gateway_ip_address;
fr_dict_attr_t const *attr_dhcp_hardware_address_length;
fr_dict_attr_t const *attr_dhcp_hardware_type;
fr_dict_attr_t const *attr_dhcp_hop_count;
fr_dict_attr_t const *attr_dhcp_number_of_seconds;
fr_dict_attr_t const *attr_dhcp_opcode;
fr_dict_attr_t const *attr_dhcp_server_host_name;
fr_dict_attr_t const *attr_dhcp_server_ip_address;
fr_dict_attr_t const *attr_dhcp_transaction_id;
fr_dict_attr_t const *attr_dhcp_your_ip_address;
fr_dict_attr_t const *attr_dhcp_dhcp_maximum_msg_size;
fr_dict_attr_t const *attr_dhcp_interface_mtu_size;
fr_dict_attr_t const *attr_dhcp_message_type;
fr_dict_attr_t const *attr_dhcp_parameter_request_list;
fr_dict_attr_t const *attr_dhcp_overload;
fr_dict_attr_t const *attr_dhcp_vendor_class_identifier;
fr_dict_attr_t const *attr_dhcp_relay_link_selection;
fr_dict_attr_t const *attr_dhcp_subnet_selection_option;
fr_dict_attr_t const *attr_dhcp_network_subnet;

extern fr_dict_attr_autoload_t dhcpv4_dict_attr[];
fr_dict_attr_autoload_t dhcpv4_dict_attr[] = {
	{ .out = &attr_dhcp_boot_filename, .name = "DHCP-Boot-Filename", .type = FR_TYPE_STRING, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_client_hardware_address, .name = "DHCP-Client-Hardware-Address", .type = FR_TYPE_ETHERNET, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_client_ip_address, .name = "DHCP-Client-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_flags, .name = "DHCP-Flags", .type = FR_TYPE_UINT16, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_gateway_ip_address, .name = "DHCP-Gateway-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_hardware_address_length, .name = "DHCP-Hardware-Address-Length", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_hardware_type, .name = "DHCP-Hardware-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_hop_count, .name = "DHCP-Hop-Count", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_number_of_seconds, .name = "DHCP-Number-of-Seconds", .type = FR_TYPE_UINT16, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_opcode, .name = "DHCP-Opcode", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_server_host_name, .name = "DHCP-Server-Host-Name", .type = FR_TYPE_STRING, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_server_ip_address, .name = "DHCP-Server-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_transaction_id, .name = "DHCP-Transaction-Id", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_your_ip_address, .name = "DHCP-Your-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_dhcp_maximum_msg_size, .name = "DHCP-DHCP-Maximum-Msg-Size", .type = FR_TYPE_UINT16, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_interface_mtu_size, .name = "DHCP-Interface-MTU-Size", .type = FR_TYPE_UINT16, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_message_type, .name = "DHCP-Message-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_parameter_request_list, .name = "DHCP-Parameter-Request-List", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_overload, .name = "DHCP-Overload", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_vendor_class_identifier, .name = "DHCP-Vendor-Class-Identifier", .type = FR_TYPE_OCTETS, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_relay_link_selection, .name = "Relay-Agent-Information.Relay-Link-Selection", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_subnet_selection_option, .name = "DHCP-Subnet-Selection-Option", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_network_subnet, .name = "DHCP-Network-Subnet", .type = FR_TYPE_IPV4_PREFIX, .dict = &dict_dhcpv4 },
	{ NULL }
};

/*
 *	INADDR_ANY : 68 -> INADDR_BROADCAST : 67	DISCOVER
 *	INADDR_BROADCAST : 68 <- SERVER_IP : 67		OFFER
 *	INADDR_ANY : 68 -> INADDR_BROADCAST : 67	REQUEST
 *	INADDR_BROADCAST : 68 <- SERVER_IP : 67		ACK
 */
fr_dict_attr_t const **dhcp_header_attrs[] = {
	&attr_dhcp_opcode,
	&attr_dhcp_hardware_type,
	&attr_dhcp_hardware_address_length,
	&attr_dhcp_hop_count,
	&attr_dhcp_transaction_id,
	&attr_dhcp_number_of_seconds,
	&attr_dhcp_flags,
	&attr_dhcp_client_ip_address,
	&attr_dhcp_your_ip_address,
	&attr_dhcp_server_ip_address,
	&attr_dhcp_gateway_ip_address,
	&attr_dhcp_client_hardware_address,
	&attr_dhcp_server_host_name,
	&attr_dhcp_boot_filename,
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

#define DHCP_MAX_MESSAGE_TYPE (NUM_ELEMENTS(dhcp_message_types))

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
	fr_pair_t const *my_a = a, *my_b = b;
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
	if (((my_a->da->parent->type != FR_TYPE_TLV) && (my_a->da == attr_dhcp_message_type)) &&
	    ((my_b->da->parent->type == FR_TYPE_TLV) || (my_b->da != attr_dhcp_message_type))) return -1;
	if (((my_a->da->parent->type == FR_TYPE_TLV) || (my_a->da != attr_dhcp_message_type)) &&
	    ((my_b->da->parent->type != FR_TYPE_TLV) && (my_b->da == attr_dhcp_message_type))) return +1;

	/*
	 *	Relay-Agent is last.
	 *
	 *	Check if either of the options are descended from option 82.
	 */
	a_82 = fr_dict_attr_common_parent(dhcp_option_82, my_a->da, true);
	b_82 = fr_dict_attr_common_parent(dhcp_option_82, my_b->da, true);
	if (a_82 && !b_82) return +1;
	if (!a_82 && !b_82) return -1;

	return fr_pair_cmp_by_parent_num(my_a, my_b);
}

/** Check received DHCP request is valid and build fr_radius_packet_t structure if it is
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

	code = fr_dhcpv4_packet_get_option((dhcp_packet_t const *) data, data_len, attr_dhcp_message_type);
	if (!code || (code[1] == 0)) {
		fr_strerror_printf("No message-type option was found in the packet");
		return false;
	}

	if ((code[2] == 0) || (code[2] >= DHCP_MAX_MESSAGE_TYPE)) {
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

/** Evaluation function for DCHPV4-encodability
 *
 * @param item	pointer to a fr_pair_t
 * @param uctx	context
 *
 * @return true if the underlying fr_pair_t is DHCPv4 encodable, false otherwise
 */
bool fr_dhcpv4_is_encodable(void const *item, UNUSED void const *uctx)
{
	fr_pair_t const *vp = item;

	VP_VERIFY(vp);
	return (vp->da->dict == dict_dhcpv4) && (!vp->da->flags.internal);
}

ssize_t fr_dhcpv4_encode(uint8_t *buffer, size_t buflen, dhcp_packet_t *original, int code, uint32_t xid, fr_pair_t *vps)
{
	return fr_dhcpv4_encode_dbuff(&FR_DBUFF_TMP(buffer, buflen), original, code, xid, vps);
}

ssize_t fr_dhcpv4_encode_dbuff(fr_dbuff_t *dbuff, dhcp_packet_t *original, int code, uint32_t xid, fr_pair_t *vps)
{
	fr_cursor_t	cursor;
	fr_pair_t	*vp;
	ssize_t	len;
	fr_dbuff_t	work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

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
	vp = fr_pair_find_by_da(&vps, attr_dhcp_dhcp_maximum_msg_size);
	if (vp && (vp->vp_uint32 > mms)) {
		mms = vp->vp_uint32;

		if (mms > MAX_PACKET_SIZE) mms = MAX_PACKET_SIZE;
	}
#endif

	vp = fr_pair_find_by_da(&vps, attr_dhcp_opcode);
	if (vp) {
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint8_t) vp->vp_uint8);
	} else {
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint8_t)0x01);	/* client message */
	}

	/* DHCP-Hardware-Type */
	vp = fr_pair_find_by_da(&vps, attr_dhcp_hardware_type);
	if (vp) {
		FR_DBUFF_IN_RETURN(&work_dbuff, vp->vp_uint8);

	} else if (original) {
		FR_DBUFF_IN_RETURN(&work_dbuff, original->htype);

	} else { /* we are ALWAYS ethernet */
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint8_t)0x01);
	}

	/* DHCP-Hardware-Address-len */
	vp = fr_pair_find_by_da(&vps, attr_dhcp_hardware_address_length);
	if (vp) {
		FR_DBUFF_IN_RETURN(&work_dbuff, vp->vp_uint8);

	} else if (original) {
		FR_DBUFF_IN_RETURN(&work_dbuff, original->hlen);

	} else { /* we are ALWAYS ethernet */
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint8_t)0x06);
	}

	/* DHCP-Hop-Count */
	vp = fr_pair_find_by_da(&vps, attr_dhcp_hop_count);
	if (vp) {
		FR_DBUFF_IN_RETURN(&work_dbuff, vp->vp_uint8);

	} else if (original) {
		FR_DBUFF_IN_RETURN(&work_dbuff, original->hops);

	} else {
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint8_t)0x00);
	}

	/* DHCP-Transaction-Id */
	FR_DBUFF_IN_RETURN(&work_dbuff, xid);

	/* DHCP-Number-of-Seconds */
	vp = fr_pair_find_by_da(&vps, attr_dhcp_number_of_seconds);
	if (vp) {
		FR_DBUFF_IN_RETURN(&work_dbuff, vp->vp_uint16);
	} else {
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, sizeof(vp->vp_uint16));
	}

	/* DHCP-Flags */
	vp = fr_pair_find_by_da(&vps, attr_dhcp_flags);
	if (vp) {
		FR_DBUFF_IN_RETURN(&work_dbuff, vp->vp_uint16);
	} else {
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, sizeof(vp->vp_uint16));
	}

	/* DHCP-Client-IP-Address */
	vp = fr_pair_find_by_da(&vps, attr_dhcp_client_ip_address);
	if (vp) {
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)&vp->vp_ipv4addr, sizeof(vp->vp_ipv4addr));
	} else {
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, sizeof(vp->vp_ipv4addr));
	}

	/* DHCP-Your-IP-address */
	vp = fr_pair_find_by_da(&vps, attr_dhcp_your_ip_address);
	if (vp) {
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)&vp->vp_ipv4addr, sizeof(vp->vp_ipv4addr));
	} else {
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint32_t) INADDR_ANY);
	}

	/* DHCP-Server-IP-Address */
	vp = fr_pair_find_by_da(&vps, attr_dhcp_server_ip_address);
	if (vp) {
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)&vp->vp_ipv4addr, sizeof(vp->vp_ipv4addr));
	} else {
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint32_t) INADDR_ANY);
	}

	/*
	 *	DHCP-Gateway-IP-Address
	 */
	vp = fr_pair_find_by_da(&vps, attr_dhcp_gateway_ip_address);
	if (vp) {
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)&vp->vp_ipv4addr, sizeof(vp->vp_ipv4addr));

	} else if (original) {	/* copy whatever value was in the original */
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)&original->giaddr, sizeof(original->giaddr));

	} else {
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint32_t) INADDR_ANY);
	}

	/* DHCP-Client-Hardware-Address */
	if ((vp = fr_pair_find_by_da(&vps, attr_dhcp_client_hardware_address))) {
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)vp->vp_ether, sizeof(vp->vp_ether));
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, DHCP_CHADDR_LEN - sizeof(vp->vp_ether));

	} else if (original) {	/* copy whatever value was in the original */
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, &original->chaddr[0], sizeof(original->chaddr));

	} else {
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, DHCP_CHADDR_LEN);
	}

	/* DHCP-Server-Host-Name */
	if ((vp = fr_pair_find_by_da(&vps, attr_dhcp_server_host_name))) {
		if (vp->vp_length > DHCP_SNAME_LEN) {
			FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_strvalue, DHCP_SNAME_LEN);
		} else {
			FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_strvalue, vp->vp_length);
			FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, DHCP_SNAME_LEN - vp->vp_length);
		}
	} else {
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, DHCP_SNAME_LEN);
	}

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
	if ((vp = fr_pair_find_by_da(&vps, attr_dhcp_boot_filename))) {
		if (vp->vp_length > DHCP_FILE_LEN) {
			FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_strvalue, DHCP_FILE_LEN);
		} else {
			FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_strvalue, vp->vp_length);
			FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, DHCP_FILE_LEN - vp->vp_length);
		}
	} else {
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, DHCP_FILE_LEN);
	}

	/* DHCP magic number */
	FR_DBUFF_IN_RETURN(&work_dbuff, (uint32_t) DHCP_OPTION_MAGIC_NUMBER);

	if ((vp = fr_pair_find_by_da(&vps, attr_dhcp_message_type))) {
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_DHCP_MESSAGE_TYPE, 0x01, vp->vp_uint8);
	} else {
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_DHCP_MESSAGE_TYPE, 0x01, (uint8_t)code);
	}

	/*
	 *  Pre-sort attributes into contiguous blocks so that fr_dhcpv4_encode_option
	 *  operates correctly. This changes the order of the list, but never mind...
	 */
	fr_pair_list_sort(&vps, fr_dhcpv4_attr_cmp);
	fr_cursor_talloc_iter_init(&cursor, &vps, fr_proto_next_encodable, dict_dhcpv4, fr_pair_t);

	/*
	 *  Each call to fr_dhcpv4_encode_option will encode one complete DHCP option,
	 *  and sub options.
	 */
	while ((vp = fr_cursor_current(&cursor))) {
		/*
		 *	The encoder skips message type, and returns
		 *	"len==0" for it.  We want to allow that, BUT
		 *	stop when the encoder returns "len==0" for
		 *	other attributes.  So we need to skip it
		 *	manually, too.
		 */
		if (vp->da == attr_dhcp_message_type) {
			(void) fr_cursor_next(&cursor);
			continue;
		}

		len = fr_dhcpv4_encode_option(&work_dbuff,
					      &cursor, &(fr_dhcpv4_ctx_t){ .root = fr_dict_root(dict_dhcpv4) });
		if (len <= 0) break;
	};

	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_DHCP_END_OF_OPTIONS, 0x00);

	/*
	 *	FIXME: if (fr_dbuff_used(&work_dbuff) > mms),
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
	if (fr_dbuff_used(&work_dbuff) < DEFAULT_PACKET_SIZE) {
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, DEFAULT_PACKET_SIZE - fr_dbuff_used(&work_dbuff));
	}

	return fr_dbuff_set(dbuff, fr_dbuff_used(&work_dbuff));
}


/** Resolve/cache attributes in the DHCP dictionary
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dhcpv4_global_init(void)
{
	fr_value_box_t		value = { .type = FR_TYPE_UINT8 };
	uint8_t			i;

	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	if (fr_dict_autoload(dhcpv4_dict) < 0) return -1;
	if (fr_dict_attr_autoload(dhcpv4_dict_attr) < 0) {
		fr_dict_autofree(dhcpv4_dict);
		return -1;
	}

	/*
	 *	Fixup dictionary entry for DHCP-Paramter-Request-List adding all the options
	 */
	for (i = 1; i < 255; i++) {
		fr_dict_attr_t const *attr;

		attr = fr_dict_attr_child_by_num(fr_dict_root(dict_dhcpv4), i);
		if (!attr) {
			continue;
		}
		value.vb_uint8 = i;

		if (fr_dict_attr_enum_add_name(fr_dict_attr_unconst(attr_dhcp_parameter_request_list),
					  attr->name, &value, true, false) < 0) {
			return -1;
		}
	}

	instance_count++;

	return 0;
}

void fr_dhcpv4_global_free(void)
{
	if (--instance_count > 0) return;

	fr_dict_autofree(dhcpv4_dict);
}


static char const *short_header_names[] = {
	"opcode",
	"hwtype",
	"hwaddrlen",
	"hop_count",
	"xid",
	"seconds",
	"flags",
	"ciaddr",
	"yiaddr",
	"siaddr",
	"giaddr",
	"chaddr",
	"server_hostname",
	"boot_filename",
};

static void print_hex_data(FILE *fp, uint8_t const *ptr, int attrlen, int depth)
{
	int i;
	static char const tabs[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

	for (i = 0; i < attrlen; i++) {
		if ((i > 0) && ((i & 0x0f) == 0x00))
			fprintf(fp, "%.*s", depth, tabs);
		fprintf(fp, "%02x ", ptr[i]);
		if ((i & 0x0f) == 0x0f) fprintf(fp, "\n");
	}
	if ((i & 0x0f) != 0) fprintf(fp, "\n");
}

/** Print a raw DHCP packet as hex.
 *
 */
void fr_dhcpv4_print_hex(FILE *fp, uint8_t const *packet, size_t packet_len)
{
	int i;
	uint8_t const *attr, *end;

	end = packet + packet_len;
	attr = packet;

	for (i = 0; i < 14; i++) {
		fprintf(fp, "\t%s: ", short_header_names[i]);
		print_hex_data(fp, attr, dhcp_header_sizes[i], 2);
		attr += dhcp_header_sizes[i];
	}

	fprintf(fp, "\tmagic:\t%02x %02x %02x %02x\n", attr[0], attr[1], attr[2], attr[3]);
	attr += 4;

	fprintf(fp, "\toptions\n");
	while (attr < end) {
		fprintf(fp, "\t\t");

		fprintf(fp, "%02x  %02x  ", attr[0], attr[1]);

		print_hex_data(fp, attr + 2, attr[1], 3);

		/*
		 *	"End of option" option.
		 */
		if (attr[0] == 255) break;

		attr += attr[1] + 2;
	}

	fprintf(fp, "\n");
}

static fr_table_num_ordered_t const subtype_table[] = {
	{ L("dns_label"),			FLAG_ENCODE_DNS_LABEL },
	{ L("encode=dns_label"),		FLAG_ENCODE_DNS_LABEL },
};

static bool attr_valid(UNUSED fr_dict_t *dict, UNUSED fr_dict_attr_t const *parent,
		       UNUSED char const *name, UNUSED int attr, fr_type_t type, fr_dict_attr_flags_t *flags)
{
	/*
	 *	"extra" signifies that subtype is being used by the
	 *	dictionaries itself.
	 */
	if (flags->extra || !flags->subtype) return true;

	if (type != FR_TYPE_STRING) {
		fr_strerror_printf("The 'dns_label' flag can only be used with attributes of type 'string'");
		return false;
	}

	return true;
}

extern fr_dict_protocol_t libfreeradius_dhcpv4_dict_protocol;
fr_dict_protocol_t libfreeradius_dhcpv4_dict_protocol = {
	.name = "dhcpv4",
	.default_type_size = 1,
	.default_type_length = 1,
	.subtype_table = subtype_table,
	.subtype_table_len = NUM_ELEMENTS(subtype_table),
	.attr_valid = attr_valid,
};
