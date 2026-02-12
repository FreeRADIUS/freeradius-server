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

#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/proto.h>
#include "attrs.h"

static uint32_t instance_count = 0;
static bool	instantiated = false;

typedef struct {
	uint8_t		code;
	uint8_t		length;
} dhcp_option_t;

fr_dict_t const *dict_dhcpv4;

extern fr_dict_autoload_t dhcpv4_dict[];
fr_dict_autoload_t dhcpv4_dict[] = {
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },

	DICT_AUTOLOAD_TERMINATOR
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
fr_dict_attr_t const *attr_dhcp_option_82;

extern fr_dict_attr_autoload_t dhcpv4_dict_attr[];
fr_dict_attr_autoload_t dhcpv4_dict_attr[] = {
	{ .out = &attr_dhcp_boot_filename, .name = "Boot-Filename", .type = FR_TYPE_STRING, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_client_hardware_address, .name = "Client-Hardware-Address", .type = FR_TYPE_ETHERNET, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_client_ip_address, .name = "Client-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_flags, .name = "Flags", .type = FR_TYPE_UINT16, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_gateway_ip_address, .name = "Gateway-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_hardware_address_length, .name = "Hardware-Address-Length", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_hardware_type, .name = "Hardware-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_hop_count, .name = "Hop-Count", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_number_of_seconds, .name = "Number-of-Seconds", .type = FR_TYPE_UINT16, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_opcode, .name = "Opcode", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_server_host_name, .name = "Server-Host-Name", .type = FR_TYPE_STRING, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_server_ip_address, .name = "Server-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_transaction_id, .name = "Transaction-Id", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_your_ip_address, .name = "Your-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_dhcp_maximum_msg_size, .name = "Maximum-Msg-Size", .type = FR_TYPE_UINT16, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_interface_mtu_size, .name = "Interface-MTU-Size", .type = FR_TYPE_UINT16, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_message_type, .name = "Message-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_parameter_request_list, .name = "Parameter-Request-List", .type = FR_TYPE_ATTR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_overload, .name = "Overload", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_vendor_class_identifier, .name = "Vendor-Class-Identifier", .type = FR_TYPE_OCTETS, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_relay_link_selection, .name = "Relay-Agent-Information.Relay-Link-Selection", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_subnet_selection_option, .name = "Subnet-Selection-Option", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_network_subnet, .name = "Network-Subnet", .type = FR_TYPE_IPV4_PREFIX, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_option_82, .name = "Relay-Agent-Information", .type = FR_TYPE_TLV, .dict = &dict_dhcpv4 },

	DICT_AUTOLOAD_TERMINATOR
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
};
size_t dhcp_header_attrs_len = NUM_ELEMENTS(dhcp_header_attrs);

char const *dhcp_message_types[] = {
	"invalid",
	"Discover",
	"Offer",
	"Request",
	"Decline",
	"Ack",
	"NAK",
	"Release",
	"Inform",
	"Force-Renew",
	"Lease-Query",
	"Lease-Unassigned",
	"Lease-Unknown",
	"Lease-Active",
	"Bulk-Lease-Query",
	"Lease-Query-Done"
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

FR_DICT_ATTR_FLAG_FUNC(fr_dhcpv4_attr_flags_t, dns_label)
FR_DICT_ATTR_FLAG_FUNC(fr_dhcpv4_attr_flags_t, exists)

static int dict_flag_prefix(fr_dict_attr_t **da_p, char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)
{
	static fr_table_num_sorted_t const table[] = {
		{ L("bits"),			DHCPV4_FLAG_PREFIX_BITS },
		{ L("split"),			DHCPV4_FLAG_PREFIX_SPLIT }
	};
	static size_t table_len = NUM_ELEMENTS(table);

	fr_dhcpv4_attr_flags_t *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	fr_dhcpv4_attr_flags_prefix_t flag;

	flag = fr_table_value_by_str(table, value, DHCPV4_FLAG_PREFIX_INVALID);
	if (flag == DHCPV4_FLAG_PREFIX_INVALID) {
		fr_strerror_printf("Unknown prefix type '%s'", value);
		return -1;
	}
	flags->prefix = flag;

	return 0;
}

static fr_dict_flag_parser_t const dhcpv4_flags[] = {
	{ L("dns_label"),	{ .func = dict_flag_dns_label } },
	{ L("exists"),		{ .func = dict_flag_exists } },
	{ L("prefix"),		{ .func = dict_flag_prefix } }
};

/*
 *	@todo - arguably we don't want to mutate the input list.
 *	Instead, the encoder should just do 3 passes, where middle one
 *	ignores the message-type and option 82.
 */
int8_t fr_dhcpv4_attr_cmp(void const *a, void const *b)
{
	fr_pair_t const *my_a = a, *my_b = b;

	PAIR_VERIFY(my_a);
	PAIR_VERIFY(my_b);

	/*
	 *	Message-Type is first, for simplicity.
	 */
	if ((my_a->da == attr_dhcp_message_type) && (my_b->da != attr_dhcp_message_type)) return -1;
	if ((my_a->da != attr_dhcp_message_type) && (my_b->da == attr_dhcp_message_type)) return +1;

	/*
	 *	Relay-Agent is last.
	 *
	 *	RFC 3046:
	 *	Servers SHOULD copy the Relay Agent Information
   	 *	option as the last DHCP option in the response.
	 *
	 *	Some crazy DHCP relay agents idea of how to strip option 82 in
	 *	a reply packet is to simply overwrite the 82 with 255 - the
	 *	"Eod of Options" option - causing the client to then ignore
	 *	any subsequent options.
	 *
	 *	Check if either of the options are option 82
	 */
	if ((my_a->da == attr_dhcp_option_82) && (my_b->da != attr_dhcp_option_82)) return +1;
	if ((my_a->da != attr_dhcp_option_82) && (my_b->da == attr_dhcp_option_82)) return -1;

	return fr_dict_attr_cmp(my_a->da, my_b->da);
}

/** Check received DHCP request is valid and build fr_packet_t structure if it is
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
		fr_strerror_printf("DHCP packet is too large (%zd > %d)", data_len, MAX_PACKET_SIZE);
		return false;
	}

	if (data[1] != 1) {
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
		fr_strerror_const("BOOTP not supported");
		return false;
	}

	code = fr_dhcpv4_packet_get_option((dhcp_packet_t const *) data, data_len, attr_dhcp_message_type);
	if (!code || (code[1] == 0)) {
		fr_strerror_const("No message-type option was found in the packet");
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

	PAIR_VERIFY(vp);
	return (vp->da->dict == dict_dhcpv4) && (!vp->da->flags.internal);
}

/** DHCPV4-specific iterator
 *
 */
void *fr_dhcpv4_next_encodable(fr_dcursor_t *cursor, void *current, void *uctx)
{
	fr_pair_t	*c = current;
	fr_dict_t	*dict = talloc_get_type_abort(uctx, fr_dict_t);

	while ((c = fr_dlist_next(cursor->dlist, c))) {
		PAIR_VERIFY(c);
		if (c->da->dict != dict || c->da->flags.internal) continue;

		if (c->vp_type == FR_TYPE_BOOL && fr_dhcpv4_flag_exists(c->da) && !c->vp_bool) continue;

		/*
		 *	The VSIO encoder expects to see VENDOR inside of VSA, and has an assertion to that
		 *	effect.  Until we fix that, we simply ignore all attributes which do not fit into the
		 *	established hierarchy.
		 */
		if (c->da->flags.is_raw && c->da->parent && (c->da->parent->type == FR_TYPE_VSA)) continue;

		fr_assert_msg((c->da->type != FR_TYPE_VENDOR) || (c->da->attr <= 255), "Cursor found unencodable attribute");

		break;
	}

	return c;
}

ssize_t fr_dhcpv4_encode(uint8_t *buffer, size_t buflen, dhcp_packet_t *original, int code, uint32_t xid, fr_pair_list_t *vps)
{
	return fr_dhcpv4_encode_dbuff(&FR_DBUFF_TMP(buffer, buflen), original, code, xid, vps);
}

ssize_t fr_dhcpv4_encode_dbuff(fr_dbuff_t *dbuff, dhcp_packet_t *original, int code, uint32_t xid, fr_pair_list_t *vps)
{
	fr_dcursor_t	cursor;
	fr_pair_t	*vp;
	ssize_t	len;
	fr_dbuff_t	work_dbuff = FR_DBUFF(dbuff);

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

	/* Maximum-Msg-Size */
	vp = fr_pair_find_by_da(vps, NULL, attr_dhcp_dhcp_maximum_msg_size);
	if (vp && (vp->vp_uint16 > mms)) {
		mms = vp->vp_uint16;

		if (mms > MAX_PACKET_SIZE) mms = MAX_PACKET_SIZE;
	}
#endif

	vp = fr_pair_find_by_da(vps, NULL, attr_dhcp_opcode);
	if (vp) {
		FR_DBUFF_IN_RETURN(&work_dbuff, vp->vp_uint8);
	} else {
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint8_t)0x01);	/* client message */
	}

	/* Hardware-Type */
	vp = fr_pair_find_by_da(vps, NULL, attr_dhcp_hardware_type);
	if (vp) {
		FR_DBUFF_IN_RETURN(&work_dbuff, vp->vp_uint8);

	} else if (original) {
		FR_DBUFF_IN_RETURN(&work_dbuff, original->htype);

	} else { /* we are ALWAYS ethernet */
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint8_t)0x01);
	}

	/* Hardware-Address-len */
	vp = fr_pair_find_by_da(vps, NULL, attr_dhcp_hardware_address_length);
	if (vp) {
		FR_DBUFF_IN_RETURN(&work_dbuff, vp->vp_uint8);

	} else if (original) {
		FR_DBUFF_IN_RETURN(&work_dbuff, original->hlen);

	} else { /* we are ALWAYS ethernet */
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint8_t)0x06);
	}

	/* Hop-Count */
	vp = fr_pair_find_by_da(vps, NULL, attr_dhcp_hop_count);
	if (vp) {
		FR_DBUFF_IN_RETURN(&work_dbuff, vp->vp_uint8);

	} else if (original) {
		FR_DBUFF_IN_RETURN(&work_dbuff, original->hops);

	} else {
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint8_t)0x00);
	}

	/* Transaction-Id */
	FR_DBUFF_IN_RETURN(&work_dbuff, xid);

	/* Number-of-Seconds */
	vp = fr_pair_find_by_da(vps, NULL, attr_dhcp_number_of_seconds);
	if (vp) {
		FR_DBUFF_IN_RETURN(&work_dbuff, vp->vp_uint16);
	} else {
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, sizeof(vp->vp_uint16));
	}

	/* Flags */
	vp = fr_pair_find_by_da(vps, NULL, attr_dhcp_flags);
	if (vp) {
		FR_DBUFF_IN_RETURN(&work_dbuff, vp->vp_uint16);
	} else if (original) { /* Original flags, still in network order */
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t *)&original->flags, sizeof(original->flags));
	} else {
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, sizeof(vp->vp_uint16));
	}

	/* Client-IP-Address */
	vp = fr_pair_find_by_da(vps, NULL, attr_dhcp_client_ip_address);
	if (vp) {
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)&vp->vp_ipv4addr, sizeof(vp->vp_ipv4addr));
	} else {
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, sizeof(vp->vp_ipv4addr));
	}

	/* Your-IP-address */
	vp = fr_pair_find_by_da(vps, NULL, attr_dhcp_your_ip_address);
	if (vp) {
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)&vp->vp_ipv4addr, sizeof(vp->vp_ipv4addr));
	} else {
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint32_t) INADDR_ANY);
	}

	/* Server-IP-Address */
	vp = fr_pair_find_by_da(vps, NULL, attr_dhcp_server_ip_address);
	if (vp) {
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)&vp->vp_ipv4addr, sizeof(vp->vp_ipv4addr));
	} else {
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint32_t) INADDR_ANY);
	}

	/*
	 *	Gateway-IP-Address
	 */
	vp = fr_pair_find_by_da(vps, NULL, attr_dhcp_gateway_ip_address);
	if (vp) {
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)&vp->vp_ipv4addr, sizeof(vp->vp_ipv4addr));

	} else if (original) {	/* copy whatever value was in the original */
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)&original->giaddr, sizeof(original->giaddr));

	} else {
		FR_DBUFF_IN_RETURN(&work_dbuff, (uint32_t) INADDR_ANY);
	}

	/* Client-Hardware-Address */
	if ((vp = fr_pair_find_by_da(vps, NULL, attr_dhcp_client_hardware_address))) {
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)vp->vp_ether, sizeof(vp->vp_ether));
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, DHCP_CHADDR_LEN - sizeof(vp->vp_ether));

	} else if (original) {	/* copy whatever value was in the original */
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, &original->chaddr[0], sizeof(original->chaddr));

	} else {
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, DHCP_CHADDR_LEN);
	}

	/* Server-Host-Name */
	if ((vp = fr_pair_find_by_da(vps, NULL, attr_dhcp_server_host_name))) {
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
	 *	Copy over Boot-Filename.
	 *
	 *	FIXME: This copy should be delayed until AFTER the options
	 *	have been processed.  If there are too many options for
	 *	the packet, then they go into the sname && filename fields.
	 *	When that happens, the boot filename is passed as an option,
	 *	instead of being placed verbatim in the filename field.
	 */

	/* Boot-Filename */
	if ((vp = fr_pair_find_by_da(vps, NULL, attr_dhcp_boot_filename))) {
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

	/*
	 *  Pre-sort attributes into contiguous blocks so that fr_dhcpv4_encode_option
	 *  operates correctly. This changes the order of the list, but never mind...
	 *
	 *  If attr_dhcp_message_type is present it will have been sorted as the first
	 *  option, so we don't need to search for it.
	 */
	fr_pair_list_sort(vps, fr_dhcpv4_attr_cmp);
	fr_pair_dcursor_iter_init(&cursor, vps, fr_dhcpv4_next_encodable, dict_dhcpv4);

	vp = fr_dcursor_head(&cursor);
	if (vp && vp->da == attr_dhcp_message_type) {
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_MESSAGE_TYPE, 0x01, vp->vp_uint8);
		fr_dcursor_next(&cursor);	/* Skip message type so it doesn't get double encoded */
	} else {
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_MESSAGE_TYPE, 0x01, (uint8_t)code);
	}

	/*
	 *  Each call to fr_dhcpv4_encode_option will encode one complete DHCP option,
	 *  and sub options.
	 */
	while ((vp = fr_dcursor_current(&cursor))) {
		/*
		 *	The encoder skips message type, and returns
		 *	"len==0" for it.  We want to allow that, BUT
		 *	stop when the encoder returns "len==0" for
		 *	other attributes.  So we need to skip it
		 *	manually, too.
		 */
		if (vp->da == attr_dhcp_message_type) {
			(void) fr_dcursor_next(&cursor);
			continue;
		}

		len = fr_dhcpv4_encode_option(&work_dbuff,
					      &cursor, &(fr_dhcpv4_ctx_t){ .root = fr_dict_root(dict_dhcpv4) });
		if (len <= 0) break;
	}

	FR_DBUFF_IN_RETURN(&work_dbuff, (uint8_t)FR_END_OF_OPTIONS);

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
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	instance_count++;

	if (fr_dict_autoload(dhcpv4_dict) < 0) {
	fail:
		instance_count--;
		return -1;
	}

	if (fr_dict_attr_autoload(dhcpv4_dict_attr) < 0) {
		fr_dict_autofree(dhcpv4_dict);
		goto fail;
	}

	instantiated = true;
	return 0;
}

void fr_dhcpv4_global_free(void)
{
	if (!instantiated) return;

	fr_assert(instance_count > 0);

	if (--instance_count > 0) return;

	fr_dict_autofree(dhcpv4_dict);
	instantiated = false;
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

		/*
		 *	The caller should already have called fr_dhcpv4_ok().
		 */
		fr_assert((attr + 2) <= end);

		/*
		 *	End of options.
		 */
		if ((attr[0] == 0) || (attr[1]) == 255) {
			fprintf(fp, "%02x\n", attr[0]);
			break;
		}

		fprintf(fp, "%02x  %02x  ", attr[0], attr[1]);

		print_hex_data(fp, attr + 2, attr[1], 3);

		attr += attr[1] + 2;
	}

	fprintf(fp, "\n");
}

static bool attr_valid(fr_dict_attr_t *da)
{
	/*
	 *	DNS labels are strings, but are known width.
	 */
	if (fr_dhcpv4_flag_dns_label(da)) {
		if (da->type != FR_TYPE_STRING) {
			fr_strerror_const("The 'dns_label' flag can only be used with attributes of type 'string'");
			return false;
		}

		da->flags.is_known_width = true;
		da->flags.length = 0;
	}

	if (da->type == FR_TYPE_ATTR)  {
		da->flags.is_known_width = true;
		da->flags.length = 1;
	}

	if (da_is_length_field16(da)) {
		fr_strerror_const("The 'length=uint16' flag cannot be used for DHCPv4");
		return false;
	}

	/*
	 *	"arrays" of string/octets are encoded as a 8-bit
	 *	length, followed by the actual data.
	 */
	if (da->flags.array) {
		if ((da->type == FR_TYPE_STRING) || (da->type == FR_TYPE_OCTETS)) {
			if (da->flags.extra && !da_is_length_field8(da)) {
				fr_strerror_const("Invalid flags");
				return false;
			}

			da->flags.is_known_width = true;
			da->flags.extra = true;
			da->flags.subtype = FLAG_LENGTH_UINT8;
		}

		if (!da->flags.is_known_width) {
			fr_strerror_const("DHCPv4 arrays require data types which have known width");
			return false;
		}
	}

	/*
	 *	"extra" signifies that subtype is being used by the
	 *	dictionaries itself.
	 */
	if (da->flags.extra || !da->flags.subtype) return true;

	if ((da->type != FR_TYPE_IPV4_PREFIX) &&
	    (fr_dhcpv4_flag_prefix(da))) {
		fr_strerror_const("The 'prefix=...' flag can only be used with attributes of type 'ipv4prefix'");
		return false;
	}

	if ((da->type != FR_TYPE_BOOL) && fr_dhcpv4_flag_exists(da)) {
		fr_strerror_const("The 'exists' flag can only be used with attributes of type 'bool'");
		return false;
	}

	if ((da->type == FR_TYPE_ATTR) && !da->parent->flags.is_root) {
		fr_strerror_const("The 'attribute' data type can only be used at the dictionary root");
		return false;
	}

	return true;
}

extern fr_dict_protocol_t libfreeradius_dhcpv4_dict_protocol;
fr_dict_protocol_t libfreeradius_dhcpv4_dict_protocol = {
	.name = "dhcpv4",
	.default_type_size = 1,
	.default_type_length = 1,
	.attr = {
		.flags = {
			.table = dhcpv4_flags,
			.table_len = NUM_ELEMENTS(dhcpv4_flags),
			.len = sizeof(fr_dhcpv4_attr_flags_t)
		},
		.valid = attr_valid
	},

	.init = fr_dhcpv4_global_init,
	.free = fr_dhcpv4_global_free,

	.encode		= fr_dhcpv4_encode_foreign,
	.decode		= fr_dhcpv4_decode_foreign,
};
