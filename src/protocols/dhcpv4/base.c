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

static int instance_count = 0;

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
	if (((my_a->da->parent->type != FR_TYPE_TLV) && (my_a->da == attr_dhcp_message_type)) &&
	    ((my_b->da->parent->type == FR_TYPE_TLV) || (my_b->da != attr_dhcp_message_type))) return -1;
	if (((my_a->da->parent->type == FR_TYPE_TLV) || (my_a->da != attr_dhcp_message_type)) &&
	    ((my_b->da->parent->type != FR_TYPE_TLV) && (my_b->da == attr_dhcp_message_type))) return +1;

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

ssize_t fr_dhcpv4_encode(uint8_t *buffer, size_t buflen, dhcp_packet_t *original, int code, uint32_t xid, VALUE_PAIR *vps)
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
	vp = fr_pair_find_by_da(vps, attr_dhcp_dhcp_maximum_msg_size, TAG_ANY);
	if (vp && (vp->vp_uint32 > mms)) {
		mms = vp->vp_uint32;

		if (mms > MAX_PACKET_SIZE) mms = MAX_PACKET_SIZE;
	}
#endif

	vp = fr_pair_find_by_da(vps, attr_dhcp_opcode, TAG_ANY);
	if (vp) {
		*p++ = vp->vp_uint32 & 0xff;
	} else {
		*p++ = 1;	/* client message */
	}

	/* DHCP-Hardware-Type */
	vp = fr_pair_find_by_da(vps, attr_dhcp_hardware_type, TAG_ANY);
	if (vp) {
		*p = vp->vp_uint8;

	} else if (original) {
		*p = original->htype;

	} /* else leave it unset */
	p += 1;

	/* DHCP-Hardware-Address-len */
	vp = fr_pair_find_by_da(vps, attr_dhcp_hardware_address_length, TAG_ANY);
	if (vp) {
		*p = vp->vp_uint8;

	} else if (original) {
		*p = original->hlen;

	} /* else leave it unset */
	p += 1;

	/* DHCP-Hop-Count */
	vp = fr_pair_find_by_da(vps, attr_dhcp_hop_count, TAG_ANY);
	if (vp) {
		*p = vp->vp_uint8;

	} else if (original) {
		*p = original->hops;

	} /* else leave it unset */
	p++;

	/* DHCP-Transaction-Id */
	lvalue = htonl(xid);
	memcpy(p, &lvalue, 4);
	p += 4;

	/* DHCP-Number-of-Seconds */
	vp = fr_pair_find_by_da(vps, attr_dhcp_number_of_seconds, TAG_ANY);
	if (vp) {
		svalue = htons(vp->vp_uint16);
		memcpy(p, &svalue, 2);
	}
	p += 2;

	/* DHCP-Flags */
	vp = fr_pair_find_by_da(vps, attr_dhcp_flags, TAG_ANY);
	if (vp) {
		svalue = htons(vp->vp_uint16);
		memcpy(p, &svalue, 2);
	}
	p += 2;

	/* DHCP-Client-IP-Address */
	vp = fr_pair_find_by_da(vps, attr_dhcp_client_ip_address, TAG_ANY);
	if (vp) memcpy(p, &vp->vp_ipv4addr, 4);
	p += 4;

	/* DHCP-Your-IP-address */
	vp = fr_pair_find_by_da(vps, attr_dhcp_your_ip_address, TAG_ANY);
	if (vp) {
		lvalue = vp->vp_ipv4addr;
	} else {
		lvalue = htonl(INADDR_ANY);
	}
	memcpy(p, &lvalue, 4);
	p += 4;

	/* DHCP-Server-IP-Address */
	vp = fr_pair_find_by_da(vps, attr_dhcp_server_ip_address, TAG_ANY);
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
	vp = fr_pair_find_by_da(vps, attr_dhcp_gateway_ip_address, TAG_ANY);
	if (vp) {
		lvalue = vp->vp_ipv4addr;
		memcpy(p, &lvalue, 4);

	} else if (original) {	/* copy whatever value was in the original */
		memcpy(p, &original->giaddr, sizeof(original->giaddr));

	} else {
		lvalue = htonl(INADDR_ANY);
		memcpy(p, &lvalue, 4);
	}
	p += 4;

	/* DHCP-Client-Hardware-Address */
	if ((vp = fr_pair_find_by_da(vps, attr_dhcp_client_hardware_address, TAG_ANY))) {
		if (vp->vp_type == FR_TYPE_ETHERNET) {
			/*
			 *	Ensure that we mark the packet as being Ethernet.
			 */
			buffer[1] = 1;	/* Hardware address type = Ethernet */
			buffer[2] = 6;	/* Hardware address length = 6 */

			memcpy(p, vp->vp_ether, sizeof(vp->vp_ether));
		} /* else ignore it */

	} else if (original) {	/* copy whatever value was in the original */
		memcpy(p, &original->chaddr[0], sizeof(original->chaddr));

	}
	p += DHCP_CHADDR_LEN;

	/* DHCP-Server-Host-Name */
	if ((vp = fr_pair_find_by_da(vps, attr_dhcp_server_host_name, TAG_ANY))) {
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
	vp = fr_pair_find_by_da(vps, attr_dhcp_boot_filename, TAG_ANY);
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

	p[0] = FR_DHCP_MESSAGE_TYPE;
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

		len = fr_dhcpv4_encode_option(p, buflen - (p - buffer),
					      &cursor, &(fr_dhcpv4_ctx_t){ .root = fr_dict_root(dict_dhcpv4) });
		if (len <= 0) break;
		p += len;
	};

	p[0] = FR_DHCP_END_OF_OPTIONS;
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
		memset(buffer + dhcp_size, 0, DEFAULT_PACKET_SIZE - dhcp_size);
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

		if (fr_dict_enum_add_alias(attr_dhcp_parameter_request_list, attr->name, &value, true, false) < 0) {
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

static void print_hex_data(uint8_t const *ptr, int attrlen, int depth)
{
	int i;
	static char const tabs[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

	for (i = 0; i < attrlen; i++) {
		if ((i > 0) && ((i & 0x0f) == 0x00))
			fprintf(fr_log_fp, "%.*s", depth, tabs);
		fprintf(fr_log_fp, "%02x ", ptr[i]);
		if ((i & 0x0f) == 0x0f) fprintf(fr_log_fp, "\n");
	}
	if ((i & 0x0f) != 0) fprintf(fr_log_fp, "\n");
}

/** Print a raw RADIUS packet as hex.
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
		print_hex_data(attr, dhcp_header_sizes[i], 2);
		attr += dhcp_header_sizes[i];
	}

	while (attr < end) {
		fprintf(fp, "\t\t");

		fprintf(fp, "%02x  %02x  ", attr[0], attr[1]);

		print_hex_data(attr + 2, attr[1], 3);

		/*
		 *	"End of option" option.
		 */
		if (attr[0] == 255) break;

		attr += attr[1] + 2;
	}
}
