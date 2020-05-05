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
 * @file protocols/arp/base.c
 * @brief Functions to send/receive ARP packets.
 *
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com?
 */

RCSID("$Id$")

#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/io/test_point.h>
#include "attrs.h"

static uint32_t instance_count = 0;

fr_dict_t const *dict_arp;

extern fr_dict_autoload_t libfreeradius_arp_dict[];
fr_dict_autoload_t libfreeradius_arp_dict[] = {
	{ .out = &dict_arp, .proto = "arp" },
	{ NULL }
};

fr_dict_attr_t const *attr_arp_packet;

extern fr_dict_attr_autoload_t libfreeradius_arp_dict_attr[];
fr_dict_attr_autoload_t libfreeradius_arp_dict_attr[] = {
	{ .out = &attr_arp_packet, .name = "Arp-Packet", .type = FR_TYPE_STRUCT, .dict = &dict_arp },
	{ NULL }
};


/*
 *	grep VALUE share/dictionary/arp/dictionary.rfc826  | grep Op | awk '{print "[" $4 "] = \"" $3 "\","}'
 */
char const *fr_arp_packet_codes[FR_ARP_MAX_PACKET_CODE] = {
	[1] = "Request",
	[2] = "Reply",
	[3] = "Reverse-Request",
	[4] = "Reverse-Reply",
	[5] = "DRARP-Request",
	[6] = "DRARP-Reply",
	[7] = "DRARP-Error",
	[8] = "InARP-Request",
	[9] = "InARP-Reply",
	[10] = "ARP-NAK",
	[11] = "MARS-Request",
	[12] = "MARS-Multi",
	[13] = "MARS-MServ",
	[14] = "MARS-Join",
	[15] = "MARS-Leave",
	[16] = "MARS-NAK",
	[17] = "MARS-Unserv",
	[18] = "MARS-SJoin",
	[19] = "MARS-SLeave",
	[20] = "MARS-Grouplist-Request",
	[21] = "MARS-Grouplist-Reply",
	[22] = "MARS-Redirect-MAP",
	[23] = "MAPOS-UNARP",
	[24] = "OP_EXP1",
	[25] = "OP_EXP2",
};

/** Encode VPS into a raw ARP packet.
 *
 */
ssize_t fr_arp_encode(uint8_t *packet, size_t packet_len, VALUE_PAIR *vps)
{
	ssize_t			slen;
	VALUE_PAIR		*vp;
	fr_arp_packet_t		*arp;
	fr_cursor_t		cursor;
	fr_da_stack_t		da_stack;

	if (!vps) {
		fr_strerror_printf("Cannot encode empty packet");
		return -1;
	}

	/*
	 *	Find the first attribute which is parented by ARP-Packet.
	 */
	for (vp = fr_cursor_init(&cursor, &vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (vp->da->parent == attr_arp_packet) break;
	}

	/*
	 *	For simplicity, we allow the caller to omit things
	 *	that they don't care about.
	 */
	if (!vp) {
		fr_strerror_printf("No ARP attributes in the attribute list");
		return -1;
	}
	     
	fr_proto_da_stack_build(&da_stack, attr_arp_packet);
	FR_PROTO_STACK_PRINT(&da_stack, 0);

	/*
	 *	Call the struct encoder to do the actual work.
	 */
	slen = fr_struct_to_network(packet, packet_len, &da_stack, 0, &cursor, NULL, NULL);
	if (slen <= 0) return slen;

	if (slen != FR_ARP_PACKET_SIZE) return slen;

	/*
	 *	Hard-code fields which can be omitted.
	 */
	arp = (fr_arp_packet_t *) packet;
	if ((arp->htype[0] == 0) && (arp->htype[1] == 0)) arp->htype[1] = FR_HARDWARE_FORMAT_VALUE_ETHERNET;
	if ((arp->ptype[0] == 0) && (arp->ptype[1] == 0)) arp->ptype[0] = (FR_PROTOCOL_FORMAT_VALUE_IPV4 >> 8); /* 0x0800 */
	if (arp->hlen == 0) arp->hlen = 6;
	if (arp->plen == 0) arp->plen = 4;

	return FR_ARP_PACKET_SIZE;
}

/** Decode a raw ARP packet into VPs
 *
 */
ssize_t fr_arp_decode(TALLOC_CTX *ctx, uint8_t const *packet, size_t packet_len, VALUE_PAIR **vps)
{
	fr_arp_packet_t const *arp;
	fr_cursor_t cursor;
	fr_dict_attr_t const *child;

	if (packet_len < FR_ARP_PACKET_SIZE) {
		fr_strerror_printf("Packet is too small (%d) to be ARP", (int) packet_len);
		return -1;
	}

	/*
	 *	Check that the fields have the desired values.
	 */
	arp = (fr_arp_packet_t const *) packet;
	if ((arp->htype[0] != 0) || (arp->htype[1] != 1)) {
		fr_strerror_printf("Hardware-Format != Ethernet");
		return -1;
	}

	if ((arp->ptype[0] != 8) || (arp->ptype[1] != 0)) {
		fr_strerror_printf("Protocol-Format != IPv4");
		return -1;
	}

	if (arp->hlen != 6) {
		fr_strerror_printf("Hardware-Length != 6");
		return -1;
	}

	if (arp->plen != 4) {
		fr_strerror_printf("Protocol-Length != 4");
		return -1;
	}

	/*
	 *	If the packet is too long, we discard any extra data.
	 */
	fr_cursor_init(&cursor, vps);
	return fr_struct_from_network(ctx, &cursor, attr_arp_packet, packet, FR_ARP_PACKET_SIZE, &child, NULL, NULL);
}

int fr_arp_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	if (fr_dict_autoload(libfreeradius_arp_dict) < 0) return -1;
	if (fr_dict_attr_autoload(libfreeradius_arp_dict_attr) < 0) {
		fr_dict_autofree(libfreeradius_arp_dict);
		return -1;
	}

	instance_count++;

	return 0;
}

void fr_arp_free(void)
{
	if (--instance_count > 0) return;

	fr_dict_autofree(libfreeradius_arp_dict);
}

extern fr_dict_protocol_t libfreeradius_arp_dict_protocol;
fr_dict_protocol_t libfreeradius_arp_dict_protocol = {
	.name = "arp",
	.default_type_size = 4,
	.default_type_length = 0,
};


typedef struct {
	bool		tmp;
} fr_arp_ctx_t;

static int _test_ctx_free(UNUSED fr_arp_ctx_t *ctx)
{
	fr_arp_free();

	return 0;
}

static int encode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_arp_ctx_t *test_ctx;

	if (fr_arp_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_arp_ctx_t);
	if (!test_ctx) return -1;

	talloc_set_destructor(test_ctx, _test_ctx_free);

	*out = test_ctx;

	return 0;
}


/*
 *	Test points for protocol encode / decode
 *
 *	Because ARP has no TLVs, we don't have test points for pair
 *	encode / decode.
 */
static ssize_t fr_arp_encode_proto(UNUSED TALLOC_CTX *ctx, VALUE_PAIR *vps, uint8_t *data, size_t data_len, UNUSED void *proto_ctx)
{
	return fr_arp_encode(data, data_len, vps);
}

extern fr_test_point_proto_encode_t arp_tp_encode_proto;
fr_test_point_proto_encode_t arp_tp_encode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_arp_encode_proto
};

static ssize_t fr_arp_decode_proto(TALLOC_CTX *ctx, VALUE_PAIR **vps, uint8_t const *data, size_t data_len, UNUSED void *proto_ctx)
{
	return fr_arp_decode(ctx, data, data_len, vps);
}

extern fr_test_point_proto_decode_t arp_tp_decode_proto;
fr_test_point_proto_decode_t arp_tp_decode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_arp_decode_proto
};
