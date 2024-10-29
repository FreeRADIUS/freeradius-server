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
 * @copyright 2020 Network RADIUS SAS <legal@networkradius.com?
 */

RCSID("$Id$")

#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/io/test_point.h>
#include "attrs.h"

#ifdef HAVE_LINUX_IF_PACKET_H
#  include <linux/if_packet.h>
#  include <linux/if_ether.h>
#endif

#include <net/if_arp.h>

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
	{ .out = &attr_arp_packet, .name = "arp", .type = FR_TYPE_STRUCT, .dict = &dict_arp },
	{ NULL }
};


/*
 *	grep VALUE share/dictionary/arp/dictionary.rfc826  | grep Op | awk '{print "[" $4 "] = \"" $3 "\","}'
 */
char const *fr_arp_packet_codes[FR_ARP_CODE_MAX] = {
	[1] = "Request",
	[2] = "Reply",
	[3] = "Reverse-Request",
	[4] = "Reverse-Reply",
#if 0
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
#endif
};

static uint8_t const zeros[6] = { 0 };

#ifdef SIOCSARP
/** Forcibly add an ARP entry so we can send unicast packets to hosts that don't have IP addresses yet
 *
 * @param[in] fd	to add arp entry on.
 * @param[in] interface	to add arp entry on.
 * @param[in] ipaddr	to insert into ARP table.
 * @param[in] macaddr	to insert into ARP table.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_arp_entry_add(int fd, char const *interface, uint8_t ipaddr[static 4], uint8_t macaddr[static 6])
{
	struct sockaddr_in *sin;
	struct arpreq req;

	if (!interface) {
		fr_strerror_const("No interface specified.  Cannot update ARP table");
		return -1;
	}

	memset(&req, 0, sizeof(req));
	sin = (struct sockaddr_in *) &req.arp_pa;
	sin->sin_family = AF_INET;
	memcpy(&sin->sin_addr.s_addr, ipaddr, 4);

	strlcpy(req.arp_dev, interface, sizeof(req.arp_dev));

	memcpy(&req.arp_ha.sa_data, macaddr, 6);

	req.arp_flags = ATF_COM;
	if (ioctl(fd, SIOCSARP, &req) < 0) {
		fr_strerror_printf("Failed to add entry in ARP cache: %s (%d)", fr_syserror(errno), errno);
		return -1;
	}

	return 0;
}
#else
int fr_arp_entry_add(UNUSED int fd, UNUSED char const *interface,
		     UNUSED uint8_t ipaddr[static 4], UNUSED uint8_t macaddr[static 6])
{
	fr_strerror_const("Adding ARP entry is unsupported on this system");
	return -1;
}
#endif


/** Encode VPS into a raw ARP packet.
 *
 */
ssize_t fr_arp_encode(fr_dbuff_t *dbuff, uint8_t const *original, fr_pair_list_t *vps)
{
	ssize_t			slen;
	fr_pair_t		*vp;
	fr_arp_packet_t		*arp;
	fr_dcursor_t		cursor;
	fr_da_stack_t		da_stack;
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);

	if (fr_pair_list_empty(vps)) {
		fr_strerror_const("Cannot encode empty packet");
		return -1;
	}

	/*
	 *	Get a cursor over the ARP attributes.
	 */
	vp = fr_pair_dcursor_by_ancestor_init(&cursor, vps, attr_arp_packet);

	/*
	 *	For simplicity, we allow the caller to omit things
	 *	that they don't care about.
	 */
	if (!vp) {
		fr_strerror_const("No ARP attributes in the attribute list");
		return -1;
	}

	fr_proto_da_stack_build(&da_stack, attr_arp_packet);
	FR_PROTO_STACK_PRINT(&da_stack, 0);

	/*
	 *	Call the struct encoder to do the actual work.
	 */
	slen = fr_struct_to_network(&work_dbuff, &da_stack, 0, &cursor, NULL, NULL, NULL);
	if (slen <= 0) return slen;

	if (slen != FR_ARP_PACKET_SIZE) return slen;

	/*
	 *	Hard-code fields which can be omitted.
	 */
	arp = (fr_arp_packet_t *)fr_dbuff_start(&work_dbuff);

	if ((arp->htype[0] == 0) && (arp->htype[1] == 0)) arp->htype[1] = FR_HARDWARE_FORMAT_VALUE_ETHERNET;
	if ((arp->ptype[0] == 0) && (arp->ptype[1] == 0)) arp->ptype[0] = (FR_PROTOCOL_FORMAT_VALUE_IPV4 >> 8); /* 0x0800 */
	if (arp->hlen == 0) arp->hlen = 6;
	if (arp->plen == 0) arp->plen = 4;

	/*
	 *	The reply generally swaps Sender / Target addresses,
	 *	BUT fills out the Sender-Hardware-Address with the
	 *	queried MAC address.  Ensure that the admin doesn't
	 *	have to fill out all of the fields.
	 */
	if (original) {
		fr_arp_packet_t const *our_original = (fr_arp_packet_t const *) original;

#define COPY(_a, _b) do { \
	if (memcmp(arp->_a, zeros, sizeof(arp->_a)) == 0) { \
		memcpy(arp->_a, our_original->_b, sizeof(arp->_a)); \
	} \
  } while (0)

		COPY(spa, tpa);		/* answer is about the asked-for target */
		COPY(tha, sha);		/* answer is sent to the requestor hardware address */
		COPY(tpa, spa);		/* answer is sent to the requestor protocol address */
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Decode a raw ARP packet into VPs
 *
 */
ssize_t fr_arp_decode(TALLOC_CTX *ctx, fr_pair_list_t *out, uint8_t const *packet, size_t packet_len)
{
	fr_arp_packet_t const *arp;

	if (packet_len < FR_ARP_PACKET_SIZE) {
		fr_strerror_printf("Packet is too small (%d) to be ARP", (int) packet_len);
		return -1;
	}

	/*
	 *	Check that the fields have the desired values.
	 */
	arp = (fr_arp_packet_t const *) packet;
	if ((arp->htype[0] != 0) || (arp->htype[1] != 1)) {
		fr_strerror_const("Hardware-Format != Ethernet");
		return -1;
	}

	if ((arp->ptype[0] != 8) || (arp->ptype[1] != 0)) {
		fr_strerror_const("Protocol-Format != IPv4");
		return -1;
	}

	if (arp->hlen != 6) {
		fr_strerror_const("Hardware-Length != 6");
		return -1;
	}

	if (arp->plen != 4) {
		fr_strerror_const("Protocol-Length != 4");
		return -1;
	}

	/*
	 *	If the packet is too long, we discard any extra data.
	 */
	return fr_struct_from_network(ctx, out, attr_arp_packet, packet, FR_ARP_PACKET_SIZE,
				      NULL, NULL, NULL);
}

int fr_arp_global_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	instance_count++;

	if (fr_dict_autoload(libfreeradius_arp_dict) < 0) {
	fail:
		instance_count--;
		return -1;
	}

	if (fr_dict_attr_autoload(libfreeradius_arp_dict_attr) < 0) {
		fr_dict_autofree(libfreeradius_arp_dict);
		goto fail;
	}

	return 0;
}

void fr_arp_global_free(void)
{
	fr_assert(instance_count > 0);

	if (--instance_count > 0) return;

	fr_dict_autofree(libfreeradius_arp_dict);
}

extern fr_dict_protocol_t libfreeradius_arp_dict_protocol;
fr_dict_protocol_t libfreeradius_arp_dict_protocol = {
	.name = "arp",
	.default_type_size = 4,
	.default_type_length = 0,

	.init = fr_arp_global_init,
	.free = fr_arp_global_free,
};


typedef struct {
	bool		tmp;
} fr_arp_ctx_t;

static int encode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_arp_ctx_t *test_ctx;

	fr_assert(instance_count > 0);

	test_ctx = talloc_zero(ctx, fr_arp_ctx_t);
	if (!test_ctx) return -1;

	*out = test_ctx;

	return 0;
}


/*
 *	Test points for protocol encode / decode
 *
 *	Because ARP has no TLVs, we don't have test points for pair
 *	encode / decode.
 */
static ssize_t fr_arp_encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_list_t *vps, uint8_t *data, size_t data_len, UNUSED void *proto_ctx)
{
	return fr_arp_encode(&FR_DBUFF_TMP(data, data_len), NULL, vps);
}

extern fr_test_point_proto_encode_t arp_tp_encode_proto;
fr_test_point_proto_encode_t arp_tp_encode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_arp_encode_proto
};

static ssize_t fr_arp_decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *out,
				   uint8_t const *data, size_t data_len, UNUSED void *proto_ctx)
{
	return fr_arp_decode(ctx, out, data, data_len);
}

extern fr_test_point_proto_decode_t arp_tp_decode_proto;
fr_test_point_proto_decode_t arp_tp_decode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_arp_decode_proto
};
