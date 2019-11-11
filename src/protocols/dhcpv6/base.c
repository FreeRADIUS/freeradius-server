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
 * @file protocols/dhcpv6/base.c
 * @brief Functions to encode DHCP options.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 NetworkRADIUS SARL (legal@networkradius.com)
 */
#include <stdint.h>
#include <stddef.h>
#include <talloc.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/io/pair.h>
#include <freeradius-devel/protocol/dhcpv6/rfc3315.h>
#include <freeradius-devel/protocol/dhcpv6/freeradius.internal.h>

#include "dhcpv6.h"
#include "attrs.h"

static int instance_count;

fr_dict_t const *dict_dhcpv6;

extern fr_dict_autoload_t libfreeradius_dhcpv6_dict[];
fr_dict_autoload_t libfreeradius_dhcpv6_dict[] = {
	{ .out = &dict_dhcpv6, .proto = "dhcpv6" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_transaction_id;
static fr_dict_attr_t const *attr_option_request;


extern fr_dict_attr_autoload_t libfreeradius_dhcpv6_dict_attr[];
fr_dict_attr_autoload_t libfreeradius_dhcpv6_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv6 },
	{ .out = &attr_transaction_id, .name = "Transaction-Id", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv6 },
	{ .out = &attr_option_request, .name = "Option-Request", .type = FR_TYPE_UINT16, .dict = &dict_dhcpv6 },
	{ NULL }
};

size_t const fr_dhcpv6_attr_sizes[FR_TYPE_MAX + 1][2] = {
	[FR_TYPE_INVALID]		= {~0, 0},	//!< Ensure array starts at 0 (umm?)

	[FR_TYPE_STRING]		= {0, ~0},
	[FR_TYPE_OCTETS]		= {0, ~0},

	[FR_TYPE_IPV4_ADDR]		= {4, 4},
	[FR_TYPE_IPV4_PREFIX]		= {1, 5},	//!< Zero length prefix still requires one byte for prefix len.
	[FR_TYPE_IPV6_ADDR]		= {16, 16},
	[FR_TYPE_IPV6_PREFIX]		= {1, 17},	//!< Zero length prefix still requires one byte for prefix len.
	[FR_TYPE_IFID]			= {8, 8},
	[FR_TYPE_ETHERNET]		= {6, 6},

	[FR_TYPE_BOOL]			= {1, 1},
	[FR_TYPE_UINT8]			= {1, 1},
	[FR_TYPE_UINT16]		= {2, 2},
	[FR_TYPE_UINT32]		= {4, 4},
	[FR_TYPE_UINT64]		= {8, 8},

	[FR_TYPE_TLV]			= {2, ~0},
	[FR_TYPE_STRUCT]		= {1, ~0},

	[FR_TYPE_MAX]			= {~0, 0}	//!< Ensure array covers all types.
};

/** Return the on-the-wire length of an attribute value
 *
 * @param[in] vp to return the length of.
 * @return the length of the attribute.
 */
size_t fr_dhcpv6_option_len(VALUE_PAIR const *vp)
{
	switch (vp->vp_type) {
	case FR_TYPE_VARIABLE_SIZE:
		if (vp->da->flags.length) return vp->da->flags.length;	/* Variable type with fixed length */
		return vp->vp_length;

	default:
		return fr_dhcpv6_attr_sizes[vp->vp_type][0];

	case FR_TYPE_STRUCTURAL:
		fr_assert_fail(NULL);
		return 0;
	}
}

#define option_len(_x) ((_x[2] << 8) | _x[3])

/** See if the data pointed to by PTR is a valid DHCPv6 packet.
 *
 * @param[in] packet		to check.
 * @param[in] packet_len	The size of the packet data.
 * @param[in] max_attributes	to allow in the packet.
 * @return
 *	- True on success.
 *	- False on failure.
 */
bool fr_dhcpv6_ok(uint8_t const *packet, size_t packet_len,
		  uint32_t max_attributes)
{
	uint8_t const *p;
	uint8_t const *end;
	uint32_t attributes;

	/*
	 *	8 bit code + 24 bits of transaction ID
	 */
	if (packet_len < 4) return false;

	if (packet_len == 4) return true;

	attributes = 0;
	p = packet + 4;
	end = packet + packet_len;

	while (p < end) {
		uint16_t len;

		if ((end - p) < 4) return false;

		len = option_len(p);
		if ((end - p) < (4 + len)) return false;

		attributes++;
		if (attributes > max_attributes) return false;

		p += 4 + len;
	}

	return true;
}

/*
 *	Return pointer to a particular option.
 */
static uint8_t const *option_find(uint8_t const *start, uint8_t const *end, unsigned int option)
{
	uint8_t const *p = start;

	while (p < end) {
		uint16_t found = (p[0] << 8) | p[1];

		if (found == option) return p;

		p += 4 + option_len(p);
	}

	return NULL;
}

static bool duid_match(uint8_t const *option, fr_dhcpv6_decode_ctx_t const *packet_ctx)
{
	uint16_t len;

	len = option_len(option);
	if (len != packet_ctx->duid_len) return false;
	if (memcmp(option + 4, packet_ctx->duid, packet_ctx->duid_len) != 0) return false;

	return true;
}

/** Verify a reply packet from a server to a client
 *
 */
static bool verify_to_client(uint8_t const *packet, size_t packet_len, fr_dhcpv6_decode_ctx_t const *packet_ctx)
{
	uint32_t transaction_id;
	uint8_t const *option;
	uint8_t const *options = packet + 4;
	uint8_t const *end = packet + packet_len;

	switch (packet[0]) {
	case FR_PACKET_TYPE_VALUE_ADVERTISE:
		transaction_id = (packet[1] << 16) | (packet[2] << 8) | packet[3];
		if (transaction_id != packet_ctx->transaction_id) {
		fail_tid:
			fr_strerror_printf("Transaction ID does not match");
			return false;
		}

		if (!option_find(options, end, FR_SERVER_ID)) {
		fail_sid:
			fr_strerror_printf("Packet does not contain a Server-Id option");
			return false;
		}

		option = option_find(options, end, FR_CLIENT_ID);
		if (!option) {
		fail_cid:
			fr_strerror_printf("Packet does not contain a Client-Id option");
			return false;
		}

		/*
		 *	The DUID MUST exist.
		 */
		if (!packet_ctx->duid) {
		fail_duid:
			fr_strerror_printf("Packet context does not contain a DUID");
			return false;
		}

	check_duid:
		if (!duid_match(option, packet_ctx)) {
		fail_match:
			fr_strerror_printf("DUID in packet does not match our DUID");
			return false;
		}
		return true;

	case FR_PACKET_TYPE_VALUE_REPLY:
		transaction_id = (packet[1] << 16) | (packet[2] << 8) | packet[3];
		if (transaction_id != packet_ctx->transaction_id) goto fail_tid;

		if (!option_find(options, end, FR_SERVER_ID)) goto fail_sid;

		/*
		 *	It's OK to not have a client ID in the reply if we didn't send one.
		 */
		option = option_find(options, end, FR_CLIENT_ID);
		if (!option) {
			if (!packet_ctx->duid) return true;
			goto fail_cid;
		}
		goto check_duid;
		
	case FR_PACKET_TYPE_VALUE_RECONFIGURE:
		if (!option_find(options, end, FR_SERVER_ID)) goto fail_sid;

		option = option_find(options, end, FR_CLIENT_ID);
		if (!option) goto fail_cid;

		/*
		 *	The DUID MUST exist.
		 */
		if (!packet_ctx->duid) goto fail_duid;
		if (!duid_match(option, packet_ctx)) goto fail_match;

		option = option_find(options, end, FR_RECONF_MSG);
		if (!option) {
			fr_strerror_printf("Packet does not contain a Reconf-Msg option");
			return false;
		}

		/*
		 *	@todo - check reconfigure message type, and
		 *	reject if it doesn't match.
		 */

		/*
		 *	@todo - check for authentication option and
		 *	verify it.
		 */
		break;

	case FR_PACKET_TYPE_VALUE_SOLICIT:
	case FR_PACKET_TYPE_VALUE_REQUEST:
	case FR_PACKET_TYPE_VALUE_CONFIRM:
	case FR_PACKET_TYPE_VALUE_RENEW:
	case FR_PACKET_TYPE_VALUE_REBIND:
	case FR_PACKET_TYPE_VALUE_RELEASE:
	case FR_PACKET_TYPE_VALUE_DECLINE:
	case FR_PACKET_TYPE_VALUE_INFORMATION_REQUEST:
	default:
		fr_strerror_printf("Invalid message type sent to client");
		return false;
	}

	return true;
}


/** Verify a packet from a client to a server
 *
 */
static bool verify_from_client(uint8_t const *packet, size_t packet_len, fr_dhcpv6_decode_ctx_t const *packet_ctx)
{
	uint8_t const *option;
	uint8_t const *options = packet + 4;
	uint8_t const *end = packet + packet_len;

	/*
	 *	Servers MUST have a DUID
	 */
	if (!packet_ctx->duid) {
		fr_strerror_printf("Packet context does not contain a DUID");
		return false;
	}

	switch (packet[0]) {
	case FR_PACKET_TYPE_VALUE_SOLICIT:
	case FR_PACKET_TYPE_VALUE_CONFIRM:
	case FR_PACKET_TYPE_VALUE_REBIND:
		if (!option_find(options, end, FR_CLIENT_ID)) {
		fail_cid:
			fr_strerror_printf("Packet does not contain a Client-Id option");
			return false;
		}

		if (!option_find(options, end, FR_SERVER_ID)) {
		fail_sid:
			fr_strerror_printf("Packet does not contain a Server-Id option");
			return false;
		}
		break;

	case FR_PACKET_TYPE_VALUE_REQUEST:
	case FR_PACKET_TYPE_VALUE_RENEW:
	case FR_PACKET_TYPE_VALUE_DECLINE:
	case FR_PACKET_TYPE_VALUE_RELEASE:
		if (!option_find(options, end, FR_CLIENT_ID)) goto fail_cid;

		option = option_find(options, end, FR_SERVER_ID);
		if (!option) goto fail_sid;

		if (!duid_match(option, packet_ctx)) {
		fail_match:
			fr_strerror_printf("DUID in packet does not match our DUID");
			return false;
		}
		break;

	case FR_PACKET_TYPE_VALUE_INFORMATION_REQUEST:
		option = option_find(options, end, FR_SERVER_ID);
		if (!option) goto fail_sid;

		if (!duid_match(option, packet_ctx)) goto fail_match;

		/*
		 *	IA options are forbidden.
		 */
		if (option_find(options, end, FR_IA_NA)) {
			fr_strerror_printf("Packet contains an IA-NA option");
			return false;
		}
		if (option_find(options, end, FR_IA_TA)) {
			fr_strerror_printf("Packet contains an IA-TA option");
			return false;
		}
		if (option_find(options, end, FR_IA_ADDR)) {
			fr_strerror_printf("Packet contains an IA-Addr option");
			return false;
		}
		break;

	case FR_PACKET_TYPE_VALUE_ADVERTISE:
	case FR_PACKET_TYPE_VALUE_REPLY:
	case FR_PACKET_TYPE_VALUE_RECONFIGURE:
	default:
		fr_strerror_printf("Invalid message type sent to server");
		return false;
	}
	return true;
}

/** Verify the packet under some various circumstances
 *
 * @param[in] packet		to check.
 * @param[in] packet_len	The size of the packet data.
 * @param[in] packet_ctx	The expected packet_ctx
 * @param[in] from_server	true for packets from a server, false for packets from a client.
 * @return
 *	- True on success.
 *	- False on failure.
 */
bool fr_dhcpv6_verify(uint8_t const *packet, size_t packet_len, fr_dhcpv6_decode_ctx_t const *packet_ctx,
		      bool from_server)
{
	/*
	 *	We don't support relaying or lease querying for now.
	 */
	if ((packet[0] == 0) || (packet[0] > FR_PACKET_TYPE_VALUE_INFORMATION_REQUEST)) return false;

	if (!packet_ctx->duid) return false;

	if (from_server) return verify_to_client(packet, packet_len, packet_ctx);

	return verify_from_client(packet, packet_len, packet_ctx);
}

/*

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |    msg-type   |               transaction-id                  |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                            options                            .
      .                 (variable number and length)                  .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/** Decode a DHCPv6 packet
 *
 */
ssize_t	fr_dhcpv6_decode(TALLOC_CTX *ctx, uint8_t const *packet, size_t packet_len,
			 VALUE_PAIR **vps)
{
	ssize_t			slen;
	fr_cursor_t		cursor;
	uint8_t const		*p, *end;
	fr_dhcpv6_decode_ctx_t	packet_ctx;
	VALUE_PAIR		*vp;

	fr_cursor_init(&cursor, vps);

	/*
	 *	Get the packet type.
	 */
	vp = fr_pair_afrom_da(ctx, attr_packet_type);
	if (!vp) return -1;

	vp->vp_uint32 = packet[0];
	vp->type = VT_DATA;
	fr_cursor_append(&cursor, vp);

	/*
	 *	@todo - skip over hop-count, IPv6 link address and
	 *	IPv6 peer address for Relay-forward and Relay-reply
	 *	messages.  There is no transaction ID in those
	 *	packets.
	 */

	/*
	 *	And the transaction ID.
	 */
	vp = fr_pair_afrom_da(ctx, attr_transaction_id);
	if (!vp) {
		fr_pair_list_free(vps);
		return -1;
	}

	/*
	 *	The internal attribute is 64-bits, but the ID is 24 bits.
	 */
	vp->vp_uint32 = packet[1];
	vp->vp_uint32 <<= 8;
	vp->vp_uint32 |= packet[2];
	vp->vp_uint32 <<= 8;
	vp->vp_uint32 |= packet[3];

	vp->type = VT_DATA;
	fr_cursor_append(&cursor, vp);

	p = packet + 4;
	end = packet + packet_len;

	packet_ctx.tmp_ctx = talloc_init("tmp");

	/*
	 *	The caller MUST have called fr_dhcpv6_ok() first.  If
	 *	he doesn't, all hell breaks loose.
	 */
	while (p < end) {
		slen = fr_dhcpv6_decode_option(ctx, &cursor, dict_dhcpv6, p, (end - p), &packet_ctx);
		if (slen < 0) {
			fr_pair_list_free(vps);
			talloc_free(packet_ctx.tmp_ctx);
			return slen;
		}

		/*
		 *	If slen is larger than the room in the packet,
		 *	all kinds of bad things happen.
		 */
		 if (!fr_cond_assert(slen <= (end - p))) {
			 fr_pair_list_free(vps);
			 talloc_free(packet_ctx.tmp_ctx);
			 return -1;
		 }

		 p += slen;
		 talloc_free_children(packet_ctx.tmp_ctx);
	}

	/*
	 *	We've parsed the whole packet, return that.
	 */
	talloc_free(packet_ctx.tmp_ctx);
	return packet_len;
}


/** Encode a DHCPv6 packet
 *
 */
ssize_t	fr_dhcpv6_encode(uint8_t *packet, size_t packet_len, uint8_t const *original,
			 int msg_type, VALUE_PAIR *vps)
{
	VALUE_PAIR *vp;
	fr_dict_attr_t const *root;
	uint8_t *p, *end;
	ssize_t slen;
	fr_cursor_t cursor;
	fr_dhcpv6_encode_ctx_t packet_ctx;

	if (packet_len < 4) return -1;

	root = fr_dict_root(dict_dhcpv6);

	if (!msg_type) {
		vp = fr_pair_find_by_da(vps, attr_packet_type, TAG_ANY);
		if (vp) msg_type = vp->vp_uint32;
	}

	if ((msg_type <= 0) || (msg_type > 255)) {
		fr_strerror_printf("Invalid message type %d", msg_type);
		return -1;
	}

	packet[0] = msg_type;

	/*
	 *	Copy over original transaction ID if we have it.
	 */
	if (original) {
		memcpy(packet + 1, original + 1, 3);
	} else {
		uint32_t id;

		/*
		 *	We can set an XID, or we can pick a random one.
		 */
		vp = fr_pair_find_by_da(vps, attr_transaction_id, TAG_ANY);
		if (vp) {
			id = vp->vp_uint32;
		} else {
			id = fr_rand();
		}

		packet[1] = (id >> 16) & 0xff;
		packet[2] = (id >> 8) & 0xff;
		packet[3] = id & 0xff;
	}

	packet_ctx.root = root;

	fr_cursor_init(&cursor, &vps);
	p = packet + 4;
	end = packet + packet_len;

	while ((p < end) && (fr_cursor_current(&cursor) != NULL)) {
		slen = fr_dhcpv6_encode_option(p, end - p, &cursor, &packet_ctx);
		if (slen == PAIR_ENCODE_SKIP) continue;

		if (slen < 0) return slen - (p - packet);

		p += slen;
	}

	return p - packet;
}



int fr_dhcpv6_global_init(void)
{
	fr_dict_attr_t const *child;
	fr_value_box_t		value = { .type = FR_TYPE_UINT16 };

	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	if (fr_dict_autoload(libfreeradius_dhcpv6_dict) < 0) return -1;
	if (fr_dict_attr_autoload(libfreeradius_dhcpv6_dict_attr) < 0) {
		fr_dict_autofree(libfreeradius_dhcpv6_dict);
		return -1;
	}

	/*
	 *	Fixup dictionary entry for DHCP-Paramter-Request-List adding all the options
	 */
	child = NULL;
	while ((child = fr_dict_attr_iterate_children(fr_dict_root(dict_dhcpv6), &child)) != NULL) {
		if (child->flags.internal) continue;

		value.vb_uint16 = child->attr;

		if (fr_dict_enum_add_name(fr_dict_attr_unconst(attr_option_request),
					  child->name, &value, true, false) < 0) {
			fr_dict_autofree(libfreeradius_dhcpv6_dict);
			return -1;
		}
	}

	instance_count++;

	return 0;
}

void fr_dhcpv6_global_free(void)
{
	if (--instance_count > 0) return;

	fr_dict_autofree(libfreeradius_dhcpv6_dict);
}

static fr_table_num_ordered_t const subtype_table[] = {
	{ "dns_label",			FLAG_ENCODE_DNS_LABEL },
	{ "encode=dns_label",		FLAG_ENCODE_DNS_LABEL },
};

extern fr_dict_protocol_t libfreeradius_dhcpv6_dict_protocol;
fr_dict_protocol_t libfreeradius_dhcpv6_dict_protocol = {
	.name = "dhcpv6",
	.default_type_size = 2,
	.default_type_length = 2,
	.subtype_table = subtype_table,
	.subtype_table_len = NUM_ELEMENTS(subtype_table),
};
