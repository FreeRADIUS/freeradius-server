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
#include <freeradius-devel/io/pair.h>
#include <freeradius-devel/protocol/dhcpv6/freeradius.internal.h>
#include <freeradius-devel/protocol/dhcpv6/rfc3315.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/types.h>
#include <stddef.h>
#include <stdint.h>
#include <talloc.h>

#include "dhcpv6.h"
#include "attrs.h"

static uint32_t instance_count = 0;

fr_dict_t const *dict_dhcpv6;

extern fr_dict_autoload_t libfreeradius_dhcpv6_dict[];
fr_dict_autoload_t libfreeradius_dhcpv6_dict[] = {
	{ .out = &dict_dhcpv6, .proto = "dhcpv6" },
	{ NULL }
};

fr_dict_attr_t const *attr_packet_type;
fr_dict_attr_t const *attr_transaction_id;
fr_dict_attr_t const *attr_option_request;
fr_dict_attr_t const *attr_hop_count;
fr_dict_attr_t const *attr_relay_link_address;
fr_dict_attr_t const *attr_relay_peer_address;
fr_dict_attr_t const *attr_relay_message;

extern fr_dict_attr_autoload_t libfreeradius_dhcpv6_dict_attr[];
fr_dict_attr_autoload_t libfreeradius_dhcpv6_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv6 },
	{ .out = &attr_transaction_id, .name = "Transaction-Id", .type = FR_TYPE_OCTETS, .dict = &dict_dhcpv6 },
	{ .out = &attr_hop_count, .name = "Hop-Count", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv6 },
	{ .out = &attr_relay_link_address, .name = "Relay-Link-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_dhcpv6 },
	{ .out = &attr_relay_peer_address, .name = "Relay-Peer-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_dhcpv6 },
	{ .out = &attr_relay_message, .name = "Relay-Message", .type = FR_TYPE_GROUP, .dict = &dict_dhcpv6 },
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


/*
 * grep VALUE share/dictionary/dhcpv6/dictionary.freeradius.internal  | awk '{print "[" $4 "] = \"" $3 "\"," }'
 */
char const *fr_dhcpv6_packet_types[FR_DHCPV6_MAX_CODE] = {
	 [0] = "invalid",
	 [1] = "Solicit",
	 [2] = "Advertise",
	 [3] = "Request",
	 [4] = "Confirm",
	 [5] = "Renew",
	 [6] = "Rebind",
	 [7] = "Reply",
	 [8] = "Release",
	 [9] = "Decline",
	 [10] = "Reconfigure",
	 [11] = "Information-Request",
	 [12] = "Relay-Forward",
	 [13] = "Relay-Reply",
	 [14] = "Lease-Query",
	 [15] = "Lease-Query-Reply",
	 [16] = "Lease-Query-Done",
	 [17] = "Lease-Query-Data",
	 [18] = "Reconfigure-Request",
	 [19] = "Reconfigure-Reply",
	 [20] = "DHCPv4-Query",
	 [21] = "DHCPv4-Response",
	 [22] = "Active-Lease-Query",
	 [23] = "Start-TLS",
	 [24] = "Bind-Update",
	 [25] = "Bind-Reply",
	 [26] = "Pool-Request",
	 [27] = "Pool-Response",
	 [28] = "Update-Request",
	 [29] = "Update-Request-All",
	 [30] = "Update-Done",
	 [31] = "Connect",
	 [32] = "Connect-Reply",
	 [33] = "Disconnect",
	 [34] = "State",
	 [35] = "Contact",
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

	case FR_TYPE_DATE:
	case FR_TYPE_TIME_DELTA:
		if (vp->data.enumv->flags.length) return vp->data.enumv->flags.length;
		return 4;

	default:
		return fr_dhcpv6_attr_sizes[vp->vp_type][0];

	case FR_TYPE_STRUCTURAL:
		fr_assert_fail(NULL);
		return 0;
	}
}

#define get_option_num(_x) (((_x)[0] << 8) | (_x)[1])
#define get_option_len(_x) (((_x)[2] << 8) | (_x)[3])

static ssize_t fr_dhcpv6_ok_internal(uint8_t const *packet, uint8_t const *end, size_t max_attributes, int depth,
				     char const **error);

static ssize_t fr_dhcpv6_options_ok(uint8_t const *packet, uint8_t const *end, size_t max_attributes,
				    bool allow_relay, int depth, char const **error)
{
	size_t attributes;
	uint8_t const *p;

	attributes = 0;
	p = packet;

	while (p < end) {
		uint16_t len;

		if ((end - p) < 4) {
			*error = "Not enough room for option header";
			return -(p - packet);
		}

		len = get_option_len(p);
		if ((end - p) < (4 + len)) {
			*error = "Option length overflows the packet";
			return -(p - packet);
		}

		attributes++;
		if (attributes > (size_t) max_attributes) {
			*error = "Too many attributes";
			return -(p - packet);
		}

		/*
		 *	Recurse into the Relay-Message attribute, but
		 *	only if the outer packet was a relayed message.
		 */
		if (allow_relay && (p[0] == 0) && (p[1] == attr_relay_message->attr)) {
			ssize_t child;

			/*
			 *	Recurse to check the encapsulated packet.
			 */
			child = fr_dhcpv6_ok_internal(p + 4, p + 4 + len, max_attributes - attributes, depth + 1, error);
			if (child <= 0) {
				return -((p + 4) - packet) + child;
			}

			attributes += child;
		}

		p += 4 + len;
	}

	return attributes;
}

static ssize_t fr_dhcpv6_ok_internal(uint8_t const *packet, uint8_t const *end, size_t max_attributes, int depth,
				     char const **error)
{
	uint8_t const *p;
	ssize_t attributes;
	bool allow_relay;
	size_t packet_len = end - packet;

	if (depth > 8) {
		*error = "Too many layers forwarded packets";
		return 0;
	}

	if ((packet[0] == FR_DHCPV6_RELAY_FORWARD) ||
	    (packet[0] == FR_DHCPV6_RELAY_REPLY)) {
		if (packet_len < 2 + 32) {
			*error = "Packet is too small for relay header";
			return 0;
		}

		p = packet + 2 + 32;
		allow_relay = true;

	} else {
		/*
		 *	8 bit code + 24 bits of transaction ID
		 */
		if (packet_len < 4) {
			*error = "Packet is too small for DHCPv6 header";
			return 0;
		}

		p = packet + 4;
		allow_relay = false;
	}

	attributes = fr_dhcpv6_options_ok(p, end, max_attributes, allow_relay, depth, error);
	if (attributes < 0) return -(p - packet) + attributes;

	return attributes;
}


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
	ssize_t slen;
	char const *error = NULL;

	slen = fr_dhcpv6_ok_internal(packet, packet + packet_len, max_attributes, 0, &error);
	if (slen <= 0) {
		fr_strerror_printf("Invalid DHCPv6 packet starting at offset %zd - %s", -slen, error);
		return false;
	}

	return true;
}

/*
 *	Return pointer to a particular option.
 */
uint8_t const *fr_dhcpv6_option_find(uint8_t const *start, uint8_t const *end, unsigned int option)
{
	uint8_t const *p = start;

	while (p < end) {
		uint16_t found;
		uint16_t len;

		if ((end - p) < 4) return NULL;

		found = get_option_num(p);
		len = get_option_len(p);

		if ((p + 4 + len) > end) return NULL;

		if (found == option) return p;

		p += 4 + len;
	}

	return NULL;
}

static bool duid_match(uint8_t const *option, fr_dhcpv6_decode_ctx_t const *packet_ctx)
{
	uint16_t len;

	len = get_option_len(option);
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

		if (!fr_dhcpv6_option_find(options, end, FR_SERVER_ID)) {
		fail_sid:
			fr_strerror_printf("Packet does not contain a Server-Id option");
			return false;
		}

		option = fr_dhcpv6_option_find(options, end, FR_CLIENT_ID);
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

		if (!fr_dhcpv6_option_find(options, end, FR_SERVER_ID)) goto fail_sid;

		/*
		 *	It's OK to not have a client ID in the reply if we didn't send one.
		 */
		option = fr_dhcpv6_option_find(options, end, FR_CLIENT_ID);
		if (!option) {
			if (!packet_ctx->duid) return true;
			goto fail_cid;
		}
		goto check_duid;

	case FR_PACKET_TYPE_VALUE_RECONFIGURE:
		if (!fr_dhcpv6_option_find(options, end, FR_SERVER_ID)) goto fail_sid;

		option = fr_dhcpv6_option_find(options, end, FR_CLIENT_ID);
		if (!option) goto fail_cid;

		/*
		 *	The DUID MUST exist.
		 */
		if (!packet_ctx->duid) goto fail_duid;
		if (!duid_match(option, packet_ctx)) goto fail_match;

		option = fr_dhcpv6_option_find(options, end, FR_RECONF_MSG);
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

	case FR_DHCPV6_RELAY_REPLY:
		if (packet_len < 2 + 32) {
			fr_strerror_printf("Relay-Reply message is too small");
			return false;
		}

		options += (2 + 32 - 4); /* we assumed it was a normal packet above  */
		option = fr_dhcpv6_option_find(options, end, FR_RELAY_MESSAGE);
		if (!option) {
			fr_strerror_printf("Packet does not contain a Relay-Message option");
			return false;
		}
		return verify_to_client(option + 4, get_option_len(option), packet_ctx);

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
		if (!fr_dhcpv6_option_find(options, end, FR_CLIENT_ID)) {
		fail_cid:
			fr_strerror_printf("Packet does not contain a Client-Id option");
			return false;
		}

		if (!fr_dhcpv6_option_find(options, end, FR_SERVER_ID)) {
		fail_sid:
			fr_strerror_printf("Packet does not contain a Server-Id option");
			return false;
		}
		break;

	case FR_PACKET_TYPE_VALUE_REQUEST:
	case FR_PACKET_TYPE_VALUE_RENEW:
	case FR_PACKET_TYPE_VALUE_DECLINE:
	case FR_PACKET_TYPE_VALUE_RELEASE:
		if (!fr_dhcpv6_option_find(options, end, FR_CLIENT_ID)) goto fail_cid;

		option = fr_dhcpv6_option_find(options, end, FR_SERVER_ID);
		if (!option) goto fail_sid;

		if (!duid_match(option, packet_ctx)) {
		fail_match:
			fr_strerror_printf("DUID in packet does not match our DUID");
			return false;
		}
		break;

	case FR_PACKET_TYPE_VALUE_INFORMATION_REQUEST:
		option = fr_dhcpv6_option_find(options, end, FR_SERVER_ID);
		if (!option) goto fail_sid;

		if (!duid_match(option, packet_ctx)) goto fail_match;

		/*
		 *	IA options are forbidden.
		 */
		if (fr_dhcpv6_option_find(options, end, FR_IA_NA)) {
			fr_strerror_printf("Packet contains an IA-NA option");
			return false;
		}
		if (fr_dhcpv6_option_find(options, end, FR_IA_TA)) {
			fr_strerror_printf("Packet contains an IA-TA option");
			return false;
		}
		if (fr_dhcpv6_option_find(options, end, FR_IA_ADDR)) {
			fr_strerror_printf("Packet contains an IA-Addr option");
			return false;
		}
		break;

	case FR_DHCPV6_RELAY_FORWARD:
		if (packet_len < 2 + 32) {
			fr_strerror_printf("Relay-Forward message is too small");
			return false;
		}

		options += (2 + 32 - 4); /* we assumed it was a normal packet above  */
		option = fr_dhcpv6_option_find(options, end, FR_RELAY_MESSAGE);
		if (!option) {
			fr_strerror_printf("Packet does not contain a Relay-Message option");
			return false;
		}

		return verify_from_client(option + 4, get_option_len(option), packet_ctx);

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
 *
 *	fr_dhcpv6_ok() SHOULD be called before calling this function.
 */
bool fr_dhcpv6_verify(uint8_t const *packet, size_t packet_len, fr_dhcpv6_decode_ctx_t const *packet_ctx,
		      bool from_server)
{
	/*
	 *	We support up to relaying.
	 */
	if ((packet[0] == 0) || (packet[0] > FR_PACKET_TYPE_VALUE_RELAY_REPLY)) return false;

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
ssize_t	fr_dhcpv6_decode(TALLOC_CTX *ctx, uint8_t const *packet, size_t packet_len, fr_cursor_t *cursor)
{
	ssize_t			slen;
	uint8_t const		*p, *end;
	fr_dhcpv6_decode_ctx_t	packet_ctx;
	VALUE_PAIR		*vp;

	/*
	 *	Get the packet type.
	 */
	vp = fr_pair_afrom_da(ctx, attr_packet_type);
	if (!vp) return -1;

	vp->vp_uint32 = packet[0];
	vp->type = VT_DATA;
	fr_cursor_append(cursor, vp);

	if ((packet[0] == FR_DHCPV6_RELAY_FORWARD) ||
	    (packet[0] == FR_DHCPV6_RELAY_REPLY)) {
		/*
		 *	Just for sanity check.
		 */
		if (packet_len < 2 + 32) {
			return -1;
		}

		/*
		 *	Decode the header fields.
		 */
		vp = fr_pair_afrom_da(ctx, attr_hop_count);
		if (!vp) goto fail;
		if (fr_value_box_from_network(vp, &vp->data, vp->da->type, NULL, packet + 1, 1, true) < 0) {
			goto fail;
		}
		fr_cursor_append(cursor, vp);

		vp = fr_pair_afrom_da(ctx, attr_relay_link_address);
		if (!vp) goto fail;
		if (fr_value_box_from_network(vp, &vp->data, vp->da->type, NULL, packet + 2, 16, true) < 0) {
			goto fail;
		}
		fr_cursor_append(cursor, vp);

		vp = fr_pair_afrom_da(ctx, attr_relay_peer_address);
		if (!vp) goto fail;
		if (fr_value_box_from_network(vp, &vp->data, vp->da->type, NULL, packet + 2 + 16, 16, true) < 0) {
			goto fail;
		}

		fr_cursor_append(cursor, vp);

		p = packet + 2 + 32;
		goto decode_options;
	}

	/*
	 *	And the transaction ID.
	 */
	vp = fr_pair_afrom_da(ctx, attr_transaction_id);
	if (!vp) {
	fail:
		fr_cursor_head(cursor);
		fr_cursor_free_list(cursor);
		return -1;
	}

	/*
	 *	Copy 3 octets over.
	 */
	(void) fr_pair_value_memdup(vp, packet + 1, 3, false);

	vp->type = VT_DATA;
	fr_cursor_append(cursor, vp);


	p = packet + 4;

decode_options:
	end = packet + packet_len;
	packet_ctx.tmp_ctx = talloc_init_const("tmp");

	/*
	 *	The caller MUST have called fr_dhcpv6_ok() first.  If
	 *	he doesn't, all hell breaks loose.
	 */
	while (p < end) {
		slen = fr_dhcpv6_decode_option(ctx, cursor, dict_dhcpv6, p, (end - p), &packet_ctx);
		if (slen < 0) {
			fr_cursor_head(cursor);
			fr_cursor_free_list(cursor);
			talloc_free(packet_ctx.tmp_ctx);
			return slen;
		}

		/*
		 *	If slen is larger than the room in the packet,
		 *	all kinds of bad things happen.
		 */
		 if (!fr_cond_assert(slen <= (end - p))) {
			 fr_cursor_head(cursor);
			 fr_cursor_free_list(cursor);
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

/** DHCPV6-specific iterator
 *
 */
void *fr_dhcpv6_next_encodable(void **prev, void *to_eval, void *uctx)
{
	VALUE_PAIR	*c, *p;
	fr_dict_t	*dict = talloc_get_type_abort(uctx, fr_dict_t);

	if (!to_eval) return NULL;

	for (p = *prev, c = to_eval; c; p = c, c = c->next) {
		VP_VERIFY(c);
		if (c->da->dict != dict || c->da->flags.internal) continue;
		if (c->da->type == FR_TYPE_BOOL && !c->vp_bool) continue;

		break;
	}

	*prev = p;

	return c;
}



/** Encode a DHCPv6 packet
 *
 */
ssize_t	fr_dhcpv6_encode(uint8_t *packet, size_t packet_len, uint8_t const *original, size_t length,
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
		vp = fr_pair_find_by_da(vps, attr_packet_type);
		if (vp) msg_type = vp->vp_uint32;
	}

	if ((msg_type <= 0) || (msg_type > 255)) {
		fr_strerror_printf("Invalid message type %d", msg_type);
		return -1;
	}

	packet[0] = msg_type;

	if (msg_type == FR_DHCPV6_RELAY_REPLY) {
		if (packet_len < 2 + 32) return -1;
		if (!original) return -1;

		memcpy(packet + 1, original + 1, 1 + 32);

		p = packet + 2 + 32;
		goto encode_options;
	}

	if (msg_type == FR_DHCPV6_RELAY_FORWARD) {
		if (packet_len < 2 + 32) return -1;

		vp = fr_pair_find_by_da(vps, attr_hop_count);
		if (vp) (void) fr_value_box_to_network(NULL, packet + 1, packet_len - 1, &vp->data);

		vp = fr_pair_find_by_da(vps, attr_relay_link_address);
		if (vp) (void) fr_value_box_to_network(NULL, packet + 2, packet_len - 2, &vp->data);

		vp = fr_pair_find_by_da(vps, attr_relay_peer_address);
		if (vp) (void) fr_value_box_to_network(NULL, packet + 2 + 16, packet_len - 2 - 16, &vp->data);

		p = packet + 2 + 32;
		goto encode_options;
	}

	/*
	 *	Copy over original transaction ID if we have it.
	 */
	if (original) {
		memcpy(packet + 1, original + 1, 3);
	} else {
		/*
		 *	We can set an XID, or we can pick a random one.
		 */
		vp = fr_pair_find_by_da(vps, attr_transaction_id);
		if (vp && (vp->vp_length >= 3)) {
			memcpy(packet + 1, vp->vp_octets, 3);
		} else {
			uint32_t id = fr_rand();

			packet[1] = (id >> 16) & 0xff;
			packet[2] = (id >> 8) & 0xff;
			packet[3] = id & 0xff;
		}
	}

	p = packet + 4;

encode_options:
	packet_ctx.root = root;
	packet_ctx.original = original;
	packet_ctx.original_length = length;

	end = packet + packet_len;

	fr_cursor_talloc_iter_init(&cursor, &vps, fr_dhcpv6_next_encodable, dict_dhcpv6, VALUE_PAIR);
	while ((p < end) && (fr_cursor_current(&cursor) != NULL)) {
		slen = fr_dhcpv6_encode_option(p, end - p, &cursor, &packet_ctx);
		switch (slen) {
		case PAIR_ENCODE_SKIPPED:
			continue;

		case PAIR_ENCODE_FATAL_ERROR:
			return slen;

		default:
			break;

		}

		if (slen < 0) return slen - (p - packet);

		p += slen;
	}

	return p - packet;
}

/**  Bootstrap a reply from the request
 *
 *  We should arguably operate on VPs instead of raw packets.
 *  However, that would prevent us from properly copying structures.
 *
 * @param[in] ctx	the context to use for allocations
 * @param[out] reply	the reply attributes to create
 * @param[in] packet	the input packet to check
 * @param[in] packet_len the length of the input packet.
 */
int fr_dhcpv6_reply_initialize(TALLOC_CTX *ctx, VALUE_PAIR **reply, uint8_t const *packet, size_t packet_len)
{
	uint8_t const		*option, *options, *end;
	ssize_t			slen;
	fr_cursor_t		cursor;
	VALUE_PAIR		*vp;
	fr_dhcpv6_decode_ctx_t	packet_ctx;

	end = packet + packet_len;
	fr_cursor_init(&cursor, reply);
	packet_ctx.tmp_ctx = talloc_init_const("tmp");

	/*
	 *	For normal packets, echo the Client-Id back in the
	 *	reply.  Note that the Client-Id attribute doesn't
	 *	always need to exist
	 */
	if (packet[0] != FR_DHCPV6_RELAY_FORWARD) {
		options = packet + 4;

		option = fr_dhcpv6_option_find(options, end, FR_CLIENT_ID);
		if (!option) return 0;

		slen = fr_dhcpv6_decode_option(ctx, &cursor, dict_dhcpv6, option, end - option, &packet_ctx);
		talloc_free(packet_ctx.tmp_ctx);
		return slen;
	}

	/*
	 *	Relay-Forward packets MAY include an Interface-ID.  In
	 *	which case it MUST be echoed in the reply/
	 */
	options = packet + 2 + 32;
	option = fr_dhcpv6_option_find(options, end, FR_INTERFACE_ID);
	if (option) {
		slen = fr_dhcpv6_decode_option(ctx, &cursor, dict_dhcpv6, option, end - option, &packet_ctx);
		if (slen <= 0) {
			talloc_free(packet_ctx.tmp_ctx);
			return slen;
		}
	}

	/*
	 *	The reply to a Relay-Forward is a Relay-Reply.
	 *
	 *	Since we call ourselves recursively, we have to add
	 *	this to the reply now.  We can't rely on
	 *	proto_dhcpv6_process() to do it for us.
	 */
	vp = fr_pair_afrom_da(ctx, attr_packet_type);
	if (!vp) goto fail;

	vp->vp_uint32 = FR_DHCPV6_RELAY_REPLY;
	fr_cursor_append(&cursor, vp);	

	/*
	 *	A Relay-Forward message MUST contain a Relay-Message
	 */
	option = fr_dhcpv6_option_find(options, end, FR_RELAY_MESSAGE);
	if (!option) goto fail;
	
	vp = fr_pair_afrom_da(ctx, attr_relay_message);
	if (!vp) goto fail;

	fr_cursor_append(&cursor, vp);	

	/*
	 *	Recurse to create the appropriate nested VPs.
	 */
	if (fr_dhcpv6_reply_initialize(vp, &vp->vp_group, option + 4, get_option_len(option)) < 0) {
	fail:
		talloc_free(packet_ctx.tmp_ctx);
		return -1;
	}

	talloc_free(packet_ctx.tmp_ctx);
	return 0;
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

		if (fr_dict_attr_enum_add_name(fr_dict_attr_unconst(attr_option_request),
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
	{ L("dns_label"),			FLAG_ENCODE_DNS_LABEL },
	{ L("partial_dns_label"), 		FLAG_ENCODE_PARTIAL_DNS_LABEL },
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

extern fr_dict_protocol_t libfreeradius_dhcpv6_dict_protocol;
fr_dict_protocol_t libfreeradius_dhcpv6_dict_protocol = {
	.name = "dhcpv6",
	.default_type_size = 2,
	.default_type_length = 2,
	.subtype_table = subtype_table,
	.subtype_table_len = NUM_ELEMENTS(subtype_table),
	.attr_valid = attr_valid,
};
