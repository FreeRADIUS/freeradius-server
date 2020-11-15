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
#include <freeradius-devel/protocol/dhcpv6/rfc5007.h>
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
fr_dict_attr_t const *attr_hop_count;
fr_dict_attr_t const *attr_relay_link_address;
fr_dict_attr_t const *attr_relay_peer_address;
fr_dict_attr_t const *attr_relay_message;
fr_dict_attr_t const *attr_option_request;

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
	 [0]						= "invalid",
	 [FR_PACKET_TYPE_VALUE_SOLICIT]			= "Solicit",
	 [FR_PACKET_TYPE_VALUE_ADVERTISE]		= "Advertise",
	 [FR_PACKET_TYPE_VALUE_REQUEST]			= "Request",
	 [FR_PACKET_TYPE_VALUE_CONFIRM]			= "Confirm",
	 [FR_PACKET_TYPE_VALUE_RENEW]			= "Renew",
	 [FR_PACKET_TYPE_VALUE_REBIND]			= "Rebind",
	 [FR_PACKET_TYPE_VALUE_REPLY]			= "Reply",
	 [FR_PACKET_TYPE_VALUE_RELEASE]			= "Release",
	 [FR_PACKET_TYPE_VALUE_DECLINE]			= "Decline",
	 [FR_PACKET_TYPE_VALUE_RECONFIGURE]		= "Reconfigure",
	 [FR_PACKET_TYPE_VALUE_INFORMATION_REQUEST]	= "Information-Request",
	 [FR_PACKET_TYPE_VALUE_RELAY_FORWARD]		= "Relay-Forward",
	 [FR_PACKET_TYPE_VALUE_RELAY_REPLY]		= "Relay-Reply",
	 [FR_PACKET_TYPE_VALUE_LEASE_QUERY]		= "Lease-Query",
	 [FR_PACKET_TYPE_VALUE_LEASE_QUERY_REPLY]	= "Lease-Query-Reply",
	 [FR_PACKET_TYPE_VALUE_LEASE_QUERY_DONE]	= "Lease-Query-Done",
	 [FR_PACKET_TYPE_VALUE_LEASE_QUERY_DATA]	= "Lease-Query-Data",
	 [FR_PACKET_TYPE_VALUE_RECONFIGURE_REQUEST]	= "Reconfigure-Request",
	 [FR_PACKET_TYPE_VALUE_RECONFIGURE_REPLY]	= "Reconfigure-Reply",
	 [FR_PACKET_TYPE_VALUE_DHCPV4_QUERY]		= "DHCPv4-Query",
	 [FR_PACKET_TYPE_VALUE_DHCPV4_RESPONSE]		= "DHCPv4-Response",
	 [FR_PACKET_TYPE_VALUE_ACTIVE_LEASE_QUERY]	= "Active-Lease-Query",
	 [FR_PACKET_TYPE_VALUE_START_TLS]		= "Start-TLS",
	 [FR_PACKET_TYPE_VALUE_BIND_UPDATE]		= "Bind-Update",
	 [FR_PACKET_TYPE_VALUE_BIND_REPLY]		= "Bind-Reply",
	 [FR_PACKET_TYPE_VALUE_POOL_REQUEST]		= "Pool-Request",
	 [FR_PACKET_TYPE_VALUE_POOL_RESPONSE]		= "Pool-Response",
	 [FR_PACKET_TYPE_VALUE_UPDATE_REQUEST]		= "Update-Request",
	 [FR_PACKET_TYPE_VALUE_UPDATE_REQUEST_ALL]	= "Update-Request-All",
	 [FR_PACKET_TYPE_VALUE_UPDATE_DONE]		= "Update-Done",
	 [FR_PACKET_TYPE_VALUE_CONNECT]			= "Connect",
	 [FR_PACKET_TYPE_VALUE_CONNECT_REPLY]		= "Connect-Reply",
	 [FR_PACKET_TYPE_VALUE_DISCONNECT]		= "Disconnect",
	 [FR_PACKET_TYPE_VALUE_STATE]			= "State",
	 [FR_PACKET_TYPE_VALUE_CONTACT]			= "Contact"
};

static fr_table_num_ordered_t const subtype_table[] = {
	{ L("dns_label"),			FLAG_ENCODE_DNS_LABEL },
	{ L("partial_dns_label"), 		FLAG_ENCODE_PARTIAL_DNS_LABEL }
};

/** Return the on-the-wire length of an attribute value
 *
 * @param[in] vp to return the length of.
 * @return the length of the attribute.
 */
size_t fr_dhcpv6_option_len(fr_pair_t const *vp)
{
	switch (vp->vp_type) {
	case FR_TYPE_VARIABLE_SIZE:
		if (vp->da->flags.length) return vp->da->flags.length;	/* Variable type with fixed length */
		return vp->vp_length;

	case FR_TYPE_DATE:
	case FR_TYPE_TIME_DELTA:
		if (vp->data.enumv->flags.length) return vp->data.enumv->flags.length;
		return sizeof(uint32_t);

	case FR_TYPE_STRUCTURAL:
		fr_assert_fail(NULL);
		return 0;

	default:
		return fr_dhcpv6_attr_sizes[vp->vp_type][0];
	}
}

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

		if ((size_t)(end - p) < DHCPV6_OPT_HDR_LEN) {
			*error = "Not enough room for option header";
			return -(p - packet);
		}

		len = DHCPV6_GET_OPTION_LEN(p);
		if ((size_t)(end - p) < (DHCPV6_OPT_HDR_LEN + len)) {
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
			if (child <= 0) return -((p + 4) - packet) + child;

			attributes += child;
		}

		p += DHCPV6_OPT_HDR_LEN + len;
	}

	return attributes;
}

static ssize_t fr_dhcpv6_ok_internal(uint8_t const *packet, uint8_t const *end, size_t max_attributes, int depth,
				     char const **error)
{
	uint8_t const	*p;
	ssize_t		attributes;
	bool		allow_relay;
	size_t		packet_len = end - packet;

	if (depth > DHCPV6_MAX_RELAY_NESTING) {
		*error = "Too many layers forwarded packets";
		return 0;
	}

	switch (packet[0]) {
	case FR_DHCPV6_RELAY_FORWARD:
	case FR_DHCPV6_RELAY_REPLY:
		if (packet_len < DHCPV6_RELAY_HDR_LEN) {
			*error = "Packet is too small for relay header";
			return 0;
		}

		p = packet + DHCPV6_RELAY_HDR_LEN;
		allow_relay = true;
		break;

	default:
		/*
		 *	8 bit code + 24 bits of transaction ID
		 */
		if (packet_len < DHCPV6_HDR_LEN) {
			*error = "Packet is too small for DHCPv6 header";
			return 0;
		}

		p = packet + DHCPV6_HDR_LEN;
		allow_relay = false;
		break;
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

		if ((size_t)(end - p) < DHCPV6_OPT_HDR_LEN) return NULL;

		found = DHCPV6_GET_OPTION_NUM(p);
		len = DHCPV6_GET_OPTION_LEN(p);

		if ((p + DHCPV6_OPT_HDR_LEN + len) > end) return NULL;

		if (found == option) return p;

		p += DHCPV6_OPT_HDR_LEN + len;
	}

	return NULL;
}

static bool duid_match(uint8_t const *option, fr_dhcpv6_decode_ctx_t const *packet_ctx)
{
	uint16_t len;

	len = DHCPV6_GET_OPTION_LEN(option);
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
		transaction_id = fr_net_to_uint24(&packet[1]);
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
		transaction_id = fr_net_to_uint24(&packet[1]);
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
		if (packet_len < DHCPV6_RELAY_HDR_LEN) {
			fr_strerror_printf("Relay-Reply message is too small");
			return false;
		}

		options += (DHCPV6_RELAY_HDR_LEN - 4); /* we assumed it was a normal packet above  */
		option = fr_dhcpv6_option_find(options, end, FR_RELAY_MESSAGE);
		if (!option) {
			fr_strerror_printf("Packet does not contain a Relay-Message option");
			return false;
		}
		return verify_to_client(option + 4, DHCPV6_GET_OPTION_LEN(option), packet_ctx);

	case FR_DHCPV6_LEASE_QUERY_REPLY:
		transaction_id = fr_net_to_uint24(&packet[1]);
		if (transaction_id != packet_ctx->transaction_id) goto fail_tid;

		if (!fr_dhcpv6_option_find(options, end, FR_SERVER_ID)) goto fail_sid;

		option = fr_dhcpv6_option_find(options, end, FR_CLIENT_ID);
		if (!option) goto fail_cid;

		/*
		 *	The DUID MUST exist.
		 */
		if (!packet_ctx->duid) goto fail_duid;
		if (!duid_match(option, packet_ctx)) goto fail_match;
		break;

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
		if (packet_len < DHCPV6_RELAY_HDR_LEN) {
			fr_strerror_printf("Relay-Forward message is too small");
			return false;
		}

		options += (DHCPV6_RELAY_HDR_LEN - 4); /* we assumed it was a normal packet above  */
		option = fr_dhcpv6_option_find(options, end, FR_RELAY_MESSAGE);
		if (!option) {
			fr_strerror_printf("Packet does not contain a Relay-Message option");
			return false;
		}

		return verify_from_client(option + 4, DHCPV6_GET_OPTION_LEN(option), packet_ctx);

	case FR_PACKET_TYPE_VALUE_LEASE_QUERY:
		if (!fr_dhcpv6_option_find(options, end, FR_CLIENT_ID)) goto fail_cid;

		/*
		 *	Server-ID is a SHOULD, but if it exists, it
		 *	MUST match.
		 */
		option = fr_dhcpv6_option_find(options, end, FR_SERVER_ID);
		if (option && !duid_match(option, packet_ctx)) goto fail_match;

		option = fr_dhcpv6_option_find(options, end, FR_LEASE_QUERY);
		if (!option) {
			fr_strerror_printf("Packet does not contain a Lease-Query option");
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
	fr_pair_t		*vp;

	/*
	 *	Get the packet type.
	 */
	vp = fr_pair_afrom_da(ctx, attr_packet_type);
	if (!vp) return -1;

	vp->vp_uint32 = packet[0];
	vp->type = VT_DATA;
	fr_cursor_append(cursor, vp);

	switch (packet[0]) {
	case FR_DHCPV6_RELAY_FORWARD:
	case FR_DHCPV6_RELAY_REPLY:
		/*
		 *	Just for sanity check.
		 */
		if (packet_len < DHCPV6_RELAY_HDR_LEN) return -1;

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

		p = packet + DHCPV6_RELAY_HDR_LEN;
		goto decode_options;

	default:
		break;
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
	fr_pair_t	*c, *p;
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
ssize_t	fr_dhcpv6_encode(fr_dbuff_t *dbuff, uint8_t const *original, size_t length, int msg_type, fr_pair_t *vps)
{
	fr_dbuff_t		frame_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_pair_t		*vp;
	fr_dict_attr_t const	*root;
	ssize_t			slen;
	fr_cursor_t		cursor;
	fr_dhcpv6_encode_ctx_t	packet_ctx;

	root = fr_dict_root(dict_dhcpv6);

	if (!msg_type) {
		vp = fr_pair_find_by_da(&vps, attr_packet_type);
		if (vp) msg_type = vp->vp_uint32;
	}

	if ((msg_type <= 0) || (msg_type > UINT8_MAX)) {
		fr_strerror_printf("Invalid message type %d", msg_type);
		return -1;
	}

	FR_DBUFF_IN_RETURN(&frame_dbuff, (uint8_t)msg_type);

	switch (msg_type) {
	case FR_DHCPV6_RELAY_REPLY:
	case FR_DHCPV6_RELAY_FORWARD:
		vp = fr_pair_find_by_da(&vps, attr_hop_count);
		if (likely(vp != NULL)) {
			FR_VALUE_BOX_TO_NETWORK_RETURN(&frame_dbuff, &vp->data);
		} else {
			FR_DBUFF_MEMSET_RETURN(&frame_dbuff, 0, DHCPV6_HOP_COUNT_LEN);
		}

		vp = fr_pair_find_by_da(&vps, attr_relay_link_address);
		if (likely(vp != NULL)) {
			FR_VALUE_BOX_TO_NETWORK_RETURN(&frame_dbuff, &vp->data);
		} else {
			FR_DBUFF_MEMSET_RETURN(&frame_dbuff, 0, DHCPV6_LINK_ADDRESS_LEN);
		}

		vp = fr_pair_find_by_da(&vps, attr_relay_peer_address);
		if (likely(vp != NULL)) {
			FR_VALUE_BOX_TO_NETWORK_RETURN(&frame_dbuff, &vp->data);
		} else {
			FR_DBUFF_MEMSET_RETURN(&frame_dbuff, 0, DHCPV6_PEER_ADDRESS_LEN);
		}
		break;

	default:
		/*
		 *	We can set an XID, or we can pick a random one.
		 */
		vp = fr_pair_find_by_da(&vps, attr_transaction_id);
		if (vp && (vp->vp_length >= DHCPV6_TRANSACTION_ID_LEN)) {
			FR_DBUFF_IN_MEMCPY_RETURN(&frame_dbuff, vp->vp_octets, DHCPV6_TRANSACTION_ID_LEN);
		} else {
			uint8_t id[DHCPV6_TRANSACTION_ID_LEN];
			fr_net_from_uint24(id, fr_rand());
			FR_DBUFF_IN_MEMCPY_RETURN(&frame_dbuff, id, sizeof(id)); /* Need 24 bits of the 32bit integer */
		}
		break;
	}

	/*
	 * Encode options.
	 */
	packet_ctx.root = root;
	packet_ctx.original = original;
	packet_ctx.original_length = length;

	fr_cursor_talloc_iter_init(&cursor, &vps, fr_dhcpv6_next_encodable, dict_dhcpv6, fr_pair_t);
	while ((fr_dbuff_extend(&frame_dbuff) > 0) && (fr_cursor_current(&cursor) != NULL)) {
		slen = fr_dhcpv6_encode_option(&frame_dbuff, &cursor, &packet_ctx);
		switch (slen) {
		case PAIR_ENCODE_SKIPPED:
			continue;

		case PAIR_ENCODE_FATAL_ERROR:
			return slen;

		default:
			break;
		}

		if (slen < 0) return slen - fr_dbuff_used(&frame_dbuff);
	}

	return fr_dbuff_set(dbuff, &frame_dbuff);
}


static char const tabs[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

static void print_hex_data(FILE *fp, uint8_t const *ptr, int attrlen, int depth)
{
	int i;

	for (i = 0; i < attrlen; i++) {
		if ((i > 0) && ((i & 0x0f) == 0x00))
			fprintf(fp, "%.*s", depth, tabs);
		fprintf(fp, "%02x ", ptr[i]);
		if ((i & 0x0f) == 0x0f) fprintf(fp, "\n");
	}
	if ((i & 0x0f) != 0) fprintf(fp, "\n");
}

static void dhcpv6_print_hex(FILE *fp, uint8_t const *packet, size_t packet_len, int depth)
{
	uint8_t const *option, *end = packet + packet_len;

	if (packet_len < 4) {
		fprintf(fp, "%.*s", depth, tabs);
		fprintf(fp, "???:\t");
		print_hex_data(fp, packet, packet_len, depth + 1);
		return;
	}

	fprintf(fp, "%.*s", depth, tabs);
	if ((packet[0] > 0) && (packet[0] < FR_DHCPV6_MAX_CODE)) {
		fprintf(fp, "packet: %s\n", fr_dhcpv6_packet_types[packet[0]]);
	} else {
		fprintf(fp, "packet: %02x\n", packet[0]);
	}

	if ((packet[0] == FR_PACKET_TYPE_VALUE_RELAY_FORWARD) ||
	    (packet[0] == FR_PACKET_TYPE_VALUE_RELAY_REPLY)) {
		if (packet_len < 34) {
			fprintf(fp, "%.*s", depth, tabs);
			fprintf(fp, "???:\t");
			print_hex_data(fp, packet + 1, packet_len - 1, depth + 1);
			return;
		}

		fprintf(fp, "%.*s", depth, tabs);
		fprintf(fp, "hops: %02x\n", packet[1]);
		fprintf(fp, "%.*s", depth, tabs);
		fprintf(fp, "relay link address: ");
		print_hex_data(fp, packet + 2, 16, depth + 1);

		fprintf(fp, "%.*s", depth, tabs);
		fprintf(fp, "peer address:       ");
		print_hex_data(fp, packet + 18, 16, depth + 1);
		option = packet + 34;
	} else {
		fprintf(fp, "%.*s", depth, tabs);
		fprintf(fp, "transaction id: ");
		print_hex_data(fp, packet + 1, 3, depth + 1);
		option = packet + 4;
	}

	fprintf(fp, "%.*s", depth, tabs);
	fprintf(fp, "options\n");
	while (option < end) {
		uint16_t length;

		if ((end - option) < 4) {
			fprintf(fp, "%.*s", depth + 1, tabs);
			fprintf(fp, "???:\t");
			print_hex_data(fp, option, end - option, depth + 2);
			break;
		}

		length = fr_net_to_uint16(option + 2);
		fprintf(fp, "%.*s", depth + 1, tabs);
		fprintf(fp, "%04x %04x\t", fr_net_to_uint16(option), length);

		if ((option + 4 + length) > end) {
			print_hex_data(fp, option + 4, end - (option + 4), depth + 3);
			break;
		}

		print_hex_data(fp, option + 4, length, depth + 3);
		if ((option[0] == 0) && (option[1] == attr_relay_message->attr)) {
			dhcpv6_print_hex(fp, option + 4, length, depth + 2);
		}

		option += 4 + length;
	}

	fprintf(fp, "\n");
}

/** Print a raw DHCP packet as hex.
 *
 */
void fr_dhcpv6_print_hex(FILE *fp, uint8_t const *packet, size_t packet_len)
{
	dhcpv6_print_hex(fp, packet, packet_len, 0);
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
