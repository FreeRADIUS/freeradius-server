#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file protocols/dhcpv6/dhcpv6.h
 * @brief Implementation of the DHCPv6 protocol.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 NetworkRADIUS SARL (legal@networkradius.com)
 */
RCSIDH(dhcpv6_h, "$Id$")

#include <freeradius-devel/util/dict.h>

#include <freeradius-devel/protocol/dhcpv6/dictionary.h>

extern size_t const fr_dhcpv6_attr_sizes[FR_TYPE_MAX + 1][2];

#define DHCPV6_MSG_TYPE_LEN		1

#define DHCPV6_TRANSACTION_ID_LEN	3

#define DHCPV6_HOP_COUNT_LEN		1
#define DHCPV6_LINK_ADDRESS_LEN		16
#define DHCPV6_PEER_ADDRESS_LEN		16

#define DHCPV6_HDR_LEN			(DHCPV6_MSG_TYPE_LEN + DHCPV6_TRANSACTION_ID_LEN)
#define DHCPV6_RELAY_HDR_LEN		(DHCPV6_MSG_TYPE_LEN + DHCPV6_HOP_COUNT_LEN + DHCPV6_LINK_ADDRESS_LEN + DHCPV6_PEER_ADDRESS_LEN)
#define DHCPV6_OPT_HDR_LEN		(sizeof(uint16_t) * 2)

#define DHCPV6_GET_OPTION_NUM(_x)	fr_net_to_uint16(_x)
#define DHCPV6_GET_OPTION_LEN(_x)	fr_net_to_uint16((_x) + 2)

#define DHCPV6_MAX_RELAY_NESTING	10

/*
 *	Defined addresses from RFC 8415 Section 7.1
 */
#define IN6ADDR_ALL_DHCP_RELAY_AGENTS_AND_SERVERS	"FF02::1:2"
#define IN6ADDR_ALL_DHCP_RELAY_AGENTS_AND_SERVERS_INIT   {{{ 0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,1,2}}}
#define IN6ADDR_ALL_DHCP_SERVERS			"FF05::1:3"
#define IN6ADDR_ALL_DHCP_SERVERS_INIT			{{{ 0xff,0x05,0,0,0,0,0,0,0,0,0,0,0,0,1,3}}}

/*
 *	Copied from src/include/protocols/dhcpv6/freeradius.internal.h
 *	and edited.
 */
typedef enum {
	FR_DHCPV6_SOLICIT = 1,
	FR_DHCPV6_ADVERTISE = 2,
	FR_DHCPV6_REQUEST = 3,
	FR_DHCPV6_CONFIRM = 4,
	FR_DHCPV6_RENEW = 5,
	FR_DHCPV6_REBIND = 6,
	FR_DHCPV6_REPLY = 7,
	FR_DHCPV6_RELEASE = 8,
	FR_DHCPV6_DECLINE = 9,
	FR_DHCPV6_RECONFIGURE = 10,
	FR_DHCPV6_INFORMATION_REQUEST = 11,
	FR_DHCPV6_RELAY_FORWARD = 12,
	FR_DHCPV6_RELAY_REPLY = 13,
	FR_DHCPV6_LEASE_QUERY = 14,
	FR_DHCPV6_LEASE_QUERY_REPLY = 15,
	FR_DHCPV6_LEASE_QUERY_DONE = 16,
	FR_DHCPV6_LEASE_QUERY_DATA = 17,
	FR_DHCPV6_RECONFIGURE_REQUEST = 18,
	FR_DHCPV6_RECONFIGURE_REPLY = 19,
	FR_DHCPV6_DHCPV4_QUERY = 20,
	FR_DHCPV6_DHCPV4_RESPONSE = 21,
	FR_DHCPV6_ACTIVE_LEASE_QUERY = 22,
	FR_DHCPV6_START_TLS = 23,
	FR_DHCPV6_BIND_UPDATE = 24,
	FR_DHCPV6_BIND_REPLY = 25,
	FR_DHCPV6_POOL_REQUEST = 26,
	FR_DHCPV6_POOL_RESPONSE = 27,
	FR_DHCPV6_UPDATE_REQUEST = 28,
	FR_DHCPV6_UPDATE_REQUEST_ALL = 29,
	FR_DHCPV6_UPDATE_DONE = 30,
	FR_DHCPV6_CONNECT = 31,
	FR_DHCPV6_CONNECT_REPLY = 32,
	FR_DHCPV6_DISCONNECT = 33,
	FR_DHCPV6_STATE = 34,
	FR_DHCPV6_CONTACT = 35,
	FR_DHCPV6_MAX_CODE = 36,
} fr_dhcpv6_codes_t;

extern char const		*fr_dhcpv6_packet_types[FR_DHCPV6_MAX_CODE];

/** subtype values for DHCPv4 and DHCPv6
 *
 */
enum {
	FLAG_ENCODE_NONE = 0,				//!< no particular encoding for DHCPv6 strings
	FLAG_ENCODE_DNS_LABEL,				//!< encode as DNS label
	FLAG_ENCODE_PARTIAL_DNS_LABEL, 			//!< encode as a partial DNS label
};

typedef struct CC_HINT(__packed__) {
	uint8_t		code;
	uint8_t		transaction_id[3];
} fr_dhcpv6_packet_t;

/*
 *	DHCPv6 defines dates to start from Jan 1, 2000.  Which is
 *	exactly this number of seconds off of the standard Unix time
 *	stamps.
 */
#define DHCPV6_DATE_OFFSET (946684800)

typedef struct {
	fr_dict_attr_t const	*root;			//!< Root attribute of the dictionary.
	uint8_t const		*original;		//!< original packet
	size_t			original_length;	//!< length of the original packet
} fr_dhcpv6_encode_ctx_t;

typedef struct {
	TALLOC_CTX		*tmp_ctx;		//!< for temporary things cleaned up during decoding
	uint32_t		transaction_id;		//!< previous transaction ID
	uint8_t			*duid;			//!< the expected DUID, in wire format
	size_t			duid_len;		//!< length of the expected DUID
} fr_dhcpv6_decode_ctx_t;

/*
 *	base.c
 */
size_t		fr_dhcpv6_option_len(fr_pair_t const *vp);

uint8_t const	*fr_dhcpv6_option_find(uint8_t const *start, uint8_t const *end, unsigned int option);

bool		fr_dhcpv6_ok(uint8_t const *packet, size_t packet_len,
			     uint32_t max_attributes);

bool		fr_dhcpv6_verify(uint8_t const *packet, size_t packet_len, fr_dhcpv6_decode_ctx_t const *packet_ctx,
				 bool from_server);

ssize_t		fr_dhcpv6_encode(fr_dbuff_t *dbuff, uint8_t const *original, size_t length,
				 int msg_type, fr_pair_t *vps);

ssize_t		fr_dhcpv6_decode(TALLOC_CTX *ctx, uint8_t const *packet, size_t packet_len,
				 fr_cursor_t *cursor);

int		fr_dhcpv6_reply_initialize(TALLOC_CTX *ctx, fr_pair_list_t *reply_list, uint8_t const *packet, size_t packet_len);

int		fr_dhcpv6_global_init(void);

void		fr_dhcpv6_global_free(void);

/*
 *	encode.c
 */
ssize_t		fr_dhcpv6_encode_option(fr_dbuff_t *dbuff, fr_cursor_t *cursor, void * encoder_ctx);

/*
 *	decode.c
 */
ssize_t		fr_dhcpv6_decode_option(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
					uint8_t const *data, size_t data_len, void *decoder_ctx);
