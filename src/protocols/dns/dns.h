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
 * @file protocols/dns/dns.h
 * @brief Implementation of the DNS protocol.
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(dhcp_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/packet.h>
#include <freeradius-devel/util/dns.h>

#define DNS_MAX_ATTRIBUTES	255

typedef struct {
	uint16_t	id;
#ifdef WORDS_BIGENDIAN
	unsigned int	query			: 1;
	unsigned int	opcode			: 4;
	unsigned int	authoritative		: 1;
	unsigned int	truncated		: 1;
	unsigned int	recursion_desired	: 1;
#else
	unsigned int	recursion_desired	: 1;
	unsigned int	truncated		: 1;
	unsigned int	authoritative		: 1;
	unsigned int	opcode			: 4;
	unsigned int	query			: 1;
#endif

#ifdef WORDS_BIGENDIAN
	unsigned int	recursion_available	: 1;
	unsigned int	reserved		: 1;
	unsigned int	authentic_data		: 1;
	unsigned int	checking_disabled	: 1;
	unsigned int	rcode			: 4;
#else
	unsigned int	rcode			: 4;
	unsigned int	checking_disabled	: 1;
	unsigned int	authentic_data		: 1;
	unsigned int	reserved		: 1;
	unsigned int	recursion_available	: 1;
#endif

	uint16_t	qdcount;
	uint16_t	ancount;
	uint16_t	nscount;
	uint16_t	arcount;
} CC_HINT(__packed__) fr_dns_packet_t;

/** subtype values for DHCPv4 and DHCPv6
 *
 */
enum {
	FLAG_ENCODE_NONE = 0,				//!< no particular encoding for DNS strings
	FLAG_ENCODE_DNS_LABEL,				//!< encode as DNS label
};

typedef struct {
	TALLOC_CTX		*tmp_ctx;		//!< for temporary things cleaned up during decoding
	uint8_t const		*packet;		//!< DNS labels can point anywhere in the packet :(
	size_t			packet_len;
	fr_dns_labels_t		*lb;
} fr_dns_ctx_t;

int		fr_dns_global_init(void);
void		fr_dns_global_free(void);

typedef enum {
	FR_DNS_QUERY = 0,
	FR_DNS_IQUERY = 1,
	FR_DNS_STATUS = 2,
	FR_DNS_NOTIFY = 4,
	FR_DNS_UPDATE = 5,
	FR_DNS_STATEFUL_OP = 6,
	FR_DNS_CODE_MAX = 7,

	FR_DNS_QUERY_RESPONSE = 16,
	FR_DNS_IQUERY_RESPONSE = 17,
	FR_DNS_STATUS_RESPONSE = 18,
	FR_DNS_NOTIFY_RESPONSE = 20,
	FR_DNS_UPDATE_RESPONSE = 21,
	FR_DNS_STATEFUL_OP_RESPONSE = 22,

	FR_DNS_DO_NOT_RESPOND = 256,
} fr_dns_packet_code_t;

typedef enum {
	DECODE_FAIL_NONE = 0,
	DECODE_FAIL_MIN_LENGTH_PACKET,
	DECODE_FAIL_MAX_LENGTH_PACKET,
	DECODE_FAIL_UNEXPECTED,
	DECODE_FAIL_NO_QUESTIONS,
	DECODE_FAIL_ANSWERS_IN_QUESTION,
	DECODE_FAIL_NS_IN_QUESTION,
	DECODE_FAIL_INVALID_RR_LABEL,
	DECODE_FAIL_MISSING_RR_HEADER,
	DECODE_FAIL_MISSING_RR_LEN,
	DECODE_FAIL_ZERO_RR_LEN,
	DECODE_FAIL_RR_OVERFLOWS_PACKET,
	DECODE_FAIL_TOO_MANY_RRS,
	DECODE_FAIL_TOO_FEW_RRS,
	DECODE_FAIL_POINTER_TO_NON_LABEL,
	DECODE_FAIL_POINTER_OVERFLOWS_PACKET,
	DECODE_FAIL_POINTER_TO_HEADER,
	DECODE_FAIL_POINTER_LOOPS,
	DECODE_FAIL_INVALID_POINTER,
	DECODE_FAIL_LABEL_OVERFLOWS_PACKET,
	DECODE_FAIL_LABEL_TOO_LONG,
	DECODE_FAIL_MISSING_QD_HEADER,
	DECODE_FAIL_MISSING_TLV_HEADER,
	DECODE_FAIL_TLV_OVERFLOWS_RR,
	DECODE_FAIL_MAX
} fr_dns_decode_fail_t;

#define FR_DNS_PACKET_CODE_VALID(_code) (((_code) < FR_DNS_CODE_MAX) || (((_code & 0x10) != 0) && ((_code & ~0x10) < FR_DNS_CODE_MAX)))

#define DNS_HDR_LEN (12)

extern char const *fr_dns_packet_codes[FR_DNS_CODE_MAX];

bool fr_dns_packet_ok(uint8_t const *packet, size_t packet_len, bool query, fr_dns_decode_fail_t *reason);

fr_dns_labels_t *fr_dns_labels_get(uint8_t const *packet, size_t packet_len, bool init_mark);

ssize_t	fr_dns_decode(TALLOC_CTX *ctx, fr_pair_list_t *out,
		      uint8_t const *packet, size_t packet_len, fr_dns_ctx_t *packet_ctx);

ssize_t fr_dns_encode(fr_dbuff_t *dbuff, fr_pair_list_t *vps, fr_dns_ctx_t *encode_ctx);

#ifdef __cplusplus
}
#endif
