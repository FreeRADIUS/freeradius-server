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
 * @file protocols/dns/base.c
 * @brief Functions to send/receive dns packets.
 *
 * @copyright 2008 The FreeRADIUS server project
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include "dns.h"
#include "attrs.h"
#include <freeradius-devel/protocol/dns/rfc1034.h>

static uint32_t instance_count = 0;
static bool	instantiated = false;

typedef struct {
	uint16_t	code;
	uint16_t	length;
} dns_option_t;

fr_dict_t const *dict_dns;

static _Thread_local fr_dns_labels_t	fr_dns_labels;
static _Thread_local fr_dns_block_t	fr_dns_blocks[256];
static _Thread_local uint8_t		fr_dns_marker[65536];

extern fr_dict_autoload_t dns_dict[];
fr_dict_autoload_t dns_dict[] = {
	{ .out = &dict_dns, .proto = "dns" },
	DICT_AUTOLOAD_TERMINATOR
};

fr_dict_attr_t const *attr_dns_packet;
fr_dict_attr_t const *attr_dns_question;
fr_dict_attr_t const *attr_dns_rr;
fr_dict_attr_t const *attr_dns_ns;
fr_dict_attr_t const *attr_dns_ar;

extern fr_dict_attr_autoload_t dns_dict_attr[];
fr_dict_attr_autoload_t dns_dict_attr[] = {
	{ .out = &attr_dns_packet, .name = "Header", .type = FR_TYPE_STRUCT, .dict = &dict_dns },
	{ .out = &attr_dns_question, .name = "Question", .type = FR_TYPE_STRUCT, .dict = &dict_dns },
	{ .out = &attr_dns_rr, .name = "Resource-Record", .type = FR_TYPE_STRUCT, .dict = &dict_dns },
	{ .out = &attr_dns_ns, .name = "Name-Server", .type = FR_TYPE_STRUCT, .dict = &dict_dns },
	{ .out = &attr_dns_ar, .name = "Additional-Record", .type = FR_TYPE_STRUCT, .dict = &dict_dns },
	DICT_AUTOLOAD_TERMINATOR
};

 char const *fr_dns_packet_names[FR_DNS_CODE_MAX] = {
	[FR_DNS_QUERY] = "Query",
	[FR_DNS_INVERSE_QUERY] = "Inverse-Query",
	[FR_DNS_STATUS] = "Status",
	[FR_DNS_NOTIFY] = "Notify",
	[FR_DNS_UPDATE] = "Update",
	[FR_DNS_STATEFUL_OPERATION] = "Stateful-Operation",
};

FR_DICT_ATTR_FLAG_FUNC(fr_dns_attr_flags_t, dns_label)
FR_DICT_ATTR_FLAG_FUNC(fr_dns_attr_flags_t, dns_label_uncompressed)

static fr_dict_flag_parser_t const dns_flags[] = {
	{ L("dns_label"),		{ .func = dict_flag_dns_label } },
	{ L("dns_label_uncompressed"),	{ .func = dict_flag_dns_label_uncompressed } }
};

#define DECODE_FAIL(_reason) if (reason) *reason = FR_DNS_DECODE_FAIL_ ## _reason

static bool fr_dns_tlv_ok(uint8_t const *p, uint8_t const *end, fr_dns_decode_fail_t *reason)
{
	uint16_t len;

	while (p < end) {
		if ((p + 4) > end) {
			DECODE_FAIL(MISSING_TLV_HEADER);
			return false;
		}

		len = fr_nbo_to_uint16(p + 2);
		if ((p + 4 + len) > end) {
			DECODE_FAIL(TLV_OVERFLOWS_RR);
			return false;
		}

		p += 4 + len;
	}

	return true;
}

bool fr_dns_packet_ok(uint8_t const *packet, size_t packet_len, bool query, fr_dns_decode_fail_t *reason)
{
	uint8_t const *p, *end;
	int qdcount, count, expected;
	uint8_t opcode;

	if (packet_len <= DNS_HDR_LEN) {
		DECODE_FAIL(MIN_LENGTH_PACKET);
		return false;
	}

	if (packet_len > 65535) {
		DECODE_FAIL(MAX_LENGTH_PACKET);
		return false;
	}

	/*
	 *	query=0, response=1
	 */
	if (((packet[2] & 0x80) == 0) != query) {
		DECODE_FAIL(UNEXPECTED);
		return false;
	}

	/*
	 *	@todo - the truncation rules mean that the various counts below are wrong, and the caller
	 *	should retry over TCP.  This is really an indication to us, that we need to fully implement
	 *	the truncation checks.
	 */
	if ((packet[2] & 0x02) != 0) {
		DECODE_FAIL(TRUNCATED);
		return false;
	}
	qdcount = fr_nbo_to_uint16(packet + 4);

	opcode = (packet[2] >> 3) & 0x0f;

	/*
	 *	RFC 2136 (DNS update) defines the four "count" fields to have different meanings:
	 *
	 *	ZOCOUNT The number of RRs in the Zone Section.
	 *	PRCOUNT The number of RRs in the Prerequisite Section.
	 *	UPCOUNT The number of RRs in the Update Section.
	 *	ADCOUNT The number of RRs in the Additional Data Section.
	 *
	 *	@todo - we can likely do more validation checks on input packets.
	 */
	if (query && (opcode != FR_OPCODE_VALUE_UPDATE)) {
		/*
		 *	There should be at least one query, and no
		 *	replies in the query.
		 *
		 *	@todo - unless it's an IQUERY, in which case
		 *	there should be no questions, and at least one
		 *	answer.
		 */
		if (!qdcount) {
			DECODE_FAIL(NO_QUESTIONS);
			return false;
		}

		if (fr_nbo_to_uint16(packet + 6) != 0) {
			DECODE_FAIL(ANSWERS_IN_QUESTION);
			return false;
		}

		if (fr_nbo_to_uint16(packet + 8) != 0) {
			DECODE_FAIL(NS_IN_QUESTION);
			return false;
		}
		// additional records can exist!

	} else {
		/*
		 *	Replies _usually_ copy the query.  But not
		 *	always And replies can have zero or more answers.
		 */
	}

	expected = fr_nbo_to_uint16(packet + 4) + fr_nbo_to_uint16(packet + 6) + fr_nbo_to_uint16(packet + 8) + fr_nbo_to_uint16(packet + 10);
	count = 0;

	p = packet + DNS_HDR_LEN;
	end = packet + packet_len;

	/*
	 *	We track valid label targets in a simple array (up to
	 *	2^14 bits of compressed pointer).
	 *
	 *	Note that some labels might appear in the RRDATA
	 *	field, and we don't verify those here.  However, this
	 *	function will verify the most common packets.  As a
	 *	result, any issues with overflow, etc. are more
	 *	difficult to exploit.
	 */
	memset(fr_dns_marker, 0, packet_len < (1 << 14) ? packet_len : (1 << 14));

	/*
	 *	Check for wildly fake packets, by making rough
	 *	estimations.  This way we don't actually have to walk
	 *	the packet.
	 */
	if (p + (qdcount * 5) > end) {
		DECODE_FAIL(TOO_MANY_RRS);
		return false;
	}
	p += (qdcount * 5);

	if ((p + ((expected - qdcount) * (1 + 8 + 2))) > end) {
		DECODE_FAIL(TOO_MANY_RRS);
		return false;
	}

	/*
	 *	The counts are at least vaguely OK, let's walk over the whole packet.
	 */
	p = packet + DNS_HDR_LEN;

	/*
	 *	Check that lengths of RRs match.
	 */
	while (p < end) {
		uint16_t len = 0;
		uint8_t const *start = p;
		bool is_opt = false;

		/*
		 *	Simple DNS label decoder
		 *
		 *	@todo - move this to src/lib/util/dns.c,
		 *	perhaps as fr_dns_label_verify(), and then
		 *	have it also return a pointer to the next
		 *	label?  fr_dns_label_uncompressed_length()
		 *	does similar but slightly different things.
		 */
		while (p < end) {
			/*
			 *	0x00 is "end of label"
			 */
			if (!*p) {
				p++;
				break;
			}

			/*
			 *	2 octets of 14-bit pointer, which must
			 *	be at least somewhat sane.
			 */
			if (*p >= 0xc0) {
				ptrdiff_t offset;

				if ((p + 2) > end) {
					DECODE_FAIL(POINTER_OVERFLOWS_PACKET);
					return false;
				}

				offset = p[1];
				offset += ((*p & ~0xc0) << 8);

				/*
				 *	Can't point to the header.
				 */
				if (offset < 12) {
					DECODE_FAIL(POINTER_TO_HEADER);
					return false;
				}

				/*
				 *	Can't point to the current label.
				 */
				if (offset >= (start - packet)) {
					DECODE_FAIL(POINTER_LOOPS);
					return false;
				}

				if (!fr_dns_marker[offset]) {
					DECODE_FAIL(POINTER_TO_NON_LABEL);
					return false;
				}

				/*
				 *	A compressed pointer is the end of the current label.
				 */
				p += 2;
				break;
			}

			/*
			 *	0b01 and 0b10 are forbidden
			 */
			if (*p > 63) {
				DECODE_FAIL(INVALID_POINTER);
				return false;
			}

			/*
			 *	It must be a length byte, which doesn't cause overflow.
			 */
			if ((p + *p + 1) > end) {
				DECODE_FAIL(LABEL_OVERFLOWS_PACKET);
				return false;
			}

			/*
			 *	Total length of labels can't be too high.
			 */
			len += *p;
			if (len >= 256) {
				DECODE_FAIL(LABEL_TOO_LONG);
				return false;
			}

			/*
			 *	Remember that this is where we have a
			 *	label.
			 */
			fr_dns_marker[p - packet] = 1;

			/*
			 *	Go to the next label.
			 */
			p += *p + 1;
		}

		if (qdcount) {
			/*
			 *	qtype + qclass
			 */
			if ((p + 4) > end) {
				DECODE_FAIL(MISSING_QD_HEADER);
				return false;
			}

			p += 4;
			qdcount--;
			goto next;
		}

		/*
		 *	type (2) + class (2) + TTL (4)
		 *
		 *	These are overloaded for the OPT RR
		 *	and possibly others, but the basic
		 *	idea is the same.
		 */
		if ((p + 8) > end) {
			DECODE_FAIL(MISSING_RR_HEADER);
			return false;
		}
		is_opt = (p[0] == 0) && (p[1] == 41);
		p += 8;

		/*
		 *	rr_len
		 */
		if ((p + 2) > end) {
			DECODE_FAIL(MISSING_RR_LEN);
			return false;
		}

		/*
		 *	@todo - RFC2136 allows RDLENGTH=0 for many cases.
		 */
		len = fr_nbo_to_uint16(p);
		if (!is_opt && (len == 0)) {
			DECODE_FAIL(ZERO_RR_LEN);
			return false;
		}

		p += 2;
		if ((p + len) > end) {
			DECODE_FAIL(RR_OVERFLOWS_PACKET);
			return false;
		}

		/*
		 *	Verify the TLVs, too.
		 */
		if (is_opt && !fr_dns_tlv_ok(p, p + len, reason)) {
			return false;
		}

		p += len;

next:
		count++;

		if (count > expected) {
			DECODE_FAIL(TOO_MANY_RRS);
			return false;
		}
	}

	if (count != expected) {
		DECODE_FAIL(TOO_FEW_RRS);
		return false;
	}

	/*
	 *	@todo - save fr_dns_marker[] data, so that it can be used by fr_dns_labels_get().  This helps
	 *	to reduce redundant work.
	 */

	DECODE_FAIL(NONE);
	return true;
}

fr_dns_labels_t *fr_dns_labels_get(uint8_t const *packet, size_t packet_len, bool init_mark)
{
	fr_dns_labels_t *lb = &fr_dns_labels;

	lb->max = 256;
	lb->mark = fr_dns_marker;
	lb->blocks = fr_dns_blocks;

	lb->start = packet;
	lb->end = packet + packet_len;

	lb->num = 1;
	lb->blocks[0].start = DNS_HDR_LEN;
	lb->blocks[0].end = DNS_HDR_LEN;

	if (init_mark) {
		fr_assert(packet_len <= 65535);
		memset(lb->mark, 0, packet_len);
	}

	return lb;
}

/** Resolve/cache attributes in the DNS dictionary
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dns_global_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	instance_count++;

	if (fr_dict_autoload(dns_dict) < 0) {
	fail:
		instance_count--;
		return -1;
	}
	if (fr_dict_attr_autoload(dns_dict_attr) < 0) {
		fr_dict_autofree(dns_dict);
		goto fail;
	}

	instantiated = true;
	return 0;
}

void fr_dns_global_free(void)
{
	if (!instantiated) return;

	fr_assert(instance_count > 0);

	if (--instance_count > 0) return;

	fr_dict_autofree(dns_dict);
	instantiated = false;
}

static bool attr_valid(fr_dict_attr_t *da)
{
	if (da->flags.array) {
		fr_strerror_const("The 'array' flag cannot be used with DNS");
		return false;
	}

	if (da->type == FR_TYPE_ATTR) {
		fr_strerror_const("The 'attribute' data type cannot be used with DNS");
		return false;
	}

	if (fr_dns_flag_dns_label_any(da)) {
		if (da->type != FR_TYPE_STRING) {
			fr_strerror_const("The 'dns_label' flag can only be used with attributes of type 'string'");
			return false;
		}
		da->flags.is_known_width = true;	/* Lie so we don't trip up the main validation checks */
	}

	switch (da->type) {
	case FR_TYPE_IP:
		da->flags.is_known_width = true;
		break;

	default:
		break;
	}

	return true;
}

extern fr_dict_protocol_t libfreeradius_dns_dict_protocol;
fr_dict_protocol_t libfreeradius_dns_dict_protocol = {
	.name = "dns",
	.default_type_size = 2,
	.default_type_length = 2,
	.attr = {
		.flags = {
			.table = dns_flags,
			.table_len = NUM_ELEMENTS(dns_flags),
			.len = sizeof(fr_dns_attr_flags_t)
		},
		.valid = attr_valid
	},

	.init = fr_dns_global_init,
	.free = fr_dns_global_free,
};
