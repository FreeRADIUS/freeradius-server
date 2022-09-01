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

static uint32_t instance_count = 0;

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
	{ NULL }
};

//fr_dict_attr_t const *attr_dns_packet_type;
fr_dict_attr_t const *attr_dns_packet;
fr_dict_attr_t const *attr_dns_question;
fr_dict_attr_t const *attr_dns_rr;
fr_dict_attr_t const *attr_dns_ns;
fr_dict_attr_t const *attr_dns_ar;

extern fr_dict_attr_autoload_t dns_dict_attr[];
fr_dict_attr_autoload_t dns_dict_attr[] = {
//	{ .out = &attr_dns_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT16, .dict = &dict_dns },
	{ .out = &attr_dns_packet, .name = "packet", .type = FR_TYPE_STRUCT, .dict = &dict_dns },
	{ .out = &attr_dns_question, .name = "question", .type = FR_TYPE_STRUCT, .dict = &dict_dns },
	{ .out = &attr_dns_rr, .name = "rr", .type = FR_TYPE_STRUCT, .dict = &dict_dns },
	{ .out = &attr_dns_ns, .name = "ns", .type = FR_TYPE_STRUCT, .dict = &dict_dns },
	{ .out = &attr_dns_ar, .name = "ar", .type = FR_TYPE_STRUCT, .dict = &dict_dns },
	{ NULL }
};

 char const *fr_dns_packet_codes[FR_DNS_CODE_MAX] = {
	[FR_DNS_QUERY] = "query",
	[FR_DNS_IQUERY] = "iquery",
	[FR_DNS_STATUS] = "status",
	[FR_DNS_UPDATE] = "update",
	[FR_DNS_STATEFUL_OP] = "stateful-operations",
};

#define DECODE_FAIL(_reason) if (reason) *reason = DECODE_FAIL_ ## _reason

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

	qdcount = fr_nbo_to_uint16(packet + 4);

	if (query) {
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
			DECODE_FAIL(NS_IN_QUESTION);
			return false;
		}
		if (fr_nbo_to_uint16(packet + 8) != 0) {
			DECODE_FAIL(ANSWERS_IN_QUESTION);
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
				size_t offset;

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
				if ((packet + offset) >= start) {
					DECODE_FAIL(POINTER_LOOPS);
					return false;
				}

				/* coverity[tainted_data] */
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
			 *	0b10 and 0b10 are forbidden
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
		 *	type + class + TTL
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
		if ((p + 2) >= end) {
			DECODE_FAIL(MISSING_RR_LEN);
			return false;
		}

		len = fr_nbo_to_uint16(p);
		if (len == 0) {
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

	if (fr_dict_autoload(dns_dict) < 0) return -1;
	if (fr_dict_attr_autoload(dns_dict_attr) < 0) {
		fr_dict_autofree(dns_dict);
		return -1;
	}

	instance_count++;

	return 0;
}

void fr_dns_global_free(void)
{
	if (--instance_count > 0) return;

	fr_dict_autofree(dns_dict);
}

static fr_table_num_ordered_t const subtype_table[] = {
	{ L("dns_label"),			FLAG_ENCODE_DNS_LABEL },
};


static bool attr_valid(UNUSED fr_dict_t *dict, UNUSED fr_dict_attr_t const *parent,
		       UNUSED char const *name, UNUSED int attr, fr_type_t type, fr_dict_attr_flags_t *flags)
{
	/*
	 *	"arrays" of string/octets are encoded as a 16-bit
	 *	length, followed by the actual data.
	 */
	if (flags->array && ((type == FR_TYPE_STRING) || (type == FR_TYPE_OCTETS))) {
		flags->is_known_width = true;
	}

	/*
	 *	"extra" signifies that subtype is being used by the
	 *	dictionaries itself.
	 */
	if (flags->extra || !flags->subtype) return true;

	if (type != FR_TYPE_STRING) {
		fr_strerror_const("The 'dns_label' flag can only be used with attributes of type 'string'");
		return false;
	}

	flags->is_known_width = true;

	return true;
}

extern fr_dict_protocol_t libfreeradius_dns_dict_protocol;
fr_dict_protocol_t libfreeradius_dns_dict_protocol = {
	.name = "dns",
	.default_type_size = 2,
	.default_type_length = 2,
	.subtype_table = subtype_table,
	.subtype_table_len = NUM_ELEMENTS(subtype_table),
	.attr_valid = attr_valid,
};
