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
 * @file protocols/dns/decode.c
 * @brief Functions to decode DNS packets.
 *
 * @author Alan DeKok (aland@freeradius.org)
 *
 * @copyright 2021 The FreeRADIUS server project
 * @copyright 2021 NetworkRADIUS SARL (legal@networkradius.com)
 */
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/dns.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/struct.h>

#include "dns.h"
#include "attrs.h"

static ssize_t decode_option(TALLOC_CTX *ctx, fr_pair_list_t *out,
			      fr_dict_attr_t const *parent,
			      uint8_t const *data, size_t const data_len, void *decode_ctx);

static ssize_t decode_value(TALLOC_CTX *ctx, fr_pair_list_t *out,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t const data_len, void *decode_ctx);

static ssize_t decode_tlv_trampoline(TALLOC_CTX *ctx, fr_pair_list_t *out,
				     fr_dict_attr_t const *parent,
				     uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	return fr_pair_tlvs_from_network(ctx, out, parent, data, data_len, decode_ctx, decode_option, NULL, true);
}


static ssize_t decode_value_trampoline(TALLOC_CTX *ctx, fr_pair_list_t *out,
				       fr_dict_attr_t const *parent,
				       uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	if ((parent->type == FR_TYPE_STRING) && fr_dns_flag_dns_label(parent)) {
		fr_dns_ctx_t		*packet_ctx = decode_ctx;

		return fr_pair_dns_labels_from_network(ctx, out, parent, packet_ctx->packet, data, data_len, packet_ctx->lb, false);
	}

	return decode_value(ctx, out, parent, data, data_len, decode_ctx);
}


static ssize_t decode_value(TALLOC_CTX *ctx, fr_pair_list_t *out,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	ssize_t			slen;
	fr_pair_t		*vp;

	FR_PROTO_HEX_DUMP(data, data_len, "decode_value");

	switch (parent->type) {
	/*
	 *	Address MAY be shorter than 16 bytes.
	 */
	case FR_TYPE_IPV6_PREFIX:
		if (data_len == 0) {
		raw:
			return fr_pair_raw_from_network(ctx, out, parent, data, data_len);
		}

		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;
		PAIR_ALLOCED(vp);

		/*
		 *	Check values of prefix length, data lengths, etc.
		 */
		if (fr_value_box_ipaddr_from_network(&vp->data, parent->type, parent,
						     data[0], data + 1, data_len - 1,
						     (parent->parent->type == FR_TYPE_STRUCT), true) < 0) {
			talloc_free(vp);
			goto raw;
		}
		break;

	/*
	 *	A bool is encoded as an empty option if it's
	 *	true.  A bool is omitted entirely if it's
	 *	false.
	 */
	case FR_TYPE_BOOL:
		if (data_len != 0) goto raw;
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;
		PAIR_ALLOCED(vp);

		vp->vp_bool = true;
		break;

	case FR_TYPE_STRUCT:
		slen = fr_struct_from_network(ctx, out, parent, data, data_len,
					      decode_ctx, decode_value_trampoline, NULL);
		if (slen < 0) return slen;
		return data_len;

	case FR_TYPE_GROUP:
		return PAIR_DECODE_FATAL_ERROR; /* not supported */

	default:
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;
		PAIR_ALLOCED(vp);

		if (fr_value_box_from_network(vp, &vp->data, vp->vp_type, vp->da,
					      &FR_DBUFF_TMP(data, data_len), data_len, true) < 0) {
			FR_PROTO_TRACE("failed decoding?");
			talloc_free(vp);
			goto raw;
		}
		break;
	}

	vp->vp_tainted = true;
	fr_pair_append(out, vp);
	return data_len;
}


#define DNS_GET_OPTION_NUM(_x)	fr_nbo_to_uint16(_x)
#define DNS_GET_OPTION_LEN(_x)	fr_nbo_to_uint16((_x) + 2)

static ssize_t decode_option(TALLOC_CTX *ctx, fr_pair_list_t *out,
			      fr_dict_attr_t const *parent,
			      uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	unsigned int   		option;
	size_t			len;
	ssize_t			slen;
	fr_dict_attr_t const	*da;
	fr_dns_ctx_t		*packet_ctx = decode_ctx;

#ifdef STATIC_ANALYZER
	if (!packet_ctx || !packet_ctx->tmp_ctx) return PAIR_DECODE_FATAL_ERROR;
#endif

	/*
	 *	Must have at least an option header.
	 */
	if (data_len < 4) {
		fr_strerror_printf("%s: Insufficient data", __FUNCTION__);
		return -(data_len);
	}

	option = DNS_GET_OPTION_NUM(data);
	len = DNS_GET_OPTION_LEN(data);
	if (len > (data_len - 4)) {
		fr_strerror_printf("%s: Option overflows input.  "
				   "Optional length must be less than %zu bytes, got %zu bytes",
				   __FUNCTION__, data_len - 4, len);
		return PAIR_DECODE_FATAL_ERROR;
	}

	FR_PROTO_HEX_DUMP(data, len + 4, "decode_option");

	da = fr_dict_attr_child_by_num(parent, option);
	if (!da) {
		da = fr_dict_attr_unknown_raw_afrom_num(packet_ctx->tmp_ctx, parent, option);
		if (!da) return PAIR_DECODE_FATAL_ERROR;
	}
	FR_PROTO_TRACE("decode context changed %s -> %s",da->parent->name, da->name);

	if ((da->type == FR_TYPE_STRING) && fr_dns_flag_dns_label(da)) {
		slen = fr_pair_dns_labels_from_network(ctx, out, da, packet_ctx->packet, data + 4, len, packet_ctx->lb, true);

	} else if (da->flags.array) {
		slen = fr_pair_array_from_network(ctx, out, da, data + 4, len, decode_ctx, decode_value);

	} else {
		slen = decode_value(ctx, out, da, data + 4, len, decode_ctx);
	}
	fr_dict_attr_unknown_free(&da);

	if (slen < 0) return slen;

	return len + 4;
}

static ssize_t decode_record(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *attr,
			     uint8_t const *rr, uint8_t const *end,
			     fr_dns_ctx_t *packet_ctx, uint8_t const *counter)
{
	unsigned int i, count;
	uint8_t const *p = rr;

	/*
	 *	The header has a count of how many records we need to decode.
	 */
	count = fr_nbo_to_uint16(counter);
	FR_PROTO_TRACE("Decoding %u of %s", count, attr->name);

	/* coverity[tainted_data] */
	for (i = 0; (i < count) && (p < end); i++) {
		ssize_t slen;

		FR_PROTO_HEX_DUMP(p, end - p, "fr_dns_decode - %s %u/%u", attr->name, i, count);

		slen = fr_struct_from_network(ctx, out, attr, p, end - p,
					      packet_ctx, decode_value_trampoline, decode_tlv_trampoline);
		if (slen < 0) return slen;
		if (!slen) break;

		fr_assert(slen <= (end - p));

		p += slen;
	}

	return p - rr;
}

/** Decode a DNS packet
 *
 */
ssize_t	fr_dns_decode(TALLOC_CTX *ctx, fr_pair_list_t *out, uint8_t const *packet, size_t packet_len, fr_dns_ctx_t *packet_ctx)
{
	ssize_t			slen;
	uint8_t const		*p, *end;

	if (packet_len < DNS_HDR_LEN) return 0;

	/*
	 *	@todo - synthesize Packet-Type from the various fields.
	 */

	FR_PROTO_HEX_DUMP(packet, packet_len, "fr_dns_decode");

	/*
	 *	Decode the header.
	 */
	slen = fr_struct_from_network(ctx, out, attr_dns_packet, packet, DNS_HDR_LEN,
				      packet_ctx, decode_value_trampoline, NULL); /* no TLVs in the header */
	if (slen < 0) {
		fr_strerror_printf("Failed decoding DNS header - %s", fr_strerror());
		return slen;
	}
	fr_assert(slen == DNS_HDR_LEN);

	p = packet + DNS_HDR_LEN;
	end = packet + packet_len;
	FR_PROTO_HEX_DUMP(p, end - p, "fr_dns_decode - after header");

	slen = decode_record(ctx, out, attr_dns_question, p, end, packet_ctx, packet + 4);
	if (slen < 0) {
		fr_strerror_printf("Failed decoding questions - %s", fr_strerror());
		return slen;
	}
	p += slen;
	FR_PROTO_HEX_DUMP(p, end - p, "fr_dns_decode - after %zd bytes of questions", slen);

	slen = decode_record(ctx, out, attr_dns_rr, p, end, packet_ctx, packet + 6);
	if (slen < 0) {
		fr_strerror_printf("Failed decoding RRs - %s", fr_strerror());
		return slen - (p - packet);
	}
	p += slen;
	FR_PROTO_HEX_DUMP(p, end - p, "fr_dns_decode - after %zd bytes of RRs", slen);

	slen = decode_record(ctx, out, attr_dns_ns, p, end, packet_ctx, packet + 8);
	if (slen < 0) {
		fr_strerror_printf("Failed decoding NS - %s", fr_strerror());
		return slen - (p - packet);
	}
	p += slen;
	FR_PROTO_HEX_DUMP(p, end - p, "fr_dns_decode - after %zd bytes of NS", slen);

	slen = decode_record(ctx, out, attr_dns_ar, p, end, packet_ctx, packet + 10);
	if (slen < 0) {
		fr_strerror_printf("Failed decoding additional records - %s", fr_strerror());
		return slen - (p - packet);
	}
	FR_PROTO_HEX_DUMP(p, end - p, "fr_dns_decode - after %zd bytes of additional records", slen);

//	p += slen;

	return packet_len;
}

/** Decode DNS RR
 *
 * @param[in] ctx context	to alloc new attributes in.
 * @param[in,out] out		Where to write the decoded options.
 * @param[in] parent		to lookup attributes in.
 * @param[in] data		to parse.
 * @param[in] data_len		of data to parse.
 * @param[in] decode_ctx	Unused.
 */
static ssize_t decode_rr(TALLOC_CTX *ctx, fr_pair_list_t *out, UNUSED fr_dict_attr_t const *parent,
			 uint8_t const *data, size_t data_len, void *decode_ctx)
{
	ssize_t			slen;
	fr_dns_ctx_t	*packet_ctx = (fr_dns_ctx_t *) decode_ctx;

	FR_PROTO_TRACE("%s called to parse %zu byte(s)", __FUNCTION__, data_len);

	if (data_len == 0) return 0;

	/*
	 *	This function is only used for testing, so update decode_ctx
	 */
	packet_ctx->packet = data;
	packet_ctx->packet_len = data_len;

	FR_PROTO_HEX_DUMP(data, data_len, NULL);

	/*
	 *	There should be at least room for the RR header
	 */
	if (data_len < 9) {
		fr_strerror_printf("%s: Insufficient data", __FUNCTION__);
		return -1;
	}

	slen = fr_struct_from_network(ctx, out, attr_dns_rr, data, data_len,
				      decode_ctx, decode_value_trampoline, decode_tlv_trampoline);
	if (slen < 0) return slen;

	FR_PROTO_TRACE("decoding option complete, returning %zd byte(s)", slen);
	return slen;
}

/*
 *	Test points
 */
static int decode_test_ctx(void **out, TALLOC_CTX *ctx, UNUSED fr_dict_t const *dict,
			   UNUSED fr_dict_attr_t const *root_da)
{
	fr_dns_ctx_t *test_ctx;

	test_ctx = talloc_zero(ctx, fr_dns_ctx_t);

	test_ctx->tmp_ctx = talloc(test_ctx, uint8_t);
	*out = test_ctx;

	return 0;
}

fr_table_num_ordered_t fr_dns_reason_fail_table[] = {
	{ L("none"),						FR_DNS_DECODE_FAIL_NONE		},
	{ L("packet is smaller than DNS header"),		FR_DNS_DECODE_FAIL_MIN_LENGTH_PACKET	},
	{ L("packet is larger than 65535"),			FR_DNS_DECODE_FAIL_MAX_LENGTH_PACKET	},
	{ L("expected query / answer, got answer / query"),	FR_DNS_DECODE_FAIL_UNEXPECTED		},
	{ L("no 'questions' in query packet"),			FR_DNS_DECODE_FAIL_NO_QUESTIONS	},
	{ L("unexprected answers in query packet"),		FR_DNS_DECODE_FAIL_ANSWERS_IN_QUESTION	},
	{ L("unexpected NS records in query packet"),		FR_DNS_DECODE_FAIL_NS_IN_QUESTION	},
	{ L("invalid label for resource record"),	       	FR_DNS_DECODE_FAIL_INVALID_RR_LABEL	},
	{ L("missing resource record header"),			FR_DNS_DECODE_FAIL_MISSING_RR_HEADER	},
	{ L("missing resource record length field"),		FR_DNS_DECODE_FAIL_MISSING_RR_LEN	},
	{ L("resource record length field is zero"),		FR_DNS_DECODE_FAIL_ZERO_RR_LEN	},
	{ L("resource record length overflows the packet"),	FR_DNS_DECODE_FAIL_RR_OVERFLOWS_PACKET	},
	{ L("more resource records than indicated in header"),	FR_DNS_DECODE_FAIL_TOO_MANY_RRS	},
	{ L("fewer resource records than indicated in header"),	FR_DNS_DECODE_FAIL_TOO_FEW_RRS		},
	{ L("pointer overflows packet"),			FR_DNS_DECODE_FAIL_POINTER_OVERFLOWS_PACKET   	},
	{ L("pointer points to packet header"),			FR_DNS_DECODE_FAIL_POINTER_TO_HEADER		},
	{ L("pointer does not point to a label"),      		FR_DNS_DECODE_FAIL_POINTER_TO_NON_LABEL       	},
	{ L("pointer creates a loop"),				FR_DNS_DECODE_FAIL_POINTER_LOOPS		},
	{ L("invalid pointer"),					FR_DNS_DECODE_FAIL_INVALID_POINTER		},
	{ L("label overflows the packet"),			FR_DNS_DECODE_FAIL_LABEL_OVERFLOWS_PACKET     	},
	{ L("too many characters in label"),			FR_DNS_DECODE_FAIL_LABEL_TOO_LONG		},
	{ L("query record header is missing"),			FR_DNS_DECODE_FAIL_MISSING_QD_HEADER		},
	{ L("missing TLV header in OPT RR"),			FR_DNS_DECODE_FAIL_MISSING_TLV_HEADER		},
	{ L("TLV overflows enclosing RR"),			FR_DNS_DECODE_FAIL_TLV_OVERFLOWS_RR		},
};
size_t fr_dns_reason_fail_table_len = NUM_ELEMENTS(fr_dns_reason_fail_table);

static ssize_t decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *out, uint8_t const *data, size_t data_len, void *proto_ctx)
{
	fr_dns_ctx_t *packet_ctx = proto_ctx;
	fr_dns_decode_fail_t reason;

	if (data_len > 65535) return -1; /* packet is too big */

	/*
	 *	Allow queries or answers
	 */
	if (!fr_dns_packet_ok(data, data_len, true, &reason)) {
		if (reason != FR_DNS_DECODE_FAIL_UNEXPECTED) goto fail;

		if (!fr_dns_packet_ok(data, data_len, false, &reason)) {
		fail:
			fr_strerror_printf("DNS packet malformed - %s",
					   fr_table_str_by_value(fr_dns_reason_fail_table, reason, "<INVALID>"));
			return -1;
		}
	}

	packet_ctx->packet = data;
	packet_ctx->packet_len = data_len;
	packet_ctx->lb = fr_dns_labels_get(data, data_len, true);
	fr_assert(packet_ctx->lb != NULL);

	return fr_dns_decode(ctx, out, data, data_len,  packet_ctx);
}

/*
 *	Test points
 */
extern fr_test_point_pair_decode_t dns_tp_decode_pair;
fr_test_point_pair_decode_t dns_tp_decode_pair = {
	.test_ctx	= decode_test_ctx,
	.func		= decode_rr
};

extern fr_test_point_proto_decode_t dns_tp_decode_proto;
fr_test_point_proto_decode_t dns_tp_decode_proto = {
	.test_ctx	= decode_test_ctx,
	.func		= decode_proto
};
