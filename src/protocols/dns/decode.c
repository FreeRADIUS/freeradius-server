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
#include <stdint.h>
#include <stddef.h>

#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/dns.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/types.h>

#include "dns.h"
#include "attrs.h"

static ssize_t decode_raw(TALLOC_CTX *ctx, fr_dcursor_t *cursor, UNUSED fr_dict_t const *dict,
			  fr_dict_attr_t const *parent,
			  uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	fr_pair_t		*vp;
	fr_dict_attr_t		*unknown;
	fr_dict_attr_t const	*da;
	fr_dns_ctx_t	*packet_ctx = decode_ctx;
	ssize_t			slen;

#ifdef __clang_analyzer__
	if (!packet_ctx || !packet_ctx->tmp_ctx || !parent->parent) return PAIR_DECODE_FATAL_ERROR;
#endif

	FR_PROTO_HEX_DUMP(data, data_len, "decode_raw");

	/*
	 *	Re-write the attribute to be "raw".  It is
	 *	therefore of type "octets", and will be
	 *	handled below.
	 */
	unknown = fr_dict_unknown_attr_afrom_da(packet_ctx->tmp_ctx, parent);
	if (!unknown) {
		fr_strerror_printf("%s: Internal sanity check %d", __FUNCTION__, __LINE__);
		return PAIR_DECODE_OOM;
	}
	unknown->flags.is_raw = 1;

	vp = fr_pair_afrom_da(ctx, unknown);
	if (!vp) return PAIR_DECODE_OOM;

	slen = fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da,
					 &FR_DBUFF_TMP(data, data_len), data_len, true);
	if (slen < 0) {
		talloc_free(vp);
		da = unknown;
		fr_dict_unknown_free(&da);
		return slen;
	}

	vp->type = VT_DATA;
	vp->vp_tainted = true;
	fr_dcursor_append(cursor, vp);
	return data_len;
}


static ssize_t decode_value(TALLOC_CTX *ctx, fr_dcursor_t *cursor, fr_dict_t const *dict,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t const data_len, void *decode_ctx);
static ssize_t decode_array(TALLOC_CTX *ctx, fr_dcursor_t *cursor, fr_dict_t const *dict,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t const data_len, void *decode_ctx);
static ssize_t decode_dns_labels(TALLOC_CTX *ctx, fr_dcursor_t *cursor, fr_dict_t const *dict,
				 fr_dict_attr_t const *parent,
				 uint8_t const *data, size_t const data_len, void *decode_ctx);

/** Handle arrays of DNS labels for fr_struct_from_network()
 *
 */
static ssize_t decode_value_trampoline(TALLOC_CTX *ctx, fr_dcursor_t *cursor, fr_dict_t const *dict,
				       fr_dict_attr_t const *parent,
				       uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	if ((parent->type == FR_TYPE_STRING) && !parent->flags.extra && parent->flags.subtype) {
		FR_PROTO_TRACE("decode DNS labels");
		return decode_dns_labels(ctx, cursor, dict, parent, data, data_len, decode_ctx);
	}

	if (parent->flags.array) return decode_array(ctx, cursor, dict, parent, data, data_len, decode_ctx);

	return decode_value(ctx, cursor, dict, parent, data, data_len, decode_ctx);
}


static ssize_t decode_value(TALLOC_CTX *ctx, fr_dcursor_t *cursor, fr_dict_t const *dict,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	ssize_t			slen;
	fr_pair_t		*vp;
	uint8_t			prefix_len;

	FR_PROTO_HEX_DUMP(data, data_len, "decode_value");

	switch (parent->type) {
	/*
	 *	Address MAY be shorter than 16 bytes.
	 */
	case FR_TYPE_IPV6_PREFIX:
		if ((data_len == 0) || (data_len > (1 + sizeof(vp->vp_ipv6addr)))) {
		raw:
			return decode_raw(ctx, cursor, dict, parent, data, data_len, decode_ctx);

		};

		/*
		 *	Structs used fixed length fields
		 */
		if (parent->parent->type == FR_TYPE_STRUCT) {
			if (data_len != (1 + sizeof(vp->vp_ipv6addr))) goto raw;

			vp = fr_pair_afrom_da(ctx, parent);
			if (!vp) return PAIR_DECODE_OOM;

			vp->vp_ip.af = AF_INET6;
			vp->vp_ip.scope_id = 0;
			vp->vp_ip.prefix = data[0];
			memcpy(&vp->vp_ipv6addr, data + 1, data_len - 1);
			break;
		}

		/*
		 *	No address, the prefix length MUST be zero.
		 */
		if (data_len == 1) {
			if (data[0] != 0) goto raw;

			vp = fr_pair_afrom_da(ctx, parent);
			if (!vp) return PAIR_DECODE_OOM;

			vp->vp_ip.af = AF_INET6;
			vp->vp_ip.scope_id = 0;
			vp->vp_ip.prefix = 0;
			memset(&vp->vp_ipv6addr, 0, sizeof(vp->vp_ipv6addr));
			break;
		}

		prefix_len = data[0];

		/*
		 *	If we have a /64 prefix but only 7 bytes of
		 *	address, that's an error.
		 */
		if (fr_bytes_from_bits(prefix_len) > (data_len - 1)) goto raw;

		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;

		vp->vp_ip.af = AF_INET6;
		vp->vp_ip.scope_id = 0;
		vp->vp_ip.prefix = prefix_len;
		memset(&vp->vp_ipv6addr, 0, sizeof(vp->vp_ipv6addr));
		memcpy(&vp->vp_ipv6addr, data + 1, data_len - 1);
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
		vp->vp_bool = true;
		break;

	case FR_TYPE_STRUCT:
		slen = fr_struct_from_network(ctx, cursor, parent, data, data_len, true,
					      decode_ctx, decode_value_trampoline, NULL);
		if (slen < 0) return slen;
		return data_len;

	case FR_TYPE_GROUP:
		return PAIR_DECODE_FATAL_ERROR; /* not supported */

#if 0
	{
		fr_dcursor_t child_cursor;
		fr_pair_list_t head;
		fr_pair_list_init(&head);

		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;

		/*
		 *	Child VPs go into the child group, not in the
		 *	main parent list.  We start decoding
		 *	attributes from the dictionary root, not from
		 *	this parent.  We also don't decode an option
		 *	header, as we're just decoding the values
		 *	here.
		 */
		fr_dcursor_init(&child_cursor, &head);
		slen = decode_tlvs(vp, &child_cursor, dict, fr_dict_root(dict_dns), data, data_len, decode_ctx, false);
		if (slen < 0) {
			talloc_free(vp);
			goto raw;
		}
		fr_pair_list_append(&vp->vp_group, &head);
		break;
	}
#endif

	default:
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;

		if (fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da,
					      &FR_DBUFF_TMP(data, data_len), data_len, true) < 0) {
			FR_PROTO_TRACE("failed decoding?");
			talloc_free(vp);
			goto raw;
		}
		break;
	}

	vp->type = VT_DATA;
	vp->vp_tainted = true;
	fr_dcursor_append(cursor, vp);
	return data_len;
}


static ssize_t decode_array(TALLOC_CTX *ctx, fr_dcursor_t *cursor, fr_dict_t const *dict,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	uint8_t const  		*p = data, *end = p + data_len;
	ssize_t			slen;
	size_t			element_len;

	FR_PROTO_HEX_DUMP(data, data_len, "decode_array");

	if (!fr_cond_assert_msg(parent->flags.array,
				"%s: Internal sanity check failed, attribute \"%s\" does not have array bit set",
				__FUNCTION__, parent->name)) return PAIR_DECODE_FATAL_ERROR;

#if 0
	/*
	 *	Fixed-size fields get decoded with a simple decoder.
	 */
	element_len = fr_dns_attr_sizes[parent->type][0];
	if (element_len > 0) {
		while (p < end) {
			/*
			 *	Not enough room for one more element,
			 *	decode the last bit as raw data.
			 */
			if ((size_t) (end - p) < element_len) {
				slen = decode_raw(ctx, cursor, dict, parent, p, end - p , decode_ctx);
				if (slen < 0) return slen;
				break;
			}

			slen = decode_value(ctx, cursor, dict, parent, p, element_len, decode_ctx);
			if (slen < 0) return slen;
			if (!fr_cond_assert((size_t) slen == element_len)) return -(p - data);

			p += slen;
		}

		/*
		 *	We MUST have decoded the entire input.  If
		 *	not, we ignore the extra bits.
		 */
		return data_len;
	}
#endif

	/*
	 *	If the data is variable length i.e. strings or octets
	 *	there is a length field before each element.
	 *
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+
	 *   |       text-len                |        String                 |
	 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...-+-+-+-+-+-+-+
	 */
	while (p < end) {
		if ((end - p) < 2) {
		raw:
			slen = decode_raw(ctx, cursor, dict, parent, p, end - p , decode_ctx);
			if (slen < 0) return slen;
			break;
		}

		element_len = fr_net_to_uint16(p);
		if ((p + 2 + element_len) > end) {
			goto raw;
		}

		p += 2;
		slen = decode_value(ctx, cursor, dict, parent, p, element_len, decode_ctx);
		if (slen < 0) return slen;
		p += slen;
	}

	return data_len;
}


static ssize_t decode_dns_labels(TALLOC_CTX *ctx, fr_dcursor_t *cursor, fr_dict_t const *dict,
				 fr_dict_attr_t const *parent,
				 uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	ssize_t slen;
	size_t total, labels_len;
	fr_pair_t *vp;
	uint8_t const *next = data;
	fr_dns_ctx_t *packet_ctx = decode_ctx;

	FR_PROTO_HEX_DUMP(data, data_len, "decode_dns_labels");

	/*
	 *	This function handles both single-valued and array
	 *	types.  It's just easier that way.
	 */
	if (!parent->flags.array) {
		/*
		 *	Decode starting at "NEXT", but allowing decodes from the start of the packet.
		 */
		slen = fr_dns_label_uncompressed_length(packet_ctx->packet, data, data + data_len - packet_ctx->packet, &next, packet_ctx->lb);
		if (slen <= 0) {
			FR_PROTO_TRACE("length failed at %zd - %s", slen, fr_strerror());
			goto raw;
		}

		labels_len = next - data; /* decode only what we've found */
	} else {
		/*
		 *	Get the length of the entire set of labels, up
		 *	to (and including) the final 0x00.
		 *
		 *	If any of the labels point outside of this
		 *	area, OR they are otherwise invalid, then that's an error.
		 */
		slen = fr_dns_labels_network_verify(packet_ctx->packet, data, data + data_len - packet_ctx->packet, data, packet_ctx->lb);
		if (slen < 0) {
			FR_PROTO_TRACE("verify failed");
		raw:
			return decode_raw(ctx, cursor, dict, parent, data, data_len, decode_ctx);
		}

		labels_len = slen;
	}

	/*
	 *	Loop over the input buffer, decoding the labels one by
	 *	one.
	 */
	for (total = 0; total < labels_len; total += slen) {
		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return PAIR_DECODE_OOM;

		/*
		 *	Having verified the input above, this next
		 *	function should never fail unless there's a
		 *	bug in the code.
		 */
		slen = fr_dns_label_to_value_box(vp, &vp->data, data, labels_len, data + total, true, packet_ctx->lb);
		if (slen <= 0) {
			FR_PROTO_TRACE("Failed decoding label at %zd", slen);
			talloc_free(vp);
			goto raw;
		}

		vp->type = VT_DATA;
		fr_dcursor_append(cursor, vp);
	}

	FR_PROTO_TRACE("decode_dns_labels - %zu", labels_len);
	return labels_len;
}

static ssize_t decode_record(TALLOC_CTX *ctx, fr_dcursor_t *cursor, fr_dict_attr_t const *attr,
			     uint8_t const *packet, size_t packet_len,
			     fr_dns_ctx_t *packet_ctx, uint8_t const *counter)
{
	int i, count;
	uint8_t const *p, *end;

	p = packet;
	end = packet + packet_len;

	count = fr_net_to_uint16(counter);
	FR_PROTO_TRACE("Decoding %u of %s", count, attr->name);
	for (i = 0; i < count; i++) {
		ssize_t slen;

		FR_PROTO_HEX_DUMP(p, end - p, "fr_dns_decode - %s %d/%d", attr->name, i, count);

		if (p >= end) {
			FR_PROTO_TRACE("%s overflows packet at %d", attr->name, i);
			return -(p - packet);
		}

		slen = fr_struct_from_network(ctx, cursor, attr, p, end - p, true,
					      packet_ctx, decode_value_trampoline, NULL);
		if (slen < 0) return slen;
		p += slen;
	}

	return p - packet;
}

/** Decode a DNS packet
 *
 */
ssize_t	fr_dns_decode(TALLOC_CTX *ctx, uint8_t const *packet, size_t packet_len, fr_dcursor_t *cursor, fr_dns_ctx_t *packet_ctx)
{
	ssize_t			slen;
	uint8_t const		*p, *end;

	FR_PROTO_TRACE("HERE %d", __LINE__);

	if (packet_len < DNS_HDR_LEN) return 0;

	/*
	 *	@todo - synthesize Packet-Type from the various fields.
	 */

	FR_PROTO_HEX_DUMP(packet, packet_len, "fr_dns_decode");

	/*
	 *	Decode the header.
	 */
	slen = fr_struct_from_network(ctx, cursor, attr_dns_packet, packet, DNS_HDR_LEN, true,
				      packet_ctx, decode_value_trampoline, NULL);
	if (slen < 0) {
	fail:
		fr_strerror_const("Failed decoding DNS packet");
		return slen;
	}

	p = packet + DNS_HDR_LEN;
	end = packet + packet_len;

	slen = decode_record(ctx, cursor, attr_dns_question, p, end - p, packet_ctx, packet + 4);
	if (slen < 0) goto fail;
	p += slen;

	slen = decode_record(ctx, cursor, attr_dns_rr, p, end - p, packet_ctx, packet + 6);
	if (slen < 0) goto fail;
	p += slen;

	slen = decode_record(ctx, cursor, attr_dns_ns, p, end - p, packet_ctx, packet + 8);
	if (slen < 0) goto fail;
	p += slen;

	slen = decode_record(ctx, cursor, attr_dns_ar, p, end - p, packet_ctx, packet + 10);
	if (slen < 0) goto fail;
	p += slen;

	return packet_len;
}

/** Decode DNS RR
 *
 * @param[in] ctx context	to alloc new attributes in.
 * @param[in,out] cursor	Where to write the decoded options.
 * @param[in] dict		to lookup attributes in.
 * @param[in] data		to parse.
 * @param[in] data_len		of data to parse.
 * @param[in] decode_ctx	Unused.
 */
static ssize_t fr_dns_decode_rr(TALLOC_CTX *ctx, fr_dcursor_t *cursor,
				UNUSED fr_dict_t const *dict, uint8_t const *data, size_t data_len, void *decode_ctx)
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

	slen = fr_struct_from_network(ctx, cursor, attr_dns_rr, data, data_len, true,
				      decode_ctx, decode_value_trampoline, NULL);
	if (slen < 0) return slen;

	FR_PROTO_TRACE("decoding option complete, returning %zd byte(s)", slen);
	return slen;
}

/*
 *	Test points
 */
static int _decode_test_ctx(UNUSED fr_dns_ctx_t *test_ctx)
{
	fr_dns_global_free();

	return 0;
}

static int decode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_dns_ctx_t *test_ctx;

	if (fr_dns_global_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_dns_ctx_t);
	talloc_set_destructor(test_ctx, _decode_test_ctx);

	test_ctx->tmp_ctx = talloc(test_ctx, uint8_t);
	*out = test_ctx;

	return 0;
}

static ssize_t fr_dns_decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *list, uint8_t const *data, size_t data_len, void *proto_ctx)
{
	fr_dcursor_t	cursor;
	fr_dns_ctx_t *packet_ctx = proto_ctx;

	/*
	 *	Allow queries or answers
	 */
#if 0
	if (!fr_dns_packet_ok(data, data_len, true)) {
		FR_PROTO_TRACE("FAIL %d", __LINE__);
		if (!fr_dns_packet_ok(data, data_len, false)) {
			FR_PROTO_TRACE("FAIL %d", __LINE__);
			return -1;
		}

		FR_PROTO_TRACE("FAIL %d", __LINE__);
	}
#endif

	fr_pair_list_init(list);
	fr_dcursor_init(&cursor, list);

	packet_ctx->packet = data;
	packet_ctx->packet_len = data_len;

	if (packet_ctx->lb) {
		fr_dns_labels_t *lb = packet_ctx->lb;

		lb->start = data;

		/*
		 *	Always skip the DNS packet header.
		 */
		lb->blocks[0].start = 12;
		lb->blocks[0].end = 12;
		lb->num = 1;
	} else {
		packet_ctx->lb = fr_dns_labels_init(packet_ctx, data, 256);
		fr_assert(packet_ctx->lb != NULL);
	}

	return fr_dns_decode(ctx, data, data_len, &cursor, packet_ctx);
}

/*
 *	Test points
 */
extern fr_test_point_pair_decode_t dns_tp_decode_pair;
fr_test_point_pair_decode_t dns_tp_decode_pair = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_dns_decode_rr
};

extern fr_test_point_proto_decode_t dns_tp_decode_proto;
fr_test_point_proto_decode_t dns_tp_decode_proto = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_dns_decode_proto
};
