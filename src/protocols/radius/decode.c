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
 * @file protocols/radius/decode.c
 * @brief Functions to decode RADIUS attributes
 *
 * @copyright 2000-2003,2006-2015 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/protocol/radius/freeradius.internal.h>

#include "attrs.h"

/*
 *	For all of the concat/extended attributes.
 */
#include <freeradius-devel/protocol/radius/rfc2869.h>
#include <freeradius-devel/protocol/radius/rfc5904.h>
#include <freeradius-devel/protocol/radius/rfc6929.h>
#include <freeradius-devel/protocol/radius/rfc7268.h>

static void memcpy_bounded(void * restrict dst, const void * restrict src, size_t n, const void * restrict end)
{
	size_t len = n;

	if (!fr_cond_assert(n <= 65535)) {
		return;
	}

	if (!fr_cond_assert(src <= end)) {
		return;
	}

	if (len == 0) return;

	if (!fr_cond_assert(((uint8_t const * restrict) src + len) <= (uint8_t const * restrict) end)) {
		len = (uint8_t const * restrict) end - (uint8_t const * restrict) src;
	}

	memcpy(dst, src, len);
}


/** Decode Tunnel-Password encrypted attributes
 *
 * Defined in RFC-2868, this uses a two char SALT along with the
 * initial intermediate value, to differentiate it from the
 * above.
 */
static ssize_t fr_radius_decode_tunnel_password(uint8_t *passwd, size_t *pwlen, fr_radius_decode_ctx_t *packet_ctx)
{
	fr_md5_ctx_t	*md5_ctx, *md5_ctx_old;
	uint8_t		digest[RADIUS_AUTH_VECTOR_LENGTH];
	size_t		i, n, encrypted_len, embedded_len;

	encrypted_len = *pwlen;

	/*
	 *	We need at least a salt.
	 */
	if (encrypted_len < 2) {
		fr_strerror_const("Tunnel password is too short");
		return -1;
	}

	/*
	 *	There's a salt, but no password.  Or, there's a salt
	 *	and a 'data_len' octet.  It's wrong, but at least we
	 *	can figure out what it means: the password is empty.
	 *
	 *	Note that this means we ignore the 'data_len' field,
	 *	if the attribute length tells us that there's no
	 *	more data.  So the 'data_len' field may be wrong,
	 *	but that's ok...
	 */
	if (encrypted_len <= 3) {
		passwd[0] = 0;
		*pwlen = 0;
		return 0;
	}

	encrypted_len -= 2;		/* discount the salt */

	md5_ctx = fr_md5_ctx_alloc_from_list();
	md5_ctx_old = fr_md5_ctx_alloc_from_list();

	fr_md5_update(md5_ctx, (uint8_t const *) packet_ctx->common->secret, packet_ctx->common->secret_length);
	fr_md5_ctx_copy(md5_ctx_old, md5_ctx); /* save intermediate work */

	/*
	 *	Set up the initial key:
	 *
	 *	 b(1) = MD5(secret + vector + salt)
	 */
	fr_md5_update(md5_ctx, packet_ctx->request_authenticator, RADIUS_AUTH_VECTOR_LENGTH);
	fr_md5_update(md5_ctx, passwd, 2);

	embedded_len = 0;
	for (n = 0; n < encrypted_len; n += AUTH_PASS_LEN) {
		size_t base;
		size_t block_len = AUTH_PASS_LEN;

		/*
		 *	Ensure we don't overflow the input on MD5
		 */
		if ((n + 2 + AUTH_PASS_LEN) > *pwlen) {
			block_len = *pwlen - n - 2;
		}

		if (n == 0) {
			base = 1;

			fr_md5_final(digest, md5_ctx);
			fr_md5_ctx_copy(md5_ctx, md5_ctx_old);

			/*
			 *	A quick check: decrypt the first octet
			 *	of the password, which is the
			 *	'data_len' field.  Ensure it's sane.
			 */
			embedded_len = passwd[2] ^ digest[0];
			if (embedded_len > encrypted_len) {
				fr_strerror_printf("Tunnel Password is too long for the attribute "
						   "(shared secret is probably incorrect!)");
				fr_md5_ctx_free_from_list(&md5_ctx);
				fr_md5_ctx_free_from_list(&md5_ctx_old);
				return -1;
			}

			fr_md5_update(md5_ctx, passwd + 2, block_len);

		} else {
			base = 0;

			fr_md5_final(digest, md5_ctx);

			fr_md5_ctx_copy(md5_ctx, md5_ctx_old);
			fr_md5_update(md5_ctx, passwd + n + 2, block_len);
		}

		for (i = base; i < block_len; i++) {
			passwd[n + i - 1] = passwd[n + i + 2] ^ digest[i];
		}
	}

	fr_md5_ctx_free_from_list(&md5_ctx);
	fr_md5_ctx_free_from_list(&md5_ctx_old);

	/*
	 *	Check trailing bytes
	 */
	if (packet_ctx->tunnel_password_zeros) for (i = embedded_len; i < (encrypted_len - 1); i++) {	/* -1 for length field */
		if (passwd[i] != 0) {
			fr_strerror_printf("Trailing garbage in Tunnel Password "
					   "(shared secret is probably incorrect!)");

			return -1;
		}
	}

	*pwlen = embedded_len;

	passwd[embedded_len] = '\0';

	return embedded_len;
}

/** Decode password
 *
 */
static ssize_t fr_radius_decode_password(char *passwd, size_t pwlen, fr_radius_decode_ctx_t *packet_ctx)
{
	fr_md5_ctx_t	*md5_ctx, *md5_ctx_old;
	uint8_t		digest[RADIUS_AUTH_VECTOR_LENGTH];
	int		i;
	size_t		n;

	/*
	 *	The RFC's say that the maximum is 128, but where we
	 *	come from, we don't need limits.
	 */
	if (pwlen > RADIUS_MAX_PASS_LENGTH) pwlen = RADIUS_MAX_PASS_LENGTH;

	/*
	 *	Catch idiots.
	 */
	if (pwlen == 0) goto done;

	md5_ctx = fr_md5_ctx_alloc_from_list();
	md5_ctx_old = fr_md5_ctx_alloc_from_list();

	fr_md5_update(md5_ctx, (uint8_t const *) packet_ctx->common->secret, packet_ctx->common->secret_length);
	fr_md5_ctx_copy(md5_ctx_old, md5_ctx);	/* save intermediate work */

	/*
	 *	The inverse of the code above.
	 */
	for (n = 0; n < pwlen; n += AUTH_PASS_LEN) {
		if (n == 0) {
			fr_md5_update(md5_ctx, packet_ctx->request_authenticator, RADIUS_AUTH_VECTOR_LENGTH);
			fr_md5_final(digest, md5_ctx);

			fr_md5_ctx_copy(md5_ctx, md5_ctx_old);
			if (pwlen > AUTH_PASS_LEN) {
				fr_md5_update(md5_ctx, (uint8_t *) passwd, AUTH_PASS_LEN);
			}
		} else {
			fr_md5_final(digest, md5_ctx);

			fr_md5_ctx_copy(md5_ctx, md5_ctx_old);
			if (pwlen > (n + AUTH_PASS_LEN)) {
				fr_md5_update(md5_ctx, (uint8_t *) passwd + n, AUTH_PASS_LEN);
			}
		}

		for (i = 0; i < AUTH_PASS_LEN; i++) passwd[i + n] ^= digest[i];
	}

	fr_md5_ctx_free_from_list(&md5_ctx);
	fr_md5_ctx_free_from_list(&md5_ctx_old);

 done:
	passwd[pwlen] = '\0';
	return strlen(passwd);
}

/** Check if a set of RADIUS formatted TLVs are OK
 *
 */
int fr_radius_decode_tlv_ok(uint8_t const *data, size_t length, size_t dv_type, size_t dv_length)
{
	uint8_t const *end = data + length;

	FR_PROTO_TRACE("Checking TLV %u/%u", (unsigned int) dv_type, (unsigned int) dv_length);

	FR_PROTO_HEX_DUMP(data, length, "tlv_ok");

	if ((dv_length > 2) || (dv_type == 0) || (dv_type > 4)) {
		fr_strerror_printf("%s: Invalid arguments", __FUNCTION__);
		return -1;
	}

	while (data < end) {
		size_t attrlen;

		if ((data + dv_type + dv_length) > end) {
			fr_strerror_const("Attribute header overflow");
			return -1;
		}

		switch (dv_type) {
		case 4:
			if ((data[0] == 0) && (data[1] == 0) &&
			    (data[2] == 0) && (data[3] == 0)) {
			zero:
				fr_strerror_const("Invalid attribute 0");
				return -1;
			}

			if (data[0] != 0) {
				fr_strerror_const("Invalid attribute > 2^24");
				return -1;
			}
			break;

		case 2:
			if ((data[0] == 0) && (data[1] == 0)) goto zero;
			break;

		case 1:
			/*
			 *	Zero is allowed, because the Colubris
			 *	people are dumb and use it.
			 */
			break;

		default:
			fr_strerror_printf("%s: Internal sanity check failed", __FUNCTION__);
			return -1;
		}

		switch (dv_length) {
		case 0:
			return 0;

		case 2:
			if (data[dv_type] != 0) {
				fr_strerror_const("Attribute is longer than 256 octets");
				return -1;
			}
			FALL_THROUGH;
		case 1:
			attrlen = data[dv_type + dv_length - 1];
			break;


		default:
			fr_strerror_printf("%s: Internal sanity check failed", __FUNCTION__);
			return -1;
		}

		if (attrlen < (dv_type + dv_length)) {
			fr_strerror_const("Attribute header has invalid length");
			return -1;
		}

		if (attrlen > length) {
			fr_strerror_const("Attribute overflows container");
			return -1;
		}

		data += attrlen;
		length -= attrlen;
	}

	return 0;
}

/** Convert a "concatenated" attribute to one long VP
 *
 */
static ssize_t decode_concat(TALLOC_CTX *ctx, fr_pair_list_t *list,
			     fr_dict_attr_t const *parent, uint8_t const *data,
			     uint8_t const *end)
{
	size_t		total;
	uint8_t		attr;
	uint8_t const	*ptr = data;
	uint8_t		*p;
	fr_pair_t	*vp;

	fr_assert(parent->type == FR_TYPE_OCTETS);

	total = 0;
	attr = ptr[0];

	/*
	 *	See how many consecutive attributes there are.
	 */
	while (ptr < end) {
		if ((ptr + 2) == end) break;
		if ((ptr + 2) > end) return -1;
		if (ptr[1] <= 2) return -1;
		if ((ptr + ptr[1]) > end) return -1;

		total += ptr[1] - 2;

		ptr += ptr[1];

		if (ptr == end) break;

		/*
		 *	Attributes MUST be consecutive.
		 */
		if (ptr[0] != attr) break;
	}

	/*
	 *	Reset the end of the data we're trying to parse
	 */
	end = ptr;

	/*
	 *	If there's no data, just return that we skipped the
	 *	attribute header.
	 */
	if (!total) return 2;

	vp = fr_pair_afrom_da(ctx, parent);
	if (!vp) return -1;
	PAIR_ALLOCED(vp);

	if (fr_pair_value_mem_alloc(vp, &p, total, true) != 0) {
		talloc_free(vp);
		return -1;
	}

	ptr = data;
	while (ptr < end) {
		memcpy_bounded(p, ptr + 2, ptr[1] - 2, end);
		p += ptr[1] - 2;
		ptr += ptr[1];
	}
	fr_pair_append(list, vp);
	return ptr - data;
}

/*
 *	Short-term hack to help clean things up.
 */
#define decode_value fr_radius_decode_pair_value

/** decode an RFC-format TLV
 *
 */
static ssize_t decode_rfc(TALLOC_CTX *ctx, fr_pair_list_t *out,
			      fr_dict_attr_t const *parent,
			      uint8_t const *data, size_t const data_len, void *decode_ctx)
{
	unsigned int   		attr;
	size_t			len;
	ssize_t			slen;
	fr_dict_attr_t const	*da;
	fr_radius_decode_ctx_t	*packet_ctx = decode_ctx;

#ifdef STATIC_ANALYZER
	if (!packet_ctx || !packet_ctx->tmp_ctx) return PAIR_DECODE_FATAL_ERROR;
#endif

	fr_assert(parent != NULL);

	/*
	 *	Must have at least a header.
	 */
	if ((data_len < 2) || (data[1] < 2)) {
		fr_strerror_printf("%s: Insufficient data", __FUNCTION__);
		return -(data_len);
	}

	/*
	 *	Empty attributes are ignored.
	 */
	if (data[1] == 2) return 2;

	attr = data[0];
	len = data[1];
	if (len > data_len) {
		fr_strerror_printf("%s: Attribute overflows input.  "
				   "Length must be less than %zu bytes, got %zu bytes",
				   __FUNCTION__, data_len - 2, len - 2);
		return PAIR_DECODE_FATAL_ERROR;
	}

	da = fr_dict_attr_child_by_num(parent, attr);
	if (!da) {
		da = fr_dict_attr_unknown_raw_afrom_num(packet_ctx->tmp_ctx, parent, attr);
		if (!da) return PAIR_DECODE_FATAL_ERROR;
		slen = fr_pair_raw_from_network(ctx, out, da, data + 2, len - 2);
		if (slen < 0) return slen;
		return len;
	}
	FR_PROTO_TRACE("decode context changed %s -> %s",da->parent->name, da->name);

	if (da->flags.array) {
		slen = fr_pair_array_from_network(ctx, out, da, data + 2, len - 2, decode_ctx, decode_value);

	} else if (da->type == FR_TYPE_TLV) {
		slen = fr_pair_tlvs_from_network(ctx, out, da, data + 2, len - 2, decode_ctx, decode_rfc, NULL, true);

	} else {
		slen = decode_value(ctx, out, da, data + 2, len - 2, decode_ctx);
	}

	if (slen < 0) return slen;

	return len;
}


/** Decode NAS-Filter-Rule
 *
 *  Similar to decode_concat, but contains multiple values instead of
 *  one.
 */
static ssize_t decode_nas_filter_rule(TALLOC_CTX *ctx, fr_pair_list_t *out,
				      fr_dict_attr_t const *parent, uint8_t const *data,
				      size_t const data_len, fr_radius_decode_ctx_t *packet_ctx)
{
	uint8_t const	*ptr = data;
	uint8_t const	*end = data + data_len;
	uint8_t	const	*decode, *decode_end;
	uint8_t		*buffer = NULL;
	size_t		total = 0;

	/*
	 *	Figure out how long the total length of the data is.
	 *	This is so that we can do the decoding from a
	 *	temporary buffer.  Which means that we coalesce data
	 *	across multiple attributes, separately from chopping
	 *	the data at zero bytes.
	 */
	while (ptr < end) {
		if ((ptr + 2) == end) break;
		if ((ptr + 2) > end) return -1;
		if ((ptr[0] != FR_NAS_FILTER_RULE)) break;
		if (ptr[1] <= 2) return -1;
		if ((ptr + ptr[1]) > end) return -1;

		total += ptr[1] - 2;
		ptr += ptr[1];
	}
	end = ptr;

	FR_PROTO_TRACE("Coalesced NAS-Filter-Rule has %lu octets", total);

	/*
	 *	More than one attribute, create a temporary buffer,
	 *	and copy all of the data over to it.
	 */
	if (total > RADIUS_MAX_STRING_LENGTH) {
		uint8_t *p;

		buffer = talloc_array(packet_ctx->tmp_ctx, uint8_t, total);
		if (!buffer) return PAIR_DECODE_OOM;

		p = buffer;
		ptr = data;

		/*
		 *	Don't bother doing sanity checks, as they were
		 *	already done above.
		 */
		while (ptr < end) {
			fr_assert(p < (buffer + total));
			memcpy(p, ptr + 2, ptr[1] - 2);
			p += ptr[1] - 2;
			ptr += ptr[1];
		}

		decode = buffer;
		decode_end = buffer + total;
	} else {
		decode = data + 2;
		decode_end = data + data[1];
	}

	FR_PROTO_HEX_DUMP(decode, decode_end - decode, "NAS-Filter-Rule coalesced");

	/*
	 *	And now walk through "decode", decoding to VPs.
	 */
	while (decode < decode_end) {
		size_t len;
		uint8_t const *p;

		p = decode;

		while (p < decode_end) {
			if (*p == 0x00) break;
			p++;
		}

		len = (p - decode);
		if (len) {
			fr_pair_t *vp;

			FR_PROTO_TRACE("This NAS-Filter-Rule has %lu octets", len);
			FR_PROTO_HEX_DUMP(decode, len, "This NAS-Filter-Rule");
			vp = fr_pair_afrom_da(ctx, parent);
			if (!vp) {
				talloc_free(buffer);
				return -1;
			}
			PAIR_ALLOCED(vp);

			if (fr_pair_value_bstrndup(vp, (char const *) decode, len, true) != 0) {
				talloc_free(buffer);
				talloc_free(vp);
				return -1;
			}
			fr_pair_append(out, vp);
		}

		/*
		 *	Skip the zero byte
		 */
		decode = p + 1;
	}

	talloc_free(buffer);
	return end - data;	/* end of the NAS-Filter-Rule */
}


/** Decode Digest-Attributes
 *
 *  The VPs are nested, and consecutive Digest-Attributes attributes are decoded into the same parent.
 */
static ssize_t decode_digest_attributes(TALLOC_CTX *ctx, fr_pair_list_t *out,
					fr_dict_attr_t const *parent, uint8_t const *data,
					size_t const data_len, fr_radius_decode_ctx_t *packet_ctx)
{
	ssize_t slen;
	fr_pair_t *vp;
	uint8_t const *p = data;
	uint8_t const *end = data + data_len;

	fr_assert(parent->type == FR_TYPE_TLV);

	vp = fr_pair_afrom_da(ctx, parent);
	if (!vp) return PAIR_DECODE_OOM;
	PAIR_ALLOCED(vp);

redo:
	FR_PROTO_HEX_DUMP(p, end - p, "decode_digest_attributes");

	if (((size_t) (p - end) < 2) || (p[1] > (size_t) (end - p))) {
		slen = fr_pair_raw_from_network(vp, &vp->vp_group, parent, p, end - p);
		if (slen < 0) {
			talloc_free(vp);
			return slen;
		}

		goto done;
	}

	slen = fr_pair_tlvs_from_network(vp, &vp->vp_group, parent, p + 2, p[1] - 2, packet_ctx, decode_rfc, NULL, false);
	if (slen <= 0) {
		talloc_free(vp);
		return slen;
	}

	/*
	 *	Decode consecutive ones into the same parent.
	 */
	p += p[1];
	if (((p + 2) < end) && ((p[0] == FR_DIGEST_ATTRIBUTES) && (p[1] > 2))) {
		goto redo;
	}

done:
	fr_pair_append(out, vp);
	return p - data;
}


/** Convert TLVs to one or more VPs
 *
 */
ssize_t fr_radius_decode_tlv(TALLOC_CTX *ctx, fr_pair_list_t *out,
			     fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len,
			     fr_radius_decode_ctx_t *packet_ctx)
{
	uint8_t const		*p = data, *end = data + data_len;
	fr_dict_attr_t const	*child;
	fr_pair_list_t		head;
	fr_pair_list_t		tlv_tmp;
	fr_pair_t		*vp;

	fr_pair_list_init(&head);
	if (data_len < 3) return -1; /* type, length, value */

#ifdef STATIC_ANALYZER
	if (!packet_ctx->tmp_ctx) return -1;
#endif

	FR_PROTO_HEX_DUMP(p, data_len, "tlvs");

	if (fr_radius_decode_tlv_ok(p, data_len, 1, 1) < 0) return -1;

	vp = fr_pair_afrom_da(ctx, parent);
	if (!vp) return PAIR_DECODE_OOM;
	PAIR_ALLOCED(vp);

	/*
	 *  Record where we were in the list when this function was called
	 *	 Create a temporary sub-list, so decode errors don't
	 *	 affect the main list.
	 */
	fr_pair_list_init(&tlv_tmp);
	while (p < end) {
		ssize_t tlv_len;

		child = fr_dict_attr_child_by_num(parent, p[0]);
		if (!child) {
			FR_PROTO_TRACE("Failed to find child %u of TLV %s", p[0], parent->name);

			/*
			 *	Child is unknown and not a TLV: build an unknown attr
			 */
			if (fr_radius_decode_tlv_ok(p + 2, p[1] - 2, 1, 1) < 0) {
				child = fr_dict_attr_unknown_raw_afrom_num(packet_ctx->tmp_ctx, parent, p[0]);
				if (!child) {
				error:
					talloc_free(vp);
					return -1;
				}
			} else {
				/*
				 *	Child is formed as a TLV, decode it as such
				 */
				child = fr_dict_attr_unknown_typed_afrom_num(packet_ctx->tmp_ctx, parent, p[0], FR_TYPE_TLV);
				if (!child) goto error;

				FR_PROTO_TRACE("decode context changed %s -> %s", parent->name, child->name);
				tlv_len = fr_radius_decode_tlv(vp, &tlv_tmp, child, p + 2, p[1] - 2, packet_ctx);
				goto check;
			}
		}
		FR_PROTO_TRACE("decode context changed %s -> %s", parent->name, child->name);

		tlv_len = fr_radius_decode_pair_value(vp, &tlv_tmp,
						      child, p + 2, p[1] - 2,
						      packet_ctx);
	check:
		if (tlv_len < 0) goto error;
		p += p[1];
	}

	fr_pair_list_append(&vp->vp_group, &tlv_tmp);
	fr_pair_append(out, vp);

	return data_len;
}

/** Convert a top-level VSA to a VP.
 *
 * "length" can be LONGER than just this sub-vsa.
 */
static ssize_t decode_vsa_internal(TALLOC_CTX *ctx, fr_pair_list_t *out,
				   fr_dict_attr_t const *parent,
				   uint8_t const *data, size_t data_len,
				   fr_radius_decode_ctx_t *packet_ctx, fr_dict_vendor_t const *dv)
{
	unsigned int		attribute;
	ssize_t			attrlen, my_len;
	fr_dict_attr_t const	*da;

#ifdef STATIC_ANALYZER
	if (!packet_ctx->tmp_ctx) return -1;
#endif

	/*
	 *	Parent must be a vendor
	 */
	if (!fr_cond_assert(parent->type == FR_TYPE_VENDOR)) {
		fr_strerror_printf("%s: Internal sanity check failed", __FUNCTION__);
		return -1;
	}

	FR_PROTO_TRACE("Length %u", (unsigned int)data_len);

#ifndef NDEBUG
	if (data_len <= (dv->type + dv->length)) {
		fr_strerror_printf("%s: Failure to call fr_radius_decode_tlv_ok", __FUNCTION__);
		return -1;
	}
#endif

	switch (dv->type) {
	case 4:
		/* data[0] must be zero */
		attribute = data[1] << 16;
		attribute |= data[2] << 8;
		attribute |= data[3];
		break;

	case 2:
		attribute = data[0] << 8;
		attribute |= data[1];
		break;

	case 1:
		attribute = data[0];
		break;

	default:
		fr_strerror_printf("%s: Internal sanity check failed", __FUNCTION__);
		return -1;
	}

	switch (dv->length) {
	case 2:
		/* data[dv->type] must be zero, from fr_radius_decode_tlv_ok() */
		attrlen = data[dv->type + 1];
		break;

	case 1:
		attrlen = data[dv->type];
		break;

	case 0:
		attrlen = data_len;
		break;

	default:
		fr_strerror_printf("%s: Internal sanity check failed", __FUNCTION__);
		return -1;
	}

	/*
	 *	See if the VSA is known.
	 */
	da = fr_dict_attr_child_by_num(parent, attribute);
	if (da) {
	decode:
		FR_PROTO_TRACE("decode context changed %s -> %s", da->parent->name, da->name);

		my_len = fr_radius_decode_pair_value(ctx, out,
						     da, data + dv->type + dv->length,
						     attrlen - (dv->type + dv->length),
						     packet_ctx);
		if (my_len < 0) return my_len;

		/*
		 *	It's unknown.  Let's see if we can decode it as a TLV.  While this check can sometimes
		 *	(rarely) decode non-TLVs as TLVs, that situation will be rare.  And it's very useful
		 *	to be able to decode nested unknown TLVs.
		 *
		 *	Note that if the TLV length is zero, then we have no real way to tell if the TLV is
		 *	well formed, so we just go create a raw VP.
		 */
	} else if ((dv->length == 0) || (fr_radius_decode_tlv_ok(data + dv->type + dv->length, attrlen - (dv->type + dv->length), dv->type, dv->length) < 0)) {
		da = fr_dict_attr_unknown_raw_afrom_num(packet_ctx->tmp_ctx, parent, attribute);
		if (!da) return -1;

		goto decode;

	} else {
		da = fr_dict_attr_unknown_typed_afrom_num(packet_ctx->tmp_ctx, parent, attribute, FR_TYPE_TLV);
		if (!da) return -1;

		goto decode;
	}

	return attrlen;
}


/** Convert a fragmented extended attr to a VP
 *
 * Format is:
 *
 * attr
 * length
 * extended-attr
 * flag
 * data...
 *
 * But for the first fragment, we get passed a pointer to the "extended-attr"
 */
static ssize_t decode_extended_fragments(TALLOC_CTX *ctx, fr_pair_list_t *out,
					 fr_dict_attr_t const *parent,
					 uint8_t const *data, size_t attr_len,
					 fr_radius_decode_ctx_t *packet_ctx)
{
	ssize_t		ret;
	size_t		fraglen;
	uint8_t		*head, *tail;
	uint8_t const	*frag, *end;
	uint8_t const	*attr;
	int		fragments;
	bool		last_frag;

	/*
	 *	data = Ext-Attr Flag ...
	 */

	if (attr_len < 3) return -1;

	/*
	 *	No continuation, just decode the attribute in place.
	 */
	if ((data[1] & 0x80) == 0) {
		ret = fr_radius_decode_pair_value(ctx, out,
						  parent, data + 2, attr_len - 2, packet_ctx);
		if (ret < 0) return -1;
		return attr_len;
	}

	/*
	 *	Calculate the length of all of the fragments.  For
	 *	now, they MUST be contiguous in the packet, and they
	 *	MUST be all of the same TYPE and EXTENDED-TYPE
	 */
	attr = data - 2;
	fraglen = attr_len - 2;
	frag = data + attr_len;
	end = packet_ctx->end;
	fragments = 1;
	last_frag = false;

	while (frag < end) {
		if (last_frag || ((end - frag) < 4) ||
		    (frag[0] != attr[0]) ||
		    (frag[1] < 4) ||		       /* too short for long_extended */
		    (frag[2] != attr[2]) ||
		    ((frag + frag[1]) > end)) {		/* overflow */
			end = frag;
			break;
		}

		last_frag = ((frag[3] & 0x80) == 0);

		fraglen += frag[1] - 4;
		frag += frag[1];
		fragments++;
	}

	head = tail = talloc_array(ctx, uint8_t, fraglen);
	if (!head) return -1;

	FR_PROTO_TRACE("Fragments %d, total length %d", fragments, (int) fraglen);

	/*
	 *	And again, but faster and looser.
	 *
	 *	We copy the first fragment, followed by the rest of
	 *	the fragments.
	 */
	frag = attr;

	while (fragments >  0) {
		if (frag[1] > 4) memcpy_bounded(tail, frag + 4, frag[1] - 4, end);
		tail += frag[1] - 4;
		frag += frag[1];
		fragments--;
	}

	FR_PROTO_HEX_DUMP(head, fraglen, "long_extended fragments");

	/*
	 *	Reset the "end" pointer, because we're not passing in
	 *	the real data.
	 */
	{
		uint8_t const *tmp = packet_ctx->end;
		packet_ctx->end = head + fraglen;

		ret = fr_radius_decode_pair_value(ctx, out,
						  parent, head, fraglen, packet_ctx);

		packet_ctx->end = tmp;
	}

	talloc_free(head);
	if (ret < 0) return ret;

	return end - data;
}

/** Fast path for most extended attributes.
 *
 *  data_len has already been checked by the caller, so we don't care
 *  about it here.
 */
static ssize_t decode_extended(TALLOC_CTX *ctx, fr_pair_list_t *out,
			       fr_dict_attr_t const *da,
			       uint8_t const *data, UNUSED size_t data_len,
			       fr_radius_decode_ctx_t *packet_ctx)
{
	ssize_t slen;
	fr_dict_attr_t const *child;
	fr_pair_t	*vp;

	/*
	 *	They MUST have one byte of Extended-Type.  The
	 *	case of "2" is already handled above with CUI.
	 */
	if (data[1] == 3) {
		slen = fr_pair_raw_from_network(ctx, out, da, data + 2, 1);
		if (slen <= 0) return slen;
		return 2 + slen;
	}

	/*
	 *	Get a new child.
	 */
	child = fr_dict_attr_child_by_num(da, data[2]);
	if (!child) {
		fr_dict_attr_t *unknown;
		FR_PROTO_TRACE("Unknown extended attribute %u.%u", data[0], data[2]);
		unknown = fr_dict_attr_unknown_raw_afrom_num(packet_ctx->tmp_ctx, da, data[2]);
		if (!unknown) return -1;

		child = unknown;
	}

	/*
	 *	One byte of type, and N bytes of data.
	 */
	if (!fr_radius_flag_long_extended(da)) {
		if (fr_pair_find_or_append_by_da(ctx, &vp, out, da) < 0) return PAIR_DECODE_OOM;

		slen = fr_radius_decode_pair_value(vp, &vp->vp_group, child, data + 3, data[1] - 3, packet_ctx);
		fr_dict_attr_unknown_free(&child);
		if (slen < 0 ) return slen;

		fr_assert(slen < (1 << 16));
		return 3 + slen;
	}

	/*
	 *	It MUST have one byte of type, and one byte of
	 *	flags.  If there's no data here, we just
	 *	ignore it, whether or not the "More" bit is
	 *	set.
	 */
	if (data[1] == 4) {
		fr_dict_attr_unknown_free(&child);
		slen = fr_pair_raw_from_network(ctx, out, da, data + 2, 2);
		if (slen < 0) return slen;
		return 4;
	}

	if (fr_pair_find_or_append_by_da(ctx, &vp, out, da) < 0) return PAIR_DECODE_OOM;

	/*
	 *	No continuation - just decode as-is.
	 */
	if ((data[3] & 0x80) == 0) {
		slen = fr_radius_decode_pair_value(vp, &vp->vp_group, child, data + 4, data[1] - 4, packet_ctx);
		fr_dict_attr_unknown_free(&child);
		if (slen < 0 ) return slen;
		return 4 + slen;
	}

	/*
	 *	Concatenate all of the fragments together, and decode the resulting thing.
	 */
	slen = decode_extended_fragments(vp, &vp->vp_group, child, data + 2, data[1] - 2, packet_ctx);
	fr_dict_attr_unknown_free(&child);
	if (slen < 0) return slen;
	return 2 + slen;
}

/** Convert a Vendor-Specific WIMAX to vps
 *
 * @note Called ONLY for Vendor-Specific
 */
static ssize_t decode_wimax(TALLOC_CTX *ctx, fr_pair_list_t *out,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t attr_len,
			    fr_radius_decode_ctx_t *packet_ctx)
{
	ssize_t			ret;
	size_t			wimax_len;
	bool			more;
	uint8_t			*head, *tail;
	uint8_t	const		*attr, *end;
	fr_dict_attr_t const	*da;
	fr_pair_t		*vsa, *vendor;

#ifdef STATIC_ANALYZER
	if (!packet_ctx->tmp_ctx) return -1;
#endif

	fr_assert(packet_ctx->end != NULL);
	fr_assert((data + attr_len) <= packet_ctx->end);

	/*
	 *	data = VID VID VID VID WiMAX-Attr WiMAX-Len Continuation ...
	 */
	if (attr_len < 8) {
		FR_PROTO_TRACE("attribute is too small to be WiMAX");
		return -1;
	}

	/*
	 *	WiMAX-Attr WiMAX-Len Continuation
	 */
	if (data[5] < 3) {
		FR_PROTO_TRACE("attribute is too small to be WiMAX-Attr-WiMAX-Len Continuation");
		return -1;
	}

	/*
	 *	The WiMAX-Len + 4 VID must exactly fill the attribute.
	 */
	if (((size_t) (data[5] + 4)) != attr_len) {
		FR_PROTO_TRACE("WiMAX VSA does not exactly fill the attribute");
		return -1;
	}

	if (fr_pair_find_or_append_by_da(ctx, &vsa, out, attr_vendor_specific) < 0) return PAIR_DECODE_OOM;

	if (fr_pair_find_or_append_by_da(vsa, &vendor, &vsa->vp_group, parent) < 0) return PAIR_DECODE_OOM;

	da = fr_dict_attr_child_by_num(parent, data[4]);
	if (!da) da = fr_dict_attr_unknown_raw_afrom_num(packet_ctx->tmp_ctx, parent, data[4]);
	if (!da) return -1;
	FR_PROTO_TRACE("decode context changed %s -> %s", da->parent->name, da->name);

	/*
	 *	No continuation, just decode the attribute in place.
	 */
	if ((data[6] & 0x80) == 0) {
		FR_PROTO_TRACE("WiMAX no continuation");
		ret = fr_radius_decode_pair_value(vendor, &vendor->vp_group,
						  da, data + 7, data[5] - 3, packet_ctx);
		if (ret < 0) return ret;

		return attr_len;
	}

	/*
	 *	Calculate the length of all of the fragments.  For
	 *	now, they MUST be contiguous in the packet, and they
	 *	MUST be all of the same VSA, WiMAX, and WiMAX-attr.
	 *
	 *	The first fragment doesn't have a RADIUS attribute
	 *	header.
	 */
	wimax_len = 0;
	attr = data + 4;
	end = packet_ctx->end;

	while (attr < end) {
		/*
		 *	Not enough room for Attribute + length +
		 *	continuation, it's bad.
		 */
		if ((end - attr) < 3) {
			FR_PROTO_TRACE("end - attr < 3");
			return -1;
		}

		/*
		 *	Must have non-zero data in the attribute.
		 */
		if (attr[1] <= 3) {
			FR_PROTO_TRACE("attr[1] <= 3");
			return -1;
		}

		/*
		 *	If the WiMAX attribute overflows the packet,
		 *	it's bad.
		 */
		if ((attr + attr[1]) > end) {
			FR_PROTO_TRACE("attr + attr[1]) > end");
			return -1;
		}

		/*
		 *	Check the continuation flag.
		 */
		more = ((attr[2] & 0x80) != 0);

		/*
		 *	Or, there's no more data, in which case we
		 *	shorten "end" to finish at this attribute.
		 */
		if (!more) end = attr + attr[1];

		/*
		 *	There's more data, but we're at the end of the
		 *	packet.  The attribute is malformed!
		 */
		if (more && ((attr + attr[1]) == end)) {
			FR_PROTO_TRACE("more && ((attr + attr[1]) == end)");
			return -1;
		}

		/*
		 *	Add in the length of the data we need to
		 *	concatenate together.
		 */
		wimax_len += attr[1] - 3;

		/*
		 *	Go to the next attribute, and stop if there's
		 *	no more.
		 */
		attr += attr[1];
		if (!more) break;

		/*
		 *	data = VID VID VID VID WiMAX-Attr WimAX-Len Continuation ...
		 *
		 *	attr = Vendor-Specific VSA-Length VID VID VID VID WiMAX-Attr WimAX-Len Continuation ...
		 *
		 */

		/*
		 *	No room for Vendor-Specific + length +
		 *	Vendor(4) + attr + length + continuation + data
		 */
		if ((end - attr) < 9) {
			FR_PROTO_TRACE("(end - attr) < 9");
			return -1;
		}

		if (attr[0] != FR_VENDOR_SPECIFIC) {
			FR_PROTO_TRACE("attr[0] != FR_VENDOR_SPECIFIC");
			return -1;
		}

		if (attr[1] < 9) {
			FR_PROTO_TRACE("attr[1] < 9");
			return -1;
		}

		if ((attr + attr[1]) > end) {
			FR_PROTO_TRACE("(attr + attr[1]) > end");
			return -1;
		}

		if (memcmp(data, attr + 2, 4) != 0) {
			FR_PROTO_TRACE("not the same vendor");
			return -1; /* not WiMAX Vendor ID */
		}

		if (attr[1] != (attr[7] + 6)) {
			FR_PROTO_TRACE("attr[1] != (attr[7] + 6)");
			return -1; /* WiMAX attr doesn't exactly fill the VSA */
		}

		if (data[4] != attr[6]) {
			FR_PROTO_TRACE("data[4] != attr[6]");
			return -1; /* different WiMAX attribute */
		}

		/*
		 *	Skip over the Vendor-Specific header, and
		 *	continue with the WiMAX attributes.
		 */
		attr += 6;
	}

	/*
	 *	No data in the WiMAX attribute, make a "raw" one.
	 */
	if (!wimax_len) {
		FR_PROTO_TRACE("!wimax_len");
		return -1;
	}

	head = tail = talloc_array(ctx, uint8_t, wimax_len);
	if (!head) return -1;

	/*
	 *	Copy the data over, this time trusting the attribute
	 *	contents.
	 */
	attr = data;
	while (attr < end) {
		memcpy_bounded(tail, attr + 4 + 3, attr[4 + 1] - 3, end);
		tail += attr[4 + 1] - 3;
		attr += 4 + attr[4 + 1]; /* skip VID+WiMax header */
		attr += 2;		 /* skip Vendor-Specific header */
	}

	FR_PROTO_HEX_DUMP(head, wimax_len, "Wimax fragments");

	/*
	 *	Reset the "end" pointer, because we're not passing in
	 *	the real data.
	 */
	{
		uint8_t const *tmp = packet_ctx->end;
		packet_ctx->end = head + wimax_len;

		FR_PROTO_TRACE("WiMAX decode concatenated");
		FR_PROTO_HEX_DUMP(head, wimax_len, "%s", __FUNCTION__ );
		ret = fr_radius_decode_pair_value(ctx, out,
						  da, head, wimax_len, packet_ctx);

		packet_ctx->end = tmp;
	}

	talloc_free(head);
	if (ret < 0) return ret;

	return end - data;
}


/** Convert a top-level VSA to one or more VPs
 *
 */
static ssize_t  CC_HINT(nonnull) decode_vsa(TALLOC_CTX *ctx, fr_pair_list_t *out,
					    fr_dict_attr_t const *parent,
					    uint8_t const *data, size_t attr_len,
					    fr_radius_decode_ctx_t *packet_ctx)
{
	size_t			total;
	ssize_t			ret;
	uint32_t		vendor_pen;
	fr_dict_vendor_t const	*dv;
	fr_pair_list_t		head;
	fr_dict_vendor_t	my_dv;
	fr_dict_attr_t const	*vendor_da;
	fr_pair_list_t		tlv_tmp;
	fr_pair_t		*vsa, *vendor;

	fr_pair_list_init(&head);

#ifdef STATIC_ANALYZER
	if (!packet_ctx->tmp_ctx) return -1;
#endif

	/*
	 *	Container must be a VSA
	 */
	if (!fr_cond_assert(parent->type == FR_TYPE_VSA)) return -1;

	if ((data + attr_len) > packet_ctx->end) return -1;
	if (attr_len < 5) return -1; /* vid, value */
	if (data[0] != 0) return -1; /* we require 24-bit VIDs */

	FR_PROTO_TRACE("Decoding VSA");

	memcpy(&vendor_pen, data, 4);
	vendor_pen = ntohl(vendor_pen);

	/*
	 *	Verify that the parent (which should be a VSA)
	 *	contains a fake attribute representing the vendor.
	 *
	 *	If it doesn't then this vendor is unknown, but
	 *	(unlike DHCP) we know vendor attributes have a
	 *	standard format, so we can decode the data anyway.
	 */
	vendor_da = fr_dict_attr_child_by_num(parent, vendor_pen);
	if (!vendor_da) {
		fr_dict_attr_t *n;
		/*
		 *	RFC format is 1 octet type, 1 octet length
		 */
		if (fr_radius_decode_tlv_ok(data + 4, attr_len - 4, 1, 1) < 0) {
			FR_PROTO_TRACE("Unknown TLVs not OK: %s", fr_strerror());
			return -1;
		}

		n = fr_dict_attr_unknown_vendor_afrom_num(packet_ctx->tmp_ctx, parent, vendor_pen);
		if (!n) return -1;
		vendor_da = n;

		fr_assert(vendor_da->flags.type_size == 1);

		/*
		 *	Create an unknown DV too...
		 */
		memset(&my_dv, 0, sizeof(my_dv));

		my_dv.pen = vendor_pen;
		my_dv.type = 1;
		my_dv.length = 1;

		dv = &my_dv;

		goto create_attrs;
	}

	/*
	 *	We found an attribute representing the vendor
	 *	so it *MUST* exist in the vendor tree.
	 */
	dv = fr_dict_vendor_by_num(dict_radius, vendor_pen);
	if (!fr_cond_assert(dv)) return -1;
	FR_PROTO_TRACE("decode context %s -> %s", parent->name, vendor_da->name);

	/*
	 *	WiMAX craziness
	 */
	if (dv->continuation) {
		ret = decode_wimax(ctx, out, vendor_da, data, attr_len, packet_ctx);
		return ret;
	}

	/*
	 *	VSAs should normally be in TLV format.
	 */
	if (fr_radius_decode_tlv_ok(data + 4, attr_len - 4, dv->type, dv->length) < 0) {
		FR_PROTO_TRACE("TLVs not OK: %s", fr_strerror());
		return -1;
	}

	/*
	 *	There may be more than one VSA in the
	 *	Vendor-Specific.  If so, loop over them all.
	 */
create_attrs:
	if (fr_pair_find_or_append_by_da(ctx, &vsa, out, parent) < 0) return PAIR_DECODE_OOM;

	if (fr_pair_find_or_append_by_da(vsa, &vendor, &vsa->vp_group, vendor_da) < 0) return PAIR_DECODE_OOM;

	data += 4;
	attr_len -= 4;
	total = 4;

	fr_pair_list_init(&tlv_tmp);
	while (attr_len > 0) {
		ssize_t vsa_len;

		/*
		 *	Vendor attributes can have subattributes (if you hadn't guessed)
		 */
		vsa_len = decode_vsa_internal(vendor, &tlv_tmp,
					      vendor_da, data, attr_len, packet_ctx, dv);
		if (vsa_len < 0) {
			FR_PROTO_TRACE("TLV decode failed: %s", fr_strerror());
			fr_strerror_printf("%s: Internal sanity check %d", __FUNCTION__, __LINE__);
			fr_pair_list_free(&tlv_tmp);
			return -1;
		}

		data += vsa_len;
		attr_len -= vsa_len;
		total += vsa_len;
	}
	fr_pair_list_append(&vendor->vp_group, &tlv_tmp);

	/*
	 *	Hacks for tags.  The tagged VSAs don't go into the
	 *	root, they go into the Tag-# attribute.  But we only
	 *	know that after we've created the parents.  So clean up if necessary.
	 *
	 *	@todo - maybe cache these somewhere to avoid bouncing.
	 */
	if (fr_pair_list_num_elements(&vendor->vp_group) == 0) {
		if (fr_pair_list_num_elements(&vsa->vp_group) == 1) { /* only the vendor */
			fr_pair_delete(out, vsa);
		} else {
			fr_pair_delete(&vsa->vp_group, vendor);
		}
	}

	/*
	 *	When the unknown attributes were created by
	 *	decode_vsa_internal, the hierarchy between that unknown
	 *	attribute and first known attribute was cloned
	 *	meaning we can now free the unknown vendor.
	 */

	return total;
}

/** Wrapper called by fr_struct_from_network()
 *
 *  Because extended attributes can continue across the current value.
 *  So that function needs to know both the value length, *and* the
 *  packet length.  But when we're decoding values inside of a struct,
 *  we're not using extended attributes.
 */
static ssize_t decode_value_trampoline(TALLOC_CTX *ctx, fr_pair_list_t *out,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t data_len, void *decode_ctx)
{
	return fr_radius_decode_pair_value(ctx, out, parent, data, data_len, decode_ctx);
}

/** Wrapper called by fr_struct_from_network()
 */
static ssize_t decode_tlv_trampoline(TALLOC_CTX *ctx, fr_pair_list_t *out,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t data_len, void *decode_ctx)
{
	FR_PROTO_HEX_DUMP(data, data_len, "%s", __FUNCTION__ );

	return fr_radius_decode_tlv(ctx, out, parent, data, data_len, decode_ctx);
}


/** Create any kind of VP from the attribute contents
 *
 *  "length" is AT LEAST the length of this attribute, as we
 *  expect the caller to have verified the data with
 *  fr_packet_ok().  "length" may be up to the length of the
 *  packet.
 *
 *  This function will ONLY return -1 on programmer error or OOM.  If
 *  there's anything wrong with the attribute, it will ALWAYS create a
 *  "raw" attribute.
 *
 * @return
 *	- Length on success.
 *	- -1 on failure.
 */
ssize_t fr_radius_decode_pair_value(TALLOC_CTX *ctx, fr_pair_list_t *out,
				    fr_dict_attr_t const *parent,
				    uint8_t const *data, size_t const attr_len,
				    void *decode_ctx)
{
	int8_t			tag = 0;
	size_t			data_len;
	ssize_t			ret;
	fr_dict_attr_t const	*child;
	fr_pair_t		*vp = NULL;
	uint8_t const		*p = data;
	uint8_t			buffer[256];
	fr_radius_attr_flags_encrypt_t encrypt;
	fr_radius_decode_ctx_t *packet_ctx = decode_ctx;

	if (attr_len > 128 * 1024) {
		fr_strerror_printf("%s: packet is too large to be RADIUS", __FUNCTION__);
		return -1;
	}

	if ((data + attr_len) > packet_ctx->end) {
		fr_strerror_printf("%s: input overflows packet", __FUNCTION__);
		return -1;
	}

	FR_PROTO_HEX_DUMP(data, attr_len, "%s", __FUNCTION__ );

	FR_PROTO_TRACE("Parent %s len %zu ... %zu", parent->name, attr_len, (size_t) (packet_ctx->end - data));

	data_len = attr_len;

	/*
	 *	Silently ignore zero-length attributes.
	 */
	if (attr_len == 0) return 0;

	/*
	 *	Hacks for tags.
	 */
	if (fr_radius_flag_has_tag(parent)) {
		/*
		 *	Check for valid tags and data types.
		 */
		if (parent->type == FR_TYPE_UINT32) {
			if ((attr_len != 4) || (p[0] >= 0x20)) {
				goto raw;
			}

		} else if (parent->type != FR_TYPE_STRING) {
			goto raw;
		}

		/*
		 *	Tag values MUST be less than 32.
		 */
		if (p[0] < 0x20) {
			/*
			 *	Only "short" attributes can be encrypted.
			 */
			if (data_len >= sizeof(buffer)) goto raw;

			if (parent->type == FR_TYPE_STRING) {
				memcpy(buffer, p + 1, data_len - 1);
				tag = p[0];
				data_len -= 1;

			} else if (parent->type == FR_TYPE_UINT32) {
				memcpy(buffer, p, attr_len);
				tag = buffer[0];
				buffer[0] = 0;
			}

			p = buffer;

		} /* else the field is >=0x20, so it's not a tag */
	}

	if (tag) {
		fr_radius_tag_ctx_t **new_tag_ctx = NULL;

		if (!packet_ctx->tags) {
			/*
			 *	This should NOT be packet_ctx.tmp_ctx,
			 *	as that is freed after decoding every
			 *	packet.  We wish to aggregate the tags
			 *	across multiple attributes.
			 */
			new_tag_ctx = talloc_zero_array(NULL, fr_radius_tag_ctx_t *, 32);
			if (unlikely(!new_tag_ctx)) return PAIR_DECODE_OOM;

			FR_PROTO_TRACE("Allocated tag cache %p", new_tag_ctx);

			packet_ctx->tags = new_tag_ctx;
		}

		fr_assert(tag < 0x20);

		if (!packet_ctx->tags[tag]) {
			fr_pair_t		*group;
			fr_dict_attr_t const	*group_da;

			packet_ctx->tags[tag] = talloc_zero(packet_ctx->tags, fr_radius_tag_ctx_t);
			if (unlikely(!packet_ctx->tags[tag])) {
				if (new_tag_ctx) TALLOC_FREE(packet_ctx->tags);
				return PAIR_DECODE_OOM;
			}

			group_da = fr_dict_attr_child_by_num(fr_dict_root(dict_radius), FR_TAG_BASE + tag);
			if (unlikely(!group_da)) {
			tag_alloc_error:
				TALLOC_FREE(packet_ctx->tags[tag]);
				return PAIR_DECODE_OOM;
			}

			group = fr_pair_afrom_da(packet_ctx->tag_root_ctx, group_da);
			if (unlikely(!group)) goto tag_alloc_error;
			PAIR_ALLOCED(group);

			packet_ctx->tags[tag]->parent = group;

			FR_PROTO_TRACE("Allocated tag attribute %p (%u)", group, tag);

			fr_pair_append(packet_ctx->tag_root, group);
#ifdef TALLOC_GET_TYPE_ABORT_NOOP
		}
#else
		} else {
			talloc_get_type_abort(packet_ctx->tags, fr_radius_tag_ctx_t *);
			talloc_get_type_abort(packet_ctx->tags[tag], fr_radius_tag_ctx_t);
			talloc_get_type_abort(packet_ctx->tags[tag]->parent, fr_pair_t);
		}
#endif
	}

	encrypt = fr_radius_flag_encrypted(parent);
	/*
	 *	Decrypt the attribute.
	 */
	if (encrypt) {
		FR_PROTO_TRACE("Decrypting type %d", encrypt);
		/*
		 *	Encrypted attributes can only exist for the
		 *	old-style format.  Extended attributes CANNOT
		 *	be encrypted.
		 */
		if (attr_len > 253) goto raw;

		if (p == data) memcpy(buffer, p, attr_len);
		p = buffer;

		switch (encrypt) { /* can't be tagged */
		/*
		 *  User-Password
		 */
		case RADIUS_FLAG_ENCRYPT_USER_PASSWORD:
			if (!packet_ctx->request_authenticator) goto raw;

			fr_radius_decode_password((char *)buffer, attr_len, packet_ctx);
			buffer[253] = '\0';

			/*
			 *	MS-CHAP-MPPE-Keys are 24 octets, and
			 *	encrypted.  Since it's binary, we can't
			 *	look for trailing zeros.
			 */
			if (parent->flags.length) {
				if (data_len > parent->flags.length) {
					data_len = parent->flags.length;
				} /* else leave data_len alone */
			} else {
				/*
				 *	Take off trailing zeros from the END.
				 *	This allows passwords to have zeros in
				 *	the middle of a field.
				 *
				 *	However, if the password has a zero at
				 *	the end, it will get mashed by this
				 *	code.  There's really no way around
				 *	that.
				 */
				while ((data_len > 0) && (buffer[data_len - 1] == '\0')) data_len--;
			}
			break;

		/*
		 *	Tunnel-Password's go in response packets,
		 *	except for CoA-Requests.  They can have a tag,
		 *	so data_len is not the same as attrlen.
		 */
		case RADIUS_FLAG_ENCRYPT_TUNNEL_PASSWORD:
			if (!packet_ctx->request_authenticator) goto raw;

			if (fr_radius_decode_tunnel_password(buffer, &data_len, packet_ctx) < 0) {
				goto raw;
			}
			break;

		/*
		 *	Ascend-Send-Secret
		 *	Ascend-Receive-Secret
		 */
		case RADIUS_FLAG_ENCRYPT_ASCEND_SECRET:
			if (!packet_ctx->request_authenticator) goto raw;

			fr_radius_ascend_secret(&FR_DBUFF_TMP(buffer, sizeof(buffer)), p, data_len,
						packet_ctx->common->secret, packet_ctx->request_authenticator);
			buffer[RADIUS_AUTH_VECTOR_LENGTH] = '\0';
			data_len = strlen((char *) buffer);
			break;

		default:
			/*
			 *	Chop the attribute to its maximum length.
			 */
			if ((parent->type == FR_TYPE_OCTETS) &&
			    (parent->flags.length && (data_len > parent->flags.length))) {
				    data_len = parent->flags.length;
			    }
			break;
		} /* switch over encryption flags */
	}

	/*
	 *	Double-check the length after decrypting the
	 *	attribute.
	 */
	FR_PROTO_TRACE("Type \"%s\" (%u)", fr_type_to_str(parent->type), parent->type);

	switch (parent->type) {
	case FR_TYPE_LEAF:
		break;

	case FR_TYPE_VSA:
		/*
		 *	VSAs in the RFC space are encoded one way.
		 *	VSAs in the "extended" space are different.
		 */
		if (!parent->parent || !fr_radius_flag_extended(parent->parent)) {
			/*
			 *	VSAs can be WiMAX, in which case they don't
			 *	fit into one attribute.
			 */
			ret = decode_vsa(ctx, out, parent, p, attr_len, packet_ctx);
			if (ret < 0) goto raw;
			return ret;

		} else {
			fr_dict_attr_t const	*vendor_da;
			fr_pair_t		*vsa, *vendor;
			uint32_t		vendor_pen;


			if (data_len < 6) goto raw; /* vid, vtype, value */

			memcpy(&vendor_pen, p, 4);
			vendor_pen = ntohl(vendor_pen);

			/*
			 *	For simplicity in our attribute tree, vendors are
			 *	represented as a subtlv(ish) of an EVS or VSA
			 *	attribute.
			 */
			vendor_da = fr_dict_attr_child_by_num(parent, vendor_pen);
			if (!vendor_da) {
				/*
				 *	If there's no child, it means the vendor is unknown.  Create a
				 *	temporary vendor in the packet_ctx.  This will be cleaned up when the
				 *	decoder exists, which is fine.  Because any unknown attributes which
				 *	depend on it will copy the entire hierarchy.
				 */
				vendor_da = fr_dict_attr_unknown_vendor_afrom_num(packet_ctx->tmp_ctx, parent, vendor_pen);
				if (!vendor_da) return PAIR_DECODE_OOM;
			}

			child = fr_dict_attr_child_by_num(vendor_da, p[4]);
			if (!child) {
				/*
				 *	Vendor exists but child didn't, create an unknown child.
				 */
				child = fr_dict_attr_unknown_raw_afrom_num(packet_ctx->tmp_ctx, vendor_da, p[4]);
				if (!child) {
					fr_strerror_printf_push("decoder failed creating unknown attribute in %s",
								parent->name);
					return -1;
				}
			}

			if (fr_pair_find_or_append_by_da(ctx, &vsa, out, parent) < 0) return PAIR_DECODE_OOM;

			if (fr_pair_find_or_append_by_da(vsa, &vendor, &vsa->vp_group, vendor_da) < 0) return PAIR_DECODE_OOM;

			/*
			 *	Everything was found in the dictionary, we can
			 *	now recurse to decode the value.
			 */
			ret = fr_radius_decode_pair_value(vendor, &vendor->vp_group,
							  child, p + 5, attr_len - 5,
							  packet_ctx);
			if (ret < 0) goto raw;
			return attr_len;
		}

	case FR_TYPE_TLV:
		/*
		 *	We presume that the TLVs all fit into one
		 *	attribute, OR they've already been grouped
		 *	into a contiguous memory buffer.
		 */
		ret = fr_radius_decode_tlv(ctx, out,  parent, p, attr_len, packet_ctx);
		if (ret < 0) goto raw;
		return attr_len;

	case FR_TYPE_STRUCT:
		/*
		 *	We presume that the struct fits into one
		 *	attribute, OR it's already been grouped
		 *	into a contiguous memory buffer.
		 */
		ret = fr_struct_from_network(ctx, out, parent, p, attr_len,
					     packet_ctx, decode_value_trampoline, decode_tlv_trampoline);
		if (ret < 0) goto raw;
		return attr_len;

	case FR_TYPE_GROUP:
	{
		fr_dict_attr_t const *ref;
		fr_dict_protocol_t const *proto;

		ref = fr_dict_attr_ref(parent);
		if (!ref) goto raw;

		fr_assert(ref->dict != parent->dict);

		proto = fr_dict_protocol(ref->dict);
		fr_assert(proto != NULL);

		if (!proto->decode) goto raw;

		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return -1;
		PAIR_ALLOCED(vp);

		ret = proto->decode(vp, &vp->vp_group, p, attr_len);
		if (ret < 0) goto raw;

		vp->vp_tainted = true;

		fr_pair_append(out, vp);
		return attr_len;
	}

	default:
	raw:
		if (vp) talloc_free(vp);

		return fr_pair_raw_from_network(ctx, out, parent, data, attr_len);
	}

	/*
	 *	And now that we've verified the basic type
	 *	information, decode the actual p.
	 */
	if (!tag) {
		vp = fr_pair_afrom_da(ctx, parent);
	} else {
		fr_assert(packet_ctx->tags != NULL);
		fr_assert(packet_ctx->tags[tag] != NULL);
		vp = fr_pair_afrom_da_nested(packet_ctx->tags[tag]->parent, &packet_ctx->tags[tag]->parent->vp_group, parent);
	}
	if (!vp) return -1;
	PAIR_ALLOCED(vp);

	switch (parent->type) {
	/*
	 *  RFC8044 IPv4 prefix
	 *
	 *  0                   1                   2                   3
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |    Reserved   | Prefix-Length |  Prefix ...
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      ... Prefix                 |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 *  The bits outside of the prefix mask MUST be zero.
	 */
	case FR_TYPE_IPV4_PREFIX:
		if (data_len != 6) goto raw;
		if (p[0] != 0) goto raw;

		if (fr_value_box_ipaddr_from_network(&vp->data, parent->type, parent,
						     p[1], p + 2, 4, true, true) < 0) {
			goto raw;
		}
		break;

	/*
	 *  RFC8044 IPv6 prefix
	 *
	 *   0                   1                   2                   3
	 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  |     Type      |    Length     |  Reserved     | Prefix-Length |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *                               Prefix
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *                               Prefix
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *                               Prefix
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *                               Prefix                             |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 *  The bits outside of the prefix mask MUST be zero.
	 */
	case FR_TYPE_IPV6_PREFIX:
	{
		if (data_len > 18) goto raw;
		if (data_len < 2) goto raw;
		if (p[0] != 0) goto raw;	/* First byte is always 0 */

		if (fr_value_box_ipaddr_from_network(&vp->data, parent->type, parent,
						     p[1], p + 2, data_len - 2, false, true) < 0) {
			goto raw;
		}

	}
		break;

	case FR_TYPE_STRING:
		if (!fr_radius_flag_abinary(parent)) goto decode;

		if (fr_radius_decode_abinary(vp, p, data_len) < 0) goto raw;
		break;

	case FR_TYPE_OCTETS:
		/*
		 *	This attribute SHOULD have fixed size, but it
		 *	doesn't.  Therefore it's malformed.
		 */
		if (parent->flags.length && (data_len != parent->flags.length)) goto raw;
		FALL_THROUGH;

	default:
	decode:
		ret = fr_value_box_from_network(vp, &vp->data, vp->vp_type, vp->da,
						&FR_DBUFF_TMP(p, data_len), data_len, true);
		if (ret < 0) {
			/*
			 *	Paranoid loop prevention
			 */
			if (vp->da->flags.is_unknown) {
				talloc_free(vp);
				return -1;
			}
			goto raw;
		}
		break;
	}

	vp->vp_tainted = true;

	if (!tag) fr_pair_append(out, vp);

	return attr_len;
}

/*
 *	Let's try to help the CPU as much as possible.  If we have a
 *	check on a buffer, that's less work than a series of if / then
 *	/ else conditions.
 */
static const bool special[UINT8_MAX + 1] = {
	[FR_NAS_FILTER_RULE]	= true,		/* magic rules */
	[FR_DIGEST_ATTRIBUTES]	= true,		/* magic rules */

	[FR_EAP_MESSAGE]	= true,		/* concat */
	[FR_PKM_SS_CERT]	= true,		/* concat */
	[FR_PKM_CA_CERT]	= true,		/* concat */
	[FR_EAPOL_ANNOUNCEMENT] = true,		/* concat */

	[FR_EXTENDED_ATTRIBUTE_1] = true,
	[FR_EXTENDED_ATTRIBUTE_2] = true,
	[FR_EXTENDED_ATTRIBUTE_3] = true,
	[FR_EXTENDED_ATTRIBUTE_4] = true,
	[FR_EXTENDED_ATTRIBUTE_5] = true,
	[FR_EXTENDED_ATTRIBUTE_6] = true,
};

/** Create a "normal" fr_pair_t from the given data
 *
 */
ssize_t fr_radius_decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *out,
			      uint8_t const *data, size_t data_len, fr_radius_decode_ctx_t *packet_ctx)
{
	ssize_t			ret;
	fr_dict_attr_t const	*da;

	if ((data_len < 2) || (data[1] < 2) || (data[1] > data_len)) {
		fr_strerror_printf("%s: Insufficient data", __FUNCTION__);
		return -1;
	}

	/*
	 *	If we don't have a tag root already, then record where
	 *	we're putting the top level attributes and add the tags
	 *	there.
	 */
	if (!packet_ctx->tag_root) {
		packet_ctx->tag_root = out;
		packet_ctx->tag_root_ctx = ctx;
	}

	da = fr_dict_attr_child_by_num(fr_dict_root(dict_radius), data[0]);
	if (!da) {
		FR_PROTO_TRACE("Unknown attribute %u", data[0]);
		da = fr_dict_attr_unknown_raw_afrom_num(packet_ctx->tmp_ctx, fr_dict_root(dict_radius), data[0]);
	}
	if (!da) return -1;
	FR_PROTO_TRACE("decode context changed %s -> %s",da->parent->name, da->name);

	/*
	 *	Empty attributes are silently ignored, except for CUI.
	 */
	if (data[1] == 2) {
		fr_pair_t *vp;

		if (data[0] != FR_CHARGEABLE_USER_IDENTITY) {
			return 2;
		}

		/*
		 *	Hacks for CUI.  The WiMAX spec says that it can be
		 *	zero length, even though this is forbidden by the
		 *	RADIUS specs.  So... we make a special case for it.
		 *
		 *	We can't create a zero length attribute,
		 *	because the talloc API won't let us.  So, we
		 *	just create a fake attribute.
		 */
		vp = fr_pair_afrom_da(ctx, da);
		if (!vp) return -1;
		PAIR_ALLOCED(vp);

		/*
		 *	Ensure that it has a value.
		 */
		if (fr_pair_value_memdup(vp, (uint8_t const *) "", 0, false) < 0) {
			talloc_free(vp);
			return -1;
		}

		fr_pair_append(out, vp);

		return 2;
	}

	/*
	 *	A few attributes are special, but they're rare.
	 */
	if (unlikely(special[data[0]])) {
		if (data[0] == FR_NAS_FILTER_RULE) {
			return decode_nas_filter_rule(ctx, out, da, data, data_len, packet_ctx);
		}

		if (data[0] == FR_DIGEST_ATTRIBUTES) {
			return decode_digest_attributes(ctx, out, da, data, data_len, packet_ctx);
		}

		/*
		 *	Concatenate consecutive top-level attributes together.
		 */
		if (fr_radius_flag_concat(da)) {
			FR_PROTO_TRACE("Concat attribute");
			return decode_concat(ctx, out, da, data, packet_ctx->end);
		}

		/*
		 *	Extended attributes have a horrible format.
		 *	Try to deal with that here, so that the rest
		 *	of the code doesn't have to.
		 */
		if (fr_radius_flag_extended(da)) {
			return decode_extended(ctx, out, da, data, data_len, packet_ctx);
		}

		/*
		 *	@todo - pre-concatenate WiMAX, if 26, and dv->continuation, too.
		 */
	}

	/*
	 *	Note that we pass the entire length, not just the
	 *	length of this attribute.  The Extended or WiMAX
	 *	attributes may have the "continuation" bit set, and
	 *	will thus be more than one attribute in length.
	 */
	ret = fr_radius_decode_pair_value(ctx, out,
					  da, data + 2, data[1] - 2,
					  packet_ctx);
	if (ret < 0) return ret;

	fr_assert(ret < (1 << 16));

	return 2 + ret;
}

ssize_t fr_radius_decode_foreign(TALLOC_CTX *ctx, fr_pair_list_t *out,
				 uint8_t const *data, size_t data_len)
{
	ssize_t slen;
	uint8_t const *attr, *end;

	fr_radius_ctx_t common_ctx = {};
	fr_radius_decode_ctx_t decode_ctx = {
		.common = &common_ctx,
		.tmp_ctx = talloc(ctx, uint8_t),
		.end = data + data_len,
	};

	fr_assert(dict_radius != NULL);

	attr = data;
	end = decode_ctx.end;

	while (attr < end) {
		slen = fr_radius_decode_pair(ctx, out, attr, (end - attr), &decode_ctx);
		if (slen < 0) {
//		fail:
			talloc_free(decode_ctx.tmp_ctx);
			talloc_free(decode_ctx.tags);
			return slen;
		}

#if 0
		/*
		 *	If slen is larger than the room in the packet,
		 *	all kinds of bad things happen.
		 */
		 if (!fr_cond_assert(slen <= (end - attr))) {
			 goto fail;
		 }
#endif

		attr += slen;
		talloc_free_children(decode_ctx.tmp_ctx);
	}

	talloc_free(decode_ctx.tmp_ctx);
	talloc_free(decode_ctx.tags);
	return data_len;
}

static int _test_ctx_free(fr_radius_decode_ctx_t *ctx)
{
       TALLOC_FREE(ctx->tags);

       return 0;
}

static int decode_test_ctx(void **out, TALLOC_CTX *ctx, UNUSED fr_dict_t const *dict,
			   UNUSED fr_dict_attr_t const *root_da)
{
	static uint8_t vector[RADIUS_AUTH_VECTOR_LENGTH] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	fr_radius_decode_ctx_t	*test_ctx;
	fr_radius_ctx_t  	*common;

	test_ctx = talloc_zero(ctx, fr_radius_decode_ctx_t);
	test_ctx->common = common = talloc_zero(test_ctx, fr_radius_ctx_t);

	common->secret = talloc_strdup(test_ctx->common, "testing123");
	common->secret_length = talloc_array_length(test_ctx->common->secret) - 1;

	test_ctx->request_authenticator = vector;
	test_ctx->tmp_ctx = talloc_zero(test_ctx, uint8_t);
	talloc_set_destructor(test_ctx, _test_ctx_free);

	*out = test_ctx;

	return 0;
}

static ssize_t fr_radius_decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *out,
				      uint8_t const *data, size_t data_len, void *proto_ctx)
{
	fr_radius_decode_ctx_t	*test_ctx = talloc_get_type_abort(proto_ctx, fr_radius_decode_ctx_t);
	fr_radius_decode_fail_t	reason;
	fr_pair_t	*vp;
	size_t		packet_len = data_len;

	if (!fr_radius_ok(data, &packet_len, 200, false, &reason)) {
		fr_strerror_printf("Packet failed verification - %s", fr_radius_decode_fail_reason[reason]);
		return -1;
	}

	/*
	 *	Decode the header
	 */
	vp = fr_pair_afrom_da(ctx, attr_packet_type);
	if (!vp) {
		fr_strerror_const("Failed creating Packet-Type");
		return -1;
	}
	PAIR_ALLOCED(vp);

	vp->vp_uint32 = data[0];
	fr_pair_append(out, vp);

	vp = fr_pair_afrom_da(ctx, attr_packet_authentication_vector);
	if (!vp) {
		fr_strerror_const("Failed creating Packet-Authentication-Vector");
		return -1;
	}
	PAIR_ALLOCED(vp);

	(void) fr_pair_value_memdup(vp, data + 4, 16, true);
	fr_pair_append(out, vp);

	test_ctx->end = data + packet_len;

	return fr_radius_decode(ctx, out, UNCONST(uint8_t *, data), packet_len, test_ctx);
}

static ssize_t decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *out, NDEBUG_UNUSED fr_dict_attr_t const *parent,
			   uint8_t const *data, size_t data_len, void *decode_ctx)
{
	fr_radius_decode_ctx_t *packet_ctx = decode_ctx;

	fr_assert(parent == fr_dict_root(dict_radius));

	packet_ctx->end = data + data_len;
	return fr_radius_decode_pair(ctx, out, data, data_len, decode_ctx);
}


/*
 *	Test points
 */
extern fr_test_point_pair_decode_t radius_tp_decode_pair;
fr_test_point_pair_decode_t radius_tp_decode_pair = {
	.test_ctx	= decode_test_ctx,
	.func		= decode_pair
};

extern fr_test_point_proto_decode_t radius_tp_decode_proto;
fr_test_point_proto_decode_t radius_tp_decode_proto = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_radius_decode_proto
};
