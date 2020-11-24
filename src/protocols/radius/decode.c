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

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/protocol/radius/freeradius.internal.h>

#include "attrs.h"

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
ssize_t fr_radius_decode_tunnel_password(uint8_t *passwd, size_t *pwlen,
					 char const *secret, uint8_t const *vector, bool tunnel_password_zeros)
{
	fr_md5_ctx_t	*md5_ctx, *md5_ctx_old;
	uint8_t		digest[RADIUS_AUTH_VECTOR_LENGTH];
	int		secretlen;
	size_t		i, n, encrypted_len, embedded_len;

	encrypted_len = *pwlen;

	/*
	 *	We need at least a salt.
	 */
	if (encrypted_len < 2) {
		fr_strerror_printf("Tunnel password is too short");
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

	/*
	 *	Use the secret to setup the decryption digest
	 */
	secretlen = talloc_array_length(secret) - 1;

	md5_ctx = fr_md5_ctx_alloc(false);
	md5_ctx_old = fr_md5_ctx_alloc(true);

	fr_md5_update(md5_ctx, (uint8_t const *) secret, secretlen);
	fr_md5_ctx_copy(md5_ctx_old, md5_ctx); /* save intermediate work */

	/*
	 *	Set up the initial key:
	 *
	 *	 b(1) = MD5(secret + vector + salt)
	 */
	fr_md5_update(md5_ctx, vector, RADIUS_AUTH_VECTOR_LENGTH);
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
				fr_md5_ctx_free(&md5_ctx);
				fr_md5_ctx_free(&md5_ctx_old);
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

	fr_md5_ctx_free(&md5_ctx);
	fr_md5_ctx_free(&md5_ctx_old);

	/*
	 *	Check trailing bytes
	 */
	if (tunnel_password_zeros) for (i = embedded_len; i < (encrypted_len - 1); i++) {	/* -1 for length field */
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
ssize_t fr_radius_decode_password(char *passwd, size_t pwlen, char const *secret, uint8_t const *vector)
{
	fr_md5_ctx_t	*md5_ctx, *md5_ctx_old;
	uint8_t		digest[RADIUS_AUTH_VECTOR_LENGTH];
	int		i;
	size_t		n, secretlen;

	/*
	 *	The RFC's say that the maximum is 128.
	 *	The buffer we're putting it into above is 254, so
	 *	we don't need to do any length checking.
	 */
	if (pwlen > 128) pwlen = 128;

	/*
	 *	Catch idiots.
	 */
	if (pwlen == 0) goto done;

	/*
	 *	Use the secret to setup the decryption digest
	 */
	secretlen = talloc_array_length(secret) - 1;

	md5_ctx = fr_md5_ctx_alloc(false);
	md5_ctx_old = fr_md5_ctx_alloc(true);

	fr_md5_update(md5_ctx, (uint8_t const *) secret, secretlen);
	fr_md5_ctx_copy(md5_ctx_old, md5_ctx);	/* save intermediate work */

	/*
	 *	The inverse of the code above.
	 */
	for (n = 0; n < pwlen; n += AUTH_PASS_LEN) {
		if (n == 0) {
			fr_md5_update(md5_ctx, vector, RADIUS_AUTH_VECTOR_LENGTH);
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

	fr_md5_ctx_free(&md5_ctx);
	fr_md5_ctx_free(&md5_ctx_old);

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
			fr_strerror_printf("Attribute header overflow");
			return -1;
		}

		switch (dv_type) {
		case 4:
			if ((data[0] == 0) && (data[1] == 0) &&
			    (data[2] == 0) && (data[3] == 0)) {
			zero:
				fr_strerror_printf("Invalid attribute 0");
				return -1;
			}

			if (data[0] != 0) {
				fr_strerror_printf("Invalid attribute > 2^24");
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
			fr_strerror_printf("Internal sanity check failed");
			return -1;
		}

		switch (dv_length) {
		case 0:
			return 0;

		case 2:
			if (data[dv_type] != 0) {
				fr_strerror_printf("Attribute is longer than 256 octets");
				return -1;
			}
			FALL_THROUGH;
		case 1:
			attrlen = data[dv_type + dv_length - 1];
			break;


		default:
			fr_strerror_printf("Internal sanity check failed");
			return -1;
		}

		if (attrlen < (dv_type + dv_length)) {
			fr_strerror_printf("Attribute header has invalid length");
			return -1;
		}

		if (attrlen > length) {
			fr_strerror_printf("Attribute overflows container");
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
static ssize_t decode_concat(TALLOC_CTX *ctx, fr_cursor_t *cursor,
			     fr_dict_attr_t const *parent, uint8_t const *data,
			     size_t const packet_len)
{
	size_t		total;
	uint8_t		attr;
	uint8_t const	*ptr = data;
	uint8_t const	*end = data + packet_len;
	uint8_t		*p;
	fr_pair_t	*vp;

	total = 0;
	attr = ptr[0];

	/*
	 *	See how many consecutive attributes there are.
	 */
	while (ptr < end) {
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
	fr_cursor_append(cursor, vp);
	return ptr - data;
}


/** Convert TLVs to one or more VPs
 *
 */
ssize_t fr_radius_decode_tlv(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
			     fr_dict_attr_t const *parent, uint8_t const *data, size_t data_len,
			     void *decoder_ctx)
{
	uint8_t const		*p = data, *end = data + data_len;
	fr_dict_attr_t const	*child;
	fr_pair_list_t		head;
	fr_cursor_t		tlv_cursor;
	fr_radius_ctx_t		*packet_ctx = decoder_ctx;

	fr_pair_list_init(&head);
	if (data_len < 3) return -1; /* type, length, value */

#ifdef __clang_analyzer__
	if (!packet_ctx || !packet_ctx->tmp_ctx) return -1;
#endif

	FR_PROTO_HEX_DUMP(p, data_len, "tlvs");

	if (fr_radius_decode_tlv_ok(p, data_len, 1, 1) < 0) return -1;

	/*
	 *  Record where we were in the list when this function was called
	 */
	fr_cursor_init(&tlv_cursor, &head);
	while (p < end) {
		ssize_t tlv_len;

		child = fr_dict_attr_child_by_num(parent, p[0]);
		if (!child) {
			FR_PROTO_TRACE("Failed to find child %u of TLV %s", p[0], parent->name);

			/*
			 *	Build an unknown attr
			 */
			child = fr_dict_unknown_attr_afrom_num(packet_ctx->tmp_ctx, parent, p[0]);
			if (!child) {
			error:
				fr_pair_list_free(&head);
				return -1;
			}
		}
		FR_PROTO_TRACE("decode context changed %s -> %s", parent->name, child->name);

		tlv_len = fr_radius_decode_pair_value(ctx, &tlv_cursor, dict,
						      child, p + 2, p[1] - 2, p[1] - 2,
						      decoder_ctx);
		if (tlv_len < 0) goto error;
		p += p[1];
	}
	fr_cursor_head(&tlv_cursor);
	fr_cursor_tail(cursor);
	fr_cursor_merge(cursor, &tlv_cursor);	/* Wind to the end of the new pairs */

	return data_len;
}

/** Convert a top-level VSA to a VP.
 *
 * "length" can be LONGER than just this sub-vsa.
 */
static ssize_t decode_vsa_internal(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
				   fr_dict_attr_t const *parent,
				   uint8_t const *data, size_t data_len,
				   void *decoder_ctx, fr_dict_vendor_t const *dv)
{
	unsigned int		attribute;
	ssize_t			attrlen, my_len;
	fr_dict_attr_t const	*da;
	fr_radius_ctx_t		*packet_ctx = decoder_ctx;

#ifdef __clang_analyzer__
	if (!packet_ctx || !packet_ctx->tmp_ctx) return -1;
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
	if (!da) da = fr_dict_unknown_attr_afrom_num(packet_ctx->tmp_ctx, parent, attribute);
	if (!da) return -1;
	FR_PROTO_TRACE("decode context changed %s -> %s", da->parent->name, da->name);

	my_len = fr_radius_decode_pair_value(ctx, cursor, dict,
					     da, data + dv->type + dv->length,
					     attrlen - (dv->type + dv->length), attrlen - (dv->type + dv->length),
					     decoder_ctx);
	if (my_len < 0) return my_len;

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
static ssize_t decode_extended(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
			       fr_dict_attr_t const *parent,
			       uint8_t const *data, size_t attr_len, size_t packet_len,
			       void *decoder_ctx)
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
	 *	No continuation, just decode the attributre in place.
	 */
	if ((data[1] & 0x80) == 0) {
		ret = fr_radius_decode_pair_value(ctx, cursor, dict,
						  parent, data + 2, attr_len - 2, attr_len - 2, decoder_ctx);
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
	end = data + packet_len;
	fragments = 1;
	last_frag = false;

	while (frag < end) {
		if (last_frag ||
		    (frag[0] != attr[0]) ||
		    (frag[1] < 4) ||		       /* too short for long-extended */
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

	FR_PROTO_HEX_DUMP(head, fraglen, "long-extended fragments");

	ret = fr_radius_decode_pair_value(ctx, cursor, dict,
					  parent, head, fraglen, fraglen, decoder_ctx);
	talloc_free(head);
	if (ret < 0) return ret;

	return end - data;
}

/** Convert a Vendor-Specific WIMAX to vps
 *
 * @note Called ONLY for Vendor-Specific
 */
static ssize_t decode_wimax(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t attr_len, size_t packet_len, void *decoder_ctx)
{
	ssize_t			ret;
	size_t			wimax_len;
	bool			more;
	uint8_t			*head, *tail;
	uint8_t	const		*attr, *end;
	fr_dict_attr_t const	*da;
	fr_radius_ctx_t		*packet_ctx = decoder_ctx;

#ifdef __clang_analyzer__
	if (!packet_ctx || !packet_ctx->tmp_ctx) return -1;
#endif

	/*
	 *	data = VID VID VID VID WiMAX-Attr WiMAX-Len Continuation ...
	 */
	if (attr_len < 8) return -1;

	/*
	 *	WiMAX-Attr WiMAX-Len Continuation
	 */
	if (data[5] < 3) return -1;

	/*
	 *	The WiMAX-Len + 4 VID must exactly fill the attribute.
	 */
	if (((size_t) (data[5] + 4)) != attr_len) return -1;

	da = fr_dict_attr_child_by_num(parent, data[4]);
	if (!da) da = fr_dict_unknown_attr_afrom_num(packet_ctx->tmp_ctx, parent, data[4]);
	if (!da) return -1;
	FR_PROTO_TRACE("decode context changed %s -> %s", da->parent->name, da->name);

	/*
	 *	No continuation, just decode the attributre in place.
	 */
	if ((data[6] & 0x80) == 0) {
		ret = fr_radius_decode_pair_value(ctx, cursor, dict,
						  da, data + 7, data[5] - 3, data[5] - 3, decoder_ctx);
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
	end = data + packet_len;

	while (attr < end) {
		/*
		 *	Not enough room for Attribute + length +
		 *	continuation, it's bad.
		 */
		if ((end - attr) < 3) return -1;

		/*
		 *	Must have non-zero data in the attribute.
		 */
		if (attr[1] <= 3) return -1;

		/*
		 *	If the WiMAX attribute overflows the packet,
		 *	it's bad.
		 */
		if ((attr + attr[1]) > end) return -1;

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
		if (more && ((attr + attr[1]) == end)) return -1;

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
		if ((end - attr) < 9) return -1;

		if (attr[0] != FR_VENDOR_SPECIFIC) return -1;
		if (attr[1] < 9) return -1;
		if ((attr + attr[1]) > end) return -1;
		if (memcmp(data, attr + 2, 4) != 0) return -1; /* not WiMAX Vendor ID */

		if (attr[1] != (attr[7] + 6)) return -1; /* WiMAX attr doesn't exactly fill the VSA */

		if (data[4] != attr[6]) return -1; /* different WiMAX attribute */

		/*
		 *	Skip over the Vendor-Specific header, and
		 *	continue with the WiMAX attributes.
		 */
		attr += 6;
	}

	/*
	 *	No data in the WiMAX attribute, make a "raw" one.
	 */
	if (!wimax_len) return -1;

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

	ret = fr_radius_decode_pair_value(ctx, cursor, dict,
					  da, head, wimax_len, wimax_len, decoder_ctx);
	talloc_free(head);
	if (ret < 0) return ret;

	return end - data;
}


/** Convert a top-level VSA to one or more VPs
 *
 */
static ssize_t decode_vsa(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
			  fr_dict_attr_t const *parent,
			  uint8_t const *data, size_t attr_len, size_t packet_len,
			  void *decoder_ctx)
{
	size_t			total;
	ssize_t			ret;
	uint32_t		vendor;
	fr_dict_vendor_t const	*dv;
	fr_pair_list_t		head;
	fr_dict_vendor_t	my_dv;
	fr_dict_attr_t const	*vendor_da;
	fr_cursor_t		tlv_cursor;
	fr_radius_ctx_t		*packet_ctx = decoder_ctx;

	fr_pair_list_init(&head);
#ifdef __clang_analyzer__
	if (!packet_ctx || !packet_ctx->tmp_ctx) return -1;
#endif

	/*
	 *	Container must be a VSA
	 */
	if (!fr_cond_assert(parent->type == FR_TYPE_VSA)) return -1;

	if (attr_len > packet_len) return -1;
	if (attr_len < 5) return -1; /* vid, value */
	if (data[0] != 0) return -1; /* we require 24-bit VIDs */

	FR_PROTO_TRACE("Decoding VSA");

	memcpy(&vendor, data, 4);
	vendor = ntohl(vendor);

	/*
	 *	Verify that the parent (which should be a VSA)
	 *	contains a fake attribute representing the vendor.
	 *
	 *	If it doesn't then this vendor is unknown, but
	 *	(unlike DHCP) we know vendor attributes have a
	 *	standard format, so we can decode the data anyway.
	 */
	vendor_da = fr_dict_attr_child_by_num(parent, vendor);
	if (!vendor_da) {
		fr_dict_attr_t *n;
		/*
		 *	RFC format is 1 octet type, 1 octet length
		 */
		if (fr_radius_decode_tlv_ok(data + 4, attr_len - 4, 1, 1) < 0) {
			FR_PROTO_TRACE("Unknown TLVs not OK: %s", fr_strerror());
			return -1;
		}

		n = fr_dict_unknown_vendor_afrom_num(packet_ctx->tmp_ctx, parent, vendor);
		if (!n) return -1;
		vendor_da = n;

		/*
		 *	Create an unknown DV too...
		 */
		memset(&my_dv, 0, sizeof(my_dv));

		my_dv.pen = vendor;
		my_dv.type = 1;
		my_dv.length = 1;

		dv = &my_dv;

		goto create_attrs;
	}

	/*
	 *	We found an attribute representing the vendor
	 *	so it *MUST* exist in the vendor tree.
	 */
	dv = fr_dict_vendor_by_num(dict, vendor);
	if (!fr_cond_assert(dv)) return -1;
	FR_PROTO_TRACE("decode context %s -> %s", parent->name, vendor_da->name);

	/*
	 *	WiMAX craziness
	 */
	if ((vendor == VENDORPEC_WIMAX) && dv->flags) {
		ret = decode_wimax(ctx, cursor, dict, vendor_da, data, attr_len, packet_len, decoder_ctx);
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
	data += 4;
	attr_len -= 4;
	packet_len -= 4;
	total = 4;

	fr_cursor_init(&tlv_cursor, &head);
	while (attr_len > 0) {
		ssize_t vsa_len;

		/*
		 *	Vendor attributes can have subattributes (if you hadn't guessed)
		 */
		vsa_len = decode_vsa_internal(ctx, &tlv_cursor, dict,
					      vendor_da, data, attr_len, decoder_ctx, dv);
		if (vsa_len < 0) {
			fr_strerror_printf("%s: Internal sanity check %d", __FUNCTION__, __LINE__);
			fr_pair_list_free(&head);
			return -1;
		}

		data += vsa_len;
		attr_len -= vsa_len;
		packet_len -= vsa_len;
		total += vsa_len;
	}
	fr_cursor_head(&tlv_cursor);
	fr_cursor_tail(cursor);
	fr_cursor_merge(cursor, &tlv_cursor);

	/*
	 *	When the unknown attributes were created by
	 *	decode_vsa_internal, the hierachy between that unknown
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
static ssize_t decode_value(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
			    fr_dict_attr_t const *parent,
			    uint8_t const *data, size_t data_len, void *decoder_ctx)
{
	return fr_radius_decode_pair_value(ctx, cursor, dict, parent, data, data_len, data_len, decoder_ctx);
}


/** Create any kind of VP from the attribute contents
 *
 * "length" is AT LEAST the length of this attribute, as we
 * expect the caller to have verified the data with
 * fr_radius_packet_ok().  "length" may be up to the length of the
 * packet.
 *
 * @return
 *	- Length on success.
 *	- -1 on failure.
 */
ssize_t fr_radius_decode_pair_value(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
				    fr_dict_attr_t const *parent,
				    uint8_t const *data, size_t const attr_len, size_t const packet_len,
				    void *decoder_ctx)
{
	int8_t			tag = 0;
	size_t			data_len;
	ssize_t			ret;
	uint32_t		vendor;
	fr_dict_attr_t const	*child;
	fr_dict_attr_t		*unknown;
	fr_pair_t		*vp = NULL;
	uint8_t const		*p = data;
	uint8_t			buffer[256];
	fr_radius_ctx_t		*packet_ctx = decoder_ctx;
	size_t			min = 0, max = 0;
	int			extra;

	if ((attr_len > packet_len) || (attr_len > 128 * 1024)) {
		fr_strerror_printf("%s: Invalid arguments", __FUNCTION__);
		return -1;
	}

#ifdef __clang_analyzer__
	if (!packet_ctx || !packet_ctx->tmp_ctx) return -1;
#endif

	FR_PROTO_HEX_DUMP(data, attr_len, "%s", __FUNCTION__ );

	FR_PROTO_TRACE("Parent %s len %zu ... %zu", parent->name, attr_len, packet_len);

	data_len = attr_len;
	extra = flag_long_extended(&parent->flags);

	/*
	 *	Silently ignore zero-length attributes.
	 */
	if (attr_len == 0) return 0;

	/*
	 *	Hacks for tags.
	 */
	if (flag_has_tag(&parent->flags)) {
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
			if (data_len >= sizeof(buffer)) return -1;

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
		}
	}

	if (tag) {
		if (!packet_ctx->tags) {
			packet_ctx->tags = talloc_zero_array(packet_ctx->tmp_ctx, fr_radius_tag_ctx_t *, 32);
			if (!packet_ctx->tags) {
				fr_pair_list_free(&vp);
				fr_strerror_printf("%s: Internal sanity check %d", __FUNCTION__, __LINE__);
				return -1;
			}
		}

		fr_assert(tag < 0x20);

		if (!packet_ctx->tags[tag]) {
			fr_pair_t *group;
			fr_dict_attr_t const *group_da;

			packet_ctx->tags[tag] = talloc_zero(packet_ctx->tags, fr_radius_tag_ctx_t);
			if (!packet_ctx->tags[tag]) {
				fr_pair_list_free(&vp);
				fr_strerror_printf("%s: Internal sanity check %d", __FUNCTION__, __LINE__);
				return -1;
			}

			group_da = fr_dict_attr_child_by_num(fr_dict_root(dict_radius), FR_TAG_BASE + tag);
			if (!group_da) {
				fr_pair_list_free(&vp);
				fr_strerror_printf("Failed finding attribute 'Tag-%u'", tag);
				return -1;
			}

			group = fr_pair_afrom_da(ctx, group_da);
			if (!group) {
				fr_pair_list_free(&vp);
				return -1;
			}

			fr_cursor_append(cursor, group);
			packet_ctx->tags[tag]->parent = group;
			fr_cursor_init(&packet_ctx->tags[tag]->cursor, &group->vp_group);
		}
	}

	/*
	 *	Decrypt the attribute.
	 */
	if (packet_ctx && flag_encrypted(&parent->flags)) {
		FR_PROTO_TRACE("Decrypting type %u", parent->flags.subtype);
		/*
		 *	Encrypted attributes can only exist for the
		 *	old-style format.  Extended attributes CANNOT
		 *	be encrypted.
		 */
		if (attr_len > 253) return -1;

		if (p == data) memcpy(buffer, p, attr_len);
		p = buffer;

		switch (parent->flags.subtype) { /* can't be tagged */
		/*
		 *  User-Password
		 */
		case FLAG_ENCRYPT_USER_PASSWORD:
			fr_radius_decode_password((char *)buffer, attr_len,
						  packet_ctx->secret, packet_ctx->vector);
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
		case FLAG_TAGGED_TUNNEL_PASSWORD:
		case FLAG_ENCRYPT_TUNNEL_PASSWORD:
			if (fr_radius_decode_tunnel_password(buffer, &data_len,
							     packet_ctx->secret, packet_ctx->vector,
							     packet_ctx->tunnel_password_zeros) < 0) {
				goto raw;
			}
			break;

		/*
		 *	Ascend-Send-Secret
		 *	Ascend-Receive-Secret
		 */
		case FLAG_ENCRYPT_ASCEND_SECRET:
			fr_radius_ascend_secret(&FR_DBUFF_TMP(buffer, sizeof(buffer)), p, data_len,
						packet_ctx->secret, packet_ctx->vector);
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
	FR_PROTO_TRACE("Type \"%s\" (%u)", fr_table_str_by_value(fr_value_box_type_table, parent->type, "?Unknown?"), parent->type);

	min = fr_radius_attr_sizes[parent->type][0];
	max = fr_radius_attr_sizes[parent->type][1];

	if (data_len < min) {
		FR_PROTO_TRACE("Data len %zu too short, need at least %zu", data_len, min);
		goto raw;
	}
	if (data_len > max) {
		FR_PROTO_TRACE("Data len %zu too long, must be less than or equal to %zu", data_len, max);
		goto raw;
	}

	switch (parent->type) {
	case FR_TYPE_VALUE:
		break;

	case FR_TYPE_COMBO_IP_PREFIX:
		if (data_len == min) {
			child = fr_dict_attr_by_type(parent, FR_TYPE_IPV4_PREFIX);
		} else if (data_len == max) {
			child = fr_dict_attr_by_type(parent, FR_TYPE_IPV6_PREFIX);
		} else {
			FR_PROTO_TRACE("Combo attribute len %zu incorrect, must be %zu or %zu", data_len, min, max);
			goto raw;
		}
		if (!child) {
			FR_PROTO_TRACE("Missing type variant for combo attribute len %zu", data_len);
			goto raw;
		}
		parent = child;	/* re-write it */
		break;

	case FR_TYPE_COMBO_IP_ADDR:
		if (data_len == min) {
			child = fr_dict_attr_by_type(parent, FR_TYPE_IPV4_ADDR);
		} else if (data_len == max) {
			child = fr_dict_attr_by_type(parent, FR_TYPE_IPV6_ADDR);
		} else {
			FR_PROTO_TRACE("Combo attribute len %zu incorrect, must be %zu or %zu", data_len, min, max);
			goto raw;
		}
		if (!child) {
			FR_PROTO_TRACE("Missing type variant for combo attribute len %zu", data_len);
			goto raw;
		}
		parent = child;	/* re-write it */
		break;

	case FR_TYPE_VSA:
		/*
		 *	VSAs in the RFC space are encoded one way.
		 *	VSAs in the "extended" space are different.
		 */
		if (!parent->parent || !flag_extended(&parent->parent->flags)) {
			/*
			 *	VSAs can be WiMAX, in which case they don't
			 *	fit into one attribute.
			 */
			ret = decode_vsa(ctx, cursor, dict, parent, p, attr_len, packet_len, decoder_ctx);
			if (ret < 0) goto raw;
			return ret;

		} else {
			fr_dict_attr_t const	*vendor_child;

			if (data_len < 6) goto raw; /* vid, vtype, value */

			memcpy(&vendor, p, 4);
			vendor = ntohl(vendor);

			/*
			 *	For simplicity in our attribute tree, vendors are
			 *	represented as a subtlv(ish) of an EVS or VSA
			 *	attribute.
			 */
			vendor_child = fr_dict_attr_child_by_num(parent, vendor);
			if (!vendor_child) {
				/*
				 *	If there's no child, it means the vendor is unknown
				 *	which means the child attribute is unknown too.
				 *
				 *	fr_dict_unknown_afrom_fields will do the right thing
				 *	and create both an unknown vendor and an unknown
				 *	attr.
				 *
				 *	This can be used later by the encoder to rebuild
				 *	the attribute header.
				 */
				vendor_child = fr_dict_unknown_afrom_fields(packet_ctx->tmp_ctx, parent, vendor, p[4]);
				if (!vendor_child) {
					fr_strerror_printf_push("decoder failed creating unknown attribute in %s",
								parent->name);
					return -1;
				}
				parent = vendor_child;
				p += 5;
				data_len -= 5;
				break;
			}

			child = fr_dict_attr_child_by_num(vendor_child, p[4]);
			if (!child) {
				/*
				 *	Vendor exists but child didn't, again
				 *	fr_dict_unknown_afrom_fields will do the right thing
				 *	and only create the unknown attr.
				 */
				child = fr_dict_unknown_attr_afrom_num(packet_ctx->tmp_ctx, parent, p[4]);
				if (!child) {
					fr_strerror_printf_push("decoder failed creating unknown attribute in %s",
								parent->name);
					return -1;
				}
				parent = child;
				p += 5;
				data_len -= 5;
				break;
			}

			/*
			 *	Everything was found in the dictionary, we can
			 *	now recurse to decode the value.
			 */
			ret = fr_radius_decode_pair_value(ctx, cursor, dict,
							  child, p + 5, attr_len - 5, attr_len - 5,
							  decoder_ctx);
			if (ret < 0) goto raw;
			return attr_len;
		}

	case FR_TYPE_TLV:
		if (!flag_extended(&parent->flags)) {
				/*
				 *	We presume that the TLVs all fit into one
				 *	attribute, OR they've already been grouped
				 *	into a contiguous memory buffer.
				 */
				ret = fr_radius_decode_tlv(ctx, cursor, dict, parent, p, attr_len, decoder_ctx);
				if (ret < 0) goto raw;
				return attr_len;
		}

		/*
		 *	Extended attributes
		 */
		min = 1 + extra;

		/*
		 *	Not enough data, just create a raw attribute.
		 */
		if (data_len <= min) goto raw;

		/*
		 *	Look up the extended type.  It's almost always
		 *	a known child, so we use that as the fast
		 *	path.
		 */
		child = fr_dict_attr_child_by_num(parent, p[0]);
		if (child) {
			/*
			 *	Normal "extended" with 0 or more bytes
			 *	of data. OR a "long extended" with a
			 *	flag byte, BUT the "more" flag is not
			 *	set.  Just decode it.
			 */
			if (!extra || ((p[1] & 0x80) == 0)) {
				ret = fr_radius_decode_pair_value(ctx, cursor, dict, child,
								    p + min, attr_len - min, attr_len - min,
								    decoder_ctx);
				if (ret < 0) goto invalid_extended;
				return attr_len;
			}

			/*
			 *	It's a "long extended" attribute with
			 *	an attribute number, but with no flag
			 *	byte.  It's invalid.
			 */
			if (data_len == 1) goto invalid_extended;

			/*
			 *	"long extended" with a flag byte.  Due
			 *	to the above checks, the flag byte
			 *	MUST have the "more" bit set.  So we
			 *	don't check it again here.
			 */
			ret = decode_extended(ctx, cursor, dict, child, data, attr_len, packet_len, decoder_ctx);
			if (ret >= 0) return ret; /* which may be LONGER than attr_len */

			/* Fall through to invalid extended attribute */
		} else {
			FR_PROTO_TRACE("Extended attribute %s has no child %i", parent->name, p[0]);
		}

	invalid_extended:
	{
		fr_dict_attr_t *raw;

		/*
		 *	Create an unknown attribute, and decode it as
		 *	"octets".  Note that we have to account for
		 *	the flag byte, too.
		 *
		 *	If the child was a VSA, BUT the VSA contents
		 *	were malformed, then the recursive call to
		 *	ourselves would create an unknown attribute
		 *	and succeed, instead of failing.  So we don't
		 *	need to handle that case here.
		 */
		child = raw = fr_dict_unknown_attr_afrom_num(packet_ctx->tmp_ctx, parent, p[0]);
		if (!child) goto raw;

		raw->flags.is_raw = 1;
		/*
		 *	"long" extended.  Decode the value.
		 */
		if (extra) {
			ret = decode_extended(ctx, cursor, dict, child, data, attr_len, packet_len, decoder_ctx);
			if (ret >= 0) return ret; /* which may be LONGER than attr_len */
		}

		ret = fr_radius_decode_pair_value(ctx, cursor, dict, child,
						  p + min, attr_len - min, attr_len - min,
						  decoder_ctx);
		if (ret < 0) return -1;
	}
		return attr_len;

	case FR_TYPE_STRUCT:
		/*
		 *	We presume that the struct fits into one
		 *	attribute, OR it's already been grouped
		 *	into a contiguous memory buffer.
		 */
		ret = fr_struct_from_network(ctx, cursor, parent, p, attr_len, &child,
					     decode_value, decoder_ctx);
		if (ret < 0) goto raw;

		/*
		 *	The above function only decodes fixed fields
		 *	and strings.  If there are TLVs at the end of
		 *	the struct, we have to decode them manually
		 *	here.
		 */
		if (child && ((size_t) ret < attr_len)) {
			ssize_t tlv_len;

			/*
			 *	Try to decode the TLVs
			 */
			tlv_len = fr_radius_decode_tlv(ctx, cursor, dict,
						       child, p + ret, attr_len - ret,
						       decoder_ctx);
			if (tlv_len < 0) {
				vp = fr_raw_from_network(ctx, child, p + ret, attr_len - ret);
				if (vp) fr_cursor_append(cursor, vp);
			}
		}

		return attr_len;

	default:
	raw:
		if (vp) fr_pair_list_free(&vp);

		vp = fr_raw_from_network(ctx, parent, data, attr_len);
		goto done;
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
		vp = fr_pair_afrom_da(packet_ctx->tags[tag]->parent, parent);
	}
	if (!vp) return -1;

	switch (parent->type) {
	/*
	 *  Magic RADIUS format IPv4 prefix
	 *
	 *  0                   1                   2                   3
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |    Reserved   | Prefix-Length |  Prefix ...
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *      ... Prefix                 |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 * RFC does not require non-masked bits to be zero.
	 */
	case FR_TYPE_IPV4_PREFIX:
		if (data_len != min) goto raw;
		if (p[0] != 0) goto raw;
		if ((p[1] & 0x3f) > 32) goto raw;

		vp->vp_ip.af = AF_INET;
		vp->vp_ip.scope_id = 0;
		vp->vp_ip.prefix = p[1] & 0x3f;
		memcpy((uint8_t *)&vp->vp_ipv4addr, p + 2, data_len - 2);
		fr_ipaddr_mask(&vp->vp_ip, p[1] & 0x3f);
		break;

	/*
	 *  Magic RADIUS format IPv6 prefix
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
	 *  RFC says non-masked bits MUST be zero.
	 */
	case FR_TYPE_IPV6_PREFIX:
	{
		if (p[0] != 0) goto raw;	/* First byte is always 0 */
		if (p[1] > 128) goto raw;

		/*
		 *	Convert prefix bits to bytes to check that
		 *	we have sufficient data.
		 */
		if (fr_bytes_from_bits(p[1]) > (data_len - 2)) goto raw;

		vp->vp_ip.af = AF_INET6;
		vp->vp_ip.scope_id = 0;
		vp->vp_ip.prefix = p[1];

		memcpy((uint8_t *)&vp->vp_ipv6addr, p + 2, data_len - 2);
		fr_ipaddr_mask(&vp->vp_ip, p[1]);

		/*
		 *	Check the prefix data is the same before
		 *	and after casting (it should be).
		 */
		if (memcmp(p + 2, (uint8_t *)&vp->vp_ipv6addr, data_len - 2) != 0) goto raw;
	}
		break;

	case FR_TYPE_STRING:
		if (!flag_abinary(&parent->flags)) goto decode;

		if (fr_radius_decode_abinary(vp, p, data_len) < 0) goto raw;
		break;

	case FR_TYPE_OCTETS:
		/*
		 *	This attribute SHOULD have fixed size, but it
		 *	doesn't.  Therefor it's malformed.
		 */
		if (parent->flags.length && (data_len != parent->flags.length)) goto raw;
		FALL_THROUGH;

	default:
	decode:
		if (fr_value_box_from_network(vp, &vp->data, vp->da->type, vp->da, p, data_len, true) < 0) {
			/*
			 *	Paranoid loop prevention
			 */
			if (vp->da->flags.is_unknown) {
				fr_pair_list_free(&vp);
				return -1;
			}
			goto raw;
		}
		break;
	}

done:
	vp->type = VT_DATA;
	vp->vp_tainted = true;

	if (!tag) {
		fr_cursor_append(cursor, vp);
		return attr_len;
	}

	fr_assert(packet_ctx->tags != NULL);
	fr_assert(packet_ctx->tags[tag] != NULL);
	fr_cursor_append(&packet_ctx->tags[tag]->cursor, vp);
	return attr_len;
}


/** Create a "normal" fr_pair_t from the given data
 *
 */
ssize_t fr_radius_decode_pair(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
			      uint8_t const *data, size_t data_len, void *decoder_ctx)
{
	ssize_t			ret;
	fr_dict_attr_t const	*da;
	fr_radius_ctx_t		*packet_ctx = decoder_ctx;

	if ((data_len < 2) || (data[1] < 2) || (data[1] > data_len)) {
		fr_strerror_printf("%s: Insufficient data", __FUNCTION__);
		return -1;
	}

	da = fr_dict_attr_child_by_num(fr_dict_root(dict), data[0]);
	if (!da) {
		FR_PROTO_TRACE("Unknown attribute %u", data[0]);
		da = fr_dict_unknown_attr_afrom_num(packet_ctx->tmp_ctx, fr_dict_root(dict), data[0]);
	}
	if (!da) return -1;
	FR_PROTO_TRACE("decode context changed %s -> %s",da->parent->name, da->name);

	/*
	 *	Empty attributes are silently ignored, except for CUI.
	 */
	if (data_len == 2) {
		fr_pair_t *vp;

		if (!fr_dict_root(dict)->flags.is_root) {
			return 2;
		}

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

		fr_cursor_append(cursor, vp);
		vp->vp_tainted = true;		/* not REALLY necessary, but what the heck */

		return 2;
	}

	/*
	 *	Pass the entire thing to the decoding function
	 */
	if (flag_concat(&da->flags)) {
		FR_PROTO_TRACE("Concat attribute");
		return decode_concat(ctx, cursor, da, data, data_len);
	}

	/*
	 *	Note that we pass the entire length, not just the
	 *	length of this attribute.  The Extended or WiMAX
	 *	attributes may have the "continuation" bit set, and
	 *	will thus be more than one attribute in length.
	 */
	ret = fr_radius_decode_pair_value(ctx, cursor, dict,
					  da, data + 2, data[1] - 2, data_len - 2,
					  decoder_ctx);
	if (ret < 0) return ret;

	return 2 + ret;
}

static int _test_ctx_free(UNUSED fr_radius_ctx_t *ctx)
{
	fr_radius_free();

	return 0;
}

static int decode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	static uint8_t vector[RADIUS_AUTH_VECTOR_LENGTH] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	fr_radius_ctx_t	*test_ctx;

	if (fr_radius_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_radius_ctx_t);
	test_ctx->secret = talloc_strdup(test_ctx, "testing123");
	memcpy(test_ctx->vector, vector, sizeof(test_ctx->vector));
	test_ctx->tmp_ctx = talloc_zero(ctx, uint8_t);
	talloc_set_destructor(test_ctx, _test_ctx_free);

	*out = test_ctx;

	return 0;
}

static ssize_t fr_radius_decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *list, uint8_t const *data, size_t data_len, void *proto_ctx)
{
	size_t packet_len = data_len;
	fr_radius_ctx_t	*test_ctx = talloc_get_type_abort(proto_ctx, fr_radius_ctx_t);
	decode_fail_t reason;
	fr_cursor_t cursor;
	fr_pair_t *vp;
	uint8_t original[20];

	if (!fr_radius_ok(data, &packet_len, 200, false, &reason)) {
		return -1;
	}

	fr_pair_list_init(list);
	fr_cursor_init(&cursor, list);

	/*
	 *	Decode the header
	 */
	vp = fr_pair_afrom_da(ctx, attr_packet_type);
	if (!vp) {
		fr_strerror_printf("Failed creating Packet-Type");
		return -1;
	}
	vp->vp_uint32 = data[0];
	fr_cursor_append(&cursor, vp);

	vp = fr_pair_afrom_da(ctx, attr_packet_authentication_vector);
	if (!vp) {
		fr_strerror_printf("Failed creating Packet-Authentication-Vector");
		return -1;
	}
	(void) fr_pair_value_memdup(vp, data + 4, 16, true);
	fr_cursor_append(&cursor, vp);
	(void) fr_cursor_tail(&cursor);

	memset(original, 0, 4);
	memcpy(original + 4, test_ctx->vector, sizeof(test_ctx->vector));
	return fr_radius_decode(ctx, data, packet_len, original,
				test_ctx->secret, talloc_array_length(test_ctx->secret) - 1, &cursor);
}

/*
 *	Test points
 */
extern fr_test_point_pair_decode_t radius_tp_decode_pair;
fr_test_point_pair_decode_t radius_tp_decode_pair = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_radius_decode_pair
};

extern fr_test_point_proto_decode_t radius_tp_decode_proto;
fr_test_point_proto_decode_t radius_tp_decode_proto = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_radius_decode_proto
};
