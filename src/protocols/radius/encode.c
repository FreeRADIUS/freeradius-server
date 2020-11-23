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
 * @file protocols/radius/encode.c
 * @brief Functions to encode RADIUS attributes
 *
 * @copyright 2000-2003,2006-2015 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/protocol/radius/freeradius.internal.h>
#include "attrs.h"

#define TAG_VALID(x)		((x) > 0 && (x) < 0x20)
#define TAG_VALID_ZERO(x)      	((x) >= 0 && (x) < 0x20)

static ssize_t encode_value(fr_dbuff_t *dbuff,
			    fr_da_stack_t *da_stack, unsigned int depth,
			    fr_cursor_t *cursor, void *encoder_ctx);

static ssize_t encode_rfc_hdr_internal(fr_dbuff_t *dbuff,
				       fr_da_stack_t *da_stack, unsigned int depth,
				       fr_cursor_t *cursor, void *encoder_ctx);

static ssize_t encode_tlv_hdr(fr_dbuff_t *dbuff,
			      fr_da_stack_t *da_stack, unsigned int depth,
			      fr_cursor_t *cursor, void *encoder_ctx);

/** Encode a CHAP password
 *
 * @param[out] out		An output buffer of 17 bytes (id + digest).
 * @param[in] id		CHAP ID, a random ID for request/response matching.
 * @param[in] vector		from the original packet or challenge attribute.
 * @param[in] password		Input password to hash.
 * @param[in] password_len	Length of input password.
 */
void fr_radius_encode_chap_password(uint8_t out[static 1 + RADIUS_CHAP_CHALLENGE_LENGTH],
				    uint8_t id, uint8_t const vector[static RADIUS_AUTH_VECTOR_LENGTH],
				    char const *password, size_t password_len)
{
	fr_md5_ctx_t	*md5_ctx;

	md5_ctx = fr_md5_ctx_alloc(true);

	/*
	 *	First ingest the ID and the password.
	 */
	fr_md5_update(md5_ctx, (uint8_t const *)&id, 1);
	fr_md5_update(md5_ctx, (uint8_t const *)password, password_len);

	fr_md5_update(md5_ctx, vector, RADIUS_AUTH_VECTOR_LENGTH);
	out[0] = id;
	fr_md5_final(out + 1, md5_ctx);
	fr_md5_ctx_free(&md5_ctx);
}

/** "encrypt" a password RADIUS style
 *
 * Input and output buffers can be identical if in-place encryption is needed.
 */
static ssize_t encode_password(fr_dbuff_t *dbuff, uint8_t const *input, size_t inlen,
			       char const *secret, uint8_t const *vector)
{
	fr_md5_ctx_t	*md5_ctx, *md5_ctx_old;
	uint8_t	digest[RADIUS_AUTH_VECTOR_LENGTH];
	uint8_t	passwd[RADIUS_MAX_PASS_LENGTH];
	size_t		i, n;
	size_t		len;

	/*
	 *	If the length is zero, round it up.
	 */
	len = inlen;

	if (len > RADIUS_MAX_PASS_LENGTH) len = RADIUS_MAX_PASS_LENGTH;

	memcpy(passwd, input, len);
	if (len < sizeof(passwd)) memset(passwd + len, 0, sizeof(passwd) - len);

	if (len == 0) len = AUTH_PASS_LEN;
	else if ((len & 0x0f) != 0) {
		len += 0x0f;
		len &= ~0x0f;
	}

	md5_ctx = fr_md5_ctx_alloc(false);
	md5_ctx_old = fr_md5_ctx_alloc(true);

	fr_md5_update(md5_ctx, (uint8_t const *) secret, talloc_array_length(secret) - 1);
	fr_md5_ctx_copy(md5_ctx_old, md5_ctx);

	/*
	 *	Do first pass.
	 */
	fr_md5_update(md5_ctx, vector, AUTH_PASS_LEN);

	for (n = 0; n < len; n += AUTH_PASS_LEN) {
		if (n > 0) {
			fr_md5_ctx_copy(md5_ctx, md5_ctx_old);
			fr_md5_update(md5_ctx, passwd + n - AUTH_PASS_LEN, AUTH_PASS_LEN);
		}

		fr_md5_final(digest, md5_ctx);
		for (i = 0; i < AUTH_PASS_LEN; i++) passwd[i + n] ^= digest[i];
	}

	fr_md5_ctx_free(&md5_ctx);
	fr_md5_ctx_free(&md5_ctx_old);

	return fr_dbuff_in_memcpy(dbuff, passwd, len);
}


static ssize_t encode_tunnel_password(fr_dbuff_t *dbuff, uint8_t const *in, size_t inlen, void *encoder_ctx)
{
	fr_md5_ctx_t	*md5_ctx, *md5_ctx_old;
	uint8_t		digest[RADIUS_AUTH_VECTOR_LENGTH];
	uint8_t		tpasswd[RADIUS_MAX_STRING_LENGTH];
	size_t		i, n;
	size_t		encrypted_len;
	fr_radius_ctx_t	*packet_ctx = encoder_ctx;
	uint32_t	r;
	size_t		len;
	ssize_t		slen;
	fr_dbuff_t	work_dbuff = FR_DBUFF_MAX_NO_ADVANCE(dbuff, RADIUS_MAX_STRING_LENGTH);

	/*
	 *	Limit the maximum size of the in password.  2 bytes
	 *	are taken up by the salt, and one by the encoded
	 *	"length" field.  Note that if we have a tag, the
	 *	"outlen" will be 252 octets, not 253 octets.
	 */
	if (inlen > (RADIUS_MAX_STRING_LENGTH - 3)) inlen = (RADIUS_MAX_STRING_LENGTH - 3);

	/*
	 *	If we still overflow the output, let the caller know
	 *	how many bytes would have been needed.
	 */
	FR_DBUFF_SET_RETURN(&work_dbuff, inlen + 3);
	fr_dbuff_set_to_start(&work_dbuff);

	/*
	 *	Length of the encrypted data is the clear-text
	 *	password length plus one byte which encodes the length
	 *	of the password.  We round up to the nearest encoding
	 *	block.  Note that this can result in the encoding
	 *	length being more than 253 octets.
	 */
	encrypted_len = ROUND_UP(inlen + 1, 16);

	/*
	 *	We need 2 octets for the salt, followed by the actual
	 *	encrypted data. By now we know the password, salt, and
	 *	length will fit; we are willing to have a short final
	 *	block.
	 */
	slen = fr_dbuff_set(&work_dbuff, encrypted_len + 2);
	if (slen < 0) encrypted_len -= -slen;
	fr_dbuff_set_to_start(&work_dbuff);

	len = encrypted_len + 2;	/* account for the salt */

	/*
	 *	Copy the password over, and fill the remainder with random data.
	 */
	memcpy(tpasswd + 3, in, inlen);

	for (i = 3 + inlen; i < (size_t)len; i++) {
		tpasswd[i] = fr_fast_rand(&packet_ctx->rand_ctx);
	}

	/*
	 *	Generate salt.  The RFCs say:
	 *
	 *	The high bit of salt[0] must be set, each salt in a
	 *	packet should be unique, and they should be random
	 *
	 *	So, we set the high bit, add in a counter, and then
	 *	add in some PRNG data.  should be OK..
	 */
	r = fr_fast_rand(&packet_ctx->rand_ctx);
	tpasswd[0] = (0x80 | (((packet_ctx->salt_offset++) & 0x07) << 4) | ((r >> 8) & 0x0f));
	tpasswd[1] = r & 0xff;
	tpasswd[2] = inlen;	/* length of the password string */

	md5_ctx = fr_md5_ctx_alloc(false);
	md5_ctx_old = fr_md5_ctx_alloc(true);

	fr_md5_update(md5_ctx, (uint8_t const *) packet_ctx->secret, talloc_array_length(packet_ctx->secret) - 1);
	fr_md5_ctx_copy(md5_ctx_old, md5_ctx);

	fr_md5_update(md5_ctx, packet_ctx->vector, RADIUS_AUTH_VECTOR_LENGTH);
	fr_md5_update(md5_ctx, &tpasswd[0], 2);

	for (n = 0; n < encrypted_len; n += AUTH_PASS_LEN) {
		size_t block_len;

		if (n > 0) {
			fr_md5_ctx_copy(md5_ctx, md5_ctx_old);
			fr_md5_update(md5_ctx, tpasswd + 2 + n - AUTH_PASS_LEN, AUTH_PASS_LEN);
		}
		fr_md5_final(digest, md5_ctx);

		block_len = encrypted_len - n;
		if (block_len > AUTH_PASS_LEN) block_len = AUTH_PASS_LEN;

		for (i = 0; i < block_len; i++) tpasswd[i + 2 + n] ^= digest[i];
	}

	fr_md5_ctx_free(&md5_ctx);
	fr_md5_ctx_free(&md5_ctx_old);

	FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, tpasswd, len);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t encode_tlv_hdr_internal(fr_dbuff_t *dbuff,
				       fr_da_stack_t *da_stack, unsigned int depth,
				       fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t		slen;
	fr_pair_t const	*vp = fr_cursor_current(cursor);
	fr_dict_attr_t const	*da = da_stack->da[depth];
	fr_dbuff_t		work_dbuff = FR_DBUFF_MAX_NO_ADVANCE(dbuff, 253);

	for (;;) {
		FR_PROTO_STACK_PRINT(da_stack, depth);

		/*
		 *	This attribute carries sub-TLVs.  The sub-TLVs
		 *	can only carry a total of 253 bytes of data.
		 */

		/*
		 *	Determine the nested type and call the appropriate encoder
		 */
		if (da_stack->da[depth + 1]->type == FR_TYPE_TLV) {
			slen = encode_tlv_hdr(&work_dbuff, da_stack, depth + 1, cursor, encoder_ctx);
		} else {
			slen = encode_rfc_hdr_internal(&work_dbuff, da_stack, depth + 1, cursor, encoder_ctx);
		}

		if (slen <= 0) return slen;

		/*
		 *	If nothing updated the attribute, stop
		 */
		if (!fr_cursor_current(cursor) || (vp == fr_cursor_current(cursor))) break;

		/*
		 *	We can encode multiple sub TLVs, if after
		 *	rebuilding the TLV Stack, the attribute
		 *	at this depth is the same.
		 */
		if ((da != da_stack->da[depth]) || (da_stack->depth < da->depth)) break;
		vp = fr_cursor_current(cursor);
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t encode_tlv_hdr(fr_dbuff_t *dbuff,
			      fr_da_stack_t *da_stack, unsigned int depth,
			      fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t			slen;
	fr_dbuff_marker_t	len_m;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	VP_VERIFY(fr_cursor_current(cursor));
	FR_PROTO_STACK_PRINT(da_stack, depth);

	if (da_stack->da[depth]->type != FR_TYPE_TLV) {
		fr_strerror_printf("%s: Expected type \"tlv\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da_stack->da[depth]->type, "?Unknown?"));
		return PAIR_ENCODE_FATAL_ERROR;
	}

	if (!da_stack->da[depth + 1]) {
		fr_strerror_printf("%s: Can't encode empty TLV", __FUNCTION__);
		return PAIR_ENCODE_SKIPPED;
	}

	/*
	 *	Encode the first level of TLVs
	 */
	FR_DBUFF_IN_RETURN(&work_dbuff, (uint8_t)da_stack->da[depth]->attr);
	fr_dbuff_marker(&len_m, &work_dbuff);		/* Mark the start of the length field */
	FR_DBUFF_ADVANCE_RETURN(&work_dbuff, 1);	/* One byte for the length */

	slen = encode_tlv_hdr_internal(&FR_DBUFF_MAX(&work_dbuff, 253), da_stack, depth, cursor, encoder_ctx);
	if (slen <= 0) return slen;

	fr_dbuff_in(&len_m, (uint8_t)(slen + 2));

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t encode_tags(fr_dbuff_t *dbuff, fr_pair_t *vps, void *encoder_ctx)
{
	ssize_t			slen;
	fr_pair_t const	*vp;
	fr_cursor_t		cursor;

	/*
	 *	Note that we skip tags inside of tags!
	 */
	fr_cursor_talloc_iter_init(&cursor, &vps, fr_proto_next_encodable, dict_radius, fr_pair_t);
	while ((vp = fr_cursor_current(&cursor))) {
		VP_VERIFY(vp);

		/*
		 *	Encode an individual VP
		 */
		slen = fr_radius_encode_pair(dbuff, &cursor, encoder_ctx);
		if (slen < 0) {
			if (slen == PAIR_ENCODE_SKIPPED) continue;
			return slen;
		}
	}

	return fr_dbuff_used(dbuff);
}


/** Encodes the data portion of an attribute
 *
 * @return
 *	> 0, Length of the data portion.
 *      = 0, we could not encode anything, skip this attribute (and don't encode the header)
 *	  unless it's one of a list of exceptions.
 *	< 0, How many additional bytes we'd need as a negative integer.
 *	PAIR_ENCODE_FATAL_ERROR - Abort encoding the packet.
 *	PAIR_ENCODE_SKIPPED - Unencodable value
 */
static ssize_t encode_value(fr_dbuff_t *dbuff,
			    fr_da_stack_t *da_stack, unsigned int depth,
			    fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t			slen;
	size_t			len;
	fr_pair_t const	*vp = fr_cursor_current(cursor);
	fr_dict_attr_t const	*da = da_stack->da[depth];
	fr_radius_ctx_t		*packet_ctx = encoder_ctx;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_t		value_dbuff;
	fr_dbuff_marker_t	value_start;
	fr_dbuff_marker_t	start;
	bool			encrypted = false;

	fr_dbuff_marker(&start, &work_dbuff);

	VP_VERIFY(vp);
	FR_PROTO_STACK_PRINT(da_stack, depth);

	/*
	 *	Catch errors early on.
	 */
	if (flag_encrypted(&vp->da->flags) && !packet_ctx) {
		fr_strerror_printf("Asked to encrypt attribute, but no packet context provided");
		return PAIR_ENCODE_FATAL_ERROR;
	}

	/*
	 *	It's a little weird to consider a TLV as a value,
	 *	but it seems to work OK.
	 */
	if (da->type == FR_TYPE_TLV) return encode_tlv_hdr(dbuff, da_stack, depth, cursor, encoder_ctx);

	/*
	 *	This has special requirements.
	 */
	if (da->type == FR_TYPE_STRUCT) {
		slen = fr_struct_to_network_dbuff(&work_dbuff, da_stack, depth, cursor, encoder_ctx, encode_value);
		if (slen <= 0) return slen;

		vp = fr_cursor_current(cursor);
		fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

		/*
		 *	Encode any TLV, attributes which are part of this structure.
		 *
		 *	The fr_struct_to_network() function can't do
		 *	this work, as it's not protocol aware, and
		 *	doesn't have the da_stack or encoder_ctx.
		 *
		 *	Note that we call the "internal" encode
		 *	function, as we don't want the encapsulating
		 *	TLV to be encoded here.  It's number is just
		 *	the field number in the struct.
		 */
		while (vp && (da_stack->da[depth] == da) && (da_stack->depth >= da->depth)) {
			slen = encode_tlv_hdr_internal(&work_dbuff, da_stack, depth + 1, cursor, encoder_ctx);
			if (slen < 0) return slen;

			vp = fr_cursor_current(cursor);
			fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);
		}

		return fr_dbuff_set(dbuff, &work_dbuff);
	}

	/*
	 *	If it's not a TLV, it should be a value type RFC
	 *	attribute make sure that it is.
	 */
	if (da_stack->da[depth + 1] != NULL) {
		fr_strerror_printf("%s: Encoding value but not at top of stack", __FUNCTION__);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	if (vp->da != da) {
		fr_strerror_printf("%s: Top of stack does not match vp->da", __FUNCTION__);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	switch (da->type) {
	case FR_TYPE_STRUCTURAL:
		fr_strerror_printf("%s: Called with structural type %s", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da_stack->da[depth]->type, "?Unknown?"));
		return PAIR_ENCODE_FATAL_ERROR;

	default:
		break;
	}

	/*
	 *	Write tag byte
	 *
	 *	The Tag field is one octet in length and is intended to provide a
	 *	means of grouping attributes in the same packet which refer to the
	 *	same tunnel.  If the value of the Tag field is greater than 0x00
	 *	and less than or equal to 0x1F, it SHOULD be interpreted as
	 *	indicating which tunnel (of several alternatives) this attribute
	 *	pertains.  If the Tag field is greater than 0x1F, it SHOULD be
	 *	interpreted as the first byte of the following String field.
	 *
	 *	If the first byte of the string value looks like a
	 *	tag, then we always encode a tag byte, even one that
	 *	is zero.
	 */
	if ((vp->da->type == FR_TYPE_STRING) && flag_has_tag(&vp->da->flags)) {
		if (packet_ctx->tag) {
			FR_DBUFF_IN_RETURN(&work_dbuff, (uint8_t)packet_ctx->tag);
		} else if (TAG_VALID(vp->vp_strvalue[0])) {
			FR_DBUFF_IN_RETURN(&work_dbuff, (uint8_t)0x00);
		}
	}

	/*
	 * Starting here is a value that may require encryption.
	 */
	value_dbuff = FR_DBUFF_NO_ADVANCE(&work_dbuff);
	fr_dbuff_marker(&value_start, &value_dbuff);

	/*
	 *	Set up the default sources for the data.
	 */
	len = fr_radius_attr_len(vp);

	/*
	 *	Invalid value, don't encode.
	 */
	if (len > RADIUS_MAX_STRING_LENGTH) {
		fr_strerror_printf("%s length of %zu bytes exceeds maximum value length",
				   vp->da->name, len);
		return PAIR_ENCODE_SKIPPED;
	}

	switch (da->type) {
	/*
	 *	If asked to encode more data than allowed, we
	 *	encode only the allowed data.
	 */
	case FR_TYPE_STRING:
		if (flag_abinary(&da->flags)) {
			slen = fr_radius_encode_abinary(vp, fr_dbuff_current(&value_dbuff), fr_dbuff_remaining(&value_dbuff));
			if (slen <= 0) return slen;

			FR_DBUFF_ADVANCE_RETURN(&value_dbuff, (size_t) slen);
			break;
		}
		FALL_THROUGH;

	case FR_TYPE_OCTETS:
		FR_DBUFF_IN_MEMCPY_RETURN(&value_dbuff, (uint8_t const *)(vp->vp_ptr), len);
		break;

	/*
	 *	Common encoder might add scope byte
	 */
	case FR_TYPE_IPV6_ADDR:
		FR_DBUFF_IN_MEMCPY_RETURN(&value_dbuff, vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
		break;

	/*
	 *	Common encoder doesn't add reserved byte
	 */
	case FR_TYPE_IPV6_PREFIX:
		len = fr_bytes_from_bits(vp->vp_ip.prefix);
		FR_DBUFF_IN_BYTES_RETURN(&value_dbuff, 0x00, vp->vp_ip.prefix);
		/* Only copy the minimum number of address bytes required */
		FR_DBUFF_IN_MEMCPY_RETURN(&value_dbuff, (uint8_t const *)vp->vp_ipv6addr, len);
		break;

	/*
	 *	Common encoder doesn't add reserved byte
	 */
	case FR_TYPE_IPV4_PREFIX:
		FR_DBUFF_IN_BYTES_RETURN(&value_dbuff, 0x00, vp->vp_ip.prefix);
		FR_DBUFF_IN_MEMCPY_RETURN(&value_dbuff, (uint8_t const *)&vp->vp_ipv4addr, sizeof(vp->vp_ipv4addr));
		break;

	/*
	 *	Simple data types use the common encoder.
	 */
	default:
		slen = fr_value_box_to_network(&value_dbuff, &vp->data);
		if (slen < 0) return PAIR_ENCODE_FATAL_ERROR;
		break;
	}

	/*
	 *	No data: don't encode the value.  The type and length should still
	 *	be written.
	 */
	if (fr_dbuff_used(&value_dbuff) == 0) {
		vp = fr_cursor_next(cursor);
		fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);
		return 0;
	}

	/*
	 *	Encrypt the various password styles
	 *
	 *	Attributes with encrypted values MUST be less than
	 *	128 bytes long.
	 */
	if (flag_encrypted(&da->flags)) switch (vp->da->flags.subtype) {
	case FLAG_ENCRYPT_USER_PASSWORD:
		/*
		 *	Encode the password in place
		 */
		slen = encode_password(&work_dbuff, fr_dbuff_current(&value_start), fr_dbuff_used(&value_dbuff),
				       packet_ctx->secret, packet_ctx->vector);
		if (slen < 0) return slen;
		encrypted = true;
		break;

	case FLAG_TAGGED_TUNNEL_PASSWORD:
	case FLAG_ENCRYPT_TUNNEL_PASSWORD:
		/*
		 *	Always encode the tag even if it's zero.
		 *
		 *	The Tunnel-Password uses 2 salt fields which
		 *	MAY have any value.  As a result, we always
		 *	encode a tag.  If we would omit the tag, then
		 *	perhaps one of the salt fields could be
		 *	mistaken for the tag.
		 */
		if (flag_has_tag(&vp->da->flags)) fr_dbuff_advance(&work_dbuff, 1);

		slen = encode_tunnel_password(&work_dbuff, fr_dbuff_current(&value_start),
					      fr_dbuff_used(&value_dbuff), packet_ctx);
		if (slen < 0) {
			fr_strerror_printf("%s too long", vp->da->name);
			return slen;
		}

		/*
		 *	Do this after so we don't mess up the input
		 *	value.
		 */
		if (flag_has_tag(&vp->da->flags)) fr_dbuff_current(&value_start)[0] = 0x00;
		encrypted = true;
		break;

	/*
	 *	The code above ensures that this attribute
	 *	always fits.
	 */
	case FLAG_ENCRYPT_ASCEND_SECRET:
		slen = fr_radius_ascend_secret(&work_dbuff,
					       fr_dbuff_current(&value_start), fr_dbuff_used(&value_dbuff),
					       packet_ctx->secret, packet_ctx->vector);
		if (slen < 0) return slen;
		encrypted = true;
		break;
	}

	if (!encrypted) fr_dbuff_set(&work_dbuff, &value_dbuff);

	/*
	 *	High byte of 32bit integers gets set to the tag
	 *	value.
	 *
	 *	The Tag field is one octet in length and is intended to provide a
	 *	means of grouping attributes in the same packet which refer to the
	 *	same tunnel.  Valid values for this field are 0x01 through 0x1F,
	 *	inclusive.  If the Tag field is unused, it MUST be zero (0x00).
	 */
	if ((vp->da->type == FR_TYPE_UINT32) && flag_has_tag(&vp->da->flags)) {
		/*
		 *	Only 24bit integers are allowed here
		 */
		if (fr_dbuff_current(&value_start)[0] != 0) {
			fr_strerror_printf("Integer overflow for tagged uint32 attribute");
			return PAIR_ENCODE_SKIPPED;
		}
		fr_dbuff_current(&value_start)[0] = packet_ctx->tag;
	}

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "value %s",
			  fr_table_str_by_value(fr_value_box_type_table, vp->vp_type, "<UNKNOWN>"));

	/*
	 *	Rebuilds the TLV stack for encoding the next attribute
	 */
	vp = fr_cursor_next(cursor);
	fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Breaks down large data into pieces, each with a header
 *
 * @param dbuff	dbuff that has at its end a header followed by too much data
 * 			for the header's one-byte length field
 * @param ptr		marker that points at said header
 * @param hdr_len	length of the headers that will be added
 * @param len		number of bytes of data, starting at ptr + ptr[1]
 * @param flag_offset	offset within header of a flag byte whose MSB is set for all
 *			but the last piece
 * @param vsa_offset	if non-zero, the offset of a length field in a (sub?)-header
 *			of size 3 that also needs to be adjusted to include the number
 *			of bytes of data in the piece
 *
 * NOTE: the header present on entry may be longer than hdr_len (vide the VSA case in
 * encode_extended_hdr()), in which case the size of first piece is more tightly
 * constrained then those following.
 *
 * attr_shift() is not like other encoding functions. The caller retrieved the data;
 * here we're chopping it into pieces that will fit into structures whose headers
 * have one-byte length fields (that have to include the header length). Markers
 * associated with a child can't access data before the child's start--but that's
 * where the data is, so we associate them with dbuff.
 */
static ssize_t attr_shift(fr_dbuff_t *dbuff,
			  fr_dbuff_marker_t *ptr, int hdr_len, ssize_t len,
			  int flag_offset, int vsa_offset)
{
	int			check_len = len - fr_dbuff_current(ptr)[1];
	int			total = hdr_len;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_marker_t	hdr, next_hdr, next_data;

	/*
	 *	Pass 1: Check if the addition of the headers
	 *	overflows the available freespace.  If so, return
	 *	what we were capable of encoding.
	 */

	while (check_len > (255 - hdr_len)) {
		total += hdr_len;
		check_len -= (255 - hdr_len);
	}

	/*
	 *	Note that this results in a number of attributes maybe
	 *	being marked as "encoded", but which aren't in the
	 *	packet.  Oh well.  The solution is to fix the
	 *	"encode_value" function to take into account the header
	 *	lengths.
	 */
	if (fr_dbuff_advance(&work_dbuff, total) < 0) {
		return (fr_dbuff_current(ptr) + fr_dbuff_current(ptr)[1]) - fr_dbuff_start(&work_dbuff);
	}

	/*
	 * 	Markers associated with dbuff so we can manipulate data
	 *	accumulated there.
	 */
	fr_dbuff_marker(&hdr, dbuff);
	fr_dbuff_set(&hdr, fr_dbuff_current(ptr));
	fr_dbuff_marker(&next_hdr, dbuff);
	fr_dbuff_marker(&next_data, dbuff);

	/*
	 *	Pass 2: Now that we know there's enough freespace,
	 *	re-arrange the data to form a set of valid
	 *	RADIUS attributes.
	 */
	for (;;) {
		/* Extend current attribute as much as possible. */
		int sublen = 255 - fr_dbuff_current(&hdr)[1];
		if (len < sublen) sublen = len;
		fr_dbuff_current(&hdr)[1] += sublen;

		/* Adjust the other length field if it exists. */
		if (vsa_offset) fr_dbuff_current(&hdr)[vsa_offset] += sublen;

		/* If all data are accounted for, we're done. */
		len -= sublen;
		if (len == 0) break;

		/* This attribute isn't the last, so flag it. */
		fr_dbuff_current(&hdr)[flag_offset] |= 0x80;

		/* Make room for another header. */
		fr_dbuff_set(&next_hdr, fr_dbuff_current(&hdr) + 255);
		fr_dbuff_set(&next_data, fr_dbuff_current(&next_hdr) + hdr_len);
		fr_dbuff_move(&next_data, &next_hdr, len);

		/* Copy current header into new header and advance to it... */
		fr_dbuff_set(&next_hdr, fr_dbuff_current(&hdr) + 255);
		fr_dbuff_move(&next_hdr, &hdr, hdr_len);
		fr_dbuff_advance(&hdr, 255 - hdr_len);

		/* ...and set its length to that of the header. */
		fr_dbuff_current(&hdr)[1] = hdr_len;
	}

	/* Clear our markers from dbuff's list */
	fr_dbuff_marker_release(&hdr);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode an "extended" attribute
 *
 */
static ssize_t encode_extended_hdr(fr_dbuff_t *dbuff,
				   fr_da_stack_t *da_stack, unsigned int depth,
				   fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t			slen;
#ifndef NDEBUG
	fr_type_t		vsa_type;
	int			jump = 3;
#endif
	int			extra;
	fr_dbuff_marker_t	hdr;
	fr_pair_t const	*vp = fr_cursor_current(cursor);
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_t		*attr_dbuff;

	fr_dbuff_marker(&hdr, &work_dbuff);

	VP_VERIFY(vp);
	FR_PROTO_STACK_PRINT(da_stack, depth);

	extra = flag_long_extended(&da_stack->da[0]->flags);

	/*
	 *	@fixme: check depth of stack
	 */
#ifndef NDEBUG
	vsa_type = da_stack->da[1]->type;
	if (fr_debug_lvl > 3) {
		jump += extra;
	}
#endif

	/*
	 *	Encode the header for "short" or "long" attributes
	 */

	/*
	 *	Encode which extended attribute it is.
	 */
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t)da_stack->da[depth++]->attr, 3 + extra);
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t)da_stack->da[depth]->attr);

	if (extra) FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, 0x00);	/* flags start off at zero */

	FR_PROTO_STACK_PRINT(da_stack, depth);

	/*
	 *	Handle VSA as "VENDOR + attr"
	 */
	if (da_stack->da[depth]->type == FR_TYPE_VSA) {
		depth++;

		FR_DBUFF_IN_RETURN(&work_dbuff, (uint32_t) da_stack->da[depth++]->attr);
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t)da_stack->da[depth]->attr);

		fr_dbuff_current(&hdr)[1] += 5;

		FR_PROTO_STACK_PRINT(da_stack, depth);
		FR_PROTO_HEX_DUMP(fr_dbuff_current(&hdr), fr_dbuff_current(&hdr)[1],
				  "header extended vendor specific");
	} else {
		FR_PROTO_HEX_DUMP(fr_dbuff_current(&hdr), fr_dbuff_current(&hdr)[1], "header extended");
	}

	/*
	 *	"outlen" can be larger than 255 here, but only for the
	 *	"long" extended type.
	 */
	attr_dbuff = !extra ? &FR_DBUFF_MAX(&work_dbuff, 255) : &work_dbuff;

	if (da_stack->da[depth]->type == FR_TYPE_TLV) {
		slen = encode_tlv_hdr_internal(attr_dbuff, da_stack, depth, cursor, encoder_ctx);
	} else {
		slen = encode_value(attr_dbuff, da_stack, depth, cursor, encoder_ctx);
	}
	if (slen <= 0) return slen;

	/*
	 *	There may be more than 255 octets of data encoded in
	 *	the attribute.  If so, move the data up in the packet,
	 *	and copy the existing header over.  Set the "M" flag ONLY
	 *	after copying the rest of the data.
	 */
	if (slen > (255 - fr_dbuff_current(&hdr)[1])) {
		slen = attr_shift(&work_dbuff, &hdr, 4, slen, 3, 0);
		fr_dbuff_set(dbuff, &work_dbuff);
		return slen;
	}

	fr_dbuff_current(&hdr)[1] += slen;

#ifndef NDEBUG
	if (fr_debug_lvl > 3) {
		if (vsa_type == FR_TYPE_VENDOR) jump += 5;

		FR_PROTO_HEX_DUMP(fr_dbuff_current(&hdr), jump, "header extended");
	}
#endif

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode an RFC format attribute, with the "concat" flag set
 *
 * If there isn't enough freespace in the packet, the data is
 * truncated to fit.
 *
 * The attribute is split on 253 byte boundaries, with a header
 * prepended to each chunk.
 */
static ssize_t encode_concat(fr_dbuff_t *dbuff,
			     fr_da_stack_t *da_stack, unsigned int depth,
			     fr_cursor_t *cursor, UNUSED void *encoder_ctx)
{
	uint8_t const		*p;
	size_t			left;
	ssize_t			slen;
	fr_pair_t const	*vp = fr_cursor_current(cursor);
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	FR_PROTO_STACK_PRINT(da_stack, depth);

	p = vp->vp_octets;
	slen = fr_radius_attr_len(vp);

	while (slen > 0) {
		fr_dbuff_marker_t	hdr;

		fr_dbuff_marker(&hdr, &work_dbuff);
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) da_stack->da[depth]->attr, 0x02);

		left = slen;

		/* no more than 253 octets */
		if (left > 253) left = 253;

		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, p, left);

		FR_PROTO_HEX_DUMP(fr_dbuff_current(&hdr) + 2, left, "concat value octets");
		FR_PROTO_HEX_DUMP(fr_dbuff_current(&hdr), 2, "concat header rfc");

		fr_dbuff_current(&hdr)[1] += left;
		p += left;
		slen -= left;
	}

	vp = fr_cursor_next(cursor);

	/*
	 *	@fixme: attributes with 'concat' MUST of type
	 *	'octets', and therefore CANNOT have any TLV data in them.
	 */
	fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode an RFC format TLV.
 *
 * This could be a standard attribute, or a TLV data type.
 * If it's a standard attribute, then vp->da->attr == attribute.
 * Otherwise, attribute may be something else.
 */
static ssize_t encode_rfc_hdr_internal(fr_dbuff_t *dbuff,
				       fr_da_stack_t *da_stack, unsigned int depth,
				       fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t 		slen;
	fr_dbuff_marker_t	hdr;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	FR_PROTO_STACK_PRINT(da_stack, depth);
	fr_dbuff_marker(&hdr, &work_dbuff);

	switch (da_stack->da[depth]->type) {
	default:
		fr_strerror_printf("%s: Called with structural type %s", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da_stack->da[depth]->type, "?Unknown?"));
		return PAIR_ENCODE_FATAL_ERROR;

	case FR_TYPE_STRUCT:
	case FR_TYPE_VALUE:
		if (((fr_dict_vendor_num_by_da(da_stack->da[depth]) == 0) && (da_stack->da[depth]->attr == 0)) ||
		    (da_stack->da[depth]->attr > 255)) {
			fr_strerror_printf("%s: Called with non-standard attribute %u", __FUNCTION__,
					   da_stack->da[depth]->attr);
			return PAIR_ENCODE_SKIPPED;
		}
		break;
	}

	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t)da_stack->da[depth]->attr, 0x02);

	slen = encode_value(&FR_DBUFF_MAX(&work_dbuff, 253), da_stack, depth, cursor, encoder_ctx);
	if (slen <= 0) return slen;

	fr_dbuff_current(&hdr)[1] += slen;

	FR_PROTO_HEX_DUMP(fr_dbuff_current(&hdr), 2, "header rfc");

	return fr_dbuff_set(dbuff, &work_dbuff);
}


/** Encode a VSA which is a TLV
 *
 * If it's in the RFC format, call encode_rfc_hdr_internal.  Otherwise, encode it here.
 */
static ssize_t encode_vendor_attr_hdr(fr_dbuff_t *dbuff,
				      fr_da_stack_t *da_stack, unsigned int depth,
				      fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t			slen;
	size_t			hdr_len;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_marker_t	hdr;
	fr_dict_attr_t const	*da, *dv;

	FR_PROTO_STACK_PRINT(da_stack, depth);
	fr_dbuff_marker(&hdr, &work_dbuff);

	dv = da_stack->da[depth++];

	if (dv->type != FR_TYPE_VENDOR) {
		fr_strerror_printf("Expected Vendor");
		return PAIR_ENCODE_FATAL_ERROR;
	}

	da = da_stack->da[depth];

	if ((da->type != FR_TYPE_TLV) && (dv->flags.type_size == 1) && (dv->flags.length == 1)) {
		return encode_rfc_hdr_internal(dbuff, da_stack, depth, cursor, encoder_ctx);
	}

	hdr_len = dv->flags.type_size + dv->flags.length;

	/*
	 *	Vendors use different widths for their
	 *	attribute number fields.
	 */
	switch (dv->flags.type_size) {
	default:
		fr_strerror_printf("%s: Internal sanity check failed, type %u", __FUNCTION__, (unsigned) dv->flags.type_size);
		return PAIR_ENCODE_FATAL_ERROR;

	case 4:
		fr_dbuff_in(&work_dbuff, (uint32_t)da->attr);
		break;

	case 2:
		fr_dbuff_in(&work_dbuff, (uint16_t)da->attr);
		break;

	case 1:
		fr_dbuff_in(&work_dbuff, (uint8_t)da->attr);
		break;
	}

	switch (dv->flags.length) {
	default:
		fr_strerror_printf("%s: Internal sanity check failed, length %u", __FUNCTION__, (unsigned) dv->flags.length);
		return PAIR_ENCODE_FATAL_ERROR;

	case 0:
		break;

	case 2:
		fr_dbuff_in_bytes(&work_dbuff, 0, (uint8_t)(dv->flags.type_size + 2));
		break;

	case 1:
		fr_dbuff_in_bytes(&work_dbuff, (uint8_t)(dv->flags.type_size + 1));
		break;
	}

	/*
	 *	Because we've now encoded the attribute header,
	 *	if this is a TLV, we must process it via the
	 *	internal tlv function, else we get a double TLV header.
	 */
	if (da_stack->da[depth]->type == FR_TYPE_TLV) {
		slen = encode_tlv_hdr_internal(&FR_DBUFF_MAX(&work_dbuff, 255), da_stack, depth, cursor, encoder_ctx);
	} else {
		slen = encode_value(&FR_DBUFF_MAX(&work_dbuff, 255), da_stack, depth, cursor, encoder_ctx);
	}
	if (slen <= 0) return slen;

	if (dv->flags.length) fr_dbuff_current(&hdr)[hdr_len - 1] += slen;

	FR_PROTO_HEX_DUMP(fr_dbuff_current(&hdr), hdr_len, "header vsa");

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode a WiMAX attribute
 *
 */
static ssize_t encode_wimax_hdr(fr_dbuff_t *dbuff,
				fr_da_stack_t *da_stack, unsigned int depth,
				fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t			slen;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_marker_t	hdr;
	fr_pair_t const	*vp = fr_cursor_current(cursor);

	fr_dbuff_marker(&hdr, &work_dbuff);

	VP_VERIFY(vp);
	FR_PROTO_STACK_PRINT(da_stack, depth);

	if (da_stack->da[depth++]->attr != FR_VENDOR_SPECIFIC) {
		fr_strerror_printf("%s: level[1] of da_stack is incorrect, must be Vendor-Specific (26)",
				   __FUNCTION__);
		return PAIR_ENCODE_FATAL_ERROR;
	}
	FR_PROTO_STACK_PRINT(da_stack, depth);

	if (da_stack->da[depth++]->attr != VENDORPEC_WIMAX) {
		fr_strerror_printf("%s: level[2] of da_stack is incorrect, must be Wimax vendor %i", __FUNCTION__,
				   VENDORPEC_WIMAX);
		return PAIR_ENCODE_FATAL_ERROR;
	}
	FR_PROTO_STACK_PRINT(da_stack, depth);

	/*
	 *	Build the Vendor-Specific header
	 */
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_VENDOR_SPECIFIC, 0x09);
	FR_DBUFF_IN_RETURN(&work_dbuff, (uint32_t) fr_dict_vendor_num_by_da(vp->da));

	/*
	 *	Encode the first attribute
	 */
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t)da_stack->da[depth]->attr, 0x03, 0x00);

	/*
	 *	"outlen" can be larger than 255 because of the "continuation" byte.
	 */

	if (da_stack->da[depth]->type == FR_TYPE_TLV) {
		slen = encode_tlv_hdr_internal(&work_dbuff, da_stack, depth, cursor, encoder_ctx);
		if (slen <= 0) return slen;
	} else {
		slen = encode_value(&work_dbuff, da_stack, depth, cursor, encoder_ctx);
		if (slen <= 0) return slen;
	}

	/*
	 *	There may be more than 252 octets of data encoded in
	 *	the attribute.  If so, move the data up in the packet,
	 *	and copy the existing header over.  Set the "C" flag
	 *	ONLY after copying the rest of the data.
	 */
	if (slen > (255 - fr_dbuff_current(&hdr)[1])) {
		slen = attr_shift(&work_dbuff, &hdr, fr_dbuff_current(&hdr)[1], slen, 8, 7);
		fr_dbuff_set(dbuff, &work_dbuff);
		return slen;
	}

	fr_dbuff_current(&hdr)[1] += slen;
	fr_dbuff_current(&hdr)[7] += slen;

	FR_PROTO_HEX_DUMP(fr_dbuff_current(&hdr), 9, "header wimax");

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode a Vendor-Specific attribute
 *
 */
static ssize_t encode_vsa_hdr(fr_dbuff_t *dbuff,
			      fr_da_stack_t *da_stack, unsigned int depth,
			      fr_cursor_t *cursor, void *encoder_ctx)
{
	fr_dbuff_marker_t	hdr;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dict_attr_t const	*da = da_stack->da[depth];
	ssize_t			len;

	fr_dbuff_marker(&hdr, &work_dbuff);

	FR_PROTO_STACK_PRINT(da_stack, depth);

	if (da->type != FR_TYPE_VSA) {
		fr_strerror_printf("%s: Expected type \"vsa\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
		return PAIR_ENCODE_FATAL_ERROR;
	}

	/*
	 *	Double-check for WiMAX format
	 */
	if (fr_dict_vendor_num_by_da(da_stack->da[depth + 1]) == VENDORPEC_WIMAX) {
		return encode_wimax_hdr(dbuff, da_stack, depth, cursor, encoder_ctx);
	}

	/*
	 *	Build the Vendor-Specific header
	 */
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_VENDOR_SPECIFIC, 0x06);

	/*
	 *	Now process the vendor ID part (which is one attribute deeper)
	 */
	da = da_stack->da[++depth];
	FR_PROTO_STACK_PRINT(da_stack, depth);

	if (da->type != FR_TYPE_VENDOR) {
		fr_strerror_printf("%s: Expected type \"vsa\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
		return PAIR_ENCODE_FATAL_ERROR;
	}

	FR_DBUFF_IN_RETURN(&work_dbuff, (uint32_t)da->attr);	/* Copy in the 32bit vendor ID */

	len = encode_vendor_attr_hdr(&FR_DBUFF_MAX(&work_dbuff, 255 - 6), da_stack, depth, cursor, encoder_ctx);
	if (len < 0) return len;

	fr_dbuff_current(&hdr)[1] = fr_dbuff_used(&work_dbuff);

	FR_PROTO_HEX_DUMP(fr_dbuff_current(&hdr), 6, "header vsa");

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode an RFC standard attribute 1..255
 *
 */
static ssize_t encode_rfc_hdr(fr_dbuff_t *dbuff, fr_da_stack_t *da_stack, unsigned int depth,
			      fr_cursor_t *cursor, void *encoder_ctx)
{
	fr_pair_t const	*vp = fr_cursor_current(cursor);
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_marker_t	start;

	fr_dbuff_marker(&start, &work_dbuff);

	/*
	 *	Sanity checks
	 */
	VP_VERIFY(vp);
	FR_PROTO_STACK_PRINT(da_stack, depth);

	switch (da_stack->da[depth]->type) {
	case FR_TYPE_TLV:
	case FR_TYPE_VSA:
	case FR_TYPE_VENDOR:
		/* FR_TYPE_STRUCT is actually allowed... */
		fr_strerror_printf("%s: Expected leaf type got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da_stack->da[depth]->type, "?Unknown?"));
		return PAIR_ENCODE_FATAL_ERROR;

	default:
		/*
		 *	Attribute 0 is fine as a TLV leaf, or VSA, but not
		 *	in the original standards space.
		 */
		if (((fr_dict_vendor_num_by_da(da_stack->da[depth]) == 0) && (da_stack->da[depth]->attr == 0)) ||
		    (da_stack->da[depth]->attr > 255)) {
			fr_strerror_printf("%s: Called with non-standard attribute %u", __FUNCTION__, vp->da->attr);
			return PAIR_ENCODE_SKIPPED;
		}
		break;
	}

	/*
	 *	Only CUI is allowed to have zero length.
	 *	Thank you, WiMAX!
	 */
	if ((vp->da == attr_chargeable_user_identity) && (vp->vp_length == 0)) {
		fr_dbuff_in_bytes(&work_dbuff, (uint8_t)vp->da->attr, 0x02);

		FR_PROTO_HEX_DUMP(fr_dbuff_current(&start), 2, "header rfc");

		vp = fr_cursor_next(cursor);
		fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);
		return fr_dbuff_set(dbuff, &work_dbuff);
	}

	/*
	 *	Message-Authenticator is hard-coded.
	 */
	if (vp->da == attr_message_authenticator) {
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t)vp->da->attr, 18);
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, RADIUS_MESSAGE_AUTHENTICATOR_LENGTH);

		FR_PROTO_HEX_DUMP(fr_dbuff_current(&start) + 2, RADIUS_MESSAGE_AUTHENTICATOR_LENGTH,
				  "message-authenticator");
		FR_PROTO_HEX_DUMP(fr_dbuff_current(&start), 2, "header rfc");

		vp = fr_cursor_next(cursor);
		fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);
		return fr_dbuff_set(dbuff, &work_dbuff);
	}

	return encode_rfc_hdr_internal(dbuff, da_stack, depth, cursor, encoder_ctx);
}

/** Encode a data structure into a RADIUS attribute
 *
 * This is the main entry point into the encoder.  It sets up the encoder array
 * we use for tracking our TLV/VSA nesting and then calls the appropriate
 * dispatch function.
 *
 * @param[out] dbuff		Where to write encoded data.
 * @param[in] cursor		Specifying attribute to encode.
 * @param[in] encoder_ctx	Additional data such as the shared secret to use.
 * @return
 *	- >0 The number of bytes written to out.
 *	- 0 Nothing to encode (or attribute skipped).
 *	- <0 an error occurred.
 */
ssize_t fr_radius_encode_pair(fr_dbuff_t *dbuff, fr_cursor_t *cursor, void *encoder_ctx)
{
	fr_pair_t const		*vp;
	ssize_t			len;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	fr_da_stack_t		da_stack;
	fr_dict_attr_t const	*da = NULL;

	if (!cursor) return PAIR_ENCODE_FATAL_ERROR;

	vp = fr_cursor_current(cursor);
	if (!vp) return 0;

	VP_VERIFY(vp);

	if (vp->da->depth > FR_DICT_MAX_TLV_STACK) {
		fr_strerror_printf("%s: Attribute depth %i exceeds maximum nesting depth %i",
				   __FUNCTION__, vp->da->depth, FR_DICT_MAX_TLV_STACK);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	/*
	 *	Tags are *top-level*, and are never nested.
	 */
	if (vp->da->type == FR_TYPE_GROUP) {
		fr_radius_ctx_t	*packet_ctx = encoder_ctx;

		if (!vp->da->flags.internal ||
		    !((vp->da->attr > FR_TAG_BASE) && (vp->da->attr < (FR_TAG_BASE + 0x20)))) {
			fr_cursor_next(cursor);
			return PAIR_ENCODE_SKIPPED;
		}

		packet_ctx->tag = vp->da->attr - FR_TAG_BASE;
		fr_assert(packet_ctx->tag > 0);
		fr_assert(packet_ctx->tag < 0x20);

		// recurse to encode the children of this attribute
		len = encode_tags(&work_dbuff, vp->vp_group, encoder_ctx);
		packet_ctx->tag = 0;
		if (len < 0) return len;

		fr_cursor_next(cursor); /* skip the tag attribute */
		return fr_dbuff_set(dbuff, &work_dbuff);
	}

	/*
	 *	Check for zero-length attributes.
	 */
	switch (vp->da->type) {
	default:
		break;

		/*
		 *	Only variable length data types can be
		 *	variable sized.  All others have fixed size.
		 */
	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
		if (fr_radius_attr_len(vp) != 0) break;

		/*
		 *	Zero-length strings are allowed for CUI
		 *	(thanks WiMAX!), and for
		 *	Message-Authenticator, because we will
		 *	automagically generate that one ourselves.
		 */
		if (!fr_dict_attr_is_top_level(vp->da) ||
		    ((vp->da->attr != FR_CHARGEABLE_USER_IDENTITY) &&
		     (vp->da->attr != FR_MESSAGE_AUTHENTICATOR))) {
			fr_cursor_next(cursor);
			fr_strerror_printf("Zero length string attributes not allowed");
			return PAIR_ENCODE_SKIPPED;
		}
		break;
	}

	/*
	 *	Nested structures of attributes can't be longer than
	 *	255 bytes, so each call to an encode function can
	 *	only use 255 bytes of buffer space at a time.
	 */

	/*
	 *	Fast path for the common case.
	 */
	if (vp->da->parent->flags.is_root && !vp->da->flags.subtype && (vp->vp_type != FR_TYPE_TLV)) {
		da_stack.da[0] = vp->da;
		da_stack.da[1] = NULL;
		da_stack.depth = 1;
		FR_PROTO_STACK_PRINT(&da_stack, 0);
		len = encode_rfc_hdr(&FR_DBUFF_MAX(&work_dbuff, UINT8_MAX), &da_stack, 0, cursor, encoder_ctx);
		if (len < 0) return len;
		return fr_dbuff_set(dbuff, &work_dbuff);
	}

	/*
	 *	Do more work to set up the stack for the complex case.
	 */
	fr_proto_da_stack_build(&da_stack, vp->da);
	FR_PROTO_STACK_PRINT(&da_stack, 0);

	da = da_stack.da[0];
	switch (da->type) {
	case FR_TYPE_OCTETS:
		if (flag_concat(&da->flags)) {
			/*
			 *	Attributes like EAP-Message are marked as
			 *	"concat", which means that they are fragmented
			 *	using a different scheme than the "long
			 *	extended" one.
			 */
			len = encode_concat(&work_dbuff, &da_stack, 0, cursor, encoder_ctx);
			if (len < 0) return len;
			break;
		}
		FALL_THROUGH;

	default:
		len = encode_rfc_hdr(&FR_DBUFF_MAX(&work_dbuff, UINT8_MAX), &da_stack, 0, cursor, encoder_ctx);
		if (len < 0) return len;
		break;

	case FR_TYPE_VSA:
		if (fr_dict_vendor_num_by_da(da) == VENDORPEC_WIMAX) {
			/*
			 *	WiMAX has a non-standard format for
			 *	its VSAs.  And, it can do "long"
			 *	attributes by fragmenting them inside
			 *	of the WiMAX VSA space.
			 */
			len = encode_wimax_hdr(&work_dbuff, &da_stack, 0, cursor, encoder_ctx);
			if (len < 0) return len;
			break;
		}
		len = encode_vsa_hdr(&FR_DBUFF_MAX(&work_dbuff, UINT8_MAX), &da_stack, 0, cursor, encoder_ctx);
		if (len < 0) return len;
		break;

	case FR_TYPE_TLV:
		if (!flag_extended(&da->flags)) {
			len = encode_tlv_hdr(&FR_DBUFF_MAX(&work_dbuff, UINT8_MAX), &da_stack, 0, cursor, encoder_ctx);
		} else {
			len = encode_extended_hdr(&FR_DBUFF_MAX(&work_dbuff, UINT8_MAX), &da_stack, 0, cursor, encoder_ctx);
		}
		if (len < 0) return len;
		break;

	case FR_TYPE_INVALID:
	case FR_TYPE_VENDOR:
	case FR_TYPE_MAX:
		fr_strerror_printf("%s: Cannot encode attribute %s", __FUNCTION__, vp->da->name);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	/*
	 *	We couldn't do it, so we didn't do anything.
	 */
	if (fr_cursor_current(cursor) == vp) {
		fr_strerror_printf("%s: Nested attribute structure too large to encode", __FUNCTION__);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static int _test_ctx_free(UNUSED fr_radius_ctx_t *ctx)
{
	fr_radius_free();

	return 0;
}

static int encode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	static uint8_t vector[RADIUS_AUTH_VECTOR_LENGTH] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	fr_radius_ctx_t	*test_ctx;

	if (fr_radius_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_radius_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->secret = talloc_strdup(test_ctx, "testing123");
	memcpy(test_ctx->vector, vector, sizeof(test_ctx->vector));
	test_ctx->rand_ctx.a = 6809;
	test_ctx->rand_ctx.b = 2112;
	talloc_set_destructor(test_ctx, _test_ctx_free);

	*out = test_ctx;

	return 0;
}

static ssize_t fr_radius_encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_t *vps, uint8_t *data, size_t data_len, void *proto_ctx)
{
	fr_radius_ctx_t	*test_ctx = talloc_get_type_abort(proto_ctx, fr_radius_ctx_t);
	int packet_type = FR_CODE_ACCESS_REQUEST;
	fr_pair_t *vp;
	ssize_t slen;

	vp = fr_pair_find_by_da(&vps, attr_packet_type);
	if (vp) packet_type = vp->vp_uint32;

	if ((packet_type == FR_CODE_ACCESS_REQUEST) || (packet_type == FR_CODE_STATUS_SERVER)) {
		vp = fr_pair_find_by_da(&vps, attr_packet_authentication_vector);
		if (vp && (vp->vp_length == RADIUS_AUTH_VECTOR_LENGTH)) {
			memcpy(data + 4, vp->vp_octets, RADIUS_AUTH_VECTOR_LENGTH);
		} else {
			int i;

			for (i = 0; i < RADIUS_AUTH_VECTOR_LENGTH; i++) {
				data[4 + i] = fr_fast_rand(&test_ctx->rand_ctx);
			}
		}
	}

	/*
	 *	@todo - pass in test_ctx to this function, so that we
	 *	can leverage a consistent random number generator.
	 */
	slen = fr_radius_encode(data, data_len, NULL, test_ctx->secret, talloc_array_length(test_ctx->secret) - 1,
				packet_type, 0, vps);
	if (slen <= 0) return slen;

	if (fr_radius_sign(data, NULL, (uint8_t const *) test_ctx->secret, talloc_array_length(test_ctx->secret) - 1) < 0) {
		return -1;
	}

	return slen;
}

/*
 *	No one else should be using this.
 */
extern void *fr_radius_next_encodable(void **prev, void *to_eval, void *uctx);

/*
 *	Test points
 */
extern fr_test_point_pair_encode_t radius_tp_encode_pair;
fr_test_point_pair_encode_t radius_tp_encode_pair = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_radius_encode_pair,
	.next_encodable	= fr_radius_next_encodable,
};


extern fr_test_point_proto_encode_t radius_tp_encode_proto;
fr_test_point_proto_encode_t radius_tp_encode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_radius_encode_proto
};
