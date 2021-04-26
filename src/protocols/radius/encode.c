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

static ssize_t encode_value(fr_dbuff_t *dbuff,
			    fr_da_stack_t *da_stack, unsigned int depth,
			    fr_dcursor_t *cursor, void *encode_ctx);

static ssize_t encode_attribute(fr_dbuff_t *dbuff,
				fr_da_stack_t *da_stack, unsigned int depth,
				fr_dcursor_t *cursor, void *encode_ctx);

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
static ssize_t encode_password(fr_dbuff_t *dbuff, fr_dbuff_marker_t *input, size_t inlen,
			       char const *secret, uint8_t const *vector)
{
	fr_md5_ctx_t	*md5_ctx, *md5_ctx_old;
	uint8_t	digest[RADIUS_AUTH_VECTOR_LENGTH];
	uint8_t	passwd[RADIUS_MAX_PASS_LENGTH] = {0};
	size_t		i, n;
	size_t		len;

	/*
	 *	If the length is zero, round it up.
	 */
	len = inlen;

	if (len > RADIUS_MAX_PASS_LENGTH) len = RADIUS_MAX_PASS_LENGTH;

	fr_dbuff_out_memcpy(passwd, input, len);
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


static ssize_t encode_tunnel_password(fr_dbuff_t *dbuff, fr_dbuff_marker_t *in, size_t inlen, void *encode_ctx)
{
	fr_md5_ctx_t	*md5_ctx, *md5_ctx_old;
	uint8_t		digest[RADIUS_AUTH_VECTOR_LENGTH];
	uint8_t		tpasswd[RADIUS_MAX_STRING_LENGTH];
	size_t		i, n;
	size_t		encrypted_len;
	fr_radius_ctx_t	*packet_ctx = encode_ctx;
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
	fr_dbuff_out_memcpy(tpasswd + 3, in, inlen);

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

/*
 *	Encode the contents of an attribute of type TLV.
 */
static ssize_t encode_tlv_children(fr_dbuff_t *dbuff,
				   fr_da_stack_t *da_stack, unsigned int depth,
				   fr_dcursor_t *cursor, void *encode_ctx)
{
	ssize_t		slen;
	fr_pair_t const	*vp = fr_dcursor_current(cursor);
	fr_dict_attr_t const	*da = da_stack->da[depth];
	fr_dbuff_t		work_dbuff = FR_DBUFF_MAX_NO_ADVANCE(dbuff, RADIUS_MAX_STRING_LENGTH);

	for (;;) {
		FR_PROTO_STACK_PRINT(da_stack, depth);

		/*
		 *	This attribute carries sub-TLVs.  The sub-TLVs
		 *	can only carry a total of 253 bytes of data.
		 */

		/*
		 *	Determine the nested type and call the appropriate encoder
		 */
		if (!da_stack->da[depth + 1]) {
			fr_dcursor_t child_cursor;

			if (vp->da != da_stack->da[depth]) {
				fr_strerror_printf("%s: Can't encode empty TLV", __FUNCTION__);
				return PAIR_ENCODE_SKIPPED;
			}

			fr_dcursor_init(&child_cursor, &vp->vp_group);
			vp = fr_dcursor_current(&child_cursor);
			fr_proto_da_stack_build(da_stack, vp->da);

			/*
			 *	Call ourselves recursively to encode children.
			 */
			slen = encode_tlv_children(&work_dbuff, da_stack, depth, &child_cursor, encode_ctx);
			if (slen <= 0) {
				if (slen == PAIR_ENCODE_SKIPPED) continue;
				return slen;
			}

			vp = fr_dcursor_next(cursor);
			fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

		} else {
			slen = encode_attribute(&work_dbuff, da_stack, depth + 1, cursor, encode_ctx);
		}
		if (slen <= 0) {
			if (slen == PAIR_ENCODE_SKIPPED) continue;
			return slen;
		}

		/*
		 *	If nothing updated the attribute, stop
		 */
		if (!fr_dcursor_current(cursor) || (vp == fr_dcursor_current(cursor))) break;

		/*
		 *	We can encode multiple sub TLVs, if after
		 *	rebuilding the TLV Stack, the attribute
		 *	at this depth is the same.
		 */
		if ((da != da_stack->da[depth]) || (da_stack->depth < da->depth)) break;
		vp = fr_dcursor_current(cursor);
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t encode_tags(fr_dbuff_t *dbuff, fr_pair_list_t const *vps, void *encode_ctx)
{
	ssize_t			slen;
	fr_pair_t const	*vp;
	fr_dcursor_t		cursor;

	/*
	 *	Note that we skip tags inside of tags!
	 */
	fr_dcursor_talloc_iter_init(&cursor, vps, fr_proto_next_encodable, dict_radius, fr_pair_t);
	while ((vp = fr_dcursor_current(&cursor))) {
		VP_VERIFY(vp);

		/*
		 *	Encode an individual VP
		 */
		slen = fr_radius_encode_pair(dbuff, &cursor, encode_ctx);
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
			    fr_dcursor_t *cursor, void *encode_ctx)
{
	ssize_t			slen;
	size_t			len;
	fr_pair_t const	*vp = fr_dcursor_current(cursor);
	fr_dict_attr_t const	*da = da_stack->da[depth];
	fr_radius_ctx_t		*packet_ctx = encode_ctx;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_t		value_dbuff;
	fr_dbuff_marker_t	value_start, src, dest;
	bool			encrypted = false;

	VP_VERIFY(vp);
	FR_PROTO_STACK_PRINT(da_stack, depth);

	/*
	 *	TLVs are just another type of value.
	 */
	if (da->type == FR_TYPE_TLV) return encode_tlv_children(dbuff, da_stack, depth, cursor, encode_ctx);

	/*
	 *	Catch errors early on.
	 */
	if (flag_encrypted(&vp->da->flags) && !packet_ctx) {
		fr_strerror_const("Asked to encrypt attribute, but no packet context provided");
		return PAIR_ENCODE_FATAL_ERROR;
	}

	/*
	 *	This has special requirements.
	 */
	if ((vp->da->type == FR_TYPE_STRUCT) || (da->type == FR_TYPE_STRUCT)) {
		slen = fr_struct_to_network(&work_dbuff, da_stack, depth, cursor, encode_ctx, encode_value,
					    encode_tlv_children);
		if (slen <= 0) return slen;

		vp = fr_dcursor_current(cursor);
		fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);
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

	if (fr_type_is_structural(da->type)) {
		fr_strerror_printf("%s: Called with structural type %s", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da_stack->da[depth]->type, "?Unknown?"));
		return PAIR_ENCODE_FATAL_ERROR;
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
	fr_dbuff_marker(&src, &value_dbuff);
	fr_dbuff_marker(&dest, &value_dbuff);

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
		 *	IPv4 addresses are normal, but IPv6 addresses are special to RADIUS.
		 */
	case FR_TYPE_COMBO_IP_ADDR:
		if (vp->vp_ip.af == AF_INET) goto encode;
		FALL_THROUGH;

	/*
	 *	Common encoder might add scope byte, which we don't want.
	 */
	case FR_TYPE_IPV6_ADDR:
		FR_DBUFF_IN_MEMCPY_RETURN(&value_dbuff, vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
		break;

	case FR_TYPE_COMBO_IP_PREFIX:
		if (vp->vp_ip.af == AF_INET) goto ipv4_prefix;
		FALL_THROUGH;

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
	ipv4_prefix:
		FR_DBUFF_IN_BYTES_RETURN(&value_dbuff, 0x00, vp->vp_ip.prefix);
		FR_DBUFF_IN_MEMCPY_RETURN(&value_dbuff, (uint8_t const *)&vp->vp_ipv4addr, sizeof(vp->vp_ipv4addr));
		break;

	/*
	 *	Special handling for "abinary".  Otherwise, fall
	 *	through to using the common encoder.
	 */
	case FR_TYPE_STRING:
		if (flag_abinary(&da->flags)) {
			slen = fr_radius_encode_abinary(vp, &value_dbuff);
			if (slen <= 0) return slen;
			break;
		}
		FALL_THROUGH;

	case FR_TYPE_OCTETS:

	/*
	 *	Simple data types use the common encoder.
	 */
	default:
	encode:
		slen = fr_value_box_to_network(&value_dbuff, &vp->data);
		if (slen <= 0) return slen;
		break;
	}

	/*
	 *	No data: don't encode the value.  The type and length should still
	 *	be written.
	 */
	if (fr_dbuff_used(&value_dbuff) == 0) {
		vp = fr_dcursor_next(cursor);
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
		slen = encode_password(&work_dbuff, &value_start, fr_dbuff_used(&value_dbuff),
				       packet_ctx->secret, packet_ctx->vector);
		if (slen < 0) return slen;
		encrypted = true;
		break;

	case FLAG_TAGGED_TUNNEL_PASSWORD:
	case FLAG_ENCRYPT_TUNNEL_PASSWORD:
		if (packet_ctx->disallow_tunnel_passwords) {
			fr_strerror_const("Attributes with 'encrypt=2' set cannot go into this packet.");
			return PAIR_ENCODE_SKIPPED;
		}

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

		slen = encode_tunnel_password(&work_dbuff, &value_start, fr_dbuff_used(&value_dbuff), packet_ctx);
		if (slen < 0) {
			fr_strerror_printf("%s too long", vp->da->name);
			return slen;
		}
		/*
		 *	Do this after so we don't mess up the input
		 *	value.
		 */
		if (flag_has_tag(&vp->da->flags)) {
			fr_dbuff_set_to_start(&value_start);
			fr_dbuff_in(&value_start, (uint8_t) 0x00);
		}
		encrypted = true;
		break;

	/*
	 *	The code above ensures that this attribute
	 *	always fits.
	 */
	case FLAG_ENCRYPT_ASCEND_SECRET:
		/*
		 *	@todo radius decoding also uses fr_radius_ascend_secret() (Vernam cipher
		 *	is its own inverse). As part of converting decode, make sure the caller
		 *	there can pass a marker so we can use it here, too.
		 */
		slen = fr_radius_ascend_secret(&work_dbuff, fr_dbuff_current(&value_start), fr_dbuff_used(&value_dbuff),
					       packet_ctx->secret, packet_ctx->vector);
		if (slen < 0) return slen;
		encrypted = true;
		break;
	}

	if (!encrypted) {
		fr_dbuff_set(&work_dbuff, &value_dbuff);
		fr_dbuff_set(&value_start, fr_dbuff_start(&value_dbuff));
	}

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
		uint8_t	msb = 0;
		/*
		 *	Only 24bit integers are allowed here
		 */
		fr_dbuff_set(&src,  &value_start);
		fr_dbuff_out(&msb, &src);
		if (msb != 0) {
			fr_strerror_const("Integer overflow for tagged uint32 attribute");
			return PAIR_ENCODE_SKIPPED;
		}
		fr_dbuff_set(&dest, &value_start);
		fr_dbuff_in(&dest, packet_ctx->tag);
	}

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "value %s",
			  fr_table_str_by_value(fr_value_box_type_table, vp->vp_type, "<UNKNOWN>"));

	/*
	 *	Rebuilds the TLV stack for encoding the next attribute
	 */
	vp = fr_dcursor_next(cursor);
	fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Breaks down large data into pieces, each with a header
 *
 * @param[out] data		we're fragmenting.
 * @param[in] data_len		the amount of data in the dbuff that makes up the value we're
 *      			splitting.
 * @param[in,out] hdr      	marker that points at said header
 * @param[in] hdr_len		length of the headers that will be added
 * @param[in] flag_offset	offset within header of a flag byte whose MSB is set for all
 *				but the last piece.
 * @param[in] vsa_offset	if non-zero, the offset of a length field in a (sub?)-header
 *				of size 3 that also needs to be adjusted to include the number
 *				of bytes of data in the piece
 * @return
 *      - <0 the number of bytes we would have needed to create
 *	  space for another attribute header in the buffer.
 *	- 0 data was not modified.
 *      - >0 the number additional bytes we used inserting extra
 *        headers.
 */
static ssize_t attr_fragment(fr_dbuff_t *data, size_t data_len, fr_dbuff_marker_t *hdr, size_t hdr_len,
			     int flag_offset, int vsa_offset)
{
	unsigned int		num_fragments, i = 0;
	size_t			max_frag_data = UINT8_MAX - hdr_len;
	fr_dbuff_t		frag_data = FR_DBUFF_NO_ADVANCE_ABS(hdr);
	fr_dbuff_marker_t	frag_hdr, frag_hdr_p;

	if (unlikely(!data_len)) return 0;	/* Shouldn't have been called */

	num_fragments = ROUND_UP_DIV(data_len, max_frag_data);
	if (num_fragments == 1) return 0;	/* Nothing to do */

	fr_dbuff_marker(&frag_hdr, &frag_data);
	fr_dbuff_marker(&frag_hdr_p, &frag_data);

	fr_dbuff_advance(&frag_data, hdr_len);

	FR_PROTO_HEX_DUMP(fr_dbuff_current(hdr), hdr_len + data_len, "attr_fragment in");
	for (;;) {
		bool	last = (i + 1) == num_fragments;
		uint8_t frag_len;

		/*
		 *	How long is this fragment?
		 */
		if (last) {
			frag_len = (data_len - (max_frag_data * (num_fragments - 1)));
		} else {
			frag_len = max_frag_data;
		}

		/*
		 *	Update the "outer" header to reflect the actual
		 *	length of the fragment
		 */
		fr_dbuff_set(&frag_hdr_p, &frag_hdr);
		fr_dbuff_advance(&frag_hdr_p, 1);
		fr_dbuff_in(&frag_hdr_p, (uint8_t)(hdr_len + frag_len));

		/*
		 *	Update the "inner" header.  The length here is
		 *	the inner VSA header length (3) + the fragment
		 *	length.
		 */
		if (vsa_offset) {
			fr_dbuff_set(&frag_hdr_p, fr_dbuff_current(&frag_hdr) + vsa_offset);
			fr_dbuff_in(&frag_hdr_p, (uint8_t)(3 + frag_len));
		}

		/*
		 *	Just over-ride the flag field.  Nothing else
		 *	uses it.
		 */
		fr_dbuff_set(&frag_hdr_p, fr_dbuff_current(&frag_hdr) + flag_offset);
		fr_dbuff_in(&frag_hdr_p, (uint8_t)(!last << 7));

		FR_PROTO_HEX_DUMP(fr_dbuff_current(hdr), frag_len + hdr_len,
				  "attr_fragment fragment %u/%u", i + 1, num_fragments);

		fr_dbuff_advance(&frag_data, frag_len);	/* Go to the start of the next fragment */
		if (last) break;

		/*
		 *	There's still trailing data after this
		 *	fragment.  Move the trailing data to *past*
		 *	the next header.  And after there's room, copy
		 *	the header over.
		 *
		 *	This process leaves the next header in place,
		 *	ready for the next iteration of the loop.
		 *
		 *	Yes, moving things multiple times is less than
		 *	efficient.  Oh well.  it's ~1K memmoved()
		 *	maybe 4 times.  We are nowhere near the CPU /
		 *	electrical requirements of Bitcoin.
		 */
		i++;

		fr_dbuff_set(&frag_hdr, &frag_data);		/* Remember where the header should be */
		fr_dbuff_advance(&frag_data, hdr_len);		/* Advance past the header */

		/*
		 *	Shift remaining data by hdr_len.
		 */
		FR_DBUFF_IN_MEMCPY_RETURN(&FR_DBUFF_NO_ADVANCE(&frag_data), &frag_hdr, data_len - (i * max_frag_data));
		fr_dbuff_in_memcpy(&FR_DBUFF_NO_ADVANCE(&frag_hdr), hdr, hdr_len);	/* Copy the old header over */
	}

	return fr_dbuff_set(data, &frag_data);
}

/** Encode an "extended" attribute
 *
 */
static ssize_t encode_extended(fr_dbuff_t *dbuff,
				   fr_da_stack_t *da_stack, unsigned int depth,
				   fr_dcursor_t *cursor, void *encode_ctx)
{
	ssize_t			slen;
	uint8_t			hlen;
	size_t			vendor_hdr;
	bool			extra;
	fr_dbuff_marker_t	hdr, length_field;
	fr_pair_t const	*vp = fr_dcursor_current(cursor);
	fr_dbuff_t		work_dbuff;

	VP_VERIFY(vp);
	FR_PROTO_STACK_PRINT(da_stack, depth);

	extra = flag_long_extended(&da_stack->da[0]->flags);

	/*
	 *	The data used here can be more than 255 bytes, but only for the
	 *	"long" extended type.
	 */
	if (extra) {
		work_dbuff = FR_DBUFF_COPY(dbuff);
	} else {
		work_dbuff = FR_DBUFF_MAX(dbuff, UINT8_MAX);
	}
	fr_dbuff_marker(&hdr, &work_dbuff);

	/*
	 *	Encode the header for "short" or "long" attributes
	 */
	hlen = 3 + extra;
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t)da_stack->da[depth++]->attr);
	fr_dbuff_marker(&length_field, &work_dbuff);
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, hlen); /* this gets overwritten later*/

	/*
	 *	Encode which extended attribute it is.
	 */
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

		hlen += 5;
		vendor_hdr = 5;

		FR_PROTO_STACK_PRINT(da_stack, depth);
		FR_PROTO_HEX_DUMP(fr_dbuff_current(&hdr), hlen, "header extended vendor specific");
	} else {
		vendor_hdr = 0;
		FR_PROTO_HEX_DUMP(fr_dbuff_current(&hdr), hlen, "header extended");
	}

	slen = encode_value(&work_dbuff, da_stack, depth, cursor, encode_ctx);
	if (slen <= 0) return slen;

	/*
	 *	There may be more than 255 octets of data encoded in
	 *	the attribute.  If so, move the data up in the packet,
	 *	and copy the existing header over.  Set the "M" flag ONLY
	 *	after copying the rest of the data.
	 *
	 *	Note that we add "vendor_hdr" to the length of the
	 *	encoded data.  That 5 octet field is logically part of
	 *	the data, and not part of the header.
	 */
	if (slen > (UINT8_MAX - hlen)) {
		slen = attr_fragment(&work_dbuff, (size_t)vendor_hdr + slen, &hdr, 4, 3, 0);
		if (slen <= 0) return slen;

		return fr_dbuff_set(dbuff, &work_dbuff);
	}

	fr_dbuff_in_bytes(&length_field, (uint8_t) fr_dbuff_used(&work_dbuff));
	FR_PROTO_HEX_DUMP(fr_dbuff_current(&hdr), hlen, "header extended");

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
			     fr_dcursor_t *cursor, UNUSED void *encode_ctx)
{
	uint8_t const		*p;
	size_t			data_len;
	fr_pair_t const	*vp = fr_dcursor_current(cursor);
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_marker_t	hdr;

	FR_PROTO_STACK_PRINT(da_stack, depth);

	p = vp->vp_octets;
	data_len = fr_radius_attr_len(vp);
	fr_dbuff_marker(&hdr, &work_dbuff);

	while (data_len > 0) {
		size_t frag_len = (data_len > RADIUS_MAX_STRING_LENGTH) ? RADIUS_MAX_STRING_LENGTH : data_len;

		fr_dbuff_set(&hdr, &work_dbuff);
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t) da_stack->da[depth]->attr, 0x00);

		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, p, frag_len);

		fr_dbuff_advance(&hdr, 1);
		fr_dbuff_in(&hdr, (uint8_t) (2 + frag_len));

		FR_PROTO_HEX_DUMP(fr_dbuff_current(&hdr) - 1, 2 + frag_len, "encode_concat fragment");

		p += frag_len;
		data_len -= frag_len;
	}

	vp = fr_dcursor_next(cursor);

	/*
	 *	@fixme: attributes with 'concat' MUST of type
	 *	'octets', and therefore CANNOT have any TLV data in them.
	 */
	fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode an RFC format attribute.
 *
 * This could be a standard attribute, or a TLV data type.
 * If it's a standard attribute, then vp->da->attr == attribute.
 * Otherwise, attribute may be something else.
 */
static ssize_t encode_attribute(fr_dbuff_t *dbuff,
				 fr_da_stack_t *da_stack, unsigned int depth,
				 fr_dcursor_t *cursor, void *encode_ctx)
{
	ssize_t 		slen;
	uint8_t			hlen;
	fr_dbuff_marker_t	hdr;
	fr_dbuff_t		work_dbuff = FR_DBUFF_MAX_NO_ADVANCE(dbuff, UINT8_MAX);

	FR_PROTO_STACK_PRINT(da_stack, depth);
	fr_dbuff_marker(&hdr, &work_dbuff);

	hlen = 2;
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t)da_stack->da[depth]->attr, hlen);

	slen = encode_value(&work_dbuff, da_stack, depth, cursor, encode_ctx);
	if (slen <= 0) return slen;

	fr_dbuff_advance(&hdr, 1);
	fr_dbuff_in_bytes(&hdr, (uint8_t)(hlen + slen));

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), 2, "header rfc");

	return fr_dbuff_set(dbuff, &work_dbuff);
}


/** Encode one full Vendor-Specific + Vendor-ID + Vendor-Attr + Vendor-Length + ...
 */
static ssize_t encode_vendor_attr(fr_dbuff_t *dbuff,
				  fr_da_stack_t *da_stack, unsigned int depth,
				  fr_dcursor_t *cursor, void *encode_ctx)
{
	ssize_t			slen;
	size_t			hdr_len;
	fr_dbuff_marker_t	hdr, length_field, vsa_length_field;
	fr_dict_attr_t const	*da, *dv;
	fr_dbuff_t		work_dbuff = FR_DBUFF_MAX_NO_ADVANCE(dbuff, UINT8_MAX);

	FR_PROTO_STACK_PRINT(da_stack, depth);

	dv = da_stack->da[depth++];

	if (dv->type != FR_TYPE_VENDOR) {
		fr_strerror_const("Expected Vendor");
		return PAIR_ENCODE_FATAL_ERROR;
	}

	fr_dbuff_marker(&hdr, &work_dbuff);

	/*
	 *	Build the Vendor-Specific header
	 */
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_VENDOR_SPECIFIC);

	fr_dbuff_marker(&length_field, &work_dbuff);
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, 0);

	FR_DBUFF_IN_RETURN(&work_dbuff, (uint32_t)dv->attr);	/* Copy in the 32bit vendor ID */

	/*
	 *	Now we encode one vendor attribute.
	 */
	da = da_stack->da[depth];
	fr_assert(da != NULL);

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

	/*
	 *	The length fields will get over-written later.
	 */
	switch (dv->flags.length) {
	default:
		fr_strerror_printf("%s: Internal sanity check failed, length %u", __FUNCTION__, (unsigned) dv->flags.length);
		return PAIR_ENCODE_FATAL_ERROR;

	case 0:
		break;

	case 2:
		fr_dbuff_in_bytes(&work_dbuff, 0);
		FALL_THROUGH;

	case 1:
		/*
		 *	Lenght fields are set to zero, because they
		 *	will get over-ridden later.
		 */
		fr_dbuff_marker(&vsa_length_field, &work_dbuff);
		fr_dbuff_in_bytes(&work_dbuff, 0);
		break;
	}

	slen = encode_value(&work_dbuff, da_stack, depth, cursor, encode_ctx);
	if (slen <= 0) return slen;

	if (dv->flags.length) {
		fr_dbuff_in(&vsa_length_field, (uint8_t)(hdr_len + slen));
	}

	fr_dbuff_in(&length_field, (uint8_t) fr_dbuff_used(&work_dbuff));

	FR_PROTO_HEX_DUMP(fr_dbuff_current(&hdr), 6 + hdr_len, "header vsa");

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode a WiMAX attribute
 *
 */
static ssize_t encode_wimax(fr_dbuff_t *dbuff,
				fr_da_stack_t *da_stack, unsigned int depth,
				fr_dcursor_t *cursor, void *encode_ctx)
{
	ssize_t			slen;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_marker_t	hdr, length_field, vsa_length_field;
	fr_dict_attr_t const	*dv;
	fr_pair_t const		*vp = fr_dcursor_current(cursor);

	fr_dbuff_marker(&hdr, &work_dbuff);

	VP_VERIFY(vp);
	FR_PROTO_STACK_PRINT(da_stack, depth);

	dv = da_stack->da[depth++];

	if (dv->type != FR_TYPE_VENDOR) {
		fr_strerror_const("Expected Vendor");
		return PAIR_ENCODE_FATAL_ERROR;
	}

	FR_PROTO_STACK_PRINT(da_stack, depth);

	/*
	 *	Build the Vendor-Specific header
	 */
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_VENDOR_SPECIFIC);
	fr_dbuff_marker(&length_field, &work_dbuff);
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, 0x09);

	FR_DBUFF_IN_RETURN(&work_dbuff, (uint32_t) dv->attr);

	/*
	 *	Encode the first attribute
	 */
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, (uint8_t)da_stack->da[depth]->attr);

	fr_dbuff_marker(&vsa_length_field, &work_dbuff);
	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, 0x03, 0x00); /* length + continuation, both may be overwritten later */

	/*
	 *	We don't bound the size of work_dbuff; it can use more than UINT8_MAX bytes
	 *	because of the "continuation" byte.
	 */
	slen = encode_value(&work_dbuff, da_stack, depth, cursor, encode_ctx);
	if (slen <= 0) return slen;

	/*
	 *	There may be more than 253 octets of data encoded in
	 *	the attribute.  If so, move the data up in the packet,
	 *	and copy the existing header over.  Set the "C" flag
	 *	ONLY after copying the rest of the data.
	 *
	 *	Note that we do NOT check 'slen' here, as it's only
	 *	the size of the sub-sub attribute, and doesn't include
	 *	the RADIUS attribute header, or Vendor-ID.
	 */
	if (fr_dbuff_used(&work_dbuff) > UINT8_MAX) {
		slen = attr_fragment(&work_dbuff, (size_t)slen, &hdr, 9, 8, 7);
		if (slen <= 0) return slen;

		return fr_dbuff_set(dbuff, &work_dbuff);
	}

	fr_dbuff_in_bytes(&vsa_length_field, (uint8_t) (fr_dbuff_used(&work_dbuff) - 6));
	fr_dbuff_in_bytes(&length_field, (uint8_t) fr_dbuff_used(&work_dbuff));

	FR_PROTO_HEX_DUMP(fr_dbuff_current(&hdr), 9, "header wimax");

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t encode_vendor(fr_dbuff_t *dbuff,
				 fr_da_stack_t *da_stack, unsigned int depth,
				 fr_dcursor_t *cursor, void *encode_ctx)
{
	fr_dict_attr_t const	*da = da_stack->da[depth];
	ssize_t			slen;
	fr_pair_t		*vp;
	fr_dict_vendor_t const	*dv;
	fr_dcursor_t		child_cursor;
	fr_dbuff_t		work_dbuff;

	FR_PROTO_STACK_PRINT(da_stack, depth);

	if (da->type != FR_TYPE_VENDOR) {
		fr_strerror_printf("%s: Expected type \"vendor\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
		return PAIR_ENCODE_FATAL_ERROR;
	}

	dv = fr_dict_vendor_by_da(da_stack->da[depth]);

	/*
	 *	Flat hierarchy, encode one attribute at a time.
	 *
	 *	Note that there's no attempt to encode multiple VSAs
	 *	into one attribute.  We can add that back as a flag,
	 *	once all of the nested attribute conversion has been
	 *	done.
	 */
	if (da_stack->da[depth + 1]) {
		if (dv && dv->flags) {
			return encode_wimax(dbuff, da_stack, depth, cursor, encode_ctx);
		}

		return encode_vendor_attr(dbuff, da_stack, depth, cursor, encode_ctx);
	}

	/*
	 *	Loop over the children of this attribute of type Vendor.
	 */
	vp = fr_dcursor_current(cursor);
	fr_assert(vp->da == da);
	work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	fr_dcursor_init(&child_cursor, &vp->vp_group);
	while ((vp = fr_dcursor_current(&child_cursor)) != NULL) {
		fr_proto_da_stack_build(da_stack, vp->da);

		if (dv && dv->flags) {
			slen = encode_wimax(&work_dbuff, da_stack, depth, &child_cursor, encode_ctx);
		} else {
			slen = encode_vendor_attr(&work_dbuff, da_stack, depth, &child_cursor, encode_ctx);
		}
		if (slen <= 0) {
			if (slen == PAIR_ENCODE_SKIPPED) continue;
			return slen;
		}
	}

	vp = fr_dcursor_next(cursor);
	fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode a Vendor-Specific attribute
 *
 */
static ssize_t encode_vsa(fr_dbuff_t *dbuff,
			      fr_da_stack_t *da_stack, unsigned int depth,
			      fr_dcursor_t *cursor, void *encode_ctx)
{
	ssize_t			slen;
	fr_pair_t		*vp;
	fr_dcursor_t		child_cursor;
	fr_dict_attr_t const	*da = da_stack->da[depth];
	fr_dbuff_t		work_dbuff;

	FR_PROTO_STACK_PRINT(da_stack, depth);

	if (da->type != FR_TYPE_VSA) {
		fr_strerror_printf("%s: Expected type \"vsa\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
		return PAIR_ENCODE_FATAL_ERROR;
	}

	/*
	 *	Loop over the contents of Vendor-Specific, each of
	 *	which MUST be of type FR_TYPE_VENDOR.
	 */
	if (da_stack->da[depth + 1]) {
		return encode_vendor(dbuff, da_stack, depth + 1, cursor, encode_ctx);
	}

	work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	vp = fr_dcursor_current(cursor);
	if (vp->da != da_stack->da[depth]) {
		fr_strerror_printf("%s: Can't encode empty Vendor-Specific", __FUNCTION__);
		return PAIR_ENCODE_SKIPPED;
	}

	/*
	 *	Loop over the children of this Vendor-Specific
	 *	attribute.
	 */
	fr_dcursor_init(&child_cursor, &vp->vp_group);
	while ((vp = fr_dcursor_current(&child_cursor)) != NULL) {
		fr_proto_da_stack_build(da_stack, vp->da);

		fr_assert(da_stack->da[depth + 1]->type == FR_TYPE_VENDOR);

		slen = encode_vendor(&work_dbuff, da_stack, depth + 1, &child_cursor, encode_ctx);
		if (slen <= 0) {
			if (slen == PAIR_ENCODE_SKIPPED) continue;
			return slen;
		}
	}

	/*
	 *	Fix up the da stack, and return the data we've encoded.
	 */
	vp = fr_dcursor_next(cursor);
	fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), 6, "header vsa");

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode an RFC standard attribute 1..255
 *
 *  This function is not the same as encode_attribute(), because this
 *  one treats some "top level" attributes as special.  e.g.
 *  Message-Authenticator.
 */
static ssize_t encode_rfc(fr_dbuff_t *dbuff, fr_da_stack_t *da_stack, unsigned int depth,
			      fr_dcursor_t *cursor, void *encode_ctx)
{
	fr_pair_t const	*vp = fr_dcursor_current(cursor);
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
		    (da_stack->da[depth]->attr > UINT8_MAX)) {
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

		vp = fr_dcursor_next(cursor);
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

		vp = fr_dcursor_next(cursor);
		fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);
		return fr_dbuff_set(dbuff, &work_dbuff);
	}

	/*
	 *	Once we've checked for various top-level magic, RFC attributes are just TLVs.
	 */
	return encode_attribute(dbuff, da_stack, depth, cursor, encode_ctx);
}

/** Encode a data structure into a RADIUS attribute
 *
 * This is the main entry point into the encoder.  It sets up the encoder array
 * we use for tracking our TLV/VSA nesting and then calls the appropriate
 * dispatch function.
 *
 * @param[out] dbuff		Where to write encoded data.
 * @param[in] cursor		Specifying attribute to encode.
 * @param[in] encode_ctx	Additional data such as the shared secret to use.
 * @return
 *	- >0 The number of bytes written to out.
 *	- 0 Nothing to encode (or attribute skipped).
 *	- <0 an error occurred.
 */
ssize_t fr_radius_encode_pair(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, void *encode_ctx)
{
	fr_pair_t const		*vp;
	ssize_t			slen;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	fr_da_stack_t		da_stack;
	fr_dict_attr_t const	*da = NULL;

	if (!cursor) return PAIR_ENCODE_FATAL_ERROR;

	vp = fr_dcursor_current(cursor);
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
		fr_radius_ctx_t	*packet_ctx = encode_ctx;

		if (!vp->da->flags.internal ||
		    !((vp->da->attr > FR_TAG_BASE) && (vp->da->attr < (FR_TAG_BASE + 0x20)))) {
			fr_dcursor_next(cursor);
			return PAIR_ENCODE_SKIPPED;
		}

		packet_ctx->tag = vp->da->attr - FR_TAG_BASE;
		fr_assert(packet_ctx->tag > 0);
		fr_assert(packet_ctx->tag < 0x20);

		// recurse to encode the children of this attribute
		slen = encode_tags(&work_dbuff, &vp->vp_group, encode_ctx);
		packet_ctx->tag = 0;
		if (slen < 0) return slen;

		fr_dcursor_next(cursor); /* skip the tag attribute */
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
			fr_dcursor_next(cursor);
			fr_strerror_const("Zero length string attributes not allowed");
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
	if (vp->da->parent->flags.is_root && !vp->da->flags.subtype) {
		switch (vp->da->type) {
		case FR_TYPE_LEAF:
			da_stack.da[0] = vp->da;
			da_stack.da[1] = NULL;
			da_stack.depth = 1;
			FR_PROTO_STACK_PRINT(&da_stack, 0);
			slen = encode_rfc(&work_dbuff, &da_stack, 0, cursor, encode_ctx);
			if (slen < 0) return slen;
			return fr_dbuff_set(dbuff, &work_dbuff);

		default:
			break;
		}
	}

	/*
	 *	Do more work to set up the stack for the complex case.
	 */
	fr_proto_da_stack_build(&da_stack, vp->da);
	FR_PROTO_STACK_PRINT(&da_stack, 0);

	/*
	 *	Top-level attributes get treated specially.  Things
	 *	like VSAs inside of extended attributes are handled
	 *	inside of type-specific encoders.
	 */
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
			slen = encode_concat(&work_dbuff, &da_stack, 0, cursor, encode_ctx);
			if (slen < 0) return slen;
			break;
		}
		FALL_THROUGH;

	default:
		slen = encode_rfc(&work_dbuff, &da_stack, 0, cursor, encode_ctx);
		if (slen < 0) return slen;
		break;

	case FR_TYPE_VSA:
		slen = encode_vsa(&work_dbuff, &da_stack, 0, cursor, encode_ctx);
		if (slen < 0) return slen;
		break;

	case FR_TYPE_TLV:
		if (!flag_extended(&da->flags)) {
			slen = encode_attribute(&work_dbuff, &da_stack, 0, cursor, encode_ctx);
		} else {
			slen = encode_extended(&work_dbuff, &da_stack, 0, cursor, encode_ctx);
		}
		if (slen < 0) return slen;
		break;

	case FR_TYPE_NULL:
	case FR_TYPE_VENDOR:
	case FR_TYPE_MAX:
		fr_strerror_printf("%s: Cannot encode attribute %s", __FUNCTION__, vp->da->name);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	/*
	 *	We couldn't do it, so we didn't do anything.
	 */
	if (fr_dcursor_current(cursor) == vp) {
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

static ssize_t fr_radius_encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_list_t *vps, uint8_t *data, size_t data_len, void *proto_ctx)
{
	fr_radius_ctx_t	*test_ctx = talloc_get_type_abort(proto_ctx, fr_radius_ctx_t);
	int packet_type = FR_RADIUS_CODE_ACCESS_REQUEST;
	fr_pair_t *vp;
	ssize_t slen;

	vp = fr_pair_find_by_da(vps, attr_packet_type, 0);
	if (vp) packet_type = vp->vp_uint32;

	if ((packet_type == FR_RADIUS_CODE_ACCESS_REQUEST) || (packet_type == FR_RADIUS_CODE_STATUS_SERVER)) {
		vp = fr_pair_find_by_da(vps, attr_packet_authentication_vector, 0);
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
extern void *fr_radius_next_encodable(fr_dlist_head_t *list, void *to_eval, void *uctx);

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
