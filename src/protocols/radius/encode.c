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
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/io/test_point.h>
#include "attrs.h"

static unsigned int salt_offset = 0;

static ssize_t encode_value(uint8_t *out, size_t outlen,
			    fr_dict_attr_t const **tlv_stack, int depth,
			    fr_cursor_t *cursor, void *encoder_ctx);

static ssize_t encode_rfc_hdr_internal(uint8_t *out, size_t outlen,
				       fr_dict_attr_t const **tlv_stack, unsigned int depth,
				       fr_cursor_t *cursor, void *encoder_ctx);

static ssize_t encode_tlv_hdr(uint8_t *out, size_t outlen,
			      fr_dict_attr_t const **tlv_stack, unsigned int depth,
			      fr_cursor_t *cursor, void *encoder_ctx);


/** Determine if the current attribute is encodable, or find the first one that is
 *
 * @param cursor to iterate over.
 * @return encodable VALUE_PAIR, or NULL if none available.
 */
static inline VALUE_PAIR *first_encodable(fr_cursor_t *cursor)
{
	VALUE_PAIR *vp;

	for (vp = fr_cursor_current(cursor); vp && vp->da->flags.internal; vp = fr_cursor_next(cursor));
	return fr_cursor_current(cursor);
}

/** Find the next attribute to encode
 *
 * @param cursor to iterate over.
 * @return encodable VALUE_PAIR, or NULL if none available.
 */
static inline VALUE_PAIR *next_encodable(fr_cursor_t *cursor)
{
	VALUE_PAIR *vp;

	for (;;) {
		vp = fr_cursor_next(cursor);
		if (!vp || !vp->da->flags.internal) break;
	}

	return fr_cursor_current(cursor);
}

/** Encode a CHAP password
 *
 * @bug FIXME: might not work with Ascend because
 * we use vp->vp_length, and Ascend gear likes
 * to send an extra '\0' in the string!
 */
int fr_radius_encode_chap_password(uint8_t *output, RADIUS_PACKET *packet, int id, VALUE_PAIR const *password)
{
	int		i;
	uint8_t		*ptr;
	uint8_t		string[FR_MAX_STRING_LEN * 2 + 1];
	VALUE_PAIR	*challenge;

	/*
	 *	Sanity check the input parameters
	 */
	if ((packet == NULL) || (password == NULL)) return -1;

	/*
	 *	Note that the password VP can be EITHER
	 *	a User-Password attribute (from a check-item list),
	 *	or a CHAP-Password attribute (the client asking
	 *	the library to encode it).
	 */

	i = 0;
	ptr = string;
	*ptr++ = id;

	i++;
	memcpy(ptr, password->vp_strvalue, password->vp_length);
	ptr += password->vp_length;
	i += password->vp_length;

	/*
	 *	Use Chap-Challenge pair if present,
	 *	Request Authenticator otherwise.
	 */
	challenge = fr_pair_find_by_da(packet->vps, attr_chap_challenge, TAG_ANY);
	if (challenge) {
		memcpy(ptr, challenge->vp_strvalue, challenge->vp_length);
		i += challenge->vp_length;
	} else {
		memcpy(ptr, packet->vector, RADIUS_AUTH_VECTOR_LENGTH);
		i += RADIUS_AUTH_VECTOR_LENGTH;
	}

	*output = id;
	fr_md5_calc((uint8_t *)output + 1, (uint8_t *)string, i);

	return 0;
}

/** Encode Tunnel-Password attributes when sending them out on the wire
 *
 * int *pwlen is updated to the new length of the encrypted
 * password - a multiple of 16 bytes.
 *
 * This is per RFC-2868 which adds a two char SALT to the initial intermediate
 * value MD5 hash.
 */
int fr_radius_encode_tunnel_password(char *passwd, size_t *pwlen, char const *secret, uint8_t const *vector)
{
	uint8_t		buffer[RADIUS_AUTH_VECTOR_LENGTH + FR_MAX_STRING_LEN + 3];
	unsigned char	digest[RADIUS_AUTH_VECTOR_LENGTH];
	char		*salt;
	int		i, n, secretlen;
	unsigned	len, n2;

	len = *pwlen;

	if (len > 127) len = 127;

	/*
	 *	Shift the password 3 positions right to place a salt and original
	 *	length, tag will be added automatically on packet send.
	 */
	for (n = len ; n >= 0 ; n--) passwd[n + 3] = passwd[n];
	salt = passwd;
	passwd += 2;

	/*
	 *	save original password length as first password character;
	 */
	*passwd = len;
	len += 1;


	/*
	 *	Generate salt.  The RFC's say:
	 *
	 *	The high bit of salt[0] must be set, each salt in a
	 *	packet should be unique, and they should be random
	 *
	 *	So, we set the high bit, add in a counter, and then
	 *	add in some CSPRNG data.  should be OK..
	 */
	salt[0] = (0x80 | (((salt_offset++) & 0x0f) << 3) | (fr_rand() & 0x07));
	salt[1] = fr_rand();

	/*
	 *	Padd password to multiple of AUTH_PASS_LEN bytes.
	 */
	n = len % AUTH_PASS_LEN;
	if (n) {
		n = AUTH_PASS_LEN - n;
		for (; n > 0; n--, len++) passwd[len] = 0;
	}
	/* set new password length */
	*pwlen = len + 2;

	/*
	 *	Use the secret to setup the decryption digest
	 */
	secretlen = talloc_array_length(secret) - 1;
	memcpy(buffer, secret, secretlen);

	for (n2 = 0; n2 < len; n2 +=AUTH_PASS_LEN) {
		if (!n2) {
			memcpy(buffer + secretlen, vector, RADIUS_AUTH_VECTOR_LENGTH);
			memcpy(buffer + secretlen + RADIUS_AUTH_VECTOR_LENGTH, salt, 2);
			fr_md5_calc(digest, buffer, secretlen + RADIUS_AUTH_VECTOR_LENGTH + 2);
		} else {
			memcpy(buffer + secretlen, passwd + n2 - AUTH_PASS_LEN, AUTH_PASS_LEN);
			fr_md5_calc(digest, buffer, secretlen + AUTH_PASS_LEN);
		}
		for (i = 0; i < AUTH_PASS_LEN; i++) passwd[i + n2] ^= digest[i];
	}
	passwd[n2] = 0;
	return 0;
}

/** Encode password
 *
 * We assume that the passwd buffer passed is big enough.
 * RFC2138 says the password is max 128 chars, so the size
 * of the passwd buffer must be at least 129 characters.
 * Preferably it's just FR_MAX_STRING_LEN.
 *
 * int *pwlen is updated to the new length of the encrypted
 * password - a multiple of 16 bytes.
 */
int fr_radius_encode_password(char *passwd, size_t *pwlen, char const *secret, uint8_t const *vector)
{
	fr_md5_ctx_t	*md5_ctx, *md5_ctx_old;
	uint8_t		digest[RADIUS_AUTH_VECTOR_LENGTH];
	int		i, n, secretlen;
	int		len;

	/*
	 *	RFC maximum is 128 bytes.
	 *
	 *	If length is zero, pad it out with zeros.
	 *
	 *	If the length isn't aligned to 16 bytes,
	 *	zero out the extra data.
	 */
	len = *pwlen;

	if (len > 128) len = 128;

	if (len == 0) {
		memset(passwd, 0, AUTH_PASS_LEN);
		len = AUTH_PASS_LEN;
	} else if ((len % AUTH_PASS_LEN) != 0) {
		memset(&passwd[len], 0, AUTH_PASS_LEN - (len % AUTH_PASS_LEN));
		len += AUTH_PASS_LEN - (len % AUTH_PASS_LEN);
	}
	*pwlen = len;

	/*
	 *	Use the secret to setup the decryption digest
	 */
	secretlen = talloc_array_length(secret) - 1;

	md5_ctx = fr_md5_ctx_alloc(false);
	md5_ctx_old = fr_md5_ctx_alloc(true);

	fr_md5_update(md5_ctx, (uint8_t const *) secret, secretlen);
	fr_md5_ctx_copy(md5_ctx_old, md5_ctx); /* save intermediate work */

	/*
	 *	Encrypt it in place.  Don't bother checking
	 *	len, as we've ensured above that it's OK.
	 */
	for (n = 0; n < len; n += AUTH_PASS_LEN) {
		if (n == 0) {
			fr_md5_update(md5_ctx, vector, AUTH_PASS_LEN);
			fr_md5_final(digest, md5_ctx);
		} else {
			fr_md5_ctx_copy(md5_ctx, md5_ctx_old);
			fr_md5_update(md5_ctx, (uint8_t *) passwd + n - AUTH_PASS_LEN, AUTH_PASS_LEN);
			fr_md5_final(digest, md5_ctx);
		}

		for (i = 0; i < AUTH_PASS_LEN; i++) passwd[i + n] ^= digest[i];
	}

	fr_md5_ctx_free(&md5_ctx);
	fr_md5_ctx_free(&md5_ctx_old);

	return 0;
}

static void encode_password(uint8_t *out, ssize_t *outlen, uint8_t const *input, size_t inlen,
			    char const *secret, uint8_t const *vector)
{
	fr_md5_ctx_t	*md5_ctx, *md5_ctx_old;
	uint8_t		digest[RADIUS_AUTH_VECTOR_LENGTH];
	uint8_t		passwd[RADIUS_MAX_PASS_LENGTH];
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
	*outlen = len;

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

	memcpy(out, passwd, len);
}


static void encode_tunnel_password(uint8_t *out, ssize_t *outlen,
				   uint8_t const *input, size_t inlen, size_t freespace,
				   char const *secret, uint8_t const *vector)
{
	fr_md5_ctx_t	*md5_ctx, *md5_ctx_old;
	uint8_t		digest[RADIUS_AUTH_VECTOR_LENGTH];
	size_t		i, n;
	size_t		encrypted_len;

	/*
	 *	The password gets encoded with a 1-byte "length"
	 *	field.  Ensure that it doesn't overflow.
	 */
	if (freespace > 253) freespace = 253;

	/*
	 *	Limit the maximum size of the input password.  2 bytes
	 *	are taken up by the salt, and one by the encoded
	 *	"length" field.  Note that if we have a tag, the
	 *	"freespace" will be 252 octets, not 253 octets.
	 */
	if (inlen > (freespace - 3)) inlen = freespace - 3;

	/*
	 *	Length of the encrypted data is the clear-text
	 *	password length plus one byte which encodes the length
	 *	of the password.  We round up to the nearest encoding
	 *	block.  Note that this can result in the encoding
	 *	length being more than 253 octets.
	 */
	encrypted_len = inlen + 1;
	if ((encrypted_len & 0x0f) != 0) {
		encrypted_len += 0x0f;
		encrypted_len &= ~0x0f;
	}

	/*
	 *	We need 2 octets for the salt, followed by the actual
	 *	encrypted data.
	 */
	if (encrypted_len > (freespace - 2)) encrypted_len = freespace - 2;

	*outlen = encrypted_len + 2;	/* account for the salt */

	/*
	 *	Copy the password over, and zero-fill the remainder.
	 */
	memcpy(out + 3, input, inlen);
	memset(out + 3 + inlen, 0, *outlen - 3 - inlen);

	/*
	 *	Generate salt.  The RFCs say:
	 *
	 *	The high bit of salt[0] must be set, each salt in a
	 *	packet should be unique, and they should be random
	 *
	 *	So, we set the high bit, add in a counter, and then
	 *	add in some CSPRNG data.  should be OK..
	 */
	out[0] = (0x80 | (((salt_offset++) & 0x0f) << 3) | (fr_rand() & 0x07));
	out[1] = fr_rand();
	out[2] = inlen;	/* length of the password string */

	md5_ctx = fr_md5_ctx_alloc(false);
	md5_ctx_old = fr_md5_ctx_alloc(true);

	fr_md5_update(md5_ctx, (uint8_t const *) secret, talloc_array_length(secret) - 1);
	fr_md5_ctx_copy(md5_ctx_old, md5_ctx);

	fr_md5_update(md5_ctx, vector, RADIUS_AUTH_VECTOR_LENGTH);
	fr_md5_update(md5_ctx, &out[0], 2);

	for (n = 0; n < encrypted_len; n += AUTH_PASS_LEN) {
		size_t block_len;

		if (n > 0) {
			fr_md5_ctx_copy(md5_ctx, md5_ctx_old);
			fr_md5_update(md5_ctx, out + 2 + n - AUTH_PASS_LEN, AUTH_PASS_LEN);
		}
		fr_md5_final(digest, md5_ctx);

		if ((2 + n + AUTH_PASS_LEN) < freespace) {
			block_len = AUTH_PASS_LEN;
		} else {
			block_len = freespace - 2 - n;
		}

		for (i = 0; i < block_len; i++) out[i + 2 + n] ^= digest[i];
	}

	fr_md5_ctx_free(&md5_ctx);
	fr_md5_ctx_free(&md5_ctx_old);
}

static ssize_t encode_tlv_hdr_internal(uint8_t *out, size_t outlen,
				       fr_dict_attr_t const **tlv_stack, unsigned int depth,
				       fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t			len;
	uint8_t			*p = out;
	VALUE_PAIR const	*vp = fr_cursor_current(cursor);
	fr_dict_attr_t const	*da = tlv_stack[depth];

	while (outlen >= 5) {
		size_t sublen;
		FR_PROTO_STACK_PRINT(tlv_stack, depth);

		/*
		 *	This attribute carries sub-TLVs.  The sub-TLVs
		 *	can only carry 255 bytes of data.
		 */
		sublen = outlen;
		if (sublen > 255) sublen = 255;

		/*
		 *	Determine the nested type and call the appropriate encoder
		 */
		if (tlv_stack[depth + 1]->type == FR_TYPE_TLV) {
			len = encode_tlv_hdr(p, sublen, tlv_stack, depth + 1, cursor, encoder_ctx);
		} else {
			len = encode_rfc_hdr_internal(p, sublen, tlv_stack, depth + 1, cursor, encoder_ctx);
		}

		if (len <= 0) return len;

		p += len;
		outlen -= len;				/* Subtract from the buffer we have available */

		/*
		 *	If nothing updated the attribute, stop
		 */
		if (!fr_cursor_current(cursor) || (vp == fr_cursor_current(cursor))) break;

		/*
		 *	We can encode multiple sub TLVs, if after
		 *	rebuilding the TLV Stack, the attribute
		 *	at this depth is the same.
		 */
		if (da != tlv_stack[depth]) break;
		vp = fr_cursor_current(cursor);
	}

	return p - out;
}

static ssize_t encode_tlv_hdr(uint8_t *out, size_t outlen,
			      fr_dict_attr_t const **tlv_stack, unsigned int depth,
			      fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t			len;

	VP_VERIFY(fr_cursor_current(cursor));
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	if (tlv_stack[depth]->type != FR_TYPE_TLV) {
		fr_strerror_printf("%s: Expected type \"tlv\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, tlv_stack[depth]->type, "?Unknown?"));
		return -1;
	}

	if (!tlv_stack[depth + 1]) {
		fr_strerror_printf("%s: Can't encode empty TLV", __FUNCTION__);
		return -1;
	}

	if (outlen < 5) return 0;

	/*
	 *	Encode the first level of TLVs
	 */
	out[0] = tlv_stack[depth]->attr & 0xff;
	out[1] = 2;	/* TLV header */

	if (outlen > 255) outlen = 255;

	len = encode_tlv_hdr_internal(out + out[1], outlen - out[1], tlv_stack, depth, cursor, encoder_ctx);
	if (len <= 0) return len;

	out[1] += len;

	return out[1];
}

/** Encodes the data portion of an attribute
 *
 * @return
 *	> 0, Length of the data portion.
 *      = 0, we could not encode anything, skip this attribute (and don't encode the header)
 *	< 0, failure.
 */
static ssize_t encode_value(uint8_t *out, size_t outlen,
			    fr_dict_attr_t const **tlv_stack, int depth,
			    fr_cursor_t *cursor, void *encoder_ctx)
{
	size_t			offset;
	ssize_t			len;
	uint8_t	const		*data = NULL;
	uint8_t			*ptr = out;
	uint8_t			buffer[64];
	VALUE_PAIR const	*vp = fr_cursor_current(cursor);
	fr_dict_attr_t const	*da = tlv_stack[depth];
	fr_radius_ctx_t		*packet_ctx = encoder_ctx;

	VP_VERIFY(vp);
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	/*
	 *	It's a little weird to consider a TLV as a value,
	 *	but it seems to work OK.
	 */
	if (da->type == FR_TYPE_TLV) {
		return encode_tlv_hdr(out, outlen, tlv_stack, depth, cursor, encoder_ctx);
	}

	/*
	 *	This has special requirements.
	 */
	if (da->type == FR_TYPE_STRUCT) {
		ssize_t struct_len;

		struct_len = fr_struct_to_network(out, outlen, tlv_stack[depth], cursor);
		if (struct_len <= 0) return struct_len;

		vp = fr_cursor_current(cursor);
		fr_proto_tlv_stack_build(tlv_stack, vp ? vp->da : NULL);

		out += struct_len;
		outlen -= struct_len;

		/*
		 *	Encode any TLV, attributes which are part of this structure.
		 *
		 *	The fr_struct_to_network() function can't do
		 *	this work, as it's not protocol aware, and
		 *	doesn't have the tlv_stack or encoder_ctx.
		 *
		 *	Note that we call the "internal" encode
		 *	function, as we don't want the encapsulating
		 *	TLV to be encoded here.  It's number is just
		 *	the field number in the struct.
		 */
		while (vp && (tlv_stack[depth] == da) && (outlen > 0)) {
			len = encode_tlv_hdr_internal(out, outlen, tlv_stack, depth + 1, cursor, encoder_ctx);
			if (len < 0) return len;

			struct_len += len;

			vp = fr_cursor_current(cursor);
			fr_proto_tlv_stack_build(tlv_stack, vp ? vp->da : NULL);
		}

		return struct_len;
	}

	/*
	 *	If it's not a TLV, it should be a value type RFC
	 *	attribute make sure that it is.
	 */
	if (tlv_stack[depth + 1] != NULL) {
		fr_strerror_printf("%s: Encoding value but not at top of stack", __FUNCTION__);
		return -1;
	}

	if (vp->da != da) {
		fr_strerror_printf("%s: Top of stack does not match vp->da", __FUNCTION__);
		return -1;
	}

	switch (da->type) {
	case FR_TYPE_STRUCTURAL:
		fr_strerror_printf("%s: Called with structural type %s", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, tlv_stack[depth]->type, "?Unknown?"));
		return -1;

	default:
		break;
	}

	/*
	 *	Set up the default sources for the data.
	 */
	len = fr_radius_attr_len(vp);

	switch (da->type) {
	/*
	 *	If asked to encode more data than allowed, we
	 *	encode only the allowed data.
	 */
	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
		if (da->flags.length && (len > da->flags.length)) len = da->flags.length;
		data = vp->vp_ptr;
		break;

	case FR_TYPE_ABINARY:
		data = vp->vp_filter;
		break;

	/*
	 *	Common encoder might add scope byte
	 */
	case FR_TYPE_IPV6_ADDR:
		memcpy(buffer, vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
		data = buffer;
		break;

	/*
	 *	Common encoder doesn't add reserved byte
	 */
	case FR_TYPE_IPV6_PREFIX:
		buffer[0] = 0;
		buffer[1] = vp->vp_ip.prefix;
		len = vp->vp_ip.prefix >> 3;			/* Convert bits to whole bytes */
		memcpy(buffer + 2, vp->vp_ipv6addr, len);	/* Only copy the minimum number of address bytes required */
		len += 2;					/* Reserved and prefix bytes */
		data = buffer;
		break;

	/*
	 *	Common encoder doesn't add reserved byte
	 */
	case FR_TYPE_IPV4_PREFIX:
		buffer[0] = 0;
		buffer[1] = vp->vp_ip.prefix;
		memcpy(buffer + 2, &vp->vp_ipv4addr, sizeof(vp->vp_ipv4addr));
		data = buffer;
		break;

	/*
	 *	Simple data types use the common encoder.
	 */
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IFID:
	case FR_TYPE_ETHERNET:	/* just in case */
	case FR_TYPE_BOOL:
	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
	case FR_TYPE_INT8:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:
	case FR_TYPE_DATE:
		len = fr_value_box_to_network(NULL, buffer, sizeof(buffer), &vp->data);
		if (len < 0) return -1;
		data = buffer;
		break;

	case FR_TYPE_INVALID:
	case FR_TYPE_EXTENDED:
	case FR_TYPE_COMBO_IP_ADDR:	/* Should have been converted to concrete equivalent */
	case FR_TYPE_COMBO_IP_PREFIX:	/* Should have been converted to concrete equivalent */
	case FR_TYPE_VSA:
	case FR_TYPE_VENDOR:
	case FR_TYPE_TLV:
	case FR_TYPE_STRUCT:
	case FR_TYPE_SIZE:
	case FR_TYPE_TIME_DELTA:
	case FR_TYPE_FLOAT32:
	case FR_TYPE_FLOAT64:
	case FR_TYPE_GROUP:
	case FR_TYPE_VALUE_BOX:
	case FR_TYPE_MAX:
		fr_strerror_printf("Unsupported attribute type %d", da->type);
		return -1;
	}

	/*
	 *	No data: don't encode the value.  The type and length should still
	 *	be written.
	 */
	if (!data || (len == 0)) {
		vp = next_encodable(cursor);
		fr_proto_tlv_stack_build(tlv_stack, vp ? vp->da : NULL);
		return 0;
	}

	/*
	 *	Bind the data to the calling size
	 */
	if (len > (ssize_t)outlen) len = outlen;

	if (vp->da->flags.encrypt && !packet_ctx) {
		fr_strerror_printf("Asked to encrypt attribute, but no packet context provided");
		return -1;
	}
	/*
	 *	Encrypt the various password styles
	 *
	 *	Attributes with encrypted values MUST be less than
	 *	128 bytes long.
	 */
	if (da->type != FR_TYPE_STRUCT) switch (vp->da->flags.encrypt) {
	case FLAG_ENCRYPT_USER_PASSWORD:
		encode_password(ptr, &len, data, len, packet_ctx->secret, packet_ctx->vector);
		break;

	case FLAG_ENCRYPT_TUNNEL_PASSWORD:
		offset = 0;
		if (da->flags.has_tag) offset = 1;

		/*
		 *	Check if there's enough freespace.  If there isn't,
		 *	we discard the attribute.
		 *
		 *	This is ONLY a problem if we have multiple VSA's
		 *	in one Vendor-Specific, though.
		 */
		if (outlen < (18 + offset)) return 0;

		if (offset) ptr[0] = TAG_VALID(vp->tag) ? vp->tag : TAG_NONE;

		encode_tunnel_password(ptr + offset, &len, data, len,
				       outlen - offset, packet_ctx->secret, packet_ctx->vector);
		len += offset;
		break;

		/*
		 *	The code above ensures that this attribute
		 *	always fits.
		 */
	case FLAG_ENCRYPT_ASCEND_SECRET:
		if (len != 16) return 0;

		fr_radius_ascend_secret(ptr, packet_ctx->vector, packet_ctx->secret, data);
		len = RADIUS_AUTH_VECTOR_LENGTH;
		break;

	default:
		if (vp->da->flags.has_tag && TAG_VALID(vp->tag)) {
			if (vp->vp_type == FR_TYPE_STRING) {
				if (len > ((ssize_t) (outlen - 1))) len = outlen - 1;
				ptr[0] = vp->tag;
				ptr++;
			} else if (vp->vp_type == FR_TYPE_UINT32) {
				buffer[0] = vp->tag;
			} /* else it can't be any other type */
		}
		memcpy(ptr, data, len);
		break;
	} /* switch over encryption flags */

	FR_PROTO_HEX_DUMP(out, len, "value %s", fr_table_str_by_value(fr_value_box_type_table, vp->vp_type, "<UNKNOWN>"));

	/*
	 *	Rebuilds the TLV stack for encoding the next attribute
	 */
	vp = next_encodable(cursor);
	fr_proto_tlv_stack_build(tlv_stack, vp ? vp->da : NULL);

	return len + (ptr - out);
}

static ssize_t attr_shift(uint8_t const *start, uint8_t const *end,
			  uint8_t *ptr, int hdr_len, ssize_t len,
			  int flag_offset, int vsa_offset)
{
	int check_len = len - ptr[1];
	int total = len + hdr_len;

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
	if ((ptr + ptr[1] + total) > end) return (ptr + ptr[1]) - start;

	/*
	 *	Pass 2: Now that we know there's enough freespace,
	 *	re-arrange the data to form a set of valid
	 *	RADIUS attributes.
	 */
	while (1) {
		int sublen = 255 - ptr[1];

		if (len <= sublen) break;

		len -= sublen;
		memmove(ptr + 255 + hdr_len, ptr + 255, sublen);
		memmove(ptr + 255, ptr, hdr_len);
		ptr[1] += sublen;
		if (vsa_offset) ptr[vsa_offset] += sublen;
		ptr[flag_offset] |= 0x80;

		ptr += 255;
		ptr[1] = hdr_len;
		if (vsa_offset) ptr[vsa_offset] = 3;
	}

	ptr[1] += len;
	if (vsa_offset) ptr[vsa_offset] += len;

	return (ptr + ptr[1]) - start;
}

/** Encode an "extended" attribute
 *
 */
static int encode_extended_hdr(uint8_t *out, size_t outlen,
			       fr_dict_attr_t const **tlv_stack, unsigned int depth,
			       fr_cursor_t *cursor, void *encoder_ctx)
{
	int			len;
	fr_type_t		attr_type;
#ifndef NDEBUG
	fr_type_t		vsa_type;
	int			jump = 3;
#endif
	uint8_t			*start = out;
	VALUE_PAIR const	*vp = fr_cursor_current(cursor);

	VP_VERIFY(vp);
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	/*
	 *	@fixme: check depth of stack
	 */
	attr_type = tlv_stack[0]->type;
#ifndef NDEBUG
	vsa_type = tlv_stack[1]->type;
	if (fr_debug_lvl > 3) {
		jump += tlv_stack[0]->flags.extra;
	}
#endif

	/*
	 *	Encode the header for "short" or "long" attributes
	 */
	switch (attr_type) {
	case FR_TYPE_EXTENDED:
		if (outlen < (size_t) (3 + tlv_stack[0]->flags.extra)) return 0;

		/*
		 *	Encode which extended attribute it is.
		 */
		out[0] = tlv_stack[depth++]->attr & 0xff;
		out[1] = 3 + tlv_stack[0]->flags.extra;
		out[2] = tlv_stack[depth]->attr & 0xff;

		if (tlv_stack[0]->flags.extra) out[3] = 0;	/* flags start off at zero */
		break;

	default:
		fr_strerror_printf("%s : Called for non-extended attribute type %s",
				   __FUNCTION__, fr_table_str_by_value(fr_value_box_type_table,
				   tlv_stack[depth]->type, "?Unknown?"));
		return -1;
	}

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	/*
	 *	Handle VSA as "VENDOR + attr"
	 */
	if (tlv_stack[depth]->type == FR_TYPE_VSA) {
		uint8_t *evs = out + out[1];
		uint32_t lvalue;

		if (outlen < (size_t) (out[1] + 5)) return 0;

		depth++;

		lvalue = htonl(tlv_stack[depth++]->attr);
		memcpy(evs, &lvalue, 4);

		evs[4] = tlv_stack[depth]->attr & 0xff;

		out[1] += 5;

		FR_PROTO_STACK_PRINT(tlv_stack, depth);
		FR_PROTO_HEX_DUMP(out, out[1], "header extended vendor specific");
	} else {
		FR_PROTO_HEX_DUMP(out, out[1], "header extended");
	}

	/*
	 *	"outlen" can be larger than 255 here, but only for the
	 *	"long" extended type.
	 */
	if ((attr_type == FR_TYPE_EXTENDED) && !tlv_stack[0]->flags.extra && (outlen > 255)) outlen = 255;

	if (tlv_stack[depth]->type == FR_TYPE_TLV) {
		len = encode_tlv_hdr_internal(out + out[1], outlen - out[1], tlv_stack, depth, cursor, encoder_ctx);
	} else {
		len = encode_value(out + out[1], outlen - out[1], tlv_stack, depth, cursor, encoder_ctx);
	}
	if (len <= 0) return len;

	/*
	 *	There may be more than 255 octets of data encoded in
	 *	the attribute.  If so, move the data up in the packet,
	 *	and copy the existing header over.  Set the "M" flag ONLY
	 *	after copying the rest of the data.
	 */
	if (len > (255 - out[1])) {
		return attr_shift(start, start + outlen, out, 4, len, 3, 0);
	}

	out[1] += len;

#ifndef NDEBUG
	if (fr_debug_lvl > 3) {
		if (vsa_type == FR_TYPE_VENDOR) jump += 5;

		FR_PROTO_HEX_DUMP(out, jump, "header extended");
	}
#endif

	return (out + out[1]) - start;
}

/** Encode an RFC format attribute, with the "concat" flag set
 *
 * If there isn't enough freespace in the packet, the data is
 * truncated to fit.
 *
 * The attribute is split on 253 byte boundaries, with a header
 * prepended to each chunk.
 */
static ssize_t encode_concat(uint8_t *out, size_t outlen,
			     fr_dict_attr_t const **tlv_stack, unsigned int depth,
			     fr_cursor_t *cursor, UNUSED void *encoder_ctx)
{
	uint8_t			*ptr = out;
	uint8_t			const *p;
	size_t			len, left;
	VALUE_PAIR const	*vp = fr_cursor_current(cursor);

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	p = vp->vp_octets;
	len = fr_radius_attr_len(vp);

	while (len > 0) {
		if (outlen <= 2) break;

		ptr[0] = tlv_stack[depth]->attr & 0xff;
		ptr[1] = 2;

		left = len;

		/* no more than 253 octets */
		if (left > 253) left = 253;

		/* no more than "freespace" octets */
		if (outlen < (left + 2)) left = outlen - 2;

		memcpy(ptr + 2, p, left);

		FR_PROTO_HEX_DUMP(ptr + 2, left, "concat value octets");
		FR_PROTO_HEX_DUMP(ptr, 2, "concat header rfc");

		ptr[1] += left;
		ptr += ptr[1];
		p += left;
		outlen -= left;
		len -= left;
	}

	vp = next_encodable(cursor);

	/*
	 *	@fixme: attributes with 'concat' MUST of type
	 *	'octets', and therefore CANNOT have any TLV data in them.
	 */
	fr_proto_tlv_stack_build(tlv_stack, vp ? vp->da : NULL);

	return ptr - out;
}

/** Encode an RFC format TLV.
 *
 * This could be a standard attribute, or a TLV data type.
 * If it's a standard attribute, then vp->da->attr == attribute.
 * Otherwise, attribute may be something else.
 */
static ssize_t encode_rfc_hdr_internal(uint8_t *out, size_t outlen,
				       fr_dict_attr_t const **tlv_stack, unsigned int depth,
				       fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t len;

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	switch (tlv_stack[depth]->type) {
	default:
		fr_strerror_printf("%s: Called with structural type %s", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, tlv_stack[depth]->type, "?Unknown?"));
		return -1;

	case FR_TYPE_STRUCT:
	case FR_TYPE_VALUES:
		if (((fr_dict_vendor_num_by_da(tlv_stack[depth]) == 0) && (tlv_stack[depth]->attr == 0)) ||
		    (tlv_stack[depth]->attr > 255)) {
			fr_strerror_printf("%s: Called with non-standard attribute %u", __FUNCTION__,
					   tlv_stack[depth]->attr);
			return -1;
		}
		break;
	}

	if (outlen <= 2) return 0;

	out[0] = tlv_stack[depth]->attr & 0xff;
	out[1] = 2;

	if (outlen > 255) outlen = 255;

	len = encode_value(out + out[1], outlen - out[1], tlv_stack, depth, cursor, encoder_ctx);
	if (len <= 0) return len;

	out[1] += len;

	FR_PROTO_HEX_DUMP(out, 2, "header rfc");

	return out[1];
}


/** Encode a VSA which is a TLV
 *
 * If it's in the RFC format, call encode_rfc_hdr_internal.  Otherwise, encode it here.
 */
static ssize_t encode_vendor_attr_hdr(uint8_t *out, size_t outlen,
				      fr_dict_attr_t const **tlv_stack, unsigned int depth,
				      fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t			len;
	size_t			hdr_len;
	fr_dict_attr_t const	*da, *dv;

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	dv = tlv_stack[depth++];

	if (dv->type != FR_TYPE_VENDOR) {
		fr_strerror_printf("Expected Vendor");
		return -1;
	}

	da = tlv_stack[depth];

	if ((da->type != FR_TYPE_TLV) && (dv->flags.type_size == 1) && (dv->flags.length == 1)) {
		return encode_rfc_hdr_internal(out, outlen, tlv_stack, depth, cursor, encoder_ctx);
	}

	hdr_len = dv->flags.type_size + dv->flags.length;

	/*
	 *	Vendors use different widths for their
	 *	attribute number fields.
	 */
	switch (dv->flags.type_size) {
	default:
		fr_strerror_printf("%s: Internal sanity check failed, type %u", __FUNCTION__, (unsigned) dv->flags.type_size);
		return -1;

	case 4:
		out[0] = 0;	/* attr must be 24-bit */
		out[1] = (da->attr >> 16) & 0xff;
		out[2] = (da->attr >> 8) & 0xff;
		out[3] = da->attr & 0xff;
		break;

	case 2:
		out[0] = (da->attr >> 8) & 0xff;
		out[1] = da->attr & 0xff;
		break;

	case 1:
		out[0] = da->attr & 0xff;
		break;
	}

	switch (dv->flags.length) {
	default:
		fr_strerror_printf("%s: Internal sanity check failed, length %u", __FUNCTION__, (unsigned) dv->flags.length);
		return -1;

	case 0:
		break;

	case 2:
		out[dv->flags.type_size] = 0;
		out[dv->flags.type_size + 1] = dv->flags.type_size + 2;
		break;

	case 1:
		out[dv->flags.type_size] = dv->flags.type_size + 1;
		break;

	}

	if (outlen > 255) outlen = 255;

	/*
	 *	Because we've now encoded the attribute header,
	 *	if this is a TLV, we must process it via the
	 *	internal tlv function, else we get a double TLV header.
	 */
	if (tlv_stack[depth]->type == FR_TYPE_TLV) {
		len = encode_tlv_hdr_internal(out + hdr_len, outlen - hdr_len, tlv_stack, depth, cursor, encoder_ctx);
	} else {
		len = encode_value(out + hdr_len, outlen - hdr_len, tlv_stack, depth, cursor, encoder_ctx);
	}
	if (len <= 0) return len;

	if (dv->flags.length) out[hdr_len - 1] += len;

	FR_PROTO_HEX_DUMP(out, hdr_len, "header vsa");

	return hdr_len + len;
}

/** Encode a WiMAX attribute
 *
 */
static int encode_wimax_hdr(uint8_t *out, size_t outlen,
			    fr_dict_attr_t const **tlv_stack, unsigned int depth,
			    fr_cursor_t *cursor, void *encoder_ctx)
{
	int			len;
	uint32_t		lvalue;
	uint8_t			*start = out;
	VALUE_PAIR const	*vp = fr_cursor_current(cursor);

	VP_VERIFY(vp);
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	/*
	 *	Not enough freespace for:
	 *		attr, len, vendor-id, vsa, vsalen, continuation
	 */
	if (outlen < 9) return 0;

	if (tlv_stack[depth++]->attr != FR_VENDOR_SPECIFIC) {
		fr_strerror_printf("%s: level[1] of tlv_stack is incorrect, must be Vendor-Specific (26)",
				   __FUNCTION__);
		return -1;
	}
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	if (tlv_stack[depth++]->attr != VENDORPEC_WIMAX) {
		fr_strerror_printf("%s: level[2] of tlv_stack is incorrect, must be Wimax vendor %i", __FUNCTION__,
				   VENDORPEC_WIMAX);
		return -1;
	}
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	/*
	 *	Build the Vendor-Specific header
	 */
	out = start;
	out[0] = FR_VENDOR_SPECIFIC;
	out[1] = 9;
	lvalue = htonl(fr_dict_vendor_num_by_da(vp->da));
	memcpy(out + 2, &lvalue, 4);

	/*
	 *	Encode the first attribute
	 */
	out[6] = tlv_stack[depth]->attr;
	out[7] = 3;
	out[8] = 0;		/* continuation byte */

	/*
	 *	"outlen" can be larger than 255 because of the "continuation" byte.
	 */

	if (tlv_stack[depth]->type == FR_TYPE_TLV) {
		len = encode_tlv_hdr_internal(out + out[1], outlen - out[1], tlv_stack, depth, cursor, encoder_ctx);
		if (len <= 0) return len;
	} else {
		len = encode_value(out + out[1], outlen - out[1], tlv_stack, depth, cursor, encoder_ctx);
		if (len <= 0) return len;
	}

	/*
	 *	There may be more than 252 octets of data encoded in
	 *	the attribute.  If so, move the data up in the packet,
	 *	and copy the existing header over.  Set the "C" flag
	 *	ONLY after copying the rest of the data.
	 */
	if (len > (255 - out[1])) {
		return attr_shift(start, start + outlen, out, out[1], len, 8, 7);
	}

	out[1] += len;
	out[7] += len;

	FR_PROTO_HEX_DUMP(out, 9, "header wimax");

	return (out + out[1]) - start;
}

/** Encode a Vendor-Specific attribute
 *
 */
static int encode_vsa_hdr(uint8_t *out, size_t outlen,
			  fr_dict_attr_t const **tlv_stack, unsigned int depth,
			  fr_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t			len;
	uint32_t		lvalue;
	fr_dict_attr_t const	*da = tlv_stack[depth];

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	if (da->type != FR_TYPE_VSA) {
		fr_strerror_printf("%s: Expected type \"vsa\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
		return -1;
	}

	/*
	 *	Double-check for WiMAX format
	 */
	if (fr_dict_vendor_num_by_da(tlv_stack[depth + 1]) == VENDORPEC_WIMAX) {
		return encode_wimax_hdr(out, outlen, tlv_stack, depth, cursor, encoder_ctx);
	}

	/*
	 *	Not enough freespace for: attr, len, vendor-id
	 */
	if (outlen < 6) return 0;

	/*
	 *	Build the Vendor-Specific header
	 */
	out[0] = FR_VENDOR_SPECIFIC;
	out[1] = 6;

	/*
	 *	Now process the vendor ID part (which is one attribute deeper)
	 */
	da = tlv_stack[++depth];
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	if (da->type != FR_TYPE_VENDOR) {
		fr_strerror_printf("%s: Expected type \"vsa\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"));
		return -1;
	}

	lvalue = htonl(da->attr);
	memcpy(out + 2, &lvalue, 4);	/* Copy in the 32bit vendor ID */

	if (outlen > 255) outlen = 255;

	len = encode_vendor_attr_hdr(out + out[1], outlen - out[1], tlv_stack, depth, cursor, encoder_ctx);
	if (len < 0) return len;

	out[1] += len;

	FR_PROTO_HEX_DUMP(out, 6, "header vsa");

	return out[1];
}

/** Encode an RFC standard attribute 1..255
 *
 */
static int encode_rfc_hdr(uint8_t *out, size_t outlen, fr_dict_attr_t const **tlv_stack, unsigned int depth,
			  fr_cursor_t *cursor, void *encoder_ctx)
{
	VALUE_PAIR const *vp = fr_cursor_current(cursor);

	/*
	 *	Sanity checks
	 */
	VP_VERIFY(vp);
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	switch (tlv_stack[depth]->type) {
	case FR_TYPE_EXTENDED:
	case FR_TYPE_TLV:
	case FR_TYPE_VSA:
	case FR_TYPE_VENDOR:
		/* FR_TYPE_STRUCT is actually allowed... */
		fr_strerror_printf("%s: Expected leaf type got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, tlv_stack[depth]->type, "?Unknown?"));
		return -1;

	default:
		/*
		 *	Attribute 0 is fine as a TLV leaf, or VSA, but not
		 *	in the original standards space.
		 */
		if (((fr_dict_vendor_num_by_da(tlv_stack[depth]) == 0) && (tlv_stack[depth]->attr == 0)) ||
		    (tlv_stack[depth]->attr > 255)) {
			fr_strerror_printf("%s: Called with non-standard attribute %u", __FUNCTION__, vp->da->attr);
			return -1;
		}
		break;
	}

	/*
	 *	Only CUI is allowed to have zero length.
	 *	Thank you, WiMAX!
	 */
	if ((vp->da == attr_chargeable_user_identity) && (vp->vp_length == 0)) {
		out[0] = (uint8_t)vp->da->attr;
		out[1] = 2;

		FR_PROTO_HEX_DUMP(out, 2, "header rfc");

		vp = next_encodable(cursor);
		fr_proto_tlv_stack_build(tlv_stack, vp ? vp->da : NULL);
		return out[1];
	}

	/*
	 *	Message-Authenticator is hard-coded.
	 */
	if (vp->da == attr_message_authenticator) {
		if (outlen < 18) return -1;

		out[0] = (uint8_t)vp->da->attr;
		out[1] = 18;
		memset(out + 2, 0, 16);

		FR_PROTO_HEX_DUMP(out + 2, RADIUS_MESSAGE_AUTHENTICATOR_LENGTH, "message-authenticator");
		FR_PROTO_HEX_DUMP(out, 2, "header rfc");

		vp = next_encodable(cursor);
		fr_proto_tlv_stack_build(tlv_stack, vp ? vp->da : NULL);
		return out[1];
	}

	return encode_rfc_hdr_internal(out, outlen, tlv_stack, depth, cursor, encoder_ctx);
}

/** Encode a data structure into a RADIUS attribute
 *
 * This is the main entry point into the encoder.  It sets up the encoder array
 * we use for tracking our TLV/VSA nesting and then calls the appropriate
 * dispatch function.
 *
 * @param[out] out		Where to write encoded data.
 * @param[in] outlen		Length of the out buffer.
 * @param[in] cursor		Specifying attribute to encode.
 * @param[in] encoder_ctx	Additional data such as the shared secret to use.
 * @return
 *	- >0 The number of bytes written to out.
 *	- 0 Nothing to encode (or attribute skipped).
 *	- <0 an error occurred.
 */
ssize_t fr_radius_encode_pair(uint8_t *out, size_t outlen, fr_cursor_t *cursor, void *encoder_ctx)
{
	VALUE_PAIR const *vp;
	int ret;
	size_t attr_len;

	fr_dict_attr_t const *tlv_stack[FR_DICT_MAX_TLV_STACK + 1];
	fr_dict_attr_t const *da = NULL;

	if (!cursor || !out || (outlen <= 2)) return -1;

	vp = first_encodable(cursor);
	if (!vp) return 0;

	VP_VERIFY(vp);

	if (vp->da->depth > FR_DICT_MAX_TLV_STACK) {
		fr_strerror_printf("%s: Attribute depth %i exceeds maximum nesting depth %i",
				   __FUNCTION__, vp->da->depth, FR_DICT_MAX_TLV_STACK);
		return -1;
	}

	/*
	 *	We allow zero-length strings in "unlang", but skip
	 *	them (except for CUI, thanks WiMAX!) on all other
	 *	attributes.
	 */
	if (fr_radius_attr_len(vp) == 0) {
		if (!fr_dict_attr_is_top_level(vp->da) ||
		    ((vp->da->attr != FR_CHARGEABLE_USER_IDENTITY) &&
		     (vp->da->attr != FR_MESSAGE_AUTHENTICATOR))) {
			next_encodable(cursor);
			return 0;
		}
	}

	/*
	 *	Nested structures of attributes can't be longer than
	 *	255 bytes, so each call to an encode function can
	 *	only use 255 bytes of buffer space at a time.
	 */
	attr_len = (outlen > UINT8_MAX) ? UINT8_MAX : outlen;

	/*
	 *	Fast path for the common case.
	 */
	if (vp->da->parent->flags.is_root && !vp->da->flags.concat && (vp->vp_type != FR_TYPE_TLV)) {
		tlv_stack[0] = vp->da;
		tlv_stack[1] = NULL;
		FR_PROTO_STACK_PRINT(tlv_stack, 0);
		return encode_rfc_hdr(out, attr_len, tlv_stack, 0, cursor, encoder_ctx);
	}

	/*
	 *	Do more work to set up the stack for the complex case.
	 */
	fr_proto_tlv_stack_build(tlv_stack, vp->da);
	FR_PROTO_STACK_PRINT(tlv_stack, 0);

	da = tlv_stack[0];
	switch (da->type) {
	default:
		if (da->flags.concat) {
			/*
			 *	Attributes like EAP-Message are marked as
			 *	"concat", which means that they are fragmented
			 *	using a different scheme than the "long
			 *	extended" one.
			 */
			ret = encode_concat(out, outlen, tlv_stack, 0, cursor, encoder_ctx);
			break;
		}
		ret = encode_rfc_hdr(out, attr_len, tlv_stack, 0, cursor, encoder_ctx);
		break;

	case FR_TYPE_VSA:
		if (fr_dict_vendor_num_by_da(da) == VENDORPEC_WIMAX) {
			/*
			 *	WiMAX has a non-standard format for
			 *	its VSAs.  And, it can do "long"
			 *	attributes by fragmenting them inside
			 *	of the WiMAX VSA space.
			 */
			ret = encode_wimax_hdr(out, outlen, tlv_stack, 0, cursor, encoder_ctx);
			break;
		}
		ret = encode_vsa_hdr(out, attr_len, tlv_stack, 0, cursor, encoder_ctx);
		break;

	case FR_TYPE_TLV:
		ret = encode_tlv_hdr(out, attr_len, tlv_stack, 0, cursor, encoder_ctx);
		break;

	case FR_TYPE_EXTENDED:
		ret = encode_extended_hdr(out, attr_len, tlv_stack, 0, cursor, encoder_ctx);
		break;

	case FR_TYPE_INVALID:
	case FR_TYPE_VENDOR:
	case FR_TYPE_TIME_DELTA:
	case FR_TYPE_FLOAT64:
	case FR_TYPE_MAX:
		fr_strerror_printf("%s: Cannot encode attribute %s", __FUNCTION__, vp->da->name);
		return -1;
	}

	if (ret < 0) return ret;

	/*
	 *	We couldn't do it, so we didn't do anything.
	 */
	if (fr_cursor_current(cursor) == vp) {
		fr_strerror_printf("%s: Nested attribute structure too large to encode", __FUNCTION__);
		return -1;
	}

	return ret;
}

static int _test_ctx_free(UNUSED fr_radius_ctx_t *ctx)
{
	fr_radius_free();

	return 0;
}

static int encode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	static uint8_t vector[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	fr_radius_ctx_t	*test_ctx;

	if (fr_radius_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_radius_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->secret = talloc_strdup(test_ctx, "testing123");
	test_ctx->vector = vector;
	talloc_set_destructor(test_ctx, _test_ctx_free);

	*out = test_ctx;

	return 0;
}

/*
 *	Test points
 */
extern fr_test_point_pair_encode_t radius_tp_encode;
fr_test_point_pair_encode_t radius_tp_encode = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_radius_encode_pair
};
