/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * @file rlm_eap/lib/sim/encode.c
 * @brief Code common to EAP-SIM/AKA/AKA' clients and servers.
 *
 * @copyright 2017 FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/sha1.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/tls.h>
#include <freeradius-devel/io/test_point.h>

#include "eap_types.h"
#include "eap_sim_common.h"
#include "sim_proto.h"

#define SIM_MAX_ATTRIBUTE_VALUE_LEN	((255 * 4) - 2)		/* max length field value less Type + Length fields */

/*
 *  EAP-SIM/AKA/AKA' PACKET FORMAT
 *  ---------------- ------ ------
 *
 * EAP Request and Response Packet Format
 * --- ------- --- -------- ------ ------
 *  0		   1		   2		   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |	    Length	     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |    AT-Type    |   AT-Length   |     value ... |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * With AT-Type/AT-Length/Value... repeating. Length is in units
 * of 32 bits, and includes the Type/Length fields.
 */

static ssize_t encode_tlv_hdr(uint8_t *out, size_t outlen,
			      fr_dict_attr_t const **tlv_stack, unsigned int depth,
			      vp_cursor_t *cursor, void *encoder_ctx);

/** Find the next attribute to encode
 *
 * @param cursor to iterate over.
 * @param encoder_ctx the context for the encoder
 * @return encodable VALUE_PAIR, or NULL if none available.
 */
static inline VALUE_PAIR *next_encodable(vp_cursor_t *cursor, void *encoder_ctx)
{
	VALUE_PAIR		*vp;
	fr_sim_encode_ctx_t	*packet_ctx = encoder_ctx;

	for (;;) {
		vp = fr_pair_cursor_next_by_ancestor(cursor, packet_ctx->root, TAG_ANY);
		if (!vp || !vp->da->flags.internal) break;
	}

	return fr_pair_cursor_current(cursor);
}

/** Determine if the current attribute is encodable, or find the first one that is
 *
 * @param cursor to iterate over.
 * @param encoder_ctx the context for the encoder
 * @return encodable VALUE_PAIR, or NULL if none available.
 */
static inline VALUE_PAIR *first_encodable(vp_cursor_t *cursor, void *encoder_ctx)
{
	VALUE_PAIR		*vp;
	fr_sim_encode_ctx_t	*packet_ctx = encoder_ctx;

	vp = fr_pair_cursor_current(cursor);
	if (vp && !vp->da->flags.internal && fr_dict_parent_common(packet_ctx->root, vp->da, true)) {
		cursor->found = vp;
		return vp;
	}

	return next_encodable(cursor, encoder_ctx);
}

/** Add an IV to a packet
 *
 @verbatim
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|     AT_IV     | Length = 5    |           Reserved            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                                                               |
	|                 Initialization Vector                         |
	|                                                               |
	|                                                               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 @endverbatim
 */
static ssize_t encode_iv(uint8_t *out, size_t outlen, void *encoder_ctx)
{
	fr_sim_encode_ctx_t	*packet_ctx = encoder_ctx;
	uint8_t			*p = out;
	uint32_t		iv[4];

	/*
	 *	One IV per packet
	 */
	if (packet_ctx->iv_included) return 0;

	if (outlen < (4 + SIM_IV_SIZE)) {	/* AT_IV + Length + Reserved(2) + IV */
		fr_strerror_printf("%s: Insufficient buffer space, need %u bytes, have %zu bytes",
				   __FUNCTION__, 4 + SIM_IV_SIZE, outlen);
		return -1;
	}

	/*
	 *	Generate IV
	 */
	iv[0] = fr_rand();
	iv[1] = fr_rand();
	iv[2] = fr_rand();
	iv[3] = fr_rand();

	memcpy(packet_ctx->iv, (uint8_t *)&iv[0], sizeof(packet_ctx->iv));	/* ensures alignment */

	*p++ = FR_SIM_IV;
	*p++ = (4 + SIM_IV_SIZE) >> 2;
	memcpy(p, packet_ctx->iv, sizeof(packet_ctx->iv));
	p += sizeof(packet_ctx->iv);

	packet_ctx->iv_included = true;

	return p - out;
}

/** encrypt a value with AES-CBC-128
 *
 * encrypts a value using AES-CBC-128, padding the value with AT_PADDING
 * attributes until it matches the block length of the cipher (16).
 *
 * May also write out an AT_IV attribute if this is the first encrypted
 * value being encoded.
 @verbatim
	1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	| AT_ENCR_DATA  | Length        |           Reserved            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                                                               |
	.                    Encrypted Data                             .
	.                                                               .
	|                                                               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 @endverbatim
 */
static ssize_t encode_encrypted_value(uint8_t *out, size_t outlen,
			     	      uint8_t const *in, size_t inlen, void *encoder_ctx)
{
	size_t			rounded_len, pad_len, encr_len, len = 0;
	uint8_t			*p = out, *encr = NULL;
	fr_sim_encode_ctx_t	*packet_ctx = encoder_ctx;
	EVP_CIPHER_CTX		*evp_ctx;
	EVP_CIPHER const	*evp_cipher = EVP_aes_128_cbc();
	size_t			block_size = EVP_CIPHER_block_size(evp_cipher);
	/*
	 *	Needs to be a multiple of 4 else we can't
	 *	pad with AT_PADDING correctly as its
	 *	length is specified in multiples of 4.
	 */
	if (unlikely(inlen % 4)) {
		fr_strerror_printf("%s: Input data length is not a multiple of 4", __FUNCTION__);
		return -1;
	}

	rounded_len = (inlen + (block_size - 1)) & ~(block_size - 1);	/* Round input length to block size (16) */
	pad_len = (rounded_len - inlen);		/* How much we need to pad */

	if (rounded_len > outlen) {
		fr_strerror_printf("%s: Insufficient buffer space, need %zu bytes, have %zu bytes",
				   __FUNCTION__, rounded_len, outlen);
		return -1;
	}

	/*
	 *	Usually in and out will be the same buffer
	 */
	if (unlikely(out != in)) memcpy(out, in, inlen);
	p += inlen;

	/*
	 *	Append an AT_PADDING attribute if required
	 */
	if (pad_len != 0) {
		p[0] = FR_SIM_PADDING;
		p[1] = pad_len >> 2;
		memset(p + 2, 0, pad_len - 2);	/* Ensure the rest is zeroed out */
		FR_PROTO_HEX_DUMP("Done padding attribute", p, pad_len);
	}

	evp_ctx = EVP_CIPHER_CTX_new();
	if (!evp_ctx) {
		tls_strerror_printf(true, "Failed allocating EVP context");
		return -1;
	}

	if (unlikely(EVP_EncryptInit_ex(evp_ctx, evp_cipher, NULL,
					packet_ctx->keys->k_encr, packet_ctx->iv) != 1)) {
		tls_strerror_printf(true, "Failed initialising AES-128-ECB context");
	error:
		talloc_free(encr);
		EVP_CIPHER_CTX_free(evp_ctx);
		return -1;
	}

	encr = talloc_array(NULL, uint8_t, rounded_len);
	if (!encr) {
		fr_strerror_printf("%s: Failed allocating temporary buffer", __FUNCTION__);
		goto error;
	}

	p = out;	/* Because we're using out to store our plaintext (and out usually == in) */

	FR_PROTO_HEX_DUMP("plaintext", p, rounded_len);

	/*
	 *	By default OpenSSL expects 16 bytes of plaintext
	 *	to produce 32 bytes of ciphertext, due to padding
	 *	being added if the plaintext is a multiple of 16.
	 *
	 *	There's no way for OpenSSL to determine if a
	 *	16 byte encr was padded or not, so we need to
	 *	inform OpenSSL explicitly that there's no padding.
	 */
	EVP_CIPHER_CTX_set_padding(evp_ctx, 0);
	if (unlikely(EVP_EncryptUpdate(evp_ctx, encr, (int *)&len, p, rounded_len) != 1)) {
		tls_strerror_printf(true, "%s: Failed encrypting attribute", __FUNCTION__);
		goto error;
	}
	encr_len = len;

	if (unlikely(EVP_EncryptFinal_ex(evp_ctx, encr + encr_len, (int *)&len) != 1)) {
		tls_strerror_printf(true, "%s: Failed finalising encrypted attribute", __FUNCTION__);
		goto error;
	}
	encr_len += len;

	/*
	 *	Plaintext should be same length as plaintext.
	 */
	if (unlikely(encr_len != rounded_len)) {
		fr_strerror_printf("%s: Invalid plaintext length, expected %zu, got %zu",
				   __FUNCTION__, rounded_len, encr_len);
		goto error;
	}

	FR_PROTO_HEX_DUMP("ciphertext", encr, encr_len);

	p = out;

	/*
	 *	Overwrite the plaintext with our encrypted blob
	 */
	memcpy(p, encr, encr_len);

	talloc_free(encr);
	EVP_CIPHER_CTX_free(evp_ctx);

	return encr_len;
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
			    vp_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t			len;
	VALUE_PAIR const	*vp = fr_pair_cursor_current(cursor);
	fr_dict_attr_t const	*da = tlv_stack[depth];
	fr_sim_encode_ctx_t	*packet_ctx = encoder_ctx;

	VP_VERIFY(vp);
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

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
				   fr_int2str(dict_attr_types, tlv_stack[depth]->type, "?Unknown?"));
		return -1;

	default:
		break;
	}

	switch (da->attr) {
	/*
	 *	Allow manual override of IV - Mostly for testing or debugging
	 *
	 *	0                   1                   2                   3
	 *	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *	|     AT_IV     | Length = 5    |           Reserved            |
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *	|                                                               |
	 *	|                 Initialization Vector                         |
	 *	|                                                               |
	 *	|                                                               |
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	case FR_SIM_IV:
		if ((vp->da->flags.length && (da->flags.length != vp->vp_length)) ||
		    (vp->vp_length != sizeof(packet_ctx->iv))) {
			fr_strerror_printf("%s: Attribute \"%s\" needs a value of exactly %zu bytes, "
					   "but value was %zu bytes", __FUNCTION__,
					   da->name, (size_t)da->flags.length, vp->vp_length);
			return -1;
		}
		memcpy(packet_ctx->iv, vp->vp_octets, sizeof(packet_ctx->iv));
		packet_ctx->iv_included = true;
		break;	/* Encode IV */

	/*
	 *	AT_RES - Special case (RES length is in bits)
	 *
	 *	0                   1                   2                   3
	 *	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *	|     AT_RES    |    Length     |          RES Length           |
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
	 *	|                                                               |
	 *	|                             RES                               |
	 *	|                                                               |
	 *	|                                                               |
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	case FR_EAP_AKA_RES:
	{
		uint16_t	res_len = htons(vp->vp_length * 8);	/* Get length in bits */
		size_t	 	rounded_len = (vp->vp_length + 3) & ~3;
		size_t	 	pad_len = rounded_len - vp->vp_length;
		uint8_t		*p = out;

		if ((vp->vp_length < 4) || (vp->vp_length > 16)) {
			fr_strerror_printf("%s: AKA-RES Length must be between 4-16 bytes, got %zu bytes",
					   __FUNCTION__, vp->vp_length);
			return -1;
		}

		if ((rounded_len + 2) > outlen) {
		oos:
			fr_strerror_printf("%s: Attribute exceeds available buffer space", __FUNCTION__);
			return -1;
		}

		memcpy(p, &res_len, sizeof(res_len));			/* RES Length (bits, big endian) */
		p += sizeof(res_len);

		memcpy(p, vp->vp_octets, vp->vp_length);
		p += vp->vp_length;

		if (pad_len) {
			memset(p, 0, pad_len);
			p += pad_len;
		}

		len = p - out;
	}
		goto done;

	/*
	 *	AT_AUTS - Octets type with no reserved field
	 *
	 *	0                   1                   2                   3
	 *	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
	 *	|    AT_AUTS    | Length = 4    |                               |
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
	 *	|                                                               |
	 *	|                             AUTS                              |
	 *	|                                                               |
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	case FR_EAP_AKA_AUTS:
		if (vp->da->flags.length && (da->flags.length != vp->vp_length)) {
			fr_strerror_printf("%s: Attribute \"%s\" needs a value of exactly %zu bytes, "
					   "but value was %zu bytes", __FUNCTION__,
					   da->name, (size_t)da->flags.length, vp->vp_length);
			return -1;
		}
		if (vp->vp_length > outlen) goto oos;

		memcpy(out, vp->vp_octets, vp->vp_length);
		len = vp->vp_length;
		goto done;

	default:
		break;
	}

	switch (da->type) {
	case FR_TYPE_OCTETS:
	{
		size_t	 	rounded_len;
		size_t	 	pad_len;
		uint8_t		*p = out;

		/*
		 *	Autopad attributes
		 */
		if (vp->da->flags.length && (vp->vp_length != vp->da->flags.length)) {
			rounded_len = (vp->vp_length + (vp->da->flags.length - 1)) & ~(vp->da->flags.length - 1);
			pad_len = rounded_len - vp->vp_length;
		} else {
			rounded_len = (vp->vp_length + 3) & ~3;
			pad_len = rounded_len - vp->vp_length;
		}

		/*
		 *	Non-array attributes have a 2 byte padding
		 */
		if (!vp->da->flags.array) {
			if ((rounded_len + 2) > outlen) goto oos;

			*p++ = 0;	/* Reserved */
			*p++ = 0;	/* Reserved */
		/*
		 *	Fixed length array attributes have no padding
		 */
		} else if (rounded_len > outlen) goto oos;

		memcpy(p, vp->vp_octets, vp->vp_length);
		p += vp->vp_length;

		if (pad_len) {
			memset(p, 0, pad_len);
			p += pad_len;
		}

		len = p - out;
	}
		break;

	/*
	 *	In order to represent the string length properly we include a second
	 *	16bit length field with the real string length.
	 *
	 *	The end of the string is padded buff to a multiple of 4.
	 *
	 *	0                   1                   2                   3
	 *	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *	| AT_<STRING>   | Length        |    Actual <STRING> Length     |
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *	|                                                               |
	 *	.                           String                              .
	 *	.                                                               .
	 *	|                                                               |
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	case FR_TYPE_STRING:
	{
		uint16_t 	actual_len = htons((vp->vp_length & UINT16_MAX));
		size_t	 	rounded_len = (vp->vp_length + 3) & ~3;
		size_t	 	pad_len = rounded_len - vp->vp_length;
		uint8_t		*p = out;

		if ((rounded_len + 2) > outlen) goto oos;

		if (vp->da->flags.length && (vp->vp_length != vp->da->flags.length)) {
			fr_strerror_printf("%s: Attribute \"%s\" needs a value of exactly %zu bytes, "
					   "but value was %zu bytes", __FUNCTION__,
					   vp->da->name, (size_t)vp->da->flags.length, vp->vp_length);
			return -1;
		}

		memcpy(p, &actual_len, sizeof(actual_len));		/* Big endian real string length */
		p += sizeof(actual_len);

		memcpy(p, vp->vp_strvalue, vp->vp_length);
		p += vp->vp_length;

		if (pad_len) {
			memset(p, 0, pad_len);
			p += pad_len;
		}

		len = p - out;
	}
		break;

	/*
	 *	In SIM/AKA/AKA' we represent truth values
	 *	by either including or not including the attribute
	 *	in the packet.
	 *
	 *	0                   1                   2                   3
	 *	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *	|   AT_<BOOL>   | Length = 1    |           Reserved            |
	 *	+---------------+---------------+-------------------------------+
	 */
	case FR_TYPE_BOOL:
		if (2 > outlen) goto oos;
		out[0] = 0;
		out[1] = 0;
		len = 2;
		break;

	/*
	 *	Numbers are network byte order.
	 *
	 *	In the base RFCs only short (16bit) unsigned integers are used.
	 *	We add support for more, just for completeness.
	 *
	 *	0                   1                   2                   3
	 *	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *	|   AT_<SHORT>  | Length = 1    |    Short 1    |    Short 2    |
	 *	+---------------+---------------+-------------------------------+
	 */
	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
	case FR_TYPE_INT32:
		len = fr_value_box_to_network(NULL, out, outlen, &vp->data);
		if (len < 0) return -1;
		break;

	default:
		fr_strerror_printf("%s: Cannot encode attribute %s", __FUNCTION__, vp->da->name);
		return -1;
	}

done:
	/*
	 *	Rebuilds the TLV stack for encoding the next attribute
	 */
	vp = next_encodable(cursor, encoder_ctx);
	fr_proto_tlv_stack_build(tlv_stack, vp ? vp->da : NULL);

	return len;
}

/** Encodes the data portion of an attribute
 *
 @verbatim
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	| AT_VERSION_L..| Length        | Actual Version List Length    |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|  Supported Version 1          |  Supported Version 2          |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	.                                                               .
	.                                                               .
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	| Supported Version N           |     Padding                   |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 @endverbatim
 *
 */
static ssize_t encode_array(uint8_t *out, size_t outlen,
			    fr_dict_attr_t const **tlv_stack, int depth,
			    vp_cursor_t *cursor, void *encoder_ctx)
{
	uint8_t			*p = out, *end = p + outlen;
	uint8_t			*value;
	size_t			pad_len;
	size_t			element_len;
	uint16_t		actual_len;
	fr_dict_attr_t const	*da = tlv_stack[depth];
	rad_assert(da->flags.array);

	p += 2;
	value = p;	/* Space for actual length */

	if (da->type == FR_TYPE_OCTETS) {
		if (!da->flags.length) {
			fr_strerror_printf("Can't encode array type attribute \"%s\" as it does not "
					   "have a fixed length", da->name);
			return -1;
		}
		element_len = da->flags.length;
	} else {
		element_len = fr_sim_attr_sizes[da->type][0];
	}

	/*
	 *	Keep encoding as long as we have space to
	 *	encode things.
	 */
	while (element_len <= ((size_t)(end - p))) {
		VALUE_PAIR	*vp;
		ssize_t		slen;

		slen = encode_value(p, end - p, tlv_stack, depth, cursor, encoder_ctx);
		if (slen < 0) return slen;

		p += slen;

		vp = fr_pair_cursor_current(cursor);
		if (!vp || (vp->da != da)) break;		/* Stop if we have an attribute of a different type */
	}

	/*
	 *	Arrays with an element size which is
	 *	a multiple of 4 don't need an
	 *	actual_length field, because the number
	 *	of elements can be calculated from
	 *	the attribute length.
	 */
	if (element_len % 4) {
		actual_len = htons((p - value) & UINT16_MAX);	/* Length of the elements we encoded */
		memcpy(out, &actual_len, sizeof(actual_len));
	} else {
		out[0] = 0;
		out[1] = 0;
	}

	/*
	 *	Pad value a multiple of 4
	 */
	pad_len = (((p - value) + 3) & ~3) - (p - value);
	if (pad_len) {
		memset(p, 0, pad_len);
		p += pad_len;
	}

	return p - out;
}

/** Encode an RFC format attribute header
 *
 * This could be a standard attribute, or a TLV data type.
 * If it's a standard attribute, then vp->da->attr == attribute.
 * Otherwise, attribute may be something else.
 */
static ssize_t encode_rfc_hdr(uint8_t *out, size_t outlen, fr_dict_attr_t const **tlv_stack, unsigned int depth,
			      vp_cursor_t *cursor, void *encoder_ctx)
{
	size_t			rounded_len;
	fr_dict_attr_t const	*da;
	ssize_t			slen;

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	switch (tlv_stack[depth]->type) {
	case FR_TYPE_STRUCTURAL:
		fr_strerror_printf("%s: Called with structural type %s", __FUNCTION__,
				   fr_int2str(dict_attr_types, tlv_stack[depth]->type, "?Unknown?"));
		return -1;

	default:
		if (((tlv_stack[depth]->vendor == 0) && (tlv_stack[depth]->attr == 0)) ||
		    (tlv_stack[depth]->attr > 255)) {
			fr_strerror_printf("%s: Called with non-standard attribute %u", __FUNCTION__,
					   tlv_stack[depth]->attr);
			return -1;
		}
		break;
	}

	if (outlen <= 4) return 0;	/* Attribute lengths are always multiples of 4 */
	if (outlen > SIM_MAX_ATTRIBUTE_VALUE_LEN) outlen = SIM_MAX_ATTRIBUTE_VALUE_LEN;

	/*
	 *	Write out the value to a buffer location
	 *	past the AT and Length fields.
	 *
	 *	Encode value will set reserved bytes to
	 *	zero and fill any subfields like actual
	 *	length.
	 */
	da = tlv_stack[depth];

	if (da->flags.array) {
		slen = encode_array(out + 2, outlen - 2, tlv_stack, depth, cursor, encoder_ctx);
	} else {
		slen = encode_value(out + 2, outlen - 2, tlv_stack, depth, cursor, encoder_ctx);
	}
	if (slen <= 0) return slen;
	/*
	 *	Round attr + len + data length out to a multiple
	 *	of four, and setup the attribute header and
	 *	length field in the buffer.
	 */
	rounded_len = (slen + 2 + 3) & ~3;
	out[0] = da->attr & 0xff;
	out[1] = rounded_len >> 2;

	FR_PROTO_HEX_DUMP("Done RFC attribute", out, rounded_len);

	return rounded_len;	/* AT + Length + Data */
}

static inline ssize_t encode_tlv(uint8_t *out, size_t outlen,
				 fr_dict_attr_t const **tlv_stack, unsigned int depth,
				 vp_cursor_t *cursor, void *encoder_ctx)
{
	ssize_t			slen;
	uint8_t			*p = out, *end = p + outlen, *value;
	VALUE_PAIR const	*vp = fr_pair_cursor_current(cursor);
	fr_dict_attr_t const	*da = tlv_stack[depth];

	if (outlen < 2) {
		fr_strerror_printf("Insufficient space for TLV");
		return -1;
	}

	*p++ = 0;	/* Reserved (0) */
	*p++ = 0;	/* Reserved (1) */
	value = p;

	while ((end - p) > 4) {
		size_t sublen;
		FR_PROTO_STACK_PRINT(tlv_stack, depth);

		/*
		 *	This attribute carries sub-TLVs.  The sub-TLVs
		 *	can only carry SIM_MAX_ATTRIBUTE_VALUE_LEN bytes of data.
		 */
		sublen = end - p;
		if (sublen > SIM_MAX_ATTRIBUTE_VALUE_LEN) sublen = SIM_MAX_ATTRIBUTE_VALUE_LEN;

		/*
		 *	Determine the nested type and call the appropriate encoder
		 */
		if (tlv_stack[depth + 1]->type == FR_TYPE_TLV) {
			slen = encode_tlv_hdr(p, sublen, tlv_stack, depth + 1, cursor, encoder_ctx);
		} else {
			slen = encode_rfc_hdr(p, sublen, tlv_stack, depth + 1, cursor, encoder_ctx);
		}

		if (slen <= 0) return slen;
		p += slen;

		/*
		 *	If nothing updated the attribute, stop
		 */
		if (!fr_pair_cursor_current(cursor) || (vp == fr_pair_cursor_current(cursor))) break;

		/*
		 *	We can encode multiple sub TLVs, if after
		 *	rebuilding the TLV Stack, the attribute
		 *	at this depth is the same.
		 */
		if (da != tlv_stack[depth]) break;
		vp = fr_pair_cursor_current(cursor);
	}

	/*
	 *	encrypt the contents of the TLV using AES-CBC-128
	 *	or another encryption algorithm.
	 */
	if (da->flags.encrypt) {
		slen = encode_encrypted_value(value, end - value, value, p - value, encoder_ctx);
		if (slen < 0) return -1;

		p = value + slen;
	}

	FR_PROTO_HEX_DUMP("Done TLV", out, p - out);

	return p - out;
}

static ssize_t encode_tlv_hdr(uint8_t *out, size_t outlen,
			      fr_dict_attr_t const **tlv_stack, unsigned int depth,
			      vp_cursor_t *cursor, void *encoder_ctx)
{
	unsigned int		rounded_len;
	ssize_t			len;
	uint8_t			*p = out;
	fr_dict_attr_t const	*da;

	VP_VERIFY(fr_pair_cursor_current(cursor));
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	if (tlv_stack[depth]->type != FR_TYPE_TLV) {
		fr_strerror_printf("%s: Expected type \"tlv\" got \"%s\"", __FUNCTION__,
				   fr_int2str(dict_attr_types, tlv_stack[depth]->type, "?Unknown?"));
		return -1;
	}

	if (!tlv_stack[depth + 1]) {
		fr_strerror_printf("%s: Can't encode empty TLV", __FUNCTION__);
		return -1;
	}

	/*
	 *	Add the IV before the TLV
	 *	The ASCII art in the RFCs the attributes in
	 *	this order.
	 */
	if (tlv_stack[depth]->flags.encrypt) {
		len = encode_iv(out, outlen, encoder_ctx);
		if (len < 0) return -1;

		p += len;
		outlen -= len;
	}

	if (outlen < 4) return 0;
	if (outlen > SIM_MAX_ATTRIBUTE_VALUE_LEN) outlen = SIM_MAX_ATTRIBUTE_VALUE_LEN;

	da = tlv_stack[depth];
	len = encode_tlv(p + 2, outlen - 2, tlv_stack, depth, cursor, encoder_ctx);
	if (len <= 0) return len;

	/*
	 *	Round attr + len + data length out to a multiple
	 *	of four, and setup the attribute header and
	 *	length field in the buffer.
	 */
	rounded_len = (len + 2 + 3) & ~3;
	p[0] = da->attr & 0xff;			/* Type */
	p[1] = rounded_len >> 2;		/* Length */

	FR_PROTO_HEX_DUMP("Done TLV attribute", out, rounded_len);

	return rounded_len;	/* AT_IV + AT_*(TLV) */
}

ssize_t fr_sim_encode_pair(uint8_t *out, size_t outlen, vp_cursor_t *cursor, void *encoder_ctx)
{
	VALUE_PAIR const	*vp;
	int			ret;
	size_t			attr_len;

	fr_dict_attr_t const	*tlv_stack[FR_DICT_MAX_TLV_STACK + 1];
	fr_dict_attr_t const	*da = NULL;
	fr_sim_encode_ctx_t	*packet_ctx = encoder_ctx;

	if (!cursor || !out || (outlen < 4)) return -1;	/* Attributes lengths are always multiples of 4 */

	vp = first_encodable(cursor, encoder_ctx);
	if (!vp) return 0;

	VP_VERIFY(vp);

	if (vp->da->depth > FR_DICT_MAX_TLV_STACK) {
		fr_strerror_printf("%s: Attribute depth %i exceeds maximum nesting depth %i",
				   __FUNCTION__, vp->da->depth, FR_DICT_MAX_TLV_STACK);
		return -1;
	}

	if (vp->da->attr == FR_EAP_SIM_MAC) return 0;

	/*
	 *	Nested structures of attributes can't be longer than
	 *	4 * 255 bytes, so each call to an encode function can
	 *	only use 4 * 255 bytes of buffer space at a time.
	 */
	attr_len = (outlen > (SIM_MAX_ATTRIBUTE_VALUE_LEN + 2)) ? (SIM_MAX_ATTRIBUTE_VALUE_LEN + 2) : outlen;

	/*
	 *	Fast path for the common case.
	 */
	if ((vp->da->parent == packet_ctx->root) && !vp->da->flags.concat && (vp->vp_type != FR_TYPE_TLV)) {
		tlv_stack[0] = packet_ctx->root;
		tlv_stack[1] = vp->da;
		tlv_stack[2] = NULL;
		FR_PROTO_STACK_PRINT(tlv_stack, 0);
		return encode_rfc_hdr(out, attr_len, tlv_stack, 1, cursor, encoder_ctx);
	}

	/*
	 *	Do more work to set up the stack for the complex case.
	 */
	fr_proto_tlv_stack_build(tlv_stack, vp->da);
	FR_PROTO_STACK_PRINT(tlv_stack, 0);

	da = tlv_stack[1];	/* FIXME - Should be index 0, and will be when we have proto dicts */

	switch (da->type) {
	/*
	 *	Supported types
	 */
	default:
		ret = encode_rfc_hdr(out, attr_len, tlv_stack, 1, cursor, encoder_ctx);
		break;

	case FR_TYPE_TLV:
		ret = encode_tlv_hdr(out, attr_len, tlv_stack, 1, cursor, encoder_ctx);
		break;
	}

	if (ret < 0) return ret;

	/*
	 *	We couldn't do it, so we didn't do anything.
	 */
	if (fr_pair_cursor_current(cursor) == vp) {
		fr_strerror_printf("%s: Nested attribute structure too large to encode", __FUNCTION__);
		return -1;
	}

	return ret;
}

ssize_t fr_sim_encode(REQUEST *request, fr_dict_attr_t const *parent, uint8_t type,
		      VALUE_PAIR *to_encode, eap_packet_t *eap_packet, fr_sim_keys_t const *keys)
{
	VALUE_PAIR		*vp;

	unsigned int		id, eap_code;

	uint8_t			*buff, *p, *end;
	size_t			len = 0;
	ssize_t			slen;

	bool			do_hmac = false;

	unsigned char		subtype;
	vp_cursor_t		cursor;
	fr_sim_encode_ctx_t	packet_ctx = {
					.root = parent,
					.keys = keys,
					.iv_included = false
				};

	/*
	 *	Encoded_msg is now an EAP-SIM message.
	 *	It might be too big for putting into an
	 *	EAP packet.
	 */
	vp = fr_pair_find_by_child_num(to_encode, parent, FR_SIM_SUBTYPE, TAG_ANY);
	if (!vp) {
		REDEBUG("Missing subtype attribute");
		return -1;
	}
	subtype = vp->vp_uint16;

	vp = fr_pair_find_by_num(to_encode, 0, FR_EAP_ID, TAG_ANY);
	id = vp ? vp->vp_uint32 : ((int)getpid() & 0xff);

	vp = fr_pair_find_by_num(to_encode, 0, FR_EAP_CODE, TAG_ANY);
	eap_code = vp ? vp->vp_uint32 : FR_EAP_CODE_REQUEST;

	vp = fr_pair_find_by_num(to_encode, 0, FR_EAP_SIM_MAC, TAG_ANY);
	if (vp) do_hmac = true;

	/*
	 *	Fill in some bits in the EAP packet
	 *
	 *	These are needed even if we're sending an almost empty packet.
	 */
	if (eap_packet->code != FR_EAP_CODE_SUCCESS) eap_packet->code = eap_code;
	eap_packet->id = (id & 0xff);
	eap_packet->type.num = type;

	/*
	 *	Group attributes with similar lineages together
	 */
	fr_pair_list_sort(&to_encode, fr_pair_cmp_by_parent_num_tag);
	(void)fr_pair_cursor_init(&cursor, &to_encode);

	/*
	 *	Fast path...
	 */
	if (!next_encodable(&cursor, &packet_ctx)) {
		MEM(buff = talloc_array(eap_packet, uint8_t, 3));

		buff[0] = subtype;	/* SIM or AKA subtype */
		buff[1] = 0;		/* Reserved (0) */
		buff[2] = 0;		/* Reserved (1) */

		eap_packet->type.length = 3;
		eap_packet->type.data = buff;

		return 0;
	}
	fr_pair_cursor_first(&cursor);	/* Reset */

	MEM(p = buff = talloc_zero_array(eap_packet, uint8_t, 1024));	/* We'll shrink this later */
	end = p + talloc_array_length(p);
	if (do_hmac) end -= SIM_CALC_MAC_SIZE;

	*p++ = subtype;			/* Subtype */
	*p++ = 0;			/* Reserved (0) */
	*p++ = 0;			/* Reserved (1) */

	/*
	 *	Encode all the things...
	 */
	(void)fr_pair_cursor_first(&cursor);
	while ((vp = fr_pair_cursor_current(&cursor))) {
		slen = fr_sim_encode_pair(p, end - p, &cursor, &packet_ctx);
		if (slen < 0) {
		error:
			talloc_free(buff);
			return -1;
		}
		p += slen;
		rad_assert(p < end);	/* We messed up a check somewhere in the encoder */
	}

	eap_packet->type.length = p - end;

	/*
	 *	Calculate a SHA1-HMAC over the complete EAP packet
	 */
	if (do_hmac) {
		/*
		 *	We left some room earlier...
		 */
		*p++ = FR_SIM_MAC;
		*p++ = (SIM_CALC_MAC_SIZE >> 2);
		*p++ = 0x00;
		*p++ = 0x00;

		slen = fr_sim_crypto_sign_packet(p, eap_packet,
				       		 keys->k_aut, sizeof(keys->k_aut),
				       		 keys->vector_type == SIM_VECTOR_GSM ? keys->gsm.nonce_mt : NULL,
				       		 keys->vector_type == SIM_VECTOR_GSM ? sizeof(keys->gsm.nonce_mt) : 0);
		if (slen < 0) goto error;
		eap_packet->type.length += SIM_CALC_MAC_SIZE;
	}
	FR_PROTO_HEX_DUMP("sim packet", buff, eap_packet->type.length);

	/*
	 *	Shrink buffer to the correct size
	 */
	if (eap_packet->type.length != talloc_array_length(buff)) {
		uint8_t *new;

		new = talloc_realloc(eap_packet, buff, uint8_t, eap_packet->type.length);
		if (!new) goto error;

		eap_packet->type.data = new;
	} else {
		eap_packet->type.data = buff;
	}

	return len;
}

/*
 *	Test ctx data
 */
static void *encode_test_ctx_sim(UNUSED TALLOC_CTX *ctx)
{
	static fr_sim_encode_ctx_t	test_ctx;
	static fr_sim_keys_t		keys = {
						.k_encr = { 0x00, 0x01, 0x02, 0x03, 0x04 ,0x05, 0x06, 0x07,
							    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }
					};
	fr_sim_global_init();

	test_ctx.root = dict_sim_root;
	test_ctx.keys = &keys;
	memset(&test_ctx.iv, 0, sizeof(test_ctx.iv));
	test_ctx.iv_included = true;	/* Ensures IV is all zeros */

	return &test_ctx;
}

static void *encode_test_ctx_aka(UNUSED TALLOC_CTX *ctx)
{
	static fr_sim_encode_ctx_t	test_ctx;
	static fr_sim_keys_t		keys = {
						.k_encr = { 0x00, 0x01, 0x02, 0x03, 0x04 ,0x05, 0x06, 0x07,
							    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }
					};
	fr_sim_global_init();

	test_ctx.root = dict_aka_root;
	test_ctx.keys = &keys;
	memset(&test_ctx.iv, 0, sizeof(test_ctx.iv));
	test_ctx.iv_included = true;	/* Ensures IV is all zeros */

	return &test_ctx;
}

static void *encode_test_ctx_sim_rfc4186(UNUSED TALLOC_CTX *ctx)
{
	static fr_sim_encode_ctx_t	test_ctx;
	static fr_sim_keys_t		keys = {
						.k_encr = { 0x53, 0x6e, 0x5e, 0xbc, 0x44 ,0x65, 0x58, 0x2a,
							    0xa6, 0xa8, 0xec, 0x99, 0x86, 0xeb, 0xb6, 0x20 }
					};
	fr_sim_global_init();

	test_ctx.root = dict_sim_root;
	test_ctx.keys = &keys;

	return &test_ctx;
}

/*
 *	Test points
 */
extern fr_test_point_pair_encode_t sim_tp_encode;
fr_test_point_pair_encode_t sim_tp_encode = {
	.test_ctx	= encode_test_ctx_sim,
	.func		= fr_sim_encode_pair
};

extern fr_test_point_pair_encode_t aka_tp_encode;
fr_test_point_pair_encode_t aka_tp_encode = {
	.test_ctx	= encode_test_ctx_aka,
	.func		= fr_sim_encode_pair
};

extern fr_test_point_pair_encode_t sim_tp_encode_rfc4186;
fr_test_point_pair_encode_t sim_tp_encode_rfc4186 = {
	.test_ctx	= encode_test_ctx_sim_rfc4186,
	.func		= fr_sim_encode_pair
};
