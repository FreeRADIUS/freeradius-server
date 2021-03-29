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
 * @file src/lib/eap_aka_sim/encode.c
 * @brief Code common to EAP-SIM/AKA/AKA' clients and servers.
 *
 * @copyright 2017 FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/io/test_point.h>

#include <freeradius-devel/eap/types.h>
#include "base.h"
#include "attrs.h"
#include "crypto_priv.h"

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

static ssize_t encode_tlv_hdr(fr_dbuff_t *dbuff,
			      fr_da_stack_t *da_stack, unsigned int depth,
			      fr_dcursor_t *cursor, void *encode_ctx);

/** Evaluation function for EAP-AKA-encodability
 *
 * @param item	pointer to a fr_pair_t
 * @param uctx	context
 *
 * @return true if the underlying fr_pair_t is EAP_AKA encodable, false otherwise
 */
static bool is_eap_aka_encodable(void const *item, void const *uctx)
{
	fr_pair_t const		*vp = item;
	fr_aka_sim_encode_ctx_t	const *packet_ctx = uctx;

	if (!vp) return false;
	if (vp->da->flags.internal) return false;
	/*
	 *	Bool attribute presence is 'true' in SIM
	 *	and absence is 'false'
	 */
	if ((vp->da->type == FR_TYPE_BOOL) && (vp->vp_bool == false)) return false;
	if (!fr_dict_attr_common_parent(packet_ctx->root, vp->da, true)) return false;

	return true;
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
static ssize_t encode_iv(fr_dbuff_t *dbuff, void *encode_ctx)
{
	fr_aka_sim_encode_ctx_t	*packet_ctx = encode_ctx;
	uint32_t		iv[4];
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	/*
	 *	One IV per packet
	 */
	if (packet_ctx->iv_included) return 0;

	/*
	 *	Generate IV
	 */
	iv[0] = fr_rand();
	iv[1] = fr_rand();
	iv[2] = fr_rand();
	iv[3] = fr_rand();

	memcpy(packet_ctx->iv, (uint8_t *)&iv[0], sizeof(packet_ctx->iv));	/* ensures alignment */

	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_IV, (4 + AKA_SIM_IV_SIZE) >> 2, 0x00, 0x00);
	FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, packet_ctx->iv, sizeof(packet_ctx->iv));

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "Initialisation vector");

	packet_ctx->iv_included = true;

	return fr_dbuff_set(dbuff, &work_dbuff);
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
static ssize_t encode_encrypted_value(fr_dbuff_t *dbuff,
			     	      uint8_t const *in, size_t inlen, void *encode_ctx)
{
	size_t			total_len, pad_len, encr_len, len = 0;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	uint8_t			*encr = NULL;
	fr_aka_sim_encode_ctx_t	*packet_ctx = encode_ctx;
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
		return PAIR_ENCODE_FATAL_ERROR;
	}

	total_len = (inlen + (block_size - 1)) & ~(block_size - 1);	/* Round input length to block size (16) */
	pad_len = (total_len - inlen);		/* How much we need to pad */

	/*
	 *	Usually in and out will be the same buffer
	 */
	if (unlikely(fr_dbuff_start(&work_dbuff) != in)) {
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, in, inlen);
	} else {
		FR_DBUFF_EXTEND_LOWAT_OR_RETURN(&work_dbuff, inlen);
		fr_dbuff_advance(&work_dbuff, inlen);
	}

	/*
	 *	Append an AT_PADDING attribute if required
	 */
	if (pad_len != 0) {
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, FR_PADDING, (uint8_t)(pad_len >> 2));
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, pad_len - 2);
		FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), pad_len, "Done padding attribute");
	}

	if (unlikely(!packet_ctx->k_encr)) {
		fr_strerror_printf("%s: No k_encr set, cannot encrypt attributes", __FUNCTION__);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	evp_ctx = aka_sim_crypto_cipher_ctx();
	if (unlikely(EVP_EncryptInit_ex(evp_ctx, evp_cipher, NULL,
					packet_ctx->k_encr, packet_ctx->iv) != 1)) {
		tls_strerror_printf("Failed initialising AES-128-ECB context");
	error:
		talloc_free(encr);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	encr = talloc_array(NULL, uint8_t, total_len);
	if (!encr) {
		fr_strerror_printf("%s: Failed allocating temporary buffer", __FUNCTION__);
		goto error;
	}

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), total_len, "plaintext");

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
	if (unlikely(EVP_EncryptUpdate(evp_ctx, encr, (int *)&len, fr_dbuff_start(&work_dbuff), total_len) != 1)) {
		tls_strerror_printf("%s: Failed encrypting attribute", __FUNCTION__);
		goto error;
	}
	encr_len = len;

	if (unlikely(EVP_EncryptFinal_ex(evp_ctx, encr + encr_len, (int *)&len) != 1)) {
		tls_strerror_printf("%s: Failed finalising encrypted attribute", __FUNCTION__);
		goto error;
	}
	encr_len += len;

	/*
	 *	Ciphertext should be same length as plaintext.
	 */
	if (unlikely(encr_len != total_len)) {
		fr_strerror_printf("%s: Invalid plaintext length, expected %zu, got %zu",
				   __FUNCTION__, total_len, encr_len);
		goto error;
	}

	FR_PROTO_HEX_DUMP(encr, encr_len, "ciphertext");

	/*
	 *	Overwrite the plaintext with our encrypted blob
	 */
	fr_dbuff_set_to_start(&work_dbuff);

	slen = fr_dbuff_in_memcpy(&work_dbuff, encr, encr_len);
	talloc_free(encr);
	if (slen <= 0) return slen;

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encodes the data portion of an attribute
 *
 * @return
 *	> 0, Length of the data portion.
 *      = 0, we could not encode anything, skip this attribute (and don't encode the header)
 *	< 0, failure.
 */
static ssize_t encode_value(fr_dbuff_t *dbuff,
			    fr_da_stack_t *da_stack, int depth,
			    fr_dcursor_t *cursor, void *encode_ctx)
{
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_pair_t const		*vp = fr_dcursor_current(cursor);
	fr_dict_attr_t const	*da = da_stack->da[depth];
	fr_aka_sim_encode_ctx_t	*packet_ctx = encode_ctx;

	VP_VERIFY(vp);
	FR_PROTO_STACK_PRINT(da_stack, depth);

	if (unlikely(da_stack->da[depth + 1] != NULL)) {
		fr_strerror_printf("%s: Encoding value but not at top of stack", __FUNCTION__);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	if (unlikely(vp->da != da)) {
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
	case FR_IV:
		if ((vp->da->flags.length && (da->flags.length != vp->vp_length)) ||
		    (vp->vp_length != sizeof(packet_ctx->iv))) {
			fr_strerror_printf("%s: Attribute \"%s\" needs a value of exactly %zu bytes, "
					   "but value was %zu bytes", __FUNCTION__,
					   da->name, (size_t)da->flags.length, vp->vp_length);
			return PAIR_ENCODE_FATAL_ERROR;
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
	case FR_RES:
		if ((vp->vp_length < 4) || (vp->vp_length > 16)) {
			fr_strerror_printf("%s: AKA-RES Length must be between 4-16 bytes, got %zu bytes",
					   __FUNCTION__, vp->vp_length);
			return PAIR_ENCODE_FATAL_ERROR;
		}

		FR_DBUFF_IN_RETURN(&work_dbuff, (uint16_t)(vp->vp_length * 8));	/* RES Length (bits, big endian) */
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_octets, vp->vp_length);
		goto done;

	/*
	 *	AT_CHECKCODE - Special case (Variable length with no length field)
	 *
	 *   	0                   1                   2                   3
	 *	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *	| AT_CHECKCODE  | Length        |           Reserved            |
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *	|                                                               |
	 *	|                     Checkcode (0 or 20 bytes)                 |
	 *	|                                                               |
	 *	|                                                               |
	 *	|                                                               |
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	case FR_CHECKCODE:
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, 0x00, 0x00);	/* Reserved */
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_octets, vp->vp_length);
		goto done;

	default:
		break;
	}

	switch (da->type) {
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
		if (vp->da->flags.length && (vp->vp_length != vp->da->flags.length)) {
			fr_strerror_printf("%s: Attribute \"%s\" needs a value of exactly %zu bytes, "
					   "but value was %zu bytes", __FUNCTION__,
					   vp->da->name, (size_t)vp->da->flags.length, vp->vp_length);
			return PAIR_ENCODE_FATAL_ERROR;
		}

		FR_DBUFF_IN_RETURN(&work_dbuff, (uint16_t)vp->vp_length);		/* Big endian real string length */
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)vp->vp_strvalue, vp->vp_length);
		break;

	case FR_TYPE_OCTETS:
		/*
		 *	Fixed length attribute
		 */
		if (vp->da->flags.length) {
			size_t prefix = fr_aka_sim_octets_prefix_len(vp->da);
			size_t pad_len;
			size_t value_len_rounded;

			if (vp->vp_length > vp->da->flags.length) {
				fr_strerror_printf("%s: Attribute \"%s\" needs a value of <= %zu bytes, "
						   "but value was %zu bytes", __FUNCTION__,
						   vp->da->name, (size_t)vp->da->flags.length, vp->vp_length);
				return PAIR_ENCODE_FATAL_ERROR;
			}

			/*
			 *	Calculate value padding (autopad)
			 */
			value_len_rounded = ROUND_UP(vp->vp_length, (size_t)vp->da->flags.length);
			/*
			 *	Zero out reserved bytes
			 */
			if (prefix) FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, prefix);

			/*
			 *	Copy in value
			 */
			FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_octets, vp->vp_length);

			/*
			 *	Pad out the value
			 */
			pad_len = value_len_rounded - vp->vp_length;
			if (pad_len) FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, pad_len);
		/*
		 *	Variable length attribute
		 */
		} else {
			FR_DBUFF_IN_RETURN(&work_dbuff, (uint16_t)vp->vp_length);	/* Big endian real string length */
			FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, (uint8_t const *)vp->vp_strvalue, vp->vp_length);
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
		FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, 0x00, 0x00);	/* reserved bytes */
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
	default:
	{
		ssize_t len = fr_value_box_to_network(&work_dbuff, &vp->data);
		if (len < 0) return len;
		break;
	}
	}
done:
	/*
	 *	Rebuilds the TLV stack for encoding the next attribute
	 */
	vp = fr_dcursor_filter_next(cursor, is_eap_aka_encodable, encode_ctx);
	fr_proto_da_stack_build(da_stack, vp ? vp->da : NULL);

	return fr_dbuff_set(dbuff, &work_dbuff);
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
static ssize_t encode_array(fr_dbuff_t *dbuff,
			    fr_da_stack_t *da_stack, int depth,
			    fr_dcursor_t *cursor, void *encode_ctx)
{
	size_t			pad_len;
	size_t			element_len;
	size_t			actual_len;
	fr_dbuff_t		len_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dict_attr_t const	*da = da_stack->da[depth];
	fr_assert(da->flags.array);

	FR_DBUFF_EXTEND_LOWAT_OR_RETURN(&work_dbuff, 2);
	fr_dbuff_advance(&work_dbuff, 2);

	if (unlikely(da->type == FR_TYPE_OCTETS)) {
		if (!da->flags.length) {
			fr_strerror_printf("Can't encode array type attribute \"%s\" as it does not "
					   "have a fixed length", da->name);
			return PAIR_ENCODE_FATAL_ERROR;
		}
		element_len = da->flags.length;
	} else {
		element_len = fr_aka_sim_attr_sizes[da->type][0];
	}

	/*
	 *	Keep encoding as long as we have space to
	 *	encode things.
	 */
	while (fr_dbuff_extend_lowat(NULL, &work_dbuff, element_len) >= element_len) {
		fr_pair_t	*vp;
		ssize_t		slen;

		slen = encode_value(&work_dbuff, da_stack, depth, cursor, encode_ctx);
		if (slen == PAIR_ENCODE_FATAL_ERROR) return slen;
		if (slen < 0) break;

		vp = fr_dcursor_current(cursor);
		if (!vp || (vp->da != da)) break;		/* Stop if we have an attribute of a different type */
	}

	actual_len = fr_dbuff_used(&work_dbuff) - 2;	/* Length of the elements we encoded */
	/*
	 *	Arrays with an element size which is
	 *	a multiple of 4 don't need an
	 *	actual_length field, because the number
	 *	of elements can be calculated from
	 *	the attribute length.
	 */
	if (element_len % 4) {
		FR_DBUFF_IN_RETURN(&len_dbuff, (uint16_t) actual_len);
	} else {
		FR_DBUFF_IN_RETURN(&len_dbuff, (uint16_t) 0);
	}

	/*
	 *	Pad value to multiple of 4
	 */
	pad_len = ROUND_UP_POW2(actual_len, 4) - actual_len;
	if (pad_len) FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, pad_len);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/** Encode an RFC format attribute header
 *
 * This could be a standard attribute, or a TLV data type.
 * If it's a standard attribute, then vp->da->attr == attribute.
 * Otherwise, attribute may be something else.
 */
static ssize_t encode_rfc_hdr(fr_dbuff_t *dbuff, fr_da_stack_t *da_stack, unsigned int depth,
			      fr_dcursor_t *cursor, void *encode_ctx)
{
	size_t			pad_len;
	fr_dict_attr_t const	*da;
	ssize_t			slen;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_t		hdr_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	FR_PROTO_STACK_PRINT(da_stack, depth);

	switch (da_stack->da[depth]->type) {
	case FR_TYPE_STRUCTURAL:
		fr_strerror_printf("%s: Called with structural type %s", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da_stack->da[depth]->type, "?Unknown?"));
		return PAIR_ENCODE_FATAL_ERROR;

	default:
		if (((fr_dict_vendor_num_by_da(da_stack->da[depth]) == 0) && (da_stack->da[depth]->attr == 0)) ||
		    (da_stack->da[depth]->attr > 255)) {
			fr_strerror_printf("%s: Called with non-standard attribute %u", __FUNCTION__,
					   da_stack->da[depth]->attr);
			return PAIR_ENCODE_FATAL_ERROR;
		}
		break;
	}

	/*
	 *	Write out the value to a buffer location
	 *	past the AT and Length fields.
	 *
	 *	Encode value will set reserved bytes to
	 *	zero and fill any subfields like actual
	 *	length.
	 */
	da = da_stack->da[depth];

	FR_DBUFF_EXTEND_LOWAT_OR_RETURN(&work_dbuff, 2);
	fr_dbuff_advance(&work_dbuff, 2);

	if (da->flags.array) {
		slen = encode_array(&FR_DBUFF_MAX(&work_dbuff, SIM_MAX_ATTRIBUTE_VALUE_LEN - 2),
				    da_stack, depth, cursor, encode_ctx);
	} else {
		slen = encode_value(&FR_DBUFF_MAX(&work_dbuff, SIM_MAX_ATTRIBUTE_VALUE_LEN - 2),
				    da_stack, depth, cursor, encode_ctx);
	}
	if (slen <= 0) return slen;

	/*
	 *	Pad value to multiple of 4
	 */
	pad_len = ROUND_UP_POW2(fr_dbuff_used(&work_dbuff), 4) - fr_dbuff_used(&work_dbuff);
	if (pad_len) {
		FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, pad_len);
	}

	fr_dbuff_in_bytes(&hdr_dbuff, (uint8_t)da->attr,
			  (uint8_t)(fr_dbuff_used(&work_dbuff) >> 2));

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "Done RFC attribute");

	return fr_dbuff_set(dbuff, &work_dbuff);	/* AT + Length + Data */
}

static inline ssize_t encode_tlv_internal(fr_dbuff_t *dbuff,
					  fr_da_stack_t *da_stack, unsigned int depth,
					  fr_dcursor_t *cursor, void *encode_ctx)
{
	ssize_t			slen;
	fr_dbuff_t		work_dbuff = FR_DBUFF_MAX_NO_ADVANCE(dbuff, SIM_MAX_ATTRIBUTE_VALUE_LEN);
	fr_dbuff_t		value_dbuff;
	fr_dbuff_marker_t	value_start;
	fr_pair_t const		*vp = fr_dcursor_current(cursor);
	fr_dict_attr_t const	*da = da_stack->da[depth];

	FR_DBUFF_IN_BYTES_RETURN(&work_dbuff, 0x00, 0x00);

	value_dbuff = FR_DBUFF_NO_ADVANCE(&work_dbuff);
	fr_dbuff_marker(&value_start, &value_dbuff);

	for(;;) {
		FR_PROTO_STACK_PRINT(da_stack, depth);

		/*
		 *	This attribute carries sub-TLVs.  The sub-TLVs
		 *	can only carry SIM_MAX_ATTRIBUTE_VALUE_LEN bytes of data.
		 */

		/*
		 *	Determine the nested type and call the appropriate encoder
		 */
		if (da_stack->da[depth + 1]->type == FR_TYPE_TLV) {
			slen = encode_tlv_hdr(&work_dbuff, da_stack, depth + 1, cursor, encode_ctx);
		} else {
			slen = encode_rfc_hdr(&work_dbuff, da_stack, depth + 1, cursor, encode_ctx);
		}

		if (slen <= 0) return slen;

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

	/*
	 *	encrypt the contents of the TLV using AES-CBC-128
	 *	or another encryption algorithm.
	 */
	if (!da->flags.extra && da->flags.subtype) {
		ssize_t	value_len = fr_dbuff_used(&work_dbuff) - 2;

		slen = encode_encrypted_value(&value_dbuff, fr_dbuff_current(&value_start),
					      value_len, encode_ctx);
		if (slen < 0) return PAIR_ENCODE_FATAL_ERROR;

		FR_DBUFF_EXTEND_LOWAT_OR_RETURN(&work_dbuff, (size_t)slen - value_len);
		fr_dbuff_advance(&work_dbuff, (size_t)slen - value_len);
	}

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "Done TLV");

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t encode_tlv_hdr(fr_dbuff_t *dbuff,
			      fr_da_stack_t *da_stack, unsigned int depth,
			      fr_dcursor_t *cursor, void *encode_ctx)
{
	unsigned int		total_len;
	ssize_t			len;
	fr_dict_attr_t const	*da;
	fr_dbuff_t		tl_dbuff;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	VP_VERIFY(fr_dcursor_current(cursor));
	FR_PROTO_STACK_PRINT(da_stack, depth);

	if (da_stack->da[depth]->type != FR_TYPE_TLV) {
		fr_strerror_printf("%s: Expected type \"tlv\" got \"%s\"", __FUNCTION__,
				   fr_table_str_by_value(fr_value_box_type_table, da_stack->da[depth]->type, "?Unknown?"));
		return PAIR_ENCODE_FATAL_ERROR;
	}

	if (!da_stack->da[depth + 1]) {
		fr_strerror_printf("%s: Can't encode empty TLV", __FUNCTION__);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	/*
	 *	Add the IV before the TLV
	 *	The ASCII art in the RFCs the attributes in
	 *	this order.
	 */
	if (!da_stack->da[depth]->flags.extra && da_stack->da[depth]->flags.subtype) {
		len = encode_iv(&work_dbuff, encode_ctx);
		if (len < 0) return len;
	}
	tl_dbuff = FR_DBUFF_NO_ADVANCE(&work_dbuff);

	FR_DBUFF_EXTEND_LOWAT_OR_RETURN(&work_dbuff, 2);
	fr_dbuff_advance(&work_dbuff, 2);

	da = da_stack->da[depth];
	len = encode_tlv_internal(&FR_DBUFF_MAX(&work_dbuff, SIM_MAX_ATTRIBUTE_VALUE_LEN - 2),
				  da_stack, depth, cursor, encode_ctx);
	if (len <= 0) return len;

	/*
	 *	Round attr + len + data length out to a multiple
	 *	of four, and setup the attribute header and
	 *	length field in the buffer.
	 */
	total_len = ROUND_UP_POW2(len + 2, 4);
	FR_DBUFF_IN_BYTES_RETURN(&tl_dbuff, (uint8_t)da->attr, (uint8_t)(total_len >> 2));

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), "Done TLV attribute");

	return fr_dbuff_set(dbuff, &work_dbuff);	/* AT_IV + AT_*(TLV) - Can't use total_len, doesn't include IV */
}

ssize_t fr_aka_sim_encode_pair(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, void *encode_ctx)
{
	fr_pair_t const		*vp;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_marker_t	m;
	ssize_t			slen;

	fr_da_stack_t		da_stack;
	fr_dict_attr_t const	*da = NULL;
	fr_aka_sim_encode_ctx_t	*packet_ctx = encode_ctx;

	fr_dbuff_marker(&m, &work_dbuff);
	if (!cursor) return PAIR_ENCODE_FATAL_ERROR;

	vp = fr_dcursor_filter_current(cursor, is_eap_aka_encodable, encode_ctx);
	if (!vp) return 0;

	VP_VERIFY(vp);

	if (vp->da->depth > FR_DICT_MAX_TLV_STACK) {
		fr_strerror_printf("%s: Attribute depth %i exceeds maximum nesting depth %i",
				   __FUNCTION__, vp->da->depth, FR_DICT_MAX_TLV_STACK);
		return PAIR_ENCODE_FATAL_ERROR;
	}

	if (vp->da->attr == FR_MAC) {
		fr_dcursor_filter_next(cursor, is_eap_aka_encodable, encode_ctx);
		return 0;
	}
	/*
	 *	Nested structures of attributes can't be longer than
	 *	4 * 255 bytes, so each call to an encode function can
	 *	only use 4 * 255 bytes of buffer space at a time.
	 */

	/*
	 *	Fast path for the common case.
	 */
	if ((vp->da->parent == packet_ctx->root) && (vp->vp_type != FR_TYPE_TLV)) {
		da_stack.da[0] = vp->da;
		da_stack.da[1] = NULL;
		da_stack.depth = 1;
		FR_PROTO_STACK_PRINT(&da_stack, 0);
		return encode_rfc_hdr(&FR_DBUFF_MAX(dbuff, SIM_MAX_ATTRIBUTE_VALUE_LEN + 2),
				      &da_stack, 0, cursor, encode_ctx);
	}

	/*
	 *	Do more work to set up the stack for the complex case.
	 */
	fr_proto_da_stack_build(&da_stack, vp->da);
	FR_PROTO_STACK_PRINT(&da_stack, 0);

	da = da_stack.da[0];

	switch (da->type) {
	/*
	 *	Supported types
	 */
	default:
		slen = encode_rfc_hdr(&FR_DBUFF_MAX(&work_dbuff, SIM_MAX_ATTRIBUTE_VALUE_LEN + 2),
				      &da_stack, 0, cursor, encode_ctx);
		if (slen < 0) return slen;
		break;

	case FR_TYPE_TLV:
		slen = encode_tlv_hdr(&FR_DBUFF_MAX(&work_dbuff, SIM_MAX_ATTRIBUTE_VALUE_LEN + 2),
				      &da_stack, 0, cursor, encode_ctx);
		if (slen < 0) return slen;
		break;
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

ssize_t fr_aka_sim_encode(request_t *request, fr_pair_list_t *to_encode, void *encode_ctx)
{
	fr_pair_t		*vp;

	uint8_t			*buff;
	ssize_t			slen;
	fr_dbuff_t		dbuff;
	fr_dbuff_marker_t	hmac;
	fr_dbuff_uctx_talloc_t	tctx;

	bool			do_hmac = false;

	unsigned char		subtype;
	fr_dcursor_t		cursor;
	fr_aka_sim_encode_ctx_t	*packet_ctx = encode_ctx;
	eap_packet_t		*eap_packet = packet_ctx->eap_packet;

	/*
	 *	Encoded_msg is now an EAP-SIM message.
	 *	It might be too big for putting into an
	 *	EAP packet.
	 */
	vp = fr_pair_find_by_child_num(to_encode, packet_ctx->root, FR_SUBTYPE);
	if (!vp) {
		REDEBUG("Missing subtype attribute");
		return PAIR_ENCODE_FATAL_ERROR;
	}
	subtype = vp->vp_uint16;

	/*
	 *	Group attributes with similar lineages together
	 */
	fr_pair_list_sort(to_encode, fr_pair_cmp_by_parent_num);
	if (fr_dcursor_init(&cursor, to_encode) == vp) fr_dcursor_next(&cursor);	/* Skip subtype if it came out first */

	/*
	 *	Will we need to generate a HMAC?
	 */
	if (fr_pair_find_by_child_num(to_encode, packet_ctx->root, FR_MAC)) do_hmac = true;

	/*
	 *	Fast path, we just need to encode a subtype
	 */
	if (!do_hmac && !fr_dcursor_filter_current(&cursor, is_eap_aka_encodable, packet_ctx)) {
		MEM(buff = talloc_array(eap_packet, uint8_t, 3));

		buff[0] = subtype;	/* SIM or AKA subtype */
		buff[1] = 0;		/* Reserved (0) */
		buff[2] = 0;		/* Reserved (1) */

		eap_packet->type.length = 3;
		eap_packet->type.data = buff;

		FR_PROTO_HEX_DUMP(buff, eap_packet->type.length, "sim packet");

		return 0;
	}
	fr_dcursor_head(&cursor);	/* Reset */

	fr_dbuff_init_talloc(NULL, &dbuff, &tctx, 512, 1024);

	fr_dbuff_in_bytes(&dbuff, subtype, 0x00, 0x00);

	/*
	 *	Add space in the packet for AT_MAC
	 */
	if (do_hmac) {
		FR_DBUFF_IN_BYTES_RETURN(&dbuff, FR_MAC, AKA_SIM_MAC_SIZE >> 2, 0x00, 0x00);
		fr_dbuff_marker(&hmac, &dbuff);
		FR_DBUFF_MEMSET_RETURN(&dbuff, 0, 16);
	}

	/*
	 *	Encode all the things...
	 */
	(void)fr_dcursor_head(&cursor);
	while (fr_dcursor_current(&cursor)) {
		slen = fr_aka_sim_encode_pair(&dbuff, &cursor, packet_ctx);
		if (slen < 0) {
		error:
			talloc_free(fr_dbuff_buff(&dbuff));
			return PAIR_ENCODE_FATAL_ERROR;
		}
		fr_assert(fr_dbuff_used(&dbuff) > 0);	/* We messed up a check somewhere in the encoder */
	}

	eap_packet->type.length = fr_dbuff_used(&dbuff);
	eap_packet->type.data = fr_dbuff_buff(&dbuff);

	/*
	 *	Calculate a SHA1-HMAC over the complete EAP packet
	 */
	if (do_hmac) {
		slen = fr_aka_sim_crypto_sign_packet(fr_dbuff_current(&hmac), eap_packet, false,
						 packet_ctx->hmac_md,
						 packet_ctx->keys->k_aut, packet_ctx->keys->k_aut_len,
						 packet_ctx->hmac_extra, packet_ctx->hmac_extra_len);
		if (slen < 0) goto error;
		FR_PROTO_HEX_DUMP(fr_dbuff_current(&hmac) - 4, AKA_SIM_MAC_SIZE, "hmac attribute");
	}
	FR_PROTO_HEX_DUMP(eap_packet->type.data, eap_packet->type.length, "sim packet");

	/*
	 *	Shrink buffer to the correct size
	 */
	if (eap_packet->type.length != talloc_array_length(eap_packet->type.data)) {
		uint8_t *realloced;

		realloced = talloc_realloc(eap_packet, eap_packet->type.data, uint8_t, eap_packet->type.length);
		if (!realloced) goto error;

		eap_packet->type.data = realloced;
	}

	return fr_dbuff_used(&dbuff);
}

/*
 *	Test ctx data
 */
static int _test_ctx_free(UNUSED fr_aka_sim_encode_ctx_t *ctx)
{
	fr_aka_sim_free();

	return 0;
}

static fr_aka_sim_encode_ctx_t *test_ctx_init(TALLOC_CTX *ctx, uint8_t const *k_encr, size_t k_encr_len)
{
	fr_aka_sim_encode_ctx_t	*test_ctx;
	fr_aka_sim_keys_t		*keys;

	test_ctx = talloc_zero(ctx, fr_aka_sim_encode_ctx_t);
	test_ctx->keys = keys = talloc_zero(test_ctx, fr_aka_sim_keys_t);
	memcpy(keys->k_encr, k_encr, k_encr_len);
	talloc_set_destructor(test_ctx, _test_ctx_free);

	if (fr_aka_sim_init() < 0) {
		talloc_free(test_ctx);
		return NULL;
	}

	return test_ctx;
}

/*
 *	Test ctx data
 */
static int encode_test_ctx_sim(void **out, TALLOC_CTX *ctx)
{
	fr_aka_sim_encode_ctx_t	*test_ctx;
	static uint8_t		k_encr[] = { 0x00, 0x01, 0x02, 0x03, 0x04 ,0x05, 0x06, 0x07,
					     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	test_ctx = test_ctx_init(ctx, k_encr, sizeof(k_encr));
	if (!test_ctx) return -1;

	test_ctx->root = fr_dict_root(dict_eap_aka_sim);
	test_ctx->iv_included = true;	/* Ensures IV is all zeros */

	*out = test_ctx;

	return 0;
}

static int encode_test_ctx_aka(void **out, TALLOC_CTX *ctx)
{
	fr_aka_sim_encode_ctx_t	*test_ctx;
	static uint8_t		k_encr[] = { 0x00, 0x01, 0x02, 0x03, 0x04 ,0x05, 0x06, 0x07,
					     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	test_ctx = test_ctx_init(ctx, k_encr, sizeof(k_encr));
	if (!test_ctx) return -1;

	test_ctx->root = fr_dict_root(dict_eap_aka_sim);
	test_ctx->iv_included = true;	/* Ensures IV is all zeros */

	*out = test_ctx;

	return 0;
}

static int encode_test_ctx_sim_rfc4186(void **out, TALLOC_CTX *ctx)
{
	fr_aka_sim_encode_ctx_t	*test_ctx;
	static uint8_t		k_encr[] = { 0x53, 0x6e, 0x5e, 0xbc, 0x44 ,0x65, 0x58, 0x2a,
					     0xa6, 0xa8, 0xec, 0x99, 0x86, 0xeb, 0xb6, 0x20 };

	test_ctx = test_ctx_init(ctx, k_encr, sizeof(k_encr));
	if (!test_ctx) return -1;

	test_ctx->root = fr_dict_root(dict_eap_aka_sim);

	*out = test_ctx;

	return 0;
}

/*
 *	Test points
 */
extern fr_test_point_pair_encode_t sim_tp_encode;
fr_test_point_pair_encode_t sim_tp_encode = {
	.test_ctx	= encode_test_ctx_sim,
	.func		= fr_aka_sim_encode_pair
};

extern fr_test_point_pair_encode_t aka_tp_encode;
fr_test_point_pair_encode_t aka_tp_encode = {
	.test_ctx	= encode_test_ctx_aka,
	.func		= fr_aka_sim_encode_pair
};

extern fr_test_point_pair_encode_t sim_tp_encode_rfc4186;
fr_test_point_pair_encode_t sim_tp_encode_rfc4186 = {
	.test_ctx	= encode_test_ctx_sim_rfc4186,
	.func		= fr_aka_sim_encode_pair
};
