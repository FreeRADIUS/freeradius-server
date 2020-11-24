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
 * @file src/lib/eap_aka_sim/decode.c
 * @brief Code common to EAP-SIM/AKA/AKA' clients and servers.
 *
 * The development of the EAP-SIM support was funded by Internet Foundation
 * Austria (http://www.nic.at/ipa).
 *
 * @copyright 2003 Michael Richardson (mcr@sandelman.ottawa.on.ca)
 * @copyright 2003-2016 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/io/test_point.h>

#include <freeradius-devel/eap/types.h>
#include "base.h"
#include "attrs.h"

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

static ssize_t sim_decode_pair_internal(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *parent,
					   uint8_t const *data, size_t data_len, void *decoder_ctx);

static ssize_t sim_decode_pair_value(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *parent,
				     uint8_t const *data, size_t const attr_len, size_t const data_len,
				     void *decoder_ctx);

/** Extract the IV value from an AT_IV attribute
 *
 * SIM uses padding at the start of the attribute to make it a multiple of 4.
 * We need to strip packet_ctx and check that it was set to zero.
 *
 * @param[out] out 	Where to write IV.
 * @param[in] in	value of AT_IV attribute.
 * @param[in] in_len	the length of the AT_IV attribute (should be 18).
 * @return
 *	- 0 on success.
 *	- < 0 on failure (bad IV).
 */
static inline int sim_iv_extract(uint8_t out[AKA_SIM_IV_SIZE], uint8_t const *in, size_t in_len)
{
	/*
	 *	Two bytes are reserved, so although
	 *	the IV is actually 16 bytes, we
	 *	check for 18.
	 */
	if (in_len != (AKA_SIM_IV_SIZE + 2)) {
		fr_strerror_printf("%s: Invalid IV length, expected %u got %zu",
				   __FUNCTION__, (AKA_SIM_IV_SIZE + 2), in_len);
		return -1;
	}

	if ((in[0] != 0x00) || (in[1] != 0x00)) {
		fr_strerror_printf("%s: Reserved bytes in IV are not zeroed", __FUNCTION__);
		return -1;
	}

	/* skip reserved bytes */
	memcpy(out, in + 2, AKA_SIM_IV_SIZE);

	return 0;
}

/** Decrypt an AES-128-CBC encrypted attribute
 *
 * @param[in] ctx		to allocate decr buffer in.
 * @param[out] out		where to write pointer to decr buffer.
 * @param[in] data		to decrypt.
 * @param[in] attr_len		length of encrypted data.
 * @param[in] data_len		length of data remaining in the packet.
 * @param[in] decoder_ctx	containing keys, and the IV (if we already found it).
 * @return
 *	- Number of decr bytes decrypted on success.
 *	- < 0 on failure.
 */
static ssize_t sim_value_decrypt(TALLOC_CTX *ctx, uint8_t **out,
				 uint8_t const *data, size_t const attr_len, size_t const data_len,
				 void *decoder_ctx)
{
	fr_aka_sim_decode_ctx_t	*packet_ctx = decoder_ctx;
	EVP_CIPHER_CTX		*evp_ctx;
	EVP_CIPHER const	*evp_cipher = EVP_aes_128_cbc();
	size_t			block_size = EVP_CIPHER_block_size(evp_cipher);
	size_t			len = 0, decr_len = 0;
	uint8_t			*decr = NULL;

	if (!fr_cond_assert(attr_len <= data_len)) return -1;

	FR_PROTO_HEX_DUMP(data, attr_len, "ciphertext");

	/*
	 *	Encrypted values must be a multiple of 16.
	 *
	 *	There's a padding attribute to ensure they
	 *	always can be...
	 */
	if (attr_len % block_size) {
		fr_strerror_printf("%s: Encrypted attribute is not a multiple of cipher's block size (%zu)",
				   __FUNCTION__, block_size);
		return -1;
	}

	/*
	 *	Ugh, now we have to go hunting for it....
	 */
	if (!packet_ctx->have_iv) {
		uint8_t const	*p = data + attr_len;	/* Skip to the end of packet_ctx attribute */
		uint8_t const	*end = data + data_len;

		while ((size_t)(end - p) >= sizeof(uint32_t)) {
			uint8_t	 sim_at = p[0];
			size_t	 sim_at_len = p[1] * sizeof(uint32_t);

			if (sim_at_len == 0) {
				fr_strerror_printf("%s: Failed IV search.  AT Length field is zero", __FUNCTION__);
				return -1;
			}

			if ((p + sim_at_len) > end) {
				fr_strerror_printf("%s: Invalid IV length, longer than remaining data", __FUNCTION__);
				return -1;
			}

			if (sim_at == FR_IV) {
				if (sim_iv_extract(&(packet_ctx->iv[0]), p + 2, sim_at_len - 2) < 0) return -1;
				packet_ctx->have_iv = true;
				break;
			}
			p += sim_at_len;
		}

		if (!packet_ctx->have_iv) {
			fr_strerror_printf("%s: No IV present in packet, can't decrypt data", __FUNCTION__);
			return -1;
		}
	}

	evp_ctx = EVP_CIPHER_CTX_new();
	if (!evp_ctx) {
		tls_strerror_printf("%s: Failed initialising EVP ctx", __FUNCTION__);
		return -1;
	}

	if (!EVP_DecryptInit_ex(evp_ctx, evp_cipher, NULL, packet_ctx->keys->k_encr, packet_ctx->iv)) {
		tls_strerror_printf("%s: Failed setting decryption parameters", __FUNCTION__);
	error:
		talloc_free(decr);
		EVP_CIPHER_CTX_free(evp_ctx);
		return -1;
	}

	MEM(decr = talloc_zero_array(ctx, uint8_t, attr_len));

	/*
	 *	By default OpenSSL expects 16 bytes of cleartext
	 *	to produce 32 bytes of ciphertext, due to padding
	 *	being added if the decr is a multiple of 16.
	 *
	 *	There's no way for OpenSSL to determine if a
	 *	16 byte ciphertext was padded or not, so we need to
	 *	inform OpenSSL explicitly that there's no padding.
	 */
	EVP_CIPHER_CTX_set_padding(evp_ctx, 0);
	if (!EVP_DecryptUpdate(evp_ctx, decr, (int *)&len, data, attr_len)) {
		tls_strerror_printf("%s: Failed decrypting attribute", __FUNCTION__);
		goto error;
	}
	decr_len = len;

	if (!EVP_DecryptFinal_ex(evp_ctx, decr + decr_len, (int *)&len)) {
		tls_strerror_printf("%s: Failed decrypting attribute", __FUNCTION__);
		goto error;
	}
	decr_len += len;

	EVP_CIPHER_CTX_free(evp_ctx);

	/*
	 *	Note: packet_ctx implicitly validates the length of the padding
	 *	attribute (if present), so we don't have to do it later.
	 */
	if (decr_len % block_size) {
		fr_strerror_printf("%s: Expected decrypted value length to be multiple of %zu, got %zu",
				   __FUNCTION__, block_size, decr_len);
		goto error;
	}

	/*
	 *	Ciphertext should be same length as plaintext.
	 */
	if (unlikely(attr_len != decr_len)) {
		fr_strerror_printf("%s: Invalid plaintext length, expected %zu, got %zu",
				   __FUNCTION__, attr_len, decr_len);
		goto error;
	}

	FR_PROTO_TRACE("decryption successful, got %zu bytes of cleartext", decr_len);
	FR_PROTO_HEX_DUMP(decr, decr_len, "cleartext");

	*out = decr;

	return decr_len;
}

/** Returns the number of array members for arrays with fixed element sizes
 *
 * @param[out] out	The element length.
 * @param[in] len	the total length of the array.
 * @param[in] da	the specifying the array type.
 * @return
 *	- The number of elements in the array on success.
 *	- < 0 on error (array length not a multiple of element size).
 */
static int sim_array_members(size_t *out, size_t len, fr_dict_attr_t const *da)
{
	size_t		element_len;

	/*
	 *	Could be an array of bytes, integers, etc.
	 */
	switch (da->type) {
	case FR_TYPE_OCTETS:
		if (da->flags.length == 0) {
			fr_strerror_printf("%s: Octets array must have fixed length elements", __FUNCTION__);
			return -1;
		}
		element_len = da->flags.length;
		break;

	default:
		element_len = fr_aka_sim_attr_sizes[da->type][0];
		break;
	}

	if (element_len == 1) {
		*out = 1;
		return 1;	/* Fast path */
	}

	if (!fr_cond_assert(element_len > 0)) return -1;

	if (element_len > len) {
		fr_strerror_printf("%s: Element length (%zu) > array length (%zu)", __FUNCTION__,
				   element_len, len);
		return -1;
	}

	/*
	 *	Number of elements must divide exactly
	 */
	if (len % element_len) {
		fr_strerror_printf("%s: Expected array actual length to be multiple of %zu, got %zu",
				   __FUNCTION__, element_len, len);
		return -1;
	}
	*out = element_len;

	return len / element_len;
}

static ssize_t sim_decode_array(TALLOC_CTX *ctx, fr_cursor_t *cursor,
				fr_dict_attr_t const *parent,
				uint8_t const *data, size_t const attr_len, UNUSED size_t data_len,
				void *decoder_ctx)
{
	uint8_t const	*p = data, *end = p + attr_len;
	uint16_t	actual_len;
	int		elements, i;
	size_t		element_len;
	ssize_t		ret;

	FR_PROTO_TRACE("Array attribute");

	fr_assert(parent->flags.array);
	fr_assert(attr_len >= 2);		/* Should have been caught earlier */

	/*
	 *	Arrays with fixed length members that
	 *	are a multiple of 4 don't need an
	 *	actual_len value, as we can get the
	 *	number of elements from the attribute
	 *	length.
	 */
	if (!parent->flags.length || (parent->flags.length % 4)) {
		actual_len = (p[0] << 8) | p[1];
		if (actual_len > (attr_len - 2)) {
			fr_strerror_printf("%s: Actual length field value (%hu) > attribute value length (%zu)",
					   __FUNCTION__, actual_len, attr_len - 2);
			return -1;
		}
	} else {
		actual_len = attr_len - 2;	/* -2 for the reserved bytes */
	}
	p += 2;

	/*
	 *	Zero length array
	 */
	if (!actual_len) return p - data;

	/*
	 *	Get the number of elements
	 */
	elements = sim_array_members(&element_len, actual_len, parent);
	if (elements < 0) return elements;

	for (i = 0; i < elements; i++) {
		ret = sim_decode_pair_value(ctx, cursor, parent, p, element_len, end - p, decoder_ctx);
		if (ret < 0) return ret;

		p += ret;

		if (!fr_cond_assert(p <= end)) break;
	}

	return attr_len;	/* Say we consumed attr_len because it may have padding */
}

/** Break apart a TLV attribute into individual attributes
 *
 * @param[in] ctx		to allocate new attributes in.
 * @param[in] cursor		to add new attributes to.
 * @param[in] parent		the current attribute TLV attribute we're processing.
 * @param[in] data		to parse. Points to the data field of the attribute.
 * @param[in] attr_len		length of the TLV attribute.
 * @param[in] data_len		remaining data in the packet.
 * @param[in] decoder_ctx	IVs, keys etc...
 * @return
 *	- Length on success.
 *	- < 0 on malformed attribute.
 */
static ssize_t sim_decode_tlv(TALLOC_CTX *ctx, fr_cursor_t *cursor,
			      fr_dict_attr_t const *parent,
			      uint8_t const *data, size_t const attr_len, size_t data_len,
			      void *decoder_ctx)
{
	uint8_t const		*p = data, *end = p + attr_len;
	uint8_t			*decr = NULL;
	ssize_t			decr_len;
	fr_dict_attr_t const	*child;
	fr_pair_list_t		head;
	fr_cursor_t		tlv_cursor;
	ssize_t			ret;

	fr_pair_list_init(&head);
	if (data_len < 2) {
		fr_strerror_printf("%s: Insufficient data", __FUNCTION__);
		return -1; /* minimum attr size */
	}

	/*
	 *	We have an AES-128-CBC encrypted attribute
	 *
	 *	IV is from AT_IV, key is from k_encr.
	 *
	 *	unfortunately the ordering of these two attributes
	 *	aren't specified, so we may have to hunt for the IV.
	 */
	if (!parent->flags.extra && parent->flags.subtype) {
		FR_PROTO_TRACE("found encrypted attribute '%s'", parent->name);

		decr_len = sim_value_decrypt(ctx, &decr, p + 2,
					     attr_len - 2, data_len - 2, decoder_ctx);	/* Skip reserved */
		if (decr_len < 0) return -1;

		p = decr;
		end = p + decr_len;
	} else {
		p += 2;	/* Skip the reserved bytes */
	}

	FR_PROTO_HEX_DUMP(p, end - p, "tlvs");

	/*
	 *  Record where we were in the list when packet_ctx function was called
	 */
	fr_cursor_init(&tlv_cursor, &head);
	while ((size_t)(end - p) >= sizeof(uint32_t)) {
		uint8_t	sim_at = p[0];
		size_t	sim_at_len = ((size_t)p[1]) << 2;

		if ((p + sim_at_len) > end) {
			fr_strerror_printf("%s: Malformed nested attribute %d: Length field (%zu bytes) value "
					   "longer than remaining data in parent (%zu bytes)",
					   __FUNCTION__, sim_at, sim_at_len, end - p);

		error:
			talloc_free(decr);
			fr_pair_list_free(&head);
			return -1;
		}

		if (sim_at_len == 0) {
			fr_strerror_printf("%s: Malformed nested attribute %d: Length field 0", __FUNCTION__, sim_at);
			goto error;
		}

		/*
		 *	Padding attributes are cleartext inside of
		 *	encrypted TLVs to pad out the value to the
		 *	correct length for the block cipher
		 *	(16 in the case of AES-128-CBC).
		 */
		if (sim_at == FR_PADDING) {
			uint8_t zero = 0;
			uint8_t i;

			if (!parent->flags.subtype) {
				fr_strerror_printf("%s: Found padding attribute outside of an encrypted TLV",
						   __FUNCTION__);
				goto error;
			}

			if (!fr_cond_assert(data_len % 4)) goto error;

			if (sim_at_len > 12) {
				fr_strerror_printf("%s: Expected padding attribute length <= 12 bytes, got %zu bytes",
						   __FUNCTION__, sim_at_len);
				goto error;
			}

			/*
			 *	RFC says we MUST verify that FR_PADDING
			 *	data is zeroed out.
			 */
			for (i = 2; i < sim_at_len; i++) zero |= p[i];
			if (zero) {
				fr_strerror_printf("%s: Padding attribute value not zeroed 0x%pH", __FUNCTION__,
						   fr_box_octets(p + 2, sim_at_len - 2));
				goto error;
			}

			p += sim_at_len;
			continue;
		}

		child = fr_dict_attr_child_by_num(parent, p[0]);
		if (!child) {
			fr_dict_attr_t const *unknown_child;

			FR_PROTO_TRACE("Failed to find child %u of TLV %s", p[0], parent->name);

			/*
			 *	Encountered none skippable attribute
			 *
			 *	RFC says we need to die on these if we don't
			 *	understand them.  non-skippables are < 128.
			 */
			if (sim_at <= AKA_SIM_SKIPPABLE_MAX) {
				fr_strerror_printf("%s: Unknown (non-skippable) attribute %i",
						   __FUNCTION__, sim_at);
				goto error;
			}

			/*
			 *	Build an unknown attr
			 */
			unknown_child = fr_dict_unknown_attr_afrom_num(ctx, parent, p[0]);
			if (!unknown_child) goto error;
			child = unknown_child;
		}
		FR_PROTO_TRACE("decode context changed %s -> %s", parent->name, child->name);

		ret = sim_decode_pair_value(ctx, &tlv_cursor, child, p + 2, sim_at_len - 2, (end - p) - 2,
					      decoder_ctx);
		if (ret < 0) goto error;
		p += sim_at_len;
	}
	fr_cursor_head(&tlv_cursor);
	fr_cursor_tail(cursor);
	fr_cursor_merge(cursor, &tlv_cursor);	/* Wind to the end of the new pairs */
	talloc_free(decr);

	return attr_len;
}

/** Create any kind of VP from the attribute contents
 *
 * @param[in] ctx		to allocate new attributes in.
 * @param[in] cursor		to addd new attributes to.
 * @param[in] parent		the current attribute we're processing.
 * @param[in] data		to parse. Points to the data field of the attribute.
 * @param[in] attr_len		length of the attribute being parsed.
 * @param[in] data_len		length of the remaining data in the packet.
 * @param[in] decoder_ctx	IVs, keys etc...
 * @return
 *	- Length on success.
 *	- -1 on failure.
 */
static ssize_t sim_decode_pair_value(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *parent,
				     uint8_t const *data, size_t const attr_len, size_t const data_len,
				     void *decoder_ctx)
{
	fr_pair_t		*vp;
	uint8_t const		*p = data;
	size_t			prefix = 0;
	fr_dict_attr_t		*unknown;

	fr_aka_sim_decode_ctx_t	*packet_ctx = decoder_ctx;

	if (!fr_cond_assert(attr_len <= data_len)) return -1;
	if (!fr_cond_assert(parent)) return -1;

	FR_PROTO_TRACE("Parent %s len %zu", parent->name, attr_len);
	FR_PROTO_HEX_DUMP(data, attr_len, __FUNCTION__ );

	FR_PROTO_TRACE("Type \"%s\" (%u)", fr_table_str_by_value(fr_value_box_type_table, parent->type, "?Unknown?"), parent->type);

	/*
	 *	Special cases, attributes that either have odd formats, or need
	 *	have information we need to decode the packet.
	 */
	switch (parent->attr) {
	/*
	 *	We need to record packet_ctx so we can decrypt AT_ENCR attributes.
	 *
	 *	If we don't find it before, then that's fine, we'll try and
	 *	find it in the rest of the packet after the encrypted
	 *	attribute.
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
		if (sim_iv_extract(&packet_ctx->iv[0], data, attr_len) < 0) return -1;
		packet_ctx->have_iv = true;
		break;	/* Now create the attribute */

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
	{
		uint16_t res_len;

		if (attr_len < 2) goto raw;	/* Need at least two bytes for the length field */

		res_len = (p[0] << 8) | p[1];
		if (res_len % 8) {
			fr_strerror_printf("%s: RES Length (%hu) is not a multiple of 8",
					   __FUNCTION__, res_len);
			return -1;
		}
		res_len /= 8;

		if (res_len > (attr_len - 2)) {
			fr_strerror_printf("%s: RES Length field value (%u bits) > attribute value length (%zu bits)",
					   __FUNCTION__, res_len * 8, (attr_len - 2) * 8);
			return -1;
		}

		if ((res_len < 4) || (res_len > 16)) {
			fr_strerror_printf("%s: RES Length field value must be between 32-128 bits, got %u bits",
					   __FUNCTION__, (res_len * 8));
			return -1;
		}

		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return -1;

		fr_pair_value_memdup(vp, p + 2, res_len, true);
	}
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
		if (attr_len < 2) goto raw;	/* Need at least two bytes for reserved field */

		vp = fr_pair_afrom_da(ctx, parent);
		if (!vp) return -1;

		fr_pair_value_memdup(vp, p + 2, attr_len - 2, true);
		goto done;

	default:
		break;
	}

	switch (parent->type) {
	case FR_TYPE_STRING:
		if (attr_len < 2) goto raw;	/* Need at least two bytes for the length field */
		if (parent->flags.length && (attr_len != parent->flags.length)) {
		wrong_len:
			fr_strerror_printf("%s: Attribute \"%s\" needs a value of exactly %zu bytes, "
					   "but value was %zu bytes", __FUNCTION__,
					   parent->name, (size_t)parent->flags.length, attr_len);
			goto raw;
		}
		break;

	case FR_TYPE_OCTETS:
		/*
		 *	Get the number of bytes we expect before the value
		 */
		prefix = fr_aka_sim_octets_prefix_len(parent);
		if (attr_len < prefix) goto raw;
		if (parent->flags.length && (attr_len != (parent->flags.length + prefix))) goto wrong_len;
		break;

	case FR_TYPE_BOOL:
	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
		if (attr_len != fr_aka_sim_attr_sizes[parent->type][0]) goto raw;
		break;

	case FR_TYPE_TLV:
		if (attr_len < 2) goto raw;

		/*
		 *	We presume that the TLVs all fit into one
		 *	attribute, OR they've already been grouped
		 *	into a contiguous memory buffer.
		 */
		return sim_decode_tlv(ctx, cursor, parent, p, attr_len, data_len, decoder_ctx);

	default:
	raw:
		/*
		 *	We can't create unknowns for non-skippable attributes
		 *	as we're prohibited from continuing by the SIM RFCs.
		 */
		if (parent->attr <= AKA_SIM_SKIPPABLE_MAX) {
			fr_strerror_printf_push("%s: Failed parsing non-skippable attribute '%s'",
						__FUNCTION__, parent->name);
			return -1;
		}

#ifdef __clang_analyzer__
		if (!parent->parent) return -1; /* stupid static analyzers */
#endif
		fr_assert(parent->parent);

		/*
		 *	Re-write the attribute to be "raw".  It is
		 *	therefore of type "octets", and will be
		 *	handled below.
		 */
		parent = unknown = fr_dict_unknown_attr_afrom_da(ctx, parent);
		if (!parent) {
			fr_strerror_printf_push("%s[%d]: Internal sanity check failed", __FUNCTION__, __LINE__);
			return -1;
		}
		unknown->flags.is_raw = 1;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (!vp) return -1;

	/*
	 *	For unknown attributes copy the entire value, not skipping
	 *	any reserved bytes.
	 */
	if (parent->flags.is_unknown || parent->flags.is_raw) {
		fr_pair_value_memdup(vp, p, attr_len, true);
		vp->vp_length = attr_len;
		goto done;
	}

	switch (parent->type) {
	/*
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
		uint16_t actual_len = (p[0] << 8) | p[1];

		if (actual_len > (attr_len - 2)) {
			fr_strerror_printf("%s: Actual length field value (%hu) > attribute value length (%zu)",
					   __FUNCTION__, actual_len, attr_len - 2);
			return -1;
		}

		fr_pair_value_bstrndup(vp, (char const *)p + 2, actual_len, true);
	}
		break;

	case FR_TYPE_OCTETS:
		/*
		 *	Variable length octets buffer
		 */
		if (!parent->flags.length) {
			uint16_t actual_len = (p[0] << 8) | p[1];

			if (actual_len > (attr_len - prefix)) {
				fr_strerror_printf("%s: Actual length field value (%hu) > attribute value length (%zu)",
						   __FUNCTION__, actual_len, attr_len - 2);
				return -1;
			}

			fr_pair_value_memdup(vp, p + prefix, actual_len, true);
		/*
		 *	Fixed length octets buffer
		 */
		} else {
			fr_pair_value_memdup(vp, p + prefix, attr_len - prefix, true);
		}
		break;

	/*
	 *	Not proper bool. We Use packet_ctx to represent
	 *	flag attributes like AT_FULLAUTH_ID_REQ
	 *
	 *	0                   1                   2                   3
	 *	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *	|   AT_<BOOL>   | Length = 1    |           Reserved            |
	 *	+---------------+---------------+-------------------------------+
	 */
	case FR_TYPE_BOOL:
		vp->vp_bool = true;
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
		vp->vp_uint8 = p[0];
		break;

	case FR_TYPE_UINT16:
		memcpy(&vp->vp_uint16, p, sizeof(vp->vp_uint16));
		vp->vp_uint16 = ntohs(vp->vp_uint32);
		break;

	case FR_TYPE_UINT32:
		memcpy(&vp->vp_uint32, p, sizeof(vp->vp_uint32));
		vp->vp_uint32 = ntohl(vp->vp_uint32);
		break;

	case FR_TYPE_UINT64:
		memcpy(&vp->vp_uint64, p, sizeof(vp->vp_uint64));
		vp->vp_uint64 = ntohll(vp->vp_uint64);
		break;

	default:
		fr_pair_list_free(&vp);
		fr_strerror_printf_push("%s[%d]: Internal sanity check failed", __FUNCTION__, __LINE__);
		return -1;
	}

done:
	vp->type = VT_DATA;
	fr_cursor_append(cursor, vp);

	return attr_len;
}

/** Decode SIM/AKA/AKA' attributes
 *
 * @param[in] ctx		to allocate attributes in.
 * @param[in] cursor		where to insert the attributes.
 * @param[in] parent		of current attribute being decoded.
 * @param[in] data		data to parse.
 * @param[in] data_len		length of data.  For top level attributes packet_ctx must be the length
 *				of the packet (so we can hunt for AT_IV), for Sub-TLVs it should
 *				be the length of the container value.
 * @param[in] decoder_ctx	extra context to pass to the decoder.
 * @return
 *	- The number of bytes parsed.
 *	- -1 on error.
 */
static ssize_t sim_decode_pair_internal(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *parent,
					uint8_t const *data, size_t data_len, void *decoder_ctx)
{
	uint8_t			sim_at;
	size_t			sim_at_len;

	ssize_t			ret;
	fr_dict_attr_t const	*da;


	/*
	 *	We need at least 2 bytes.  We really need 4 but it's
	 *	useful to print the attribute number in the errors.
	 */
	if (data_len < 2) {
		fr_strerror_printf("%s: Insufficient data: Expected >= 2 bytes, got %zu bytes",
				   __FUNCTION__, data_len);
		return -1;
	}

	sim_at = data[0];

	sim_at_len = ((size_t)data[1]) << 2;
	if (sim_at_len > data_len) {
		fr_strerror_printf("%s: Insufficient data for attribute %d: Length field %zu, remaining data %zu",
				   __FUNCTION__, sim_at, sim_at_len, data_len);
		return -1;
	}

	if (sim_at_len == 0) {
		fr_strerror_printf("%s: Malformed attribute %d: Length field 0", __FUNCTION__, sim_at);
		return -1;
	}

	da = fr_dict_attr_child_by_num(parent, sim_at);
	if (!da) {
		FR_PROTO_TRACE("Unknown attribute %u", sim_at);

		/*
		 *	Encountered none skippable attribute
		 *
		 *	RFC says we need to die on these if we don't
		 *	understand them.  non-skippables are < 128.
		 */
		if (sim_at <= AKA_SIM_SKIPPABLE_MAX) {
			fr_strerror_printf("Unknown (non-skippable) attribute %i", sim_at);
			return -1;
		}
		da = fr_dict_unknown_attr_afrom_num(ctx, parent, sim_at);
	}
	if (!da) return -1;

	FR_PROTO_TRACE("decode context changed %s -> %s", da->parent->name, da->name);

	if (da->flags.array) {
		ret = sim_decode_array(ctx, cursor, da, data + 2, sim_at_len - 2, data_len - 2, decoder_ctx);
	} else {
		ret = sim_decode_pair_value(ctx, cursor, da, data + 2, sim_at_len - 2, data_len - 2, decoder_ctx);
	}
	if (ret < 0) return ret;

	return 2 + ret;
}

/** Decode SIM/AKA/AKA' attributes
 *
 * @param[in] ctx		to allocate attributes in.
 * @param[in] cursor		where to insert the attributes.
 * @param[in] dict		for looking up attributes.
 * @param[in] data		data to parse.
 * @param[in] data_len		length of data.  For top level attributes packet_ctx must be the length
 *				of the packet (so we can hunt for AT_IV), for Sub-TLVs it should
 *				be the length of the container value.
 * @param[in] decoder_ctx	extra context to pass to the decoder.
 * @return
 *	- The number of bytes parsed.
 *	- -1 on error.
 */
ssize_t fr_aka_sim_decode_pair(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
			   uint8_t const *data, size_t data_len, void *decoder_ctx)
{
	return sim_decode_pair_internal(ctx, cursor, fr_dict_root(dict), data, data_len, decoder_ctx);
}

/** Decode SIM/AKA/AKA' specific packet data
 *
 * @note data should point to the subtype field in the EAP packet.
 *
 * Extracts the SUBTYPE and adds it an attribute, then decodes any TLVs in the
 * SIM/AKA/AKA' packet.
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Code      |  Identifier   |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Type      |    Subtype    |           Reserved            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The first byte of the data pointer should be the subtype.
 *
 * @param[in] request		the current request.
 * @param[in] decoded		where to write decoded attributes.
 * @param[in] dict		for looking up attributes.
 * @param[in] data		to convert to pairs.
 * @param[in] data_len		length of data to convert.
 * @param[in] decoder_ctx	holds the state of the decoder.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_aka_sim_decode(request_t *request, fr_cursor_t *decoded, fr_dict_t const *dict,
		  uint8_t const *data, size_t data_len, fr_aka_sim_decode_ctx_t *decoder_ctx)
{
	ssize_t			ret;
	uint8_t	const		*p = data;
	uint8_t const		*end = p + data_len;

	/*
	 *	Move the cursor to the end, so we know if
	 *	any additional attributes were added.
	 */
	fr_cursor_tail(decoded);

	/*
	 *	We need at least enough data for the subtype
	 *	and reserved bytes.
	 *
	 *	Note: Not all packets should contain attrs.
	 *	When the client acknowledges an
	 *	AKA-Notification from the server, the
	 *	AKA-Notification is returns contains no
	 *	attributes.
	 */
	if (data_len < 3) {
		fr_strerror_printf("Packet data too small, expected at least 3 bytes got %zu bytes", data_len);
		return -1;
	}
	p += 3;

	/*
	 *	Loop over all the attributes decoding
	 *	them into the appropriate attributes
	 *	in the SIM/AKA/AKA' dict.
	 */
	while (p < end) {
		ret = fr_aka_sim_decode_pair(request->packet, decoded, dict, p, end - p, decoder_ctx);
		if (ret <= 0) {
			RPEDEBUG("Failed decoding AT");
		error:
			fr_cursor_free_list(decoded);	/* Free any attributes we added */
			return -1;
		}

		p += ret;
		fr_assert(p <= end);
	}

	/*
	 *	No point in doing packet_ctx until we known the rest
	 *	of the data is OK!
	 */
	{
		fr_pair_t *vp;

		vp = fr_pair_afrom_child_num(request->packet, fr_dict_root(dict), FR_SUBTYPE);
		if (!vp) {
			fr_strerror_printf("Failed allocating subtype attribute");
			goto error;
		}
		vp->vp_uint32 = data[0];
		fr_cursor_append(decoded, vp);
	}

	return 0;
}

static int _test_ctx_free(UNUSED fr_aka_sim_decode_ctx_t *ctx)
{
	fr_aka_sim_free();

	return 0;
}

static fr_aka_sim_decode_ctx_t *test_ctx_init(TALLOC_CTX *ctx, uint8_t const *k_encr, size_t k_encr_len)
{
	fr_aka_sim_decode_ctx_t	*test_ctx;
	fr_aka_sim_keys_t		*keys;

	if (fr_aka_sim_init() < 0) return NULL;

	test_ctx = talloc_zero(ctx, fr_aka_sim_decode_ctx_t);
	test_ctx->keys = keys = talloc_zero(test_ctx, fr_aka_sim_keys_t);
	memcpy(keys->k_encr, k_encr, k_encr_len);
	talloc_set_destructor(test_ctx, _test_ctx_free);

	return test_ctx;
}
/*
 *	Test ctx data
 */
static int decode_test_ctx_sim(void **out, TALLOC_CTX *ctx)
{
	fr_aka_sim_decode_ctx_t	*test_ctx;
	static uint8_t		k_encr[] = { 0x00, 0x01, 0x02, 0x03, 0x04 ,0x05, 0x06, 0x07,
					     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	test_ctx = test_ctx_init(ctx, k_encr, sizeof(k_encr));
	if (!test_ctx) return -1;

	test_ctx->have_iv = true;	/* Ensures IV is all zeros */

	*out = test_ctx;

	return 0;
}


static int decode_test_ctx_aka(void **out, TALLOC_CTX *ctx)
{
	fr_aka_sim_decode_ctx_t *test_ctx;
	static uint8_t		k_encr[] = { 0x00, 0x01, 0x02, 0x03, 0x04 ,0x05, 0x06, 0x07,
					     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

	test_ctx = test_ctx_init(ctx, k_encr, sizeof(k_encr));
	if (!test_ctx) return -1;

	test_ctx->have_iv = true;	/* Ensures IV is all zeros */

	*out = test_ctx;

	return 0;
}

static int decode_test_ctx_sim_rfc4186(void **out, TALLOC_CTX *ctx)
{
	fr_aka_sim_decode_ctx_t *test_ctx;
	static uint8_t		k_encr[] = { 0x53, 0x6e, 0x5e, 0xbc, 0x44 ,0x65, 0x58, 0x2a,
					     0xa6, 0xa8, 0xec, 0x99, 0x86, 0xeb, 0xb6, 0x20 };

	test_ctx = test_ctx_init(ctx, k_encr, sizeof(k_encr));
	if (!test_ctx) return -1;

	*out = test_ctx;

	return 0;
}

/*
 *	Test points
 */
extern fr_test_point_pair_decode_t sim_tp_decode;
fr_test_point_pair_decode_t sim_tp_decode = {
	.test_ctx	= decode_test_ctx_sim,
	.func		= fr_aka_sim_decode_pair
};

extern fr_test_point_pair_decode_t sim_tp_decode_rfc4186;
fr_test_point_pair_decode_t sim_tp_decode_rfc4186 = {
	.test_ctx	= decode_test_ctx_sim_rfc4186,
	.func		= fr_aka_sim_decode_pair
};

extern fr_test_point_pair_decode_t aka_tp_decode;
fr_test_point_pair_decode_t aka_tp_decode = {
	.test_ctx	= decode_test_ctx_aka,
	.func		= fr_aka_sim_decode_pair
};
