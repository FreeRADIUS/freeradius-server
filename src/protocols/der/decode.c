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
 * @file protocols/der/decode.c
 * @brief Functions to decode DER encoded data.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @author Ethan Thompson (ethan.thompson@inkbridge.io)
 *
 * @copyright 2025 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2025 Inkbridge Networks SAS.
 */

#include <freeradius-devel/build.h>
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/decode.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/dict_ext.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/value.h>
#include <stdint.h>
#include "der.h"

typedef struct {
	uint8_t *tmp_ctx;
	bool	 oid_value_pairs;
} fr_der_decode_ctx_t;

#define IS_DER_TAG_CONTINUATION(_tag) (((_tag) & DER_TAG_CONTINUATION) == DER_TAG_CONTINUATION)
#define IS_DER_TAG_CONSTRUCTED(_tag) (((_tag) & 0x20) == 0x20)
#define IS_DER_LEN_MULTI_BYTE(_len) (((_len) & DER_LEN_MULTI_BYTE) == DER_LEN_MULTI_BYTE)

typedef ssize_t (*fr_der_decode_oid_t)(uint64_t subidentifier, void *uctx, bool is_last);

static ssize_t fr_der_decode_oid(fr_pair_list_t *out, fr_dbuff_t *in, fr_der_decode_oid_t func, void *uctx) CC_HINT(nonnull(2,3,4));

static ssize_t fr_der_decode_oid_value_pair(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dbuff_t *in,
					    fr_dict_attr_t const *parent, fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_hdr(fr_dict_attr_t const *parent, fr_dbuff_t *in, uint64_t *tag, size_t *len) CC_HINT(nonnull(2,3,4));

typedef ssize_t (*fr_der_decode_t)(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				   fr_der_decode_ctx_t *decode_ctx);

typedef struct {
	fr_der_tag_constructed_t constructed;
	fr_der_decode_t		 decode;
} fr_der_tag_decode_t;

/** Function signature for DER decode functions
 *
 * @param[in] ctx		Allocation context
 * @param[in] out		Where to store the decoded pairs.
 * @param[in] parent		Parent attribute.  This should be the root of the dictionary
 *				we're using to decode DER data initially, and then nested children.
 * @param[in] in		The DER encoded data.
 * @param[in] decode_ctx	Any decode specific data.
 * @return
 *	- > 0 on success.  How many bytes were decoded.
 *	- 0 no bytes decoded.
 *	- < 0 on error.  May be the offset (as a negative value) where the error occurred.
 */
static ssize_t fr_der_decode_pair_dbuff(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_boolean(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				     fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_integer(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				     fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_bitstring(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				       fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_octetstring(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					 fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_null(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				  fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_enumerated(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_utf8_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					 fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_sequence(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_set(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				 fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_printable_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_t61_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_ia5_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_utc_time(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_generalized_time(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_visible_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					    fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_general_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					    fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_decode_universal_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

static fr_der_tag_decode_t tag_funcs[] = {
	[FR_DER_TAG_BOOLEAN]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .decode = fr_der_decode_boolean },
	[FR_DER_TAG_INTEGER]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .decode = fr_der_decode_integer },
	[FR_DER_TAG_BITSTRING]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .decode = fr_der_decode_bitstring },
	[FR_DER_TAG_OCTETSTRING]      = { .constructed = FR_DER_TAG_PRIMITIVE, .decode = fr_der_decode_octetstring },
	[FR_DER_TAG_NULL]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .decode = fr_der_decode_null },
	[FR_DER_TAG_ENUMERATED]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .decode = fr_der_decode_enumerated },
	[FR_DER_TAG_UTF8_STRING]      = { .constructed = FR_DER_TAG_PRIMITIVE, .decode = fr_der_decode_utf8_string },
	[FR_DER_TAG_SEQUENCE]	      = { .constructed = FR_DER_TAG_CONSTRUCTED, .decode = fr_der_decode_sequence },
	[FR_DER_TAG_SET]	      = { .constructed = FR_DER_TAG_CONSTRUCTED, .decode = fr_der_decode_set },
	[FR_DER_TAG_PRINTABLE_STRING] = { .constructed = FR_DER_TAG_PRIMITIVE,
					  .decode      = fr_der_decode_printable_string },
	[FR_DER_TAG_T61_STRING]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .decode = fr_der_decode_t61_string },
	[FR_DER_TAG_IA5_STRING]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .decode = fr_der_decode_ia5_string },
	[FR_DER_TAG_UTC_TIME]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .decode = fr_der_decode_utc_time },
	[FR_DER_TAG_GENERALIZED_TIME] = { .constructed = FR_DER_TAG_PRIMITIVE,
					  .decode      = fr_der_decode_generalized_time },
	[FR_DER_TAG_VISIBLE_STRING]   = { .constructed = FR_DER_TAG_PRIMITIVE, .decode = fr_der_decode_visible_string },
	[FR_DER_TAG_GENERAL_STRING]   = { .constructed = FR_DER_TAG_PRIMITIVE, .decode = fr_der_decode_general_string },
	[FR_DER_TAG_UNIVERSAL_STRING] = { .constructed = FR_DER_TAG_PRIMITIVE,
					  .decode      = fr_der_decode_universal_string },

	[UINT8_MAX] = { .constructed = FR_DER_TAG_PRIMITIVE, .decode = NULL },
};

static ssize_t fr_der_decode_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				    bool const allowed_chars[], fr_der_decode_ctx_t *decode_ctx) CC_HINT(nonnull(1,2,3,4,6));

static ssize_t fr_der_decode_boolean(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				     UNUSED fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	uint8_t	   val = 0;

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_bool(parent->type)) {
		fr_strerror_printf("Boolean found in non-boolean attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	/*
	 * 	ISO/IEC 8825-1:2021
	 * 	8.2 Encoding of a boolean value
	 * 	8.2.1 The encoding of a boolean value shall be primitive.
	 *       	The contents octets shall consist of a single octet.
	 * 	8.2.2 If the boolean value is:
	 *       	FALSE the octet shall be zero [0x00].
	 *       	If the boolean value is TRUE the octet shall have any non-zero value, as a sender's option.
	 *
	 * 	11.1 Boolean values
	 * 		If the encoding represents the boolean value TRUE, its single contents octet shall have all
	 *		eight bits set to one [0xFF]. (Contrast with 8.2.2.)
	 */
	if (len != 1) {
		fr_strerror_printf("Boolean has incorrect length (%" PRIuPTR "). Must be 1.", len);
		return -1;
	}

	if (unlikely(fr_dbuff_out(&val, &our_in) < 0)) {
		fr_strerror_const("Insufficient data for boolean");
		return -1;
	}

	if (unlikely((val != DER_BOOLEAN_FALSE) && (val != DER_BOOLEAN_TRUE))) {
		fr_strerror_printf("Boolean is not correctly DER encoded (0x%02" PRIx32 " or 0x%02" PRIx32 ").", DER_BOOLEAN_FALSE,
				   DER_BOOLEAN_TRUE);
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory");
		return -1;
	}

	vp->vp_bool = val > 0;

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_integer(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				     UNUSED fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	uint64_t   val	  = 0;
	uint8_t	   sign	  = 0;
	size_t	   i;

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_integer_except_bool(parent->type)) {
		fr_strerror_printf("Integer found in non-integer attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	if (len > sizeof(val)) {
		fr_strerror_printf("Integer too large (%" PRIuPTR ")", len);
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.3 Encoding of an integer value
	 *	8.3.1 The encoding of an integer value shall be primitive.
	 *	      The contents octets shall consist of one or more octets.
	 *	8.3.2 If the contents octets of an integer value encoding consist of more than one octet,
	 *	      then the bits of the first octet and bit 8 of the second octet:
	 *	      a) shall not all be ones; and
	 *	      b) shall not all be zero.
	 *	      NOTE – These rules ensure that an integer value is always encoded in the smallest possible number
	 *	      of octets. 8.3.3 The contents octets shall be a two's complement binary number equal to the
	 *	      integer value, and consisting of bits 8 to 1 of the first octet, followed by bits 8 to 1 of the
	 *	      second octet, followed by bits 8 to 1 of each octet in turn up to and including the last octet of
	 *	      the contents octets.
	 */
	if (unlikely(fr_dbuff_out(&sign, &our_in) < 0)) {
		fr_strerror_const("Insufficient data for integer. Missing first byte");
		return -1;
	}

	if (sign & 0x80) {
		/*
		 *	If the sign bit is set, this is a negative number.
		 *	This will fill the upper bits with 1s.
		 *	This is important for the case where the length of the integer is less than the length of the
		 *	integer type.
		 */
		val = UINT64_MAX;
	}

	val = (val << 8) | sign;

	if (len > 1) {
		/*
		 *	If the length of the integer is greater than 1, we need to check that the first 9 bits:
		 *	1. are not all 0s; and
		 *	2. are not all 1s
		 *	These two conditions are necessary to ensure that the integer conforms to DER.
		 */
		uint8_t byte;
		if (unlikely(fr_dbuff_out(&byte, &our_in) < 0)) {
			fr_strerror_const("Insufficient data for integer. Missing second byte");
			return -1;
		}

		if ((((val & 0xFF) == 0xFF) && (byte & 0x80)) || (((~val & 0xFF) == 0xFF) && !(byte & 0x80))) {
			fr_strerror_const(
				"Integer is not correctly DER encoded. First two bytes are all 0s or all 1s.");
			return -1;
		}

		val = (val << 8) | byte;
	}

	for (i = 2; i < len; i++) {
		uint8_t byte;

		if (unlikely(fr_dbuff_out(&byte, &our_in) < 0)) {
			fr_strerror_const("Insufficient data for integer. Ran out of bytes");
			return -1;
		}

		val = (val << 8) | byte;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory");
		return -1;
	}

	vp->vp_int64 = val;

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_bitstring(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				       fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in      = FR_DBUFF(in);
	uint8_t	   unused_bits = 0;
	uint8_t	  *data;

	ssize_t data_len = 0, index = 0;
	size_t	len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_octets(parent->type) && !fr_type_is_struct(parent->type)) {
		fr_strerror_printf("Bitstring found in non-octets attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	/*
	 *	Now we know that the parent is an octets attribute, we can decode the bitstring
	 */

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.6 Encoding of a bitstring value
	 *		8.6.1 The encoding of a bitstring value shall be either primitive or constructed at the option
	 *		      of the sender.
	 *			NOTE – Where it is necessary to transfer part of a bit string before the entire
	 *			       bitstring is available, the constructed encoding is used.
	 *		8.6.2 The contents octets for the primitive encoding shall contain an initial octet followed
	 *		      by zero, one or more subsequent octets.
	 *			8.6.2.1 The bits in the bitstring value, commencing with the leading bit and proceeding
	 *				to the trailing bit, shall be placed in bits 8 to 1 of the first subsequent
	 *				octet, followed by bits 8 to 1 of the second subsequent octet, followed by bits
	 *				8 to 1 of each octet in turn, followed by as many bits as are needed of the
	 *				final subsequent octet, commencing with bit 8.
	 *				NOTE – The terms "leading bit" and "trailing bit" are defined in
	 *				       Rec. ITU-T X.680 | ISO/IEC 8824-1, 22.2.
	 *			8.6.2.2 The initial octet shall encode, as an unsigned binary integer with bit 1 as the
	 *				least significant bit, the number of unused bits in the final subsequent octet.
	 *				The number shall be in the range zero to seven.
	 *			8.6.2.3 If the bitstring is empty, there shall be no subsequent octets, and the initial
	 *				octet shall be zero.
	 *
	 *	10.2 String encoding forms
	 *		For bitstring, octetstring and restricted character string types, the constructed form of
	 *		encoding shall not be used. (Contrast with 8.23.6.)
	 *
	 *	11.2 Unused bits 11.2.1 Each unused bit in the final octet of the encoding of a bit string value shall
	 *	     be set to zero.
	 */

	if (unlikely(fr_dbuff_out(&unused_bits, &our_in) < 0)) {
		fr_strerror_const("Insufficient data for bitstring");
		return -1;
	}

	if (unlikely(unused_bits > 7)) {
		/*
		 *	This means an entire byte is unused bits. Which is not allowed.
		 */
		fr_strerror_const("Invalid number of unused bits in bitstring");
		return -1;
	}

	if (len == 1 && unused_bits) {
		fr_strerror_const("Insufficient data for bitstring. Missing data bytes");
		return -1;
	}

	if (fr_type_is_struct(parent->type)) {
		/*
		 *	If the parent is a struct attribute, we will not be adding the unused bits count to the first
		 *	byte
		 */
		data_len = len - 1;
	} else {
		data_len = len;
	}

	data = talloc_array(ctx, uint8_t, data_len);
	if (unlikely(data == NULL)) {
		fr_strerror_const("Out of memory");
		return -1;
	}

	if (fr_type_is_octets(parent->type)) {
		/*
		 *	If the parent is an octets attribute, we need to add the unused bits count to the first byte
		 */
		index	= 1;
		data[0] = unused_bits;
	}

	for (; index < data_len; index++) {
		uint8_t byte;

		if (unlikely(fr_dbuff_out(&byte, &our_in) < 0)) {
			fr_strerror_const("Insufficient data for bitstring. Ran out of bytes");
		error:
			talloc_free(data);
			return -1;
		}

		data[index] = byte;
	}

	/*
	 *	Remove the unused bits from the last byte
	 */
	if (unused_bits) {
		uint8_t mask = 0xff << unused_bits;

		data[data_len - 1] &= mask;
	}

	if (fr_type_is_struct(parent->type)) {
		ssize_t slen;

		slen = fr_struct_from_network(ctx, out, parent, data, data_len, decode_ctx, NULL, NULL);

		/*
		 *	If the structure decoder didn't consume all the data, we need to free the data and bail out
		 */
		if (unlikely(slen < data_len - 1)) {
			fr_strerror_printf(
				"Bitstring structure decoder didn't consume all data. Consumed %" PRIuPTR " of %" PRIuPTR " bytes", slen,
				data_len);
			goto error;
		}

		return fr_dbuff_set(in, &our_in);
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory");
		goto error;
	}

	/*
	 *	Add the bitstring to the pair value as octets
	 */
	fr_pair_value_memdup(vp, data, len, false);

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_octetstring(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					 fr_dbuff_t *in, UNUSED fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	uint8_t	  *data	  = NULL;

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_octets(parent->type)) {
		fr_strerror_printf("Octetstring found in non-octets attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.7 Encoding of an octetstring value
	 *		8.7.1 The encoding of an octetstring value shall be either primitive or constructed at the
	 *		      option of the sender.
	 *			NOTE – Where it is necessary to transfer part of an octet string before the entire
	 *			       octetstring is available, the constructed encoding is used.
	 *		8.7.2 The primitive encoding contains zero, one or more contents octets equal in value to the
	 *		      octets in the data value, in the order they appear in the data value, and with the most
	 *		      significant bit of an octet of the data value aligned with the most significant bit of an
	 *		      octet of the contents octets.
	 *		8.7.3 The contents octets for the constructed encoding shall consist of zero, one, or more
	 *		      encodings.
	 *			NOTE – Each such encoding includes identifier, length, and contents octets, and may
	 *			       include end-of-contents octets if it is constructed.
	 *			8.7.3.1 To encode an octetstring value in this way, it is segmented. Each segment shall
	 *			       consist of a series of consecutive octets of the value. There shall be no
	 *			       significance placed on the segment boundaries.
	 *				NOTE – A segment may be of size zero, i.e. contain no octets.
	 *
	 *	10.2 String encoding forms
	 *		For bitstring, octetstring and restricted character string types, the constructed form of
	 *		encoding shall not be used. (Contrast with 8.23.6.)
	 */

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
	oom:
		fr_strerror_const("Out of memory");
		return -1;
	}

	if (unlikely(fr_pair_value_mem_alloc(vp, &data, len, false) < 0)) {
		talloc_free(vp);
		goto oom;
	}

	fr_dbuff_out_memcpy(data, &our_in, len);

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_null(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				  UNUSED fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);

	if (fr_dbuff_remaining(&our_in) != 0) {
		fr_strerror_const("Null has non-zero length");
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.8 Encoding of a null value 8.8.1 The encoding of a null value shall be primitive. 8.8.2 The contents
	 *	    octets shall not contain any octets. NOTE – The length octet is zero.
	 */

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory");
		return -1;
	}

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

typedef struct {
	TALLOC_CTX	     *ctx; 		//!< Allocation context
	fr_dict_attr_t const *parent_da;	//!< Parent dictionary attribute
	fr_pair_list_t	     *parent_list; 	//!< Parent pair list
	char		      oid_buff[1024]; 	//!< Buffer to store the OID string
	fr_sbuff_marker_t     marker; 		//!< Marker of the current position in the OID buffer
} fr_der_decode_oid_to_str_ctx_t; 		//!< Context for decoding an OID to a string

/** Decode an OID to a string
 *
 * @param[in] subidentifier	The subidentifier to decode
 * @param[in] uctx		User context
 * @param[in] is_last		Is this the last subidentifier in the OID
 * @return
 *	- 1 on success
 *	- < 0 on error
 */
static ssize_t fr_der_decode_oid_to_str(uint64_t subidentifier, void *uctx, bool is_last)
{
	fr_der_decode_oid_to_str_ctx_t *decode_ctx = uctx;
	fr_sbuff_marker_t		marker	   = decode_ctx->marker;
	fr_sbuff_t			sb	   = FR_SBUFF_OUT(decode_ctx->oid_buff, sizeof(decode_ctx->oid_buff));

	FR_PROTO_TRACE("Decoding OID to string");
	if (decode_ctx->oid_buff[0] == '\0') {
		/*
		 *	First subidentifier
		 */
		if (unlikely(fr_sbuff_in_sprintf(&sb, "%" PRIu64, subidentifier) < 0)) {
		oom:
			fr_strerror_const("Out of memory");
			return -1;
		}

		fr_sbuff_marker(&marker, &sb);

		decode_ctx->marker = marker;
		return 1;
	}

	fr_sbuff_set(&sb, &marker);

	fr_sbuff_in_sprintf(&sb, ".%" PRIu64, subidentifier);
	fr_sbuff_marker(&marker, &sb);

	decode_ctx->marker = marker;

	if (is_last) {
		/*
		 *	If this is the last subidentifier, we need to terminate the string,
		 * 	create a vp with the oid string, and add it to the parent list
		 */
		fr_pair_t *vp;

		vp = fr_pair_afrom_da(decode_ctx->ctx, decode_ctx->parent_da);
		if (unlikely(vp == NULL)) goto oom;

		if (unlikely(!fr_type_is_string(vp->da->type))) {
			fr_strerror_printf("OID found in non-string attribute %s of type %s", vp->da->name,
					   fr_type_to_str(vp->da->type));
			talloc_free(vp);
			return -1;
		}

		fr_sbuff_terminate(&sb);

		fr_pair_value_strdup(vp, decode_ctx->oid_buff, false);

		fr_pair_append(decode_ctx->parent_list, vp);

		decode_ctx->ctx = vp;
	}

	return 1;
}

typedef struct {
	TALLOC_CTX	     *ctx; 		//!< Allocation context
	fr_dict_attr_t const *parent_da; 	//!< Parent dictionary attribute
	fr_pair_list_t	     *parent_list; 	//!< Parent pair list
} fr_der_decode_oid_to_da_ctx_t; 		//!< Context for decoding an OID to a dictionary attribute

/** Decode an OID to a dictionary attribute
 *
 * @param[in] subidentifier	The subidentifier to decode
 * @param[in] uctx		User context
 * @param[in] is_last		Is this the last subidentifier in the OID
 * @return
 *	- 1 on success
 *	- < 0 on error
 */
static ssize_t fr_der_decode_oid_to_da(uint64_t subidentifier, void *uctx, bool is_last)
{
	fr_der_decode_oid_to_da_ctx_t *decode_ctx = uctx;
	fr_pair_t		      *vp;
	fr_dict_attr_t const	      *da;

	fr_dict_attr_t const *parent_da = fr_type_is_group(decode_ctx->parent_da->type) ?
						  fr_dict_attr_ref(decode_ctx->parent_da) :
						  decode_ctx->parent_da;

	FR_PROTO_TRACE("Decoding OID to dictionary attribute");
	FR_PROTO_TRACE("decode context - Parent Name: %s Sub-Identifier %" PRIu64, parent_da->name, subidentifier);
	FR_PROTO_TRACE("decode context - Parent Address: %p", parent_da);

	da = fr_dict_attr_child_by_num(parent_da, subidentifier);

	if (is_last) {
		if (unlikely(da == NULL)) {
			decode_ctx->parent_da = fr_dict_attr_unknown_typed_afrom_num(decode_ctx->ctx, parent_da,
										     subidentifier, FR_TYPE_OCTETS);

			if (unlikely(decode_ctx->parent_da == NULL)) {
				return -1;
			}

			FR_PROTO_TRACE("Created DA: ", decode_ctx->parent_da->name);
			return 1;
		}

		decode_ctx->parent_da = da;

		FR_PROTO_TRACE("Created DA: ", decode_ctx->parent_da->name);
		return 1;
	}

	if (unlikely(da == NULL)) {
		/*
		 *	We need to create an unknown attribute for this subidentifier so we can store the raw data
		 */
		fr_dict_attr_t *unknown_da =
			fr_dict_attr_unknown_typed_afrom_num(decode_ctx->ctx, parent_da, subidentifier, FR_TYPE_TLV);

		if (unlikely(unknown_da == NULL)) {
		oom:
			fr_strerror_const("Out of memory");
			return -1;
		}

		vp = fr_pair_afrom_da(decode_ctx->ctx, unknown_da);

		talloc_free(unknown_da);
	} else {
		vp = fr_pair_afrom_da(decode_ctx->ctx, da);
	}

	if (unlikely(vp == NULL)) goto oom;

	fr_pair_append(decode_ctx->parent_list, vp);

	decode_ctx->ctx		= vp;
	decode_ctx->parent_da	= vp->da;
	decode_ctx->parent_list = &vp->vp_group;

	FR_PROTO_TRACE("Created DA: ", decode_ctx->parent_da->name);
	return 1;
}

/** Decode an OID from a DER encoded buffer using a callback
 *
 * @param[in] out		The pair list to add the OID to.
 * @param[in] in		The DER encoded data.
 * @param[in] func		The callback function to call for each subidentifier.
 * @param[in] uctx		User context for the callback function.
 * @return
 *	- 0 on success
 *	- < 0 on error
 */
static ssize_t fr_der_decode_oid(UNUSED fr_pair_list_t *out, fr_dbuff_t *in, fr_der_decode_oid_t func, void *uctx)
{
	fr_dbuff_t our_in  = FR_DBUFF(in);
	uint64_t   oid_a   = 0;
	uint64_t   oid_b   = 0;
	bool	   is_last = false;

	size_t index = 1, magnitude = 1;
	size_t len = fr_dbuff_remaining(&our_in);

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.19 Encoding of an object identifier value
	 *	8.19.1 The encoding of an object identifier value shall be primitive.
	 *	8.19.2 The contents octets shall be an (ordered) list of encodings of subidentifiers (see 8.19.3
	 *	       and 8.19.4) concatenated together. Each subidentifier is represented as a series of
	 *	       (one or more) octets. Bit 8 of each octet indicates whether it is the last in the series: bit 8
	 *	       of the last octet is zero; bit 8 of each preceding octet is one. Bits 7 to 1 of the octets in
	 *	       the series collectively encode the subidentifier. Conceptually, these groups of bits are
	 *	       concatenated to form an unsigned binary number whose most significant bit is bit 7 of the first
	 *	       octet and whose least significant bit is bit 1 of the last octet. The subidentifier shall be
	 *	       encoded in the fewest possible octets, that is, the leading octet of the subidentifier shall not
	 *	       have the value 8016.
	 *	8.19.3 The number of subidentifiers (N) shall be one less than the number of object identifier
	 *		components in the object identifier value being encoded. 8.19.4 The numerical value of the
	 *		first subidentifier is derived from the values of the first two object identifier components in
	 *		the object identifier value being encoded, using the formula: (X*40) + Y where X is the value
	 *		of the first object identifier component and Y is the value of the second object identifier
	 *		component. NOTE – This packing of the first two object identifier components recognizes that
	 *		only three values are allocated from the root node, and at most 39 subsequent values from nodes
	 *		reached by X = 0 and X = 1. 8.19.5 The numerical value of the ith subidentifier, (2 ≤ i ≤ N) is
	 *		that of the (i + 1)th object identifier component.
	 */

	FR_PROTO_TRACE("Decoding OID");
	FR_PROTO_HEX_DUMP(fr_dbuff_current(&our_in), len, "buff in OID");
	/*
	 *	The first subidentifier is the encoding of the first two object identifier components, encoded as:
	 *		(X * 40) + Y
	 *	where X is the first number and Y is the second number.
	 *	The first number is 0, 1, or 2.
	 */
	for (; index < len; index++) {
		uint8_t byte;

		if (unlikely(fr_dbuff_out(&byte, &our_in) < 0)) {
			fr_strerror_const("Insufficient data for OID subidentifier");
			return -1;
		}

		oid_b = (oid_b << 7) | (byte & 0x7f);

		if (!(byte & 0x80)) {
			/*
			 *	If the high bit is not set, this is the last byte of the subidentifier
			 */
			if (oid_b < 40) {
				oid_a = 0;
			} else if (oid_b < 80) {
				oid_a = 1;
				oid_b = oid_b - 40;
			} else {
				oid_a = 2;
				oid_b = oid_b - 80;
			}

			magnitude = 1;
			break;
		}

		magnitude++;

		/*
		 *	We need to check that the subidentifier is not too large
		 *	Since the subidentifier is encoded using 7-bit "chunks", we can't have a subidentifier larger
		 *	than 9 chunks
		 */
		if (unlikely(magnitude > 9)) {
			fr_strerror_const("OID subidentifier too large (9 chunks)");
			return -1;
		}
	}

	FR_PROTO_TRACE("decode context - OID A: %" PRIu64, oid_a);
	FR_PROTO_TRACE("decode context - OID B: %" PRIu64, oid_b);

	if (unlikely(func(oid_a, uctx, is_last) < 0)) return -1;

	if (index == len) is_last = true;

	if (unlikely(func(oid_b, uctx, is_last) < 0)) return -1;

	/*
	 *	The remaining subidentifiers are encoded individually
	 */
	oid_b = 0;
	for (; index < len; index++) {
		uint8_t byte;

		if (unlikely(fr_dbuff_out(&byte, &our_in) < 0)) {
			fr_strerror_const("Insufficient data for remaining OID subidentifier(s)");
			return -1;
		}

		oid_b = (oid_b << 7) | (byte & 0x7f);

		if (!(byte & 0x80)) {
			if (index == len - 1) is_last = true;

			if (unlikely(func(oid_b, uctx, is_last) < 0)) return -1;

			oid_b	  = 0;
			magnitude = 1;
			continue;
		}

		magnitude++;

		/*
		 *	We need to check that the subidentifier is not too large
		 *	Since the subidentifier is encoded using 7-bit "chunks", we can't have a subidentifier larger
		 *	than 9 chunks
		 */
		if (unlikely(magnitude > 9)) {
			fr_strerror_const("OID subidentifier too large (9 chunks)");
			return -1;
		}
	}

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_enumerated(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					fr_dbuff_t *in, UNUSED fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	uint64_t   val	  = 0;
	uint8_t	   sign	  = 0;
	size_t	   i;

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_integer_except_bool(parent->type)) {
		fr_strerror_printf("Enumerated value found in non-integer attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	if (len > sizeof(val)) {
		fr_strerror_printf("Enumerated value too large (%"  PRIuPTR ")", len);
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.4 Encoding of an enumerated value
	 *		The encoding of an enumerated value shall be that of the integer value with which it is
	 *		associated.
	 *			NOTE – It is primitive.
	 */
	if (unlikely(fr_dbuff_out(&sign, &our_in) < 0)) {
		fr_strerror_const("Insufficient data for enumerated value. Missing first byte");
		return -1;
	}

	if (sign & 0x80) {
		/*
		 *	If the sign bit is set, this is a negative number.
		 *	This will fill the upper bits with 1s.
		 *	This is important for the case where the length of the integer is less than the length of the
		 *	integer type.
		 */
		val = UINT64_MAX;
	}

	val = (val << 8) | sign;

	if (len > 1) {
		/*
		 *	If the length of the integer is greater than 1, we need to check that the first 9 bits:
		 *	1. are not all 0s; and
		 *	2. are not all 1s
		 *	These two conditions are necessary to ensure that the integer conforms to DER.
		 */
		uint8_t byte;
		if (unlikely(fr_dbuff_out(&byte, &our_in) < 0)) {
			fr_strerror_const("Insufficient data for enumerated value. Missing second byte");
			return -1;
		}

		if ((((val & 0xFF) == 0xFF) && (byte & 0x80)) || (((~val & 0xFF) == 0xFF) && !(byte & 0x80))) {
			fr_strerror_const("Enumerated value is not correctly DER encoded");
			return -1;
		}

		val = (val << 8) | byte;
	}

	for (i = 2; i < len; i++) {
		uint8_t byte;

		if (unlikely(fr_dbuff_out(&byte, &our_in) < 0)) {
			fr_strerror_const("Insufficient data for enumerated value. Ran out of bytes");
			return -1;
		}

		val = (val << 8) | byte;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory");
		return -1;
	}

	vp->vp_int64 = val;

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_utf8_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					 fr_dbuff_t *in, UNUSED fr_der_decode_ctx_t *decode_ctx)
{
	return fr_der_decode_string(ctx, out, parent, in, NULL, decode_ctx);
}

static ssize_t fr_der_decode_sequence(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				      fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t	     *vp;
	fr_dict_attr_t const *child  = NULL;
	fr_dbuff_t	      our_in = FR_DBUFF(in);

	if (!fr_type_is_struct(parent->type) && !fr_type_is_tlv(parent->type) && !fr_type_is_group(parent->type)) {
		fr_strerror_printf("Sequence found in incompatible attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.9 Encoding of a sequence value
	 *		8.9.1 The encoding of a sequence value shall be constructed.
	 *		8.9.2 The contents octets shall consist of the complete encoding of one data value from each of
	 *		      the types listed in the ASN.1 definition of the sequence type, in the order of their
	 *		      appearance in the definition, unless the type was referenced with the keyword OPTIONAL
	 *		      or the keyword DEFAULT.
	 *		8.9.3 The encoding of a data value may, but need not, be present for a type referenced with the
	 *		      keyword OPTIONAL or the keyword DEFAULT. If present, it shall appear in the order of
	 *		      appearance of the corresponding type in the ASN.1 definition.
	 *
	 *	11.5 Set and sequence components with default value
	 *		The encoding of a set value or sequence value shall not include an encoding for any component
	 *		value which is equal to its default value.
	 */

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory");
		return -1;
	}

	if (unlikely(fr_der_flag_is_pair(parent))) {
		/*
		 *	This sequence contains an oid value pair
		 */
		if (unlikely(!fr_type_is_group(parent->type))) {
			fr_strerror_printf("Sequence with pair found in incompatible attribute %s of type %s",
					   parent->name, fr_type_to_str(parent->type));
			talloc_free(vp);
			return -1;
		}

		if (unlikely(fr_der_decode_oid_value_pair(vp, &vp->vp_group, &our_in, vp->da, decode_ctx) < 0)) {
			talloc_free(vp);
			return -1;
		}

		fr_pair_append(out, vp);

		return fr_dbuff_set(in, &our_in);
	}

	if (unlikely(fr_der_flag_is_pairs(parent) || decode_ctx->oid_value_pairs)) {
		/*
		 *	This sequence contains sequences/sets of pairs
		 */
		bool old		    = decode_ctx->oid_value_pairs;
		decode_ctx->oid_value_pairs = true;
		while (fr_dbuff_remaining(&our_in) > 0) {
			child = NULL;
			child = fr_dict_attr_iterate_children(parent, &child);

			FR_PROTO_TRACE("decode context %s -> %s", parent->name, child->name);

			if (unlikely(fr_der_decode_pair_dbuff(vp, &vp->vp_group, child, &our_in, decode_ctx) < 0)) {
				talloc_free(vp);
				return -1;
			}
		}

		decode_ctx->oid_value_pairs = old;

		fr_pair_append(out, vp);

		return fr_dbuff_set(in, &our_in);
	}

	if (unlikely(fr_der_flag_is_sequence_of(parent))) {
		/*
		 * 	This is a sequence-of, meaning there are restrictions on the types which can be present
		 */

		bool restriction_types[] = { [UINT8_MAX] = false };

		if (fr_der_flag_sequence_of(parent) != FR_DER_TAG_CHOICE) {
			restriction_types[fr_der_flag_sequence_of(parent)] = true;
		} else {
			/*
			 *	If it is a seuqnec of choices, then we must construct the list of restriction_types.
			 *	This will be a list of the number of choices, starting at 0.
			 */
			fr_dict_attr_t const *choices = NULL;
			if (unlikely(!fr_type_is_structural(parent->type))) {
				fr_strerror_printf("Sequence-of choice found in incompatible attribute %s of type %s",
						   parent->name, fr_type_to_str(parent->type));
				talloc_free(vp);
				return -1;
			}

			if (fr_type_is_group(parent->type)) {
				while ((choices = fr_dict_attr_iterate_children(fr_dict_attr_ref(parent), &choices))) {
					restriction_types[choices->attr] = true;
				}
			}
			else {
				while ((choices = fr_dict_attr_iterate_children(parent, &choices))) {
					restriction_types[choices->attr] = true;
				}
			}
		}

		while (fr_dbuff_remaining(&our_in) > 0) {
			ssize_t	 ret;
			uint8_t	 current_tag;
			uint8_t	 tag_byte;
			uint8_t *current_marker = fr_dbuff_current(&our_in);

			if (unlikely(fr_dbuff_out(&tag_byte, &our_in) < 0)) {
				fr_strerror_const("Insufficient data for sequence. Missing tag");
			error:
				talloc_free(vp);
				return -1;
			}

			current_tag = (tag_byte & DER_TAG_CONTINUATION);

			if (unlikely(!restriction_types[current_tag])) {
				fr_strerror_printf("Attribute %s is a sequence-of, but received tag %" PRIu32, parent->name,
						   current_tag);
				goto error;
			}

			if (unlikely(fr_der_flag_sequence_of(parent) == FR_DER_TAG_CHOICE)) {
				child = fr_dict_attr_child_by_num(parent, current_tag);
				if (unlikely(child == NULL)) {
					fr_strerror_printf(
						"Attribute %s is a sequence-of choice, but received unknown option %" PRIu32,
						parent->name, current_tag);
					goto error;
				}
			}
			else if (child == NULL) {
				child = fr_dict_attr_iterate_children(parent, &child);
			}

			FR_PROTO_TRACE("decode context %s -> %s", parent->name, child->name);

			fr_dbuff_set(&our_in, current_marker);

			ret = fr_der_decode_pair_dbuff(vp, &vp->vp_group, child, &our_in, decode_ctx);
			if (unlikely(ret < 0)) {
				goto error;
			}
		}

		fr_pair_append(out, vp);

		return fr_dbuff_set(in, &our_in);
	}

	while ((child = fr_dict_attr_iterate_children(parent, &child))) {
		ssize_t ret;

		FR_PROTO_TRACE("decode context %s -> %s", parent->name, child->name);

		ret = fr_der_decode_pair_dbuff(vp, &vp->vp_group, child, &our_in, decode_ctx);
		if (unlikely(ret < 0)) {
			talloc_free(vp);
			return ret;
		}
	}

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_set(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				 fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t	     *vp;
	fr_dict_attr_t const *child  = NULL;
	fr_dbuff_t	      our_in = FR_DBUFF(in);
	fr_dbuff_marker_t     previous_marker;
	uint8_t		      previous_tag = 0x00;
	size_t		      previous_len = 0;

	if (!fr_type_is_struct(parent->type) && !fr_type_is_tlv(parent->type) && !fr_type_is_group(parent->type)) {
		fr_strerror_printf("Set found in incompatible attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.11 Encoding of a set value
	 *		8.11.1 The encoding of a set value shall be constructed.
	 *		8.11.2 The contents octets shall consist of the complete encoding of one data value from each
	 *		       of the types listed in the ASN.1 definition of the set type, in an order chosen by the
	 *		       sender, unless the type was referenced with the keyword OPTIONAL or the keyword DEFAULT.
	 *		8.11.3 The encoding of a data value may, but need not, be present for a type referenced with the
	 *		       keyword OPTIONAL or the keyword DEFAULT.
	 *
	 *	11.5 Set and sequence components with default value
	 *		The encoding of a set value or sequence value shall not include an encoding for any component
	 *		value which is equal to its default value.
	 */

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory");
		return -1;
	}

	if (fr_der_flag_is_pair(parent)) {
		/*
		 *	This set contains an oid value pair
		 */
		if (unlikely(!fr_type_is_group(parent->type))) {
			fr_strerror_printf("Set with pair found in incompatible attribute %s of type %s", parent->name,
					   fr_type_to_str(parent->type));
			talloc_free(vp);
			return -1;
		}

		if (unlikely(fr_der_decode_oid_value_pair(vp, &vp->vp_group, &our_in, vp->da, decode_ctx) < 0)) {
			talloc_free(vp);
			return -1;
		}

		fr_pair_append(out, vp);

		return fr_dbuff_set(in, &our_in);
	}

	if (fr_der_flag_is_pairs(parent) || decode_ctx->oid_value_pairs) {
		/*
		 *	This set contains sequences/sets of pairs
		 */
		bool old		    = decode_ctx->oid_value_pairs;
		decode_ctx->oid_value_pairs = true;
		while (fr_dbuff_remaining(&our_in) > 0) {
			child = NULL;
			child = fr_dict_attr_iterate_children(parent, &child);

			FR_PROTO_TRACE("decode context %s -> %s", parent->name, child->name);

			if (unlikely(fr_der_decode_pair_dbuff(vp, &vp->vp_group, child, &our_in, decode_ctx) < 0)) {
				talloc_free(vp);
				return -1;
			}
		}

		decode_ctx->oid_value_pairs = old;

		fr_pair_append(out, vp);

		return fr_dbuff_set(in, &our_in);
	}

	if (fr_der_flag_is_set_of(parent)) {
		/*
		 * 	This is a set-of, meaning there are restrictions on the types which can be present
		 */
		fr_der_tag_num_t restriction_type = fr_der_flag_set_of(parent);

		// while ((child = fr_dict_attr_iterate_children(parent, &child))) {
		while (fr_dbuff_remaining(&our_in) > 0) {
			fr_dbuff_marker_t current_value_marker;
			ssize_t		  ret;
			uint64_t	  current_tag;
			uint8_t		 *current_marker = fr_dbuff_current(&our_in);
			size_t		  len;

			if (child == NULL) {
				child = fr_dict_attr_iterate_children(parent, &child);
			}

			FR_PROTO_TRACE("decode context %s -> %s", parent->name, child->name);

			if (unlikely(fr_der_decode_hdr(NULL, &our_in, &current_tag, &len) < 0)) {
				fr_strerror_const("Insufficient data for set. Missing tag");
				ret = -1;
			error:
				talloc_free(vp);
				return ret;
			}

			if (unlikely(current_tag != restriction_type)) {
				fr_strerror_printf("Attribute %s is a set-of type %" PRIu32 ", but found type %" PRIu64,
						   parent->name, restriction_type, current_tag);
				ret = -1;
				goto error;
			}

			fr_dbuff_marker(&current_value_marker, &our_in);

			if (previous_tag != 0x00) {
				uint8_t	   prev_char = 0, curr_char = 0;
				fr_dbuff_t previous_item = FR_DBUFF(&previous_marker);

				fr_dbuff_set_end(&previous_item, fr_dbuff_current(&previous_marker) + previous_len);

				do {
					if (unlikely(fr_dbuff_out(&prev_char, &previous_item) < 0)) {
						fr_strerror_const(
							"Insufficient data for set. Missing tag for previous marker");
						ret = -1;
						goto error;
					}

					if (unlikely(fr_dbuff_out(&curr_char, &our_in) < 0)) {
						fr_strerror_const(
							"Insufficient data for set. Missing tag for current marker");
						ret = -1;
						goto error;
					}

					if (prev_char > curr_char) {
						fr_strerror_const("Set tags are not in ascending order");
						ret = -1;
						goto error;
					}

				} while (fr_dbuff_remaining(&our_in) > 0 && fr_dbuff_remaining(&previous_item) > 0);

				if (fr_dbuff_remaining(&previous_item) > 0) {
					fr_strerror_const(
						"Set tags are not in ascending order. Previous item has more data");
					ret = -1;
					goto error;
				}
			}

			previous_tag = current_tag;
			previous_len = len;

			previous_marker = current_value_marker;

			fr_dbuff_set(&our_in, current_marker);

			ret = fr_der_decode_pair_dbuff(vp, &vp->vp_group, child, &our_in, decode_ctx);
			if (unlikely(ret < 0)) {
				goto error;
			}
		}

		fr_pair_append(out, vp);

		return fr_dbuff_set(in, &our_in);
	}

	while ((child = fr_dict_attr_iterate_children(parent, &child))) {
		ssize_t	 ret;
		uint8_t	 current_tag;
		uint8_t *current_marker = fr_dbuff_current(&our_in);

		FR_PROTO_TRACE("decode context %s -> %s", parent->name, child->name);

		/*
		 *	Check that the tag is in ascending order
		 */
		if (unlikely(fr_dbuff_out(&current_tag, &our_in) < 0)) {
			fr_strerror_const("Insufficient data for set. Missing tag");
			talloc_free(vp);
			return -1;
		}

		if (unlikely(current_tag < previous_tag)) {
			fr_strerror_const("Set tags are not in ascending order");
			talloc_free(vp);
			return -1;
		}

		previous_tag = current_tag;

		/*
		 *	Reset the buffer to the start of the tag
		 */
		fr_dbuff_set(&our_in, current_marker);

		ret = fr_der_decode_pair_dbuff(vp, &vp->vp_group, child, &our_in, decode_ctx);
		if (unlikely(ret < 0)) {
			talloc_free(vp);
			return ret;
		}
	}

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_printable_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					      fr_dbuff_t *in, UNUSED fr_der_decode_ctx_t *decode_ctx)
{
	static bool const allowed_chars[] = {
		[' '] = true, ['\''] = true, ['('] = true, [')'] = true,
		['+'] = true, [','] = true, ['-'] = true, ['.'] = true,
		['/'] = true, [':'] = true, ['='] = true, ['?'] = true,
		['A' ... 'Z'] = true, ['a' ... 'z'] = true,
		['0' ... '9'] = true, [UINT8_MAX] = false
	};

	return fr_der_decode_string(ctx, out, parent, in, allowed_chars, decode_ctx);
}

static ssize_t fr_der_decode_t61_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					fr_dbuff_t *in, UNUSED fr_der_decode_ctx_t *decode_ctx)
{
	static bool const allowed_chars[] = {
		[0x08] = true, [0x0A] = true, [0x0C] = true, [0x0D] = true,
		[0x0E] = true, [0x0F] = true, [0x19] = true, [0x1A] = true,
		[0x1B] = true, [0x1D] = true, [' '] = true, ['!'] = true,
		['"'] = true, ['%'] = true, ['&'] = true, ['\''] = true,
		['('] = true, [')'] = true, ['*'] = true, ['+'] = true,
		[','] = true, ['-'] = true, ['.'] = true, ['/'] = true,
		[':'] = true, [';'] = true, ['<'] = true, ['='] = true,
		['>'] = true, ['?'] = true, ['@'] = true, ['['] = true,
		[']'] = true, ['_'] = true, ['|'] = true, [0x7F] = true,
		[0x8B] = true, [0x8C] = true, [0x9B] = true, [0xA0] = true,
		[0xA1] = true, [0xA2] = true, [0xA3] = true, [0xA4] = true,
		[0xA5] = true, [0xA6] = true, [0xA7] = true, [0xA8] = true,
		[0xAB] = true, [0xB0] = true, [0xB1] = true, [0xB2] = true,
		[0xB3] = true, [0xB4] = true, [0xB5] = true, [0xB6] = true,
		[0xB7] = true, [0xB8] = true, [0xBB] = true, [0xBC] = true,
		[0xBD] = true, [0xBE] = true, [0xBF] = true, [0xC1] = true,
		[0xC2] = true, [0xC3] = true, [0xC4] = true, [0xC5] = true,
		[0xC6] = true, [0xC7] = true, [0xC8] = true, [0xC9] = true,
		[0xCA] = true, [0xCB] = true, [0xCC] = true, [0xCD] = true,
		[0xCE] = true, [0xCF] = true, [0xE0] = true, [0xE1] = true,
		[0xE2] = true, [0xE3] = true, [0xE4] = true, [0xE5] = true,
		[0xE7] = true, [0xE8] = true, [0xE9] = true, [0xEA] = true,
		[0xEB] = true, [0xEC] = true, [0xED] = true, [0xEE] = true,
		[0xEF] = true, [0xF0] = true, [0xF1] = true, [0xF2] = true,
		[0xF3] = true, [0xF4] = true, [0xF5] = true, [0xF6] = true,
		[0xF7] = true, [0xF8] = true, [0xF9] = true, [0xFA] = true,
		[0xFB] = true, [0xFC] = true, [0xFD] = true, [0xFE] = true,
		['A' ... 'Z'] = true, ['a' ... 'z'] = true,
		['0' ... '9'] = true, [UINT8_MAX] = false
	};

	return fr_der_decode_string(ctx, out, parent, in, allowed_chars, decode_ctx);
}
static ssize_t fr_der_decode_ia5_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					fr_dbuff_t *in, UNUSED fr_der_decode_ctx_t *decode_ctx)
{
	return fr_der_decode_string(ctx, out, parent, in, NULL, decode_ctx);
}

static ssize_t fr_der_decode_utc_time(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				      fr_dbuff_t *in, UNUSED fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	char	   timestr[DER_UTC_TIME_LEN + 1] = {};
	char	  *p;
	struct tm  tm = {};

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_date(parent->type)) {
		fr_strerror_printf("UTC time found in non-date attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	if (len != DER_UTC_TIME_LEN) {
		fr_strerror_const("Insufficient data for UTC time or incorrect length");
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.25 Encoding for values of the useful types
	 *		The following "useful types" shall be encoded as if they had been replaced by their definitions
	 *		given in clauses 46-48 of Rec. ITU-T X.680 | ISO/IEC 8824-1:
	 *			– generalized time;
	 *			– universal time;
	 *			– object descriptor.
	 *
	 *	8.26 Encoding for values of the TIME type and the useful time types
	 *		8.26 Encoding for values of the TIME type and the useful time types 8.26.1 Encoding for values
	 *		of the TIME type NOTE – The defined time types are subtypes of the TIME type, with the same
	 *		tag, and have the same encoding as the TIME type. 8.26.1.1 The encoding of the TIME type shall
	 *		be primitive. 8.26.1.2 The contents octets shall be the UTF-8 encoding of the value notation,
	 *		after the removal of initial and final QUOTATION MARK (34) characters.
	 *
	 *	11.8 UTCTime
	 *		11.8.1 The encoding shall terminate with "Z", as described in the ITU-T X.680 | ISO/IEC 8824-1
	 *		       clause on UTCTime.
	 *		11.8.2 The seconds element shall always be present.
	 *		11.8.3 Midnight (GMT) shall be represented as "YYMMDD000000Z", where "YYMMDD" represents the
	 *		       day following the midnight in question.
	 */

	/*
	 *	The format of a UTC time is "YYMMDDhhmmssZ"
	 *	Where:
	 *	1. YY is the year
	 *	2. MM is the month
	 *	3. DD is the day
	 *	4. hh is the hour
	 *	5. mm is the minute
	 *	6. ss is the second (not optional in DER)
	 *	7. Z is the timezone (UTC)
	 */

	if (fr_dbuff_out_memcpy((uint8_t *)timestr, &our_in, len) < 0) {
		fr_strerror_const("Insufficient data for UTC time. Missing data bytes");
		return -1;
	}

	if (memchr(timestr, '\0', len) != NULL) {
		fr_strerror_const("UTC time contains null byte");
		return -1;
	}

	timestr[len] = '\0';

	p = strptime(timestr, "%y%m%d%H%M%SZ", &tm);

	if (unlikely(p == NULL) || *p != '\0') {
		fr_strerror_const("Invalid UTC time format");
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory");
		return -1;
	}

	vp->vp_date = fr_unix_time_from_tm(&tm);

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_generalized_time(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					      fr_dbuff_t *in, UNUSED fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t    *vp;
	fr_dbuff_t    our_in = FR_DBUFF(in);
	char	      timestr[DER_GENERALIZED_TIME_LEN_MIN + 1] = {};
	char	     *p;
	unsigned long subseconds = 0;
	struct tm     tm	 = {};

	size_t len = fr_dbuff_remaining(&our_in);

	if (!fr_type_is_date(parent->type)) {
		fr_strerror_printf("Generalized time found in non-date attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	if (len < DER_GENERALIZED_TIME_LEN_MIN) {
		fr_strerror_const("Insufficient data for generalized time or incorrect length");
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.25 Encoding for values of the useful types
	 *		The following "useful types" shall be encoded as if they had been replaced by their definitions
	 *		given in clauses 46-48 of Rec. ITU-T X.680 | ISO/IEC 8824-1:
	 *			– generalized time;
	 *			– universal time;
	 *			– object descriptor.
	 *
	 *	8.26 Encoding for values of the TIME type and the useful time types
	 *		8.26 Encoding for values of the TIME type and the useful time types 8.26.1 Encoding for values
	 *		of the TIME type NOTE – The defined time types are subtypes of the TIME type, with the same
	 *		tag, and have the same encoding as the TIME type. 8.26.1.1 The encoding of the TIME type shall
	 *		be primitive. 8.26.1.2 The contents octets shall be the UTF-8 encoding of the value notation,
	 *		after the removal of initial and final QUOTATION MARK (34) characters.
	 *
	 *	11.7 GeneralizedTime
	 *		11.7.1 The encoding shall terminate with a "Z", as described in the Rec. ITU-T X.680 | ISO/IEC
	 *		       8824-1 clause on GeneralizedTime.
	 *		11.7.2 The seconds element shall always be present.
	 *		11.7.3 The fractional-seconds elements, if present, shall omit all trailing zeros; if the
	 *		       elements correspond to 0, they shall be wholly omitted, and the decimal point element
	 *		       also shall be omitted.
	 */

	/*
	 *	The format of a generalized time is "YYYYMMDDHHMMSS[.fff]Z"
	 *	Where:
	 *	1. YYYY is the year
	 *	2. MM is the month
	 *	3. DD is the day
	 *	4. HH is the hour
	 *	5. MM is the minute
	 *	6. SS is the second
	 *	7. fff is the fraction of a second (optional)
	 *	8. Z is the timezone (UTC)
	 */

	if (fr_dbuff_out_memcpy((uint8_t *)timestr, &our_in, DER_GENERALIZED_TIME_LEN_MIN) < 0) {
		fr_strerror_const("Insufficient data for generalized time. Missing data bytes");
		return -1;
	}

	if (memchr(timestr, '\0', DER_GENERALIZED_TIME_LEN_MIN) != NULL) {
		fr_strerror_const("Generalized time contains null byte");
		return -1;
	}

	if (timestr[DER_GENERALIZED_TIME_LEN_MIN - 1] != 'Z' && timestr[DER_GENERALIZED_TIME_LEN_MIN - 1] != '.') {
		fr_strerror_const("Incorrect format for generalized time. Missing timezone");
		return -1;
	}

	/*
	 *	Check if the fractional seconds are present
	 */
	if (timestr[DER_GENERALIZED_TIME_LEN_MIN - 1] == '.') {
		/*
		 *	We only support subseconds up to 4 decimal places
		 */
		char subsecstring[DER_GENERALIZED_TIME_PRECISION_MAX + 1];

		uint8_t precision = DER_GENERALIZED_TIME_PRECISION_MAX;

		if (unlikely(fr_dbuff_remaining(&our_in) - 1 < DER_GENERALIZED_TIME_PRECISION_MAX)) {
			precision = fr_dbuff_remaining(&our_in) - 1;
		}

		if (unlikely(precision == 0)) {
			fr_strerror_const("Insufficient data for subseconds");
			return -1;
		}

		if (fr_dbuff_out_memcpy((uint8_t *)subsecstring, &our_in, precision) < 0) {
			fr_strerror_const("Insufficient data for subseconds. Missing data bytes");
			return -1;
		}

		if (memchr(subsecstring, '\0', precision) != NULL) {
			fr_strerror_const("Generalized time contains null byte in subseconds");
			return -1;
		}

		subsecstring[DER_GENERALIZED_TIME_PRECISION_MAX] = '\0';

		/*
		 *	Convert the subseconds to an unsigned long
		 */
		subseconds = strtoul(subsecstring, NULL, 10);

		/*
		 *	Scale to nanoseconds
		 */
		subseconds *= 1000000;
	}

	/*
	 *	Make sure the timezone is UTC (Z)
	 */
	timestr[DER_GENERALIZED_TIME_LEN_MIN - 1] = 'Z';

	timestr[DER_GENERALIZED_TIME_LEN_MIN] = '\0';

	p = strptime(timestr, "%Y%m%d%H%M%SZ", &tm);

	if (unlikely(p == NULL)) {
		fr_strerror_const("Invalid generalized time format (strptime)");
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory");
		return -1;
	}

	vp->vp_date = fr_unix_time_add(fr_unix_time_from_tm(&tm), fr_time_delta_wrap(subseconds));

	fr_pair_append(out, vp);

	/*
	 *	Move to the end of the buffer
	 *	This is necessary because the fractional seconds are being ignored
	 */
	fr_dbuff_advance(&our_in, fr_dbuff_remaining(&our_in));

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_visible_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					    fr_dbuff_t *in, UNUSED fr_der_decode_ctx_t *decode_ctx)
{
	static bool const allowed_chars[] = {
		[' '] = true,  ['!'] = true,  ['"'] = true, ['#'] = true,
		['$'] = true,  ['%'] = true,  ['&'] = true, ['\''] = true,
		['('] = true,  [')'] = true,  ['*'] = true, ['+'] = true,
		[','] = true,  ['-'] = true,  ['.'] = true, ['/'] = true,
		[':'] = true,  [';'] = true,  ['<'] = true, ['='] = true,
		['>'] = true,  ['?'] = true,  ['@'] = true, ['['] = true,
		['\\'] = true, [']'] = true,  ['^'] = true, ['_'] = true,
		['`'] = true,  ['{'] = true,  ['|'] = true, ['}'] = true,
		['A' ... 'Z'] = true, ['a' ... 'z'] = true,
		['0' ... '9'] = true, [UINT8_MAX] = false
	};

	return fr_der_decode_string(ctx, out, parent, in, allowed_chars, decode_ctx);
}

static ssize_t fr_der_decode_general_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					    fr_dbuff_t *in, UNUSED fr_der_decode_ctx_t *decode_ctx)
{
	return fr_der_decode_string(ctx, out, parent, in, NULL, decode_ctx);
}

static ssize_t fr_der_decode_universal_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					      fr_dbuff_t *in, UNUSED fr_der_decode_ctx_t *decode_ctx)
{
	return fr_der_decode_string(ctx, out, parent, in, NULL, decode_ctx);
}

/** Decode the tag and length fields of a DER encoded structure
 *
 * @param[in] parent	Parent attribute
 * @param[in] in	Input buffer
 * @param[out] tag	Tag value
 * @param[out] len	Length of the value field
 *
 * @return		0 on success, -1 on failure
 */
static ssize_t fr_der_decode_hdr(fr_dict_attr_t const *parent, fr_dbuff_t *in, uint64_t *tag, size_t *len)
{
	fr_dbuff_t		 our_in = FR_DBUFF(in);
	uint8_t			 tag_byte;
	uint8_t			 len_byte;
	fr_der_tag_decode_t	*func;
	fr_der_tag_class_t	 tag_class;
	fr_der_tag_constructed_t constructed;

	if (unlikely(fr_dbuff_out(&tag_byte, &our_in) < 0)) {
		fr_strerror_const("Insufficient data for tag field");
		return -1;
	}

	/*
	 *	Decode the tag flags
	 */
	tag_class   = (tag_byte & DER_TAG_CLASS_MASK);
	constructed = IS_DER_TAG_CONSTRUCTED(tag_byte);

	/*
	 *	Decode the tag
	 */
	if (IS_DER_TAG_CONTINUATION(tag_byte)) {
		/*
		 *	We have a multi-byte tag
		 *
		 *	Note: Multi-byte tags would mean having a tag number that is greater than 30 (0x1E) (since tag
		 *	31 would indicate a multi-byte tag). For most use-cases, this should not be needed, since all
		 *	of the basic ASN.1 types are tagged under 30, and if a CHOICE type were to have over 30 options
		 *	(meaning a multi-byte tag would be needed), that would be a very complex CHOICE type that
		 *	should probably be simplified.
		 */
		fr_strerror_const("Multi-byte tags are not supported");
		return -1;
	}

	*tag = tag_byte & DER_TAG_CONTINUATION;

	/*
	 *	Check if the tag is not universal
	 */
	if (tag_class != FR_DER_CLASS_UNIVERSAL) {
		/*
		 *	The data type will need to be resolved using the dictionary and the tag value
		 */

		if (parent == NULL) {
			fr_strerror_const("No parent attribute to resolve tag");
			return -1;
		}

		if (tag_class == fr_der_flag_class(parent)) {
			if (*tag == fr_der_flag_tagnum(parent)) {
				*tag = fr_der_flag_subtype(parent);
			} else {
				goto bad_tag;
			}
		} else {
		bad_tag:
			fr_strerror_printf("Invalid tag %" PRIu64 " for attribute %s. Expected %" PRIu32, *tag, parent->name,
					   fr_der_flag_tagnum(parent));
			return -1;
		}
	}

	if ((*tag > NUM_ELEMENTS(tag_funcs)) || (*tag == FR_DER_TAG_INVALID)) {
		fr_strerror_printf("Unknown tag %" PRIu64, *tag);
		return -1;
	}

	func = &tag_funcs[*tag];
	/*
	 *	Check if the tag is an OID. OID tags will be handled differently
	 */
	if (*tag != FR_DER_TAG_OID) {
		if (unlikely(func->decode == NULL)) {
			fr_strerror_printf("No decode function for tag %" PRIu64, *tag);
			return -1;
		}

		if (IS_DER_TAG_CONSTRUCTED(func->constructed) != constructed) {
			fr_strerror_printf("Constructed flag mismatch for tag %" PRIu64, *tag);
			return -1;
		}
	}

	if (unlikely(fr_dbuff_out(&len_byte, &our_in) < 0)) {
		fr_strerror_const("Missing length field");
		return -1;
	}

	/*
	 *	Check if the length is a multi-byte length field
	 */
	if (IS_DER_LEN_MULTI_BYTE(len_byte)) {
		uint8_t len_len = len_byte & 0x7f;
		*len		= 0;

		/*
		 *	Length bits of zero is an indeterminate length field where
		 *	the length is encoded in the data instead.
		 */
		if (len_len > 0) {
			if (unlikely(len_len > sizeof(*len))) {
				fr_strerror_printf("Length field too large (%" PRIu32 ")", len_len);
				return -1;
			}

			while (len_len--) {
				if (unlikely(fr_dbuff_out(&len_byte, &our_in) < 0)) {
					fr_strerror_const("Insufficient data to satisfy multi-byte length field");
					return -1;
				}
				*len = (*len << 8) | len_byte;
			}
		}

		else if (!constructed) {
			fr_strerror_const("Primitive data with indefinite form length field is invalid");
			return -1;
		}
	} else {
		*len = len_byte;
	}

	/*
	 *	Check if the length is valid for our buffer
	 */
	if (unlikely(fr_dbuff_extend_lowat(NULL, &our_in, *len) < *len)) {
		fr_strerror_printf("Insufficient data for length field (%" PRIuPTR ")", *len);
		return -1;
	}

	return fr_dbuff_set(in, &our_in);
}

/** Decode a CHOICE type
 * This is where the actual decoding of the CHOICE type happens. The CHOICE type is a type that can have multiple
 * types, but only one of them can be present at a time. The type that is present is determined by the tag of the
 * data
 *
 * @param[in] ctx		Talloc context
 * @param[in] out		Output list
 * @param[in] parent		Parent attribute
 * @param[in] in		Input buffer
 * @param[in] decode_ctx	Decode context
 */
static ssize_t fr_der_decode_choice(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				    fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t	     *vp;
	fr_dict_attr_t const *child  = NULL;
	fr_dbuff_t	      our_in = FR_DBUFF(in);
	uint64_t	   tag_num;
	uint8_t		   tag_byte;
	uint8_t		  *current_marker = fr_dbuff_current(&our_in);

	if (!fr_type_is_struct(parent->type) && !fr_type_is_tlv(parent->type) && !fr_type_is_group(parent->type)) {
		fr_strerror_printf("Sequence found in incompatible attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("Out of memory");
		return -1;
	}

	if (unlikely(fr_dbuff_out(&tag_byte, &our_in) < 0)) {
		fr_strerror_const("Insufficient data for sequence choice. Missing tag");
		talloc_free(vp);
		return -1;
	}

	if (unlikely(IS_DER_TAG_CONTINUATION(tag_byte))) {
		fr_strerror_printf("Attribute %s is a choice, but received tag with continuation bit set",
					parent->name);
		talloc_free(vp);
		return -1;
	}

	tag_num = (tag_byte & DER_TAG_CONTINUATION);

	child = fr_dict_attr_child_by_num(parent, tag_num);
	if (unlikely(child == NULL)) {
		fr_strerror_printf("Attribute %s is a choice, but received unknown option %" PRIu64, parent->name,
					tag_num);
		talloc_free(vp);
		return -1;
	}

	fr_dbuff_set(&our_in, current_marker);

	if (unlikely(fr_der_decode_pair_dbuff(vp, &vp->vp_group, child, &our_in, decode_ctx) < 0)) {
		talloc_free(vp);
		return -1;
	}

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

/** Decode an X509 Extentions Field
 *
 * @param[in] ctx		Talloc context
 * @param[in] out		Output list
 * @param[in] in		Input buffer
 * @param[in] parent		Parent attribute
 * @param[in] decode_ctx	Decode context
 *
 * @return		0 on success, -1 on failure
 */
static ssize_t fr_der_decode_x509_extensions(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dbuff_t *in,
					     fr_dict_attr_t const *parent, fr_der_decode_ctx_t *decode_ctx)
{
	fr_dbuff_t our_in = FR_DBUFF(in);
	fr_pair_t *vp, *vp2;

	uint64_t tag;
	int64_t	max;
	size_t	 len;
	ssize_t	 slen;

	FR_PROTO_TRACE("Decoding extensions");
	FR_PROTO_TRACE("Attribute %s", parent->name);
	FR_PROTO_HEX_DUMP(fr_dbuff_current(in), fr_dbuff_remaining(in), "Top of extension decoding");

	if (unlikely(!fr_type_is_group(parent->type))) {
		fr_strerror_printf("Pair found in non-group attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	/*
	 *	RFC 5280 Section 4.2
	 *	The extensions defined for X.509 v3 certificates provide methods for
	 *	associating additional attributes with users or public keys and for
	 *	managing relationships between CAs.  The X.509 v3 certificate format
	 *	also allows communities to define private extensions to carry
	 *	information unique to those communities.  Each extension in a
	 *	certificate is designated as either critical or non-critical.
	 *
	 *	Each extension includes an OID and an ASN.1 structure.  When an
	 *	extension appears in a certificate, the OID appears as the field
	 *	extnID and the corresponding ASN.1 DER encoded structure is the value
	 *	of the octet string extnValue.
	 *
	 *	RFC 5280 Section A.1 Explicitly Tagged Module, 1988 Syntax
	 *		Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
	 *
	 *		Extension  ::=  SEQUENCE  {
	 *			extnID      OBJECT IDENTIFIER,
	 *			critical    BOOLEAN DEFAULT FALSE,
	 *			extnValue   OCTET STRING
	 *					-- contains the DER encoding of an ASN.1 value
	 *					-- corresponding to the extension type identified
	 *					-- by extnID
	 *		}
	 *
	 *	So the extensions are a SEQUENCE of SEQUENCEs containing an OID, a boolean and an OCTET STRING.
	 *	Note: If the boolean value is false, it is not included in the encoding.
	 */

	vp = fr_pair_afrom_da(ctx, parent);

	if (unlikely(vp == NULL)) {
	oom:
		fr_strerror_const("Out of memory");
		return -1;
	}

	vp2 = fr_pair_afrom_da(vp, fr_dict_attr_by_name(NULL, fr_dict_attr_ref(parent), "critical"));

	if (unlikely(vp2 == NULL)) {
		talloc_free(vp);
		goto oom;
	}

	if (unlikely((slen = fr_der_decode_hdr(parent, &our_in, &tag, &len)) < 0)) {
		fr_strerror_const_push("Failed decoding extensions list header");
	error:
		talloc_free(vp2);
		talloc_free(vp);
		return slen;
	}

	if (tag != FR_DER_TAG_SEQUENCE) {
		fr_strerror_printf("Expected SEQUENCE tag as the first item in an extensions list. Got tag: %" PRIu64, tag);
		slen = -1;
		goto error;
	}

	FR_PROTO_TRACE("Attribute %s, tag %" PRIu64, parent->name, tag);

	max = fr_der_flag_max(parent); /* Maximum number of extensions specified in the dictionary*/

	while (fr_dbuff_remaining(&our_in) > 0) {
		fr_dbuff_t		      sub_in = FR_DBUFF(&our_in);
		fr_dbuff_marker_t	      sub_marker;
		fr_der_decode_oid_to_da_ctx_t uctx;

		size_t	sub_len, len_peek;
		uint8_t is_critical = false;

		fr_dbuff_set_end(&sub_in, fr_dbuff_current(&sub_in) + len);

		if (unlikely((slen = fr_der_decode_hdr(parent, &sub_in, &tag, &sub_len)) < 0)) {
			fr_strerror_const_push("Failed decoding extension sequence header");
			goto error;
		}

		if (tag != FR_DER_TAG_SEQUENCE) {
			fr_strerror_printf("Expected SEQUENCE tag as the first tag in an extension. Got tag: %" PRIu64,
					   tag);
			slen = -1;
			goto error;
		}

		FR_PROTO_TRACE("Attribute %s, tag %" PRIu64, parent->name, tag);

		if (unlikely((slen = fr_der_decode_hdr(NULL, &sub_in, &tag, &sub_len)) < 0)) {
			fr_strerror_const_push("Failed decoding oid header");
			goto error;
		}

		if (tag != FR_DER_TAG_OID) {
			fr_strerror_printf("Expected OID tag as the first item in an extension. Got tag: %" PRIu64, tag);
			slen = -1;
			goto error;
		}

		FR_PROTO_TRACE("Attribute %s, tag %" PRIu64, parent->name, tag);

		uctx.ctx	 = vp;
		uctx.parent_da	 = vp->da;
		uctx.parent_list = &vp->vp_group;

		fr_dbuff_marker(&sub_marker, &sub_in);

		FR_PROTO_HEX_DUMP(fr_dbuff_current(&sub_in), fr_dbuff_remaining(&sub_in),
				  "Before moving buffer in extension");

		fr_dbuff_advance(&sub_in, sub_len);

		FR_PROTO_HEX_DUMP(fr_dbuff_current(&sub_in), fr_dbuff_remaining(&sub_in),
				  "After moving buffer in extension");

		if (unlikely(fr_der_decode_hdr(NULL, &sub_in, &tag, &len_peek) < 0)) {
			fr_strerror_const_push("Failed decoding value header for extension ");
			slen = -1;
			fr_dbuff_marker_release(&sub_marker);
			goto error;
		}

		if (tag == FR_DER_TAG_BOOLEAN) {
			/*
			 *	This Extension has the isCritical field.
			 * 	If this value is true, we will be storing the pair in the critical list
			 */
			if (unlikely(fr_dbuff_out(&is_critical, &sub_in) < 0)) {
				fr_strerror_const("Insufficient data for isCritical field");
				slen = -1;
				fr_dbuff_marker_release(&sub_marker);
				goto error;
			}

			if (is_critical) {
				uctx.ctx	 = vp2;
				uctx.parent_da	 = vp2->da;
				uctx.parent_list = &vp2->vp_group;
			}
		}

		/*
		 *	Restore the marker and rewind the buffer
		 */
		fr_dbuff_set(&sub_in, &sub_marker);
		fr_dbuff_marker_release(&sub_marker);

		fr_dbuff_set_end(&sub_in, fr_dbuff_current(&sub_in) + sub_len);

		FR_PROTO_HEX_DUMP(fr_dbuff_current(&sub_in), fr_dbuff_remaining(&sub_in),
				  "Before decoding extension oid");

		/*
		 *	Decode the OID to get the attribute to use for the extension value
		 */
		if (unlikely((slen = fr_der_decode_oid(NULL, &sub_in, fr_der_decode_oid_to_da, &uctx)) < 0)) {
			fr_strerror_const_push("Failed decoding extension");
			goto error;
		}

		fr_dbuff_set(&our_in, &sub_in);

		sub_in = FR_DBUFF(&our_in);

		FR_PROTO_HEX_DUMP(fr_dbuff_current(&sub_in), fr_dbuff_remaining(&sub_in),
				  "After decoding extension oid");

		if (is_critical) {
			/*
			 *	Skip over boolean value
			 */
			fr_dbuff_advance(&sub_in, 3);
		}

		FR_PROTO_HEX_DUMP(fr_dbuff_current(&sub_in), fr_dbuff_remaining(&sub_in),
				  "After advancing buffer in extension");

		if (unlikely((slen = fr_der_decode_hdr(NULL, &sub_in, &tag, &sub_len)) < 0)) {
			fr_strerror_const_push("Failed decoding value header for extension value");
			goto error;
		}

		if (unlikely(tag != FR_DER_TAG_OCTETSTRING)) {
			fr_strerror_printf("Expected OCTETSTRING tag as the second item in an extension. Got tag: %" PRIu64,
					   tag);
			slen = -1;
			goto error;
		}

		fr_dbuff_set_end(&sub_in, fr_dbuff_current(&sub_in) + sub_len);

		FR_PROTO_HEX_DUMP(fr_dbuff_current(&sub_in), fr_dbuff_remaining(&sub_in),
				  "Before decoding extension value");

		if (uctx.parent_da->flags.is_unknown) {
			/*
			 * 	The extension was not found in the dictionary. We will store the value as raw octets
			 */
			if (unlikely((slen = fr_der_decode_octetstring(uctx.ctx, uctx.parent_list, uctx.parent_da,
								       &sub_in, decode_ctx)) < 0)) {
				fr_strerror_const_push("Failed decoding extension value");
				goto error;
			}
		} else if (unlikely((slen = fr_der_decode_pair_dbuff(uctx.ctx, uctx.parent_list, uctx.parent_da, &sub_in,
								   decode_ctx)) < 0)) {
			fr_strerror_const_push("Failed decoding extension value");
			goto error;
		}

		FR_PROTO_HEX_DUMP(fr_dbuff_current(&sub_in), fr_dbuff_remaining(&sub_in),
				  "After decoding extension value");

		fr_dbuff_set(&our_in, &sub_in);

		if (--max == 0 && fr_dbuff_remaining(&our_in) > 0) {
			fr_strerror_const("Too many extensions");
			return -1;
		}
	}

	if (vp2->children.order.head.dlist_head.num_elements > 0) {
		fr_pair_prepend(&vp->vp_group, vp2);
	}

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

/** Decode an OID value pair
 *
 * @param[in] ctx		Talloc context
 * @param[out] out		Output list
 * @param[in] in		Input buffer
 * @param[in] parent		Parent attribute
 * @param[in] decode_ctx	Decode context
 *
 * @return		0 on success, -1 on failure
 */
static ssize_t fr_der_decode_oid_value_pair(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dbuff_t *in,
					    fr_dict_attr_t const *parent, fr_der_decode_ctx_t *decode_ctx)
{
	fr_dbuff_t		      our_in = FR_DBUFF(in);
	fr_dbuff_marker_t	      marker;
	fr_der_decode_oid_to_da_ctx_t uctx;

	uint64_t tag;
	size_t	 len;
	ssize_t	 slen;

	FR_PROTO_TRACE("Decoding OID value pair");
	if (unlikely(!fr_type_is_group(parent->type))) {
		fr_strerror_printf("Pair found in non-group attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	/*
	 *	A very common pattern in DER encoding is ro have a sequence of set containing two things: an OID and a
	 *	value, where the OID is used to determine how to decode the value.
	 *	We will be decoding the OID first and then try to find the attribute associated with that OID to then
	 *	decode the value. If no attribute is found, one will be created and the value will be stored as raw
	 *	octets in the attribute.
	 */

	fr_dbuff_marker(&marker, in);

	if (unlikely((slen = fr_der_decode_hdr(parent, &our_in, &tag, &len)) < 0)) {
		fr_strerror_const_push("Failed decoding oid header");
	error:
		fr_dbuff_marker_release(&marker);
		return slen;
	}

	if (tag != FR_DER_TAG_OID) {
		fr_strerror_printf("Expected OID tag as the first item in a pair. Got tag: %" PRIu64, tag);
		slen = -1;
		goto error;
	}

	FR_PROTO_TRACE("Attribute %s, tag %" PRIu64, parent->name, tag);

	uctx.ctx	 = ctx;
	uctx.parent_da	 = fr_dict_attr_ref(parent);
	uctx.parent_list = out;

	fr_dbuff_set_end(&our_in, fr_dbuff_current(&our_in) + len);

	FR_PROTO_HEX_DUMP(fr_dbuff_current(&our_in), fr_dbuff_remaining(&our_in), "DER pair value");

	slen = fr_der_decode_oid(out, &our_in, fr_der_decode_oid_to_da, &uctx);
	if (unlikely(slen < 0)) goto error;

	/*
	 *	We have the attribute associated with the OID
	 *	We will now decode the value.
	 *
	 *	We will advance the buffer to the end of the OID, and then reuse the our_in buffer to decode the value.
	 *  	This looks strange in the code, but it is necessary to reset the end restrictions on the our_in buffer
	 * 	which were set to avoid overreading the buffer when decoding the OID.
	 */
	fr_dbuff_set(in, &our_in);

	our_in = FR_DBUFF(in);

	FR_PROTO_HEX_DUMP(fr_dbuff_current(&our_in), fr_dbuff_remaining(&our_in), "DER pair value");

	if (unlikely(uctx.parent_da->flags.is_unknown)) {
		/*
		 *	The this pair is not in the dictionary
		 *	We will store the value as raw octets
		 */
		if (unlikely(slen = fr_der_decode_octetstring(uctx.ctx, uctx.parent_list, uctx.parent_da, &our_in,
							      decode_ctx) < 0)) {
			fr_strerror_const_push("Failed decoding extension value");
			goto error;
		}
	} else if (unlikely(slen = fr_der_decode_pair_dbuff(uctx.ctx, uctx.parent_list, uctx.parent_da, &our_in,
							    decode_ctx) < 0)) {
		fr_strerror_const_push("Failed decoding extension value");
		goto error;
	}

	fr_dbuff_set(in, &our_in);

	FR_PROTO_HEX_DUMP(fr_dbuff_current(&our_in), fr_dbuff_remaining(&our_in), "DER pair value");

	return fr_dbuff_marker_release_behind(&marker);
}

static ssize_t fr_der_decode_string(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, fr_dbuff_t *in,
				    bool const allowed_chars[], UNUSED fr_der_decode_ctx_t *decode_ctx)
{
	fr_pair_t *vp;
	fr_dbuff_t our_in = FR_DBUFF(in);
	char	  *str	  = NULL;

	size_t len = fr_dbuff_remaining(&our_in), pos;

	if (!fr_type_is_string(parent->type)) {
		fr_strerror_printf("String found in non-string attribute %s of type %s", parent->name,
				   fr_type_to_str(parent->type));
		return -1;
	}

	/*
	 *	ISO/IEC 8825-1:2021
	 * 	8.23 Encoding for values of the restricted character string types
	 *	8.23.1 The data value consists of a string of characters from the character set specified in the ASN.1
	 *		type definition. 8.23.2 Each data value shall be encoded independently of other data values of
	 *		the same type.
	 *	8.23.3 Each character string type shall be encoded as if it had been declared:
	 *			[UNIVERSAL x] IMPLICIT OCTET STRING
	 *		where x is the number of the universal class tag assigned to the character string type in
	 *		Rec. ITU-T X.680 | ISO/IEC 8824-1. The value of the octet string is specified in 8.23.4 and
	 *		8.23.5.
	 */

	vp = fr_pair_afrom_da(ctx, parent);
	if (unlikely(vp == NULL)) {
	oom:
		fr_strerror_const("Out of memory");
		return -1;
	}

	if (unlikely(fr_pair_value_bstr_alloc(vp, &str, len, false) < 0)) {
		talloc_free(vp);
		goto oom;
	}

	fr_dbuff_out_memcpy((uint8_t *)str, &our_in, len);

	if (allowed_chars) {
		fr_sbuff_t sbuff;
		sbuff = FR_SBUFF_OUT(str, len);

		if ((pos = fr_sbuff_adv_past_allowed(&sbuff, SIZE_MAX, allowed_chars, NULL)) < len - 1) {
		invalid:
			fr_strerror_printf("Invalid character in a string (%" PRId32 ")", str[pos]);
			return -1;
		}

		// Check the final character
		if (!allowed_chars[(uint8_t)str[pos]]) goto invalid;
	}

	str[len] = '\0';

	fr_pair_append(out, vp);

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_pair_dbuff(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
					fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx)
{
	fr_dbuff_t	     our_in = FR_DBUFF(in);
	fr_der_tag_decode_t *func;
	ssize_t		     slen;
	uint64_t	     tag, max;
	size_t		     len;

	/*
	 *	ISO/IEC 8825-1:2021
	 *	The structure of a DER encoding is as follows:
	 *
	 *		+------------+--------+-------+
	 *		| IDENTIFIER | LENGTH | VALUE |
	 *		+------------+--------+-------+
	 *
	 *	The IDENTIFIER is a tag that specifies the type of the value field and is encoded as follows:
	 *
	 *		  8   7    6    5   4   3   2   1
	 *		+---+---+-----+---+---+---+---+---+
	 *		| Class | P/C |     Tag Number    |
	 *		+---+---+-----+---+---+---+---+---+
	 *			   |
	 *			   |- 0 = Primitive
	 *			   |- 1 = Constructed
	 *
	 *	The CLASS field specifies the encoding class of the tag and may be one of the following values:
	 *
	 *		+------------------+-------+-------+
	 *		|      Class       | Bit 8 | Bit 7 |
	 *		+------------------+-------+-------+
	 *		| UNIVERSAL        |   0   |   0   |
	 *		| APPLICATION      |   0   |   1   |
	 *		| CONTEXT-SPECIFIC |   1   |   0   |
	 *		| PRIVATE          |   1   |   1   |
	 *		+------------------+-------+-------+
	 *
	 *	The P/C field specifies whether the value field is primitive or constructed.
	 *	The TAG NUMBER field specifies the tag number of the value field and is encoded as an unsigned binary
	 *	integer.
	 *
	 *	The LENGTH field specifies the length of the VALUE field and is encoded as an unsigned binary integer
	 *	and may be encoded as a single byte or multiple bytes.
	 *
	 *	The VALUE field contains LENGTH number of bytes and is encoded according to the tag.
	 *
	 */

	/*
	 *	If there are no more bytes to read, it is possible that the value was not encoded since
	 *	it may be using the DEFAULT value. Here we try extending the buffer to see if we can read
	 *	the next header.
	 */
	if ((fr_dbuff_extend_lowat(NULL, &our_in, 2) < 2)) {
		if (fr_der_flag_has_default(parent)) {
			fr_pair_t	     *vp = fr_pair_afrom_da(ctx, parent);
			fr_dict_enum_value_t *ev;

			if (unlikely(vp == NULL)) {
			oom:
				fr_strerror_const("Out of memory");
				return -1;
			}

			ev = fr_dict_enum_by_name(parent, "DEFAULT", strlen("DEFAULT"));
			if (unlikely(ev == NULL)) {
				fr_strerror_printf("No DEFAULT value for attribute %s", parent->name);
			error:
				talloc_free(vp);
				return -1;
			}

			if (fr_value_box_copy(vp, &vp->data, ev->value) < 0) goto error;

			vp->data.enumv = vp->da;

			fr_pair_append(out, vp);

			return 0;
		}

		/*
		 *	This may look like a "quiet fail", but this is needed when looping over a sequence
		 *	and the last attribute has a default value. This will allow the loop to continue
		 *	without failing.
		 */
		return 0;
	}

	if (unlikely(fr_der_flag_is_choice(parent))) {
		slen = fr_der_decode_choice(ctx, out, parent, &our_in, decode_ctx);

		if (unlikely(slen < 0)) return slen;

		return fr_dbuff_set(in, &our_in);
	}

	if (unlikely(fr_der_decode_hdr(parent, &our_in, &tag, &len) < 0)) {
		fr_strerror_const_push("Failed decoding header");
		return -1;
	}

	FR_PROTO_TRACE("Attribute %s, tag %" PRIu64, parent->name, tag);

	if (unlikely(tag != FR_DER_TAG_NULL) && (!fr_type_to_der_tag_valid(parent->type, tag) || fr_dbuff_remaining(&our_in) == 0)) {
		if (fr_der_flag_has_default(parent)) {
			/*
			 *	If the attribute has a default value, we will use that.
			 *	We could end up here if we are decoding a sequence which has a default value
			 *	for an attribute that is not the last attribute in the sequence.
			 */
			fr_pair_t	     *vp = fr_pair_afrom_da(ctx, parent);
			fr_dict_enum_value_t *ev;

			if (unlikely(vp == NULL)) goto oom;

			ev = fr_dict_enum_by_name(parent, "DEFAULT", strlen("DEFAULT"));
			if (unlikely(ev == NULL)) {
				fr_strerror_printf("No DEFAULT value for attribute %s", parent->name);
				talloc_free(vp);
				return -1;
			}

			if (fr_value_box_copy(vp, &vp->data, ev->value) < 0) {
				talloc_free(vp);
				goto oom;
			}

			vp->data.enumv = vp->da;

			fr_pair_append(out, vp);

			/*
			 *	If we did not consume any bytes (tag didn't match, and DEFAULT was used), we
			 *	should return 0 to indicate that we successfully decoded the attribute.
			 * 	If we did consume bytes, we should return the number of bytes consumed.
			 */
			if (fr_dbuff_remaining(&our_in) == 0) return fr_dbuff_set(in, &our_in);

			return 0;
		}

		if (fr_type_is_octets(parent->type)) {
			/*
			 *	We will store the value as raw octets if indicated by the dictionary
			 */
			tag = FR_DER_TAG_OCTETSTRING;
		} else if (!(fr_type_to_der_tag_valid(parent->type, tag) && fr_type_is_structural(parent->type))) {
			/*
			 *	If this is not a sequence/set/structure like thing, then it does not have children that
			 *	could have defaults.
			 */
			fr_strerror_printf("Attribute %s of type %s cannot store type %" PRIu64, parent->name,
					   fr_type_to_str(parent->type), tag);
			return -1;
		}
	}

	if (fr_der_flag_is_extensions(parent)) {
		slen = fr_der_decode_x509_extensions(ctx, out, &our_in, parent, decode_ctx);

		if (unlikely(slen < 0)) return slen;

		return fr_dbuff_set(in, &our_in);
	}

	func = &tag_funcs[tag];

	/*
	 *	Make sure the data length is less than the maximum allowed
	 */
	switch (tag) {
	case FR_DER_TAG_SEQUENCE:
	case FR_DER_TAG_SET:
		break;
	default:
		max = fr_der_flag_max(parent) ? fr_der_flag_max(parent) : DER_MAX_STR;

		if (unlikely(len > max)) {
			fr_strerror_printf("Data length (%" PRIuPTR ") exceeds max size (%" PRIu64 ")", len, max);
			return -1;
		}
		break;
	}

	if (tag != FR_DER_TAG_OID) {
		fr_dbuff_set_end(&our_in, fr_dbuff_current(&our_in) + len);
		slen = func->decode(ctx, out, parent, &our_in, decode_ctx);
	} else {
		fr_der_decode_oid_to_str_ctx_t uctx = {
			.ctx	     = ctx,
			.parent_da   = parent,
			.parent_list = out,
			.oid_buff = {},
			.marker = {},
		};

		fr_dbuff_set_end(&our_in, fr_dbuff_current(&our_in) + len);

		slen = fr_der_decode_oid(out, &our_in, fr_der_decode_oid_to_str, &uctx);
	}

	if (unlikely(slen < 0)) return slen;

	return fr_dbuff_set(in, &our_in);
}

static ssize_t fr_der_decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *out, uint8_t const *data, size_t data_len,
				   void *proto_ctx)
{
	fr_dbuff_t our_in = FR_DBUFF_TMP(data, data_len);

	fr_dict_attr_t const *parent = fr_dict_root(dict_der);

	if (unlikely(parent == fr_dict_root(dict_der))) {
		fr_strerror_printf("Invalid dictionary. DER decoding requires a specific dictionary.");
		return -1;
	}

	return fr_der_decode_pair_dbuff(ctx, out, parent, &our_in, proto_ctx);
}

/** Decode a DER structure using the specific dictionary
 *
 * @param[in] ctx		to allocate new pairs in.
 * @param[in] out		where new VPs will be added
 * @param[in] parent		Parent attribute.  This should be the root of the dictionary
 *				we're using to decode DER data.  This only specifies structures
 *				like SEQUENCES.  OID based pairs are resolved using the global
 *				dictionary tree.
 *
 */
static ssize_t decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent, uint8_t const *data,
			   size_t data_len, void *decode_ctx)
{
	// fr_assert(parent == fr_dict_root(dict_der));

	if (unlikely(parent == fr_dict_root(dict_der))) {
		fr_strerror_printf("Invalid dictionary. DER decoding requires a specific dictionary.");
		return -1;
	}

	return fr_der_decode_pair_dbuff(ctx, out, parent, &FR_DBUFF_TMP(data, data_len), decode_ctx);
}

/*
 *	Test points
 */
static int decode_test_ctx(void **out, TALLOC_CTX *ctx, UNUSED fr_dict_t const *dict)
{
	fr_der_decode_ctx_t *test_ctx;

	test_ctx = talloc_zero(ctx, fr_der_decode_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->tmp_ctx	  = talloc(test_ctx, uint8_t);
	test_ctx->oid_value_pairs = false;

	*out = test_ctx;

	return 0;
}

extern fr_test_point_pair_decode_t der_tp_decode_pair;
fr_test_point_pair_decode_t	   der_tp_decode_pair = {
	       .test_ctx = decode_test_ctx,
	       .func	 = decode_pair,
};

extern fr_test_point_proto_decode_t der_tp_decode_proto;
fr_test_point_proto_decode_t	    der_tp_decode_proto = {
	       .test_ctx = decode_test_ctx,
	       .func	 = fr_der_decode_proto,
};
