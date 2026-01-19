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
 * @file protocols/der/encode.c
 * @brief Functions to encode DER
 *
 * @copyright 2025 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/encode.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/dict_ext.h>

#include <freeradius-devel/io/test_point.h>

#include "der.h"

extern fr_dict_attr_t const *attr_oid_tree;

typedef struct {
	uint8_t *tmp_ctx;	 		//!< Temporary context for encoding.
} fr_der_encode_ctx_t;

/** Function signature for DER encode functions
 *
 * @param[in] dbuff		Where to encode the data.
 * @param[in] cursor		Where to encode the data from.
 * @param[in] encode_ctx	Any encode specific data.
 * @return
 *	- > 0 on success.  How many bytes were encoded.
 *	- 0 no bytes encoded.
 *	- < 0 on error.  May be the offset (as a negative value) where the error occurred.
 */
typedef ssize_t (*fr_der_encode_t)(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx);

typedef struct {
	fr_der_tag_constructed_t constructed;
	fr_der_encode_t		 encode;
} fr_der_tag_encode_t;


static ssize_t fr_der_encode_oid_and_value(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx) CC_HINT(nonnull);
static ssize_t fr_der_encode_choice(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx) CC_HINT(nonnull);

/*
 *	We have per-type function names to make it clear that different types have different encoders.
 *	However, the methods to encode them are the same.  So rather than having trampoline functions, we just
 *	use defines.
 */
#define fr_der_encode_enumerated fr_der_encode_integer


static ssize_t fr_der_encode_len(fr_dbuff_t *dbuff, fr_dbuff_marker_t *length_start) CC_HINT(nonnull);
static inline CC_HINT(always_inline) ssize_t
	fr_der_encode_tag(fr_dbuff_t *dbuff, fr_der_tag_t tag_num, fr_der_tag_class_t tag_class,
			  fr_der_tag_constructed_t constructed) CC_HINT(nonnull);
static ssize_t encode_value(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, void *encode_ctx);

/** Compare two pairs by their tag number.
 *
 * @param[in] a	First pair.
 * @param[in] b	Second pair.
 * @return		-1 if a < b, 0 if a == b, 1 if a > b.
 */
static inline CC_HINT(always_inline) int8_t fr_der_pair_cmp_by_da_tag(void const *a, void const *b)
{
	fr_pair_t const *my_a = a;
	fr_pair_t const *my_b = b;

	return CMP_PREFER_SMALLER(fr_der_flag_der_type(my_a->da), fr_der_flag_der_type(my_b->da));
}

static ssize_t encode_pair(fr_dbuff_t *dbuff, UNUSED fr_da_stack_t *da_stack, UNUSED unsigned int depth, fr_dcursor_t *cursor,
			   void *encode_ctx)
{
	return encode_value(dbuff, cursor, encode_ctx);
}

static ssize_t fr_der_encode_boolean(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	 our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	uint8_t		 value;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

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
	value = vp->vp_bool;

	FR_DBUFF_IN_RETURN(&our_dbuff, (uint8_t)(value ? DER_BOOLEAN_TRUE : DER_BOOLEAN_FALSE));

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_integer(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	 our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	uint64_t       	 value;
	uint8_t		 first_octet = 0;
	size_t		 i, len;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.3 Encoding of an integer value
	 *	8.3.1 The encoding of an integer value shall be primitive.
	 *	      The contents octets shall consist of one or more octets.
	 *	8.3.2 If the contents octets of an integer value encoding consist of more than one octet,
	 *	      then the bits of the first octet and bit 8 of the second octet:
	 *	      a) shall not all be ones; and
	 *	      b) shall not all be zero.
	 *	      NOTE - These rules ensure that an integer value is always encoded in the smallest possible number
	 *	      of octets. 8.3.3 The contents octets shall be a two's complement binary number equal to the
	 *	      integer value, and consisting of bits 8 to 1 of the first octet, followed by bits 8 to 1 of the
	 *	      second octet, followed by bits 8 to 1 of each octet in turn up to and including the last octet of
	 *	      the contents octets.
	 */

	/*
	 *	Some 'integer' types such as serialNumber are too
	 *	large for 64-bits.  So we just treat them as octet
	 *	strings.
	 */
	if (vp->da->type != FR_TYPE_INT64) {
		fr_assert(vp->da->type == FR_TYPE_OCTETS);
		FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, vp->vp_octets, vp->vp_length);
		return fr_dbuff_set(dbuff, &our_dbuff);
	}

	/*
	 *	Yes, the type is FR_TYPE_INT64.  But we encode the
	 *	data as-is, without caring about things like signed
	 *	math.
	 */
	value = vp->vp_uint64;

	for (i = 0, len = 0; i < sizeof(value); i++) {
		uint8_t byte = (value >> 56) & 0xff;

		value <<= 8;

		if (len == 0) {
			first_octet = byte;
			len++;
			continue;

		} else if (len == 1) {
			/*
			 *	8.3.2 If the contents octets of an integer value encoding consist of more than one
			 *	octet, then the bits of the first octet and bit 8 of the second octet: a) shall not all
			 *	be ones; and b) shall not all be zero.
			 */
			if ((first_octet == 0xff && (byte & 0x80)) || ((first_octet == 0x00) && (byte >> 7 == 0))) {
				if (i == sizeof(value) - 1) {
					/*
					 * 	If this is the only byte, then we can encode it as a single byte.
					 */
					FR_DBUFF_IN_RETURN(&our_dbuff, byte);
					continue;
				}

				first_octet = byte;
				continue;

			} else {
				FR_DBUFF_IN_RETURN(&our_dbuff, first_octet);
				FR_DBUFF_IN_RETURN(&our_dbuff, byte);
				len++;
				continue;
			}
		}

		FR_DBUFF_IN_RETURN(&our_dbuff, byte);
		len++;
	}

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_bitstring(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	ssize_t		 slen;
	uint8_t		 unused_bits = 0;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.6 Encoding of a bitstring value
	 *		8.6.1 The encoding of a bitstring value shall be either primitive or constructed at the option
	 *		      of the sender.
	 *			NOTE - Where it is necessary to transfer part of a bit string before the entire
	 *			       bitstring is available, the constructed encoding is used.
	 *		8.6.2 The contents octets for the primitive encoding shall contain an initial octet followed
	 *		      by zero, one or more subsequent octets.
	 *			8.6.2.1 The bits in the bitstring value, commencing with the leading bit and proceeding
	 *				to the trailing bit, shall be placed in bits 8 to 1 of the first subsequent
	 *				octet, followed by bits 8 to 1 of the second subsequent octet, followed by bits
	 *				8 to 1 of each octet in turn, followed by as many bits as are needed of the
	 *				final subsequent octet, commencing with bit 8.
	 *				NOTE - The terms "leading bit" and "trailing bit" are defined in
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

	if (fr_type_is_struct(vp->vp_type)) {
		/*
		 *	For struct type, we need to encode the struct as a bitstring using the
		 *	fr_struct_to_network function.
		 */
		unsigned int	  depth = vp->da->depth - 1;
		fr_da_stack_t	  da_stack;
		fr_dbuff_t	  work_dbuff = FR_DBUFF(&our_dbuff);
		fr_dbuff_marker_t unused_bits_marker;
		uint8_t		  last_byte = 0;

		fr_dbuff_marker(&unused_bits_marker, &work_dbuff);
		FR_DBUFF_ADVANCE_RETURN(&work_dbuff, 1);

		fr_proto_da_stack_build(&da_stack, vp->da);

		FR_PROTO_STACK_PRINT(&da_stack, depth);

		slen = fr_struct_to_network(&work_dbuff, &da_stack, depth, cursor, encode_ctx, NULL, NULL);
		if (slen < 0) {
			fr_strerror_printf("Failed to encode struct: %s", fr_strerror());
			return slen;
		}

		/*
		 *	We need to trim any empty trailing octets
		 */
		while ((slen > 1) && (fr_dbuff_current(&work_dbuff) != fr_dbuff_start(&work_dbuff))) {
			uint8_t byte;

			/*
			 *	Move the dbuff cursor back by one byte
			 */
			fr_dbuff_set(&work_dbuff, fr_dbuff_current(&work_dbuff) - sizeof(byte));

			if (fr_dbuff_out(&byte, &work_dbuff) < 0) {
				fr_strerror_const("Failed to read byte");
				return -1;
			}

			if (byte != 0) break;

			/*
			 *	Trim this byte from the buff
			 */
			fr_dbuff_set_end(&work_dbuff, fr_dbuff_current(&work_dbuff) - sizeof(byte));
			fr_dbuff_set(&work_dbuff, fr_dbuff_current(&work_dbuff) - (sizeof(byte) * 2));
			slen--;
		}

		/*
		 *	Grab the last octet written to the dbuff and count the number of trailing 0 bits
		 */
		if (fr_dbuff_out(&last_byte, &work_dbuff) < 0) {
			fr_strerror_const("Failed to read last byte");
			return -1;
		}

		while ((last_byte != 0) && ((last_byte & 0x01) == 0)) {
			unused_bits++;
			last_byte >>= 1;
		}

		/*
		 *	Write the unused bits
		 */
		fr_dbuff_set(&our_dbuff, fr_dbuff_current(&unused_bits_marker));
		FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, &unused_bits, 1);

		/*
		 *	Copy the work dbuff to the output dbuff
		 */
		fr_dbuff_set(&work_dbuff, &our_dbuff);
		FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, &work_dbuff, (size_t)slen);

		return fr_dbuff_set(dbuff, &our_dbuff);
	}

	/*
	 *	For octets type, we do not need to write the unused bits portion
	 *	because this information should be retained when encoding/decoding.
	 */
	if (vp->vp_length == 0) {
		FR_DBUFF_IN_RETURN(&our_dbuff, (uint8_t) 0x00);

	} else {
		FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, vp->vp_octets, vp->vp_length);
	}

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_ipv4_addr(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	 our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	/*
	 *	RFC3779 Section 2.1.1.
	 *
	 *	An IP address or prefix is encoded in the IP address delegation
	 *	extension as a DER-encoded ASN.1 BIT STRING containing the constant
	 *	most-significant bits.  Recall [X.690] that the DER encoding of a BIT
	 *	STRING consists of the BIT STRING type (0x03), followed by (an
	 *	encoding of) the number of value octets, followed by the value.  The
	 *	value consists of an "initial octet" that specifies the number of
	 *	unused bits in the last value octet, followed by the "subsequent
	 *	octets" that contain the octets of the bit string.  (For IP
	 *	addresses, the encoding of the length will be just the length.)
	 */

	/*
	 *	The number of unused bits in the last byte is always zero.
	 */
	FR_DBUFF_IN_RETURN(&our_dbuff, (uint8_t) 0x00);
	FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, (uint8_t const *) &vp->vp_ipv4addr, sizeof(vp->vp_ipv4addr));

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_ipv4_prefix(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	 our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	size_t		len;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	if (vp->vp_ip.prefix == 0) {
		FR_DBUFF_IN_RETURN(&our_dbuff, (uint8_t) 0x00);
		return fr_dbuff_set(dbuff, &our_dbuff);
	}

	/*
	 *	RFC3779 Section 2.1.1.
	 *
	 *	An IP address or prefix is encoded in the IP address delegation
	 *	extension as a DER-encoded ASN.1 BIT STRING containing the constant
	 *	most-significant bits.  Recall [X.690] that the DER encoding of a BIT
	 *	STRING consists of the BIT STRING type (0x03), followed by (an
	 *	encoding of) the number of value octets, followed by the value.  The
	 *	value consists of an "initial octet" that specifies the number of
	 *	unused bits in the last value octet, followed by the "subsequent
	 *	octets" that contain the octets of the bit string.  (For IP
	 *	addresses, the encoding of the length will be just the length.)
	 */
	if (vp->vp_ip.prefix == 32) {
		FR_DBUFF_IN_RETURN(&our_dbuff, (uint8_t) 0x00);
		FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, (uint8_t const *) &vp->vp_ipv4addr, sizeof(vp->vp_ipv4addr));
		return fr_dbuff_set(dbuff, &our_dbuff);
	}

	FR_DBUFF_IN_RETURN(&our_dbuff, (uint8_t) (8 - (vp->vp_ip.prefix & 0x07)));

	len = (vp->vp_ip.prefix + 0x07) >> 3;

	if (len) FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, (uint8_t const *) &vp->vp_ipv4addr, len);

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_ipv6_addr(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	 our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	/*
	 *	RFC3779 Section 2.1.1.
	 *
	 *	An IP address or prefix is encoded in the IP address delegation
	 *	extension as a DER-encoded ASN.1 BIT STRING containing the constant
	 *	most-significant bits.  Recall [X.690] that the DER encoding of a BIT
	 *	STRING consists of the BIT STRING type (0x03), followed by (an
	 *	encoding of) the number of value octets, followed by the value.  The
	 *	value consists of an "initial octet" that specifies the number of
	 *	unused bits in the last value octet, followed by the "subsequent
	 *	octets" that contain the octets of the bit string.  (For IP
	 *	addresses, the encoding of the length will be just the length.)
	 */

	/*
	 *	The number of unused bits in the last byte is always zero.
	 */
	FR_DBUFF_IN_RETURN(&our_dbuff, (uint8_t) 0x00);
	FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, (uint8_t const *) &vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_ipv6_prefix(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	 our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	size_t		len;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	/*
	 *	RFC3779 Section 2.1.1.
	 *
	 *	An IP address or prefix is encoded in the IP address delegation
	 *	extension as a DER-encoded ASN.1 BIT STRING containing the constant
	 *	most-significant bits.  Recall [X.690] that the DER encoding of a BIT
	 *	STRING consists of the BIT STRING type (0x03), followed by (an
	 *	encoding of) the number of value octets, followed by the value.  The
	 *	value consists of an "initial octet" that specifies the number of
	 *	unused bits in the last value octet, followed by the "subsequent
	 *	octets" that contain the octets of the bit string.  (For IP
	 *	addresses, the encoding of the length will be just the length.)
	 */

	if (vp->vp_ip.prefix == 128) {
		FR_DBUFF_IN_RETURN(&our_dbuff, (uint8_t) 0x00);
		FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, (uint8_t const *) &vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
		return fr_dbuff_set(dbuff, &our_dbuff);
	}

	FR_DBUFF_IN_RETURN(&our_dbuff, (uint8_t) (8 - (vp->vp_ip.prefix & 0x07)));

	len = (vp->vp_ip.prefix + 0x07) >> 3;

	if (len) FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, (uint8_t const *) &vp->vp_ipv6addr, len);

	return fr_dbuff_set(dbuff, &our_dbuff);
}


static ssize_t fr_der_encode_combo_ip(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	 our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	/*
	 *	RFC5280 Section 4.2.1.6
	 *
	 *	When the subjectAltName extension contains an iPAddress, the address
	 *	MUST be stored in the octet string in "network byte order", as
	 *	specified in [RFC791].  The least significant bit (LSB) of each octet
	 *	is the LSB of the corresponding byte in the network address.  For IP
	 *	version 4, as specified in [RFC791], the octet string MUST contain
	 *	exactly four octets.  For IP version 6, as specified in
	 *	[RFC2460], the octet string MUST contain exactly sixteen octets.
	 */
	if (vp->vp_ip.af == AF_INET) {
		FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, (uint8_t const *) &vp->vp_ipv4addr, sizeof(vp->vp_ipv4addr));
	} else {
		FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, (uint8_t const *) &vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
	}

	return fr_dbuff_set(dbuff, &our_dbuff);
}


static ssize_t fr_der_encode_octetstring(fr_dbuff_t *dbuff, fr_dcursor_t *cursor,
					 UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	/* can be raw! */

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.7 Encoding of an octetstring value
	 *		8.7.1 The encoding of an octetstring value shall be either primitive or constructed at the
	 *		      option of the sender.
	 *			NOTE - Where it is necessary to transfer part of an octet string before the entire
	 *			       octetstring is available, the constructed encoding is used.
	 *		8.7.2 The primitive encoding contains zero, one or more contents octets equal in value to the
	 *		      octets in the data value, in the order they appear in the data value, and with the most
	 *		      significant bit of an octet of the data value aligned with the most significant bit of an
	 *		      octet of the contents octets.
	 *		8.7.3 The contents octets for the constructed encoding shall consist of zero, one, or more
	 *		      encodings.
	 *			NOTE - Each such encoding includes identifier, length, and contents octets, and may
	 *			       include end-of-contents octets if it is constructed.
	 *			8.7.3.1 To encode an octetstring value in this way, it is segmented. Each segment shall
	 *			       consist of a series of consecutive octets of the value. There shall be no
	 *			       significance placed on the segment boundaries.
	 *				NOTE - A segment may be of size zero, i.e. contain no octets.
	 *
	 *	10.2 String encoding forms
	 *		For bitstring, octetstring and restricted character string types, the constructed form of
	 *		encoding shall not be used. (Contrast with 8.23.6.)
	 */
	FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, vp->vp_octets, vp->vp_length);

	return fr_dbuff_set(dbuff, &our_dbuff);
}


static ssize_t fr_der_encode_null(UNUSED fr_dbuff_t *dbuff, fr_dcursor_t *cursor,
				  UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.8 Encoding of a null value
	 *	8.8.1 The encoding of a null value shall be primitive.
	 *	8.8.2 The contents octets shall not contain any octets.
	 * 		NOTE - The length must be zero.
	 */
	if (vp->vp_length != 0) {
		fr_strerror_printf("Null has non-zero length %zu", vp->vp_length);
		return -1;
	}

	return 0;
}

static ssize_t fr_der_encode_oid_from_value(fr_dbuff_t *dbuff, uint64_t value, uint64_t *component, int *count)
{
	fr_dbuff_t	our_dbuff;
	int		i;
	uint64_t	oid;

	/*
	 *	The first subidentifier is the encoding of the first two object identifier components, encoded as:
	 *		(X * 40) + Y
	 *	where X is the first number and Y is the second number.
	 *	The first number is 0, 1, or 2.
	 */
	if (*count == 0) {
		if (!((value == 0) || (value == 1) || (value == 2))) {
			fr_strerror_printf("Invalid value %" PRIu64 " for initial component", value);
			return -1;
		}

		*component = value;
		(*count)++;
		return 0;
	}

	if (*count == 1) {
		if ((*component < 2) && (value > 40)) {
			fr_strerror_printf("Invalid value %" PRIu64 " for second component", value);
			return -1;
		}

		oid = *component * 40 + value;
	} else {
		oid = value;
	}

	our_dbuff = FR_DBUFF(dbuff);

	/*
	 *	Encode the number as 7-bit chunks.  Just brute-force over all bits, as doing that ends
	 *	up being fast enough.
	 *
	 *	i.e. if we did anything else to count bits, it would end up with pretty much the same
	 *	code.
	 */
	for (i = 63; i >= 0; i -= 7) {
		uint8_t more, part;

		part = (oid >> i) & 0x7f;
		if (!part) continue;

		more = ((uint8_t) (i > 0)) << 7;

		FR_DBUFF_IN_RETURN(&our_dbuff, (uint8_t) (more | part));
	}

	(*count)++;

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_oid(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	uint64_t	component;
	int		i, count = 0;
	fr_da_stack_t	da_stack;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);
	fr_assert(vp->vp_type == FR_TYPE_ATTR);

	fr_proto_da_stack_build(&da_stack, vp->vp_attr);
	FR_PROTO_STACK_PRINT(&da_stack, da_stack.depth);

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
	 *		component. NOTE - This packing of the first two object identifier components recognizes that
	 *		only three values are allocated from the root node, and at most 39 subsequent values from nodes
	 *		reached by X = 0 and X = 1. 8.19.5 The numerical value of the ith subidentifier, (2 <= i <= N) is
	 *		that of the (i + 1)th object identifier component.
	 */

	/*
	 *	Parse each OID component.
	 */
	for (i = 0; i < da_stack.depth; i++) {
		ssize_t slen;

		if ((i == 0) && (da_stack.da[0] == attr_oid_tree)) continue; /* don't encode this */

		slen = fr_der_encode_oid_from_value(&our_dbuff, da_stack.da[i]->attr, &component, &count);
		if (slen < 0) return -1;
	}

	if (count <= 2) {
		fr_strerror_printf("Invalid OID '%s' - too short", vp->vp_strvalue);
		return -1;
	}

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_sequence(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t	      *vp;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	fr_assert(fr_type_is_group(vp->vp_type) || fr_type_is_tlv(vp->vp_type));

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
	if (fr_type_is_group(vp->vp_type) && fr_der_flag_is_oid_and_value(vp->da)) {
		return fr_der_encode_oid_and_value(dbuff, cursor, encode_ctx);
	}

	return fr_der_encode_choice(dbuff, cursor, encode_ctx);
}

typedef struct {
	uint8_t	*data;		//!< Pointer to the start of the encoded item (beginning of the tag)
	size_t	 len;		//!< Length of the encoded item (tag + length + value)
} fr_der_encode_set_of_ptr_pairs_t;

/*
 *	Lexicographically sort the set of pairs
 */
static int CC_HINT(nonnull) fr_der_encode_set_of_cmp(void const *one, void const *two)
{
	fr_der_encode_set_of_ptr_pairs_t const *a = one;
	fr_der_encode_set_of_ptr_pairs_t const *b = two;

	if (a->len >= b->len) {
		return memcmp(a->data, b->data, a->len);
	}

	return memcmp(a->data, b->data, b->len);
}

static ssize_t fr_der_encode_set(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	      our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t	     *vp;
	ssize_t		      slen;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	fr_assert(fr_type_is_tlv(vp->vp_type));

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
	 *
	 *	ISO/IEC 8825-1:2021
	 *	8.12 Encoding of a set-of value
	 *		8.12.1 The encoding of a set-of value shall be constructed.
	 *		8.12.2 The text of 8.10.2 applies.
	 *		8.12.3 The order of data values need not be preserved by the encoding and subsequent decoding.
	 *
	 *	11.6 Set-of components
	 *		The encodings of the component values of a set-of value shall appear in ascending order, the
	 *		encodings being compared as octet strings with the shorter components being padded at their
	 *		trailing end with 0-octets.
	 *			NOTE - The padding octets are for comparison purposes only and do not appear in the
	 *			encodings.
	 */

	if (fr_der_flag_is_set_of(vp->da)) {
		/*
		 *	Set-of items will all have the same tag, so we need to sort them lexicographically
		 */
		size_t				  i, count;
		fr_dbuff_t			  work_dbuff;
		fr_der_encode_set_of_ptr_pairs_t *ptr_pairs;
		uint8_t				 *buff;
		fr_da_stack_t	      		  da_stack;
		fr_dcursor_t	      		  child_cursor;

		/*
		 *	This can happen, but is possible.
		 */
		count = fr_pair_list_num_elements(&vp->children);
		if (unlikely(!count)) return 0;

		/*
		 *	Sets can be nested, so we have to use local buffers when sorting.
		 */
		buff = talloc_array(encode_ctx->tmp_ctx, uint8_t, fr_dbuff_remaining(&our_dbuff));
		fr_assert(buff != NULL);

		ptr_pairs = talloc_array(buff, fr_der_encode_set_of_ptr_pairs_t, count);
		if (unlikely(ptr_pairs == NULL)) {
			fr_strerror_const("Failed to allocate memory for set of pointers");
			talloc_free(buff);
			return -1;
		}

		/*
		 *	Now that we have our intermediate buffers, initialize the buffers and start encoding.
		 */
		fr_dbuff_init(&work_dbuff, buff, fr_dbuff_remaining(&our_dbuff));

		fr_proto_da_stack_build(&da_stack, vp->da);

		FR_PROTO_STACK_PRINT(&da_stack, vp->da->depth - 1);

		fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, cursor);

		for (i = 0; fr_dcursor_current(&child_cursor) != NULL; i++) {
			ptr_pairs[i].data = fr_dbuff_current(&work_dbuff);

			slen = encode_value(&work_dbuff, &child_cursor, encode_ctx);
			if (unlikely(slen < 0)) {
				fr_strerror_printf("Failed to encode pair: %s", fr_strerror());
				talloc_free(buff);
				return slen;
			}

			ptr_pairs[i].len = slen;
		}

		fr_assert(i <= count);
		count = i;

		/*
		 *	If there's a "min" for this set, then we can't do anything about it.
		 */
		if (unlikely(!count)) goto done;

		/*
		 *	If there's only one child, we don't need to sort it.
		 */
		if (count > 1) qsort(ptr_pairs, count, sizeof(fr_der_encode_set_of_ptr_pairs_t), fr_der_encode_set_of_cmp);

		/*
		 *	The data in work_dbuff is always less than the data in the our_dbuff, so we don't need
		 *	to check the return value here.
		 */
		for (i = 0; i < count; i++) {
			(void) fr_dbuff_in_memcpy(&our_dbuff, ptr_pairs[i].data, ptr_pairs[i].len);
		}

	done:
		talloc_free(buff);

		return fr_dbuff_set(dbuff, &our_dbuff);
	}

	/*
	 *	Children of a set are ordered by tag.  However, as each tag can only be used once, this is a
	 *	unique order.
	 */
	fr_pair_list_sort(&vp->children, fr_der_pair_cmp_by_da_tag);

	return fr_der_encode_choice(dbuff, cursor, encode_ctx);
}

static ssize_t fr_der_encode_utc_time(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	 our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const	*vp;
	fr_sbuff_t	 time_sbuff;
	char		 fmt_time[50] = { 0 };
	size_t		 i;

	fmt_time[0] = '\0';
	time_sbuff  = FR_SBUFF_OUT(fmt_time, sizeof(fmt_time));

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.25 Encoding for values of the useful types
	 *		The following "useful types" shall be encoded as if they had been replaced by their definitions
	 *		given in clauses 46-48 of Rec. ITU-T X.680 | ISO/IEC 8824-1:
	 *			- generalized time;
	 *			- universal time;
	 *			- object descriptor.
	 *
	 *	8.26 Encoding for values of the TIME type and the useful time types
	 *		8.26 Encoding for values of the TIME type and the useful time types 8.26.1 Encoding for values
	 *		of the TIME type NOTE - The defined time types are subtypes of the TIME type, with the same
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
	fr_unix_time_to_str(&time_sbuff, vp->vp_date, FR_TIME_RES_SEC, true);

	/*
	 *	Remove the century from the year
	 */
	fr_sbuff_shift(&time_sbuff, 2, false);

	/*
	 *	Trim the time string of any unwanted characters
	 */
	for (i = 0; i < sizeof(fmt_time); i++) {
		if (fmt_time[i] == '\0') {
			break;
		}

		if ((fmt_time[i] == '-') || (fmt_time[i] == 'T') || (fmt_time[i] == ':')) {
			size_t j = i;

			while (fmt_time[j] != '\0') {
				fmt_time[j] = fmt_time[j + 1];
				j++;
			}

			fmt_time[j] = '\0';

			continue;
		}
	}

	FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, fmt_time, DER_UTC_TIME_LEN);

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_generalized_time(fr_dbuff_t *dbuff, fr_dcursor_t *cursor,
					      UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t 	 our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	fr_sbuff_t	 time_sbuff;
	char		 fmt_time[50] = { 0 };
	size_t		 i;

	fmt_time[0] = '\0';
	time_sbuff  = FR_SBUFF_OUT(fmt_time, sizeof(fmt_time));

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.25 Encoding for values of the useful types
	 *		The following "useful types" shall be encoded as if they had been replaced by their definitions
	 *		given in clauses 46-48 of Rec. ITU-T X.680 | ISO/IEC 8824-1:
	 *			- generalized time;
	 *			- universal time;
	 *			- object descriptor.
	 *
	 *	8.26 Encoding for values of the TIME type and the useful time types
	 *		8.26 Encoding for values of the TIME type and the useful time types 8.26.1 Encoding for values
	 *		of the TIME type NOTE - The defined time types are subtypes of the TIME type, with the same
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

	fr_unix_time_to_str(&time_sbuff, vp->vp_date, FR_TIME_RES_USEC, true);

	/*
	 *	Trim the time string of any unwanted characters
	 */
	for (i = 0; i < sizeof(fmt_time); i++) {
		if (fmt_time[i] == '\0') {
			break;
		}

		if ((fmt_time[i] == '-') || (fmt_time[i] == 'T') || (fmt_time[i] == ':')) {
			size_t j = i;

			while (fmt_time[j] != '\0') {
				fmt_time[j] = fmt_time[j + 1];
				j++;
			}

			fmt_time[j] = '\0';

			continue;
		}

		if (fmt_time[i] == '.') {
			/*
			 *	Remove any trailing zeros
			 */
			size_t j = strlen(fmt_time) - 2;

			while (fmt_time[j] == '0') {
				fmt_time[j]	= fmt_time[j + 1];
				fmt_time[j + 1] = '\0';
				j--;
			}

			/*
			 *	Remove the decimal point if there are no fractional seconds
			 */
			if (j == i) {
				fmt_time[i]	= fmt_time[i + 1];
				fmt_time[i + 1] = '\0';
			}
		}
	}

	FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, fmt_time, i);

	return fr_dbuff_set(dbuff, &our_dbuff);
}

/** Encode a CHOICE type
 *
 * @param[in] dbuff		Buffer to write the encoded data to
 * @param[in] cursor		Cursor to the pair to encode
 * @param[in] encode_ctx	Encoding context
 *
 * @return	Number of bytes written to the buffer, or -1 on error
 */
static ssize_t fr_der_encode_choice(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t 	      our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	fr_da_stack_t	      da_stack;
	fr_dcursor_t	      child_cursor;
	ssize_t		 slen = 0;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	fr_proto_da_stack_build(&da_stack, vp->da);

	FR_PROTO_STACK_PRINT(&da_stack, vp->da->depth - 1);

	fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, cursor);

	slen = fr_pair_cursor_to_network(&our_dbuff, &da_stack, vp->da->depth - 1, &child_cursor, encode_ctx, encode_pair);
	if (slen < 0) return -1;

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_X509_extensions(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	  our_dbuff = FR_DBUFF(dbuff);
	fr_dbuff_marker_t outer_seq_len_start;
	fr_dcursor_t	  child_cursor, root_cursor, parent_cursor;
	fr_pair_t const	 *vp;
	ssize_t		  slen	      = 0;
	size_t		  is_critical = 0;
	uint64_t	  max, num;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	fr_assert(fr_type_is_group(vp->vp_type));

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

	max = fr_der_flag_max(vp->da); /* Maximum number of extensions specified in the dictionary */
	num = 0;

	slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_SEQUENCE, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_CONSTRUCTED);
	if (slen < 0) return slen;

	fr_dbuff_marker(&outer_seq_len_start, &our_dbuff);
	FR_DBUFF_ADVANCE_RETURN(&our_dbuff, 1);

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&our_dbuff), fr_dbuff_used(&our_dbuff),"BEFORE encoded X509 extension");

	fr_pair_dcursor_child_iter_init(&root_cursor, &vp->children, cursor);
	fr_dcursor_copy(&parent_cursor, &root_cursor);

	while (fr_dcursor_current(&parent_cursor)) {
		uint64_t	  component;
		int		  count;
		fr_dbuff_marker_t length_start, inner_seq_len_start;
		fr_pair_t	  *child;

		/*
		 *	Extensions are sequences or sets containing 2 items:
		 *	1. The first item is the OID
		 *	2. The second item is the value
		 *
		 *	Note: The value may be a constructed or primitive type
		 */

		if (num >= max) {
			fr_strerror_printf("Too many X509 extensions (%" PRIu64 ")", max);
			break;
		}

		slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_SEQUENCE, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_CONSTRUCTED);
		if (slen < 0) return slen;

		fr_dbuff_marker(&inner_seq_len_start, &our_dbuff);
		FR_DBUFF_ADVANCE_RETURN(&our_dbuff, 1);

		/*
		 *	Encode the OID portion of the extension
		 */
		slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_OID, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMITIVE);
		if (slen < 0) return slen;

		fr_dbuff_marker(&length_start, &our_dbuff);
		FR_DBUFF_ADVANCE_RETURN(&our_dbuff, 1);

		/*
		 *	Walk through the children until we find either an attribute marked as an extension, or one with
		 *	no children (which is an unknown OID).
		 *
		 *	We will use this to construct the OID to encode, as well as to get the actual value of the
		 *	extension.
		 */
		fr_dcursor_copy(&child_cursor, &parent_cursor);
		count = 0;

		while ((child = fr_dcursor_current(&child_cursor)) != NULL) {
			PAIR_VERIFY(child);

			FR_PROTO_TRACE("Child: %s", child->da->name);

			if (!is_critical && (strcmp(child->da->name, "Critical") == 0)) {
				/*
				 *	We don't encode the critical flag
				 */
				is_critical = fr_pair_list_num_elements(&child->children);
				FR_PROTO_TRACE("Critical flag: %zu", is_critical);

				fr_pair_dcursor_child_iter_init(&parent_cursor, &child->children, &child_cursor);
				goto next;
			}

			/*
			 *	If we find a normal leaf data type, we don't encode it.  But we do encode leaf data
			 *	types which are marked up as needing OID leaf encoding.
			 */
			if (!fr_type_is_structural(child->vp_type) && !fr_der_flag_leaf(child->da) && !child->da->flags.is_raw) {
				FR_PROTO_TRACE("Found non-structural child %s", child->da->name);

				fr_dcursor_copy(&child_cursor, &parent_cursor);
				break;
			}

			slen = fr_der_encode_oid_from_value(&our_dbuff, child->da->attr, &component, &count);
			if (unlikely(slen < 0)) return -1;

			/*
			 *	We've encoded a leaf data type, or a raw one.  Stop encoding it.
			 */
			if (!fr_type_is_structural(child->vp_type)) break;

			/*
			 *	Unless this was the last child (marked as an extension), there should only be one child
			 *	- representing the next OID in the extension
			 */
			if (fr_pair_list_num_elements(&child->children) > 1) break;

		next:
			if (fr_der_flag_leaf(child->da)) break;

			fr_pair_dcursor_child_iter_init(&child_cursor, &child->children, &child_cursor);
		}

		/*
		 *	Encode the length of the OID
		 */
		slen = fr_der_encode_len(&our_dbuff, &length_start);
		if (slen < 0) return slen;

		/*
		 *	Encode the critical flag
		 */
		if (is_critical) {
			/*
			 *	Universal+Boolean flag is always 0x01. Length of a boolean is always 0x01.
			 *	True is always 0xff.
			 */
			FR_DBUFF_IN_BYTES_RETURN(&our_dbuff, (uint8_t) 0x01, (uint8_t) 0x01, (uint8_t)(0xff));
			is_critical--;
		}

		/*
		 *	Encode the value portion of the extension
		 */
		slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_OCTETSTRING, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMITIVE);
		if (slen < 0) return slen;

		fr_dbuff_marker(&length_start, &our_dbuff);
		FR_DBUFF_ADVANCE_RETURN(&our_dbuff, 1);

		/*
		 *	Encode the data
		 */
		slen = encode_value(&our_dbuff, &child_cursor, encode_ctx);
		if (slen < 0) return slen;

		/*
		 *	Encode the length of the value
		 */
		slen = fr_der_encode_len(&our_dbuff, &length_start);
		if (slen < 0) return slen;

		/*
		 *	Encode the length of the extension (OID + Value portions)
		 */
		slen = fr_der_encode_len(&our_dbuff, &inner_seq_len_start);
		if (slen < 0) return -1;

		if (is_critical) {
			fr_dcursor_next(&parent_cursor);
			num++;
			continue;
		}

		FR_PROTO_HEX_DUMP(fr_dbuff_start(&our_dbuff), fr_dbuff_behind(&outer_seq_len_start) + 2,
				  "Encoded X509 extension");

		fr_dcursor_next(&root_cursor);
		fr_dcursor_copy(&parent_cursor, &root_cursor);
		num++;
	}

	/*
	 *	Encode the length of the extensions
	 */
	slen = fr_der_encode_len(&our_dbuff, &outer_seq_len_start);
	if (slen < 0) return slen;

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&our_dbuff), slen, "Encoded X509 extensions");

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_oid_and_value(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	  our_dbuff = FR_DBUFF(dbuff);
	fr_dbuff_marker_t length_start;
	fr_dcursor_t	  child_cursor, parent_cursor = *cursor;
	fr_pair_t const	  *vp, *child;
	ssize_t		  slen	 = 0;
	uint64_t	  component;
	int		  count;

	vp = fr_dcursor_current(&parent_cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	fr_assert(fr_type_is_group(vp->vp_type));

	/*
	 *	A very common pattern in DER encoding is ro have a sequence of set containing two things: an OID and a
	 *	value, where the OID is used to determine how to decode the value.
	 *	We will be decoding the OID first and then try to find the attribute associated with that OID to then
	 *	decode the value. If no attribute is found, one will be created and the value will be stored as raw
	 *	octets in the attribute.
	 *
	 *	Note: The value may be a constructed or primitive type
	 */

	slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_OID, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMITIVE);
	if (slen < 0) return slen;

	fr_dbuff_marker(&length_start, &our_dbuff);
	FR_DBUFF_ADVANCE_RETURN(&our_dbuff, 1);

	/*
	 *	Walk through the children until we find either an attribute marked as an oid leaf, or one with
	 *	no children (which is an unknown OID).
	 *
	 *	We will use this to construct the OID to encode, as well as to get the actual value of the
	 *	pair.
	 */
	fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, &parent_cursor);
	count = 0;

	while ((child = fr_dcursor_current(&child_cursor)) != NULL) {
		PAIR_VERIFY(child);

		/*
		 *	If we find a normal leaf data type, we don't encode it.  But we do encode leaf data
		 *	types which are marked up as needing OID leaf encoding.
		 */
		if (!fr_type_is_structural(child->vp_type) && !fr_der_flag_leaf(child->da) && !child->da->flags.is_raw) {
			FR_PROTO_TRACE("Found non-structural child %s", child->da->name);

			fr_dcursor_copy(&child_cursor, &parent_cursor);
			break;
		}

		slen = fr_der_encode_oid_from_value(&our_dbuff, child->da->attr, &component, &count);
		if (unlikely(slen < 0)) return -1;

		/*
		 *	We've encoded a leaf data type, or a raw one.  Stop encoding it.
		 */
		if (!fr_type_is_structural(child->vp_type)) break;

		/*
		 *	Some structural types can be marked as a leaf for the purposes of OID encoding.
		 */
		if (fr_der_flag_leaf(child->da)) break;

		/*
		 *	Unless this was the last child (marked as an oid leaf), there should only be one child
		 *	- representing the next OID in the pair
		 */
		if (fr_pair_list_num_elements(&child->children) > 1) break;

		fr_pair_dcursor_child_iter_init(&child_cursor, &child->children, &child_cursor);
	}

	/*
	 *	Encode the length of the OID
	 */
	slen = fr_der_encode_len(&our_dbuff, &length_start);
	if (slen < 0) return slen;

	/*
	 *	And then encode the actual data.
	 */
	slen = encode_value(&our_dbuff, &child_cursor, encode_ctx);
	if (slen < 0) return slen;

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	 our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;

	vp = fr_dcursor_current(cursor);
	PAIR_VERIFY(vp);
	fr_assert(!vp->da->flags.is_raw);

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.23 Encoding for values of the restricted character string types
	 *		8.23.1 The data value consists of a string of characters from the character set specified in
	 *			the ASN.1 type definition.
	 *		8.23.2 Each data value shall be encoded independently of other data values of the same type.
	 *
	 *	10.2 String encoding forms
	 *		For bitstring, octetstring and restricted character string types, the constructed form of
	 *		encoding shall not be used. (Contrast with 8.23.6.)
	 *
	 * 	NOTE:
	 * 		We DO NOT check for restricted character sets here. This should be done as a separate validation
	 * 		step. Here we simply trust that administrators have done their job and are providing us with
	 * 		valid data.
	 */

	FR_DBUFF_IN_MEMCPY_RETURN(&our_dbuff, vp->vp_strvalue, vp->vp_length);

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static const fr_der_tag_encode_t tag_funcs[FR_DER_TAG_MAX] = {
	[FR_DER_TAG_BOOLEAN]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_boolean },
	[FR_DER_TAG_INTEGER]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_integer },
	[FR_DER_TAG_BITSTRING]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_bitstring },
	[FR_DER_TAG_OCTETSTRING]      = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_octetstring },
	[FR_DER_TAG_NULL]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_null },
	[FR_DER_TAG_OID]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_oid },
	[FR_DER_TAG_ENUMERATED]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_enumerated },
	[FR_DER_TAG_UTF8_STRING]      = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_string },
	[FR_DER_TAG_SEQUENCE]	      = { .constructed = FR_DER_TAG_CONSTRUCTED, .encode = fr_der_encode_sequence },
	[FR_DER_TAG_SET]	      = { .constructed = FR_DER_TAG_CONSTRUCTED, .encode = fr_der_encode_set },
	[FR_DER_TAG_PRINTABLE_STRING] = { .constructed = FR_DER_TAG_PRIMITIVE,
					  .encode      = fr_der_encode_string },
	[FR_DER_TAG_T61_STRING]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_string },
	[FR_DER_TAG_IA5_STRING]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_string },
	[FR_DER_TAG_UTC_TIME]	      = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_utc_time },
	[FR_DER_TAG_GENERALIZED_TIME] = { .constructed = FR_DER_TAG_PRIMITIVE,
					  .encode      = fr_der_encode_generalized_time },
	[FR_DER_TAG_VISIBLE_STRING]   = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_string },
	[FR_DER_TAG_GENERAL_STRING]   = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_string },
	[FR_DER_TAG_UNIVERSAL_STRING] = { .constructed = FR_DER_TAG_PRIMITIVE,
					  .encode      = fr_der_encode_string },
};

static const fr_der_tag_encode_t type_funcs[FR_TYPE_MAX] = {
	[FR_TYPE_IPV4_ADDR]    	  = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_ipv4_addr },
	[FR_TYPE_IPV4_PREFIX]  	  = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_ipv4_prefix },
	[FR_TYPE_IPV6_ADDR]    	  = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_ipv6_addr },
	[FR_TYPE_IPV6_PREFIX]	  = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_ipv6_prefix },

	[FR_TYPE_COMBO_IP_ADDR]	  = { .constructed = FR_DER_TAG_PRIMITIVE, .encode = fr_der_encode_combo_ip },
};


/** Encode the length field of a DER structure
 *
 *  The input dbuff is composed of the following data:
 *
 *	1 byte of nothing (length_start).  Where the "length length" will be written to.
 *	N bytes of data.  dbuff is pointing to the end of the encoded data.
 *
 *  We have to either write a length to length_start (if it's < 0x7f),
 *
 *  OR we figure out how many bytes we need to encode the length,
 *  shift the data to the right to make room, and then encode the
 *  length.
 *
 * @param dbuff		The buffer to update with the length field
 * @param length_start	The start of the length field
 * @return
 *	- <0 for "cannot extend the input buffer by the needed "length length".
 *	- 1 for "success".  Note that 'length_start' WILL be updated after this call,
 *	  and the caller should just release it immediately.
 */
static ssize_t fr_der_encode_len(fr_dbuff_t *dbuff, fr_dbuff_marker_t *length_start)
{
	size_t		  i, len_len;
	size_t		  tmp, datalen;

	datalen = fr_dbuff_current(dbuff) - fr_dbuff_current(length_start) - 1;

	/*
	 *	If the length can fit in a single byte, we don't need to extend the size of the length field
	 */
	if (datalen <= 0x7f) {
		(void) fr_dbuff_in(length_start, (uint8_t) datalen);
		return 1;
	}

	/*
	 *	Calculate the number of bytes needed to encode the length.
	 */
	for (tmp = datalen, len_len = 0; tmp != 0; tmp >>= 8) {
		len_len++;
	}

	/*
	 *	DER says that the length field cannot be more than
	 *	0x7f.  Since sizeof(datalen) == 8, we can always
	 *	encode the length field.
	 */
	fr_assert(len_len > 0);
	fr_assert(len_len < 0x7f);

	(void) fr_dbuff_in(length_start, (uint8_t) (0x80 | len_len));

	/*
	 *	This is the only operation which can fail.  The dbuff
	 *	is currently set to the end of the encoded data.  We
	 *	need to ensure that there is sufficient room in the
	 *	dbuff to encode the additional bytes.
	 *
	 *	fr_dbuff_set() checks if the length exceeds the input
	 *	buffer.  But it does NOT extend the buffer by reading
	 *	more data, if more data is needed.  So we need to
	 *	manually extend the dbuff here.
	 */
	FR_DBUFF_EXTEND_LOWAT_OR_RETURN(dbuff, len_len);

	/*
	 *	Reset the dbuff to the new start, where the data
	 *	should be.
	 */
	fr_dbuff_set(dbuff, fr_dbuff_current(length_start) + len_len);

	/*
	 *	Move the data over.  Note that the move updates BOTH
	 *	input and output dbuffs.  As a result, we have to wrap
	 *	'length_start' in a temporary dbuff, so that it
	 *	doesn't get updated by the move.
	 */
	fr_dbuff_move(dbuff, &FR_DBUFF(length_start), datalen);

	/*
	 *	Encode high bits first, but only the non-zero ones.
	 */
	for (i = len_len; i > 0; i--) {
		(void) fr_dbuff_in(length_start, (uint8_t)((datalen) >> ((i - 1) * 8)));
	}

	return 1;
}

/** Encode a DER tag
 *
 * @param dbuff		The buffer to write the tag to
 * @param tag_num	The tag number
 * @param tag_class	The tag class
 * @param constructed	Whether the tag is constructed
 *
 * @return		The number of bytes written to the buffer
 */
static inline CC_HINT(always_inline) ssize_t
	fr_der_encode_tag(fr_dbuff_t *dbuff, fr_der_tag_t tag_num, fr_der_tag_class_t tag_class,
			  fr_der_tag_constructed_t constructed)
{
	fr_dbuff_t	our_dbuff = FR_DBUFF(dbuff);
	uint8_t 	tag_byte;

	tag_byte = (tag_class & DER_TAG_CLASS_MASK) | (constructed & DER_TAG_CONSTRUCTED_MASK) |
		   (tag_num & DER_TAG_NUM_MASK);

	FR_DBUFF_IN_RETURN(&our_dbuff, tag_byte);

	return fr_dbuff_set(dbuff, &our_dbuff);
}

/** Encode a DER structure
 *
 * @param[out] dbuff		The buffer to write the structure to
 * @param[in] cursor	The cursor to the structure to encode
 * @param[in] encode_ctx	The encoding context
 *
 * @return		The number of bytes written to the buffer
 */
static ssize_t encode_value(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, void *encode_ctx)
{
	fr_pair_t const	    *vp;
	fr_dbuff_t	     our_dbuff;
	fr_dbuff_marker_t    marker;
	fr_der_tag_encode_t const *func;
	fr_der_tag_t         tag;
	fr_der_tag_class_t   tag_class;
	fr_der_encode_ctx_t *uctx = encode_ctx;
	ssize_t		     slen = 0;
	fr_der_attr_flags_t const *flags;

	if (unlikely(cursor == NULL)) {
		fr_strerror_const("No cursor to encode");
		return -1;
	}

	vp = fr_dcursor_current(cursor);
	if (unlikely(!vp)) {
		fr_strerror_const("No pair to encode");
		return -1;
	}

	PAIR_VERIFY(vp);

	FR_PROTO_TRACE("Encoding %s", vp->da->name);

	flags = fr_der_attr_flags(vp->da);
	fr_assert(flags != NULL);

	/*
	 *	Raw things get encoded as-is, so that we can encode the correct tag and class.
	 */
	if (unlikely(vp->da->flags.is_raw)) {
		fr_assert(vp->vp_type == FR_TYPE_OCTETS);

		slen = fr_der_encode_octetstring(dbuff, cursor, encode_ctx);
		if (slen < 0) return 0;

		fr_dcursor_next(cursor);
		return slen;
	}

	our_dbuff = FR_DBUFF(dbuff);

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

	if (flags->has_default_value) {
		/*
		 *	Skip encoding the default value, as per ISO/IEC 8825-1:2021 11.5
		 */
		if (fr_value_box_cmp(&vp->data, flags->default_value) == 0) {
			FR_PROTO_TRACE("Skipping default value");
			fr_dcursor_next(cursor);
			return 0;
		}
	}

	if (unlikely(flags->is_choice)) {
		slen = fr_der_encode_choice(&our_dbuff, cursor, uctx);
		if (slen < 0) return slen;

		fr_dcursor_next(cursor);
		return fr_dbuff_set(dbuff, &our_dbuff);
	}

	tag = flags->der_type;
	if (!tag) tag = fr_type_to_der_tag_default(vp->vp_type);

	if (unlikely(tag == FR_DER_TAG_INVALID)) {
		fr_strerror_printf("No tag defined for type %s", fr_type_to_str(vp->vp_type));
		return -1;
	}

	fr_assert(tag < FR_DER_TAG_MAX);

	func = &type_funcs[vp->vp_type];
	if (!func->encode) func = &tag_funcs[tag];

	fr_assert(func != NULL);
	fr_assert(func->encode != NULL);

	/*
	 *	Default flag class is 0, which is FR_DER_CLASS_UNIVERSAL.
	 */
	tag_class = flags->class;

	/*
	 *	We call the DER type encoding function based on its
	 *	tag, but we might need to encode an option value
	 *	instead of a tag.
	 */
	if (flags->is_option) tag = flags->option;

	slen = fr_der_encode_tag(&our_dbuff, tag, tag_class, func->constructed);
	if (slen < 0) return slen;

	/*
	 *	Mark and reserve space in the buffer for the length field
	 */
	fr_dbuff_marker(&marker, &our_dbuff);
	FR_DBUFF_ADVANCE_RETURN(&our_dbuff, 1);

	if (flags->is_extensions) {
		slen = fr_der_encode_X509_extensions(&our_dbuff, cursor, uctx);
	} else {

		slen = func->encode(&our_dbuff, cursor, uctx);
	}
	if (slen < 0) return slen;

	/*
	*	Encode the length of the value
	*/
	slen = fr_der_encode_len(&our_dbuff, &marker);
	if (slen < 0) return slen;

	fr_dcursor_next(cursor);
	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_list_t *vps, uint8_t *data, size_t data_len,
				   void *encode_ctx)
{
	fr_dbuff_t   dbuff;
	fr_dcursor_t cursor;
	ssize_t	     slen;

	fr_dbuff_init(&dbuff, data, data_len);

	fr_pair_dcursor_init(&cursor, vps);

	slen = encode_value(&dbuff, &cursor, encode_ctx);

	if (slen < 0) {
		fr_strerror_printf("Failed to encode data: %s", fr_strerror());
		return -1;
	}

	return slen;
}

/*
 *	Test points
 */
static int encode_test_ctx(void **out, TALLOC_CTX *ctx, UNUSED fr_dict_t const *dict,
			   UNUSED fr_dict_attr_t const *root_da)
{
	fr_der_encode_ctx_t *test_ctx;

	test_ctx = talloc_zero(ctx, fr_der_encode_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->tmp_ctx	     = talloc(test_ctx, uint8_t);

	*out = test_ctx;

	return 0;
}

extern fr_test_point_pair_encode_t der_tp_encode_pair;
fr_test_point_pair_encode_t	   der_tp_encode_pair = {
	       .test_ctx = encode_test_ctx,
	       .func	 = encode_value,
};

extern fr_test_point_proto_encode_t der_tp_encode_proto;
fr_test_point_proto_encode_t	    der_tp_encode_proto = {
	       .test_ctx = encode_test_ctx,
	       .func	 = fr_der_encode_proto,
};
