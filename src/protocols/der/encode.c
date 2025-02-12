
#include <freeradius-devel/build.h>
#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/dcursor.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/dict_ext.h>
#include <freeradius-devel/util/encode.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/struct.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/value.h>
#include "der.h"

typedef struct {
	fr_dbuff_marker_t encoding_start;	//!< This is the start of the encoding. It is NOT the same as the start of the
	uint8_t *tmp_ctx;	 		//!< Temporary context for decoding.
						//!< encoded value. It is the position of the tag.
	size_t encoding_length;			//!< This is the length of the entire encoding. It is NOT the same as the length
						//!< of the encoded value. It includes the tag, length, and value.
	ssize_t value_length;			//!< This is the number of bytes used by the encoded value. It is NOT the
						//!< same as the encoded length field.
	uint8_t *encoded_value;			//!< This is a pointer to the start of the encoded value.
} fr_der_encode_ctx_t;

#define DER_MAX_STR 16384

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

static ssize_t fr_der_encode_boolean(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx) CC_HINT(nonnull(1,2));
static ssize_t fr_der_encode_integer(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx) CC_HINT(nonnull(1,2));
static ssize_t fr_der_encode_bitstring(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx) CC_HINT(nonnull);
static ssize_t fr_der_encode_octetstring(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx) CC_HINT(nonnull);
static ssize_t fr_der_encode_null(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx) CC_HINT(nonnull(2));
static ssize_t fr_der_encode_oid(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx) CC_HINT(nonnull(1,2));
static ssize_t fr_der_encode_enumerated(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx) CC_HINT(nonnull(1,2));
static ssize_t fr_der_encode_sequence(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx) CC_HINT(nonnull);
static ssize_t fr_der_encode_set(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx) CC_HINT(nonnull);
static ssize_t fr_der_encode_utc_time(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx) CC_HINT(nonnull(1,2));
static ssize_t fr_der_encode_generalized_time(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx) CC_HINT(nonnull(1,2));

static ssize_t fr_der_encode_oid_value_pair(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx) CC_HINT(nonnull);

static ssize_t fr_der_encode_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx) CC_HINT(nonnull(1,2));

static ssize_t fr_der_encode_len(fr_dbuff_t *dbuff, fr_dbuff_marker_t *length_start, ssize_t len) CC_HINT(nonnull);
static inline CC_HINT(always_inline) ssize_t
	fr_der_encode_tag(fr_dbuff_t *dbuff, fr_der_tag_num_t tag_num, fr_der_tag_class_t tag_class,
			  fr_der_tag_constructed_t constructed) CC_HINT(nonnull);
static ssize_t encode_value(fr_dbuff_t *dbuff, fr_da_stack_t *da_stack, unsigned int depth, fr_dcursor_t *cursor,
			    void *encode_ctx);
static ssize_t encode_pair(fr_dbuff_t *dbuff, fr_da_stack_t *da_stack, unsigned int depth, fr_dcursor_t *cursor,
			   void *encode_ctx);
static ssize_t der_encode_pair(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, void *encode_ctx) CC_HINT(nonnull);

static fr_der_tag_encode_t tag_funcs[] = {
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

	return CMP_PREFER_SMALLER(fr_der_flag_subtype(my_a->da), fr_der_flag_subtype(my_b->da));
}

static ssize_t fr_der_encode_boolean(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	 our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	uint8_t		 value;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode boolean");
		return -1;
	}

	PAIR_VERIFY(vp);

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

	fr_dbuff_in(&our_dbuff, (uint8_t)(value ? DER_BOOLEAN_TRUE : DER_BOOLEAN_FALSE));

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_integer(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	 our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	int64_t		 value;
	uint8_t		 first_octet = 0;
	ssize_t		 slen	     = 0;
	size_t		 i	     = 0;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode integer");
		return -1;
	}

	PAIR_VERIFY(vp);

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
	value = vp->vp_int64;

	for (; i < sizeof(value); i++) {
		uint8_t byte = (uint8_t)(value >> (((sizeof(value) * 8) - 8) - (i * 8)));

		if (slen == 0) {
			first_octet = byte;
			slen++;
			continue;
		} else if (slen == 1) {
			/*
			 *	8.3.2 If the contents octets of an integer value encoding consist of more than one
			 *	octet, then the bits of the first octet and bit 8 of the second octet: a) shall not all
			 *	be ones; and b) shall not all be zero.
			 */
			if ((first_octet == 0xff && (byte & 0x80)) || (first_octet == 0x00 && byte >> 7 == 0)) {
				if (i == sizeof(value) - 1) {
					/*
					 * 	If this is the only byte, then we can encode it as a single byte.
					 */
					fr_dbuff_in(&our_dbuff, byte);
					continue;
				}

				first_octet = byte;
				continue;
			} else {
				fr_dbuff_in(&our_dbuff, first_octet);
				fr_dbuff_in(&our_dbuff, byte);
				slen++;
				continue;
			}
		}

		fr_dbuff_in(&our_dbuff, byte);
		slen++;
	}

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_bitstring(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	uint8_t const	*value = NULL;
	ssize_t		 slen;
	uint8_t		 unused_bits = 0;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode bitstring");
		return -1;
	}

	PAIR_VERIFY(vp);

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

	if (fr_type_is_struct(vp->vp_type)) {
		/*
		 *	For struct type, we need to encode the struct as a bitstring using the
		 *	fr_struct_to_network function.
		 */
		unsigned int	  depth = vp->da->depth - 1;
		fr_da_stack_t	  da_stack;
		fr_dbuff_t	  work_dbuff = FR_DBUFF(&our_dbuff);
		fr_dbuff_marker_t unused_bits_marker;
		uint8_t  	last_byte = 0;

		fr_dbuff_marker(&unused_bits_marker, &work_dbuff);
		fr_dbuff_advance(&work_dbuff, 1);

		fr_proto_da_stack_build(&da_stack, vp->da);

		FR_PROTO_STACK_PRINT(&da_stack, depth);

		slen = fr_struct_to_network(&work_dbuff, &da_stack, depth, cursor, encode_ctx, NULL, NULL);
		if (slen < 0) {
			fr_strerror_printf("Failed to encode struct: %s", fr_strerror());
		error:
			fr_dbuff_marker_release(&unused_bits_marker);
			return slen;
		}

		/*
		 *	We need to trim any empty trailing octets
		 */
		while (slen > 1 && fr_dbuff_current(&work_dbuff) != fr_dbuff_start(&work_dbuff)) {
			uint8_t byte;

			/*
			 *	Move the dbuff cursor back by one byte
			 */
			fr_dbuff_set(&work_dbuff, fr_dbuff_current(&work_dbuff) - sizeof(byte));

			if (fr_dbuff_out(&byte, &work_dbuff) < 0) {
				fr_strerror_const("Failed to read byte");
				slen = -1;
				goto error;
			}

			if (byte == 0) {
				/*
				 *	Trim this byte from the buff
				 */
				fr_dbuff_set_end(&work_dbuff, fr_dbuff_current(&work_dbuff) - sizeof(byte));
				fr_dbuff_set(&work_dbuff, fr_dbuff_current(&work_dbuff) - (sizeof(byte) * 2));
				slen--;
			} else {
				break;
			}
		}

		/*
		 *	Grab the last octet written to the dbuff and count the number of trailing 0 bits
		 */
		if (fr_dbuff_out(&last_byte, &work_dbuff) < 0) {
			fr_strerror_const("Failed to read last byte");
			slen = -1;
			goto error;
		}

		while ( last_byte != 0 && (last_byte & 0x01) == 0) {
			unused_bits++;
			last_byte >>= 1;
		}

		/*
		 *	Write the unused bits
		 */
		fr_dbuff_set(&our_dbuff, fr_dbuff_current(&unused_bits_marker));
		fr_dbuff_marker_release(&unused_bits_marker);
		fr_dbuff_in_memcpy(&our_dbuff, &unused_bits, 1);

		/*
		 *	Copy the work dbuff to the output dbuff
		 */
		fr_dbuff_set(&work_dbuff, &our_dbuff);
		if (fr_dbuff_in_memcpy(&our_dbuff, &work_dbuff, slen) <= 0) {
			fr_strerror_const("Failed to copy bitstring value");
			return -1;
		}

		return fr_dbuff_set(dbuff, &our_dbuff);
	}

	/*
	 *	For octets type, we do not need to write the unused bits portion
	 *	because this information should be retained when encoding/decoding.
	 */

	value = vp->vp_octets;
	slen  = (ssize_t)vp->vp_length;

	if (slen == 0) {
		fr_dbuff_in(&our_dbuff, 0x00);
		fr_dbuff_set(dbuff, &our_dbuff);
	}

	if (fr_dbuff_in_memcpy(&our_dbuff, value, slen) <= 0) {
		fr_strerror_const("Failed to copy bitstring value");
		return -1;
	}

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_octetstring(fr_dbuff_t *dbuff, fr_dcursor_t *cursor,
					 UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	uint8_t const	*value = NULL;
	ssize_t		 slen;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode octet string");
		return -1;
	}

	PAIR_VERIFY(vp);

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

	value = vp->vp_octets;
	slen  = vp->vp_length;

	if (fr_dbuff_in_memcpy(&our_dbuff, value, slen) < slen) {
		fr_strerror_const("Failed to copy octet string value");
		return -1;
	}

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_null(UNUSED fr_dbuff_t *dbuff, fr_dcursor_t *cursor,
				  UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_pair_t const *vp;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode null");
		return -1;
	}

	PAIR_VERIFY(vp);

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.8 Encoding of a null value
	 *	8.8.1 The encoding of a null value shall be primitive.
	 *	8.8.2 The contents octets shall not contain any octets.
	 * 		NOTE – The length octet is zero.
	 */
	if (vp->vp_length != 0) {
		fr_strerror_printf("Null has non-zero length %" PRIuPTR, vp->vp_length);
		return -1;
	}

	return 0;
}

static ssize_t fr_der_encode_oid_to_str(fr_dbuff_t *dbuff, const char *oid_str)
{
	fr_dbuff_t our_dbuff = FR_DBUFF(dbuff);
	char	 buffer[21] = { 0 };
	uint64_t subidentifier	       = 0;
	uint8_t	 first_component       = 0;
	size_t	 buffer_len	       = 0;
	size_t	 index		       = 0, bit_index;
	bool	 started_subidentifier = false, subsequent = false;

	/*
	 *	The first subidentifier is the encoding of the first two object identifier components, encoded as:
	 *		(X * 40) + Y
	 *	where X is the first number and Y is the second number.
	 *	The first number is 0, 1, or 2.
	 */

	first_component = (uint8_t)(strtol(&oid_str[0], NULL, 10));

	index += 2; /* Advance past the first number and the delimiter '.' */

	for (; index < strlen(oid_str) + 1; index++) {
		uint8_t byte = 0;
		if (oid_str[index] == '.' || oid_str[index] == '\0') {
			/*
			 *	We have a subidentifier
			 */
			started_subidentifier = false;
			bit_index	      = sizeof(subidentifier) * 8;

			if (buffer_len == 0) {
				fr_strerror_const("Empty buffer for final subidentifier");
				return -1;
			}

			if (!subsequent) {
				subidentifier = (first_component * 40) + (uint64_t)strtol(buffer, NULL, 10);
				subsequent    = true;
			} else {
				subidentifier = (uint64_t)strtol(buffer, NULL, 10);
			}

			/*
			 *	We will be reading the subidentifier 7 bits at a time. This is because the
			 *	OID components are encoded in a variable length format, where the high bit
			 *	of each byte indicates if there are more bytes to follow.
			 */
			while (bit_index > 7) {
				if (!started_subidentifier && ((uint8_t)(subidentifier >> (bit_index - 8)) == 0)) {
					bit_index -= 8;
					continue;
				}

				if (!started_subidentifier) {
					byte = (uint8_t)(subidentifier >> (bit_index -= (bit_index % 7)));

					if (byte == 0) {
						if (bit_index <= 7) {
							break;
						}

						byte = (uint8_t)(subidentifier >> (bit_index -= 7));

						if (byte == 0) {
							byte = (uint8_t)(subidentifier >> (bit_index -= 7));
						}
					}

				} else {
					byte = (uint8_t)(subidentifier >> (bit_index -= 7));
				}

				byte = byte | 0x80; /* Set the high bit to indicate more bytes to follow */

				fr_dbuff_in(&our_dbuff, byte);
				started_subidentifier = true;
			}

			/*
			 *	Tack on the last byte
			 */
			byte = (uint8_t)(subidentifier);

			byte = byte & 0x7f;

			fr_dbuff_in(&our_dbuff, byte);
			memset(buffer, 0, sizeof(buffer));
			buffer_len = 0;

			continue;
		}

		buffer[buffer_len++] = oid_str[index];
	}

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_oid(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t     our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	char const	*value = NULL;
	ssize_t		 slen = 0;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode OID");
		return -1;
	}

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

	PAIR_VERIFY(vp);

	value = vp->vp_strvalue;

	slen = fr_der_encode_oid_to_str(&our_dbuff, value);
	if (slen < 0) {
		fr_strerror_printf("Failed to encode OID: %s", fr_strerror());
		return slen;
	}

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_enumerated(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t     our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	int64_t		 value;
	uint8_t		 first_octet = 0;
	ssize_t		 slen	     = 0;
	size_t		 i	     = 0;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode enumerated");
		return -1;
	}

	PAIR_VERIFY(vp);

	/*
	 *	ISO/IEC 8825-1:2021
	 *	8.4 Encoding of an enumerated value
	 *		The encoding of an enumerated value shall be that of the integer value with which it is
	 *		associated.
	 *			NOTE – It is primitive.
	 */
	value = vp->vp_int64;

	for (; i < sizeof(value); i++) {
		uint8_t byte = (uint8_t)(value >> (((sizeof(value) * 8) - 8) - (i * 8)));

		if (slen == 0) {
			first_octet = byte;
			slen++;
			continue;
		} else if (slen == 1) {
			/*
			 *	8.3.2 If the contents octets of an integer value encoding consist of more than one
			 *	octet, then the bits of the first octet and bit 8 of the second octet: a) shall not
			 *	all be ones; and b) shall not all be zero.
			 */
			if ((first_octet == 0xff && (byte & 0x80)) || (first_octet == 0x00 && byte >> 7 == 0)) {
				if (i == sizeof(value) - 1) {
					/*
					 * If this is the only byte, then we can encode it in a single byte.
					 */
					fr_dbuff_in(&our_dbuff, byte);
					continue;
				}

				first_octet = byte;
				continue;
			} else {
				fr_dbuff_in(&our_dbuff, first_octet);
				fr_dbuff_in(&our_dbuff, byte);
				slen++;
				continue;
			}
		}

		fr_dbuff_in(&our_dbuff, byte);
		slen++;
	}

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_sequence(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	      our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const	     *vp;
	fr_da_stack_t	      da_stack;
	fr_dcursor_t	      child_cursor;
	fr_dict_attr_t const *ref   = NULL;
	ssize_t		      slen  = 0;
	unsigned int	      depth = 0;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode sequence");
		return -1;
	}

	if (!fr_type_is_group(vp->vp_type) && !fr_type_is_struct(vp->vp_type) && !fr_type_is_tlv(vp->vp_type)) {
		fr_strerror_printf("Unknown type %" PRId32, vp->vp_type);
		return -1;
	}

	PAIR_VERIFY(vp);

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

	if (fr_type_is_struct(vp->vp_type)) {
		fr_proto_da_stack_build(&da_stack, vp->da);

		FR_PROTO_STACK_PRINT(&da_stack, depth);

		slen = fr_struct_to_network(&our_dbuff, &da_stack, depth, cursor, encode_ctx, encode_value, encode_pair);

		if (slen < 0) {
			fr_strerror_printf("Failed to encode struct: %s", fr_strerror());
			return -1;
		}

		return fr_dbuff_set(dbuff, &our_dbuff);
	}

	if (fr_type_is_group(vp->vp_type)) {
		/*
		 *	Groups could be also be a pair, so we need to check for that.
		 */
		if (fr_der_flag_is_pair(vp->da)) {
			if (unlikely((slen = fr_der_encode_oid_value_pair(&our_dbuff, cursor, encode_ctx)) < 0)) {
				fr_strerror_printf("Failed to encode OID value pair: %s", fr_strerror());
				return -1;
			}

			return fr_dbuff_set(dbuff, &our_dbuff);
		}

		ref = fr_dict_attr_ref(vp->da);

		if (ref && (ref->dict != dict_der)) {
			fr_strerror_printf("Group %s is not a DER group", ref->name);
			return -1;
		}
	}

	fr_proto_da_stack_build(&da_stack, vp->da);

	FR_PROTO_STACK_PRINT(&da_stack, depth);

	fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, cursor);

	while (fr_dcursor_current(&child_cursor)) {
		slen = fr_pair_cursor_to_network(&our_dbuff, &da_stack, depth, &child_cursor,
							encode_ctx, encode_pair);
		if (unlikely(slen < 0)) {
			fr_strerror_printf("Failed to encode pair: %s", fr_strerror());
			return -1;
		}
	}

	return fr_dbuff_set(dbuff, &our_dbuff);
}

typedef struct {
	fr_dbuff_marker_t item_ptr;	//!< Pointer to the start of the encoded item (beginning of the tag)
	size_t	 item_len;		//!< Length of the encoded item (tag + length + value)
	uint8_t *octet_ptr;		//!< Pointer to the current octet
	size_t	 remaining;		//!< Remaining octets
} fr_der_encode_set_of_ptr_pairs_t;

/*
 *	Lexicographically sort the set of pairs
 */
static int CC_HINT(nonnull) fr_der_encode_set_of_cmp(void const *a, void const *b)
{
	fr_der_encode_set_of_ptr_pairs_t const *my_a = a;
	fr_der_encode_set_of_ptr_pairs_t const *my_b = b;

	if (my_a->item_len > my_b->item_len) {
		return memcmp(fr_dbuff_current(&my_a->item_ptr), fr_dbuff_current(&my_b->item_ptr), my_a->item_len);
	}

	return memcmp(fr_dbuff_current(&my_a->item_ptr), fr_dbuff_current(&my_b->item_ptr), my_b->item_len);
}

static ssize_t fr_der_encode_set(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	      our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t	     *vp;
	fr_da_stack_t	      da_stack;
	fr_dcursor_t	      child_cursor;
	fr_dict_attr_t const *ref   = NULL;
	ssize_t		      slen  = 0;
	unsigned int	      depth = 0;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode set");
		return -1;
	}

	if (!fr_type_is_group(vp->vp_type) && !fr_type_is_struct(vp->vp_type) && !fr_type_is_tlv(vp->vp_type)) {
		fr_strerror_printf("Unknown type %" PRId32, vp->vp_type);
		return -1;
	}

	PAIR_VERIFY(vp);

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
	 *			NOTE – The padding octets are for comparison purposes only and do not appear in the
	 *			encodings.
	 */

	if (fr_type_is_struct(vp->vp_type)) {
		/*
		 * 	Note: Structures should be in the correct order in the dictionary.
		 *	if they are not, the dictionary loader should complain.
		 */

		fr_proto_da_stack_build(&da_stack, vp->da);

		FR_PROTO_STACK_PRINT(&da_stack, depth);

		slen = fr_struct_to_network(&our_dbuff, &da_stack, depth, cursor, encode_ctx, encode_value, encode_pair);

		if (slen < 0) {
			fr_strerror_printf("Failed to encode struct: %s", fr_strerror());
			return -1;
		}

		return fr_dbuff_set(dbuff, &our_dbuff);
	}

	if (fr_type_is_group(vp->vp_type)) {
		/*
		 *	Groups could be also be a pair, so we need to check for that.
		 */
		if (fr_der_flag_is_pair(vp->da)) {
			if (unlikely((slen = fr_der_encode_oid_value_pair(&our_dbuff, cursor, encode_ctx)) < 0)) {
				fr_strerror_printf("Failed to encode OID value pair: %s", fr_strerror());
				return -1;
			}

			return fr_dbuff_set(dbuff, &our_dbuff);
		}


		/*
		 *	Check that the group is not referencing a non-DER-thing.
		 */
		ref = fr_dict_attr_ref(vp->da);

		if (ref && (ref->dict != dict_der)) {
			fr_strerror_printf("Group %s is not a DER group", ref->name);
			return -1;
		}
	}

	if (fr_der_flag_is_set_of(vp->da)) {
		/*
		 *	Set-of items will all have the same tag, so we need to sort them lexicographically
		 */
		fr_dbuff_t			  work_dbuff;
		fr_der_encode_set_of_ptr_pairs_t *ptr_pairs;
		uint8_t				 *buff;
		size_t				  i = 0, count;

		buff = talloc_array(vp, uint8_t, fr_dbuff_remaining(&our_dbuff));

		fr_dbuff_init(&work_dbuff, buff, fr_dbuff_remaining(&our_dbuff));

		fr_proto_da_stack_build(&da_stack, vp->da);

		FR_PROTO_STACK_PRINT(&da_stack, depth);

		fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, cursor);

		count = fr_pair_list_num_elements(&vp->children);

		ptr_pairs = talloc_array(vp, fr_der_encode_set_of_ptr_pairs_t, count);
		if (unlikely(ptr_pairs == NULL)) {
			fr_strerror_const("Failed to allocate memory for set of pointers");
			talloc_free(buff);
			return -1;
		}

		for (i = 0; i < count; i++) {
			ssize_t len_count;

			if (unlikely(fr_dcursor_current(&child_cursor) == NULL)) {
				fr_strerror_const("No pair to encode set of");
				slen = -1;
			free_and_return:
				talloc_free(ptr_pairs);
				talloc_free(buff);
				return slen;
			}

			len_count = encode_value(&work_dbuff, NULL, depth, &child_cursor, encode_ctx);

			if (unlikely(len_count < 0)) {
				fr_strerror_printf("Failed to encode pair: %s", fr_strerror());
				slen = -1;
				goto free_and_return;
			}

			ptr_pairs[i].item_ptr  = encode_ctx->encoding_start;
			ptr_pairs[i].item_len  = encode_ctx->encoding_length;
			ptr_pairs[i].octet_ptr = encode_ctx->encoded_value;
			ptr_pairs[i].remaining = encode_ctx->value_length;

			slen += len_count;
		}

		if (unlikely(fr_dcursor_current(&child_cursor) != NULL)) {
			fr_strerror_const("Failed to encode all pairs");
			slen = -1;
			goto free_and_return;
		}

		qsort(ptr_pairs, count, sizeof(fr_der_encode_set_of_ptr_pairs_t), fr_der_encode_set_of_cmp);

		for (i = 0; i < count; i++) {
			fr_dbuff_set(&work_dbuff, &ptr_pairs[i].item_ptr);

			FR_PROTO_TRACE("Copying %" PRIuPTR " bytes from %p to %p", ptr_pairs[i].item_len,
					&ptr_pairs[i].item_ptr, fr_dbuff_current(dbuff));

			if (fr_dbuff_in_memcpy(&our_dbuff, fr_dbuff_current(&work_dbuff), ptr_pairs[i].item_len) <=
				0) {
				fr_strerror_const("Failed to copy set of value");
				slen = -1;
				goto free_and_return;
			}
		}

		slen = fr_dbuff_set(dbuff, &our_dbuff);
		goto free_and_return;
	}

	fr_pair_list_sort(&vp->children, fr_der_pair_cmp_by_da_tag);

	fr_proto_da_stack_build(&da_stack, vp->da);

	FR_PROTO_STACK_PRINT(&da_stack, depth);

	fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, cursor);

	while (fr_dcursor_current(&child_cursor)) {
		slen = fr_pair_cursor_to_network(&our_dbuff, &da_stack, depth, &child_cursor, encode_ctx,
							encode_pair);
		if (unlikely(slen < 0)) {
			fr_strerror_printf("Failed to encode pair: %s", fr_strerror());
			return -1;
		}
	}

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_utc_time(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	 our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	fr_sbuff_t	 time_sbuff;
	char		 fmt_time[50] = { 0 };
	size_t		 i = 0;

	fmt_time[0] = '\0';
	time_sbuff  = FR_SBUFF_OUT(fmt_time, sizeof(fmt_time));

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode UTC time");
		return -1;
	}

	PAIR_VERIFY(vp);

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
	fr_unix_time_to_str(&time_sbuff, vp->vp_date, FR_TIME_RES_SEC, true);

	/*
	 *	Remove the century from the year
	 */
	fr_sbuff_shift(&time_sbuff, 2);

	/*
	 *	Trim the time string of any unwanted characters
	 */
	for (; i < sizeof(fmt_time); i++) {
		if (fmt_time[i] == '\0') {
			break;
		}

		if (fmt_time[i] == '-' || fmt_time[i] == 'T' || fmt_time[i] == ':') {
			size_t j = i;

			while (fmt_time[j] != '\0') {
				fmt_time[j] = fmt_time[j + 1];
				j++;
			}

			fmt_time[j] = '\0';

			continue;
		}
	}

	if (fr_dbuff_in_memcpy(&our_dbuff, fmt_time, DER_UTC_TIME_LEN) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for UTC time");
		return -1;
	}

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_generalized_time(fr_dbuff_t *dbuff, fr_dcursor_t *cursor,
					      UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t 	 our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	fr_sbuff_t	 time_sbuff;
	char		 fmt_time[50] = { 0 };
	size_t		 i = 0;

	fmt_time[0] = '\0';
	time_sbuff  = FR_SBUFF_OUT(fmt_time, sizeof(fmt_time));

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode generalized time");
		return -1;
	}

	PAIR_VERIFY(vp);

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

	fr_unix_time_to_str(&time_sbuff, vp->vp_date, FR_TIME_RES_USEC, true);

	/*
	 *	Trim the time string of any unwanted characters
	 */
	for (; i < sizeof(fmt_time); i++) {
		if (fmt_time[i] == '\0') {
			break;
		}

		if (fmt_time[i] == '-' || fmt_time[i] == 'T' || fmt_time[i] == ':') {
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

	if (fr_dbuff_in_memcpy(&our_dbuff, fmt_time, i) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for generalized time");
		return -1;
	}

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
	unsigned int 	depth = 0;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode choice");
		return -1;
	}

	PAIR_VERIFY(vp);

	depth = vp->da->depth - 1;

	fr_proto_da_stack_build(&da_stack, vp->da);

	FR_PROTO_STACK_PRINT(&da_stack, depth);

	fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, cursor);

	do {
		slen = fr_pair_cursor_to_network(&our_dbuff, &da_stack, depth, &child_cursor, encode_ctx,
							encode_pair);
		if (unlikely(slen < 0)) {
			fr_strerror_printf("Failed to encode pair: %s", fr_strerror());
			return slen;
		}
	} while (fr_dcursor_next(&child_cursor));

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
	int64_t	 	  max;

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

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode pair");
		return -1;
	}

	PAIR_VERIFY(vp);

	if (unlikely(!fr_type_is_group(vp->vp_type))) {
		fr_strerror_printf("Pair %s is not a group", vp->da->name);
		return -1;
	}

	max = fr_der_flag_max(vp->da); /* Maximum number of extensions specified in the dictionary */

	if (max == 0) max = INT64_MAX;

	slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_SEQUENCE, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_CONSTRUCTED);
	if (slen < 0) return slen;

	fr_dbuff_marker(&outer_seq_len_start, &our_dbuff);
	fr_dbuff_advance(&our_dbuff, 1);

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&our_dbuff), fr_dbuff_behind(&outer_seq_len_start) - 1,
			  "BEFORE encoded X509 extension");

	fr_pair_dcursor_child_iter_init(&root_cursor, &vp->children, cursor);
	fr_dcursor_copy(&parent_cursor, &root_cursor);
	while (fr_dcursor_current(&parent_cursor)) {
		fr_sbuff_t	  oid_sbuff;
		fr_dbuff_marker_t length_start, inner_seq_len_start;
		char		  oid_buff[1024] = { 0 };
		bool		  is_raw = false;

		/*
		 *	Extensions are sequences or sets containing 2 items:
		 *	1. The first item is the OID
		 *	2. The second item is the value
		 *
		 *	Note: The value may be a constructed or primitive type
		 */

		if (max < 0) {
			fr_strerror_printf("Too many X509 extensions (%" PRIi64 ")", max);
			break;
		}

		oid_sbuff   = FR_SBUFF_OUT(oid_buff, sizeof(oid_buff));
		oid_buff[0] = '\0';

		/*
		 *	Walk through the children until we find either an attribute marked as an extension, or one with
		 *	no children (which is an unknown OID).
		 *
		 *	We will use this to construct the OID to encode, as well as to get the actual value of the
		 *	extension.
		 */
		fr_dcursor_copy(&child_cursor, &parent_cursor);
		while (fr_dcursor_current(&child_cursor)) {
			fr_pair_t const *child_vp = fr_dcursor_current(&child_cursor);

			PAIR_VERIFY(child_vp);

			FR_PROTO_TRACE("Child: %s", child_vp->da->name);

			if (!is_critical && (strcmp(child_vp->da->name, "Critical") == 0)) {
				/*
				 *	We don't encode the critical flag
				 */
				is_critical = fr_pair_list_num_elements(&child_vp->children);
				FR_PROTO_TRACE("Critical flag: %" PRIuPTR, is_critical);
				fr_pair_dcursor_child_iter_init(&parent_cursor, &child_vp->children, &child_cursor);
				goto next;
			}

			if (!fr_type_is_structural(child_vp->vp_type) && !fr_der_flag_is_oid_leaf(child_vp->da)) {
				FR_PROTO_TRACE("Found non-structural child %s", child_vp->da->name);

				if (child_vp->da->flags.is_raw) {
					/*
					 *	This was an unknown oid
					 */
					if (unlikely(fr_sbuff_in_sprintf(&oid_sbuff, ".%" PRIu32, child_vp->da->attr) <= 0)) {
						fr_strerror_const("Failed to copy OID to buffer");
						slen = -1;
					error:
						fr_dbuff_marker_release(&outer_seq_len_start);
						return slen;
					}
					is_raw = true;
					break;
				}

				fr_dcursor_copy(&child_cursor, &parent_cursor);
				break;
			}

			if (oid_buff[0] == '\0') {
				if (unlikely(fr_sbuff_in_sprintf(&oid_sbuff, "%" PRIu32, child_vp->da->attr) <= 0)) {
					fr_strerror_const("Failed to copy OID to buffer");
					slen = -1;
					goto error;
				}

				goto next;
			}

			if (unlikely(fr_sbuff_in_sprintf(&oid_sbuff, ".%" PRIu32, child_vp->da->attr) <= 0)) {
				goto error;
			}

			/*
			 *	Unless this was the last child (marked as an extension), there should only be one child
			 *	- representing the next OID in the extension
			 */
			if (fr_pair_list_num_elements(&child_vp->children) > 1) break;

		next:
			FR_PROTO_TRACE("OID: %s", oid_buff);
			if (fr_der_flag_is_oid_leaf(child_vp->da)) break;
			fr_pair_dcursor_child_iter_init(&child_cursor, &child_vp->children, &child_cursor);
		}

		fr_sbuff_terminate(&oid_sbuff);
		FR_PROTO_TRACE("OID: %s", oid_buff);

		slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_SEQUENCE, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_CONSTRUCTED);
		if (slen < 0) {
			goto error;
		}

		fr_dbuff_marker(&inner_seq_len_start, &our_dbuff);
		fr_dbuff_advance(&our_dbuff, 1);

		/*
		 *	Encode the OID portion of the extension
		 */
		slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_OID, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMITIVE);
		if (slen < 0) {
			fr_dbuff_marker_release(&inner_seq_len_start);
			goto error;
		}

		fr_dbuff_marker(&length_start, &our_dbuff);
		fr_dbuff_advance(&our_dbuff, 1);

		slen = fr_der_encode_oid_to_str(&our_dbuff, oid_buff);
		if (slen < 0) {
			fr_dbuff_marker_release(&length_start);
			fr_dbuff_marker_release(&inner_seq_len_start);
			goto error;
		}

		/*
		 *	Encode the length of the OID
		 */
		slen = fr_der_encode_len(&our_dbuff, &length_start, fr_dbuff_behind(&length_start) - 1);
		fr_dbuff_marker_release(&length_start);
		if (slen < 0) {
			fr_dbuff_marker_release(&inner_seq_len_start);
			goto error;
		}

		if (is_critical) {
			/*
			 *	Encode the critical flag
			 */
			slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_BOOLEAN, FR_DER_CLASS_UNIVERSAL,
						 FR_DER_TAG_PRIMITIVE);
			if (slen < 0) {
				fr_dbuff_marker_release(&inner_seq_len_start);
				goto error;
			}

			fr_dbuff_marker(&length_start, &our_dbuff);
			fr_dbuff_advance(&our_dbuff, 1);

			fr_dbuff_in(&our_dbuff, (uint8_t)(0xff));

			slen = fr_der_encode_len(&our_dbuff, &length_start, fr_dbuff_behind(&length_start) - 1);
			fr_dbuff_marker_release(&length_start);
			if (slen < 0) {
				fr_dbuff_marker_release(&inner_seq_len_start);
				goto error;
			}

			is_critical--;
		}

		/*
		 *	Encode the value portion of the extension
		 */
		slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_OCTETSTRING, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMITIVE);
		if (slen < 0) {
			fr_dbuff_marker_release(&inner_seq_len_start);
			goto error;
		}

		fr_dbuff_marker(&length_start, &our_dbuff);
		fr_dbuff_advance(&our_dbuff, 1);

		if (is_raw) {
			slen = fr_der_encode_octetstring(&our_dbuff, &child_cursor, encode_ctx);
		} else {
			slen = der_encode_pair(&our_dbuff, &child_cursor, encode_ctx);
		}
		if (slen < 0) {
			fr_dbuff_marker_release(&length_start);
			fr_dbuff_marker_release(&inner_seq_len_start);
			goto error;
		}

		/*
		 *	Encode the length of the value
		 */
		slen = fr_der_encode_len(&our_dbuff, &length_start, fr_dbuff_behind(&length_start) - 1);
		fr_dbuff_marker_release(&length_start);
		if (slen < 0) {
			fr_dbuff_marker_release(&inner_seq_len_start);
			goto error;
		}

		/*
		 *	Encode the length of the extension (OID + Value portions)
		 */
		slen = fr_der_encode_len(&our_dbuff, &inner_seq_len_start, fr_dbuff_behind(&inner_seq_len_start) - 1);
		fr_dbuff_marker_release(&inner_seq_len_start);
		if (slen < 0) {
			goto error;
		}

		if (is_critical) {
			fr_dcursor_next(&parent_cursor);
			max--;
			continue;
		}

		FR_PROTO_HEX_DUMP(fr_dbuff_start(&our_dbuff), fr_dbuff_behind(&outer_seq_len_start) + 2,
				  "Encoded X509 extension");

		fr_dcursor_next(&root_cursor);
		fr_dcursor_copy(&parent_cursor, &root_cursor);
		max--;
	}

	/*
	 *	Encode the length of the extensions
	 */
	slen = fr_der_encode_len(&our_dbuff, &outer_seq_len_start, fr_dbuff_behind(&outer_seq_len_start) - 1);
	fr_dbuff_marker_release(&outer_seq_len_start);
	if (slen < 0) return slen;

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&our_dbuff), slen, "Encoded X509 extensions");

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_oid_value_pair(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	  our_dbuff = FR_DBUFF(dbuff);
	fr_sbuff_t	  oid_sbuff;
	fr_dbuff_marker_t length_start;
	fr_dcursor_t	  child_cursor, parent_cursor = *cursor;
	fr_pair_t const	 *vp;
	char		  oid_buff[1024] = { 0 };
	ssize_t		  slen	 = 0;
	bool		  is_raw = false;

	vp = fr_dcursor_current(&parent_cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode pair");
		return -1;
	}

	PAIR_VERIFY(vp);

	if (unlikely(!fr_type_is_group(vp->vp_type))) {
		fr_strerror_printf("Pair %s is not a group", vp->da->name);
		return -1;
	}

	/*
	 *	A very common pattern in DER encoding is ro have a sequence of set containing two things: an OID and a
	 *	value, where the OID is used to determine how to decode the value.
	 *	We will be decoding the OID first and then try to find the attribute associated with that OID to then
	 *	decode the value. If no attribute is found, one will be created and the value will be stored as raw
	 *	octets in the attribute.
	 *
	 *	Note: The value may be a constructed or primitive type
	 */

	oid_sbuff   = FR_SBUFF_OUT(oid_buff, sizeof(oid_buff));
	oid_buff[0] = '\0';

	/*
	 *	Walk through the children until we find either an attribute marked as an oid leaf, or one with
	 *	no children (which is an unknown OID).
	 *
	 *	We will use this to construct the OID to encode, as well as to get the actual value of the
	 *	pair.
	 */
	fr_pair_dcursor_child_iter_init(&child_cursor, &vp->children, &parent_cursor);
	while (fr_dcursor_current(&child_cursor)) {
		fr_pair_t const *child_vp = fr_dcursor_current(&child_cursor);

		PAIR_VERIFY(child_vp);

		if (!fr_type_is_structural(child_vp->vp_type) && !fr_der_flag_is_oid_leaf(child_vp->da)) {
			FR_PROTO_TRACE("Found non-structural child %s", child_vp->da->name);

			if (child_vp->da->flags.is_raw) {
				/*
				 *	This was an unknown oid
				 */
				if (unlikely(fr_sbuff_in_sprintf(&oid_sbuff, ".%" PRIu32, child_vp->da->attr) <= 0)) {
					fr_strerror_const("Failed to copy OID to buffer");
					return slen;
				}
				is_raw = true;
				break;
			}

			fr_dcursor_copy(&child_cursor, &parent_cursor);
			break;
		}

		if (oid_buff[0] == '\0') {
			if (unlikely(fr_sbuff_in_sprintf(&oid_sbuff, "%" PRIu32, child_vp->da->attr) <= 0)) {
				fr_strerror_const("Failed to copy OID to buffer");
				return -1;
			}

			goto next;
		}

		if (unlikely(fr_sbuff_in_sprintf(&oid_sbuff, ".%" PRIu32, child_vp->da->attr) <= 0)) {
			fr_strerror_const("Failed to copy OID to buffer");
			return -1;
		}

		/*
		 *	Unless this was the last child (marked as an oid leaf), there should only be one child
		 *	- representing the next OID in the pair
		 */
		if (fr_pair_list_num_elements(&child_vp->children) > 1) break;

	next:
		FR_PROTO_TRACE("OID: %s", oid_buff);
		if (fr_der_flag_is_oid_leaf(child_vp->da)) break;
		fr_pair_dcursor_child_iter_init(&child_cursor, &child_vp->children, &child_cursor);
	}

	fr_sbuff_terminate(&oid_sbuff);
	FR_PROTO_TRACE("OID: %s", oid_buff);

	slen = fr_der_encode_tag(&our_dbuff, FR_DER_TAG_OID, FR_DER_CLASS_UNIVERSAL, FR_DER_TAG_PRIMITIVE);
	if (slen < 0) return slen;

	fr_dbuff_marker(&length_start, &our_dbuff);
	fr_dbuff_advance(&our_dbuff, 1);

	/*
	 *	Encode the OID portion of the pair
	 */
	slen = fr_der_encode_oid_to_str(&our_dbuff, oid_buff);
	if (slen < 0) {
		fr_dbuff_marker_release(&length_start);
		return slen;
	}

	/*
	 *	Encode the length of the OID
	 */
	slen = fr_der_encode_len(&our_dbuff, &length_start, slen);
	fr_dbuff_marker_release(&length_start);
	if (slen < 0) return slen;

	if (is_raw) {
		slen = fr_der_encode_octetstring(&our_dbuff, &child_cursor, encode_ctx);
	} else {
		slen = der_encode_pair(&our_dbuff, &child_cursor, encode_ctx);
	}
	if (slen < 0) return slen;

	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t fr_der_encode_string(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, UNUSED fr_der_encode_ctx_t *encode_ctx)
{
	fr_dbuff_t	 our_dbuff = FR_DBUFF(dbuff);
	fr_pair_t const *vp;
	char const	*value = NULL;
	ssize_t		 slen;

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode string");
		return -1;
	}

	PAIR_VERIFY(vp);

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
	value = vp->vp_strvalue;
	slen  = vp->vp_length;

	if (fr_dbuff_in_memcpy(&our_dbuff, value, (size_t)slen) <= 0) {
		fr_strerror_const("Failed to copy string value to buffer for string type");
		return -1;
	}

	return fr_dbuff_set(dbuff, &our_dbuff);
}

/** Encode the length field of a DER structure
 *
 * @param dbuff		The buffer to write the length field to
 * @param length_start	The start of the length field
 * @param slen		The length of the structure
 *
 * @return		The number of bytes written to the buffer
 */
static ssize_t fr_der_encode_len(fr_dbuff_t *dbuff, fr_dbuff_marker_t *length_start, ssize_t slen)
{
	fr_dbuff_marker_t value_start;
	fr_dbuff_t	  value_field;
	uint8_t		  len_len = 0;
	ssize_t		  i = 0, our_slen = slen;

	/*
	 * If the length can fit in a single byte, we don't need to extend the size of the length field
	 */
	if (slen <= 0x7f) {
		fr_dbuff_in(length_start, (uint8_t)slen);
		return 1;
	}

	/*
	 * Calculate the number of bytes needed to encode the length
	 */
	while (our_slen > 0) {
		our_slen >>= 8;
		len_len++;
	}

	if (len_len > 0x7f) {
		fr_strerror_printf("Length %" PRIiPTR " is too large to encode", slen);
		return -1;
	}

	value_field = FR_DBUFF(length_start);

	fr_dbuff_set(&value_field, fr_dbuff_current(length_start));

	fr_dbuff_marker(&value_start, &value_field);

	/*
	 *	Set the dbuff write locaiton to where the new value field will start
	 */
	fr_dbuff_set(dbuff, fr_dbuff_current(length_start) + len_len);

	fr_dbuff_move(dbuff, fr_dbuff_ptr(&value_start), slen + 1);

	fr_dbuff_set(dbuff, length_start);

	fr_dbuff_in(dbuff, (uint8_t)(0x80 | len_len));

	for (; i < len_len; i++) {
		fr_dbuff_in(dbuff, (uint8_t)((slen) >> ((len_len - i - 1) * 8)));
	}

	fr_dbuff_set(dbuff, fr_dbuff_current(length_start) + len_len + 1 + slen);

	fr_dbuff_marker_release(&value_start);

	return len_len + 1;
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
	fr_der_encode_tag(fr_dbuff_t *dbuff, fr_der_tag_num_t tag_num, fr_der_tag_class_t tag_class,
			  fr_der_tag_constructed_t constructed)
{
	fr_dbuff_t	our_dbuff = FR_DBUFF(dbuff);
	uint8_t 	tag_byte;

	tag_byte = (tag_class & DER_TAG_CLASS_MASK) | (constructed & DER_TAG_CONSTRUCTED_MASK) |
		   (tag_num & DER_TAG_NUM_MASK);

	fr_dbuff_in(&our_dbuff, tag_byte);

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
static ssize_t encode_value(fr_dbuff_t *dbuff, UNUSED fr_da_stack_t *da_stack, UNUSED unsigned int depth,
			    fr_dcursor_t *cursor, void *encode_ctx)
{
	fr_pair_t const	    *vp;
	fr_dbuff_t	     our_dbuff = FR_DBUFF(dbuff);
	fr_dbuff_marker_t    marker;
	fr_der_tag_encode_t *tag_encode;
	fr_der_tag_num_t     tag_num;
	fr_der_tag_class_t   tag_class;
	fr_der_encode_ctx_t *uctx = encode_ctx;
	ssize_t		     slen = 0;

	if (unlikely(cursor == NULL)) {
		fr_strerror_const("No cursor to encode");
		return -1;
	}

	vp = fr_dcursor_current(cursor);
	if (unlikely(vp == NULL)) {
		fr_strerror_const("No pair to encode");
		return -1;
	}

	FR_PROTO_TRACE("Encoding %s", vp->da->name);

	PAIR_VERIFY(vp);

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

	if (fr_der_flag_has_default(vp->da)) {
		/*
		 *	Skip encoding the default value, as per ISO/IEC 8825-1:2021 11.5
		 */
		fr_dict_enum_value_t const *evp;

		evp = fr_dict_enum_by_name(vp->da, "DEFAULT", strlen("DEFAULT"));
		if (unlikely(evp == NULL)) {
			fr_strerror_printf("No default value for %s", vp->da->name);
			return -1;
		}

		if (fr_value_box_cmp(&vp->data, evp->value) == 0) {
			FR_PROTO_TRACE("Skipping default value");
			fr_dcursor_next(cursor);
			return 0;
		}
	}

	if (unlikely(fr_der_flag_is_choice(vp->da))) {
		slen = fr_der_encode_choice(&our_dbuff, cursor, uctx);
		if (slen < 0) return slen;
		fr_dcursor_next(cursor);
		return fr_dbuff_set(dbuff, &our_dbuff);
	}

	tag_num = fr_der_flag_subtype(vp->da) ? fr_der_flag_subtype(vp->da) : fr_type_to_der_tag_default(vp->vp_type);

	if (unlikely(tag_num == FR_DER_TAG_INVALID)) {
		fr_strerror_printf("No tag number for type %" PRId32, vp->vp_type);
		return -1;
	}

	tag_encode = &tag_funcs[tag_num];
	if (tag_encode->encode == NULL) {
		fr_strerror_printf("No encoding function for type %" PRId32, vp->vp_type);
		return -1;
	}

	tag_class = fr_der_flag_class(vp->da) ? fr_der_flag_class(vp->da) : FR_DER_CLASS_UNIVERSAL;

	fr_dbuff_marker(&uctx->encoding_start, &our_dbuff);

	slen = fr_der_encode_tag(&our_dbuff,
				 fr_der_flag_tagnum(vp->da) | tag_class ? fr_der_flag_tagnum(vp->da) : tag_num,
				 tag_class, tag_encode->constructed);
	if (slen < 0) {
	error:
		fr_dbuff_marker_release(&uctx->encoding_start);
		return slen;
	}

	uctx->encoding_length = slen;

	/*
	 * Mark and reserve space in the buffer for the length field
	 */
	fr_dbuff_marker(&marker, &our_dbuff);
	fr_dbuff_advance(&our_dbuff, 1);

	if (fr_der_flag_is_extensions(vp->da)) {
		slen = fr_der_encode_X509_extensions(&our_dbuff, cursor, uctx);
	} else {
		slen = tag_encode->encode(&our_dbuff, cursor, uctx);
	}
	if (slen < 0) {
		fr_dbuff_marker_release(&marker);
		goto error;
	}

	uctx->encoding_length += slen;
	uctx->value_length = slen;

	/*
	 * Encode the length of the value
	 */
	slen = fr_der_encode_len(&our_dbuff, &marker, fr_dbuff_behind(&marker) - 1);
	if (slen < 0) {
		fr_dbuff_marker_release(&marker);
		goto error;
	}

	uctx->encoded_value = fr_dbuff_start(&marker) + slen + 1;
	fr_dbuff_marker_release(&marker);
	uctx->encoding_length += slen;

	fr_dcursor_next(cursor);
	return fr_dbuff_set(dbuff, &our_dbuff);
}

static ssize_t encode_pair(fr_dbuff_t *dbuff, fr_da_stack_t *da_stack, unsigned int depth, fr_dcursor_t *cursor,
			   void *encode_ctx)
{
	return encode_value(dbuff, da_stack, depth, cursor, encode_ctx);
}

static ssize_t der_encode_pair(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, void *encode_ctx)
{
	return encode_pair(dbuff, NULL, 0, cursor, encode_ctx);
}

static ssize_t fr_der_encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_list_t *vps, uint8_t *data, size_t data_len,
				   void *encode_ctx)
{
	fr_dbuff_t   dbuff;
	fr_dcursor_t cursor;
	ssize_t	     slen;

	fr_dbuff_init(&dbuff, data, data_len);

	fr_pair_dcursor_init(&cursor, vps);

	slen = der_encode_pair(&dbuff, &cursor, encode_ctx);

	if (slen < 0) {
		fr_strerror_printf("Failed to encode data: %s", fr_strerror());
		return -1;
	}

	return slen;
}

/*
 *	Test points
 */
static int encode_test_ctx(void **out, TALLOC_CTX *ctx, UNUSED fr_dict_t const *dict)
{
	fr_der_encode_ctx_t *test_ctx;

	test_ctx = talloc_zero(ctx, fr_der_encode_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->tmp_ctx	     = talloc(test_ctx, uint8_t);
	test_ctx->encoding_length    = 0;
	test_ctx->value_length = 0;
	test_ctx->encoded_value	     = NULL;

	*out = test_ctx;

	return 0;
}

extern fr_test_point_pair_encode_t der_tp_encode_pair;
fr_test_point_pair_encode_t	   der_tp_encode_pair = {
	       .test_ctx = encode_test_ctx,
	       .func	 = der_encode_pair,
};

extern fr_test_point_proto_encode_t der_tp_encode_proto;
fr_test_point_proto_encode_t	    der_tp_encode_proto = {
	       .test_ctx = encode_test_ctx,
	       .func	 = fr_der_encode_proto,
};
