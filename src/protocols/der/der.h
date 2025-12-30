#pragma once
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
 * @file protocols/der/der.c
 * @brief Structures and prototypes for base DER functionality.
 *
 * @author Ethan Thompson (ethan.thompson@inkbridge.io)
 *
 * @copyright 2025 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/build.h>
#include <freeradius-devel/util/value.h>

/** Enumeration describing the data types in a DER encoded structure
 */
typedef enum {
	FR_DER_TAG_INVALID	    = 0x00,	   //!< Invalid tag.
	FR_DER_TAG_BOOLEAN	    = 0x01,	   //!< Boolean true/false
	FR_DER_TAG_INTEGER	    = 0x02,	   //!< Arbitrary width signed integer.
	FR_DER_TAG_BITSTRING	    = 0x03,	   //!< String of bits (length field specifies bits).
	FR_DER_TAG_OCTETSTRING	    = 0x04,	   //!< String of octets (length field specifies bytes).
	FR_DER_TAG_NULL		    = 0x05,	   //!< An empty value.
	FR_DER_TAG_OID		    = 0x06,	   //!< Reference to an OID based attribute.
	FR_DER_TAG_ENUMERATED	    = 0x0a,	   //!< An enumerated value.
	FR_DER_TAG_UTF8_STRING	    = 0x0c,	   //!< String of UTF8 chars.
	FR_DER_TAG_SEQUENCE	    = 0x10,	   //!< A sequence of DER encoded data (a structure).
	FR_DER_TAG_SET		    = 0x11,	   //!< A set of DER encoded data (a structure).
	FR_DER_TAG_PRINTABLE_STRING = 0x13,	   //!< String of printable chars.
	FR_DER_TAG_T61_STRING	    = 0x14,	   //!< String of T61 (8bit) chars.
	FR_DER_TAG_IA5_STRING	    = 0x16,	   //!< String of IA5 (7bit) chars.
	FR_DER_TAG_UTC_TIME	    = 0x17,	   //!< A time in UTC "YYMMDDhhmmssZ" format.
	FR_DER_TAG_GENERALIZED_TIME = 0x18,	   //!< A time in "YYYYMMDDHHMMSS[.fff]Z" format.
	FR_DER_TAG_VISIBLE_STRING   = 0x1a,	   //!< String of visible chars.
	FR_DER_TAG_GENERAL_STRING   = 0x1b,	   //!< String of general chars.
	FR_DER_TAG_UNIVERSAL_STRING = 0x1c,	   //!< String of universal chars.
	FR_DER_TAG_BMP_STRING	    = 0x1e,	   //!< String of BMP chars.

	FR_DER_TAG_CHOICE	    = 0x23,	   //!< A choice of types. Techically not a DER tag, but used to represent a choice.

	FR_DER_TAG_MAX		    = 0x24
} fr_der_tag_t;

#define FR_DER_TAG_VALUE_MAX (0x1f)		//!< tags >=max can't exist

typedef enum {
	FR_DER_TAG_PRIMITIVE   = 0x00,	     //!< This is a leaf value, it contains no children.
	FR_DER_TAG_CONSTRUCTED = 0x20	     //!< This is a sequence or set, it contains children.
} fr_der_tag_constructed_t;

typedef enum {
	FR_DER_CLASS_UNIVERSAL   = 0x00,
	FR_DER_CLASS_APPLICATION = 0x40,
	FR_DER_CLASS_CONTEXT	    = 0x80,
	FR_DER_CLASS_PRIVATE	    = 0xC0,
	FR_DER_CLASS_INVALID	    = 0x04
} fr_der_tag_class_t;

#define DER_MAX_STR 16384

#define DER_UTC_TIME_LEN 13	 //!< Length of the UTC time string.
#define DER_GENERALIZED_TIME_LEN_MIN 15	 //!< Minimum length of the generalized time string.
#define DER_GENERALIZED_TIME_PRECISION_MAX 4 //!< Maximum precision of the generalized time string.

#define DER_TAG_CLASS_MASK 0xc0	 //!< Mask to extract the class from the tag.
#define DER_TAG_CONSTRUCTED_MASK 0x20	 //!< Mask to check if the tag is constructed.
#define DER_TAG_NUM_MASK 0x1f	 //!< Mask to extract the tag number from the tag.

#define DER_TAG_CONTINUATION 0x1f	 //!< Mask to check if the tag is a continuation.

#define DER_LEN_MULTI_BYTE 0x80	 //!< Mask to check if the length is multi-byte.

#define DER_BOOLEAN_FALSE 0x00	 //!< DER encoded boolean false value.
#define DER_BOOLEAN_TRUE 0xff	 //!< DER encoded boolean true value.

typedef struct {
	fr_der_tag_class_t 	class;		//!< tag Class
	fr_der_tag_t 		der_type;	//!< the DER type, which is different from the FreeRADIUS type
	union {
		fr_der_tag_t 		sequence_of;
		fr_der_tag_t 		set_of;
		fr_value_box_t		*default_value;
	};
	uint64_t 		max;			//!< maximum count of items in a sequence, set, or string.
	uint32_t		restrictions;		//!< for choice of options and tags - no dups allowed
	uint8_t			min;			//!< mininum count
	uint8_t 		option;			//!< an "attribute number" encoded in the tag field.
	bool			is_option : 1;		//!< has an option defined
	bool			optional : 1;		//!< optional, we MUST already have set 'option'
	bool			is_sequence_of : 1;	//!< sequence_of has been defined
	bool 			is_set_of : 1;		//!< set_of has been defined
	bool 			is_oid_and_value : 1;	//!< is OID+value
	bool 			is_extensions : 1;	//!< a list of X.509 extensions
	bool			has_default_value : 1;	//!< a default value exists
	bool 			leaf : 1;		//!< encode this OID along with its value
	bool			is_choice : 1;		//!< DER name "choice".
} fr_der_attr_flags_t;

typedef struct {
	TALLOC_CTX	*tmp_ctx;		//!< ctx under which temporary data will be allocated
} fr_der_decode_ctx_t;

static inline fr_der_attr_flags_t const *fr_der_attr_flags(fr_dict_attr_t const *da)
{
	return fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
}

#define fr_der_flag_option(_da) 	(fr_der_attr_flags(_da)->option)
#define fr_der_flag_optional(_da) 	(fr_der_attr_flags(_da)->optional)
#define fr_der_flag_class(_da)		(fr_der_attr_flags(_da)->class)
#define fr_der_flag_der_type(_da) 	(fr_der_attr_flags(_da)->der_type)
#define fr_der_flag_sequence_of(_da) 	(fr_der_attr_flags(_da)->sequence_of)
#define fr_der_flag_is_sequence_of(_da) (fr_der_attr_flags(_da)->is_sequence_of)
#define fr_der_flag_set_of(_da) 	(fr_der_attr_flags(_da)->set_of)
#define fr_der_flag_is_set_of(_da) 	(fr_der_attr_flags(_da)->is_set_of)
#define fr_der_flag_max(_da) 		(fr_der_attr_flags(_da)->max)
#define fr_der_flag_is_oid_and_value(_da) (fr_der_attr_flags(_da)->is_oid_and_value)
#define fr_der_flag_is_extensions(_da) 	(fr_der_attr_flags(_da)->is_extensions)
#define fr_der_flag_has_default_value(_da) 	((fr_der_attr_flags(_da)->has_default_value) != NULL);
#define fr_der_flag_leaf(_da) 		(fr_der_attr_flags(_da)->leaf)
#define fr_der_flag_is_choice(_da) 	(fr_der_attr_flags(_da)->is_choice)

/*
 * 	base.c
 */
fr_der_tag_t fr_type_to_der_tag_default(fr_type_t type);
bool	fr_type_to_der_tag_valid(fr_type_t type, fr_der_tag_t tag);
bool	fr_der_tags_compatible(fr_der_tag_t tag1, fr_der_tag_t tag2);
char	const *fr_der_tag_to_str(fr_der_tag_t tag);

int	fr_der_global_init(void);
void	fr_der_global_free(void);

/*
 *	decode.c
 */
ssize_t	fr_der_decode_pair_dbuff(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				 fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);
