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
#define DER_GENERALIZED_TIME_PRECISION_MAX 9 //!< Maximum precision of the generalized time string (nanoseconds).

#define DER_TAG_CLASS_MASK 0xc0	 //!< Mask to extract the class from the tag.
#define DER_TAG_CONSTRUCTED_MASK 0x20	 //!< Mask to check if the tag is constructed.
#define DER_TAG_NUM_MASK 0x1f	 //!< Mask to extract the tag number from the tag.

#define DER_TAG_CONTINUATION 0x1f	 //!< Mask to check if the tag is a continuation.

#define DER_LEN_MULTI_BYTE 0x80	 //!< Mask to check if the length is multi-byte.

#define DER_BOOLEAN_FALSE 0x00	 //!< DER encoded boolean false value.
#define DER_BOOLEAN_TRUE 0xff	 //!< DER encoded boolean true value.

/** Which member of the fr_der_attr_flags_t union is in use
 *
 */
typedef enum {
	FR_DER_ATTR_FLAG_NONE = 0,		//!< no member is in use
	FR_DER_ATTR_FLAG_SEQUENCE_OF,		//!< sequence_of has been defined
	FR_DER_ATTR_FLAG_SETOF,			//!< set_of has been defined
	FR_DER_ATTR_FLAG_DEFAULT_VALUE,		//!< a default value exists
	FR_DER_ATTR_FLAG_SHORTNAME		//!< has a short name
} fr_der_attr_flag_type_t;

typedef struct {
	fr_der_tag_class_t 	class;		//!< tag Class
	fr_der_tag_t 		der_type;	//!< the DER type, which is different from the FreeRADIUS type

	/*
	 *	The member which is in use is given by 'flag_type'.
	 */
	union {
		fr_der_tag_t 		sequence_of;
		fr_der_tag_t 		set_of;
		fr_value_box_t		*default_value;
		char const		*shortname;
	};
	uint64_t 		max;			//!< maximum count of items in a sequence, set, or string.
	uint32_t		restrictions;		//!< for choice of options and tags - no dups allowed
	uint8_t			min;			//!< mininum count
	uint8_t 		option;			//!< an "attribute number" encoded in the tag field.
	fr_der_attr_flag_type_t	flag_type : 3;		//!< which member of the union is in use
	unsigned int		is_option : 1;		//!< has an option defined
	unsigned int		optional : 1;		//!< optional, we MUST already have set 'option'
	unsigned int   		is_oid_and_value : 1;	//!< is OID+value
	unsigned int   		is_extensions : 1;	//!< a list of X.509 extensions
	unsigned int   		leaf : 1;		//!< encode this OID along with its value
	unsigned int		is_choice : 1;		//!< DER name "choice".
} fr_der_attr_flags_t;

typedef struct {
	TALLOC_CTX	*tmp_ctx;		//!< ctx under which temporary data will be allocated
	fr_dict_attr_t const *root;		//!< where to start decoding from
} fr_der_decode_ctx_t;

extern fr_dict_protocol_t libfreeradius_der_dict_protocol;

/** Return DER-specific flags for a given attribute
 *
 * Assert in debug builds when the attribute belongs to another dictionary, as
 * the flags of one protocol say nothing about an attribute of another.
 *
 * If the attribute does not carry the protocol-specific extension, then assert.
 * Other builds log the error and return zeroed flags instead of NULL.
 */
static inline fr_der_attr_flags_t const *fr_der_attr_flags(fr_dict_attr_t const *da)
{
	static fr_der_attr_flags_t const	no_flags = {};
	fr_der_attr_flags_t const		*flags;

	fr_assert_msg(fr_dict_protocol(da->dict) == &libfreeradius_der_dict_protocol,
		      "%s is not a DER attribute, it is from the \"%s\" dictionary",
		      da->name, fr_dict_root(da->dict)->name);

	flags = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
	if (!fr_cond_assert_msg(flags, "%s is not a DER attribute, it has no protocol extension",
				da->name)) return &no_flags;

	return flags;
}

static inline uint8_t fr_der_flag_option(fr_dict_attr_t const *da)
{
	return fr_der_attr_flags(da)->option;
}

static inline bool fr_der_flag_optional(fr_dict_attr_t const *da)
{
	return fr_der_attr_flags(da)->optional;
}

static inline fr_der_tag_class_t fr_der_flag_class(fr_dict_attr_t const *da)
{
	return fr_der_attr_flags(da)->class;
}

static inline fr_der_tag_t fr_der_flag_der_type(fr_dict_attr_t const *da)
{
	return fr_der_attr_flags(da)->der_type;
}

static inline fr_der_tag_t fr_der_flag_sequence_of(fr_dict_attr_t const *da)
{
	fr_der_attr_flags_t const *flags = fr_der_attr_flags(da);

	fr_assert_msg(flags->flag_type == FR_DER_ATTR_FLAG_SEQUENCE_OF,
		      "%s is not a 'sequence_of=...' attribute, so the union does not hold 'sequence_of'",
		      da->name);

	return flags->sequence_of;
}

static inline bool fr_der_flag_is_sequence_of(fr_dict_attr_t const *da)
{
	return fr_der_attr_flags(da)->flag_type == FR_DER_ATTR_FLAG_SEQUENCE_OF;
}

static inline fr_der_tag_t fr_der_flag_set_of(fr_dict_attr_t const *da)
{
	fr_der_attr_flags_t const *flags = fr_der_attr_flags(da);

	fr_assert_msg(flags->flag_type == FR_DER_ATTR_FLAG_SETOF,
		      "%s is not a 'set_of=...' attribute, so the union does not hold 'set_of'",
		      da->name);

	return flags->set_of;
}

static inline bool fr_der_flag_is_set_of(fr_dict_attr_t const *da)
{
	return fr_der_attr_flags(da)->flag_type == FR_DER_ATTR_FLAG_SETOF;
}

static inline uint64_t fr_der_flag_max(fr_dict_attr_t const *da)
{
	return fr_der_attr_flags(da)->max;
}

static inline bool fr_der_flag_is_oid_and_value(fr_dict_attr_t const *da)
{
	return fr_der_attr_flags(da)->is_oid_and_value;
}

static inline bool fr_der_flag_is_extensions(fr_dict_attr_t const *da)
{
	return fr_der_attr_flags(da)->is_extensions;
}

static inline bool fr_der_flag_has_default_value(fr_dict_attr_t const *da)
{
	return fr_der_attr_flags(da)->flag_type == FR_DER_ATTR_FLAG_DEFAULT_VALUE;
}

static inline bool fr_der_flag_leaf(fr_dict_attr_t const *da)
{
	return fr_der_attr_flags(da)->leaf;
}

static inline bool fr_der_flag_is_choice(fr_dict_attr_t const *da)
{
	return fr_der_attr_flags(da)->is_choice;
}

/*
 * 	base.c
 */
fr_der_tag_t fr_type_to_der_tag_default(fr_type_t type);
bool	fr_type_to_der_tag_valid(fr_type_t type, fr_der_tag_t tag);
bool	fr_der_tags_compatible(fr_der_tag_t tag1, fr_der_tag_t tag2);
char	const *fr_der_tag_to_str(fr_der_tag_t tag);
char	const *fr_der_dict_attr_to_shortname(fr_dict_attr_t const *da);

int	fr_der_global_init(void);
void	fr_der_global_free(void);

/*
 *	decode.c
 */
ssize_t	fr_der_decode_pair_dbuff(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_attr_t const *parent,
				 fr_dbuff_t *in, fr_der_decode_ctx_t *decode_ctx);
