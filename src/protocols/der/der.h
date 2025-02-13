#include <freeradius-devel/build.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/types.h>

extern HIDDEN fr_dict_t const *dict_der;

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

	FR_DER_TAG_MAX		= UINT8_MAX
} fr_der_tag_num_t;

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

extern fr_der_tag_constructed_t tag_labels[];

/*
 *	Create a mapping between FR_TYPE_* and valid FR_DER_TAG_*'s
 */
static bool *fr_type_to_der_tags[] = {
	[FR_TYPE_MAX] = NULL,
	[FR_TYPE_BOOL] = (bool []){[FR_DER_TAG_BOOLEAN] = true,
				   [FR_DER_TAG_INTEGER] = true,
				   [FR_DER_TAG_NULL] = true,
				   [FR_DER_TAG_MAX] = false},
	[FR_TYPE_UINT8] = (bool []){[FR_DER_TAG_INTEGER] = true,
				    [FR_DER_TAG_ENUMERATED] = true,
				    [FR_DER_TAG_MAX] = false},
	[FR_TYPE_UINT16] = (bool []){[FR_DER_TAG_INTEGER] = true,
				     [FR_DER_TAG_ENUMERATED] = true,
				     [FR_DER_TAG_MAX] = false},
	[FR_TYPE_UINT32] = (bool []){[FR_DER_TAG_INTEGER] = true,
				     [FR_DER_TAG_ENUMERATED] = true,
				     [FR_DER_TAG_MAX] = false},
	[FR_TYPE_UINT64] = (bool []){[FR_DER_TAG_INTEGER] = true,
				     [FR_DER_TAG_ENUMERATED] = true,
				     [FR_DER_TAG_MAX] = false},
	[FR_TYPE_INT8] = (bool []){[FR_DER_TAG_INTEGER] = true,
				   [FR_DER_TAG_ENUMERATED] = true,
				   [FR_DER_TAG_MAX] = false},
	[FR_TYPE_INT16] = (bool []){[FR_DER_TAG_INTEGER] = true,
				    [FR_DER_TAG_ENUMERATED] = true,
				    [FR_DER_TAG_MAX] = false},
	[FR_TYPE_INT32] = (bool []){[FR_DER_TAG_INTEGER] = true,
				    [FR_DER_TAG_ENUMERATED] = true,
				    [FR_DER_TAG_MAX] = false},
	[FR_TYPE_INT64] = (bool []){[FR_DER_TAG_INTEGER] = true,
				    [FR_DER_TAG_ENUMERATED] = true,
				    [FR_DER_TAG_MAX] = false},
	[FR_TYPE_OCTETS] = (bool []){[FR_DER_TAG_BITSTRING] = true,
				     [FR_DER_TAG_OCTETSTRING] = true,
				     [FR_DER_TAG_MAX] = false},
	[FR_TYPE_STRING] = (bool []){[FR_DER_TAG_OID] = true,
				     [FR_DER_TAG_UTF8_STRING] = true,
				     [FR_DER_TAG_PRINTABLE_STRING] = true,
				     [FR_DER_TAG_T61_STRING] = true,
				     [FR_DER_TAG_IA5_STRING] = true,
				     [FR_DER_TAG_VISIBLE_STRING] = true,
				     [FR_DER_TAG_GENERAL_STRING] = true,
				     [FR_DER_TAG_UNIVERSAL_STRING] = true,
				     [FR_DER_TAG_MAX] = false},
	[FR_TYPE_DATE] = (bool []){[FR_DER_TAG_UTC_TIME] = true,
				   [FR_DER_TAG_GENERALIZED_TIME] = true,
				   [FR_DER_TAG_MAX] = false},
	[FR_TYPE_TLV] = (bool []){[FR_DER_TAG_SEQUENCE] = true,
				  [FR_DER_TAG_SET] = true,
				  [FR_DER_TAG_MAX] = false},
	[FR_TYPE_STRUCT] = (bool []){[FR_DER_TAG_BITSTRING] = true,
				     [FR_DER_TAG_SEQUENCE] = true,
				     [FR_DER_TAG_SET] = true,
				     [FR_DER_TAG_MAX] = false},
	[FR_TYPE_GROUP] = (bool []){[FR_DER_TAG_SEQUENCE] = true,
				    [FR_DER_TAG_SET] = true,
				    [FR_DER_TAG_MAX] = false}
};

/*
 *	Return true if the given type can be encoded as the given tag.
 * 		@param[in] type The fr_type to check.
 * 		@param[in] tag The der tag to check.
 * 		@return true if the type can be encoded as the given tag.
 */
static inline CC_HINT(always_inline) bool fr_type_to_der_tag_valid(fr_type_t type, fr_der_tag_num_t tag)
{
	return fr_type_to_der_tags[type][tag];
}

static int fr_type_to_der_tag_defaults[] = {
	[FR_TYPE_NULL] = FR_DER_TAG_NULL,
	[FR_TYPE_BOOL] = FR_DER_TAG_BOOLEAN,
	[FR_TYPE_UINT8] = FR_DER_TAG_INTEGER,
	[FR_TYPE_UINT16] = FR_DER_TAG_INTEGER,
	[FR_TYPE_UINT32] = FR_DER_TAG_INTEGER,
	[FR_TYPE_UINT64] = FR_DER_TAG_INTEGER,
	[FR_TYPE_INT8] = FR_DER_TAG_INTEGER,
	[FR_TYPE_INT16] = FR_DER_TAG_INTEGER,
	[FR_TYPE_INT32] = FR_DER_TAG_INTEGER,
	[FR_TYPE_INT64] = FR_DER_TAG_INTEGER,
	[FR_TYPE_OCTETS] = FR_DER_TAG_OCTETSTRING,
	[FR_TYPE_STRING] = FR_DER_TAG_UTF8_STRING,
	[FR_TYPE_DATE] = FR_DER_TAG_GENERALIZED_TIME,
	[FR_TYPE_TLV] = FR_DER_TAG_SEQUENCE,
	[FR_TYPE_STRUCT] = FR_DER_TAG_SEQUENCE,
	[FR_TYPE_GROUP] = FR_DER_TAG_SEQUENCE
};

static inline CC_HINT(always_inline) fr_der_tag_num_t fr_type_to_der_tag_default(fr_type_t type)
{
	return fr_type_to_der_tag_defaults[type];
}

#define DER_MAX_STR 16384

#define DER_UTC_TIME_LEN 13	 //!< Length of the UTC time string.
#define DER_GENERALIZED_TIME_LEN_MIN 15	 //!< Minimum length of the generalized time string.
#define DER_GENERALIZED_TIME_PRECISION_MAX 4 //!< Maximum precision of the generalized time string.

#define DER_TAG_CLASS_MASK 0xc0	 //!< Mask to extract the class from the tag.
#define DER_TAG_CONSTRUCTED_MASK 0x20	 //!< Mask to check if the tag is constructed.
#define DER_TAG_NUM_MASK 0x1f	 //!< Mask to extract the tag number from the tag.

#define DER_MAX_TAG_NUM 0xfe * 8	 //!< Maximum tag number that can be encoded in a single byte.

#define DER_TAG_CONTINUATION 0x1f	 //!< Mask to check if the tag is a continuation.

#define DER_LEN_MULTI_BYTE 0x80	 //!< Mask to check if the length is multi-byte.

#define DER_BOOLEAN_FALSE 0x00	 //!< DER encoded boolean false value.
#define DER_BOOLEAN_TRUE 0xff	 //!< DER encoded boolean true value.

typedef struct {
	uint8_t 		tagnum;
	fr_der_tag_class_t 	class;
	fr_der_tag_num_t 	subtype;
	fr_der_tag_num_t 	sequence_of;
	fr_der_tag_num_t 	set_of;
	int64_t 		max;
	bool 			is_sequence_of;
	bool 			is_set_of;
	bool 			is_pair;
	bool 			is_pairs;
	bool 			is_extensions; // This is a flag for a list X.509 extensions
	bool 			has_default;
	bool 			is_oid_leaf;
	bool			is_choice;
} fr_der_attr_flags_t;

static inline fr_der_attr_flags_t const *fr_der_attr_flags(fr_dict_attr_t const *da)
{
	return fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
}

#define fr_der_flag_tagnum(_da) 	(fr_der_attr_flags(_da)->tagnum)
#define fr_der_flag_class(_da)		(fr_der_attr_flags(_da)->class)
#define fr_der_flag_subtype(_da) 	(fr_der_attr_flags(_da)->subtype)
#define fr_der_flag_sequence_of(_da) 	(fr_der_attr_flags(_da)->sequence_of)
#define fr_der_flag_is_sequence_of(_da) (fr_der_attr_flags(_da)->is_sequence_of)
#define fr_der_flag_set_of(_da) 	(fr_der_attr_flags(_da)->set_of)
#define fr_der_flag_is_set_of(_da) 	(fr_der_attr_flags(_da)->is_set_of)
#define fr_der_flag_max(_da) 		(fr_der_attr_flags(_da)->max)
#define fr_der_flag_is_pair(_da) 	(fr_der_attr_flags(_da)->is_pair)
#define fr_der_flag_is_pairs(_da) 	(fr_der_attr_flags(_da)->is_pairs)
#define fr_der_flag_is_extensions(_da) 	(fr_der_attr_flags(_da)->is_extensions)
#define fr_der_flag_has_default(_da) 	(fr_der_attr_flags(_da)->has_default)
#define fr_der_flag_is_oid_leaf(_da) 	(fr_der_attr_flags(_da)->is_oid_leaf)
#define fr_der_flag_is_choice(_da) 	(fr_der_attr_flags(_da)->is_choice)

/*
 * 	base.c
 */
int fr_der_global_init(void);
void fr_der_global_free(void);
