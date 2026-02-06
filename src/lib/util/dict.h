#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Multi-protocol AVP dictionary API
 *
 * @file src/lib/util/dict.h
 *
 * @copyright 2015 The FreeRADIUS server project
 */

RCSIDH(dict_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/dl.h>
#include <freeradius-devel/util/ext.h>
#include <freeradius-devel/util/hash.h>
#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/types.h>

#include <stdbool.h>
#include <stdint.h>

/*
 *	Avoid circular type references.
 */
typedef struct dict_attr_s fr_dict_attr_t;
typedef struct fr_dict_s fr_dict_t;

typedef struct value_box_s fr_value_box_t;

/*
 *	Allow public and private versions of the same structures
 */
#ifdef _CONST
#  error _CONST can only be defined in the local header
#endif
#ifndef _DICT_PRIVATE
#  define _CONST const
#else
#  define _CONST
#endif

#ifdef WITH_VERIFY_PTR
#  define DA_VERIFY(_x)		fr_dict_attr_verify(__FILE__, __LINE__, _x)
#else
#  define DA_VERIFY(_x)		fr_cond_assert(_x)
#endif

typedef struct dict_tokenize_ctx_s dict_tokenize_ctx_t;
typedef struct fr_dict_autoload_talloc_s fr_dict_autoload_talloc_t;

/** Values of the encryption flags
 */
typedef struct {
	unsigned int		is_root : 1;			//!< Is root of a dictionary.

	unsigned int 		is_unknown : 1;			//!< This dictionary attribute is ephemeral
								///< and not part of the main dictionary.

	unsigned int		is_raw : 1;			//!< This dictionary attribute was constructed
								///< from a known attribute to allow the user
								///< to assign octets values directly.
								///< See .is_unknown to determine if it is
								///< ephemeral.
	unsigned int		is_alias : 1;			//!< This isn't a real attribute, it's a reference to
								///< to one.
	unsigned int		has_alias : 1;			//!< this attribute has an alias.
	unsigned int		internal : 1;			//!< Internal attribute, should not be received
								///< in protocol packets, should not be encoded.
	unsigned int		array : 1; 			//!< Pack multiples into 1 attr.

	unsigned int		is_known_width : 1;		//!< is treated as if it has a known width for structs

	unsigned int		has_value : 1;			//!< Has a value.

	unsigned int		is_unsigned : 1;       		//!< hackity hack for dates and time deltas

	unsigned int		counter : 1;       		//!< integer attribute is actually an impulse / counter

	unsigned int		name_only : 1;			//!< this attribute should always be referred to by name.
								///< A number will be allocated, but the allocation scheme
								///< will depend on the parent, and definition type, and
								///< may not be stable in all instances.

	unsigned int		secret : 1;			//!< this attribute should be omitted in debug mode

	unsigned int		unsafe : 1;	       		//!< e.g. Cleartext-Password

	unsigned int		is_ref_target : 1;		//!< is the target of a ref, and cannot be moved.

	/*
	 *	@todo - if we want to clean these fields up, make
	 *	"subtype" and "type_size" both 4-bit bitfields.  That
	 *	gives us an extra 8 bits for adding new flags, and we
	 *	can likely get rid of "extra", in order to save one
	 *	more bit.
	 */
	unsigned int		extra : 1;			//!< really "subtype is used by dict, not by protocol"

	unsigned int		local : 1;       		//!< is a local variable

	unsigned int		allow_flat : 1;			//!< only for FR_TYPE_GROUP, can contain "flat" lists.

	unsigned int		has_fixup : 1;			//! needs a fixup during dictionary parsing

	/*
	 *	main: extra is set, then this field is is key, bit, or a uint16 length field.
	 *	radius: is one of 9 options for flags
	 *	dhcp v4/v6: DNS label, or partial DNS label
	 */
	uint8_t			subtype;			//!< protocol-specific values, OR key fields

	/*
	 *	TLVs: Number of bytes in the "type" field for TLVs (typically 1, 2, or 4)
	 *
	 *	da_is_bit_field(da): offset in the byte where this bit
	 *  	field ends.  This is only used as a caching mechanism
	 *  	during parsing of the dictionaries.
	 *
	 *	time/time_delta: fr_time_res_t, which has 4 possible values.
	 *
	 *	otherwise: unused.
	 */
	uint8_t			type_size;			//!< Type size for TLVs

	/*
	 *	da_is_bit_field(da): Length of the field in bits.
	 *
	 *	TLV: Number of bytes in the "length" field
	 *
	 *	otherwise: Length in bytes
	 */
	uint16_t	       	length;				//!< length of the attribute
} fr_dict_attr_flags_t;

#define flag_time_res type_size
#define flag_byte_offset type_size

/** subtype values for the dictionary when extra=1
 *
 */
enum {
	FLAG_EXTRA_NONE = 0,				//!< no extra meaning, should be invalid
	FLAG_KEY_FIELD,					//!< this is a key field for a subsequent struct
	FLAG_BIT_FIELD,				       	//!< bit field inside of a struct
	FLAG_LENGTH_UINT8,				//!< string / octets type is prefixed by uint8 of length
	FLAG_LENGTH_UINT16,				//!< string / octets type is prefixed by uint16 of length
};

#define fr_dict_attr_is_key_field(_da) ((_da)->flags.extra && ((_da)->flags.subtype == FLAG_KEY_FIELD))
#define da_is_bit_field(_da) ((_da)->flags.extra && ((_da)->flags.subtype == FLAG_BIT_FIELD))
#define da_is_length_field(_da) ((_da)->flags.extra && (((_da)->flags.subtype == FLAG_LENGTH_UINT8) || ((_da)->flags.subtype == FLAG_LENGTH_UINT16)))
#define da_is_length_field8(_da) ((_da)->flags.extra && ((_da)->flags.subtype == FLAG_LENGTH_UINT8))
#define da_is_length_field16(_da) ((_da)->flags.extra && ((_da)->flags.subtype == FLAG_LENGTH_UINT16))
#define da_length_offset(_da) ((_da)->flags.type_size)

/** Extension identifier
 *
 * @note New extension structures should also be added to the to the appropriate table in dict_ext.c
 */
typedef enum {
	FR_DICT_ATTR_EXT_NAME = 0,				//!< Name of the attribute.
	FR_DICT_ATTR_EXT_CHILDREN,				//!< Attribute has children.
	FR_DICT_ATTR_EXT_REF,					//!< Attribute references another
								///< attribute and/or dictionary.
	FR_DICT_ATTR_EXT_KEY,					//!< UNION attribute references a key
	FR_DICT_ATTR_EXT_VENDOR,				//!< Cached vendor pointer.
	FR_DICT_ATTR_EXT_ENUMV,					//!< Enumeration values.
	FR_DICT_ATTR_EXT_NAMESPACE,				//!< Attribute has its own namespace.
	FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC,			//!< Protocol specific extensions
	FR_DICT_ATTR_EXT_MAX
} fr_dict_attr_ext_t;

/** Dictionary attribute
 */
struct dict_attr_s {
	fr_dict_t _CONST* _CONST dict;				//!< Dict attribute belongs to.

	char const		*name;				//!< Attribute name.
	size_t			name_len;			//!< Length of the name.

	unsigned int		attr;				//!< Attribute number.
	unsigned int		depth;				//!< Depth of nesting for this attribute.

	unsigned int		last_child_attr;		//!< highest value of last child attribute.

	fr_type_t		type;				//!< Value type.

	fr_dict_attr_t const	*parent;			//!< Immediate parent of this attribute.
	fr_dict_attr_t const	*next;				//!< Next child in bin.

	fr_dict_attr_flags_t	flags;				//!< Flags.

	struct {
		bool			attr_set : 1;		//!< Attribute number has been set.
								//!< We need the full range of values 0-UINT32_MAX
								///< so we can't use any attr values to indicate
								///< "unsetness".

		bool			finalised : 1;		//!< Attribute definition is complete and modifications
								///< that would change the address of the memory chunk
								///< of the attribute are no longer permitted.
	} state;

	char const		*filename;			//!< Where the attribute was defined.
								///< this buffer's lifetime is bound to the
								///< fr_dict_t.
	int			line;				//!< Line number where the attribute was defined.

	uint8_t			ext[FR_DICT_ATTR_EXT_MAX];	//!< Extensions to the dictionary attribute.
} CC_HINT(aligned(FR_EXT_ALIGNMENT));

/** Extension identifier
 *
 * @note New extension structures should also be added to the appropriate table in dict_ext.c
 */
typedef enum {
	FR_DICT_ENUM_EXT_ATTR_REF = 0,				//!< Reference to a child attribute associated with this key value
	FR_DICT_ENUM_EXT_MAX
} fr_dict_enum_ext_t;

/** Enum extension - Sub-struct or union pointer
 *
 */
typedef struct {
	fr_dict_attr_t const	*da;				//!< the child structure referenced by this value of key
} fr_dict_enum_ext_attr_ref_t;

/** Value of an enumerated attribute
 *
 * Maps one of more string values to integers and vice versa.
 */
typedef struct {
	char const		*name;				//!< Enum name.
	size_t			name_len;			//!< Allows for efficient name lookups when operating
								///< on partial buffers.
	fr_value_box_t const	*value;				//!< Enum value (what name maps to).

	uint8_t			ext[FR_DICT_ENUM_EXT_MAX];	//!< Extensions to the dictionary attribute.
} fr_dict_enum_value_t CC_HINT(aligned(FR_EXT_ALIGNMENT));

/** Private enterprise
 *
 * Represents an IANA private enterprise allocation.
 *
 * The width of the private enterprise number must be the same for all protocols
 * so we can represent a vendor with a single struct.
 */
typedef struct {
	uint32_t		pen;				//!< Private enterprise number.
	bool			continuation;			//!< we only have one flag for now, for WiMAX
	size_t			type; 				//!< Length of type data
	size_t			length;				//!< Length of length data
	char const		*name;				//!< Vendor name.
} fr_dict_vendor_t;

/** Specifies a value which must be present for the module to function
 *
 */
typedef struct {
	fr_value_box_t const	**out;				//!< Enumeration value.
	fr_dict_attr_t const	**attr;				//!< The protocol dictionary the attribute should
								///< be resolved in. ** so it's a compile time
								///< constant.
	char const		*name;				//!< of the attribute.
} fr_dict_enum_autoload_t;

/** Specifies an attribute which must be present for the module to function
 *
 */
typedef struct {
	fr_dict_attr_t const	**out;				//!< Where to write a pointer to the resolved
								//!< #fr_dict_attr_t.
	fr_dict_t const		**dict;				//!< The protocol dictionary the attribute should
								///< be resolved in. ** so it's a compile time
								///< constant.
	char const		*name;				//!< of the attribute.
	fr_type_t		type;				//!< of the attribute.  Mismatch is a fatal error.
} fr_dict_attr_autoload_t;

/** Specifies a dictionary which must be loaded/loadable for the module to function
 *
 */
typedef struct {
	fr_dict_t const		**out;				//!< Where to write a pointer to the loaded/resolved
								//!< #fr_dict_t.
	char const		*base_dir;			//!< Directory structure beneath share.
	char const		*proto;				//!< The protocol dictionary name.
} fr_dict_autoload_t;

#define DICT_AUTOLOAD_TERMINATOR { .out = NULL }


/** Errors returned by attribute lookup functions
 *
 */
typedef enum {
	FR_DICT_ATTR_OK			= 0,			//!< No error.
	FR_DICT_ATTR_NOTFOUND		= -1,			//!< Attribute couldn't be found.
	FR_DICT_ATTR_PROTOCOL_NOTFOUND	= -2,			//!< Protocol couldn't be found.
	FR_DICT_ATTR_PARSE_ERROR	= -3,			//!< Attribute string couldn't be parsed
	FR_DICT_ATTR_INTERNAL_ERROR	= -4,			//!< Internal error occurred.
	FR_DICT_ATTR_OOM		= -5,			//!< Memory allocation error.
	FR_DICT_ATTR_NOT_DESCENDENT	= -6,			//!< Attribute is not a descendent of the parent
								///< attribute.
	FR_DICT_ATTR_NOT_ANCESTOR	= -7,			//!< Attribute is not an ancestor of the child
								///< attribute.
	FR_DICT_ATTR_NO_CHILDREN	= -8,			//!< Child lookup in attribute with no children.
	FR_DICT_ATTR_EINVAL		= -9			//!< Invalid arguments.

} fr_dict_attr_err_t;

typedef bool (*fr_dict_attr_valid_func_t)(fr_dict_attr_t *da);
typedef bool (*fr_dict_attr_type_parse_t)(fr_type_t *type, fr_dict_attr_t **da_p, char const *name);

/*
 *	Forward declarations to avoid circular references.
 */
typedef struct pair_list_s fr_pair_list_t;
typedef struct fr_dbuff_s fr_dbuff_t;

/** A generic interface for decoding packets to fr_pair_ts
 *
 * A decoding function should decode a single top level packet from wire format.
 *
 * Note that unlike #fr_tp_proto_decode_t, this function is NOT passed an encode_ctx.  That is because when we
 * do cross-protocol encoding, the "outer" protocol has no information it can share with the "inner" protocol.
 *
 * @param[in] ctx		to allocate new pairs in.
 * @param[in] vps		where new VPs will be added
 * @param[in] data		to decode.
 * @param[in] data_len		The length of the incoming data.
 * @return
 *	- <= 0 on error.  May be the offset (as a negative value) where the error occurred.
 *	- > 0 on success.  How many bytes were decoded.
 */
typedef ssize_t (*fr_dict_attr_decode_func_t)(TALLOC_CTX *ctx, fr_pair_list_t *vps,
					      uint8_t const *data, size_t data_len);

/** A generic interface for encoding fr_pair_ts to packets
 *
 * An encoding function should encode multiple VPs to a wire format packet
 *
 * Note that unlike #fr_tp_proto_encode_t, this function is NOT passed an encode_ctx.  That is because when we
 * do cross-protocol encoding, the "outer" protocol has no information it can share with the "inner" protocol.
 *
 * @param[in] vps		vps to encode
 * @param[in] dbuff		buffer where data can be written
 * @return
 *	- <= 0 on error.  May be the offset (as a negative value) where the error occurred.
 *	- > 0 on success.  How many bytes were encoded
 */
typedef ssize_t(*fr_dict_attr_encode_func_t)(fr_dbuff_t *dbuff, fr_pair_list_t const *vps);

/** Init / free callbacks
 *
 *  Only for "autoref" usage.
 */
typedef int (*fr_dict_protocol_init_t)(void);
typedef void (*fr_dict_protocol_free_t)(void);

typedef struct fr_dict_flag_parser_rule_s fr_dict_flag_parser_rule_t;

/** Custom protocol-specific flag parsing function
 *
 * @note This function should be used to implement table based flag parsing.
 *
 * @param[in] da_p	we're currently populating
 * @param[in] value	flag value to parse.
 * @param[in] rule	How to parse the flag.
 */
typedef int (*fr_dict_flag_parse_func_t)(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rule);

struct fr_dict_flag_parser_rule_s {
	fr_dict_flag_parse_func_t	func;				//!< Custom parsing function to convert a flag value string to a C type value.
	void				*uctx;				//!< Use context to pass to the custom parsing function.
	bool				needs_value;			//!< This parsing flag must have a value.  Else we error.
};

/** Copy custom flags from one attribute to another
 *
 * @param[out] da_to		attribute to copy to.  Use for the talloc_ctx for any heap allocated flag values.
 * @param[out] flags_to		protocol specific flags struct to copy to.
 * @param[in] flags_from	protocol specific flags struct to copy from.
 * @return
 *  - 0 on success.
 *  - -1 on error.
 */
typedef int (*fr_dict_flags_copy_func_t)(fr_dict_attr_t *da_to, void *flags_to, void *flags_from);

/** Compare the protocol specific flags struct from two attributes
 *
 * @param[in] da_a	first attribute to compare.
 * @param[in] da_b	second attribute to compare.
 * @return
 *  - 0 if the flags are equal.
 *  - < 0 if da_a < da_b.
 *  - > 0 if da_a > da_b.
 */
 typedef int (*fr_dict_flags_cmp_func_t)(fr_dict_attr_t const *da_a, fr_dict_attr_t const *da_b);

/** Protocol specific custom flag definitnion
 *
 */
typedef struct  {
	fr_table_elem_name_t		name;				//!< Name of the flag
	fr_dict_flag_parser_rule_t	value;				//!< Function and context to parse the flag.
} fr_dict_flag_parser_t;

/** Define a flag setting function, which sets one bit in a fr_dict_attr_flags_t
 *
 * This is here, because AFAIK there's no completely portable way to get the bit
 * offset of a bit field in a structure.
 */
#define FR_DICT_ATTR_FLAG_FUNC(_struct, _name) \
static int dict_flag_##_name(fr_dict_attr_t **da_p, UNUSED char const *value, UNUSED fr_dict_flag_parser_rule_t const *rules)\
{ \
	_struct *flags = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC); \
	flags->_name = 1; \
	return 0; \
}

/** conf_parser_t which parses a single CONF_PAIR, writing the result to a field in a struct
 *
 * @param[in] _struct		containing the field to write the result to.
 * @param[in] _field		to write the flag to
 */
#  define FR_DICT_PROTOCOL_FLAG(_struct, _field)  \
	.type = FR_CTYPE_TO_TYPE((((_struct *)NULL)->_field)), \
	.offset = offsetof(_struct, _field)

/** Protocol-specific callbacks in libfreeradius-PROTOCOL
 *
 */
typedef struct {
	char const			*name;				//!< name of this protocol

	int				default_type_size;		//!< how many octets are in "type" field
	int				default_type_length;		//!< how many octets are in "length" field

	struct {
	        /** Custom flags for this protocol
		 */
		struct {
			fr_dict_flag_parser_t const	*table;			//!< Flags for this protocol, an array of fr_dict_flag_parser_t
			size_t				table_len;		//!< Length of protocol_flags table.

			size_t				len;			//!< Length of the protocol specific flags structure.
										///< This is used to allocate a FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC
										///< extension of the specified length.

			fr_dict_flags_copy_func_t	copy;			//!< Copy protocol-specific flags from one attribute to another.
										///< Called when copying attributes.

			fr_dict_flags_cmp_func_t	cmp;			//!< Compare protocol-specific flags from two attributes.
										///< Called when comparing attributes by their fields.
		} flags;

		fr_dict_attr_type_parse_t	type_parse;		//!< parse unknown type names
		fr_dict_attr_valid_func_t 	valid;			//!< Validation function to ensure that
									///< new attributes are valid.
	} attr;

	fr_dict_protocol_init_t		init;				//!< initialize the library
	fr_dict_protocol_free_t		free;				//!< free the library

	fr_dict_attr_decode_func_t 	decode;				//!< for decoding attributes.  Used for implementing foreign
									///< protocol attributes.
	fr_dict_attr_encode_func_t 	encode;				//!< for encoding attributes.  Used for implementing foreign
									///< protocol attributes.
} fr_dict_protocol_t;

typedef struct fr_dict_gctx_s fr_dict_gctx_t;

/*
 *	Dictionary constants
 */
#define FR_DICT_PROTO_MAX_NAME_LEN	(128)				//!< Maximum length of a protocol name.
#define FR_DICT_ENUM_MAX_NAME_LEN	(128)				//!< Maximum length of a enum value.
#define FR_DICT_VENDOR_MAX_NAME_LEN	(128)				//!< Maximum length of a vendor name.
#define FR_DICT_ATTR_MAX_NAME_LEN	(128)				//!< Maximum length of a attribute name.

/** Maximum level of TLV nesting allowed
 */
#define FR_DICT_TLV_NEST_MAX		(24)

/** Maximum TLV stack size
 *
 * The additional attributes are to account for
 *
 * Root + Vendor + NULL (top frame).
 * Root + Embedded protocol + Root + Vendor + NULL.
 *
 * Code should ensure that it doesn't run off the end of the stack,
 * as this could be remotely exploitable, using odd nesting.
 */
#define FR_DICT_MAX_TLV_STACK		(FR_DICT_TLV_NEST_MAX + 5)

/** Characters allowed in a single dictionary attribute name
 *
 */
extern bool const	fr_dict_attr_allowed_chars[UINT8_MAX + 1];

/** Characters allowed in a nested dictionary attribute name
 *
 */
extern bool const fr_dict_attr_nested_allowed_chars[UINT8_MAX + 1];

/** Characters that are allowed in dictionary enumeration value names
 *
 */
extern bool const	fr_dict_enum_allowed_chars[UINT8_MAX + 1];

/** @name Dictionary structure extensions
 *
 * @{
 */
#include <freeradius-devel/util/dict_ext.h>
/** @} */

/** @name Programmatically create dictionary attributes and values
 *
 * @{
 */
int 			fr_dict_attr_add_initialised(fr_dict_attr_t *da) CC_HINT(nonnull);

int			fr_dict_attr_add(fr_dict_t *dict, fr_dict_attr_t const *parent, char const *name, unsigned int attr,
					 fr_type_t type, fr_dict_attr_flags_t const *flags) CC_HINT(nonnull(1,2,3));

int			fr_dict_attr_add_name_only(fr_dict_t *dict, fr_dict_attr_t const *parent,
						   char const *name, fr_type_t type, fr_dict_attr_flags_t const *flags) CC_HINT(nonnull(1,2,3));

int			fr_dict_enum_add_name(fr_dict_attr_t *da, char const *name,
					      fr_value_box_t const *value, bool coerce, bool replace);

int			fr_dict_enum_add_name_next(fr_dict_attr_t *da, char const *name) CC_HINT(nonnull);

int			fr_dict_str_to_argv(char *str, char **argv, int max_argc);

int			fr_dict_attr_acopy_local(fr_dict_attr_t const *dst, fr_dict_attr_t const *src) CC_HINT(nonnull);

int			fr_dict_attr_set_group(fr_dict_attr_t **da_p, fr_dict_attr_t const *ref) CC_HINT(nonnull);
/** @} */

/** @name Dict accessors
 *
 * @{
 */
fr_dict_protocol_t const *fr_dict_protocol(fr_dict_t const *dict);
/** @} */

/** @name Unknown ephemeral attributes
 *
 * @{
 */
fr_dict_attr_t		*fr_dict_attr_unknown_alloc(TALLOC_CTX *ctx, fr_dict_attr_t const *da, fr_type_t type) CC_HINT(nonnull(2));

fr_dict_attr_t const	*fr_dict_attr_unknown_add(fr_dict_t *dict, fr_dict_attr_t const *old) CC_HINT(nonnull);

void			fr_dict_attr_unknown_free(fr_dict_attr_t const **da);

fr_dict_attr_t		*fr_dict_attr_unknown_afrom_da(TALLOC_CTX *ctx, fr_dict_attr_t const *da) CC_HINT(nonnull(2));

static inline fr_dict_attr_t *fr_dict_attr_unknown_copy(TALLOC_CTX *ctx, fr_dict_attr_t const *da)
{
	fr_assert(da->flags.is_unknown);

	return fr_dict_attr_unknown_afrom_da(ctx, da);
}

fr_dict_attr_t		*fr_dict_attr_unknown_typed_afrom_num_raw(TALLOC_CTX *ctx,
								  fr_dict_attr_t const *parent,
								  unsigned int num, fr_type_t type, bool raw)
								  CC_HINT(nonnull(2));

static inline CC_HINT(nonnull(2)) fr_dict_attr_t *fr_dict_attr_unknown_typed_afrom_num(TALLOC_CTX *ctx,
										       fr_dict_attr_t const *parent,
										       unsigned int num, fr_type_t type)
{
	return fr_dict_attr_unknown_typed_afrom_num_raw(ctx, parent, num, type, false);
}


static inline CC_HINT(nonnull(2)) fr_dict_attr_t *fr_dict_attr_unknown_vendor_afrom_num(TALLOC_CTX *ctx,
											fr_dict_attr_t const *parent,
											unsigned int vendor)
{
	return fr_dict_attr_unknown_typed_afrom_num_raw(ctx, parent, vendor, FR_TYPE_VENDOR, false);
}

static inline CC_HINT(nonnull(2)) fr_dict_attr_t *fr_dict_attr_unknown_raw_afrom_num(TALLOC_CTX *ctx,
										     fr_dict_attr_t const *parent,
										     unsigned int attr)
{
	return fr_dict_attr_unknown_typed_afrom_num_raw(ctx, parent, attr, FR_TYPE_OCTETS, true);
}

static inline CC_HINT(nonnull(2)) fr_dict_attr_t *fr_dict_attr_unknown_afrom_oid(TALLOC_CTX *ctx,
										     fr_dict_attr_t const *parent,
										     fr_sbuff_t *in, fr_type_t type)
{
	uint32_t		num;
	fr_sbuff_parse_error_t	sberr;

	fr_sbuff_out(&sberr, &num, in);
	if (sberr != FR_SBUFF_PARSE_OK) return NULL;

	return fr_dict_attr_unknown_typed_afrom_num_raw(ctx, parent, num, type, true);
}

static inline CC_HINT(nonnull(2)) fr_dict_attr_t *fr_dict_attr_unknown_raw_afrom_da(TALLOC_CTX *ctx, fr_dict_attr_t const *da)
{
	return fr_dict_attr_unknown_alloc(ctx, da, FR_TYPE_OCTETS);
}


fr_slen_t		fr_dict_attr_unknown_afrom_oid_substr(TALLOC_CTX *ctx,
							      fr_dict_attr_t const **out,
							      fr_dict_attr_t const *parent,
							      fr_sbuff_t *in, fr_type_t type)
							      CC_HINT(nonnull(2,3,4));

int			fr_dict_attr_unknown_parent_to_known(fr_dict_attr_t *da, fr_dict_attr_t const *parent);

fr_dict_attr_t const	*fr_dict_attr_unknown_resolve(fr_dict_t const *dict, fr_dict_attr_t const *da);
/** @} */

/** @name Attribute comparisons
 *
 * @{
 */
int8_t			fr_dict_attr_ordered_cmp(fr_dict_attr_t const *a, fr_dict_attr_t const *b);

static inline CC_HINT(nonnull) int8_t fr_dict_attr_cmp(fr_dict_attr_t const *a, fr_dict_attr_t const *b)
{
	int8_t ret;

	/*
	 *	Comparing unknowns or raws is expensive
	 *	because we need to check the lineage.
	 */
	if (a->flags.is_unknown | a->flags.is_raw | b->flags.is_unknown | b->flags.is_raw) {
		ret = CMP(a->depth, b->depth);
		if (ret != 0) return ret;

		ret = CMP(a->attr, b->attr);
		if (ret != 0) return ret;

		ret = (a->parent == NULL) - (b->parent == NULL);
		if ((ret != 0) || !a->parent) return ret;

		return fr_dict_attr_cmp(a->parent, b->parent);
	}

	/*
	 *	Comparing knowns is cheap because the
	 *	DAs are unique.
	 */
	return CMP(a, b);
}

/** Compare two dictionary attributes by their contents
 *
 * @param[in] a	First attribute to compare.
 * @param[in] b	Second attribute to compare.
 * @return
 *	- 0 if the attributes are equal.
 *	- -1 if a < b.
 *	- +1 if a > b.
 */
static inline CC_HINT(nonnull) int8_t fr_dict_attr_cmp_fields(const fr_dict_attr_t *a, const fr_dict_attr_t *b)
{
	int8_t ret;
	fr_dict_protocol_t const *a_proto = fr_dict_protocol(a->dict);

	/*
	 *	Technically this isn't a property of the attribute
	 *	but we need them to be the same to be able to
	 *	compare protocol specific flags successfully.
	 */
	ret = CMP(a_proto, fr_dict_protocol(b->dict));
	if (ret != 0) return ret;

	ret = CMP(a->attr, b->attr);
	if (ret != 0) return ret;

	ret = CMP(a->parent, b->parent);
	if (ret != 0) return ret;

	ret = CMP(fr_dict_vendor_num_by_da(a), fr_dict_vendor_num_by_da(b));
	if (ret != 0) return ret;

	/*
	 *	Compare protocol specific flags
	 */
	if (a_proto->attr.flags.cmp && (ret = a_proto->attr.flags.cmp(a, b))) return ret;

	return CMP(memcmp(&a->flags, &b->flags, sizeof(a->flags)), 0);
}
/** @} */

/** @name Debugging functions
 *
 * @{
 */
void			fr_dict_namespace_debug(FILE *fp, fr_dict_attr_t const *da);

void			fr_dict_attr_debug(FILE *fp, fr_dict_attr_t const *da);

void			fr_dict_debug(FILE *fp, fr_dict_t const *dict);

void			fr_dict_export(FILE *fp, fr_dict_t const *dict);

void			fr_dict_alias_export(FILE *fp, fr_dict_attr_t const *parent);
/** @} */

/** @name Attribute lineage
 *
 * @{
 */
fr_dict_attr_t const	*fr_dict_attr_common_parent(fr_dict_attr_t const *a, fr_dict_attr_t const *b, bool is_ancestor);

int			fr_dict_oid_component_legacy(unsigned int *out, char const **oid);

fr_slen_t		fr_dict_attr_flags_print(fr_sbuff_t *out, fr_dict_t const *dict,
						 fr_type_t type, fr_dict_attr_flags_t const *flags);

fr_slen_t		fr_dict_attr_oid_print(fr_sbuff_t *out,
					       fr_dict_attr_t const *ancestor, fr_dict_attr_t const *da, bool numeric);
#define			FR_DICT_ATTR_OID_PRINT_RETURN(...) FR_SBUFF_RETURN(fr_dict_attr_oid_print, ##__VA_ARGS__)

fr_slen_t		fr_dict_attr_by_oid_legacy(fr_dict_t const *dict, fr_dict_attr_t const **parent,
					           unsigned int *attr, char const *oid) CC_HINT(nonnull);

fr_slen_t		fr_dict_oid_component(fr_dict_attr_err_t *err,
					      fr_dict_attr_t const **out, fr_dict_attr_t const *parent,
					      fr_sbuff_t *in, fr_sbuff_term_t const *tt)
					      CC_HINT(nonnull(2,3,4));

fr_slen_t		fr_dict_attr_by_oid_substr(fr_dict_attr_err_t *err,
						   fr_dict_attr_t const **out, fr_dict_attr_t const *parent,
						   fr_sbuff_t *in, fr_sbuff_term_t const *tt)
						   CC_HINT(nonnull(2,3,4));

fr_dict_attr_t const	*fr_dict_attr_by_oid(fr_dict_attr_err_t *err,
					     fr_dict_attr_t const *parent, char const *oid)
					     CC_HINT(nonnull(2,3));

bool			fr_dict_attr_can_contain(fr_dict_attr_t const *parent, fr_dict_attr_t const *child) CC_HINT(nonnull);

/** @} */

/** @name Attribute, vendor and dictionary lookup
 *
 * @{
 */

/** @hidecallergraph */
fr_dict_attr_t const	*fr_dict_root(fr_dict_t const *dict) CC_HINT(nonnull);

bool			fr_dict_is_read_only(fr_dict_t const *dict);

dl_t			*fr_dict_dl(fr_dict_t const *dict);

fr_slen_t		fr_dict_by_protocol_substr(fr_dict_attr_err_t *err,
						   fr_dict_t const **out, fr_sbuff_t *name, fr_dict_t const *dict_def);

fr_dict_t const		*fr_dict_by_protocol_name(char const *name);

fr_dict_t const		*fr_dict_by_protocol_num(unsigned int num);

fr_dict_attr_t const	*fr_dict_unlocal(fr_dict_attr_t const *da) CC_HINT(nonnull);

fr_dict_t const		*fr_dict_proto_dict(fr_dict_t const *dict) CC_HINT(nonnull);

fr_dict_t const		*fr_dict_by_da(fr_dict_attr_t const *da) CC_HINT(nonnull);

fr_dict_t const		*fr_dict_by_attr_name(fr_dict_attr_t const **found, char const *name);

bool			fr_dict_compatible(fr_dict_t const *dict1, fr_dict_t const *dict2) CC_HINT(nonnull);

/** Return true if this attribute is parented directly off the dictionary root
 *
 * @param[in] da		to check.
 * @return
 *	- true if attribute is top level.
 *	- false if attribute is not top level.
 */
static inline bool fr_dict_attr_is_top_level(fr_dict_attr_t const *da)
{
	if (unlikely(!da) || unlikely(!da->parent)) return false;
	return da->parent->flags.is_root;
}

fr_dict_vendor_t const	*fr_dict_vendor_by_da(fr_dict_attr_t const *da);

fr_dict_vendor_t const	*fr_dict_vendor_by_name(fr_dict_t const *dict, char const *name);

fr_dict_vendor_t const	*fr_dict_vendor_by_num(fr_dict_t const *dict, uint32_t vendor_pen);

fr_dict_attr_t const	*fr_dict_vendor_da_by_num(fr_dict_attr_t const *vendor_root, uint32_t vendor_pen);

fr_slen_t		fr_dict_attr_search_by_qualified_name_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
								     fr_dict_t const *dict_def,
								     fr_sbuff_t *name, fr_sbuff_term_t const *tt,
								     bool internal, bool foreign)
								     CC_HINT(nonnull(2, 4));

fr_slen_t		fr_dict_attr_search_by_name_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
					  		   fr_dict_t const *dict_def,
							   fr_sbuff_t *name, fr_sbuff_term_t const *tt,
							   bool internal, bool foreign)
							   CC_HINT(nonnull(2, 4));

fr_slen_t		fr_dict_attr_search_by_qualified_oid_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
							     	    fr_dict_t const *dict_def,
								    fr_sbuff_t *in, fr_sbuff_term_t const *tt,
								    bool internal, bool foreign)
								    CC_HINT(nonnull(2, 4));

fr_dict_attr_t const	*fr_dict_attr_search_by_qualified_oid(fr_dict_attr_err_t *err,
						       	      fr_dict_t const *dict_def, char const *attr,
						       	      bool internal, bool foreign)
							      CC_HINT(nonnull(3));

fr_slen_t		fr_dict_attr_search_by_oid_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
							  fr_dict_t const *dict_def,
							  fr_sbuff_t *in, fr_sbuff_term_t const *tt,
							  bool internal, bool foreign)
							  CC_HINT(nonnull(2, 4));

fr_slen_t		fr_dict_attr_by_name_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
						    fr_dict_attr_t const *parent,
						    fr_sbuff_t *name, fr_sbuff_term_t const *tt)
						    CC_HINT(nonnull(2,3,4));

fr_dict_attr_t const	*fr_dict_attr_by_name(fr_dict_attr_err_t *err, fr_dict_attr_t const *parent,
					      char const *attr)
					      CC_HINT(nonnull(2,3));

fr_dict_attr_t const	*fr_dict_attr_child_by_num(fr_dict_attr_t const *parent, unsigned int attr);

typedef fr_hash_iter_t fr_dict_enum_iter_t;	/* Alias this in case we want to change it in future */

fr_dict_enum_value_t const *fr_dict_enum_iter_init(fr_dict_attr_t const *da, fr_dict_enum_iter_t *iter);

fr_dict_enum_value_t const *fr_dict_enum_iter_next(fr_dict_attr_t const *da, fr_dict_enum_iter_t *iter);

fr_dict_enum_value_t const *fr_dict_enum_by_value(fr_dict_attr_t const *da, fr_value_box_t const *value);

char const		*fr_dict_enum_name_by_value(fr_dict_attr_t const *da, fr_value_box_t const *value);

fr_dict_enum_value_t const *fr_dict_enum_by_name(fr_dict_attr_t const *da, char const *name, ssize_t len);

fr_slen_t		fr_dict_enum_by_name_substr(fr_dict_enum_value_t **out, fr_dict_attr_t const *da, fr_sbuff_t *in);

fr_slen_t		fr_dict_enum_name_from_substr(fr_sbuff_t *out, fr_sbuff_parse_error_t *err,
						      fr_sbuff_t *in, fr_sbuff_term_t const *tt);

static inline fr_slen_t fr_dict_enum_name_afrom_substr(TALLOC_CTX *ctx, char **out, fr_sbuff_parse_error_t *err,
						       fr_sbuff_t *in, fr_sbuff_term_t const *tt)
			SBUFF_OUT_TALLOC_FUNC_NO_LEN_DEF(fr_dict_enum_name_from_substr, err, in, tt)
/** @} */

/** @name Dictionary and protocol loading
 *
 * @{
 */
int			fr_dict_internal_afrom_file(fr_dict_t **out, char const *internal_name,
						    char const *dependent);

int			fr_dict_protocol_afrom_file(fr_dict_t **out, char const *proto_name, char const *proto_dir,
						    char const *dependent);

fr_dict_t		*fr_dict_protocol_alloc(fr_dict_t const *parent);

int			fr_dict_protocol_reference(fr_dict_attr_t const **da_p, fr_dict_attr_t const *root, fr_sbuff_t *in);

int			fr_dict_read(fr_dict_t *dict, char const *dict_dir, char const *filename);

bool			fr_dict_filename_loaded(fr_dict_t const *dict, char const *dict_dir, char const *filename);
/** @} */

/** @name Autoloader interface
 *
 * @{
 */
int			fr_dict_enum_autoload(fr_dict_enum_autoload_t const *to_load);

int			fr_dict_attr_autoload(fr_dict_attr_autoload_t const *to_load);

#define			fr_dict_autoload(_to_load) _fr_dict_autoload(_to_load, __FILE__)
int			_fr_dict_autoload(fr_dict_autoload_t const *to_load, char const *dependent);

#define			fr_dict_autofree(_to_free) _fr_dict_autofree(_to_free, __FILE__)
int			_fr_dict_autofree(fr_dict_autoload_t const *to_free, char const *dependent);

#define			fr_dict_autoload_talloc(_ctx, _dict_out, _proto) _fr_dict_autoload_talloc(_ctx, _dict_out, _proto, __FILE__)
fr_dict_autoload_talloc_t *_fr_dict_autoload_talloc(TALLOC_CTX *ctx, fr_dict_t const **out, char const *proto, char const *dependent);

int			fr_dl_dict_enum_autoload(dl_t const *module, void *symbol, void *user_ctx);

int			fr_dl_dict_attr_autoload(dl_t const *module, void *symbol, void *user_ctx);

int			fr_dl_dict_autoload(dl_t const *module, void *symbol, void *user_ctx);

void			fr_dl_dict_autofree(dl_t const *module, void *symbol, void *user_ctx);
/** @} */

/** @name Allocating and freeing
 *
 * @{
 */
fr_dict_t 		*fr_dict_alloc(char const *proto_name, unsigned int proto_number) CC_HINT(nonnull);

int			fr_dict_dependent_add(fr_dict_t const *dict, char const *dependent) CC_HINT(nonnull);

int			fr_dict_free(fr_dict_t **dict, char const *dependent) CC_HINT(nonnull);

int			fr_dict_const_free(fr_dict_t const **dict, char const *dependent) CC_HINT(nonnull);
/** @} */

/** @name Global dictionary management
 *
 * @{
 */
fr_dict_gctx_t		*fr_dict_global_ctx_init(TALLOC_CTX *ctx, bool free_at_exit, char const *dict_dir);

void			fr_dict_global_ctx_perm_check(fr_dict_gctx_t *gctx, bool enable);

void			fr_dict_global_ctx_set(fr_dict_gctx_t const *gctx);

int			fr_dict_global_ctx_free(fr_dict_gctx_t const *gctx);

int			fr_dict_global_ctx_dir_set(char const *dict_dir);

void			fr_dict_global_ctx_read_only(void);

void			fr_dict_gctx_debug(FILE *fp, fr_dict_gctx_t const *gctx);

char const		*fr_dict_global_ctx_dir(void);

typedef struct fr_hash_iter_s fr_dict_global_ctx_iter_t;

fr_dict_t		*fr_dict_global_ctx_iter_init(fr_dict_global_ctx_iter_t *iter) CC_HINT(nonnull);

fr_dict_t		*fr_dict_global_ctx_iter_next(fr_dict_global_ctx_iter_t *iter) CC_HINT(nonnull);

fr_dict_t		*fr_dict_unconst(fr_dict_t const *dict);

fr_dict_attr_t		*fr_dict_attr_unconst(fr_dict_attr_t const *da);

fr_dict_t const		*fr_dict_internal(void);

/** @} */

/** @name Dictionary testing and validation
 *
 * @{
 */
void			dict_dctx_debug(dict_tokenize_ctx_t *dctx);

int			fr_dict_parse_str(fr_dict_t *dict, char const *str,
					  fr_dict_attr_t const *parent);

ssize_t			fr_dict_valid_name(char const *name, ssize_t len);

ssize_t			fr_dict_valid_oid_str(char const *name, ssize_t len);

fr_dict_attr_t const	*fr_dict_attr_iterate_children(fr_dict_attr_t const *parent, fr_dict_attr_t const **prev);

typedef int		(*fr_dict_walk_t)(fr_dict_attr_t const *da, void *uctx);

int			fr_dict_walk(fr_dict_attr_t const *da, fr_dict_walk_t callback, void *uctx);

void			fr_dict_attr_verify(char const *file, int line, fr_dict_attr_t const *da);
/** @} */

#undef _CONST

#ifdef __cplusplus
}
#endif
