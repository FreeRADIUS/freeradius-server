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
#include <freeradius-devel/util/rbtree.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/types.h>

#include <stdbool.h>
#include <stdint.h>
#include <talloc.h>

/*
 *	Avoid circular type references.
 */
typedef struct dict_attr_s fr_dict_attr_t;
typedef struct fr_dict fr_dict_t;

#include <freeradius-devel/util/value.h>

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
#  define DA_VERIFY(_x)		fr_dict_verify(__FILE__, __LINE__, _x)
#else
#  define DA_VERIFY(_x)		fr_cond_assert(_x)
#endif

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

	unsigned int		internal : 1;			//!< Internal attribute, should not be received
								///< in protocol packets, should not be encoded.
	unsigned int		array : 1; 			//!< Pack multiples into 1 attr.
	unsigned int		has_value : 1;			//!< Has a value.

	unsigned int		virtual : 1;			//!< for dynamic expansion

	unsigned int		extra : 1;			//!< really "subtype is used by dict, not by protocol"

	uint8_t			subtype;			//!< for FR_TYPE_STRING encoding

	uint8_t			length;				//!< length of the attribute
	uint8_t			type_size;			//!< For TLV2 and root attributes.
} fr_dict_attr_flags_t;

/** subtype values for the dictionary when extra=1
 *
 */
enum {
	FLAG_EXTRA_NONE = 0,				//!< no extra meaning, should be invalid
	FLAG_KEY_FIELD,					//!< this is a key field for a subsequent struct
	FLAG_BIT_FIELD,				       	//!< bit field inside of a struct
	FLAG_LENGTH_UINT16,				//!< string / octets type is prefixed by uint16 of length
	FLAG_HAS_REF,			       		//!< the attribute has a reference to somewhere else
};

#define da_is_key_field(_da) ((_da)->flags.extra && ((_da)->flags.subtype == FLAG_KEY_FIELD))
#define da_is_bit_field(_da) ((_da)->flags.extra && ((_da)->flags.subtype == FLAG_BIT_FIELD))
#define da_is_length_field(_da) ((_da)->flags.extra && ((_da)->flags.subtype == FLAG_LENGTH_UINT16))

extern const size_t dict_attr_sizes[FR_TYPE_MAX + 1][2];

/** Extension identifier
 *
 * @note New extension structures should also be added to the to the appropriate table in dict_ext.c
 */
typedef enum {
	FR_DICT_ATTR_EXT_NAME = 0,				//!< Name of the attribute.
	FR_DICT_ATTR_EXT_CHILDREN,				//!< Attribute has children.
	FR_DICT_ATTR_EXT_REF,					//!< Attribute references another
								///< attribute and/or dictionary.
	FR_DICT_ATTR_EXT_VENDOR,				//!< Cached vendor pointer.
	FR_DICT_ATTR_EXT_DA_STACK,				//!< Cached da stack.
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

	fr_type_t		type;				//!< Value type.

	fr_dict_attr_t const	*parent;			//!< Immediate parent of this attribute.
	fr_dict_attr_t const	*next;				//!< Next child in bin.
	fr_dict_attr_t		*fixup;				//!< Attribute has been marked up for fixups.

	fr_dict_attr_flags_t	flags;				//!< Flags.

	uint8_t			ext[FR_DICT_ATTR_EXT_MAX];	//!< Extensions to the dictionary attribute.
} CC_HINT(aligned(FR_EXT_ALIGNMENT));

/** Extension identifier
 *
 * @note New extension structures should also be added to the appropriate table in dict_ext.c
 */
typedef enum {
	FR_DICT_ENUM_EXT_UNION_REF = 0,				//!< Reference to a union/subs-struct.
	FR_DICT_ENUM_EXT_MAX
} fr_dict_enum_ext_t;

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

	fr_dict_attr_t const	*child_struct[0];		//!< for key fields
} fr_dict_enum_t CC_HINT(aligned(FR_EXT_ALIGNMENT));

/** Private enterprise
 *
 * Represents an IANA private enterprise allocation.
 *
 * The width of the private enterprise number must be the same for all protocols
 * so we can represent a vendor with a single struct.
 */
typedef struct {
	uint32_t		pen;				//!< Private enterprise number.
	size_t			type; 				//!< Length of type data
	size_t			length;				//!< Length of length data
	size_t			flags;				//!< Vendor flags.
	char const		*name;				//!< Vendor name.
} fr_dict_vendor_t;

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

/** Errors returned by attribute lookup functions
 *
 */
typedef enum {
	FR_DICT_ATTR_OK			= 0,			//!< No error.
	FR_DICT_ATTR_NOTFOUND		= -1,			//!< Attribute couldn't be found.
	FR_DICT_ATTR_PROTOCOL_NOTFOUND	= -2,			//!< Protocol couldn't be found.
	FR_DICT_ATTR_PARSE_ERROR	= -3,			//!< Attribute string couldn't be parsed
	FR_DICT_ATTR_OOM		= -4,			//!< Memory allocation error.
	FR_DICT_ATTR_NOT_DESCENDENT	= -5,			//!< Attribute is not a descendent of the parent
								///< attribute.
	FR_DICT_ATTR_NOT_ANCESTOR	= -6,			//!< Attribute is not an ancestor of the child
								///< attribute.
	FR_DICT_ATTR_NO_CHILDREN	= -7,			//!< Child lookup in attribute with no children.
	FR_DICT_ATTR_EINVAL		= -8			//!< Invalid arguments.
} fr_dict_attr_err_t;

typedef bool (*fr_dict_attr_valid_func_t)(fr_dict_t *dict, fr_dict_attr_t const *parent,
					  char const *name, int attr, fr_type_t type, fr_dict_attr_flags_t *flags);

/** Protocol-specific callbacks in libfreeradius-PROTOCOL
 *
 */
typedef struct {
	char const		*name;				//!< name of this protocol
	int			default_type_size;		//!< how many octets are in "type" field
	int			default_type_length;		//!< how many octets are in "length" field
	fr_table_num_ordered_t	const *subtype_table;		//!< for "encrypt=1", etc.
	size_t			subtype_table_len;		//!< length of subtype_table
	fr_dict_attr_valid_func_t attr_valid;			//!< validation function for new attributes
} fr_dict_protocol_t;

typedef struct fr_dict_gctx_s fr_dict_gctx_t;

/*
 *	Dictionary constants
 */
#define FR_DICT_PROTO_MAX_NAME_LEN	(128)			//!< Maximum length of a protocol name.
#define FR_DICT_ENUM_MAX_NAME_LEN	(128)			//!< Maximum length of a enum value.
#define FR_DICT_VENDOR_MAX_NAME_LEN	(128)			//!< Maximum length of a vendor name.
#define FR_DICT_ATTR_MAX_NAME_LEN	(128)			//!< Maximum length of a attribute name.

/** Maximum level of TLV nesting allowed
 */
#define FR_DICT_TLV_NEST_MAX		(24)

/** Maximum level of da stack caching
 */
#define FR_DICT_DA_STACK_CACHE_MAX	(5)

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

/** Characters that are allowed in dictionary attribute names
 *
 */
extern bool const	fr_dict_attr_allowed_chars[UINT8_MAX + 1];
extern bool const	fr_dict_non_data_types[FR_TYPE_MAX + 1];

/** @name Dictionary structure extensions
 *
 * @{
 */
#include <freeradius-devel/util/dict_ext.h>
/** @} */

/** @name Programatically create dictionary attributes and values
 *
 * @{
 */
int			fr_dict_attr_add(fr_dict_t *dict, fr_dict_attr_t const *parent, char const *name, int attr,
					 fr_type_t type, fr_dict_attr_flags_t const *flags) CC_HINT(nonnull(1,2,3));

int			fr_dict_attr_enum_add_name(fr_dict_attr_t *da, char const *name,
						   fr_value_box_t const *value, bool coerce, bool replace);

int			fr_dict_attr_enum_add_name_next(fr_dict_attr_t *da, char const *name) CC_HINT(nonnull);

int			fr_dict_str_to_argv(char *str, char **argv, int max_argc);
/** @} */

/** @name Unknown ephemeral attributes
 *
 * @{
 */
fr_dict_attr_t const	*fr_dict_unknown_add(fr_dict_t *dict, fr_dict_attr_t const *old) CC_HINT(nonnull);

void			fr_dict_unknown_free(fr_dict_attr_t const **da);

fr_dict_attr_t		*fr_dict_unknown_afrom_da(TALLOC_CTX *ctx, fr_dict_attr_t const *da);

fr_dict_attr_t		*fr_dict_unknown_vendor_afrom_num(TALLOC_CTX *ctx,
							  fr_dict_attr_t const *parent, unsigned int vendor)
							  CC_HINT(nonnull(2));

fr_dict_attr_t		*fr_dict_unknown_tlv_afrom_num(TALLOC_CTX *ctx,
						       fr_dict_attr_t const *parent, unsigned int num)
						       CC_HINT(nonnull(2));

fr_dict_attr_t		*fr_dict_unknown_attr_afrom_num(TALLOC_CTX *ctx,
							fr_dict_attr_t const *parent, unsigned int num)
							CC_HINT(nonnull(2));

fr_dict_attr_t		*fr_dict_unknown_afrom_fields(TALLOC_CTX *ctx,
						      fr_dict_attr_t const *parent,
						      unsigned int vendor, unsigned int attr)
						      CC_HINT(nonnull(2));

ssize_t			fr_dict_unknown_afrom_oid_substr(TALLOC_CTX *ctx,
							 fr_dict_attr_err_t *err, fr_dict_attr_t **out,
							 fr_dict_attr_t const *parent, fr_sbuff_t *in)
							 CC_HINT(nonnull(3,4,5));

fr_dict_attr_t const	*fr_dict_attr_known(fr_dict_t const *dict, fr_dict_attr_t const *da);
/** @} */

/** @name Attribute comparisons
 *
 * @{
 */
static inline  CC_HINT(nonnull) int8_t fr_dict_attr_cmp(fr_dict_attr_t const *a, fr_dict_attr_t const *b)
{
	int8_t ret;

	/*
	 *	Comparing unknowns or raws is expensive
	 *	because we need to check the lineage.
	 */
	if (a->flags.is_unknown | a->flags.is_raw | b->flags.is_unknown | b->flags.is_raw) {
		ret = STABLE_COMPARE(a->depth, b->depth);
		if (ret != 0) return ret;

		ret = STABLE_COMPARE(a->attr, b->attr);
		if (ret != 0) return ret;

		ret = (a->parent == NULL) - (b->parent == NULL);
		if ((ret != 0) || !a->parent) return ret;

		return fr_dict_attr_cmp(a->parent, b->parent);
	}

	/*
	 *	Comparing knowns is cheap because the
	 *	DAs are unique.
	 */
	return STABLE_COMPARE(a, b);
}
/** @} */

/** @name Debugging functions
 *
 * @{
 */
void			fr_dict_namespace_debug(fr_dict_attr_t const *da);

void			fr_dict_attr_debug(fr_dict_attr_t const *da);

void			fr_dict_debug(fr_dict_t const *dict);
/** @} */

/** @name Attribute lineage
 *
 * @{
 */
fr_dict_attr_t const	*fr_dict_attr_common_parent(fr_dict_attr_t const *a, fr_dict_attr_t const *b, bool is_ancestor);

int			fr_dict_oid_component_legacy(unsigned int *out, char const **oid);

ssize_t			fr_dict_snprint_flags(fr_sbuff_t *out, fr_dict_t const *dict,
					      fr_type_t type, fr_dict_attr_flags_t const *flags);

ssize_t			fr_dict_attr_oid_print(fr_sbuff_t *out,
					       fr_dict_attr_t const *ancestor, fr_dict_attr_t const *da);
#define			FR_DICT_ATTR_OID_PRINT_RETURN(...) FR_SBUFF_RETURN(fr_dict_attr_oid_print, ##__VA_ARGS__)

ssize_t			fr_dict_attr_by_oid_legacy(fr_dict_t const *dict, fr_dict_attr_t const **parent,
					           unsigned int *attr, char const *oid) CC_HINT(nonnull);

ssize_t			fr_dict_oid_component(fr_dict_attr_err_t *err,
					      fr_dict_attr_t const **out, fr_dict_attr_t const *parent,
					      fr_sbuff_t *in)
					      CC_HINT(nonnull(2,3,4));

ssize_t			fr_dict_attr_by_oid_substr(fr_dict_attr_err_t *err,
						   fr_dict_attr_t const **out, fr_dict_attr_t const *parent,
						   fr_sbuff_t *in) CC_HINT(nonnull(2,3,4));

fr_dict_attr_t const	*fr_dict_attr_by_oid(fr_dict_attr_err_t *err,
					     fr_dict_attr_t const *parent, char const *oid)
					     CC_HINT(nonnull(2,3));
/** @} */

/** @name Attribute, vendor and dictionary lookup
 *
 * @{
 */

/** @hidecallergraph */
fr_dict_attr_t const	*fr_dict_root(fr_dict_t const *dict);

bool			fr_dict_is_read_only(fr_dict_t const *dict);

ssize_t			fr_dict_by_protocol_substr(fr_dict_attr_err_t *err,
						   fr_dict_t const **out, fr_sbuff_t *name, fr_dict_t const *dict_def);

fr_dict_t const		*fr_dict_by_protocol_name(char const *name);

fr_dict_t const		*fr_dict_by_protocol_num(unsigned int num);

fr_dict_t const		*fr_dict_by_da(fr_dict_attr_t const *da);

fr_dict_t const		*fr_dict_by_attr_name(fr_dict_attr_t const **found, char const *name);

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
	if (!da->parent->flags.is_root) return false;
	return true;
}

fr_dict_vendor_t const	*fr_dict_vendor_by_da(fr_dict_attr_t const *da);

fr_dict_vendor_t const	*fr_dict_vendor_by_name(fr_dict_t const *dict, char const *name);

fr_dict_vendor_t const	*fr_dict_vendor_by_num(fr_dict_t const *dict, uint32_t vendor_pen);

fr_dict_attr_t const	*fr_dict_vendor_da_by_num(fr_dict_attr_t const *vendor_root, uint32_t vendor_pen);

ssize_t			fr_dict_attr_by_name_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
						    fr_dict_attr_t const *parent, fr_sbuff_t *name) CC_HINT(nonnull(2,3,4));

fr_dict_attr_t const	*fr_dict_attr_by_name(fr_dict_attr_err_t *err, fr_dict_attr_t const *parent, char const *attr)
			CC_HINT(nonnull(2,3));

ssize_t			fr_dict_attr_by_qualified_name_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
							      fr_dict_t const *dict_def,
							      fr_sbuff_t *name, bool fallback);

fr_dict_attr_err_t	fr_dict_attr_by_qualified_name(fr_dict_attr_t const **out,
						       fr_dict_t const *dict_def, char const *attr, bool fallback);

fr_dict_attr_t const 	*fr_dict_attr_by_type(fr_dict_attr_t const *da, fr_type_t type);

fr_dict_attr_t const	*fr_dict_attr_child_by_da(fr_dict_attr_t const *parent, fr_dict_attr_t const *child) CC_HINT(nonnull);

fr_dict_attr_t const	*fr_dict_attr_child_by_num(fr_dict_attr_t const *parent, unsigned int attr);

ssize_t			fr_dict_attr_child_by_name_substr(fr_dict_attr_err_t *err,
							  fr_dict_attr_t const **out, fr_dict_attr_t const *parent,
							  fr_sbuff_t *name, bool is_direct_decendent);

fr_dict_enum_t		*fr_dict_enum_by_value(fr_dict_attr_t const *da, fr_value_box_t const *value);

char const		*fr_dict_enum_name_by_value(fr_dict_attr_t const *da, fr_value_box_t const *value);

fr_dict_enum_t		*fr_dict_enum_by_name(fr_dict_attr_t const *da, char const *name, ssize_t len);
/** @} */

/** @name Dictionary and protocol loading
 *
 * @{
 */
int			fr_dict_internal_afrom_file(fr_dict_t **out, char const *internal_name);

int			fr_dict_protocol_afrom_file(fr_dict_t **out, char const *proto_name, char const *proto_dir);

int			fr_dict_read(fr_dict_t *dict, char const *dict_dir, char const *filename);
/** @} */

/** @name Autoloader interface
 *
 * @{
 */
int			fr_dict_attr_autoload(fr_dict_attr_autoload_t const *to_load);

int			fr_dict_autoload(fr_dict_autoload_t const *to_load);

void			fr_dict_autofree(fr_dict_autoload_t const *to_free);

int			fr_dl_dict_autoload(dl_t const *module, void *symbol, void *user_ctx);

void			fr_dl_dict_autofree(dl_t const *module, void *symbol, void *user_ctx);

int			fr_dl_dict_attr_autoload(dl_t const *module, void *symbol, void *user_ctx);
/** @} */

/** @name Allocating and freeing
 *
 * @{
 */
void			fr_dict_reference(fr_dict_t *dict);

int			fr_dict_free(fr_dict_t **dict);

int			fr_dict_const_free(fr_dict_t const **dict);
/** @} */

/** @name Global dictionary management
 *
 * @{
 */
fr_dict_gctx_t const	*fr_dict_global_ctx_init(TALLOC_CTX *ctx, char const *dict_dir);

void			fr_dict_global_ctx_set(fr_dict_gctx_t const *gctx);

int			fr_dict_global_ctx_free(fr_dict_gctx_t const *gctx);

int			fr_dict_global_ctx_dir_set(char const *dict_dir);

void			fr_dict_global_read_only(void);

char const		*fr_dict_global_dir(void);

fr_dict_t		*fr_dict_unconst(fr_dict_t const *dict);

fr_dict_attr_t		*fr_dict_attr_unconst(fr_dict_attr_t const *da);

fr_dict_t const		*fr_dict_internal(void);

/** @} */

/** @name Dictionary testing and validation
 *
 * @{
 */
int			fr_dict_parse_str(fr_dict_t *dict, char *buf,
					  fr_dict_attr_t const *parent);

ssize_t			fr_dict_valid_name(char const *name, ssize_t len);

ssize_t			fr_dict_valid_oid_str(char const *name, ssize_t len);

void			fr_dict_verify(char const *file, int line, fr_dict_attr_t const *da);

fr_dict_attr_t const	*fr_dict_attr_iterate_children(fr_dict_attr_t const *parent, fr_dict_attr_t const **prev);

typedef int		(*fr_dict_walk_t)(fr_dict_attr_t const *da, void *uctx);

int			fr_dict_walk(fr_dict_attr_t const *da, fr_dict_walk_t callback, void *uctx);

/** @} */

#undef _CONST

#ifdef __cplusplus
}
#endif
