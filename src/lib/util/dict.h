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

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/dl.h>
#include <freeradius-devel/util/rbtree.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/types.h>

#include <stdbool.h>
#include <stdint.h>
#include <talloc.h>
#include <limits.h>

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
#define da_has_ref(_da) (((_da)->type == FR_TYPE_GROUP) || ((_da)->flags.extra && ((_da)->flags.subtype == FLAG_HAS_REF)))

extern const size_t dict_attr_sizes[FR_TYPE_MAX + 1][2];

/** Extension identifier
 *
 * @note New extension structures should also be added to the #fr_dict_ext_length_min table in dict_ext.c
 */
typedef enum {
	FR_DICT_ATTR_EXT_NAME = 0,				//!< Name of the attribute.
	FR_DICT_ATTR_EXT_CHILDREN,				//!< Attribute has children.
	FR_DICT_ATTR_EXT_REF,					//!< Attribute references another
								///< attribute and/or dictionary
	FR_DICT_ATTR_EXT_VENDOR,				//!< Cached vendor pointer.
	FR_DICT_ATTR_EXT_DA_STACK,				//!< Cached da stack.
	FR_DICT_ATTR_EXT_ENUMV,					//!< Enumeration values.
	FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC,			//!< Protocol specific extensions
	FR_DICT_ATTR_EXT_MAX
} fr_dict_attr_ext_t;

/** The alignment of object extension structures
 *
 */
#ifdef __WORD_SIZE
#  if __WORD_SIZE < 4
#    define FR_DICT_ATTR_EXT_ALIGNMENT	sizeof(uint32_t)
#  else
#    define FR_DICT_ATTR_EXT_ALIGNMENT	__WORD_SIZE		/* From limits.h */
#  endif
#else
#  define FR_DICT_ATTR_EXT_ALIGNMENT	sizeof(uint64_t)
#endif

/** Attribute extension - Holds children for an attribute
 *
 * Children are possible for:
 *
 * #FR_TYPE_TLV, #FR_TYPE_VENDOR, #FR_TYPE_VSA, #FR_TYPE_STRUCT
 *
 * *or* where the parent->parent->type is
 * #FR_TYPE_STRUCT, and "parent" is a "key"
 * field.  Note that these attributes therefore
 * cannot have VALUEs, as the child defines their
 * VALUE.  See dict_attr_can_have_children() for details.
 */
typedef struct {
	fr_hash_table_t		*child_by_name;			//!< Namespace at this level in the hierarchy.
	fr_dict_attr_t const	**children;			//!< Children of this attribute.
} fr_dict_attr_ext_children_t;

/** Attribute extension - Holds a reference to an attribute in another dictionary
 *
 */
typedef struct {
	fr_dict_attr_t const	*ref;				//!< reference, only for #FR_TYPE_GROUP
} fr_dict_attr_ext_ref_t;

/** Attribute extension - Cached vendor pointer
 *
 */
typedef struct {
	fr_dict_attr_t const	*vendor;			//!< ancestor which has type #FR_TYPE_VENDOR
} fr_dict_attr_ext_vendor_t;

/** Attribute extension - Stack of dictionary attributes that describe the path back to the root of the dictionary
 *
 */
typedef struct {
	fr_dict_attr_t const	*da_stack[0];			//!< Stack of dictionary attributes
} fr_dict_attr_ext_da_stack_t;

/** Attribute extension - Holds enumeration values
 *
 */
typedef struct {
	fr_hash_table_t		*value_by_name;			//!< Lookup an enumeration value by name
	fr_hash_table_t		*name_by_value;			//!< Lookup a name by value
} fr_dict_attr_ext_enumv_t;

/** Attribute extension - Protocol-specific
 *
 */
typedef struct {
	void			*uctx;				//!< Protocol specific extensions
} fr_dict_attr_ext_protocol_specific_t;

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
} CC_HINT(aligned(FR_DICT_ATTR_EXT_ALIGNMENT));

/** Value of an enumerated attribute
 *
 * Maps one of more string values to integers and vice versa.
 */
typedef struct {
	char const		*name;				//!< Enum name.
	size_t			name_len;			//!< Allows for efficient name lookups when operating
								///< on partial buffers.
	fr_value_box_t const	*value;				//!< Enum value (what name maps to).

	fr_dict_attr_t const	*child_struct[0];		//!< for key fields
} fr_dict_enum_t;

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

/** @name Add extension structures to attributes
 *
 * @{
 */

/** Return a pointer to the specified extension structure
 */
#define DICT_EXT_OFFSET(_ptr, _ext) ((void *)(((_ptr)->ext[_ext] * FR_DICT_ATTR_EXT_ALIGNMENT) + ((uintptr_t)(_ptr))))

/* Retrieve an extension structure for a dictionary attribute
 *
 * @param[in] da	to retrieve structure from.
 * @param[in] ext	to retrieve.
 * @return
 *	- NULL if the extension wasn't found.
 *	- A pointer to the start of the extension.
 */
static inline void *fr_dict_attr_ext(fr_dict_attr_t const *da, fr_dict_attr_ext_t ext)
{
	if (!da->ext[ext]) return NULL;

	return DICT_EXT_OFFSET(da, ext);
}

/** Return whether a da has a given extension or not
 *
 * @param[in] da	to check for extensions.
 * @param[in] ext	to check.
 * @return
 *      - true if the da has the specified extension.
 *	- false if the da does not have the specified extension
 */
static inline bool fr_dict_attr_has_ext(fr_dict_attr_t const *da, fr_dict_attr_ext_t ext)
{
	return (da->ext[ext] > 0);
}

/** Return the cached da stack (if any) associated with an attribute
 *
 * @param[in] da	to return cached da stack for.
 * @return
 *	- NULL if no da stack available.
 *	- The cached da stack on success.
 */
static inline fr_dict_attr_t const **fr_dict_attr_da_stack(fr_dict_attr_t const *da)
{
	fr_dict_attr_ext_da_stack_t *ext;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_DA_STACK);
	if (!ext) return NULL;

	return ext->da_stack;
}

/** Return the reference associated with a group type attribute
 *
 * @param[in] da	to return the reference for.
 * @return
 *	- NULL if no reference available.
 *	- A pointer to the attribute being referenced.
 */
static inline fr_dict_attr_t const *fr_dict_attr_ref(fr_dict_attr_t const *da)
{
	fr_dict_attr_ext_ref_t *ext;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_REF);
	if (!ext) return NULL;

	return ext->ref;
}
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
fr_dict_attr_t		*fr_dict_unknown_acopy(TALLOC_CTX *ctx, fr_dict_attr_t const *da, char const *name);

fr_dict_attr_t const	*fr_dict_unknown_add(fr_dict_t *dict, fr_dict_attr_t const *old) CC_HINT(nonnull);

void			fr_dict_unknown_free(fr_dict_attr_t const **da);

int			fr_dict_unknown_vendor_afrom_num(TALLOC_CTX *ctx, fr_dict_attr_t **out,
							 fr_dict_attr_t const *parent, unsigned int vendor);

fr_dict_attr_t const   	*fr_dict_unknown_afrom_fields(TALLOC_CTX *ctx, fr_dict_attr_t const *parent,
						      unsigned int vendor, unsigned int attr) CC_HINT(nonnull(2));

int			fr_dict_unknown_attr_afrom_num(TALLOC_CTX *ctx, fr_dict_attr_t **out,
						       fr_dict_attr_t const *parent, unsigned long num);

ssize_t			fr_dict_unknown_afrom_oid_str(TALLOC_CTX *ctx, fr_dict_attr_t **out,
			      	      		      fr_dict_attr_t const *parent, char const *oid_str);

ssize_t			fr_dict_unknown_afrom_oid_substr(TALLOC_CTX *ctx, fr_dict_attr_t **out,
							 fr_dict_attr_t const *parent, char const *name);

fr_dict_attr_t const	*fr_dict_attr_known(fr_dict_t const *dict, fr_dict_attr_t const *da);
/** @} */

/** @name Attribute comparisons
 *
 * @ {
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

/** @name Attribute lineage
 *
 * @{
 */
void			fr_dict_print(fr_dict_t const *dict, fr_dict_attr_t const *da);

fr_dict_attr_t const	*fr_dict_attr_common_parent(fr_dict_attr_t const *a, fr_dict_attr_t const *b, bool is_ancestor);

int			fr_dict_oid_component(unsigned int *out, char const **oid);

ssize_t			fr_dict_snprint_flags(fr_sbuff_t *out, fr_dict_t const *dict,
					      fr_type_t type, fr_dict_attr_flags_t const *flags);

ssize_t			fr_dict_print_attr_oid(fr_sbuff_t *out,
					       fr_dict_attr_t const *ancestor, fr_dict_attr_t const *da);

ssize_t			fr_dict_attr_by_oid(fr_dict_t const *dict, fr_dict_attr_t const **parent,
					    unsigned int *attr, char const *oid) CC_HINT(nonnull);
/** @} */

/** @name Attribute, vendor and dictionary lookup
 *
 * @{
 */
fr_dict_attr_t const	*fr_dict_root(fr_dict_t const *dict);

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

/** Return the vendor number for an attribute
 *
 * @param[in] da		The dictionary attribute to find the
 *				vendor for.
 * @return
 *	- 0 this isn't a vendor specific attribute.
 *	- The vendor PEN.
 */
static inline uint32_t fr_dict_vendor_num_by_da(fr_dict_attr_t const *da)
{
	fr_dict_attr_ext_vendor_t *ext;

	if (da->type == FR_TYPE_VENDOR) return da->attr;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_VENDOR);
	if (!ext || !ext->vendor) return 0;

	return ext->vendor->attr;
}

/** Return the vendor da for an attribute
 *
 * @param[in] da		The dictionary attribute to find the
 *				vendor for.
 * @return
 *	- 0 this isn't a vendor specific attribute.
 *	- The vendor PEN.
 */
static inline fr_dict_attr_t const *fr_dict_vendor_da_by_da(fr_dict_attr_t const *da)
{
	fr_dict_attr_ext_vendor_t *ext;

	if (da->type == FR_TYPE_VENDOR) return da;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_VENDOR);
	if (!ext) return NULL;

	return ext->vendor;
}

fr_dict_vendor_t const	*fr_dict_vendor_by_da(fr_dict_attr_t const *da);

fr_dict_vendor_t const	*fr_dict_vendor_by_name(fr_dict_t const *dict, char const *name);

fr_dict_vendor_t const	*fr_dict_vendor_by_num(fr_dict_t const *dict, uint32_t vendor_pen);

fr_dict_attr_t const	*fr_dict_vendor_da_by_num(fr_dict_attr_t const *vendor_root, uint32_t vendor_pen);

ssize_t			fr_dict_attr_by_name_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
						    fr_dict_t const *dict, fr_sbuff_t *name) CC_HINT(nonnull(2,4));

fr_dict_attr_t const	*fr_dict_attr_by_name(fr_dict_t const *dict, char const *attr);

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
void			fr_dict_dump(fr_dict_t const *dict);

int			fr_dict_parse_str(fr_dict_t *dict, char *buf,
					  fr_dict_attr_t const *parent);

ssize_t			fr_dict_valid_name(char const *name, ssize_t len);

ssize_t			fr_dict_valid_oid_str(char const *name, ssize_t len);

void			fr_dict_verify(char const *file, int line, fr_dict_attr_t const *da);

fr_dict_attr_t const	*fr_dict_attr_iterate_children(fr_dict_attr_t const *parent, fr_dict_attr_t const **prev);

typedef int		(*fr_dict_walk_t)(void *ctx, fr_dict_attr_t const *da, int depth);

int			fr_dict_walk(fr_dict_attr_t const *da, void *ctx, fr_dict_walk_t callback);

/** @} */

#undef _CONST

#ifdef __cplusplus
}
#endif
