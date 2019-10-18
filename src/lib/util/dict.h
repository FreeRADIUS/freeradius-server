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
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/types.h>

#include <stdbool.h>
#include <stdint.h>
#include <talloc.h>

/*
 *	Avoid circular type references.
 */
typedef struct dict_attr fr_dict_attr_t;
typedef struct fr_dict fr_dict_t;

#include <freeradius-devel/util/value.h>

#ifdef WITH_VERIFY_PTR
#  define DA_VERIFY(_x)		fr_dict_verify(__FILE__, __LINE__, _x)
#else
#  define DA_VERIFY(_x)		fr_cond_assert(_x)
#endif

/** Values of the encryption flags
 */
typedef struct {
	unsigned int		is_root : 1;			//!< Is root of a dictionary.
	unsigned int 		is_unknown : 1;			//!< Attribute number or vendor is unknown.
	unsigned int		is_raw : 1;			//!< raw attribute, unknown or malformed
	unsigned int		internal : 1;			//!< Internal attribute, should not be received
								///< in protocol packets, should not be encoded.
	unsigned int		has_tag : 1;			//!< Tagged attribute.
	unsigned int		array : 1; 			//!< Pack multiples into 1 attr.
	unsigned int		has_value : 1;			//!< Has a value.

	unsigned int		concat : 1;			//!< concatenate multiple instances

	unsigned int		virtual : 1;			//!< for dynamic expansion

	unsigned int		extra : 1;			//!< for LONG extended attributes

	uint8_t			subtype;			//!< for FR_TYPE_STRING encoding

	uint8_t			length;				//!< length of the attribute
	uint8_t			type_size;			//!< For TLV2 and root attributes.
} fr_dict_attr_flags_t;

enum {
	FLAG_ENCRYPT_NONE = 0,				//!< Don't encrypt the attribute.
	FLAG_ENCRYPT_USER_PASSWORD,			//!< Encrypt attribute RFC 2865 style.
	FLAG_ENCRYPT_TUNNEL_PASSWORD,			//!< Encrypt attribute RFC 2868 style.
	FLAG_ENCRYPT_ASCEND_SECRET,			//!< Encrypt attribute ascend style.
	FLAG_ENCRYPT_OTHER,				//!< Non-RADIUS encryption
};


extern const size_t dict_attr_sizes[FR_TYPE_MAX + 1][2];
extern fr_dict_t *fr_dict_internal;

/** Dictionary attribute
 */
struct dict_attr {
	unsigned int		attr;				//!< Attribute number.
	fr_type_t		type;				//!< Value type.

	fr_dict_attr_t const	*parent;			//!< Immediate parent of this attribute.

	union {
		struct {
			fr_dict_attr_t const	**children;	//!< Children of this attribute.
			fr_dict_attr_t const	*next;		//!< Next child in bin.
		};
		struct {
			fr_dict_t const		*dict;		//!< child dictionary
			fr_dict_attr_t const	*ref;		//!< reference
		};
	};


	unsigned int		depth;				//!< Depth of nesting for this attribute.

	fr_dict_attr_flags_t	flags;				//!< Flags.
	char const		*name;				//!< Attribute name.
};

/** Value of an enumerated attribute
 *
 * Maps one of more string values to integers and vice versa.
 */
typedef struct {
	fr_dict_attr_t const	*da;				//!< Dictionary attribute enum is associated with.
	char const		*alias;				//!< Enum name.
	size_t			alias_len;			//!< Allows for efficient alias lookups when operating
								///< on partial buffers.
	fr_value_box_t const	*value;				//!< Enum value (what name maps to).
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
	fr_dict_t		**dict;				//!< The protocol dictionary the attribute should
								///< be resolved in. ** so it's a compile time
								///< constant.
	char const		*name;				//!< of the attribute.
	fr_type_t		type;				//!< of the attribute.  Mismatch is a fatal error.
} fr_dict_attr_autoload_t;

/** Specifies a dictionary which must be loaded/loadable for the module to function
 *
 */
typedef struct {
	fr_dict_t		**out;				//!< Where to write a pointer to the loaded/resolved
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
	FR_DICT_ATTR_EINVAL		= -5			//!< Invalid arguments.
} fr_dict_attr_err_t;

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

/** Maximum dictionary attribute size
 */
#define FR_DICT_ATTR_SIZE		(sizeof(fr_dict_attr_t) + FR_DICT_ATTR_MAX_NAME_LEN)

/** Characters that are allowed in dictionary attribute names
 *
 */
extern bool const	fr_dict_attr_allowed_chars[UINT8_MAX];
extern bool const	fr_dict_non_data_types[FR_TYPE_MAX + 1];

/** @name Programatically create dictionary attributes and values
 *
 * @{
 */
int			fr_dict_attr_add(fr_dict_t *dict, fr_dict_attr_t const *parent, char const *name, int attr,
					 fr_type_t type, fr_dict_attr_flags_t const *flags) CC_HINT(nonnull(1,2,3));

int			fr_dict_enum_add_alias(fr_dict_attr_t const *da, char const *alias,
					       fr_value_box_t const *value, bool coerce, bool replace);

int			fr_dict_enum_add_alias_next(fr_dict_attr_t const *da, char const *alias) CC_HINT(nonnull);

int			fr_dict_str_to_argv(char *str, char **argv, int max_argc);
/** @} */

/** @name Unknown ephemeral attributes
 *
 * @{
 */
fr_dict_attr_t		*fr_dict_unknown_acopy(TALLOC_CTX *ctx, fr_dict_attr_t const *da);

fr_dict_attr_t const	*fr_dict_unknown_add(fr_dict_t *dict, fr_dict_attr_t const *old) CC_HINT(nonnull);

void			fr_dict_unknown_free(fr_dict_attr_t const **da);

int			fr_dict_unknown_vendor_afrom_num(TALLOC_CTX *ctx, fr_dict_attr_t **out,
							 fr_dict_attr_t const *parent, unsigned int vendor);

fr_dict_attr_t const   	*fr_dict_unknown_afrom_fields(TALLOC_CTX *ctx, fr_dict_attr_t const *parent,
						      unsigned int vendor, unsigned int attr) CC_HINT(nonnull(2));

ssize_t			fr_dict_unknown_afrom_oid_str(TALLOC_CTX *ctx, fr_dict_attr_t **out,
			      	      		      fr_dict_attr_t const *parent, char const *oid_str);

ssize_t			fr_dict_unknown_afrom_oid_substr(TALLOC_CTX *ctx, fr_dict_attr_t **out,
							 fr_dict_attr_t const *parent, char const *name);

fr_dict_attr_t const	*fr_dict_attr_known(fr_dict_t *dict, fr_dict_attr_t const *da);
/** @} */

/** @name Attribute lineage
 *
 * @{
 */
ssize_t			fr_dict_snprint_flags(char *out, size_t outlen, fr_type_t type, fr_dict_attr_flags_t const *flags);

void			fr_dict_print(fr_dict_attr_t const *da, int depth);

fr_dict_attr_t const	*fr_dict_parent_common(fr_dict_attr_t const *a, fr_dict_attr_t const *b, bool is_ancestor);

int			fr_dict_oid_component(unsigned int *out, char const **oid);

size_t			fr_dict_print_attr_oid(size_t *need, char *buffer, size_t outlen,
					       fr_dict_attr_t const *ancestor, fr_dict_attr_t const *da);

ssize_t			fr_dict_attr_by_oid(fr_dict_t *dict, fr_dict_attr_t const **parent,
					    unsigned int *attr, char const *oid) CC_HINT(nonnull);
/** @} */

/** @name Attribute, vendor and dictionary lookup
 *
 * @{
 */
fr_dict_attr_t const	*fr_dict_root(fr_dict_t const *dict);

ssize_t			fr_dict_by_protocol_substr(fr_dict_t const **out, char const *name, fr_dict_t const *dict_def);

fr_dict_t		*fr_dict_by_protocol_name(char const *name);

fr_dict_t		*fr_dict_by_protocol_num(unsigned int num);

fr_dict_t		*fr_dict_by_da(fr_dict_attr_t const *da);

fr_dict_t		*fr_dict_by_attr_name(fr_dict_attr_t const **found, char const *name);

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
	fr_dict_attr_t const *da_p = da;

	while (da_p->parent) {
		if (da_p->type == FR_TYPE_VENDOR) break;
		da_p = da_p->parent;
	}
	if (da_p->type != FR_TYPE_VENDOR) return 0;

	return da_p->attr;
}

fr_dict_vendor_t const	*fr_dict_vendor_by_da(fr_dict_attr_t const *da);

fr_dict_vendor_t const	*fr_dict_vendor_by_name(fr_dict_t const *dict, char const *name);

fr_dict_vendor_t const	*fr_dict_vendor_by_num(fr_dict_t const *dict, uint32_t vendor_pen);

fr_dict_attr_t const	*fr_dict_vendor_attr_by_da(fr_dict_attr_t const *da);

fr_dict_attr_t const	*fr_dict_vendor_attr_by_num(fr_dict_attr_t const *vendor_root, uint32_t vendor_pen);

ssize_t			fr_dict_attr_by_name_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
						    fr_dict_t const *dict, char const *name) CC_HINT(nonnull(2,4));

fr_dict_attr_t const	*fr_dict_attr_by_name(fr_dict_t const *dict, char const *attr);

ssize_t			fr_dict_attr_by_qualified_name_substr(fr_dict_attr_err_t *err, fr_dict_attr_t const **out,
							      fr_dict_t const *dict_def,
							      char const *attr, bool fallback);

fr_dict_attr_err_t	fr_dict_attr_by_qualified_name(fr_dict_attr_t const **out,
						       fr_dict_t const *dict_def, char const *attr, bool fallback);

fr_dict_attr_t const 	*fr_dict_attr_by_type(fr_dict_attr_t const *da, fr_type_t type);

fr_dict_attr_t const	*fr_dict_attr_child_by_da(fr_dict_attr_t const *parent, fr_dict_attr_t const *child) CC_HINT(nonnull);

fr_dict_attr_t const	*fr_dict_attr_child_by_num(fr_dict_attr_t const *parent, unsigned int attr);

fr_dict_enum_t		*fr_dict_enum_by_value(fr_dict_attr_t const *da, fr_value_box_t const *value);

char const		*fr_dict_enum_alias_by_value(fr_dict_attr_t const *da, fr_value_box_t const *value);

fr_dict_enum_t		*fr_dict_enum_by_alias(fr_dict_attr_t const *da, char const *alias, ssize_t len);
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

void			fr_dict_free(fr_dict_t **dict);

/** @name Initialisation
 *
 * @{
 */
 int			fr_dict_global_init(TALLOC_CTX *ctx, char const *dict_dir);
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
/** @} */

#ifdef __cplusplus
}
#endif
