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
 * @file src/lib/util/dict_ext.h
 *
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2020,2024 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(dict_ext_h, "$Id$")

#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/ext.h>
#include <freeradius-devel/util/hash.h>

#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

extern fr_ext_t const fr_dict_attr_ext_def;
extern fr_ext_t const fr_dict_enum_ext_def;

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

DIAG_OFF(attributes)
typedef enum CC_HINT(flag_enum) {
	FR_DICT_ATTR_REF_NONE		= 0x00,			//!< No ref set.
	FR_DICT_ATTR_REF_ALIAS		= 0x01,			//!< The attribute is an alias for another attribute.
								///< Either a straight ALIAS, or a reference into another
								///< dictionary.
	FR_DICT_ATTR_REF_CLONE		= 0x02,			//!< The attribute is a "copy" of another attribute.
	FR_DICT_ATTR_REF_ENUM		= 0x04,			//!< The attribute is an enumeration value.
	FR_DICT_ATTR_REF_KEY		= 0x08,			//!< it is a UNION which has a ref to a key, and children.
	FR_DICT_ATTR_REF_UNRESOLVED	= 0x10			//!< This flag is combined with the other states to indicate
								///< that the reference is unresolved.
} fr_dict_attr_ref_type_t;
DIAG_ON(attributes)

#define fr_dict_attr_ref_is_unresolved(_type)	((_type) & FR_DICT_ATTR_REF_UNRESOLVED)
#define fr_dict_attr_ref_type(_type)		((_type) & ~FR_DICT_ATTR_REF_UNRESOLVED)

/** Attribute extension - Holds a reference to an attribute in another dictionary
 *
 */
typedef struct {
	fr_dict_attr_ref_type_t type;				//!< The state of the reference.
	union {
		fr_dict_attr_t const	*ref;			//!< A resolved pointer to the referenced attribute.
		char			*unresolved;		//!< An unresolved reference (will need resolving later).
	};
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
	bool			unused;				//!< Zero length arrays are apparently GNU extensions
								///< and we're not allowed to have structs with a
								///< single variable array as its member.
								///< We'll likely want to store something else here
								///< at some point, so we just have a dummy field to
								///< avoid changing all the code.
	fr_dict_attr_t const	*da_stack[];			//!< Stack of dictionary attributes
} fr_dict_attr_ext_da_stack_t;

/** Attribute extension - Holds enumeration values
 *
 */
typedef struct {
	size_t			max_name_len;			//!< maximum length of a name
	fr_hash_table_t		*value_by_name;			//!< Lookup an enumeration value by name
	fr_hash_table_t		*name_by_value;			//!< Lookup a name by value
} fr_dict_attr_ext_enumv_t;

/** Attribute extension - Holds a hash table with the names of all children of this attribute
 *
 */
typedef struct {
	fr_hash_table_t		*namespace;			//!< Lookup a child by name
} fr_dict_attr_ext_namespace_t;

/** @name Add extension structures to attributes
 *
 * @{
 */

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

	return fr_ext_ptr(da, da->ext[ext], fr_dict_attr_ext_def.info[ext].has_hdr);
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

	/*
	 *	Unresolve refs aren't valid refs...
	 */
	if (fr_dict_attr_ref_is_unresolved(ext->type)) return NULL;

	/*
	 *	Temporary backwards compatibility...
	 */
	if (ext->type != FR_DICT_ATTR_REF_ALIAS) return NULL;

	return ext->ref;
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

/* Retrieve an extension structure for a dictionary enum
 *
 * @param[in] enumv	to retrieve structure from.
 * @param[in] ext	to retrieve.
 * @return
 *	- NULL if the extension wasn't found.
 *	- A pointer to the start of the extension.
 */
static inline void *fr_dict_enum_ext(fr_dict_enum_value_t const *enumv, fr_dict_enum_ext_t ext)
{
	if (!enumv->ext[ext]) return NULL;

	return fr_ext_ptr(enumv, enumv->ext[ext], fr_dict_enum_ext_def.info[ext].has_hdr);
}

/** Return the attribute reference associated with an enum
 *
 * @param[in] enumv	to return the reference for.
 * @return
 *	- NULL if no reference available.
 *	- A pointer to the attribute being referenced.
 */
static inline fr_dict_attr_t const *fr_dict_enum_attr_ref(fr_dict_enum_value_t const *enumv)
{
	fr_dict_enum_ext_attr_ref_t const *ref;

	ref = fr_dict_enum_ext(enumv, FR_DICT_ENUM_EXT_ATTR_REF);
	if (!ref) return NULL;

	return ref->da;
}


/** @} */

void fr_dict_attr_ext_debug(fr_dict_attr_t const *da);

#ifdef __cplusplus
}
#endif
