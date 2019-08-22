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

/** Private Multi-protocol AVP dictionary API
 *
 * @file src/lib/util/dict_priv.h
 *
 * @copyright 2019 The FreeRADIUS server project
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/hash.h>

#define DICT_POOL_SIZE		(1024 * 1024 * 2)
#define DICT_FIXUP_POOL_SIZE	(1024)

/** Set the internal dictionary if none was provided
 *
 * @param _dict		Dict pointer to check/set.
 * @param _ret		Value to return if no dictionaries are available.
 */
#define INTERNAL_IF_NULL(_dict, _ret) \
	do { \
		if (!(_dict)) { \
			_dict = fr_dict_internal; \
			if (unlikely(!(_dict))) { \
				fr_strerror_printf("No dictionaries available for attribute resolution"); \
				return (_ret); \
			} \
		} \
	} while (0)

/** Vendors and attribute names
 *
 * It's very likely that the same vendors will operate in multiple
 * protocol spaces, but number their attributes differently, so we need
 * per protocol dictionaries.
 *
 * There would also be conflicts for DHCP(v6)/RADIUS attributes etc...
 */
struct fr_dict {
	bool			in_protocol_by_name;	//!< Whether the dictionary has been inserted into the
							///< protocol_by_name hash.
	bool			in_protocol_by_num;	//!< Whether the dictionary has been inserted into the
							//!< protocol_by_num table.

	bool			autoloaded;		//!< manual vs autoload

	fr_hash_table_t		*vendors_by_name;	//!< Lookup vendor by name.
	fr_hash_table_t		*vendors_by_num;	//!< Lookup vendor by PEN.

	fr_hash_table_t		*attributes_by_name;	//!< Allow attribute lookup by unique name.

	fr_hash_table_t		*attributes_combo;	//!< Lookup variants of polymorphic attributes.

	fr_hash_table_t		*values_by_da;		//!< Lookup an attribute enum by its value.
	fr_hash_table_t		*values_by_alias;	//!< Lookup an attribute enum by its alias name.

	fr_dict_attr_t		*root;			//!< Root attribute of this dictionary.

	TALLOC_CTX		*pool;			//!< Talloc memory pool to reduce allocs.
							///< in the dictionary.

	fr_hash_table_t		*autoref;		//!< other dictionaries that we loaded via references
};

extern bool dict_initialised;
extern char *dict_dir_default;
extern TALLOC_CTX *dict_ctx;

extern fr_table_ordered_t const date_precision_table[];
extern size_t date_precision_table_len;

fr_dict_t		*dict_alloc(TALLOC_CTX *ctx);

/** Initialise fields in a dictionary attribute structure
 *
 * @param[in] da		to initialise.
 * @param[in] parent		of the attribute, if none, should be
 *				the dictionary root.
 * @param[in] attr		number.
 * @param[in] type		of the attribute.
 * @param[in] flags		to assign.
 */
static inline void dict_attr_init(fr_dict_attr_t *da,
				  fr_dict_attr_t const *parent, int attr,
				  fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	da->attr = attr;
	da->type = type;
	da->flags = *flags;
	da->parent = parent;
	da->depth = parent ? parent->depth + 1 : 0;
}

fr_dict_attr_t 		*dict_attr_alloc_name(TALLOC_CTX *ctx, char const *name);

fr_dict_attr_t		*dict_attr_alloc(TALLOC_CTX *ctx,
					 fr_dict_attr_t const *parent,
					 char const *name, int attr,
					 fr_type_t type, fr_dict_attr_flags_t const *flags);

int			dict_attr_child_add(fr_dict_attr_t *parent, fr_dict_attr_t *child);

int			dict_protocol_add(fr_dict_t *dict);

int			dict_vendor_add(fr_dict_t *dict, char const *name, unsigned int num);

int			dict_attr_add_by_name(fr_dict_t *dict, fr_dict_attr_t *da);

bool			dict_attr_flags_valid(fr_dict_t *dict, fr_dict_attr_t const *parent,
					      UNUSED char const *name, int *attr, fr_type_t type,
					      fr_dict_attr_flags_t *flags) CC_HINT(nonnull(1,2,6));

bool			dict_attr_fields_valid(fr_dict_t *dict, fr_dict_attr_t const *parent,
					       char const *name, int *attr, fr_type_t type,
					       fr_dict_attr_flags_t *flags);


#ifdef __cplusplus
}
#endif
