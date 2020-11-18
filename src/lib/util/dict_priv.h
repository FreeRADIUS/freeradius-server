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

#define _DICT_PRIVATE 1

#include <freeradius-devel/protocol/base.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/dict_ext_priv.h>
#include <freeradius-devel/util/dl.h>
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
			_dict = dict_gctx ? dict_gctx->internal : NULL; \
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
	fr_dict_gctx_t	        *gctx;			//!< Global dictionary context this dictionary
							///< was allocated in.
	bool			read_only;		//!< If true, disallow modifications.

	bool			in_protocol_by_name;	//!< Whether the dictionary has been inserted into the
							///< protocol_by_name hash.
	bool			in_protocol_by_num;	//!< Whether the dictionary has been inserted into the
							//!< protocol_by_num table.

	bool			autoloaded;		//!< manual vs autoload

	fr_hash_table_t		*vendors_by_name;	//!< Lookup vendor by name.
	fr_hash_table_t		*vendors_by_num;	//!< Lookup vendor by PEN.

	fr_hash_table_t		*attributes_combo;	//!< Lookup variants of polymorphic attributes.

	fr_dict_attr_t		*root;			//!< Root attribute of this dictionary.

	TALLOC_CTX		*pool;			//!< Talloc memory pool to reduce allocs.
							///< in the dictionary.

	fr_hash_table_t		*autoref;		//!< other dictionaries that we loaded via references

	fr_table_num_ordered_t const *subtype_table;	//!< table of subtypes for this protocol
	size_t			subtype_table_len;	//!< length of table of subtypes for this protocol

	unsigned int		vsa_parent;		//!< varies with different protocols
	int			default_type_size;	//!< for TLVs and VSAs
	int			default_type_length;	//!< for TLVs and VSAs

	dl_t			*dl;			//!< for validation

	fr_dict_protocol_t const *proto;		//!< protocol-specific validation functions

	fr_dict_attr_valid_func_t attr_valid;		//!< validation function for new attributes

	fr_dict_attr_t		**fixups;		//!< Attributes that need fixing up.
};

struct fr_dict_gctx_s {
	bool			read_only;
	char			*dict_dir_default;	//!< The default location for loading dictionaries if one
							///< wasn't provided.

	dl_loader_t		*dict_loader;		//!< for protocol validation

	fr_hash_table_t		*protocol_by_name;	//!< Hash containing names of all the
							///< registered protocols.
	fr_hash_table_t		*protocol_by_num;	//!< Hash containing numbers of all the
							///< registered protocols.

	/** Magic internal dictionary
	 *
	 * Internal dictionary is checked in addition to the protocol dictionary
	 * when resolving attribute names.
	 *
	 * This is because internal attributes are valid for every
	 * protocol.
	 */
	fr_dict_t		*internal;
};

extern fr_dict_gctx_t *dict_gctx;

extern fr_table_num_ordered_t const	date_precision_table[];
extern size_t				date_precision_table_len;

fr_dict_t		*dict_alloc(TALLOC_CTX *ctx);

int			dict_dlopen(fr_dict_t *dict, char const *name);

fr_dict_attr_t 		*dict_attr_alloc_null(TALLOC_CTX *ctx);

int			dict_attr_init(fr_dict_attr_t **da_p,
				       fr_dict_attr_t const *parent,
				       char const *name, int attr,
				       fr_type_t type, fr_dict_attr_flags_t const *flags);

fr_dict_attr_t		*dict_attr_alloc(TALLOC_CTX *ctx,
					 fr_dict_attr_t const *parent,
					 char const *name, int attr,
					 fr_type_t type, fr_dict_attr_flags_t const *flags);

fr_dict_attr_t		*dict_attr_acopy(TALLOC_CTX *ctx, fr_dict_attr_t const *in, char const *new_name);

int			dict_attr_child_add(fr_dict_attr_t *parent, fr_dict_attr_t *child);

int			dict_protocol_add(fr_dict_t *dict);

int			dict_vendor_add(fr_dict_t *dict, char const *name, unsigned int num);

int			dict_attr_add_to_namespace(fr_dict_t *dict,
						   fr_dict_attr_t const *parent, fr_dict_attr_t *da) CC_HINT(nonnull);

bool			dict_attr_flags_valid(fr_dict_t *dict, fr_dict_attr_t const *parent,
					      UNUSED char const *name, int *attr, fr_type_t type,
					      fr_dict_attr_flags_t *flags) CC_HINT(nonnull(1,2,6));

bool			dict_attr_fields_valid(fr_dict_t *dict, fr_dict_attr_t const *parent,
					       char const *name, int *attr, fr_type_t type,
					       fr_dict_attr_flags_t *flags);

fr_dict_attr_t		*dict_attr_by_name(fr_dict_attr_err_t *err, fr_dict_attr_t const *parent, char const *name);

fr_dict_attr_t		*dict_attr_child_by_num(fr_dict_attr_t const *parent, unsigned int attr);

ssize_t			dict_by_protocol_substr(fr_dict_attr_err_t *err,
						fr_dict_t **out, fr_sbuff_t *name, fr_dict_t const *dict_def);

fr_dict_t		*dict_by_protocol_name(char const *name);

fr_dict_t		*dict_by_protocol_num(unsigned int num);

fr_dict_t		*dict_by_da(fr_dict_attr_t const *da);

fr_dict_t		*dict_by_attr_name(fr_dict_attr_t const **found, char const *name);

bool			dict_attr_can_have_children(fr_dict_attr_t const *da);

int			dict_attr_enum_add_name(fr_dict_attr_t *da, char const *name, fr_value_box_t const *value,
					   bool coerce, bool replace, fr_dict_attr_t const *child_struct);

#ifdef __cplusplus
}
#endif
