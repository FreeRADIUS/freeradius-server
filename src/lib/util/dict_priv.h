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
#include <freeradius-devel/util/value.h>

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
				fr_strerror_const("No dictionaries available for attribute resolution"); \
				return (_ret); \
			} \
		} \
	} while (0)

/** Entry recording dictionary reference holders by file
 */
typedef struct {
	fr_rb_node_t		node;
	int			count;			//!< How many references are held by this file.
							///< Signed to help figure out when things go wrong...
	char const	        *dependent;		//!< File holding the reference.
} fr_dict_dependent_t;

/** Entry in the filename list of files associated with this dictionary
 *
 * Mainly used for debugging.
 */
typedef struct {
	fr_dlist_t		entry;			//!< Entry in the list of filenames.

	char const		*src_file;		//!< the source file which did the $INCLUDE
	int			src_line;		//!< the line number in the source file
	char			*filename;		//!< Name of the file the dictionary was loaded on.
} fr_dict_filename_t;

/** Vendors and attribute names
 *
 * It's very likely that the same vendors will operate in multiple
 * protocol spaces, but number their attributes differently, so we need
 * per protocol dictionaries.
 *
 * There would also be conflicts for DHCP(v6)/RADIUS attributes etc...
 */
struct fr_dict_s {
	fr_dict_gctx_t	        *gctx;			//!< Global dictionary context this dictionary
							///< was allocated in.

	char const		*dir;			//!< where this protocol is located

	fr_dlist_head_t 	filenames;		//!< Files that this dictionary was loaded from.

	bool			read_only;		//!< If true, disallow modifications.

	bool			in_protocol_by_name;	//!< Whether the dictionary has been inserted into the
							///< protocol_by_name hash.
	bool			in_protocol_by_num;	//!< Whether the dictionary has been inserted into the
							//!< protocol_by_num table.

	bool			string_based;		//!< TACACS, etc.

	bool			loading;		//!< from fr_dict_protocol_afrom_file();

	bool			loaded;			//!< from fr_dict_protocol_afrom_file();

	fr_hash_table_t		*vendors_by_name;	//!< Lookup vendor by name.
	fr_hash_table_t		*vendors_by_num;	//!< Lookup vendor by PEN.

	fr_dict_attr_t		*root;			//!< Root attribute of this dictionary.

	TALLOC_CTX		*pool;			//!< Talloc memory pool to reduce allocs.
							///< in the dictionary.

	fr_hash_table_t		*autoref;		//!< other dictionaries that we loaded via references

	fr_dict_t const		*next;			//!< for attribute overloading

	unsigned int		vsa_parent;		//!< varies with different protocols.

	fr_dict_attr_t		**fixups;		//!< Attributes that need fixing up.

	fr_rb_tree_t		*dependents;		//!< Which files are using this dictionary.

	dl_t			*dl;			//!< for validation

	fr_dict_protocol_t const *proto;		//!< protocol-specific validation functions
};

struct fr_dict_gctx_s {
	bool			free_at_exit;		//!< This gctx will be freed on exit.

	bool			perm_check;		//!< Whether we should check dictionary
							///< file permissions as they're loaded.

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

	fr_dict_attr_t const	*attr_protocol_encapsulation;
};

typedef enum {
	FR_DICT_PROTO_RADIUS = 1,
	FR_DICT_PROTO_DHCPv4 = 2,
	FR_DICT_PROTO_DHCPv6 = 3,
	FR_DICT_PROTO_ETHERNET = 4,
	FR_DICT_PROTO_TACACS = 5,
	FR_DICT_PROTO_VMPS = 6,
	FR_DICT_PROTO_SNMP = 7,
	FR_DICT_PROTO_ARP = 8,
	FR_DICT_PROTO_TFTP = 9,
	FR_DICT_PROTO_TLS = 10,
	FR_DICT_PROTO_DNS = 11,
	FR_DICT_PROTO_LDAP = 12,
	FR_DICT_PROTO_BFD = 13,
} fr_dict_protocol_id_t;

extern fr_dict_gctx_t *dict_gctx;

bool			dict_has_dependents(fr_dict_t *dict);

int			dict_dependent_add(fr_dict_t *dict, char const *dependent);

int			dict_dependent_remove(fr_dict_t *dict, char const *dependent);

fr_dict_t		*dict_alloc(TALLOC_CTX *ctx);

int			dict_dlopen(fr_dict_t *dict, char const *name);

/** Optional arguments for initialising/allocating attributes
 *
 */
typedef struct {
	fr_dict_attr_flags_t const	*flags;		//!< Any flags to assign to the attribute.

	fr_dict_attr_t const		*ref;		//!< This attribute is a reference to another attribute.
} dict_attr_args_t;

/** Partial initialisation functions
 *
 * These functions are used to initialise attributes in stages, i.e. when parsing a dictionary.
 *
 * The finalise function must be called to complete the initialisation.
 *
 * All functions must be called to fully initialise a dictionary attribute, except
 * #dict_attr_parent_init this is not necessary for root attributes.
 *
 * @{
 */
fr_dict_attr_t 		*dict_attr_alloc_null(TALLOC_CTX *ctx, fr_dict_protocol_t const *dict);

int			dict_attr_type_init(fr_dict_attr_t **da_p, fr_type_t type);

int			dict_attr_parent_init(fr_dict_attr_t **da_p, fr_dict_attr_t const *parent);

int			dict_attr_num_init(fr_dict_attr_t *da, unsigned int num);

int			dict_attr_num_init_name_only(fr_dict_attr_t *da);

void			dict_attr_location_init(fr_dict_attr_t *da, char const *filename, int line);

int			dict_attr_finalise(fr_dict_attr_t **da_p, char const *name);
/** @} */

/** Full initialisation functions
 *
 * These functions either initialise, or allocate and then initialise a
 * complete dictionary attribute.
 *
 * The output of these functions can be added into a dictionary immediately
 * @{
 */
#define 		dict_attr_init(_da_p, _parent, _name, _attr, _type, _args) \
				       _dict_attr_init(__FILE__, __LINE__, _da_p, _parent, _name, _attr, _type, _args)

int			_dict_attr_init(char const *filename, int line,
					fr_dict_attr_t **da_p, fr_dict_attr_t const *parent,
				        char const *name, unsigned int attr,
				        fr_type_t type, dict_attr_args_t const *args) CC_HINT(nonnull(1));

#define 		dict_attr_init_name_only(_da_p, _parent, _name, _type, _args) \
					    _dict_attr_init_name_only(__FILE__, __LINE__, _da_p, _parent, _name,  _type, _args)

int			_dict_attr_init_name_only(char const *filename, int line,
					     fr_dict_attr_t **da_p, fr_dict_attr_t const *parent,
					     char const *name,
					     fr_type_t type, dict_attr_args_t const *args) CC_HINT(nonnull(1));

#define			dict_attr_alloc_root(_ctx, _dict, _name, _attr, _args) \
					     _dict_attr_alloc_root(__FILE__, __LINE__, _ctx, _dict, _name, _attr, _args)
fr_dict_attr_t		*_dict_attr_alloc_root(char const *filename, int line,
					       TALLOC_CTX *ctx,
					       fr_dict_t const *dict,
					       char const *name, int attr,
					       dict_attr_args_t const *args) CC_HINT(nonnull(4,5));

#define			dict_attr_alloc(_ctx, _parent, _name, _attr, _type, _args) \
				_dict_attr_alloc(__FILE__, __LINE__, _ctx, _parent, _name, _attr, _type, (_args))
fr_dict_attr_t		*_dict_attr_alloc(char const *filename, int line,
					  TALLOC_CTX *ctx,
					  fr_dict_attr_t const *parent,
					  char const *name, int attr,
					  fr_type_t type, dict_attr_args_t const *args) CC_HINT(nonnull(4));
/** @} */

fr_dict_attr_t		*dict_attr_acopy(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, fr_dict_attr_t const *in, char const *new_name);

int			dict_attr_acopy_children(fr_dict_t *dict, fr_dict_attr_t *dst, fr_dict_attr_t const *src);

int			dict_attr_acopy_enumv(fr_dict_attr_t *dst, fr_dict_attr_t const *src);

int			dict_attr_acopy_aliases(fr_dict_attr_t *dst, fr_dict_attr_t const *src);

int 			dict_attr_alias_add(fr_dict_attr_t const *parent, char const *alias, fr_dict_attr_t const *ref, bool from_public);

int			dict_attr_child_add(fr_dict_attr_t *parent, fr_dict_attr_t *child);

int			dict_protocol_add(fr_dict_t *dict);

int			dict_vendor_add(fr_dict_t *dict, char const *name, unsigned int num);

int			dict_attr_add_to_namespace(fr_dict_attr_t const *parent, fr_dict_attr_t *da) CC_HINT(nonnull);

bool			dict_attr_flags_valid(fr_dict_attr_t *da) CC_HINT(nonnull(1));

bool			dict_attr_valid(fr_dict_attr_t *da);

fr_dict_attr_t		*dict_attr_by_name(fr_dict_attr_err_t *err, fr_dict_attr_t const *parent, char const *name);

fr_dict_attr_t		*dict_attr_child_by_num(fr_dict_attr_t const *parent, unsigned int attr);

fr_slen_t		dict_by_protocol_substr(fr_dict_attr_err_t *err,
						fr_dict_t **out, fr_sbuff_t *name, fr_dict_t const *dict_def);

fr_dict_t		*dict_by_protocol_name(char const *name);

fr_dict_t		*dict_by_protocol_num(unsigned int num);

fr_dict_t		*dict_by_da(fr_dict_attr_t const *da);

bool			dict_attr_can_have_children(fr_dict_attr_t const *da);

int			dict_attr_enum_add_name(fr_dict_attr_t *da, char const *name, fr_value_box_t const *value,
					   bool coerce, bool replace, fr_dict_attr_t const *child_struct);

#ifdef __cplusplus
}
#endif
