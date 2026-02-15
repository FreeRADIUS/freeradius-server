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

/**
 * $Id$
 *
 * @file cf_priv.h
 * @brief Private data structures and types for cf_*.c
 *
 * @copyright 2017 The FreeRADIUS server project
 */
RCSIDH(cf_priv_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/stat.h>

#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/dlist.h>

typedef enum conf_type {
	CONF_ITEM_INVALID = 0,
	CONF_ITEM_PAIR,
	CONF_ITEM_SECTION,
	CONF_ITEM_DATA,
} CONF_ITEM_TYPE;

/** Common header for all CONF_* types
 *
 */
struct cf_item {
	fr_rb_node_t		ident1_node;	//!< Entry in the ident1 tree.
	fr_rb_node_t		ident2_node;	//!< Entry in the ident2 tree.

	fr_dlist_t		entry;		//!< Entry in dlist
	fr_dlist_head_t		children;	//!< The head of the ordered list of children.

	CONF_ITEM		*parent;	//!< Parent

	fr_rb_tree_t		*ident1;	//!< Tree to store the first identifier (name1 || type || attr).
	fr_rb_tree_t		*ident2;	//!< Tree to store the second identifier (name2 || name).

	CONF_ITEM_TYPE		type;		//!< Whether the config item is a config_pair, conf_section or cf_data.

	bool			parsed;		//!< Was this item used during parsing?
	bool			referenced;	//!< Was this item referenced in the config?
	int			lineno;		//!< The line number the config item began on.
	char const		*filename;	//!< The file the config item was parsed from.
};

/** Configuration AVP similar to a fr_pair_t
 *
 */
struct cf_pair {
	CONF_ITEM		item;		//!< Common set of fields.

	char const		*attr;		//!< Attribute name
	char const		*value;		//!< Attribute value

	fr_token_t		op;		//!< Operator e.g. =, :=
	fr_token_t		lhs_quote;	//!< Name quoting style T_(DOUBLE|SINGLE|BACK)_QUOTE_STRING or T_BARE_WORD.
	fr_token_t		rhs_quote;	//!< Value Quoting style T_(DOUBLE|SINGLE|BACK)_QUOTE_STRING or T_BARE_WORD.

	bool			pass2;		//!< do expansion in pass2.
	bool			printed;	//!< Was this item printed already in debug mode?
};

typedef enum {
	CF_UNLANG_NONE = 0,			//!< no unlang
	CF_UNLANG_ALLOW,			//!< allow unlang in this section
	CF_UNLANG_SERVER,			//!< this section is a virtual server, allow unlang 2 down
	CF_UNLANG_POLICY,			//!< this section is a policy, allow unlang 2 down
	CF_UNLANG_MODULES,			//!< this section is in "modules", allow unlang 2 down
	CF_UNLANG_EDIT,				//!< only edit commands
	CF_UNLANG_ASSIGNMENT,  			//!< only assignments inside of map / update
	CF_UNLANG_DICTIONARY,  			//!< only local variable definitions
	CF_UNLANG_CAN_HAVE_UPDATE,		//!< can have "update"
} cf_unlang_t;

/** A section grouping multiple #CONF_PAIR
 *
 */
struct cf_section {
	CONF_ITEM		item;		//!< Common set of fields.

	char const		*name1;		//!< First name token.  Given ``foo bar {}`` would be ``foo``.
	char const		*name2;		//!< Second name token. Given ``foo bar {}`` would be ``bar``.

	fr_token_t		name2_quote;	//!< The type of quoting around name2.

	int			argc;		//!< number of additional arguments
	char const		**argv;		//!< additional arguments
	fr_token_t		*argv_quote;

	void			*base;
	int			depth;
	cf_unlang_t    		unlang;
	bool			allow_locals;	//!< allow local variables
	bool			at_reference;	//!< this thing was created from an @...

	CONF_SECTION		*template;
};

/** Internal data that is associated with a configuration section
 *
 */
struct cf_data {
	CONF_ITEM  		item;		//!< Common set of fields.

	char const		*type;		//!< C type of data being stored.
	char const 		*name;		//!< Additional qualification of type.

	void const   		*data;		//!< User data.
	bool			is_talloced;	//!< If true we can do extra checks.
	bool			free;		//!< If true, free data with talloc if parent node is freed.
};

typedef struct {
	fr_rb_node_t		node;
	char const		*filename;	//!< name of the file
	CONF_SECTION		*cs;		//!< CONF_SECTION associated with the file
	struct stat		buf;		//!< stat about the file
	bool			from_dir;	//!< was read from a directory
} cf_file_t;

/** Iterate over the contents of a list
 *
 * @param[in] _ci		to iterate over.
 * @param[in] _iter		Name of iteration variable.
 *				Will be declared in the scope of the loop.
 */
#define cf_item_foreach(_ci, _iter) \
	for (CONF_ITEM *JOIN(_next,_iter), *_iter = fr_dlist_head(&(_ci)->children); JOIN(_next,_iter) = fr_dlist_next(&(_ci)->children, _iter), _iter != NULL; _iter = JOIN(_next,_iter))

/** Iterate over the contents of a list
 *
 * @param[in] _ci		to iterate over.
 * @param[in] _iter		Name of iteration variable.
 *				Will be declared in the scope of the loop.
 * @param[in] _prev		previous pointer
 */
#define cf_item_foreach_next(_ci, _iter, _prev) \
	for (CONF_ITEM *_iter = fr_dlist_next(&(_ci)->children, _prev); _iter; _iter = fr_dlist_next(&(_ci)->children, _iter))

/** Iterate over the contents of a list in reverse order
 *
 * @param[in] _ci		to iterate over.
 * @param[in] _iter		Name of iteration variable.
 *				Will be declared in the scope of the loop.
 * @param[in] _prev		previous pointer
 */
#define cf_item_foreach_prev(_ci, _iter, _prev) \
	for (CONF_ITEM *_iter = fr_dlist_prev(&(_ci)->children, _prev); _iter; _iter = fr_dlist_prev(&(_ci)->children, _iter))

/** Check if the CONF_ITEM has no children.
 *
 *  Which is the common use-case
 *
 * @param[in] ci		to check
 * @return			true/false
 */
static inline CC_HINT(nonnull) bool cf_item_has_no_children(CONF_ITEM const *ci)
{
	return fr_dlist_empty(&ci->children);
}

#ifdef __cplusplus
}
#endif
