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

	CONF_ITEM_TYPE		type;		//!< Whether the config item is a config_pair, conf_section or cf_data.

	fr_dlist_t		entry;		//!< Entry in dlist
	CONF_ITEM		*parent;	//!< Parent.

	fr_dlist_head_t		children;	//!< The head of the ordered list of children.

	fr_rb_tree_t		*ident1;	//!< Tree to store the first identifier (name1 || type || attr).
	fr_rb_tree_t		*ident2;	//!< Tree to store the second identifier (name2 || name).

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
	bool			parsed;		//!< Was this item used during parsing?
	bool			printed;	//!< Was this item printed already in debug mode?
	bool			referenced;	//!< Was this item referenced in the config?
};

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
	int			allow_unlang;

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

#ifdef __cplusplus
}
#endif
