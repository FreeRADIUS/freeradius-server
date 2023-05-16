#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/**
 * $Id$
 *
 * @file unlang/call_env.h
 * @brief Structures and functions for handling call environments.
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(call_env_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/dlist.h>

typedef struct call_env_s		call_env_t;
typedef struct call_env_parsed_s	call_env_parsed_t;

FR_DLIST_TYPES(call_env_parsed)
FR_DLIST_TYPEDEFS(call_env_parsed, call_env_parsed_head_t, call_env_parsed_entry_t)

typedef enum {
	CALL_ENV_TYPE_VALUE_BOX = 1,
	CALL_ENV_TYPE_VALUE_BOX_LIST
} call_env_dest_t;

/** Per method call config
 *
 * Similar to a CONF_PARSER used to hold details of conf pairs
 * which are evaluated per call for each module method / xlat.
 *
 * This allows the conf pairs to be evaluated within the appropriate context
 * and use the appropriate dictionaries for where the module is in use.
 */
struct call_env_s {
	char const	*name;		//!< Of conf pair to pass to tmpl_tokenizer.
	char const	*dflt;		//!< Default string to pass to the tmpl_tokenizer if no CONF_PAIR found.
	fr_token_t	dflt_quote;	//!< Default quoting for the default string.

	uint32_t	type;		//!< To cast boxes to. Also contains flags controlling parser behaviour.

	size_t		offset;		//!< Where to write results in the output structure when the tmpls are evaluated.

	union {
		struct {
			bool		required;	//!< Tmpl must produce output
			bool		concat;		//!< If the tmpl produced multiple boxes they should be concatenated.
			bool		single;		//!< If the tmpl produces more than one box this is an error.
			bool		multi;		//!< Multiple instances of the conf pairs are allowed.  Resulting
							///< boxes are stored in an array - one entry per conf pair.
			bool		nullable;	//!< Tmpl expansions are allowed to produce no output.
			call_env_dest_t	type;		//!< Type of structure boxes will be written to.
			size_t		size;		//!< Size of structure boxes will be written to.
			char const	*type_name;	//!< Name of structure type boxes will be written to.
			size_t		tmpl_offset;	//!< Where to write pointer to tmpl in the output structure.  Optional.
		} pair;

		struct {
			char const		*ident2;	//!< Second identifier for a section
			call_env_t const	*subcs;		//!< Nested definitions for subsection.
    		} section;
  	};
};

#define CALL_ENV_TERMINATOR { NULL }

struct call_env_parsed_s {
	call_env_parsed_entry_t	entry;		//!< Entry in list of parsed call_env.
	tmpl_t			*tmpl;		//!< Tmpl produced from parsing conf pair.
	size_t			opt_count;	//!< Number of instances found of this option.
	size_t			multi_index;	//!< Array index for this instance.
	call_env_t const	*rule;		//!< Used to produce this.
};

FR_DLIST_FUNCS(call_env_parsed, call_env_parsed_t, entry)

#ifdef __cplusplus
}
#endif
