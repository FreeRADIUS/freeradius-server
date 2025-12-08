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
 * @file lib/server/tmpl.h
 * @brief Structures and prototypes for templates
 *
 * These functions are used to work with #tmpl_t structs.
 *
 * #tmpl_t (VPTs) specify either a data source, or a data sink.
 *
 * Examples of sources are #TMPL_TYPE_XLAT_UNRESOLVED, #TMPL_TYPE_EXEC and #TMPL_TYPE_ATTR.
 * Examples of sinks are #TMPL_TYPE_ATTR.
 *
 * VPTs are used to gather values or attributes for evaluation, or copying, and to specify
 * where values or #fr_pair_t should be copied to.
 *
 * To create new #tmpl_t use one of the tmpl_*from_* functions.  These parse
 * strings into VPTs. The main parsing function is #tmpl_afrom_substr, which can produce
 * most types of VPTs. It uses the type of quoting (passed as an #fr_token_t) to determine
 * what type of VPT to parse the string as. For example a #T_DOUBLE_QUOTED_STRING will
 * produce either a #TMPL_TYPE_XLAT_UNRESOLVED or a #TMPL_TYPE_DATA_UNRESOLVED (depending if the string
 * contained a non-literal expansion).
 *
 * @see tmpl_afrom_substr
 * @see tmpl_afrom_attr_str
 *
 * In the case of #TMPL_TYPE_ATTR, there are special cursor overlay
 * functions which can be used to iterate over only the #fr_pair_t that match a
 * tmpl_t in a given list.
 *
 * @see tmpl_dcursor_init
 * @see tmpl_cursor_next
 *
 * Or for simplicity, there are functions which wrap the cursor functions, to copy or
 * return the #fr_pair_t that match the VPT.
 *
 * @see tmpl_copy_pairs
 * @see tmpl_find_vp
 *
 * If you just need the string value of whatever the VPT refers to, the tmpl_*expand
 * functions may be used. These functions evaluate the VPT, execing, and xlat expanding
 * as necessary. In the case of #TMPL_TYPE_ATTR, and #FR_TYPE_STRING or #FR_TYPE_OCTETS
 * #tmpl_expand will return a pointer to the raw #fr_pair_t buffer. This can be very
 * useful when using the #CONF_FLAG_TMPL type in #conf_parser_t structs, as it allows the
 * user to determine whether they want the module to sanitise the value using presentation
 * format specific #xlat_escape_legacy_t function, or to operate on the raw value.
 *
 * @see tmpl_expand
 * @see tmpl_aexpand
 *
 * @copyright 2014-2015 The FreeRADIUS server project
 */
RCSIDH(tmpl_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/value.h>

#include <freeradius-devel/server/tmpl_escape.h>

/** The maximum number of request references allowed
 *
 */
#define TMPL_MAX_REQUEST_REF_NESTING	10

extern fr_table_num_ordered_t const pair_list_table[];
extern size_t pair_list_table_len;

typedef enum requests_ref_e {
	REQUEST_CURRENT = 0,		//!< The current request (default).
	REQUEST_OUTER,			//!< #request_t containing the outer layer of the EAP
					//!< conversation. Usually the RADIUS request sent
					//!< by the NAS.

	REQUEST_PARENT,			//!< Parent (whatever it is).
	REQUEST_UNKNOWN			//!< Unknown request.
} tmpl_request_ref_t;

extern fr_table_num_sorted_t const tmpl_request_ref_table[];
extern size_t tmpl_request_ref_table_len;

/** Base data type is an attribute reference
 *
 */
#define TMPL_FLAG_ATTR		0x01000000

/** Base data type is an xlat expansion
 *
 */
#define TMPL_FLAG_XLAT		0x02000000

/** Is a type of regular expression
 *
 */
#define TMPL_FLAG_REGEX		0x04000000

/** Needs resolution
 *
 */
#define TMPL_FLAG_UNRESOLVED	0x08000000

/** Types of #tmpl_t
 *
 * Types may be compound types made up of multiple other types.
 *
 * Types which are used as part of compound types are:
 * - XLAT_TYPE_XLAT		- #tmpl_t contains xlat expansion.
 * - XLAT_TYPE_UNRESOLVED	- #tmpl_t contains unresolved elements such as xlat functions or other expansions.
 */
typedef enum tmpl_type_e {
	/** Uninitialised
	 */
	TMPL_TYPE_UNINITIALISED 	= 0x0000,

	/** Value in native boxed format
	 */
	TMPL_TYPE_DATA			= 0x0002,

	/** Reference to one or more attributes
	 */
	TMPL_TYPE_ATTR			= 0x0008 | TMPL_FLAG_ATTR,

	/** Pre-parsed xlat expansion
	 */
	TMPL_TYPE_XLAT			= 0x0010 | TMPL_FLAG_XLAT,

	/** Callout to an external script or program
	 */
	TMPL_TYPE_EXEC			= 0x0020 | TMPL_FLAG_XLAT,

	/** Compiled (and possibly JIT'd) regular expression
	 */
	TMPL_TYPE_REGEX			= 0x0040 | TMPL_FLAG_REGEX,

	/** Regex where compilation is possible but hasn't been performed yet
	 */
	TMPL_TYPE_REGEX_UNCOMPILED	= 0x0080 | TMPL_FLAG_REGEX,

	/** A regex containing xlat expansions.  Cannot be pre-compiled
	 */
	TMPL_TYPE_REGEX_XLAT		= 0x0100 | TMPL_FLAG_REGEX | TMPL_FLAG_XLAT,

	/** @name unresolved types
	 *
	 * These are tmpls which could not immediately be transformed into
	 * their "resolved" form due to missing references or because
	 * additional parsing is required.
	 *
	 * @{
	 */

	/** Unparsed literal string
	 *
	 * May be an intermediary phase where the tmpl is created as a
	 * temporary structure during parsing.  The value here MUST be raw
	 * data, and cannot be anything else.
	 */
	TMPL_TYPE_DATA_UNRESOLVED	 =  TMPL_TYPE_DATA | TMPL_FLAG_UNRESOLVED,

	/** An attribute reference that we couldn't resolve but looked valid
	 *
	 * May be resolvable later once more attributes are defined.
	 */
	TMPL_TYPE_ATTR_UNRESOLVED	= TMPL_TYPE_ATTR | TMPL_FLAG_UNRESOLVED,

	/** An exec with unresolved xlat function or attribute references
	 */
	TMPL_TYPE_EXEC_UNRESOLVED	= TMPL_TYPE_EXEC | TMPL_FLAG_UNRESOLVED,

	/** A xlat expansion with unresolved xlat functions or attribute references
	 */
	TMPL_TYPE_XLAT_UNRESOLVED	= TMPL_TYPE_XLAT | TMPL_FLAG_UNRESOLVED,

	/** A regular expression with unresolved xlat functions or attribute references
	 */
	TMPL_TYPE_REGEX_XLAT_UNRESOLVED = TMPL_TYPE_REGEX_XLAT | TMPL_FLAG_UNRESOLVED,

	TMPL_TYPE_MAX			//!< Marker for the last tmpl type.
} tmpl_type_t;

/** Helpers to verify the type of #tmpl_t
 */
#define tmpl_is_uninitialised(vpt) 		((vpt)->type == TMPL_TYPE_UNINITIALISED)

#define tmpl_is_data(vpt) 			((vpt)->type == TMPL_TYPE_DATA)

#define tmpl_is_attr(vpt) 			((vpt)->type == TMPL_TYPE_ATTR)

#define tmpl_is_xlat(vpt) 			((vpt)->type == TMPL_TYPE_XLAT)
#define tmpl_is_exec(vpt) 			((vpt)->type == TMPL_TYPE_EXEC)

#define tmpl_is_regex(vpt) 			((vpt)->type == TMPL_TYPE_REGEX)
#define tmpl_is_regex_uncompiled(vpt)		((vpt)->type == TMPL_TYPE_REGEX_UNCOMPILED)
#define tmpl_is_regex_xlat(vpt) 		((vpt)->type == TMPL_TYPE_REGEX_XLAT)

#define tmpl_is_data_unresolved(vpt) 		((vpt)->type == TMPL_TYPE_DATA_UNRESOLVED)
#define tmpl_is_exec_unresolved(vpt) 		((vpt)->type == TMPL_TYPE_EXEC_UNRESOLVED)
#define tmpl_is_attr_unresolved(vpt) 		((vpt)->type == TMPL_TYPE_ATTR_UNRESOLVED)
#define tmpl_is_xlat_unresolved(vpt) 		((vpt)->type == TMPL_TYPE_XLAT_UNRESOLVED)
#define tmpl_is_regex_xlat_unresolved(vpt) 	((vpt)->type == TMPL_TYPE_REGEX_XLAT_UNRESOLVED)

#define tmpl_needs_resolving(vpt)		(((vpt)->type & TMPL_FLAG_UNRESOLVED) != 0)
#define tmpl_contains_data(vpt)			(((vpt)->type & TMPL_TYPE_DATA) != 0)
#define tmpl_contains_attr(vpt)			(((vpt)->type & TMPL_FLAG_ATTR) != 0)
#define tmpl_contains_regex(vpt)		(((vpt)->type & TMPL_FLAG_REGEX) != 0)
#define tmpl_contains_xlat(vpt)			(((vpt)->type & TMPL_FLAG_XLAT) != 0)


extern fr_table_num_ordered_t const tmpl_type_table[];
extern size_t tmpl_type_table_len;

typedef struct tmpl_rules_s tmpl_rules_t;
typedef struct tmpl_attr_rules_s tmpl_attr_rules_t;
typedef struct tmpl_xlat_rules_s tmpl_xlat_rules_t;
typedef struct tmpl_literal_rules_s tmpl_literal_rules_t;
typedef struct tmpl_res_rules_s tmpl_res_rules_t;
typedef struct tmpl_s tmpl_t;

#include <freeradius-devel/unlang/xlat.h>
#include <freeradius-devel/unlang/xlat_ctx.h>
#include <freeradius-devel/util/packet.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/regex.h>

/*
 *	Allow public and private versions of the same structures
 */
#ifdef _CONST
#  error _CONST can only be defined in the local header
#endif
#ifndef _TMPL_PRIVATE
#  define _CONST const
#else
#  define _CONST
#endif

/** Specify whether attribute references can have a list (or parent) reference
 *
 */
typedef enum {
	TMPL_ATTR_LIST_ALLOW = 0,			//!< Attribute refs are allowed to have a list
	TMPL_ATTR_LIST_FORBID,				//!< Attribute refs are forbidden from having a list
	TMPL_ATTR_LIST_REQUIRE 				//!< Attribute refs are required to have a list.
} tmpl_attr_list_presence_t;

/** Define entry and head types for tmpl request references
 *
 */
FR_DLIST_TYPES(tmpl_request_list)

struct tmpl_attr_rules_s {
	fr_dict_t const		*dict_def;		//!< Default dictionary to use
							///< with unqualified attribute references.

	fr_dict_attr_t const	*namespace;		//!< Point in dictionary tree to resume parsing
							///< from.  If this is provided then dict_def
							///< request_def and list_def will be ignored
							///< and the presence of any of those qualifiers
							///< will be treated as an error.

	FR_DLIST_HEAD(tmpl_request_list) _CONST *request_def;	//!< Default request to use with
							///< unqualified attribute references.
							///< If NULL the request is assumed to
							///< but the current request.
							///< Usually this will be one of
							///< - tmpl_request_def_current
							///< - tmpl_request_def_outer
							///< - tmpl_request_def_parent
							///< If a custom list needs to be
							///< used it should be allocated on
							///< the stack and a pointer to it
							///< placed here.

	fr_dict_attr_t const	*list_def;		//!< Default list to use with unqualified
							///< attribute reference.

	tmpl_attr_list_presence_t list_presence;	//!< Whether the attribute reference can
							///< have a list, forbid it, or require it.

	CONF_ITEM		*ci;			//!< for migration support and various warnings

	uint8_t			allow_unknown:1;	//!< Allow unknown attributes i.e. attributes
							///< defined by OID string.

	uint8_t			allow_unresolved:1;	//!< Allow attributes that look valid but were
							///< not found in the dictionaries.
							///< This should be used as part of a multi-pass
							///< approach to parsing.

	uint8_t			allow_wildcard:1;	//!< Allow the special case of .[*] representing
							///< all children of a structural attribute.

	uint8_t			allow_foreign:1;	//!< Allow arguments not found in dict_def.

	uint8_t			allow_oid:1;		//!< allow numerical OIDs.

	uint8_t			disallow_filters:1;	//!< disallow filters.

	uint8_t			xlat:1	;		//!< for %{User-Name}

	uint8_t			bare_word_enum:1;	//!< for v3 compatibility.

	uint8_t			disallow_rhs_resolve:1;	//!< map RHS is NOT immediately resolved in the context of the LHS.
};

struct tmpl_xlat_rules_s {
	fr_event_list_t		*runtime_el;		//!< The eventlist to use for runtime instantiation
							///< of xlats.
	bool			new_functions;		//!< new function syntax
};

/** Optional arguments passed to vp_tmpl functions
 *
 */
struct tmpl_rules_s {
	tmpl_rules_t const    	 	*parent;		//!< for parent / child relationships

	tmpl_attr_rules_t		attr;			//!< Rules/data for parsing attribute references.
	tmpl_xlat_rules_t		xlat;			//!< Rules/data for parsing xlats.

	fr_dict_attr_t const		*enumv;			//!< Enumeration attribute used to resolve enum values.

	fr_type_t			cast;			//!< Whether there was an explicit cast.
								///< Used to determine if barewords or other values
								///< should be converted to an internal data type.

	bool				at_runtime;		//!< Produce an ephemeral/runtime tmpl.
								///< Instantiated xlats are not added to the global
								///< trees, regexes are not JIT'd.
	fr_value_box_safe_for_t		literals_safe_for;	//!< safe_for value assigned to literal values in
								///< xlats, execs, and data.
	tmpl_escape_t			escape;			//!< How escaping should be handled during evaluation.
};

/** Similar to tmpl_rules_t, but used to specify parameters that may change during subsequent resolution passes
 *
 * When a tmpl is parsed initially the rules are stored in the #tmpl_t.
 *
 * During subsequent resolution phases where unresolved attributes are resolved to dictionary
 * attributes the initial #tmpl_rules_t is used to control resolution.
 *
 * In some instances however (primarily policies), some rules may need change between initial
 * parsing and subsequent resolution phases.
 *
 * This structure holds rules which may override the tmpl_rules_s during subsequent resolution passes.
 */
struct tmpl_res_rules_s {
	fr_dict_t const 	*dict_def;		//!< Alternative default dictionary to use if
							///< vpt->rules->dict_def is NULL.
							//!< Will be written to vpt->rules->dict_def
							///< if used.

	bool			force_dict_def;		//!< Use supplied dict_def even if original
							///< vpt->rules->dict_def was not NULL.

	fr_dict_attr_t const	*enumv;			//!< for resolving T_BARE_WORD
};

typedef enum {
	TMPL_ATTR_TYPE_NORMAL = 0,			//!< Normal, resolved, attribute ref.
	TMPL_ATTR_TYPE_UNSPEC,				//!< No attribute was specified as this level
							///< only a filter.
	TMPL_ATTR_TYPE_UNKNOWN,				//!< We have an attribute number but
							///< it doesn't match anything in the
							///< dictionary, or isn't a child of
							///< the previous ref.  May be resolved
							///< later.
	TMPL_ATTR_TYPE_UNRESOLVED			//!< We have a name, but nothing else
							///< to identify the attribute.
							///< may be resolved later.
} tmpl_attr_type_t;

#define NUM_UNSPEC			INT16_MIN
#define NUM_ALL				(INT16_MIN + 1)
#define NUM_COUNT			(INT16_MIN + 2)
#define NUM_LAST			(INT16_MIN + 3)

/** Define entry and head types for attribute reference lists
 *
 */
FR_DLIST_TYPES(tmpl_attr_list)

/** Different types of filter that can be applied to an attribute reference
 *
 */
typedef enum {
	TMPL_ATTR_FILTER_TYPE_NONE = 0,			//!< No filter present.
	TMPL_ATTR_FILTER_TYPE_INDEX,			//!< Filter is an index type.
	TMPL_ATTR_FILTER_TYPE_CONDITION,       		//!< Filter is a condition
	TMPL_ATTR_FILTER_TYPE_TMPL,       		//!< Filter is a tmpl
	TMPL_ATTR_FILTER_TYPE_EXPR,              	//!< Filter is an expression
} tmpl_attr_filter_type_t;

typedef struct {
	tmpl_attr_filter_type_t	_CONST type;		//!< Type of filter this is.
	int16_t			_CONST num;		//!< For array references.

	/*
	 *	These are "union" because they are disjoint.  The "num" field is arguably disjoint, too, but
	 *	there is currently a lot of code in tmpl_tokenize.c which directly references ar->ar_num
	 *	without checking the type.
	 */
	union {
		xlat_exp_head_t		_CONST *cond;		//!< xlat condition
		tmpl_t			_CONST *tmpl;		//!< tmpl
		xlat_exp_head_t		_CONST *expr;		//!< xlat expression
	};
} tmpl_attr_filter_t;

/** An element in a list of nested attribute references
 *
 */
typedef struct {
	FR_DLIST_ENTRY(tmpl_attr_list)	_CONST entry;	//!< Entry in the doubly linked list
							///< of attribute references.

	fr_dict_attr_t const	* _CONST da;		//!< Resolved dictionary attribute.

	union {
		struct {
			fr_dict_attr_t		* _CONST da;		//!< Unknown dictionary attribute.
		} unknown;

		struct {
			char			* _CONST name;		//!< Undefined reference type.
			fr_dict_attr_t const	* _CONST namespace;	//!< Namespace we should be trying
									///< to resolve this attribute in.
		} unresolved;
	};

	fr_dict_attr_t const	* _CONST parent;	//!< The parent we used when trying to
							///< resolve the attribute originally.
							///< Should point to the referenced
							///< attribute.

	unsigned int   		_CONST resolve_only : 1; //!< This reference and those before it
							///< in the list can only be used for
							///< resolution, not building out trees.
	unsigned int		_CONST is_raw : 1;	/// is a raw reference

	tmpl_attr_type_t	_CONST type;		//!< Type of attribute reference.

	tmpl_attr_filter_t	_CONST filter;		//!< Filter associated with the attribute reference.
} tmpl_attr_t;

/** Define manipulation functions for the attribute reference list
 *
 */
FR_DLIST_FUNCS(tmpl_attr_list, tmpl_attr_t, entry)

/** An element in a list of request references
 *
 */
typedef struct {
	FR_DLIST_ENTRY(tmpl_request_list)	_CONST entry;	//!< Entry in the doubly linked list
								///< of request references.

	tmpl_request_ref_t			_CONST request;
} tmpl_request_t;

/** Define manipulation functions for the attribute reference list
 *
 */
FR_DLIST_FUNCS(tmpl_request_list, tmpl_request_t, entry)

/** How many additional headers to allocate in a pool for a tmpl_t
 *
 */
#define TMPL_POOL_DEF_HEADERS		4

/** How many additional bytes to allocate in a pool for a tmpl_t
 *
 */
#define TMPL_POOL_DEF_LEN		(sizeof(tmpl_t) + 64 + sizeof(tmpl_attr_t) + sizeof(tmpl_request_t))

/** @name Field accessors for attribute references
 *
 * @{
 */
#define ar_type				type
#define ar_depth			depth
#define ar_da				da
#define ar_parent			parent
#define ar_unknown			unknown.da
#define ar_unresolved			unresolved.name
#define ar_unresolved_namespace		unresolved.namespace

#define ar_is_normal(_ar)		((_ar)->ar_type == TMPL_ATTR_TYPE_NORMAL)
#define ar_is_unspecified(_ar)		((_ar)->ar_type == TMPL_ATTR_TYPE_UNSPEC)
#define ar_is_unknown(_ar)		((_ar)->ar_type == TMPL_ATTR_TYPE_UNKNOWN)
#define ar_is_unresolved(_ar)		((_ar)->ar_type == TMPL_ATTR_TYPE_UNRESOLVED)
#define ar_is_raw(_ar)			((_ar)->is_raw)

#define ar_num				filter.num
#define ar_cond				filter.cond
#define ar_tmpl				filter.tmpl
#define ar_expr				filter.expr
#define ar_filter_type			filter.type

#define ar_filter_is_none(_ar)		((_ar)->ar_filter_type == TMPL_ATTR_FILTER_TYPE_NONE)
#define ar_filter_is_num(_ar)		((_ar)->ar_filter_type == TMPL_ATTR_FILTER_TYPE_INDEX)
#define ar_filter_is_cond(_ar)		((_ar)->ar_filter_type == TMPL_ATTR_FILTER_TYPE_CONDITION)
#define ar_filter_is_tmpl(_ar)		((_ar)->ar_filter_type == TMPL_ATTR_FILTER_TYPE_TMPL)
#define ar_filter_is_expr(_ar)		((_ar)->ar_filter_type == TMPL_ATTR_FILTER_TYPE_EXPR)
/** @} */

/** A source or sink of value data.
 *
 * Is used as both the RHS and LHS of a map (both update, and conditional types)
 *
 * @section update_maps Use in update map_t
 * When used on the LHS it describes an attribute to create and should be one of these types:
 * - #TMPL_TYPE_ATTR
 *
 * When used on the RHS it describes the value to assign to the attribute being created and
 * should be one of these types:
 * - #TMPL_TYPE_DATA_UNRESOLVED
 * - #TMPL_TYPE_XLAT_UNRESOLVED
 * - #TMPL_TYPE_ATTR
 * - #TMPL_TYPE_EXEC
 * - #TMPL_TYPE_DATA
 * - #TMPL_TYPE_XLAT (pre-parsed xlat)
 *
 * @section conditional_maps Use in conditional map_t
 * When used as part of a condition it may be any of the RHS side types, as well as:
 * - #TMPL_TYPE_REGEX (pre-parsed regex)
 *
 * @see map_t
 */
struct tmpl_s {
	tmpl_type_t	_CONST type;		//!< What type of value tmpl refers to.

	char const	* _CONST name;		//!< Raw string used to create the template.
						///< this string will have any escape sequences left intact.
	size_t		_CONST len;		//!< Length of the raw string used to create the template.
	fr_token_t	_CONST quote;		//!< What type of quoting was around the raw string.

	union {
		char *unescaped;		//!< Unescaped form of the name, used for TMPL_TYPE_DATA_UNRESOLVED
						///< and TMPL_TYPE_REGEX_UNCOMPILED.

		_CONST struct {
			FR_DLIST_HEAD(tmpl_request_list)	rr;	//!< Request to search or insert in.
			FR_DLIST_HEAD(tmpl_attr_list)		ar;	//!< Head of the attribute reference list.
		} attribute;

		/*
		 *  Attribute value. Typically used as the RHS of an update map.
		 */
		fr_value_box_t	literal;			 //!< Value data.

		struct {
			union {
				_CONST struct {
					xlat_exp_head_t		*ex;	 	//!< pre-parsed xlat expansion
										///< and expansion.
				} xlat;
#ifdef HAVE_REGEX
				_CONST struct {
					char			*src;		//!< Original unescaped source string.
					regex_t			*ex;		//!< pre-parsed regex_t
					bool			subcaptures;	//!< Whether the regex was compiled with
										///< subcaptures.
				} reg;
#endif
			};
			fr_regex_flags_t	reg_flags;	//!< Flags for regular expressions.
								///< Used by:
								///< - TMPL_TYPE_REGEX_XLAT
								///< - TMPL_TYPE_REGEX_UNCOMPILED
								///< - TMPL_TYPE_REGEX
								///< - TMPL_TYPE_REGEX_XLAT_UNRESOLVED
		};
	} data;

	tmpl_rules_t		_CONST	rules;		//!< The rules that were used when creating the tmpl.
							///< These are useful for multiple resolution passes as
							///< they ensure the correct parsing rules are applied.
};

/** Describes the current extents of a pair tree in relation to the tree described by a tmpl_t
 *
 */
typedef struct {
	fr_dlist_t		entry;		//!< Entry in the dlist of extents

	tmpl_attr_t const	*ar;		//!< Attribute representing the ar
						///< after the deepest node that was found
						///< in the existing pair tree when evaluating
						///< this path. If this is NULL, then all ars
						///< were evaluated.

	TALLOC_CTX		*list_ctx;	//!< Where to allocate new attributes if building
						///< out from the current extents of the tree.
	fr_pair_list_t		*list;		//!< List that we tried to evaluate ar in and failed.
						///< Or if ar is NULL, the list that represents the
						///< deepest grouping or TLV attribute the chain of
						///< ars referenced.
} tmpl_attr_extent_t;

/** Convenience macro for printing a meaningful assert message when we get a bad tmpl type
 */
#define tmpl_assert_type(_cond) \
	fr_assert_msg(_cond, "Unexpected tmpl type '%s'", \
		      tmpl_type_to_str(vpt->type))


/** @name Functions for printing and parsing tmpl type names
 *
 * @{
 */
/** Return a static string containing the type name
 *
 * @param[in] type to return name for.
 * @return name of the type
 */
static inline char const *tmpl_type_to_str(tmpl_type_t type)
{
	return fr_table_str_by_value(tmpl_type_table, type, "<INVALID>");
}

/** Return the constant value representing a type
 *
 * @param[in] type to return the constant value for.
 * @return The constant type value or TMPL_TYPE_UNINITIALISED if no type matches.
 */
static inline tmpl_type_t tmpl_type_from_str(char const *type)
{
	return fr_table_value_by_str(tmpl_type_table, type, TMPL_TYPE_UNINITIALISED);
}
/** @} */

/** @name Field accessors for #TMPL_TYPE_ATTR, #TMPL_TYPE_ATTR_UNRESOLVED
 *
 * @{
 */
 #define tmpl_attr(_tmpl)	&(_tmpl)->data.attribute.ar

static inline FR_DLIST_HEAD(tmpl_request_list) const *tmpl_request(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt) ||
			 tmpl_is_attr_unresolved(vpt));

	return &vpt->data.attribute.rr;
}

/** The number of request references contained within a tmpl
 *
 */
static inline size_t tmpl_request_ref_count(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt) ||
			 tmpl_is_attr_unresolved(vpt));

	return tmpl_request_list_num_elements(&vpt->data.attribute.rr);
}

/** Return true if the tmpl_attr is one of the list types
 *
 * @hidecallergraph
*/
static inline bool tmpl_attr_is_list_attr(tmpl_attr_t const *ar)
{
	if (!ar || !ar_is_normal(ar)) return false;

	return (ar->ar_da == request_attr_request) ||
	       (ar->ar_da == request_attr_reply) ||
	       (ar->ar_da == request_attr_control) ||
	       (ar->ar_da == request_attr_state) ||
	       (ar->ar_da == request_attr_local);
}

/** Return true if the head attribute reference is a list reference
 *
 * @hidecallergraph
 */
static inline bool tmpl_attr_head_is_list(tmpl_t const *vpt)
{
	tmpl_attr_t *ar;

	tmpl_assert_type(tmpl_contains_attr(vpt));

	ar = tmpl_attr_list_head(tmpl_attr(vpt));
	if (unlikely(!ar)) return false;

	return tmpl_attr_is_list_attr(ar);
}

/** Return true if the last attribute reference is "normal"
 *
 * @hidecallergraph
 */
static inline bool tmpl_attr_tail_is_normal(tmpl_t const *vpt)
{
	tmpl_attr_t *ar;

	tmpl_assert_type(tmpl_is_attr(vpt));

	ar = tmpl_attr_list_tail(tmpl_attr(vpt));
	if (unlikely(!ar)) return false;

	return ar_is_normal(ar);
}

/** Return true if the last attribute reference is "unspecified"
 *
 * @hidecallergraph
 */
static inline bool tmpl_attr_tail_is_unspecified(tmpl_t const *vpt)
{
	tmpl_attr_t *ar;

	tmpl_assert_type(tmpl_is_attr(vpt));

	ar = tmpl_attr_list_tail(tmpl_attr(vpt));
	if (unlikely(!ar)) return false;

	return ar_is_unspecified(ar);
}

/** Return true if the last attribute reference is "unknown"
 *
 * @hidecallergraph
 */
static inline bool tmpl_attr_tail_is_unknown(tmpl_t const *vpt)
{
	tmpl_attr_t *ar;

	tmpl_assert_type(tmpl_is_attr(vpt));

	ar = tmpl_attr_list_tail(tmpl_attr(vpt));
	if (unlikely(!ar)) return false;

	return ar_is_unknown(ar);
}

/** Return true if the last attribute reference is "unresolved"
 *
 * @hidecallergraph
 */
static inline bool tmpl_attr_tail_is_unresolved(tmpl_t const *vpt)
{
	tmpl_attr_t *ar;

	tmpl_assert_type(tmpl_contains_attr(vpt));

	ar = tmpl_attr_list_tail(tmpl_attr(vpt));
	if (unlikely(!ar)) return false;

	return ar_is_unresolved(ar);
}

/** Return true if the last attribute reference is "raw"
 *
 * @hidecallergraph
 */
static inline bool tmpl_attr_tail_is_raw(tmpl_t const *vpt)
{
	tmpl_attr_t *ar;

	tmpl_assert_type(tmpl_contains_attr(vpt));

	ar = tmpl_attr_list_tail(tmpl_attr(vpt));
	if (unlikely(!ar)) return false;

	return ar_is_raw(ar);
}

/** Return the last attribute reference
 *
 * @hidecallergraph
 */
static inline tmpl_attr_t const *tmpl_attr_tail(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt));

	return tmpl_attr_list_tail(tmpl_attr(vpt));
}

/** Return the last attribute reference da
 *
 * @hidecallergraph
 */
static inline fr_dict_attr_t const *tmpl_attr_tail_da(tmpl_t const *vpt)
{
	tmpl_attr_t *ar;

	tmpl_assert_type(tmpl_is_attr(vpt));

	ar = tmpl_attr_list_tail(tmpl_attr(vpt));
	if (!ar) return NULL;

	return ar->ar_da;
}

/** Return true if the the last attribute reference is a leaf attribute
 *
 * @hidecallergraph
 */
static inline bool tmpl_attr_tail_da_is_leaf(tmpl_t const *vpt)
{
	tmpl_attr_t *ar;

	tmpl_assert_type(tmpl_contains_attr(vpt));

	ar = tmpl_attr_list_tail(tmpl_attr(vpt));
	if (!ar) return false;

	fr_assert(ar_is_normal(ar) || ar_is_unknown(ar) || ar_is_unspecified(ar));

	return fr_type_is_leaf(ar->ar_da->type);
}

/** Return true if the the last attribute reference is a structural attribute
 *
 * @hidecallergraph
 */
static inline bool tmpl_attr_tail_da_is_structural(tmpl_t const *vpt)
{
	tmpl_attr_t *ar;

	tmpl_assert_type(tmpl_contains_attr(vpt));

	ar = tmpl_attr_list_tail(tmpl_attr(vpt));
	if (!ar) return false;

	fr_assert(ar_is_normal(ar) || ar_is_unknown(ar) || ar_is_unspecified(ar));

	return fr_type_is_structural(ar->ar_da->type);
}

/** Return the last attribute reference unknown da
 *
 * @hidecallergraph
 */
static inline fr_dict_attr_t const *tmpl_attr_tail_unknown(tmpl_t const *vpt)
{
	tmpl_attr_t *ar;

	tmpl_assert_type(tmpl_is_attr(vpt));

	ar = tmpl_attr_list_tail(tmpl_attr(vpt));
	if (!ar) return NULL;

	return ar->ar_unknown;
}

/** Return the last attribute reference unresolved da
 *
 * @hidecallergraph
 */
static inline char const *tmpl_attr_tail_unresolved(tmpl_t const *vpt)
{
	tmpl_attr_t *ar;

	tmpl_assert_type(tmpl_is_attr_unresolved(vpt));

	ar = tmpl_attr_list_tail(tmpl_attr(vpt));
	if (!ar) return NULL;

	return ar->ar_unresolved;
}

/** Return the last attribute reference's attribute number
 *
 * @hidecallergraph
 */
static inline int16_t tmpl_attr_tail_num(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt) ||
			 tmpl_is_attr_unresolved(vpt));

	return tmpl_attr_list_tail(tmpl_attr(vpt))->ar_num;
}

/** The number of attribute references contained within a tmpl
 *
 */
static inline size_t tmpl_attr_num_elements(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt) ||
			 tmpl_is_attr_unresolved(vpt));

	return tmpl_attr_list_num_elements(tmpl_attr(vpt));
}

static inline fr_dict_attr_t const *tmpl_list(tmpl_t const *vpt)
{
	if (!tmpl_attr_head_is_list(vpt)) return NULL;

	return tmpl_attr_list_head(tmpl_attr(vpt))->ar_da;
}
/** @} */

/** Return the name of a tmpl list or def if list not provided
 *
*/
static inline char const *tmpl_list_name(fr_dict_attr_t const *list, char const *def)
{
	return (list ? list->name : def);
}

static inline bool tmpl_is_list(tmpl_t const *vpt)
{
	if (!tmpl_is_attr(vpt)) return false;
	return tmpl_attr_is_list_attr(tmpl_attr_tail(vpt));
}

/** @name Field accessors for #TMPL_TYPE_XLAT
 *
 * @{
 */
#define tmpl_xlat(_tmpl)			(_tmpl)->data.xlat.ex
/** @} */

/** @name Field accessors for #TMPL_TYPE_DATA
 *
 * @{
 */
#define tmpl_value(_tmpl)			(&(_tmpl)->data.literal)
#define tmpl_value_length(_tmpl)		(_tmpl)->data.literal.vb_length
#define tmpl_value_type(_tmpl)			(_tmpl)->data.literal.type
#define tmpl_value_enumv(_tmpl)			(_tmpl)->data.literal.enumv

#define tmpl_rules_cast(_tmpl)			(_tmpl)->rules.cast
#define tmpl_rules_enumv(_tmpl)			(_tmpl)->rules.enumv

fr_type_t tmpl_data_type(tmpl_t const *vpt) CC_HINT(nonnull);

/** @} */

/** @name Field accessors for #TMPL_TYPE_REGEX and #TMPL_TYPE_REGEX_XLAT_UNRESOLVED
 *
 * @{
 */
#ifdef HAVE_REGEX
#  define tmpl_regex(_tmpl)			(_tmpl)->data.reg.ex		//!< #TMPL_TYPE_REGEX only.
#  define tmpl_regex_flags(_tmpl)		(&(_tmpl)->data.reg_flags)
#endif
/** @} */

#ifndef WITH_VERIFY_PTR
#  define TMPL_ATTR_VERIFY(_vpt)
#  define TMPL_VERIFY(_vpt)
#else
#  define TMPL_ATTR_VERIFY(_vpt) tmpl_attr_verify(__FILE__, __LINE__, _vpt)
#  define TMPL_VERIFY(_vpt) tmpl_verify(__FILE__, __LINE__, _vpt)
void tmpl_attr_verify(char const *file, int line, tmpl_t const *vpt);
void tmpl_verify(char const *file, int line, tmpl_t const *vpt);
#endif

/** Determine the correct context and list head
 *
 * Used in conjunction with the fr_dcursor functions to determine the correct list
 * and TALLOC_CTX for inserting fr_pair_ts.
 *
 * Example:
 @code{.c}
   TALLOC_CTX *ctx;
   fr_pair_list_t *head;
   fr_value_box_t value;

   tmpl_pair_list_and_ctx(ctx, head, request, CURRENT_REQUEST, request_attr_request);
   if (!list) return -1; // error

   value.strvalue = talloc_typed_strdup(NULL, "my new username");
   value.length = talloc_array_length(value.strvalue) - 1;
 @endcode
 *
 * @param _ctx new #fr_pair_t s should be allocated in for the specified list.
 * @param _head of the #fr_pair_t list.
 * @param _request The current request.
 * @param _ref to resolve.
 * @param _list to resolve.
 */
#define tmpl_pair_list_and_ctx(_ctx, _head, _request, _ref, _list) \
do {\
	request_t *_rctx = _request; \
	if ((tmpl_request_ptr(&_rctx, _ref) < 0) || \
	    !(_head = tmpl_list_head(_rctx, _list)) || \
	    !(_ctx = tmpl_list_ctx(_rctx, _list))) {\
		_ctx = NULL; \
		_head = NULL; \
	}\
} while (0)

typedef enum {
	TMPL_ATTR_ERROR_NONE = 0,			//!< No error.
	TMPL_ATTR_ERROR_EMPTY,				//!< Attribute ref contains no data.
	TMPL_ATTR_ERROR_BAD_PREFIX,			//!< Missing '&' or has '&' when it shouldn't.
	TMPL_ATTR_ERROR_LIST_NOT_ALLOWED,		//!< List qualifier is not allowed here.
	TMPL_ATTR_ERROR_LIST_MISSING,			//!< List qualifier is required, but missing.
	TMPL_ATTR_ERROR_UNKNOWN_NOT_ALLOWED,		//!< Attribute specified as OID, could not be
							///< found in the dictionaries, and is disallowed
							///< because 'disallow_internal' in tmpl_rules_t
							///< is trie.
	TMPL_ATTR_ERROR_UNRESOLVED_NOT_ALLOWED,		//!< Attribute couldn't be found in the dictionaries.
	TMPL_ATTR_ERROR_UNQUALIFIED_NOT_ALLOWED,	//!< Attribute must be qualified to be used here.
	TMPL_ATTR_ERROR_INVALID_NAME,			//!< Attribute ref length is zero, or longer than
							///< the maximum.
	TMPL_ATTR_ERROR_INTERNAL_NOT_ALLOWED,		//!< Attribute resolved to an internal attribute
							///< which is disallowed.
	TMPL_ATTR_ERROR_FOREIGN_NOT_ALLOWED,		//!< Attribute resolved in a dictionary different
							///< to the one specified.
	TMPL_ATTR_ERROR_FILTER_NOT_ALLOWED,		//!< Filters disallowed by rules.
	TMPL_ATTR_ERROR_INVALID_ARRAY_INDEX,		//!< Invalid array index.
	TMPL_ATTR_ERROR_INVALID_FILTER,			//!< Invalid filter
	TMPL_ATTR_ERROR_NESTING_TOO_DEEP,		//!< Too many levels of nesting.
	TMPL_ATTR_ERROR_MISSING_TERMINATOR,		//!< Unexpected text found after attribute reference
	TMPL_ATTR_ERROR_BAD_CAST,			//!< Specified cast was invalid.
	TMPL_ATTR_ERROR_INVALID_OID			//!< OIDs are not allowed
} tmpl_attr_error_t;

/** Map ptr type to a boxed type
 *
 */
#define	FR_TYPE_FROM_PTR(_ptr) \
	_Generic((_ptr), \
		 char **: FR_TYPE_STRING, \
		 char const **: FR_TYPE_STRING, \
		 uint8_t **: FR_TYPE_OCTETS, \
		 uint8_t const **: FR_TYPE_OCTETS, \
		 uint8_t *: FR_TYPE_UINT8, \
		 uint16_t *: FR_TYPE_UINT16, \
		 uint32_t *: FR_TYPE_UINT32, \
		 uint64_t *: FR_TYPE_UINT64, \
		 fr_value_box_t **: FR_TYPE_VALUE_BOX, \
		 fr_value_box_t const **: FR_TYPE_VALUE_BOX)

/** Expand a tmpl to a C type, using existing storage to hold variably sized types
 *
 * Expands a template using the _out ptr to determinate the cast type.
 *
 * @see _tmpl_to_type
 */
#define	tmpl_expand(_out, _buff, _buff_len, _request, _vpt) \
	_tmpl_to_type((void *)(_out), (uint8_t *)_buff, _buff_len, \
		      _request, _vpt, FR_TYPE_FROM_PTR(_out))

/** Expand a tmpl to a C type, allocing a new buffer to hold the string
 *
 * Expands a template using the _out ptr to determinate the cast type.
 *
 * @see _tmpl_to_atype
 */
#define	tmpl_aexpand(_ctx, _out, _request, _vpt, _escape, _escape_ctx) \
	_tmpl_to_atype(_ctx, (void *)(_out), _request, _vpt, _escape, _escape_ctx, FR_TYPE_FROM_PTR(_out))

/** Expand a tmpl to a C type, allocing a new buffer to hold the string
 *
 * Takes an explicit type which must match the ctype pointed to by out.
 *
 * @see _tmpl_to_atype
 */
#define tmpl_aexpand_type(_ctx, _out, _type, _request, _vpt) \
			  _tmpl_to_atype(_ctx, (void *)(_out), _request, _vpt, NULL, NULL, _type)

void			tmpl_debug(FILE *fp, tmpl_t const *vpt) CC_HINT(nonnull);

fr_pair_list_t		*tmpl_list_head(request_t *request, fr_dict_attr_t const *list);

fr_packet_t	*tmpl_packet_ptr(request_t *request, fr_dict_attr_t const *list) CC_HINT(nonnull);

TALLOC_CTX		*tmpl_list_ctx(request_t *request, fr_dict_attr_t const *list);

fr_slen_t		tmpl_attr_list_from_substr(fr_dict_attr_t const **da_p, fr_sbuff_t *in) CC_HINT(nonnull);

tmpl_t			*tmpl_init_printf(tmpl_t *vpt, tmpl_type_t type, fr_token_t quote, char const *fmt, ...) CC_HINT(nonnull(1,4));

tmpl_t			*tmpl_init_shallow(tmpl_t *vpt, tmpl_type_t type, fr_token_t quote,
					   char const *name, ssize_t len,
					   tmpl_rules_t const *t_rules) CC_HINT(nonnull(1,4));

tmpl_t			*tmpl_init(tmpl_t *vpt, tmpl_type_t type, fr_token_t quote,
				   char const *name, ssize_t len,
				   tmpl_rules_t const *t_rules) CC_HINT(nonnull(1,4));

tmpl_t			*tmpl_alloc(TALLOC_CTX *ctx, tmpl_type_t type, fr_token_t quote, char const *name, ssize_t len);

/** @name Parse request qualifiers
 *
 * @{
 */
/** Static default request ref list for the current request
 *
 * Passed as request_def in tmpl_attr_rules_t.
 */
extern FR_DLIST_HEAD(tmpl_request_list) tmpl_request_def_current;

/** Static default request ref list for the outer request
 *
 * Passed as request_def in tmpl_attr_rules_t.
 */
extern FR_DLIST_HEAD(tmpl_request_list) tmpl_request_def_outer;

/** Static default request ref list for the parent request
 *
 * Passed as request_def in tmpl_attr_rules_t.
 */
extern FR_DLIST_HEAD(tmpl_request_list) tmpl_request_def_parent;

int			tmpl_request_ptr(request_t **request, FR_DLIST_HEAD(tmpl_request_list) const *rql) CC_HINT(nonnull);

void			tmpl_request_ref_list_debug(FR_DLIST_HEAD(tmpl_request_list) const *rql);

int8_t			tmpl_request_ref_list_cmp(FR_DLIST_HEAD(tmpl_request_list) const *a,
						  FR_DLIST_HEAD(tmpl_request_list) const *b);

/** Returns true if the specified qualifier list points to the current request
 *
 * @param[in] _list	to check.
 * @return
 *	- true if the list only contains a current request qualifier.
 *	- false otherwise.
 */
#define tmpl_request_ref_is_current(_list) (tmpl_request_ref_list_cmp(_list, &tmpl_request_def_current) == 0)

/** Returns true if the specified qualifier list points to the parent request
 *
 * @param[in] _list	to check.
 * @return
 *	- true if the list only contains a parent request qualifier.
 *	- false otherwise.
 */
#define tmpl_request_ref_is_parent(_list) (tmpl_request_ref_list_cmp(_list, &tmpl_request_def_parent) == 0)

/** Returns true if the specified qualifier list points to the outer request
 *
 * @param[in] _list	to check.
 * @return
 *	- true if the list only contains a outer request qualifier.
 *	- false otherwise.
 */
#define tmpl_request_ref_is_outer(_list) (tmpl_request_ref_list_cmp(_list, &tmpl_request_def_outer) == 0)


fr_slen_t		tmpl_request_ref_list_afrom_substr(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
							   FR_DLIST_HEAD(tmpl_request_list) _CONST **out,
							   fr_sbuff_t *in);
/** @} */

void			tmpl_set_name_printf(tmpl_t *vpt, fr_token_t quote, char const *fmt, ...) CC_HINT(nonnull(1,3));

void			tmpl_set_name_shallow(tmpl_t *vpt, fr_token_t quote, char const *name, ssize_t len) CC_HINT(nonnull);

void			tmpl_set_name(tmpl_t *vpt, fr_token_t quote, char const *name, ssize_t len) CC_HINT(nonnull);

void			tmpl_set_dict_def(tmpl_t *vpt, fr_dict_t const *dict) CC_HINT(nonnull);

void 			tmpl_set_escape(tmpl_t *vpt, tmpl_escape_t const *escape) CC_HINT(nonnull);

void			tmpl_set_xlat(tmpl_t *vpt, xlat_exp_head_t *xlat) CC_HINT(nonnull);

int			tmpl_afrom_value_box(TALLOC_CTX *ctx, tmpl_t **out, fr_value_box_t *data, bool steal) CC_HINT(nonnull);

void			tmpl_attr_ref_debug(FILE *fp, const tmpl_attr_t *ar, int idx) CC_HINT(nonnull);

void			tmpl_attr_ref_list_debug(FILE *fp, FR_DLIST_HEAD(tmpl_attr_list) const *ar_head) CC_HINT(nonnull);

void			tmpl_attr_debug(FILE *fp, tmpl_t const *vpt) CC_HINT(nonnull);

int			tmpl_attr_copy(tmpl_t *dst, tmpl_t const *src) CC_HINT(nonnull);

int			tmpl_attr_set_da(tmpl_t *vpt, fr_dict_attr_t const *da) CC_HINT(nonnull);

int			tmpl_attr_set_leaf_da(tmpl_t *vpt, fr_dict_attr_t const *da) CC_HINT(nonnull);

void			tmpl_attr_rewrite_leaf_num(tmpl_t *vpt, int16_t num) CC_HINT(nonnull);

void			tmpl_attr_set_request_ref(tmpl_t *vpt, FR_DLIST_HEAD(tmpl_request_list) const *request_def) CC_HINT(nonnull);

void			tmpl_attr_set_list(tmpl_t *vpt, fr_dict_attr_t const *list) CC_HINT(nonnull);

int			tmpl_attr_afrom_list(TALLOC_CTX *ctx, tmpl_t **out, tmpl_t const *list,
					     fr_dict_attr_t const *da) CC_HINT(nonnull);

/** @name Produce a #tmpl_t from a string or substring
 *
 * @{
 */
ssize_t			tmpl_afrom_attr_substr(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
					       tmpl_t **out, fr_sbuff_t *name,
					       fr_sbuff_parse_rules_t const *p_rules,
					       tmpl_rules_t const *t_rules) CC_HINT(nonnull(3,4));

ssize_t			tmpl_afrom_attr_str(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
					    tmpl_t **out, char const *name,
					    tmpl_rules_t const *rules) CC_HINT(nonnull (3, 4));

ssize_t			tmpl_afrom_substr(TALLOC_CTX *ctx, tmpl_t **out,
					  fr_sbuff_t *in,
					  fr_token_t quote,
					  fr_sbuff_parse_rules_t const *p_rules,
					  tmpl_rules_t const *t_rules) CC_HINT(nonnull(2,3));

tmpl_t			*tmpl_copy(TALLOC_CTX *ctx, tmpl_t const *in) CC_HINT(nonnull);

ssize_t			tmpl_cast_from_substr(tmpl_rules_t *t_rules, fr_sbuff_t *in) CC_HINT(nonnull(2));		/* Parses cast string */

int			tmpl_cast_set(tmpl_t *vpt, fr_type_t type) CC_HINT(nonnull);	/* Sets cast type */

static inline fr_type_t tmpl_cast_get(tmpl_t *vpt)
{
	return vpt->rules.cast;
}

#ifdef HAVE_REGEX
ssize_t			tmpl_regex_flags_substr(tmpl_t *vpt, fr_sbuff_t *in,
						fr_sbuff_term_t const *terminals) CC_HINT(nonnull(1,2));
#endif
/** @} */

/** @name Change a #tmpl_t type, usually by casting or resolving a reference
 * @{
 */
int			tmpl_cast_in_place(tmpl_t *vpt, fr_type_t type, fr_dict_attr_t const *enumv) CC_HINT(nonnull(1));

int			tmpl_resolve(tmpl_t *vpt, tmpl_res_rules_t const *tr_rules) CC_HINT(nonnull(1));

void			tmpl_unresolve(tmpl_t *vpt) CC_HINT(nonnull);

int			tmpl_attr_unknown_add(tmpl_t *vpt);

int			tmpl_attr_tail_unresolved_add(fr_dict_t *dict, tmpl_t *vpt,
						 fr_type_t type, fr_dict_attr_flags_t const *flags) CC_HINT(nonnull(1));

#ifdef HAVE_REGEX
ssize_t			tmpl_regex_compile(tmpl_t *vpt, bool subcaptures) CC_HINT(nonnull);
#endif
/** @} */

/** @name Print the contents of a #tmpl_t
 * @{
 */
fr_slen_t		tmpl_request_ref_list_print(fr_sbuff_t *out, FR_DLIST_HEAD(tmpl_request_list) const *rql)
			CC_HINT(nonnull(1,2));

static inline fr_slen_t tmpl_request_ref_list_aprint(TALLOC_CTX *ctx, char **out, FR_DLIST_HEAD(tmpl_request_list) const *rql)
			SBUFF_OUT_TALLOC_FUNC_NO_LEN_DEF(tmpl_request_ref_list_print, rql)

fr_slen_t		tmpl_attr_print(fr_sbuff_t *out, tmpl_t const *vpt) CC_HINT(nonnull);

static inline fr_slen_t tmpl_attr_aprint(TALLOC_CTX *ctx, char **out, tmpl_t const *vpt)
			SBUFF_OUT_TALLOC_FUNC_NO_LEN_DEF(tmpl_attr_print, vpt)

fr_slen_t		tmpl_print(fr_sbuff_t *out, tmpl_t const *vpt,
				   fr_sbuff_escape_rules_t const *e_rules) CC_HINT(nonnull(1,2));

static inline fr_slen_t tmpl_aprint(TALLOC_CTX *ctx, char **out, tmpl_t const *vpt,
				    fr_sbuff_escape_rules_t const *e_rules)
			SBUFF_OUT_TALLOC_FUNC_NO_LEN_DEF(tmpl_print, vpt, e_rules)

fr_slen_t		tmpl_print_quoted(fr_sbuff_t *out, tmpl_t const *vpt) CC_HINT(nonnull);

static inline fr_slen_t tmpl_aprint_quoted(TALLOC_CTX *ctx, char **out, tmpl_t const *vpt)
			SBUFF_OUT_TALLOC_FUNC_NO_LEN_DEF(tmpl_print_quoted, vpt)
/** @} */

/** @name Expand the tmpl, returning one or more values
 * @{
 */
fr_type_t		tmpl_expanded_type(tmpl_t const *vpt) CC_HINT(nonnull);

ssize_t			_tmpl_to_type(void *out,
				      uint8_t *buff, size_t outlen,
				      request_t *request,
				      tmpl_t const *vpt,
				      fr_type_t dst_type)
			CC_HINT(nonnull (1, 4, 5));

ssize_t			_tmpl_to_atype(TALLOC_CTX *ctx, void *out,
		       		       request_t *request,
				       tmpl_t const *vpt,
				       xlat_escape_legacy_t escape, void const *escape_ctx,
				       fr_type_t dst_type)
			CC_HINT(nonnull (2, 3, 4));

int			tmpl_copy_pairs(TALLOC_CTX *ctx, fr_pair_list_t *out,
					request_t *request, tmpl_t const *vpt) CC_HINT(nonnull(2,3,4));

int			tmpl_copy_pair_children(TALLOC_CTX *ctx, fr_pair_list_t *out,
						request_t *request, tmpl_t const *vpt) CC_HINT(nonnull(2,3,4));

int			tmpl_find_vp(fr_pair_t **out, request_t *request, tmpl_t const *vpt) CC_HINT(nonnull(2,3));

int			tmpl_find_or_add_vp(fr_pair_t **out, request_t *request, tmpl_t const *vpt) CC_HINT(nonnull);

int 			pair_append_by_tmpl_parent(TALLOC_CTX *ctx, fr_pair_t **out, fr_pair_list_t *list,
						   tmpl_t const *vpt, bool skip_list) CC_HINT(nonnull(1,3,4));

int			tmpl_extents_find(TALLOC_CTX *ctx,
		      			  fr_dlist_head_t *leaf, fr_dlist_head_t *interior,
					  request_t *request, tmpl_t const *vpt) CC_HINT(nonnull(5));

int			tmpl_extents_build_to_leaf_parent(fr_dlist_head_t *leaf, fr_dlist_head_t *interior,
						   tmpl_t const *vpt) CC_HINT(nonnull);

void			tmpl_extents_debug(FILE *fp, fr_dlist_head_t *head) CC_HINT(nonnull);

int			tmpl_eval_pair(TALLOC_CTX *ctx, fr_value_box_list_t *out, request_t *request, tmpl_t const *vpt);

int			tmpl_eval(TALLOC_CTX *ctx, fr_value_box_list_t *out, request_t *request, tmpl_t const *vpt);

int			tmpl_eval_cast_in_place(fr_value_box_list_t *out, request_t *request, tmpl_t const *vpt);
/** @} */

ssize_t			tmpl_preparse(char const **out, size_t *outlen, char const *in, size_t inlen,
				      fr_token_t *type) CC_HINT(nonnull(1,2,3,5));

bool			tmpl_async_required(tmpl_t const *vpt) CC_HINT(nonnull);

int			tmpl_value_list_insert_tail(fr_value_box_list_t *list, fr_value_box_t *vb, tmpl_t const *vpt) CC_HINT(nonnull);

void			tmpl_rules_child_init(TALLOC_CTX *ctx, tmpl_rules_t *out, tmpl_rules_t const *parent, tmpl_t *vpt) CC_HINT(nonnull);

void			tmpl_rules_debug(tmpl_rules_t const *rules) CC_HINT(nonnull);

int			tmpl_global_init(void);

#undef _CONST

#ifdef __cplusplus
}
#endif
