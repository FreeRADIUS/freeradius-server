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
 * Examples of sinks are #TMPL_TYPE_ATTR, #TMPL_TYPE_LIST.
 *
 * VPTs are used to gather values or attributes for evaluation, or copying, and to specify
 * where values or #fr_pair_t should be copied to.
 *
 * To create new #tmpl_t use one of the tmpl_*from_* functions.  These parse
 * strings into VPTs. The main parsing function is #tmpl_afrom_substr, which can produce
 * most types of VPTs. It uses the type of quoting (passed as an #fr_token_t) to determine
 * what type of VPT to parse the string as. For example a #T_DOUBLE_QUOTED_STRING will
 * produce either a #TMPL_TYPE_XLAT_UNRESOLVED or a #TMPL_TYPE_UNRESOLVED (depending if the string
 * contained a non-literal expansion).
 *
 * @see tmpl_afrom_substr
 * @see tmpl_afrom_attr_str
 *
 * In the case of #TMPL_TYPE_ATTR and #TMPL_TYPE_LIST, there are special cursor overlay
 * functions which can be used to iterate over only the #fr_pair_t that match a
 * tmpl_t in a given list.
 *
 * @see tmpl_pair_cursor_init
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
 * useful when using the #FR_TYPE_TMPL type in #CONF_PARSER structs, as it allows the
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

/** The maximum number of request references allowed
 *
 */
#define TMPL_MAX_REQUEST_REF_NESTING	10

/*
 *	Forward declarations
 */
typedef enum pair_list_e {
	PAIR_LIST_REQUEST = 0,		//!< Attributes in incoming or internally proxied
					///< request (default).
	PAIR_LIST_REPLY,		//!< Attributes to send in the response.
	PAIR_LIST_CONTROL,		//!< Attributes that change the behaviour of
					///< modules.
	PAIR_LIST_STATE,		//!< Attributes to store multiple rounds of
					///< challenges/responses.
	PAIR_LIST_UNKNOWN		//!< Unknown list.
} tmpl_pair_list_t;

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

	/** Has no value.  Usually a placeholder in a binary expression that's really a unary expression
	 */
	TMPL_TYPE_NULL			= 0x0001,

	/** Value in native boxed format
	 */
	TMPL_TYPE_DATA			= 0x0002,

	/** Reference to an attribute list
	 */
	TMPL_TYPE_LIST			= 0x0004 | TMPL_FLAG_ATTR,

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
	 * temporary structure during parsing.
	 */
	TMPL_TYPE_UNRESOLVED		= 0x0200 | TMPL_FLAG_UNRESOLVED,

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
#define tmpl_is_uninitialised(vpt) 		(vpt->type == TMPL_TYPE_UNINITIALISED)

#define tmpl_is_null(vpt) 			(vpt->type == TMPL_TYPE_NULL)
#define tmpl_is_data(vpt) 			(vpt->type == TMPL_TYPE_DATA)

#define tmpl_is_attr(vpt) 			(vpt->type == TMPL_TYPE_ATTR)
#define tmpl_is_list(vpt) 			(vpt->type == TMPL_TYPE_LIST)

#define tmpl_is_xlat(vpt) 			(vpt->type == TMPL_TYPE_XLAT)
#define tmpl_is_exec(vpt) 			(vpt->type == TMPL_TYPE_EXEC)

#define tmpl_is_regex(vpt) 			(vpt->type == TMPL_TYPE_REGEX)
#define tmpl_is_regex_uncompiled(vpt)		(vpt->type == TMPL_TYPE_REGEX_UNCOMPILED)
#define tmpl_is_regex_xlat(vpt) 		(vpt->type == TMPL_TYPE_REGEX_XLAT)

#define tmpl_is_unresolved(vpt) 		(vpt->type == TMPL_TYPE_UNRESOLVED)
#define tmpl_is_exec_unresolved(vpt) 		(vpt->type == TMPL_TYPE_EXEC_UNRESOLVED)
#define tmpl_is_attr_unresolved(vpt) 		(vpt->type == TMPL_TYPE_ATTR_UNRESOLVED)
#define tmpl_is_xlat_unresolved(vpt) 		(vpt->type == TMPL_TYPE_XLAT_UNRESOLVED)
#define tmpl_is_regex_xlat_unresolved(vpt) 	(vpt->type == TMPL_TYPE_REGEX_XLAT_UNRESOLVED)

#define tmpl_needs_resolving(vpt)		(vpt->type & TMPL_FLAG_UNRESOLVED)
#define tmpl_contains_attr(vpt)			(vpt->type & TMPL_FLAG_ATTR)
#define tmpl_contains_regex(vpt)		(vpt->type & TMPL_FLAG_REGEX)
#define tmpl_contains_xlat(vpt)			(vpt->type & TMPL_FLAG_XLAT)

extern fr_table_num_ordered_t const tmpl_type_table[];
extern size_t tmpl_type_table_len;


typedef struct tmpl_rules_s tmpl_rules_t;
typedef struct tmpl_s tmpl_t;

#include <freeradius-devel/unlang/xlat.h>
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

/** Specify whether attribute references require a prefix
 *
 */
typedef enum {
	TMPL_ATTR_REF_PREFIX_YES = 0,			//!< Attribute refs must have '&' prefix.
	TMPL_ATTR_REF_PREFIX_NO,			//!< Attribute refs have no '&' prefix.
	TMPL_ATTR_REF_PREFIX_AUTO 			//!< Attribute refs may have a '&' prefix.
} tmpl_attr_prefix_t;

/** Optional arguments passed to vp_tmpl functions
 *
 */
struct tmpl_rules_s {
	tmpl_rules_t const     	*parent;		//!< for parent / child relationships

	fr_dict_t const		*dict_def;		//!< Default dictionary to use
							///< with unqualified attribute references.

	tmpl_request_ref_t	request_def;		//!< Default request to use with
							///< unqualified attribute references.

	tmpl_pair_list_t	list_def;		//!< Default list to use with unqualified
							///< attribute reference.

	fr_dict_attr_t const	*attr_parent;		//!< Point in dictionary tree to resume parsing
							///< from.  If this is provided then dict_def
							///< request_def and list_def will be ignored
							///< and the presence of any of those qualifiers
							///< will be treated as an error.

	bool			allow_unknown;		//!< Allow unknown attributes i.e. attributes
							///< defined by OID string.

	bool			allow_unresolved;	//!< Allow attributes that look valid but were
							///< not found in the dictionaries.
							///< This should be used as part of a multi-pass
							///< approach to parsing.

	bool			allow_foreign;		//!< Allow arguments not found in dict_def.

	bool			disallow_internal;	//!< Allow/fallback to internal attributes.

	bool			disallow_qualifiers;	//!< disallow request / list qualifiers

	bool			disallow_filters;	//!< disallow filters.

	bool			at_runtime;		//!< Produce an ephemeral/runtime tmpl.
							///< Instantiated xlats are not added to the global
							///< trees, regexes are not JIT'd.

	tmpl_attr_prefix_t	prefix;			//!< Whether the attribute reference requires
							///< a prefix.
};

typedef enum {
	TMPL_ATTR_TYPE_NORMAL = 0,			//!< Normal, resolved, attribute ref.
	TMPL_ATTR_TYPE_UNKNOWN,				//!< We have an attribute number but
							///< it doesn't match anything in the
							///< dictionary, or isn't a child of
							///< the previous ref.  May be resolved
							///< later.
	TMPL_ATTR_TYPE_UNRESOLVED			//!< We have a name, but nothing else
							///< to identify the attribute.
							///< may be resolved later.
} tmpl_attr_type_t;

#define NUM_ANY			INT16_MIN
#define NUM_ALL			(INT16_MIN + 1)
#define NUM_COUNT		(INT16_MIN + 2)
#define NUM_LAST		(INT16_MIN + 3)

/** An element in a list of nested attribute references
 *
 */
typedef struct {
	fr_dlist_t		_CONST entry;		//!< Entry in the doubly linked list
							///< of attribute references.

	fr_dict_attr_t const	* _CONST da;		//!< Resolved dictionary attribute.

	union {
		struct {
			fr_dict_attr_t		* _CONST da;		//!< Unknown dictionary attribute.
		} unknown;

		struct {
			char			* _CONST name;		//!< Undefined reference type.
			bool			_CONST is_raw;		//!< User wants the leaf to be raw.
			fr_dict_attr_t const	* _CONST namespace;	//!< Namespace we should be trying
									///< to resolve this attribute in.
		} unresolved;
	};

	fr_dict_attr_t const	* _CONST parent;	//!< The parent we used when trying to
							///< resolve the attribute originally.
							///< Should point to the referenced
							///< attribute.

	bool			_CONST resolve_only;	//!< This reference and those before it
							///< in the list can only be used for
							///< resolution, not building out trees.
	int16_t			_CONST num;		//!< For array references.
	tmpl_attr_type_t	_CONST type;		//!< Type of attribute reference.
} tmpl_attr_t;

/** An element in a list of request references
 *
 */
typedef struct {
	fr_dlist_t		_CONST entry;		//!< Entry in the doubly linked list
							///< of request references.

	tmpl_request_ref_t	_CONST request;
} tmpl_request_t;


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
#define ar_unresolved_raw		unresolved.is_raw
#define ar_unresolved_namespace		unresolved.namespace
#define ar_num				num
/** @} */

/** A source or sink of value data.
 *
 * Is used as both the RHS and LHS of a map (both update, and conditional types)
 *
 * @section update_maps Use in update map_t
 * When used on the LHS it describes an attribute to create and should be one of these types:
 * - #TMPL_TYPE_ATTR
 * - #TMPL_TYPE_LIST
 *
 * When used on the RHS it describes the value to assign to the attribute being created and
 * should be one of these types:
 * - #TMPL_TYPE_UNRESOLVED
 * - #TMPL_TYPE_XLAT_UNRESOLVED
 * - #TMPL_TYPE_ATTR
 * - #TMPL_TYPE_LIST
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
		char *unescaped;		//!< Unescaped form of the name, used for TMPL_TYPE_UNRESOLVED
						///< and TMPL_TYPE_REGEX_UNCOMPILED.

		_CONST struct {
			bool			ref_prefix;	//!< true if the reference was prefixed
								///< with a '&'.

			fr_dlist_head_t		rr;		//!< Request to search or insert in.

			tmpl_pair_list_t	list;		//!< List to search or insert in.
								///< deprecated.

			fr_dlist_head_t		ar;		//!< Head of the attribute reference list.

			bool			was_oid;	//!< Was originally a numeric OID.
		} attribute;

		/*
		 *  Attribute value. Typically used as the RHS of an update map.
		 */
		fr_value_box_t	literal;			 //!< Value data.

		_CONST struct {
			xlat_exp_t		*ex;	 	//!< pre-parsed xlat_exp_t
			xlat_flags_t		flags;		//!< Flags controlling evaluation
								///< and expansion.
		} xlat;
#ifdef HAVE_REGEX
		_CONST struct {
			regex_t			*ex;		//!< pre-parsed regex_t
			fr_regex_flags_t	flags;		//!< Flags for regular expressions.
		} reg;
#endif
	} data;

	fr_type_t	_CONST cast;
	tmpl_rules_t	_CONST rules;
};

typedef struct tmpl_cursor_ctx_s tmpl_pair_cursor_ctx_t;
typedef struct tmpl_cursor_nested_s tmpl_cursor_nested_t;

typedef fr_pair_t *(*tmpl_cursor_eval_t)(fr_dlist_head_t *list_head, fr_pair_t *current, tmpl_cursor_nested_t *ns);

/** State for traversing an attribute reference
 *
 */
struct tmpl_cursor_nested_s {
	fr_dlist_t		entry;		//!< Entry in the dlist.
	tmpl_attr_t const	*ar;		//!< Attribute reference this state
						///< entry is associated with.  Mainly for debugging.
	tmpl_cursor_eval_t	func;		//!< Function used to evaluate this attribute reference.
	TALLOC_CTX		*list_ctx;	//!< Track where we should be allocating attributes.

	union {
		struct {
			fr_da_stack_t		da_stack;		//!< fr_dict_attr_t hierarchy
									///< between a->b.
			fr_dcursor_stack_t	*cursor_stack;		//!< Track state as we traverse VPs.
		} tlv;

		struct {
			fr_dcursor_t		cursor;			//!< Group traversal is much easier
									///< but we still need to keep track
									///< where we are in the list in case
									///< we're doing counts.
		} group;

		struct {
			fr_pair_list_t		*list_head;		//!< Head of the list we're currently
									///< iterating over.
		} leaf;
	};
};

/** Maintains state between cursor calls
 *
 */
struct tmpl_cursor_ctx_s {
	TALLOC_CTX		*ctx;		//!< Temporary allocations go here.
	TALLOC_CTX		*pool;		//!< Temporary pool.
	tmpl_t const		*vpt;		//!< tmpl we're evaluating.

	request_t		*request;	//!< Result of following the request references.
	fr_pair_list_t		*list;		//!< List within the request.

	tmpl_cursor_nested_t	leaf;		//!< Pre-allocated leaf state.  We always need
						///< one of these so it doesn't make sense to
						///< allocate it later.

	fr_dlist_head_t		nested;		//!< Nested state.  These are allocated when we
						///< need to maintain state between multiple
						///< cursor calls for a particular attribute
						///< reference.
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
						///< out from the current extents of the tree.X
	fr_pair_list_t		*list;		//!< List that we tried to evaluate ar in and failed.
						///< Or if ar is NULL, the list that represents the
						///< deepest grouping or TLV attribute the chain of
						///< ars referenced.
} tmpl_attr_extent_t;

extern fr_sbuff_parse_rules_t const tmpl_parse_rules_bareword_unquoted;
extern fr_sbuff_parse_rules_t const tmpl_parse_rules_double_unquoted;
extern fr_sbuff_parse_rules_t const tmpl_parse_rules_single_unquoted;
extern fr_sbuff_parse_rules_t const tmpl_parse_rules_solidus_unquoted;
extern fr_sbuff_parse_rules_t const tmpl_parse_rules_backtick_unquoted;
extern fr_sbuff_parse_rules_t const *tmpl_parse_rules_unquoted[T_TOKEN_LAST];

extern fr_sbuff_parse_rules_t const tmpl_parse_rules_bareword_quoted;
extern fr_sbuff_parse_rules_t const tmpl_parse_rules_double_quoted;
extern fr_sbuff_parse_rules_t const tmpl_parse_rules_single_quoted;
extern fr_sbuff_parse_rules_t const tmpl_parse_rules_solidus_quoted;
extern fr_sbuff_parse_rules_t const tmpl_parse_rules_backtick_quoted;
extern fr_sbuff_parse_rules_t const *tmpl_parse_rules_quoted[T_TOKEN_LAST];

/** Convenience macro for printing a meaningful assert message when we get a bad tmpl type
 */
#define tmpl_assert_type(_cond) \
	fr_assert_msg(_cond, "Unexpected tmpl type '%s'", \
		      fr_table_str_by_value(tmpl_type_table, vpt->type, "<INVALID>"))

/** @name Field accessors for #TMPL_TYPE_ATTR, #TMPL_TYPE_ATTR_UNRESOLVED, #TMPL_TYPE_LIST
 *
 * @{
 */
static inline tmpl_request_ref_t tmpl_request(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt) ||
			 tmpl_is_attr_unresolved(vpt) ||
			 tmpl_is_list(vpt));

	return ((tmpl_request_t *)fr_dlist_tail(&vpt->data.attribute.rr))->request;
}

/** The number of request references contained within a tmpl
 *
 */
static inline size_t tmpl_request_ref_count(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt) ||
			 tmpl_is_attr_unresolved(vpt) ||
			 tmpl_is_list(vpt));

	return fr_dlist_num_elements(&vpt->data.attribute.rr);
}

/**
 *
 * @hidecallergraph
 */
static inline fr_dict_attr_t const *tmpl_da(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt));

	return ((tmpl_attr_t *)fr_dlist_tail(&vpt->data.attribute.ar))->ar_da;
}

static inline fr_dict_attr_t const *tmpl_unknown(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt));

	return ((tmpl_attr_t *)fr_dlist_tail(&vpt->data.attribute.ar))->ar_unknown;
}

static inline char const *tmpl_attr_unresolved(tmpl_t const *vpt)
{
	tmpl_assert_type(vpt->type == TMPL_TYPE_ATTR_UNRESOLVED);

	return ((tmpl_attr_t *)fr_dlist_tail(&vpt->data.attribute.ar))->ar_unresolved;
}

/** The number of attribute references contained within a tmpl
 *
 */
static inline size_t tmpl_attr_count(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt) ||
			 tmpl_is_attr_unresolved(vpt));

	return fr_dlist_num_elements(&vpt->data.attribute.ar);
}

static inline int16_t tmpl_num(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt) ||
			 tmpl_is_attr_unresolved(vpt) ||
			 tmpl_is_list(vpt));

	if (tmpl_is_list(vpt) && (fr_dlist_num_elements(&vpt->data.attribute.ar) == 0)) return NUM_ALL;

	return ((tmpl_attr_t *)fr_dlist_tail(&vpt->data.attribute.ar))->ar_num;
}

static inline tmpl_pair_list_t tmpl_list(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt) ||
			 tmpl_is_attr_unresolved(vpt) ||			/* Remove once list is part of ar dlist */
			 tmpl_is_list(vpt));

	return vpt->data.attribute.list;
}
/** @} */

/** @name Field accessors for #TMPL_TYPE_XLAT
 *
 * @{
 */
#define tmpl_xlat(_tmpl)			(_tmpl)->data.xlat.ex
#define tmpl_xlat_flags(_tmpl)			(&(_tmpl)->data.xlat.flags)
/** @} */

/** @name Field accessors for #TMPL_TYPE_DATA
 *
 * @{
 */
#define tmpl_value(_tmpl)			(&(_tmpl)->data.literal)
#define tmpl_value_length(_tmpl)		(_tmpl)->data.literal.vb_length
#define tmpl_value_type(_tmpl)			(_tmpl)->data.literal.type
#define tmpl_value_enumv(_tmpl)			(_tmpl)->data.literal.enumv

/*
 *	Temporary macros to track where we do assignments
 */
#define tmpl_value_length_set(_tmpl, _len)	(_tmpl)->data.literal.vb_length = (_len)
#define tmpl_value_type_set(_tmpl, _type) 	(_tmpl)->data.literal.type = (_type)
/** @} */

/** @name Field accessors for #TMPL_TYPE_REGEX and #TMPL_TYPE_REGEX_XLAT_UNRESOLVED
 *
 * @{
 */
#ifdef HAVE_REGEX
#  define tmpl_regex(_tmpl)			(_tmpl)->data.reg.ex		//!< #TMPL_TYPE_REGEX only.
#  define tmpl_regex_flags(_tmpl)		(&(_tmpl)->data.reg.flags)
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

/** Produces an initialiser for static #TMPL_TYPE_LIST type #tmpl_t
 *
 * Example:
 @code{.c}
   static tmpl_t     list = tmpl_init_initialiser_list(CURRENT_REQUEST, PAIR_LIST_REQUEST);
   fr_dcursor_t      cursor;
   tmpl_pair_cursor_ctx_t cc,
   fr_pair_t        *vp;

   // Iterate over all pairs in the request list
   for (vp = tmpl_pair_cursor_init(NULL, &cursor, request, &list);
   	vp;
   	vp = tmpl_cursor_next(&cursor, &list)) {
   	// Do something
   }
   tmpl_pair_cursor_clear(&cc);
 @endcode
 *
 * @param _request to locate the list in.
 * @param _list to set as the target for the template.
 * @see tmpl_pair_cursor_init
 * @see tmpl_cursor_next
 */
#define	tmpl_init_initialiser_list(_request, _list)\
{ \
	.name = "static", \
	.len = sizeof("static"), \
	.type = TMPL_TYPE_LIST, \
	.quote = T_SINGLE_QUOTED_STRING, \
	.data = { \
		.attribute = { \
			.request = _request, \
			.list = _list \
		} \
	} \
}

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

   tmpl_pair_list_and_ctx(ctx, head, request, CURRENT_REQUEST, PAIR_LIST_REQUEST);
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
	TMPL_ATTR_ERROR_INVALID_LIST_QUALIFIER,		//!< List qualifier is invalid.
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
	TMPL_ATTR_ERROR_NESTING_TOO_DEEP,		//!< Too many levels of nesting.
	TMPL_ATTR_ERROR_MISSING_TERMINATOR		//!< Unexpected text found after attribute reference
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
#define	tmpl_expand(_out, _buff, _buff_len, _request, _vpt, _escape, _escape_ctx) \
	_tmpl_to_type((void *)(_out), (uint8_t *)_buff, _buff_len, \
		      _request, _vpt, _escape, _escape_ctx, FR_TYPE_FROM_PTR(_out))

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
#define tmpl_aexpand_type(_ctx, _out, _type, _request, _vpt, _escape, _escape_ctx) \
			  _tmpl_to_atype(_ctx, (void *)(_out), _request, _vpt, _escape, _escape_ctx, _type)

void			tmpl_debug(tmpl_t const *vpt);

fr_pair_list_t		*tmpl_list_head(request_t *request, tmpl_pair_list_t list);

fr_radius_packet_t	*tmpl_packet_ptr(request_t *request, tmpl_pair_list_t list_name);

TALLOC_CTX		*tmpl_list_ctx(request_t *request, tmpl_pair_list_t list_name);

size_t			tmpl_pair_list_name(tmpl_pair_list_t *out, char const *name, tmpl_pair_list_t default_list);

int			tmpl_request_ptr(request_t **request, tmpl_request_ref_t name);

size_t			tmpl_request_ref_by_name(tmpl_request_ref_t *out, char const *name, tmpl_request_ref_t unknown);

tmpl_t			*tmpl_init_printf(tmpl_t *vpt, tmpl_type_t type, fr_token_t quote, char const *fmt, ...);

tmpl_t			*tmpl_init_shallow(tmpl_t *vpt, tmpl_type_t type,
					   fr_token_t quote, char const *name, ssize_t len);

tmpl_t			*tmpl_init(tmpl_t *vpt, tmpl_type_t type, fr_token_t quote, char const *name, ssize_t len);

tmpl_t			*tmpl_alloc(TALLOC_CTX *ctx, tmpl_type_t type, fr_token_t quote, char const *name, ssize_t len);

void			tmpl_set_name_printf(tmpl_t *vpt, fr_token_t quote, char const *fmt, ...);

void			tmpl_set_name_shallow(tmpl_t *vpt, fr_token_t quote, char const *name, ssize_t len);

void			tmpl_set_name(tmpl_t *vpt, fr_token_t quote, char const *name, ssize_t len);

int			tmpl_afrom_value_box(TALLOC_CTX *ctx, tmpl_t **out, fr_value_box_t *data, bool steal);

void			tmpl_attr_ref_debug(const tmpl_attr_t *ar, int idx);

void			tmpl_attr_ref_list_debug(fr_dlist_head_t const *ar_head) CC_HINT(nonnull);

void			tmpl_attr_debug(tmpl_t const *vpt) CC_HINT(nonnull);

int			tmpl_attr_copy(tmpl_t *dst, tmpl_t const *src) CC_HINT(nonnull);

int			tmpl_attr_set_da(tmpl_t *vpt, fr_dict_attr_t const *da) CC_HINT(nonnull);

int			tmpl_attr_set_leaf_da(tmpl_t *vpt, fr_dict_attr_t const *da) CC_HINT(nonnull);

void			tmpl_attr_set_leaf_num(tmpl_t *vpt, int16_t num) CC_HINT(nonnull);

void			tmpl_attr_rewrite_leaf_num(tmpl_t *vpt, int16_t from, int16_t to) CC_HINT(nonnull);

void			tmpl_attr_rewrite_num(tmpl_t *vpt, int16_t from, int16_t to) CC_HINT(nonnull);

void			tmpl_attr_set_request(tmpl_t *vpt, tmpl_request_ref_t request) CC_HINT(nonnull);

void			tmpl_attr_set_list(tmpl_t *vpt, tmpl_pair_list_t list) CC_HINT(nonnull);

int			tmpl_attr_afrom_list(TALLOC_CTX *ctx, tmpl_t **out, tmpl_t const *list,
					     fr_dict_attr_t const *da);

/** @name Produce a #tmpl_t from a string or substring
 *
 * @{
 */
ssize_t			tmpl_afrom_attr_substr(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
					       tmpl_t **out, fr_sbuff_t *name,
					       fr_sbuff_parse_rules_t const *p_rules,
					       tmpl_rules_t const *t_rules);

ssize_t			tmpl_afrom_attr_str(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
					    tmpl_t **out, char const *name,
					    tmpl_rules_t const *rules) CC_HINT(nonnull (3, 4));

ssize_t			tmpl_afrom_substr(TALLOC_CTX *ctx, tmpl_t **out,
					  fr_sbuff_t *in,
					  fr_token_t quote,
					  fr_sbuff_parse_rules_t const *p_rules,
					  tmpl_rules_t const *t_rules);

ssize_t			tmpl_cast_from_substr(fr_type_t *out, fr_sbuff_t *in);	/* Parses cast string */

int			tmpl_cast_set(tmpl_t *vpt, fr_type_t type);		/* Sets cast type */

#ifdef HAVE_REGEX
ssize_t			tmpl_regex_flags_substr(tmpl_t *vpt, fr_sbuff_t *in,
						fr_sbuff_term_t const *terminals);
#endif
/** @} */

/** @name Change a #tmpl_t type, usually by casting or resolving a reference
 * @{
 */
int			tmpl_cast_in_place(tmpl_t *vpt, fr_type_t type, fr_dict_attr_t const *enumv);

int			tmpl_resolve(tmpl_t *vpt) CC_HINT(nonnull);

void			tmpl_unresolve(tmpl_t *vpt) CC_HINT(nonnull);

int			tmpl_attr_to_xlat(TALLOC_CTX *ctx, tmpl_t **vpt_p);

void			tmpl_attr_to_raw(tmpl_t *vpt);

int			tmpl_attr_unknown_add(tmpl_t *vpt);

int			tmpl_attr_unresolved_add(fr_dict_t *dict, tmpl_t *vpt,
						 fr_type_t type, fr_dict_attr_flags_t const *flags);

#ifdef HAVE_REGEX
ssize_t			tmpl_regex_compile(tmpl_t *vpt, bool subcaptures);
#endif
/** @} */

/** @name Print the contents of a #tmpl_t
 * @{
 */
ssize_t			tmpl_attr_print(fr_sbuff_t *out, tmpl_t const *vpt, tmpl_attr_prefix_t ar_prefix);

ssize_t			tmpl_print(fr_sbuff_t *out, tmpl_t const *vpt,
				   tmpl_attr_prefix_t ar_prefix, fr_sbuff_escape_rules_t const *e_rules);

ssize_t			tmpl_print_quoted(fr_sbuff_t *out, tmpl_t const *vpt, tmpl_attr_prefix_t ar_prefix);
/** @} */

/** @name Expand the tmpl, returning one or more values
 * @{
 */
fr_type_t		tmpl_expanded_type(tmpl_t const *vpt);

ssize_t			_tmpl_to_type(void *out,
				      uint8_t *buff, size_t outlen,
				      request_t *request,
				      tmpl_t const *vpt,
				      xlat_escape_legacy_t escape, void const *escape_ctx,
				      fr_type_t dst_type)
			CC_HINT(nonnull (1, 4, 5));

ssize_t			_tmpl_to_atype(TALLOC_CTX *ctx, void *out,
		       		       request_t *request,
				       tmpl_t const *vpt,
				       xlat_escape_legacy_t escape, void const *escape_ctx,
				       fr_type_t dst_type)
			CC_HINT(nonnull (2, 3, 4));

fr_pair_t		*tmpl_pair_cursor_init(int *err, TALLOC_CTX *ctx, tmpl_pair_cursor_ctx_t *cc,
					  fr_dcursor_t *cursor, request_t *request,
					  tmpl_t const *vpt);

void			tmpl_pair_cursor_clear(tmpl_pair_cursor_ctx_t *cc);

int			tmpl_copy_pairs(TALLOC_CTX *ctx, fr_pair_list_t *out,
					request_t *request, tmpl_t const *vpt);

int			tmpl_copy_pair_children(TALLOC_CTX *ctx, fr_pair_list_t *out,
						request_t *request, tmpl_t const *vpt);

int			tmpl_find_vp(fr_pair_t **out, request_t *request, tmpl_t const *vpt);

int			tmpl_find_or_add_vp(fr_pair_t **out, request_t *request, tmpl_t const *vpt);

int			tmpl_extents_find(TALLOC_CTX *ctx,
		      			  fr_dlist_head_t *leaf, fr_dlist_head_t *interior,
					  request_t *request, tmpl_t const *vpt);

int			tmpl_extents_build_to_leaf(fr_dlist_head_t *leaf, fr_dlist_head_t *interior,
						   tmpl_t const *vpt);

void			tmpl_extents_debug(fr_dlist_head_t *head);
/** @} */

ssize_t			tmpl_preparse(char const **out, size_t *outlen, char const *in, size_t inlen,
				      fr_token_t *type,
				      fr_dict_attr_t const **castda, bool require_regex,
				      bool allow_xlat) CC_HINT(nonnull(1,2,3,5));

bool			tmpl_async_required(tmpl_t const *vpt);

#undef _CONST

#ifdef __cplusplus
}
#endif
