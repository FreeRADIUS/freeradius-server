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
 * Examples of sources are #TMPL_TYPE_XLAT_UNPARSED, #TMPL_TYPE_EXEC and #TMPL_TYPE_ATTR.
 * Examples of sinks are #TMPL_TYPE_ATTR, #TMPL_TYPE_LIST.
 *
 * VPTs are used to gather values or attributes for evaluation, or copying, and to specify
 * where values or #VALUE_PAIR should be copied to.
 *
 * To create new #tmpl_t use one of the tmpl_*from_* functions.  These parse
 * strings into VPTs. The main parsing function is #tmpl_afrom_str, which can produce
 * most types of VPTs. It uses the type of quoting (passed as an #fr_token_t) to determine
 * what type of VPT to parse the string as. For example a #T_DOUBLE_QUOTED_STRING will
 * produce either a #TMPL_TYPE_XLAT_UNPARSED or a #TMPL_TYPE_UNPARSED (depending if the string
 * contained a non-literal expansion).
 *
 * @see tmpl_afrom_str
 * @see tmpl_afrom_attr_str
 *
 * In the case of #TMPL_TYPE_ATTR and #TMPL_TYPE_LIST, there are special cursor overlay
 * functions which can be used to iterate over only the #VALUE_PAIR that match a
 * tmpl_t in a given list.
 *
 * @see tmpl_cursor_init
 * @see tmpl_cursor_next
 *
 * Or for simplicity, there are functions which wrap the cursor functions, to copy or
 * return the #VALUE_PAIR that match the VPT.
 *
 * @see tmpl_copy_vps
 * @see tmpl_find_vp
 *
 * If you just need the string value of whatever the VPT refers to, the tmpl_*expand
 * functions may be used. These functions evaluate the VPT, execing, and xlat expanding
 * as necessary. In the case of #TMPL_TYPE_ATTR, and #FR_TYPE_STRING or #FR_TYPE_OCTETS
 * #tmpl_expand will return a pointer to the raw #VALUE_PAIR buffer. This can be very
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
} pair_list_t;

extern fr_table_num_ordered_t const pair_list_table[];
extern size_t pair_list_table_len;

typedef enum requests_ref_e {
	REQUEST_CURRENT = 0,		//!< The current request (default).
	REQUEST_OUTER,			//!< #REQUEST containing the outer layer of the EAP
					//!< conversation. Usually the RADIUS request sent
					//!< by the NAS.

	REQUEST_PARENT,			//!< Parent (whatever it is).
	REQUEST_PROXY,			//!< Proxied request.
	REQUEST_UNKNOWN			//!< Unknown request.
} request_ref_t;

extern fr_table_num_sorted_t const request_ref_table[];
extern size_t request_ref_table_len;

/** Types of #tmpl_t
 */
typedef enum tmpl_type_e {
	TMPL_TYPE_UNINITIALISED = 0,	//!< Uninitialised.

	TMPL_TYPE_NULL,			//!< Has no value.  Usually a placeholder in a binary
					///< expression that's really a unary expression.
	TMPL_TYPE_DATA,			//!< Value in native boxed format.

	TMPL_TYPE_LIST,			//!< Reference to an attribute list.
	TMPL_TYPE_ATTR,			//!< Reference to one or more attributes.

	TMPL_TYPE_EXEC,			//!< Callout to an external script or program.
	TMPL_TYPE_XLAT,	      		//!< Pre-parsed xlat expansion.

	TMPL_TYPE_REGEX,	      	//!< Compiled (and possibly JIT'd) regular expression.

	/** @name Unparsed types
	 *
	 * These are tmpls which could not immediately be transformed into
	 * their "parsed" or "compiled" form due to missing references,
	 * or because the tmpl is "dynamic".
	 *
	 * @{
	 */
	TMPL_TYPE_UNPARSED,		//!< Unparsed literal string.  May be an intermediary phase
					///< where the tmpl is created as a temporary structure
					///< during parsing.

	TMPL_TYPE_ATTR_UNPARSED,	//!< An attribute reference that we couldn't resolve.
					///< May be resolvable later once more attributes are
					///< defined.

	TMPL_TYPE_XLAT_UNPARSED,	//!< Unparsed xlat expansion.  May have a dynamic element.

	TMPL_TYPE_REGEX_UNPARSED,	//!< Unparsed regular expression.  May have a dynamic element.
	/** @} */

	TMPL_TYPE_MAX			//!< Marker for the last tmpl type.
} tmpl_type_t;

/** Helpers to verify the type of #tmpl_t
 */
#define tmpl_is_uninitialised(vpt) 	(vpt->type == TMPL_TYPE_UNINITIALISED)

#define tmpl_is_null(vpt) 		(vpt->type == TMPL_TYPE_NULL)
#define tmpl_is_data(vpt) 		(vpt->type == TMPL_TYPE_DATA)

#define tmpl_is_attr(vpt) 		(vpt->type == TMPL_TYPE_ATTR)
#define tmpl_is_list(vpt) 		(vpt->type == TMPL_TYPE_LIST)

#define tmpl_is_xlat(vpt) 		(vpt->type == TMPL_TYPE_XLAT)
#define tmpl_is_exec(vpt) 		(vpt->type == TMPL_TYPE_EXEC)

#define tmpl_is_regex(vpt) 		(vpt->type == TMPL_TYPE_REGEX)

#define tmpl_is_unparsed(vpt) 		(vpt->type == TMPL_TYPE_UNPARSED)
#define tmpl_is_attr_unparsed(vpt) 	(vpt->type == TMPL_TYPE_ATTR_UNPARSED)
#define tmpl_is_xlat_unparsed(vpt) 	(vpt->type == TMPL_TYPE_XLAT_UNPARSED)
#define tmpl_is_regex_unparsed(vpt) 	(vpt->type == TMPL_TYPE_REGEX_UNPARSED)

extern fr_table_num_sorted_t const tmpl_type_table[];
extern size_t tmpl_type_table_len;

typedef struct tmpl_s tmpl_t;
typedef struct tmpl_rules_s tmpl_rules_t;

#include <freeradius-devel/unlang/xlat.h>
#include <freeradius-devel/util/packet.h>
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
	TMPL_ATTR_REF_PREFIX_NO,				//!< Attribute refs have no '&' prefix.
	TMPL_ATTR_REF_PREFIX_AUTO 			//!< Attribute refs may have a '&' prefix.
} tmpl_attr_ref_prefix_t;

/** Optional arguments passed to vp_tmpl functions
 *
 */
struct tmpl_rules_s {
	fr_dict_t const		*dict_def;		//!< Default dictionary to use
							///< with unqualified attribute references.

	request_ref_t		request_def;		//!< Default request to use with
							///< unqualified attribute references.

	pair_list_t		list_def;		//!< Default list to use with unqualified
							///< attribute reference.

	bool			allow_unknown;		//!< Allow unknown attributes i.e. attributes
							///< defined by OID string.

	bool			allow_unparsed;		//!< Allow attributes that look valid but were
							///< not found in the dictionaries.
							///< This should be used as part of a multi-pass
							///< approach to parsing.

	bool			allow_foreign;		//!< Allow arguments not found in dict_def.

	bool			disallow_internal;	//!< Allow/fallback to internal attributes.

	bool			disallow_qualifiers;	//!< disallow request / list qualifiers

	tmpl_attr_ref_prefix_t	prefix;			//!< Whether the attribute reference requires
							///< a prefix.
};

typedef enum {
	TMPL_ATTR_TYPE_NORMAL = 0,			//!< Normal, resolved, attribute ref.
	TMPL_ATTR_TYPE_UNKNOWN,				//!< We have an attribute number but
							///< it doesn't match anything in the
							///< dictionary, or isn't a child of
							///< the previous ref.  May be resolved
							///< later.
	TMPL_ATTR_TYPE_UNPARSED				//!< We have a name, but nothing else
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
		fr_dict_attr_t		* _CONST da;		//!< Unknown dictionary attribute.
		char			* _CONST name;		//!< Undefined attr ref type.
	} unknown;

	int16_t			_CONST num;		//!< For array references.
	int8_t			_CONST tag;		//!< For tag references.

	tmpl_attr_type_t	_CONST type;
} tmpl_attr_t;

/** An element in a list of request references
 *
 */
typedef struct {
	fr_dlist_t		_CONST entry;		//!< Entry in the doubly linked list
							///< of requestreferences.

	request_ref_t		_CONST request;
} tmpl_request_t;

/** @name Field accessors for attribute references
 *
 * @{
 */
#define ar_da				da
#define ar_unknown			unknown.da
#define ar_unparsed			unknown.name
#define ar_num				num
#define ar_tag				tag
/** @} */

/** A source or sink of value data.
 *
 * Is used as both the RHS and LHS of a map (both update, and conditional types)
 *
 * @section update_maps Use in update vp_map_t
 * When used on the LHS it describes an attribute to create and should be one of these types:
 * - #TMPL_TYPE_ATTR
 * - #TMPL_TYPE_LIST
 *
 * When used on the RHS it describes the value to assign to the attribute being created and
 * should be one of these types:
 * - #TMPL_TYPE_UNPARSED
 * - #TMPL_TYPE_XLAT_UNPARSED
 * - #TMPL_TYPE_ATTR
 * - #TMPL_TYPE_LIST
 * - #TMPL_TYPE_EXEC
 * - #TMPL_TYPE_DATA
 * - #TMPL_TYPE_XLAT (pre-parsed xlat)
 *
 * @section conditional_maps Use in conditional vp_map_t
 * When used as part of a condition it may be any of the RHS side types, as well as:
 * - #TMPL_TYPE_REGEX (pre-parsed regex)
 *
 * @see vp_map_t
 */
struct tmpl_s {
	tmpl_type_t	type;		//!< What type of value tmpl refers to.

	char const	* _CONST name;		//!< Raw string used to create the template.
	size_t		_CONST len;		//!< Length of the raw string used to create the template.
	fr_token_t	_CONST quote;		//!< What type of quoting was around the raw string.

	union {
		_CONST struct {
			fr_dlist_head_t		rr;	//!< Request to search or insert in.

			pair_list_t		list;	//!< List to search or insert in.
							///< deprecated.

			fr_dlist_head_t		ar;	//!< Head of the attribute reference list.

			bool			was_oid;
		} attribute;

		/*
		 *  Attribute value. Typically used as the RHS of an update map.
		 */
		fr_value_box_t	literal;			 //!< Value data.

		xlat_exp_t	*xlat;	 			//!< pre-parsed xlat_exp_t

#ifdef HAVE_REGEX
		struct {
			regex_t			*preg;		//!< pre-parsed regex_t
			fr_regex_flags_t	regex_flags;	//!< Flags for regular expressions.
		};
#endif
	} data;
};

/** Convenience macro for printing a meaningful assert message when we get a bad tmpl type
 */
#define tmpl_assert_type(_cond) \
	fr_assert_msg(_cond, "Unexpected tmpl type '%s'", \
		      fr_table_str_by_value(tmpl_type_table, vpt->type, "<INVALID>"))

/** @name Field accessors for #TMPL_TYPE_ATTR, #TMPL_TYPE_ATTR_UNPARSED, #TMPL_TYPE_LIST
 *
 * @{
 */
static inline request_ref_t tmpl_request(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt) ||
			 tmpl_is_attr_unparsed(vpt) ||
			 tmpl_is_list(vpt));

	return ((tmpl_request_t *)fr_dlist_tail(&vpt->data.attribute.rr))->request;
}

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

static inline char const *tmpl_attr_unparsed(tmpl_t const *vpt)
{
	tmpl_assert_type(vpt->type == TMPL_TYPE_ATTR_UNPARSED);

	return ((tmpl_attr_t *)fr_dlist_tail(&vpt->data.attribute.ar))->ar_unparsed;
}

static inline int16_t tmpl_num(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt) ||
			 tmpl_is_attr_unparsed(vpt) ||
			 tmpl_is_list(vpt));

	return ((tmpl_attr_t *)fr_dlist_tail(&vpt->data.attribute.ar))->ar_num;
}

static inline int8_t tmpl_tag(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt) ||
			 tmpl_is_attr_unparsed(vpt) ||			/* Remove once tags are part of ar dlist */
			 tmpl_is_list(vpt));

	return ((tmpl_attr_t *)fr_dlist_tail(&vpt->data.attribute.ar))->ar_tag;
}

static inline pair_list_t tmpl_list(tmpl_t const *vpt)
{
	tmpl_assert_type(tmpl_is_attr(vpt) ||
			 tmpl_is_attr_unparsed(vpt) ||			/* Remove once list is part of ar dlist */
			 tmpl_is_list(vpt));

	return vpt->data.attribute.list;
}
/** @} */

/** @name Field accessors for #TMPL_TYPE_XLAT
 *
 * @{
 */
#define tmpl_xlat(_tmpl)		(_tmpl)->data.xlat
/** @} */

/** @name Field accessors for #TMPL_TYPE_DATA
 *
 * @{
 */
#define tmpl_value(_tmpl)		(&(_tmpl)->data.literal)
#define tmpl_value_length(_tmpl)	(_tmpl)->data.literal.datum.length
#define tmpl_value_type(_tmpl)		(_tmpl)->data.literal.type

/*
 *	Temporary macros to track where we do assignments
 */
#define tmpl_value_length_set(_tmpl, _len)	(_tmpl)->data.literal.datum.length = (_len)
#define tmpl_value_type_set(_tmpl, _type) 	(_tmpl)->data.literal.type = (_type)
/** @} */

/** @name Field accessors for #TMPL_TYPE_REGEX and #TMPL_TYPE_REGEX_UNPARSED
 *
 * @{
 */
#ifdef HAVE_REGEX
#  define tmpl_preg(_tmpl)		(_tmpl)->data.preg	//!< #TMPL_TYPE_REGEX only.
#  define tmpl_regex_flags(_tmpl)	(_tmpl)->data.regex_flags
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
   static tmpl_t list = tmpl_initialiser_list(CURRENT_REQUEST, PAIR_LIST_REQUEST);
   fr_cursor_t cursor;
   VALUE_PAIR *vp;

   // Iterate over all pairs in the request list
   for (vp = tmpl_cursor_init(NULL, &cursor, request, &list);
   	vp;
   	vp = tmpl_cursor_next(&cursor, &list)) {
   	// Do something
   }
 @endcode
 *
 * @param _request to locate the list in.
 * @param _list to set as the target for the template.
 * @see tmpl_cursor_init
 * @see tmpl_cursor_next
 */
#define	tmpl_initialiser_list(_request, _list)\
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
 * Used in conjunction with the fr_cursor functions to determine the correct list
 * and TALLOC_CTX for inserting VALUE_PAIRs.
 *
 * Example:
 @code{.c}
   TALLOC_CTX *ctx;
   VALUE_PAIR **head;
   fr_value_box_t value;

   RADIUS_LIST_AND_CTX(ctx, head, request, CURRENT_REQUEST, PAIR_LIST_REQUEST);
   if (!list) return -1; // error

   value.strvalue = talloc_typed_strdup(NULL, "my new username");
   value.length = talloc_array_length(value.strvalue) - 1;
 @endcode
 *
 * @param _ctx new #VALUE_PAIR s should be allocated in for the specified list.
 * @param _head of the #VALUE_PAIR list.
 * @param _request The current request.
 * @param _ref to resolve.
 * @param _list to resolve.
 */
#define RADIUS_LIST_AND_CTX(_ctx, _head, _request, _ref, _list) \
do {\
	REQUEST *_rctx = _request; \
	if ((radius_request(&_rctx, _ref) < 0) || \
	    !(_head = radius_list(_rctx, _list)) || \
	    !(_ctx = radius_list_ctx(_rctx, _list))) {\
		_ctx = NULL; \
		_head = NULL; \
	}\
} while (0)

typedef enum {
	ATTR_REF_ERROR_NONE = 0,			//!< No error.
	ATTR_REF_ERROR_EMPTY,				//!< Attribute ref contains no data.
	ATTR_REF_ERROR_BAD_PREFIX,			//!< Missing '&' or has '&' when it shouldn't.
	ATTR_REF_ERROR_INVALID_LIST_QUALIFIER,		//!< List qualifier is invalid.
	ATTR_REF_ERROR_UNKNOWN_ATTRIBUTE_NOT_ALLOWED,	//!< Attribute specified as OID, could not be
							///< found in the dictionaries, and is disallowed
							///< because 'disallow_internal' in tmpl_rules_t
							///< is trie.
	ATTR_REF_ERROR_UNDEFINED_ATTRIBUTE_NOT_ALLOWED,	//!< Attribute couldn't be found in the dictionaries.
	ATTR_REF_ERROR_INVALID_ATTRIBUTE_NAME,		//!< Attribute ref length is zero, or longer than
							///< the maximum.
	ATTR_REF_ERROR_INTERNAL_ATTRIBUTE_NOT_ALLOWED,	//!< Attribute resolved to an internal attribute
							///< which is disallowed.
	ATTR_REF_ERROR_FOREIGN_ATTRIBUTES_NOT_ALLOWED,	//!< Attribute resolved in a dictionary different
							///< to the one specified.
	ATTR_REF_ERROR_TAGGED_ATTRIBUTE_NOT_ALLOWED,	//!< Tagged attributes not allowed here.
	ATTR_REF_ERROR_INVALID_TAG,			//!< Invalid tag value.
	ATTR_REF_ERROR_INVALID_ARRAY_INDEX		//!< Invalid array index.
} attr_ref_error_t;

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

VALUE_PAIR		**radius_list(REQUEST *request, pair_list_t list);

RADIUS_PACKET		*radius_packet(REQUEST *request, pair_list_t list_name);

TALLOC_CTX		*radius_list_ctx(REQUEST *request, pair_list_t list_name);

size_t			radius_list_name(pair_list_t *out, char const *name, pair_list_t default_list);

int			radius_request(REQUEST **request, request_ref_t name);

size_t			radius_request_name(request_ref_t *out, char const *name, request_ref_t unknown);

tmpl_t		*tmpl_init(tmpl_t *vpt, tmpl_type_t type,
				   char const *name, ssize_t len, fr_token_t quote);

tmpl_t		*tmpl_alloc(TALLOC_CTX *ctx, tmpl_type_t type, char const *name,
				    ssize_t len, fr_token_t quote);

void			tmpl_set_name(tmpl_t *vpt, fr_token_t quote, char const *fmt, ...);

int			tmpl_afrom_value_box(TALLOC_CTX *ctx, tmpl_t **out, fr_value_box_t *data, bool steal);

void			tmpl_attr_debug(tmpl_t const *vpt) CC_HINT(nonnull);

int			tmpl_attr_copy(tmpl_t *dst, tmpl_t const *src) CC_HINT(nonnull);

int			tmpl_attr_abstract_to_concrete(tmpl_t *vpt, fr_type_t type) CC_HINT(nonnull);

void			tmpl_attr_to_raw(tmpl_t *vpt) CC_HINT(nonnull);

int			tmpl_attr_set_da(tmpl_t *vpt, fr_dict_attr_t const *da) CC_HINT(nonnull);

int			tmpl_attr_resolve_unparsed(tmpl_t *vpt, tmpl_rules_t const *rules) CC_HINT(nonnull);

void			tmpl_attr_set_unparsed(tmpl_t *vpt, char const *name, size_t len) CC_HINT(nonnull);

int			tmpl_attr_set_leaf_da(tmpl_t *vpt, fr_dict_attr_t const *da) CC_HINT(nonnull);

void			tmpl_attr_set_leaf_num(tmpl_t *vpt, int16_t num) CC_HINT(nonnull);

void			tmpl_attr_rewrite_leaf_num(tmpl_t *vpt, int16_t from, int16_t to) CC_HINT(nonnull);

void			tmpl_attr_rewrite_num(tmpl_t *vpt, int16_t from, int16_t to) CC_HINT(nonnull);

void			tmpl_attr_set_leaf_tag(tmpl_t *vpt, int8_t tag) CC_HINT(nonnull);

void			tmpl_attr_set_request(tmpl_t *vpt, request_ref_t request) CC_HINT(nonnull);

void			tmpl_attr_set_list(tmpl_t *vpt, pair_list_t list) CC_HINT(nonnull);

int			tmpl_attr_afrom_list(TALLOC_CTX *ctx, tmpl_t **out, tmpl_t const *list,
					     fr_dict_attr_t const *da, int8_t tag);

ssize_t			tmpl_afrom_attr_substr(TALLOC_CTX *ctx, attr_ref_error_t *err,
					       tmpl_t **out, char const *name, ssize_t name_len,
					       tmpl_rules_t const *rules);

ssize_t			tmpl_afrom_attr_str(TALLOC_CTX *ctx, attr_ref_error_t *err,
					    tmpl_t **out, char const *name,
					    tmpl_rules_t const *rules) CC_HINT(nonnull (3, 4));

ssize_t			tmpl_afrom_str(TALLOC_CTX *ctx, tmpl_t **out, char const *name, size_t inlen,
				       fr_token_t type, tmpl_rules_t const *rules, bool do_escape);

int			tmpl_cast_in_place(tmpl_t *vpt, fr_type_t type, fr_dict_attr_t const *enumv);

size_t			tmpl_snprint_attr_str(size_t *need, char *out, size_t outlen, tmpl_t const *vpt);

size_t			tmpl_snprint(size_t *need, char *out, size_t outlen, tmpl_t const *vpt);

ssize_t			_tmpl_to_type(void *out,
				      uint8_t *buff, size_t outlen,
				      REQUEST *request,
				      tmpl_t const *vpt,
				      xlat_escape_legacy_t escape, void const *escape_ctx,
				      fr_type_t dst_type)
			CC_HINT(nonnull (1, 4, 5));

ssize_t			_tmpl_to_atype(TALLOC_CTX *ctx, void *out,
		       		       REQUEST *request,
				       tmpl_t const *vpt,
				       xlat_escape_legacy_t escape, void const *escape_ctx,
				       fr_type_t dst_type)
			CC_HINT(nonnull (2, 3, 4));

VALUE_PAIR		*tmpl_cursor_init(int *err, fr_cursor_t *cursor, REQUEST *request,
					  tmpl_t const *vpt);

int			tmpl_copy_vps(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request,
				      tmpl_t const *vpt);

int			tmpl_find_vp(VALUE_PAIR **out, REQUEST *request, tmpl_t const *vpt);

int			tmpl_find_or_add_vp(VALUE_PAIR **out, REQUEST *request, tmpl_t const *vpt);

int			tmpl_unknown_attr_add(tmpl_t *vpt);

int			tmpl_unparsed_attr_add(fr_dict_t *dict, tmpl_t *vpt,
						   fr_type_t type, fr_dict_attr_flags_t const *flags);

ssize_t			tmpl_preparse(char const **out, size_t *outlen, char const *in, size_t inlen,
				      fr_token_t *type, char const **error,
				      fr_dict_attr_t const **castda, bool require_regex,
				      bool allow_xlat) CC_HINT(nonnull(1,2,3,5,6));

bool			tmpl_async_required(tmpl_t const *vpt);

#undef _CONST

#ifdef __cplusplus
}
#endif
