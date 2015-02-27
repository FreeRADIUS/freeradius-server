/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifndef TMPL_H
#define TMPL_H
/**
 * $Id$
 *
 * @file tmpl.h
 * @brief Structures and prototypes for templates
 *
 * @copyright 2014  The FreeRADIUS server project
 */

RCSIDH(tmpl_h, "$Id$")

#include <freeradius-devel/xlat.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum pair_lists {
	PAIR_LIST_UNKNOWN = 0,
	PAIR_LIST_REQUEST,
	PAIR_LIST_REPLY,
	PAIR_LIST_CONTROL,
	PAIR_LIST_STATE,
#ifdef WITH_PROXY
	PAIR_LIST_PROXY_REQUEST,
	PAIR_LIST_PROXY_REPLY,
#endif
#ifdef WITH_COA
	PAIR_LIST_COA,
	PAIR_LIST_COA_REPLY,
	PAIR_LIST_DM,
	PAIR_LIST_DM_REPLY
#endif
} pair_lists_t;

extern const FR_NAME_NUMBER pair_lists[];

typedef enum requests {
	REQUEST_UNKNOWN = 0,
	REQUEST_OUTER,
	REQUEST_CURRENT,
	REQUEST_PARENT	/* For future use */
} request_refs_t;

extern const FR_NAME_NUMBER request_refs[];

typedef struct pair_list {
	char const		*name;
	VALUE_PAIR		*check;
	VALUE_PAIR		*reply;
	int			lineno;
	int			order;
	struct pair_list	*next;
	struct pair_list	*lastdefault;
} PAIR_LIST;

typedef enum tmpl_type {
	TMPL_TYPE_UNKNOWN = 0,
	TMPL_TYPE_LITERAL,		//!< Is a literal string.
	TMPL_TYPE_XLAT,			//!< Needs to be expanded.
	TMPL_TYPE_ATTR,			//!< Is a dictionary attribute.
	TMPL_TYPE_ATTR_UNDEFINED,	//!< Is an attribute not found in the global dictionary.
	TMPL_TYPE_LIST,			//!< Is a list.
	TMPL_TYPE_REGEX,		//!< Is a regex.
	TMPL_TYPE_EXEC,			//!< Needs to be executed.
	TMPL_TYPE_DATA,			//!< Is a value_data_t
	TMPL_TYPE_XLAT_STRUCT,	      	//!< pre-parsed xlat_exp_t
	TMPL_TYPE_REGEX_STRUCT,	      	//!< pre-parsed regex_t
	TMPL_TYPE_NULL			//!< VPT has no value
} tmpl_type_t;

extern const FR_NAME_NUMBER tmpl_names[];

typedef struct {
	request_refs_t		request;		//!< Request to search or insert in.
	pair_lists_t		list;			//!< List to search or insert in.

	DICT_ATTR const		*da;			//!< Resolved dictionary attribute.
	union {
		uint8_t			da[DICT_ATTR_SIZE];	//!< Unknown dictionary attribute buffer.
		char			name[DICT_ATTR_SIZE];	//!< Raw unknown dictionary name.
	} unknown;
	int			num;			 //!< For array references.
	int8_t			tag;			 //!< For tag references.
} value_pair_tmpl_attr_t;

/** A pre-parsed template attribute
 *
 * Is used as both the RHS and LHS of a map (both update, and conditional types)
 *
 * When used on the LHS it describes an attribute to create and should be one of these types:
 * - TMPL_TYPE_ATTR
 * - TMPL_TYPE_LIST
 *
 * When used on the RHS it describes the value to assign to the attribute being created and
 * should be one of these types:
 * - TMPL_TYPE_LITERAL
 * - TMPL_TYPE_XLAT
 * - TMPL_TYPE_ATTR
 * - TMPL_TYPE_LIST
 * - TMPL_TYPE_EXEC
 * - TMPL_TYPE_DATA
 * - TMPL_TYPE_XLAT_STRUCT (pre-parsed xlat)
 *
 * When used as part of a condition it may be any of the RHS side types, as well as:
 * - TMPL_TYPE_REGEX_STRUCT (pre-parsed regex)
 *
 * @see value_pair_map_t
 */
typedef struct value_pair_tmpl_t {
	tmpl_type_t	type;		//!< What type of value tmpl refers to.
	char const	*name;		//!< Original attribute ref string, or
					//!< where this refers to a none FR
					//!< attribute, just the string id for
					//!< the attribute.
	size_t		len;		//!< Name length.

#ifdef HAVE_REGEX
	bool		iflag;		//!< regex - case insensitive (if operand is used in regex comparison)
	bool		mflag;		//!< regex - multiline flags (controls $ matching)
#endif

	union {
		/*
		 *  Attribute reference. Either an attribute currently in the request
		 *  or an attribute to create.
		 */
		value_pair_tmpl_attr_t attribute;

		/*
		 *  Attribute value. Typically used as the RHS of an update map.
		 */
		struct {
			PW_TYPE			type;			 //!< Type of data.
			size_t			length;			 //!< of the vpd data.
			value_data_t		data;			 //!< Value data.
		} literal;

		xlat_exp_t	*xlat;	 //!< pre-parsed xlat_exp_t

#ifdef HAVE_REGEX
		regex_t		*preg;		//!< pre-parsed regex_t
#endif
	} data;
} value_pair_tmpl_t;

#define tmpl_request		data.attribute.request
#define tmpl_list		data.attribute.list
#define tmpl_da			data.attribute.da
#define tmpl_unknown		data.attribute.unknown.da
#define tmpl_unknown_name      	data.attribute.unknown.name
#define tmpl_num		data.attribute.num
#define tmpl_tag		data.attribute.tag

#define tmpl_xlat		data.xlat

#define tmpl_data		data.literal
#define tmpl_data_type		data.literal.type
#define tmpl_data_length	data.literal.length
#define tmpl_data_value		data.literal.data

#ifdef HAVE_REGEX
#  define tmpl_preg		data.preg
#  define tmpl_iflag		iflag
#  define tmpl_mflag		mflag
#endif

#ifndef WITH_VERIFY_PTR
#  define VERIFY_TMPL(_x)
#else
#  define VERIFY_TMPL(_x) tmpl_verify(__FILE__,  __LINE__, _x)
void tmpl_verify(char const *file, int line, value_pair_tmpl_t const *vpt);
#endif

/* Attribute qualifier parsing */
VALUE_PAIR		**radius_list(REQUEST *request, pair_lists_t list);

RADIUS_PACKET		*radius_packet(REQUEST *request, pair_lists_t list_name);

TALLOC_CTX		*radius_list_ctx(REQUEST *request, pair_lists_t list_name);

size_t			radius_list_name(pair_lists_t *out, char const *name, pair_lists_t default_list);

int			radius_request(REQUEST **request, request_refs_t name);

size_t			radius_request_name(request_refs_t *out, char const *name, request_refs_t unknown);


/* Template manipulation and execution */
value_pair_tmpl_t	*tmpl_init(value_pair_tmpl_t *vpt, tmpl_type_t type,
				   char const *name, ssize_t len);

value_pair_tmpl_t	*tmpl_alloc(TALLOC_CTX *ctx, tmpl_type_t type, char const *name,
				    ssize_t len);

/*
 *	The following three functions parse attribute name strings into templates
 *
 *	The 'str' variants will error out if the entire string isn't parsed.
 *	The 'afrom' variant will alloc a new tmpl structure.
 *
 */
ssize_t			tmpl_from_attr_substr(value_pair_tmpl_t *vpt, char const *name,
					      request_refs_t request_def, pair_lists_t list_def,
					      bool allow_unknown, bool allow_undefined);

ssize_t			tmpl_from_attr_str(value_pair_tmpl_t *vpt, char const *name,
					   request_refs_t request_def,
					   pair_lists_t list_def,
					   bool allow_unknown, bool allow_undefined);

ssize_t			tmpl_afrom_attr_str(TALLOC_CTX *ctx, value_pair_tmpl_t **out, char const *name,
					    request_refs_t request_def,
					    pair_lists_t list_def,
					    bool allow_unknown, bool allow_undefined);

/*
 *	Parses any type of string into a template
 */
ssize_t			tmpl_afrom_str(TALLOC_CTX *ctx, value_pair_tmpl_t **out, char const *name, size_t inlen,
				       FR_TOKEN type, request_refs_t request_def, pair_lists_t list_def, bool do_escape);

void			tmpl_free(value_pair_tmpl_t **tmpl);

bool			tmpl_cast_in_place(value_pair_tmpl_t *vpt, PW_TYPE type, DICT_ATTR const *enumv);

void			tmpl_cast_in_place_str(value_pair_tmpl_t *vpt);

size_t			tmpl_prints(char *buffer, size_t bufsize, value_pair_tmpl_t const *vpt,
				    DICT_ATTR const *values);

int			tmpl_cast_to_vp(VALUE_PAIR **out, REQUEST *request,
					value_pair_tmpl_t const *vpt, DICT_ATTR const *cast);

ssize_t			tmpl_expand(char const **out, char *buff, size_t outlen, REQUEST *request,
				    value_pair_tmpl_t const *vpt, RADIUS_ESCAPE_STRING escape, void *escape_ctx);

ssize_t			tmpl_aexpand(TALLOC_CTX *ctx, char **out, REQUEST *request, value_pair_tmpl_t const *vpt,
				     RADIUS_ESCAPE_STRING escape, void *escape_ctx);

VALUE_PAIR		*tmpl_cursor_init(int *err, vp_cursor_t *cursor, REQUEST *request,
					  value_pair_tmpl_t const *vpt);

VALUE_PAIR		*tmpl_cursor_next(vp_cursor_t *cursor, value_pair_tmpl_t const *vpt);

int			tmpl_copy_vps(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request,
				      value_pair_tmpl_t const *vpt);

int			tmpl_find_vp(VALUE_PAIR **out, REQUEST *request, value_pair_tmpl_t const *vpt);

bool			tmpl_define_unknown_attr(value_pair_tmpl_t *vpt);

#ifdef __cplusplus
}
#endif
#endif	/* TMPL_H */
