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

#ifdef __cplusplus
extern "C" {
#endif

typedef enum pair_lists {
	PAIR_LIST_UNKNOWN = 0,
	PAIR_LIST_REQUEST,
	PAIR_LIST_REPLY,
	PAIR_LIST_CONTROL,
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

/*
 * $Id$
 *
 * @file map.h
 * @brief Structures and prototypes for templates / maps
 *
 * @copyright 2014  The FreeRADIUS server project
 */
typedef enum tmpl_type {
	TMPL_TYPE_UNKNOWN = 0,
	TMPL_TYPE_LITERAL,		//!< Is a literal string.
	TMPL_TYPE_XLAT,			//!< Needs to be expanded.
	TMPL_TYPE_ATTR,			//!< Is a dictionary attribute.
	TMPL_TYPE_LIST,			//!< Is a list.
	TMPL_TYPE_REGEX,		//!< Is a regex.
	TMPL_TYPE_EXEC,			//!< Needs to be executed.
	TMPL_TYPE_DATA,			//!< is a value_data_t
	TMPL_TYPE_XLAT_STRUCT,	      	//!< pre-parsed xlat_exp_t
	TMPL_TYPE_REGEX_STRUCT,	      	//!< pre-parsed regex_t
	TMPL_TYPE_NULL			//!< VPT has no value
} tmpl_type_t;

extern const FR_NAME_NUMBER vpt_types[];

typedef struct xlat_exp xlat_exp_t;

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
	tmpl_type_t		type;	 //!< What type of value tmpl refers to.
	char const		*name;   //!< Original attribute ref string, or
					 //!< where this refers to a none FR
					 //!< attribute, just the string id for
					 //!< the attribute.

	/*
	 * @todo This should be moved into the union, but some code currently
	 * uses value_pair_tmpl_t's to describe both the value and the attribute.
	 * This is wrong, and the code that does this should be converted to use
	 * maps.
	 */
	struct {
		request_refs_t		request; //!< Request to search or insert in.
		pair_lists_t		list;	 //!< List to search or insert in.

		DICT_ATTR const		*da;	 //!< Resolved dictionary attribute.
		int			num;	 //!< for array references
		int8_t			tag;     //!< for tag references
	} attribute;

	union {
		struct {
			value_data_t const	*value;		//!< actual data
			size_t			length;		//!< of the vpd data
		} literal;
		xlat_exp_t	*xlat;	 //!< pre-parsed xlat_exp_t
#ifdef HAVE_REGEX
		struct {
			regex_t			*comp;		//!< pre-parsed regex_t
			bool			iflag;		//!< Case insensitive
		} preg;
#endif
	} data;
} value_pair_tmpl_t;

#define tmpl_request	attribute.request
#define tmpl_list	attribute.list
#define tmpl_da		attribute.da
#define tmpl_num	attribute.num
#define tmpl_tag	attribute.tag

#define tmpl_xlat	data.xlat

#ifdef HAVE_REGEX
#  define tmpl_preg	data.preg.comp
#  define tmpl_iflag	data.preg.iflag
#endif

#define tmpl_value	data.literal.value
#define tmpl_length	data.literal.length

/* Attribute qualifier parsing */
VALUE_PAIR		**radius_list(REQUEST *request, pair_lists_t list);

TALLOC_CTX		*radius_list_ctx(REQUEST *request, pair_lists_t list_name);

pair_lists_t		radius_list_name(char const **name, pair_lists_t unknown);

int			radius_request(REQUEST **request, request_refs_t name);

request_refs_t		radius_request_name(char const **name, request_refs_t unknown);


/* Template manipulation and execution */
int			radius_parse_attr(value_pair_tmpl_t *vpt, char const *name,
					  request_refs_t request_def,
					  pair_lists_t list_def);

void			radius_tmplfree(value_pair_tmpl_t **tmpl);

value_pair_tmpl_t	*radius_attr2tmpl(TALLOC_CTX *ctx, char const *name,
					  request_refs_t request_def,
					  pair_lists_t list_def);

value_pair_tmpl_t	*radius_str2tmpl(TALLOC_CTX *ctx, char const *name, FR_TOKEN type,
					 request_refs_t request_def,
					 pair_lists_t list_def);

bool			radius_cast_tmpl(value_pair_tmpl_t *vpt, DICT_ATTR const *da);

size_t			radius_tmpl2str(char *buffer, size_t bufsize, value_pair_tmpl_t const *vpt);

int			radius_tmpl_get_vp(VALUE_PAIR **out, REQUEST *request, value_pair_tmpl_t const *vpt);

int			radius_tmpl_copy_vp(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request,
					    value_pair_tmpl_t const *vpt);
#endif	/* TMPL_H */
