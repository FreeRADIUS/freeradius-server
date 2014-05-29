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
#ifndef MAP_H
#define MAP_H
/*
 * $Id$
 *
 * @file map.h
 * @brief Structures and prototypes for templates / maps
 *
 * @copyright 2013  The FreeRADIUS server project
 */

RCSIDH(map_h, "$Id$")

#include <freeradius-devel/conffile.h>

#ifdef HAVE_PCREPOSIX_H
#  include <pcreposix.h>
#else
#  ifdef HAVE_REGEX_H
#    include <regex.h>

/*
 *  For POSIX Regular expressions.
 *  (0) Means no extended regular expressions.
 *  REG_EXTENDED means use extended regular expressions.
 */
#    ifndef REG_EXTENDED
#      define REG_EXTENDED (0)
#    endif

#    ifndef REG_NOSUB
#      define REG_NOSUB (0)
#    endif
#  endif
#endif

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

typedef enum vpt_type {
	VPT_TYPE_UNKNOWN = 0,
	VPT_TYPE_LITERAL,		//!< Is a literal string.
	VPT_TYPE_XLAT,			//!< Needs to be expanded.
	VPT_TYPE_ATTR,			//!< Is a dictionary attribute.
	VPT_TYPE_LIST,			//!< Is a list.
	VPT_TYPE_REGEX,			//!< Is a regex.
	VPT_TYPE_EXEC,			//!< Needs to be executed.
	VPT_TYPE_DATA,			//!< is a value_data_t
	VPT_TYPE_XLAT_STRUCT,	      	//!< pre-parsed xlat_exp_t
	VPT_TYPE_REGEX_STRUCT,	      	//!< pre-parsed regex_t
	VPT_TYPE_NULL			//!< VPT has no value
} vpt_type_t;

extern const FR_NAME_NUMBER vpt_types[];

typedef struct xlat_exp xlat_exp_t;

/** A pre-parsed template attribute
 *
 * Is used as both the RHS and LHS of a map (both update, and conditional types)
 *
 * When used on the LHS it describes an attribute to create and should be one of these types:
 * - VPT_TYPE_ATTR
 * - VPT_TYPE_LIST
 *
 * When used on the RHS it describes the value to assign to the attribute being created and
 * should be one of these types:
 * - VPT_TYPE_LITERAL
 * - VPT_TYPE_XLAT
 * - VPT_TYPE_ATTR
 * - VPT_TYPE_LIST
 * - VPT_TYPE_EXEC
 * - VPT_TYPE_DATA
 * - VPT_TYPE_XLAT_STRUCT (pre-parsed xlat)
 *
 * When used as part of a condition it may be any of the RHS side types, as well as:
 * - VPT_TYPE_REGEX_STRUCT (pre-parsed regex)
 *
 * @see value_pair_map_t
 */
typedef struct value_pair_tmpl_t {
	vpt_type_t		type;	 //!< What type of value tmpl refers to.
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
		struct {
			regex_t			*comp;		//!< pre-parsed regex_t
			bool			iflag;		//!< Case insensitive
		} preg;
	} data;
} value_pair_tmpl_t;

#define vpt_request	attribute.request
#define vpt_list	attribute.list
#define vpt_da		attribute.da
#define vpt_num		attribute.num
#define vpt_tag		attribute.tag

#define vpt_xlat	data.xlat

#define vpt_preg	data.preg.comp
#define vpt_iflag	data.preg.iflag

#define vpt_value	data.literal.value
#define vpt_length	data.literal.length

/** Value pair map
 *
 * Value pair maps contain a pair of templates, that describe a src attribute
 * or value, and a destination attribute.
 *
 * Neither src or dst need to be an FR attribute, and their type can be inferred
 * from whether map->da is NULL (not FR).
 *
 * @see value_pair_tmpl_t
 */
typedef struct value_pair_map {
	value_pair_tmpl_t	*dst;	//!< Typically describes the attribute
					//!< to add or modify.
	value_pair_tmpl_t	*src;   //!< Typically describes a value or a
					//!< src attribute to copy.

	FR_TOKEN		op; 	//!< The operator that controls
					//!< insertion of the dst attribute.

	CONF_ITEM		*ci;	//!< Config item that the map was
					//!< created from. Mainly used for
					//!< logging validation errors.

	struct value_pair_map	*next;	//!< The next valuepair map.
} value_pair_map_t;

void radius_tmplfree(value_pair_tmpl_t **tmpl);
int radius_parse_attr(value_pair_tmpl_t *vpt, char const *name,
		      request_refs_t request_def,
		      pair_lists_t list_def);
value_pair_tmpl_t *radius_attr2tmpl(TALLOC_CTX *ctx, char const *name,
				    request_refs_t request_def,
				    pair_lists_t list_def);

value_pair_tmpl_t *radius_str2tmpl(TALLOC_CTX *ctx, char const *name, FR_TOKEN type,
				   request_refs_t request_def,
				   pair_lists_t list_def);
bool radius_cast_tmpl(value_pair_tmpl_t *vpt, DICT_ATTR const *da);
size_t radius_tmpl2str(char *buffer, size_t bufsize, value_pair_tmpl_t const *vpt);
int radius_attrmap(CONF_SECTION *cs, value_pair_map_t **head,
		   pair_lists_t dst_list_def, pair_lists_t src_list_def,
		   unsigned int max);
value_pair_map_t *radius_str2map(TALLOC_CTX *ctx, char const *lhs, FR_TOKEN lhs_type,
				 FR_TOKEN op, char const *rhs, FR_TOKEN rhs_type,
				 request_refs_t dst_request_def,
				 pair_lists_t dst_list_def,
				 request_refs_t src_request_def,
				 pair_lists_t src_list_def);
size_t radius_map2str(char *buffer, size_t bufsize, value_pair_map_t const *map);
value_pair_map_t *radius_cp2map(TALLOC_CTX *ctx, CONF_PAIR *cp,
				request_refs_t dst_request_def,
				pair_lists_t dst_list_def,
				request_refs_t src_request_def,
				pair_lists_t src_list_def);

#ifdef __cplusplus
}
#endif

#endif	/* MAP_H */
