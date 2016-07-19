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
#ifndef _FR_TMPL_H
#define _FR_TMPL_H
/**
 * $Id$
 *
 * @file include/tmpl.h
 * @brief Structures and prototypes for templates
 *
 * These functions are used to work with #vp_tmpl_t structs.
 *
 * #vp_tmpl_t (VPTs) specify either a data source, or a data sink.
 *
 * Examples of sources are #TMPL_TYPE_XLAT, #TMPL_TYPE_EXEC and #TMPL_TYPE_ATTR.
 * Examples of sinks are #TMPL_TYPE_ATTR, #TMPL_TYPE_LIST.
 *
 * VPTs are used to gather values or attributes for evaluation, or copying, and to specify
 * where values or #VALUE_PAIR should be copied to.
 *
 * To create new #vp_tmpl_t use one of the tmpl_*from_* functions.  These parse
 * strings into VPTs. The main parsing function is #tmpl_afrom_str, which can produce
 * most types of VPTs. It uses the type of quoting (passed as an #FR_TOKEN) to determine
 * what type of VPT to parse the string as. For example a #T_DOUBLE_QUOTED_STRING will
 * produce either a #TMPL_TYPE_XLAT or a #TMPL_TYPE_UNPARSED (depending if the string
 * contained a non-literal expansion).
 *
 * @see tmpl_afrom_str
 * @see tmpl_afrom_attr_str
 * @see tmpl_from_attr_str
 * @see tmpl_from_attr_substr
 *
 * In the case of #TMPL_TYPE_ATTR and #TMPL_TYPE_LIST, there are special cursor overlay
 * functions which can be used to iterate over only the #VALUE_PAIR that match a
 * vp_tmpl_t in a given list.
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
 * as necessary. In the case of #TMPL_TYPE_ATTR, and #PW_TYPE_STRING or #PW_TYPE_OCTETS
 * #tmpl_expand will return a pointer to the raw #VALUE_PAIR buffer. This can be very
 * useful when using the #PW_TYPE_TMPL type in #CONF_PARSER structs, as it allows the
 * user to determine whether they want the module to sanitise the value using presentation
 * format specific #xlat_escape_t function, or to operate on the raw value.
 *
 * @see tmpl_expand
 * @see tmpl_aexpand
 *
 * @copyright 2014-2015 The FreeRADIUS server project
 */
RCSIDH(tmpl_h, "$Id$")

#include <freeradius-devel/xlat.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum pair_lists {
	PAIR_LIST_UNKNOWN = 0,		//!< Unknown list.
	PAIR_LIST_REQUEST,		//!< Attributes in incoming or internally proxied
					///< request.
	PAIR_LIST_REPLY,		//!< Attributes to send in the response.
	PAIR_LIST_CONTROL,		//!< Attributes that change the behaviour of
					///< modules.
	PAIR_LIST_STATE,		//!< Attributes to store multiple rounds of
					///< challenges/responses.
#ifdef WITH_PROXY
	PAIR_LIST_PROXY_REQUEST,	//!< A copy of attributes in the request list
					///< that may be modified in pre-proxy before
					//!< proxying the request.
	PAIR_LIST_PROXY_REPLY,		//!< Attributes sent in response to the proxied
					///< request.
#endif
#ifdef WITH_COA
	PAIR_LIST_COA,			//!< Attributes to send in a forked CoA-Request.
	PAIR_LIST_COA_REPLY,		//!< Attributes sent in response to the forked
					///< CoA-Request.
	PAIR_LIST_DM,			//!< Attributes to send in a forked Disconnect-Request.
	PAIR_LIST_DM_REPLY		//!< Attributes sent in response to the forked
					//!< Disconnect-Request.
#endif
} pair_lists_t;

extern const FR_NAME_NUMBER pair_lists[];

typedef enum requests {
	REQUEST_UNKNOWN = 0,		//!< Unknown request.
	REQUEST_OUTER,			//!< #REQUEST containing the outer layer of the EAP
					//!< conversation. Usually the RADIUS request sent
					//!< by the NAS.
	REQUEST_CURRENT,		//!< The current request.
	REQUEST_PARENT,			//!< Parent (whatever it is).
	REQUEST_PROXY			//!< Proxied request
} request_refs_t;

extern const FR_NAME_NUMBER request_refs[];

typedef struct pair_list {
	char const		*name;
	VALUE_PAIR		*check;
	VALUE_PAIR		*reply;
	int			lineno;
	struct pair_list	*next;
} PAIR_LIST;

/** Types of #vp_tmpl_t
 */
typedef enum tmpl_type {
	TMPL_TYPE_UNKNOWN = 0,		//!< Uninitialised.
	TMPL_TYPE_UNPARSED,		//!< Unparsed literal string.
	TMPL_TYPE_XLAT,			//!< XLAT expansion.
	TMPL_TYPE_ATTR,			//!< Dictionary attribute.
	TMPL_TYPE_ATTR_UNDEFINED,	//!< Attribute not found in the global dictionary.
	TMPL_TYPE_LIST,			//!< Attribute list.
	TMPL_TYPE_REGEX,		//!< Regular expression.
	TMPL_TYPE_EXEC,			//!< Callout to an external script or program.
	TMPL_TYPE_DATA,			//!< Value in native format.
	TMPL_TYPE_XLAT_STRUCT,	      	//!< Pre-parsed XLAT expansion.
	TMPL_TYPE_REGEX_STRUCT,	      	//!< Pre-parsed regular expression.
	TMPL_TYPE_NULL			//!< Has no value.
} tmpl_type_t;

extern const FR_NAME_NUMBER tmpl_names[];

/** Describes a #TMPL_TYPE_ATTR, #TMPL_TYPE_ATTR_UNDEFINED or #TMPL_TYPE_LIST
 */
typedef struct {
	request_refs_t		request;		//!< Request to search or insert in.
	pair_lists_t		list;			//!< List to search or insert in.

	fr_dict_attr_t const		*da;			//!< Resolved dictionary attribute.
	union {
		uint8_t			da[FR_DICT_ATTR_SIZE];	//!< Unknown dictionary attribute buffer.
		uint8_t			vendor[FR_DICT_ATTR_SIZE];	//!< Unknown dictionary attribute buffer.
		char			name[FR_DICT_ATTR_SIZE];	//!< Raw unknown dictionary name.
	} unknown;
	int			num;			 //!< For array references.
	int8_t			tag;			 //!< For tag references.
} value_pair_tmpl_attr_t;

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
 * - #TMPL_TYPE_XLAT
 * - #TMPL_TYPE_ATTR
 * - #TMPL_TYPE_LIST
 * - #TMPL_TYPE_EXEC
 * - #TMPL_TYPE_DATA
 * - #TMPL_TYPE_XLAT_STRUCT (pre-parsed xlat)
 *
 * @section conditional_maps Use in conditional vp_map_t
 * When used as part of a condition it may be any of the RHS side types, as well as:
 * - #TMPL_TYPE_REGEX_STRUCT (pre-parsed regex)
 *
 * @see vp_map_t
 */
typedef struct vp_tmpl_t {
	tmpl_type_t	type;		//!< What type of value tmpl refers to.

	char const	*name;		//!< Raw string used to create the template.
	size_t		len;		//!< Length of the raw string used to create the template.
	FR_TOKEN	quote;		//!< What type of quoting was around the raw string.

	bool		auto_converted; //!< Attr-26.9.1 --> Cisco-AVPair

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
			value_data_t		data;			 //!< Value data.
		} literal;

		xlat_exp_t	*xlat;	 //!< pre-parsed xlat_exp_t

#ifdef HAVE_REGEX
		regex_t		*preg;	//!< pre-parsed regex_t
#endif
	} data;
} vp_tmpl_t;

/** @name Field accessors for #TMPL_TYPE_ATTR, #TMPL_TYPE_ATTR_UNDEFINED, #TMPL_TYPE_LIST
 *
 * @{
 */
#define tmpl_request		data.attribute.request
#define tmpl_list		data.attribute.list
#define tmpl_da			data.attribute.da
#define tmpl_unknown		data.attribute.unknown.da
#define tmpl_unknown_name      	data.attribute.unknown.name
#define tmpl_num		data.attribute.num
#define tmpl_tag		data.attribute.tag
/* @} **/

/** @name Field accessors for #TMPL_TYPE_XLAT_STRUCT
 *
 * @{
 */
#define tmpl_xlat		data.xlat
/* @} **/

/** @name Field accessors for #TMPL_TYPE_DATA
 *
 * @{
 */
#define tmpl_data		data.literal
#define tmpl_data_type		data.literal.type
#define tmpl_data_length	data.literal.data.length
#define tmpl_data_value		data.literal.data
/* @} **/

/** @name Field accessors for #TMPL_TYPE_REGEX_STRUCT and #TMPL_TYPE_REGEX
 *
 * @{
 */
#ifdef HAVE_REGEX
#  define tmpl_preg		data.preg	//!< #TMPL_TYPE_REGEX_STRUCT only.
#  define tmpl_iflag		iflag
#  define tmpl_mflag		mflag
#endif
/* @} **/

#ifndef WITH_VERIFY_PTR
#  define VERIFY_TMPL(_x)
#else
#  define VERIFY_TMPL(_x) tmpl_verify(__FILE__,  __LINE__, _x)
void tmpl_verify(char const *file, int line, vp_tmpl_t const *vpt);
#endif

/** Produces an initialiser for static #TMPL_TYPE_LIST type #vp_tmpl_t
 *
 * Example:
 @code{.c}
   static vp_tmpl_t list = tmpl_initialiser_list(CURRENT_REQUEST, PAIR_LIST_REQUEST);
   vp_cursor_t cursor;
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
   value_data_t value;

   RADIUS_LIST_AND_CTX(ctx, head, request, CURRENT_REQUEST, PAIR_LIST_REQUEST);
   if (!list) return -1; // error

   value.strvalue = talloc_strdup(NULL, "my new username");
   value.length = talloc_array_length(value.strvalue) - 1;

   if (fr_pair_update_by_num(ctx, head, PW_USERNAME, 0, TAG_ANY, PW_TYPE_STRING, &value) < 0) return -1; // error
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


#define	PW_TYPE_FROM_PTR(_ptr) \
	_Generic((_ptr), \
		 char **: PW_TYPE_STRING, \
		 char const **: PW_TYPE_STRING, \
		 uint8_t **: PW_TYPE_OCTETS, \
		 uint8_t *: PW_TYPE_BYTE, \
		 uint16_t *: PW_TYPE_SHORT, \
		 uint32_t *: PW_TYPE_INTEGER, \
		 uint64_t *: PW_TYPE_INTEGER64)

/** Expand a tmpl to a C type, allocing a new buffer to hold the string
 *
 * Expands a template using the _out ptr to determinate the cast type.
 *
 * @see _tmpl_to_atype
 */
#define	tmpl_aexpand(_ctx, _out, _request, _vpt, _escape, _escape_ctx) \
	_tmpl_to_atype(_ctx, (void *)(_out), _request, _vpt, _escape, _escape_ctx, PW_TYPE_FROM_PTR(_out))

VALUE_PAIR		**radius_list(REQUEST *request, pair_lists_t list);

RADIUS_PACKET		*radius_packet(REQUEST *request, pair_lists_t list_name);

TALLOC_CTX		*radius_list_ctx(REQUEST *request, pair_lists_t list_name);

size_t			radius_list_name(pair_lists_t *out, char const *name, pair_lists_t default_list);

int			radius_request(REQUEST **request, request_refs_t name);

size_t			radius_request_name(request_refs_t *out, char const *name, request_refs_t unknown);

vp_tmpl_t		*tmpl_init(vp_tmpl_t *vpt, tmpl_type_t type,
				   char const *name, ssize_t len, FR_TOKEN quote);

vp_tmpl_t		*tmpl_alloc(TALLOC_CTX *ctx, tmpl_type_t type, char const *name,
				    ssize_t len, FR_TOKEN quote);

void			tmpl_from_da(vp_tmpl_t *vpt, fr_dict_attr_t const *da, int8_t tag, int num,
				     request_refs_t request, pair_lists_t list);

int			tmpl_afrom_value_data(TALLOC_CTX *ctx, vp_tmpl_t **out, value_data_t *data,
					      PW_TYPE type, fr_dict_attr_t const *enumv, bool steal);

ssize_t			tmpl_from_attr_substr(vp_tmpl_t *vpt, char const *name,
					      request_refs_t request_def, pair_lists_t list_def,
					      bool allow_unknown, bool allow_undefined);

ssize_t			tmpl_from_attr_str(vp_tmpl_t *vpt, char const *name,
					   request_refs_t request_def,
					   pair_lists_t list_def,
					   bool allow_unknown, bool allow_undefined);

ssize_t			tmpl_afrom_attr_substr(TALLOC_CTX *ctx, vp_tmpl_t **out, char const *name,
					       request_refs_t request_def, pair_lists_t list_def,
					       bool allow_unknown, bool allow_undefined);

ssize_t			tmpl_afrom_attr_str(TALLOC_CTX *ctx, vp_tmpl_t **out, char const *name,
					    request_refs_t request_def,
					    pair_lists_t list_def,
					    bool allow_unknown, bool allow_undefined);

ssize_t			tmpl_afrom_str(TALLOC_CTX *ctx, vp_tmpl_t **out, char const *name, size_t inlen,
				       FR_TOKEN type, request_refs_t request_def, pair_lists_t list_def, bool do_escape);

int			tmpl_cast_in_place(vp_tmpl_t *vpt, PW_TYPE type, fr_dict_attr_t const *enumv);

void			tmpl_cast_in_place_str(vp_tmpl_t *vpt);

int			tmpl_cast_to_vp(VALUE_PAIR **out, REQUEST *request,
					vp_tmpl_t const *vpt, fr_dict_attr_t const *cast);

size_t			tmpl_snprint(char *buffer, size_t bufsize, vp_tmpl_t const *vpt,
				    fr_dict_attr_t const *values);

ssize_t			tmpl_expand(char const **out, char *buff, size_t outlen, REQUEST *request,
				    vp_tmpl_t const *vpt, xlat_escape_t escape, void *escape_ctx);

ssize_t			_tmpl_to_atype(TALLOC_CTX *ctx, void *out,
		       		       REQUEST *request,
				       vp_tmpl_t const *vpt,
				       xlat_escape_t escape, void *escape_ctx,
				       PW_TYPE dst_type);

VALUE_PAIR		*tmpl_cursor_init(int *err, vp_cursor_t *cursor, REQUEST *request,
					  vp_tmpl_t const *vpt);

VALUE_PAIR		*tmpl_cursor_next(vp_cursor_t *cursor, vp_tmpl_t const *vpt);

int			tmpl_copy_vps(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request,
				      vp_tmpl_t const *vpt);

int			tmpl_find_vp(VALUE_PAIR **out, REQUEST *request, vp_tmpl_t const *vpt);

int			tmpl_find_or_add_vp(VALUE_PAIR **out, REQUEST *request, vp_tmpl_t const *vpt);

int			tmpl_define_unknown_attr(vp_tmpl_t *vpt);

int			tmpl_define_undefined_attr(vp_tmpl_t *vpt, PW_TYPE type, fr_dict_attr_flags_t const *flags);

#ifdef __cplusplus
}
#endif
#endif	/* _FR_TMPL_H */
