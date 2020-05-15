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

/**
 * $Id$
 *
 * @brief #VALUE_PAIR template functions
 * @file src/lib/server/tmpl.c
 *
 * @ingroup AVP
 *
 * @copyright 2014-2015 The FreeRADIUS server project
 */
RCSID("$Id$")

#define _TMPL_PRIVATE 1

#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/util/misc.h>

#include <ctype.h>

/** Map #tmpl_type_t values to descriptive strings
 */
fr_table_num_sorted_t const tmpl_type_table[] = {
	{ "uninitialised",	TMPL_TYPE_UNINITIALISED		},

	{ "null",		TMPL_TYPE_NULL			},
	{ "data",		TMPL_TYPE_DATA			},

	{ "attr",		TMPL_TYPE_ATTR			},
	{ "list",		TMPL_TYPE_LIST			},

	{ "exec",		TMPL_TYPE_EXEC			},
	{ "xlat",		TMPL_TYPE_XLAT			},

	{ "regex",		TMPL_TYPE_REGEX			},

	{ "literal",		TMPL_TYPE_UNPARSED 		},
	{ "attr-unparsed",	TMPL_TYPE_ATTR_UNPARSED		},
	{ "xlat-unparsed",	TMPL_TYPE_XLAT_UNPARSED		},
	{ "regex-unparsed",	TMPL_TYPE_REGEX_UNPARSED	}
};
size_t tmpl_type_table_len = NUM_ELEMENTS(tmpl_type_table);

/** Map keywords to #pair_list_t values
 */
fr_table_num_ordered_t const pair_list_table[] = {
	{ "request",		PAIR_LIST_REQUEST		},
	{ "reply",		PAIR_LIST_REPLY			},
	{ "control",		PAIR_LIST_CONTROL		},		/* New name should have priority */
	{ "config",		PAIR_LIST_CONTROL		},
	{ "session-state",	PAIR_LIST_STATE			},
};
size_t pair_list_table_len = NUM_ELEMENTS(pair_list_table);

/** Map keywords to #request_ref_t values
 */
fr_table_num_sorted_t const request_ref_table[] = {
	{ "current",		REQUEST_CURRENT			},
	{ "outer",		REQUEST_OUTER			},
	{ "parent",		REQUEST_PARENT			},
	{ "proxy",		REQUEST_PROXY			}
};
size_t request_ref_table_len = NUM_ELEMENTS(request_ref_table);


/** Special attribute reference indexes
 */
static fr_table_num_sorted_t const attr_num_table[] = {
	{ "*",			NUM_ALL				},
	{ "#",			NUM_COUNT			},
	{ "any",		NUM_ANY				},
	{ "n",			NUM_LAST			}
};
static size_t attr_num_table_len = NUM_ELEMENTS(attr_num_table);

/** @name Parse list and request qualifiers to #pair_list_t and #request_ref_t values
 *
 * These functions also resolve #pair_list_t and #request_ref_t values to #REQUEST
 * structs and the head of #VALUE_PAIR lists in those structs.
 *
 * For adding new #VALUE_PAIR to the lists, the #radius_list_ctx function can be used
 * to obtain the appropriate TALLOC_CTX pointer.
 *
 * @note These don't really have much to do with #vp_tmpl_t. They're in the same
 *	file as they're used almost exclusively by the tmpl_* functions.
 * @{
 */

/** Resolve attribute name to a #pair_list_t value.
 *
 * Check the name string for #pair_list_t qualifiers and write a #pair_list_t value
 * for that list to out. This value may be passed to #radius_list, along with the current
 * #REQUEST, to get a pointer to the actual list in the #REQUEST.
 *
 * If we're sure we've definitely found a list qualifier token delimiter (``:``) but the
 * string doesn't match a #radius_list qualifier, return 0 and write #PAIR_LIST_UNKNOWN
 * to out.
 *
 * If we can't find a string that looks like a request qualifier, set out to def, and
 * return 0.
 *
 * @note #radius_list_name should be called before passing a name string that may
 *	contain qualifiers to #fr_dict_attr_by_name.
 *
 * @param[out] out Where to write the list qualifier.
 * @param[in] name String containing list qualifiers to parse.
 * @param[in] def the list to return if no qualifiers were found.
 * @return 0 if no valid list qualifier could be found, else the number of bytes consumed.
 *	The caller may then advanced the name pointer by the value returned, to get the
 *	start of the attribute name (if any).
 *
 * @see pair_list
 * @see radius_list
 */
size_t radius_list_name(pair_list_t *out, char const *name, pair_list_t def)
{
	char const *p = name;
	char const *q;

	/* This should never be a NULL pointer */
	fr_assert(name);

	/*
	 *	Try and determine the end of the token
	 */
	for (q = p; fr_dict_attr_allowed_chars[(uint8_t) *q]; q++);

	switch (*q) {
	/*
	 *	It's a bareword made up entirely of dictionary chars
	 *	check and see if it's a list qualifier, and if it's
	 *	not, return the def and say we couldn't parse
	 *	anything.
	 */
	case '\0':
		*out = fr_table_value_by_substr(pair_list_table, p, (q - p), PAIR_LIST_UNKNOWN);
		if (*out != PAIR_LIST_UNKNOWN) return q - p;
		*out = def;
		return 0;

	/*
	 *	It may be a list qualifier delimiter. Because of tags
	 *	We need to check that it doesn't look like a tag suffix.
	 *	We do this by looking at the chars between ':' and the
	 *	next token delimiter, and seeing if they're all digits.
	 */
	case ':':
	{
		char const *d = q + 1;

		if (isdigit((int) *d)) {
			while (isdigit((int) *d)) d++;

			/*
			 *	Char after the number string
			 *	was a token delimiter, so this is a
			 *	tag, not a list qualifier.
			 */
			if (!fr_dict_attr_allowed_chars[(uint8_t) *d]) {
				*out = def;
				return 0;
			}
		}

		*out = fr_table_value_by_substr(pair_list_table, p, (q - p), PAIR_LIST_UNKNOWN);
		if (*out == PAIR_LIST_UNKNOWN) return 0;

		return (q + 1) - name; /* Consume the list and delimiter */
	}

	default:
		*out = def;
		return 0;
	}
}

/** Resolve attribute #pair_list_t value to an attribute list.
 *
 * The value returned is a pointer to the pointer of the HEAD of a #VALUE_PAIR list in the
 * #REQUEST. If the head of the list changes, the pointer will still be valid.
 *
 * @param[in] request containing the target lists.
 * @param[in] list #pair_list_t value to resolve to #VALUE_PAIR list. Will be NULL if list
 *	name couldn't be resolved.
 * @return a pointer to the HEAD of a list in the #REQUEST.
 *
 * @see tmpl_cursor_init
 */
VALUE_PAIR **radius_list(REQUEST *request, pair_list_t list)
{
	if (!request) return NULL;

	switch (list) {
	/* Don't add default */
	case PAIR_LIST_UNKNOWN:
		break;

	case PAIR_LIST_REQUEST:
		if (!request->packet) return NULL;
		return &request->packet->vps;

	case PAIR_LIST_REPLY:
		if (!request->reply) return NULL;
		return &request->reply->vps;

	case PAIR_LIST_CONTROL:
		return &request->control;

	case PAIR_LIST_STATE:
		return &request->state;
	}

	RWDEBUG2("List \"%s\" is not available",
		fr_table_str_by_value(pair_list_table, list, "<INVALID>"));

	return NULL;
}

/** Resolve a list to the #RADIUS_PACKET holding the HEAD pointer for a #VALUE_PAIR list
 *
 * Returns a pointer to the #RADIUS_PACKET that holds the HEAD pointer of a given list,
 * for the current #REQUEST.
 *
 * @param[in] request To resolve list in.
 * @param[in] list #pair_list_t value to resolve to #RADIUS_PACKET.
 * @return
 *	- #RADIUS_PACKET on success.
 *	- NULL on failure.
 *
 * @see radius_list
 */
RADIUS_PACKET *radius_packet(REQUEST *request, pair_list_t list)
{
	switch (list) {
	/* Don't add default */
	case PAIR_LIST_STATE:
	case PAIR_LIST_CONTROL:
	case PAIR_LIST_UNKNOWN:
		return NULL;

	case PAIR_LIST_REQUEST:
		return request->packet;

	case PAIR_LIST_REPLY:
		return request->reply;
	}

	return NULL;
}

/** Return the correct TALLOC_CTX to alloc #VALUE_PAIR in, for a list
 *
 * Allocating new #VALUE_PAIR in the context of a #REQUEST is usually wrong.
 * #VALUE_PAIR should be allocated in the context of a #RADIUS_PACKET, so that if the
 * #RADIUS_PACKET is freed before the #REQUEST, the associated #VALUE_PAIR lists are
 * freed too.
 *
 * @param[in] request containing the target lists.
 * @param[in] list #pair_list_t value to resolve to TALLOC_CTX.
 * @return
 *	- TALLOC_CTX on success.
 *	- NULL on failure.
 *
 * @see radius_list
 */
TALLOC_CTX *radius_list_ctx(REQUEST *request, pair_list_t list)
{
	if (!request) return NULL;

	switch (list) {
	case PAIR_LIST_REQUEST:
		return request->packet;

	case PAIR_LIST_REPLY:
		return request->reply;

	case PAIR_LIST_CONTROL:
		return request;

	case PAIR_LIST_STATE:
		return request->state_ctx;

	/* Don't add default */
	case PAIR_LIST_UNKNOWN:
		break;
	}

	return NULL;
}

/** Resolve attribute name to a #request_ref_t value.
 *
 * Check the name string for qualifiers that reference a parent #REQUEST.
 *
 * If we find a string that matches a #request_ref_t qualifier, return the number of chars
 * we consumed.
 *
 * If we're sure we've definitely found a list qualifier token delimiter (``*``) but the
 * qualifier doesn't match one of the #request_ref_t qualifiers, return 0 and set out to
 * #REQUEST_UNKNOWN.
 *
 * If we can't find a string that looks like a request qualifier, set out to def, and
 * return 0.
 *
 * @param[out] out The #request_ref_t value the name resolved to (or #REQUEST_UNKNOWN).
 * @param[in] name of attribute.
 * @param[in] def default request ref to return if no request qualifier is present.
 * @return 0 if no valid request qualifier could be found, else the number of bytes consumed.
 *	The caller may then advanced the name pointer by the value returned, to get the
 *	start of the attribute list or attribute name(if any).
 *
 * @see radius_list_name
 * @see request_ref_table
 */
size_t radius_request_name(request_ref_t *out, char const *name, request_ref_t def)
{
	char const *p, *q;

	p = name;
	/*
	 *	Try and determine the end of the token
	 */
	for (q = p; fr_dict_attr_allowed_chars[(uint8_t) *q] && (*q != '.') && (*q != '-'); q++);

	/*
	 *	First token delimiter wasn't a '.'
	 */
	if (*q != '.') {
		*out = def;
		return 0;
	}

	*out = fr_table_value_by_substr(request_ref_table, name, q - p, REQUEST_UNKNOWN);
	if (*out == REQUEST_UNKNOWN) return 0;

	return (q + 1) - p;
}

/** Resolve a #request_ref_t to a #REQUEST.
 *
 * Sometimes #REQUEST structs may be chained to each other, as is the case
 * when internally proxying EAP. This function resolves a #request_ref_t
 * to a #REQUEST higher in the chain than the current #REQUEST.
 *
 * @see radius_list
 * @param[in,out] context #REQUEST to start resolving from, and where to write
 *	a pointer to the resolved #REQUEST back to.
 * @param[in] name (request) to resolve.
 * @return
 *	- 0 if request is valid in this context.
 *	- -1 if request is not valid in this context.
 */
int radius_request(REQUEST **context, request_ref_t name)
{
	REQUEST *request = *context;

	switch (name) {
	case REQUEST_CURRENT:
		return 0;

	case REQUEST_PARENT:	/* for future use in request chaining */
	case REQUEST_OUTER:
		if (!request->parent) {
			return -1;
		}
		*context = request->parent;
		break;

	case REQUEST_PROXY:
		if (!request->proxy) {
			return -1;
		}
		*context = request->proxy;
		break;

	case REQUEST_UNKNOWN:
	default:
		fr_assert(0);
		return -1;
	}

	return 0;
}
/** @} */

/** @name Alloc or initialise #vp_tmpl_t
 *
 * @note Should not usually be called outside of tmpl_* functions, use one of
 *	the tmpl_*from_* functions instead.
 * @{
 */

/** Initialise stack allocated #vp_tmpl_t
 *
 * @note Name is not talloc_strdup'd or memcpy'd so must be available, and must not change
 *	for the lifetime of the #vp_tmpl_t.
 *
 * @param[out] vpt to initialise.
 * @param[in] type to set in the #vp_tmpl_t.
 * @param[in] name of the #vp_tmpl_t.
 * @param[in] len The length of the buffer (or a substring of the buffer) pointed to by name.
 *	If < 0 strlen will be used to determine the length.
 * @param[in] quote The type of quoting around the template name.
 * @return a pointer to the initialised #vp_tmpl_t. The same value as vpt.
 */
vp_tmpl_t *tmpl_init(vp_tmpl_t *vpt, tmpl_type_t type, char const *name, ssize_t len, fr_token_t quote)
{
	fr_assert(vpt);
	fr_assert(type != TMPL_TYPE_UNINITIALISED);

	memset(vpt, 0, sizeof(vp_tmpl_t));
	vpt->type = type;

	if (name) {
		vpt->name = name;
		vpt->len = len < 0 ? strlen(name) :
				     (size_t) len;
		vpt->quote = quote;
	}

	switch (type) {
	case TMPL_TYPE_ATTR:
	case TMPL_ATTR_TYPE_UNPARSED:
	case TMPL_TYPE_LIST:
		fr_dlist_talloc_init(&vpt->data.attribute.ar, vp_tmpl_attr_t, entry);
		fr_dlist_talloc_init(&vpt->data.attribute.rr, vp_tmpl_request_t, entry);
		break;

	default:
		break;
	}

	return vpt;
}

/** Create a new heap allocated #vp_tmpl_t
 *
 * @param[in,out] ctx to allocate in.
 * @param[in] type to set in the #vp_tmpl_t.
 * @param[in] name of the #vp_tmpl_t (will be copied to a new talloc buffer parented
 *	by the #vp_tmpl_t).
 * @param[in] len The length of the buffer (or a substring of the buffer) pointed to by name.
 *	If < 0 strlen will be used to determine the length.
 * @param[in] quote The type of quoting around the template name.
 * @return the newly allocated #vp_tmpl_t.
 */
vp_tmpl_t *tmpl_alloc(TALLOC_CTX *ctx, tmpl_type_t type, char const *name, ssize_t len, fr_token_t quote)
{
	vp_tmpl_t *vpt;

#ifndef HAVE_REGEX
	if ((type == TMPL_TYPE_REGEX_UNPARSED) || (type == TMPL_TYPE_REGEX)) return NULL;
#endif

	vpt = talloc_zero(ctx, vp_tmpl_t);
	if (!vpt) return NULL;
	vpt->type = type;
	if (name) {
		vpt->name = talloc_bstrndup(vpt, name, len < 0 ? strlen(name) : (size_t)len);
		vpt->len = talloc_array_length(vpt->name) - 1;
		vpt->quote = quote;
	}

	/*
	 *	Don't add default here.  We want to warn
	 *	if there may be special initialisation
	 *	needed.
	 */
	switch (type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_ATTR_UNPARSED:
	case TMPL_TYPE_LIST:
		fr_dlist_talloc_init(&vpt->data.attribute.ar, vp_tmpl_attr_t, entry);
		fr_dlist_talloc_init(&vpt->data.attribute.rr, vp_tmpl_request_t, entry);
		break;

	case TMPL_TYPE_NULL:
	case TMPL_TYPE_DATA:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_UNPARSED:
	case TMPL_TYPE_XLAT_UNPARSED:
	case TMPL_TYPE_REGEX_UNPARSED:
		break;

	case TMPL_TYPE_UNINITIALISED:
	case TMPL_TYPE_MAX:
		fr_assert(0);
	}

	return vpt;
}

/** Set a new name for a vp_tmpl_t
 *
 * @param[in] vpt	to set name for.
 * @param[in] quote	Original quoting around the name.
 * @param[in] fmt	string.
 * @param[in] ...	format arguments.
 */
void tmpl_set_name(vp_tmpl_t *vpt, fr_token_t quote, char const *fmt, ...)
{
	va_list		ap;
	char const	*old;

	old = vpt->name;
	if (fmt) {
		va_start(ap, fmt);
		MEM(vpt->name = fr_vasprintf(vpt, fmt, ap));
		va_end(ap);
		vpt->len = talloc_array_length(vpt->name) - 1;
	} else {
		vpt->name = NULL;
		vpt->len = 0;
	}
	talloc_const_free(old);	/* Do this last, so the caller can pass in the current name */
	vpt->quote = quote;
}
/** @} */

/** @name Create new #vp_tmpl_t from a string
 *
 * @{
 */

 /** Allocate a new request reference and add it to the end of the attribute reference list
 *
 */
static vp_tmpl_request_t *tmpl_rr_add(vp_tmpl_t *vpt, request_ref_t request)
{
	vp_tmpl_request_t	*rr;
	TALLOC_CTX		*ctx;

	if (fr_dlist_num_elements(&vpt->data.attribute.rr) == 0) {
		ctx = vpt;
	} else {
		ctx = fr_dlist_tail(&vpt->data.attribute.rr);
	}

	MEM(rr = talloc_zero(ctx, vp_tmpl_request_t));
	rr->request = request;

	fr_dlist_insert_tail(&vpt->data.attribute.rr, rr);

	return rr;
}

/** Allocate a new attribute reference and add it to the end of the attribute reference list
 *
 */
static vp_tmpl_attr_t *tmpl_ar_add(vp_tmpl_t *vpt, vp_tmpl_attr_type_t type)
{
	vp_tmpl_attr_t	*ar;
	TALLOC_CTX	*ctx;

	if (fr_dlist_num_elements(&vpt->data.attribute.ar) == 0) {
		ctx = vpt;
	} else {
		ctx = fr_dlist_tail(&vpt->data.attribute.ar);
	}

	MEM(ar = talloc_zero(ctx, vp_tmpl_attr_t));
	ar->type = type;
	ar->num = NUM_ANY;

	fr_dlist_insert_tail(&vpt->data.attribute.ar, ar);

	return ar;
}

/** Create a #vp_tmpl_t from a #fr_value_box_t
 *
 * @param[in,out] ctx	to allocate #vp_tmpl_t in.
 * @param[out] out	Where to write pointer to new #vp_tmpl_t.
 * @param[in] data	to convert.
 * @param[in] steal	If true, any buffers are moved to the new
 *			ctx instead of being duplicated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_afrom_value_box(TALLOC_CTX *ctx, vp_tmpl_t **out, fr_value_box_t *data, bool steal)
{
	char const *name;
	vp_tmpl_t *vpt;

	vpt = talloc(ctx, vp_tmpl_t);
	name = fr_value_box_asprint(vpt, data, '\0');
	tmpl_init(vpt, TMPL_TYPE_DATA, name, talloc_array_length(name),
		  (data->type == FR_TYPE_STRING) ? T_SINGLE_QUOTED_STRING : T_BARE_WORD);

	if (steal) {
		if (fr_value_box_steal(vpt, tmpl_value(vpt), data) < 0) {
			talloc_free(vpt);
			return -1;
		}
	} else {
		if (fr_value_box_copy(vpt, tmpl_value(vpt), data) < 0) {
			talloc_free(vpt);
			return -1;
		}
	}
	*out = vpt;

	return 0;
}

#ifndef NDEBUG
void tmpl_attr_debug(vp_tmpl_t const *vpt)
{
	vp_tmpl_attr_t		*ar = NULL;
	unsigned int		i = 0;
	char			buffer[sizeof(STRINGIFY(INT16_MAX)) + 1];

	INFO("%s (%p)", vpt->name, vpt);
	while ((ar = fr_dlist_next(&vpt->data.attribute.ar, ar))) {
		snprintf(buffer, sizeof(buffer), "%i", ar->num);

		switch (ar->type) {
		case TMPL_ATTR_TYPE_NORMAL:
		case TMPL_ATTR_TYPE_UNKNOWN:
			if (!ar->da) {
				INFO("\t[%u] null%s%s%s",
				     i,
				     ar->num != NUM_ANY ? "[" : "",
			     	     ar->num != NUM_ANY ? fr_table_str_by_value(attr_num_table, ar->num, buffer) : "",
			     	     ar->num != NUM_ANY ? "]" : "");
				goto next;
			}

			INFO("\t[%u] <%s> %s%s%s%s%s",
			     i,
			     fr_table_str_by_value(fr_value_box_type_table, ar->da->type, "<INVALID>"),
			     ar->da->name,
			     ar->num != NUM_ANY ? "[" : "",
			     ar->num != NUM_ANY ? fr_table_str_by_value(attr_num_table, ar->num, buffer) : "",
			     ar->num != NUM_ANY ? "]" : "",
			     ar->da->flags.is_unknown ? " - is_unknown" : ""
			);
			break;


		case TMPL_ATTR_TYPE_UNPARSED:
			INFO("\t[%u] %s%s%s%s - unparsed",
			     i, ar->unknown.name,
			     ar->num != NUM_ANY ? "[" : "",
			     ar->num != NUM_ANY ? fr_table_str_by_value(attr_num_table, ar->num, buffer) : "",
			     ar->num != NUM_ANY ? "]" : "");
			break;

		default:
			INFO("\t[%u] Bad type %u", i, ar->type);
			break;
		}

	next:
		i++;
	}
}
#endif

/** Copy a list of attribute and request references from one tmpl to another
 *
 */
int tmpl_attr_copy(vp_tmpl_t *dst, vp_tmpl_t const *src)
{
	vp_tmpl_attr_t		*src_ar = NULL, *dst_ar;
	vp_tmpl_request_t	*src_rr = NULL, *dst_rr;

	/*
	 *	Clear any existing attribute references
	 */
	if (fr_dlist_num_elements(&dst->data.attribute.ar) > 0) fr_dlist_talloc_reverse_free(&dst->data.attribute.ar);

	while ((src_ar = fr_dlist_next(&src->data.attribute.ar, src_ar))) {
		dst_ar = tmpl_ar_add(dst, src_ar->type);

		switch (src_ar->type) {
	 	case TMPL_ATTR_TYPE_NORMAL:
	 		dst_ar->ar_da = src_ar->ar_da;
	 		break;

	 	case TMPL_ATTR_TYPE_UNKNOWN:
	 		dst_ar->ar_unknown = fr_dict_unknown_acopy(dst_ar, src_ar->ar_unknown);
	 		break;

	 	case TMPL_ATTR_TYPE_UNPARSED:
	 		dst_ar->ar_unparsed = talloc_bstrdup(dst_ar, src_ar->ar_unparsed);
	 		break;

	 	default:
	 		if (!fr_cond_assert(0)) return -1;
	 	}

	 	dst_ar->ar_tag = src_ar->ar_tag;
	 	dst_ar->ar_num = src_ar->ar_num;
	}

	/*
	 *	Clear any existing request references
	 */
	if (fr_dlist_num_elements(&dst->data.attribute.rr) > 0) fr_dlist_talloc_reverse_free(&dst->data.attribute.rr);

	while ((src_rr = fr_dlist_next(&src->data.attribute.rr, src_rr))) {
		MEM(dst_rr = tmpl_rr_add(dst, src_rr->request));
	}

	/*
	 *	Remove me...
	 */
	dst->data.attribute.list = src->data.attribute.list;

	return 0;
}

/** Convert an abstract da into a concrete one
 *
 * Usually used to fixup combo ip addresses
 */
int tmpl_attr_abstract_to_concrete(vp_tmpl_t *vpt, fr_type_t type)
{
	fr_dict_attr_t const	*abstract;
	fr_dict_attr_t const	*concrete;
	vp_tmpl_attr_t	*ref;

	tmpl_assert_type(tmpl_is_attr(vpt));

	abstract = tmpl_da(vpt);
	if (abstract->type != FR_TYPE_COMBO_IP_ADDR) {
		fr_strerror_printf("Abstract attribute \"%s\" is of incorrect type '%s'", abstract->name,
				   fr_table_str_by_value(fr_value_box_type_table, abstract->type, "<INVALID>"));
		return -1;
	}

	concrete = fr_dict_attr_by_type(abstract, type);
	if (!concrete) {
		fr_strerror_printf("Can't convert abstract type '%s' to concrete type '%s'",
				   fr_table_str_by_value(fr_value_box_type_table, abstract->type, "<INVALID>"),
				   fr_table_str_by_value(fr_value_box_type_table, type, "<INVALID>"));
		return -1;
	}

	ref = fr_dlist_tail(&vpt->data.attribute.ar);
	ref->da = concrete;

	return 0;
}

/** Covert the leaf attribute of a tmpl to a unknown/raw type
 *
 */
void tmpl_attr_to_raw(vp_tmpl_t *vpt)
{
	vp_tmpl_attr_t *ref;

	ref = fr_dlist_tail(&vpt->data.attribute.ar);
	switch (ref->type) {
	case TMPL_ATTR_TYPE_NORMAL:
	{
		char		buffer[256] = "Attr-";
		char		*p = buffer + strlen(buffer);
		char		*end = buffer + sizeof(buffer);
		size_t		len;
		fr_dict_attr_t	*da;

		len = fr_dict_print_attr_oid(NULL, p, end - p, NULL, ref->da);
		p += len;

		ref->da = ref->ar_unknown = da = fr_dict_unknown_acopy(vpt, ref->da);
		ref->ar_unknown->type = FR_TYPE_OCTETS;
		ref->ar_unknown->flags.is_raw = 1;

		talloc_const_free(da->name);
		MEM(da->name = talloc_bstrndup(da, buffer, p - buffer));

		ref->type = TMPL_ATTR_TYPE_UNKNOWN;
	}
		break;

	case TMPL_ATTR_TYPE_UNKNOWN:
		ref->ar_unknown->type = FR_TYPE_OCTETS;
		ref->ar_unknown->flags.is_raw = 1;
		break;

	case TMPL_ATTR_TYPE_UNPARSED:
		fr_assert(0);
		break;
	}
}

/** Replace the current attribute reference
 *
 */
int tmpl_attr_set_da(vp_tmpl_t *vpt, fr_dict_attr_t const *da)
{
	vp_tmpl_attr_t *ref;

	(void)talloc_get_type_abort_const(da, fr_dict_attr_t);

	/*
	 *	Clear any existing references
	 */
	if (fr_dlist_num_elements(&vpt->data.attribute.ar) > 0) {
		fr_dlist_talloc_reverse_free(&vpt->data.attribute.ar);
	}

	/*
	 *	Unknown attributes get copied
	 */
	if (da->flags.is_unknown) {
		ref = tmpl_ar_add(vpt, TMPL_ATTR_TYPE_UNKNOWN);
		ref->da = ref->ar_unknown = fr_dict_unknown_acopy(vpt, da);
	} else {
		ref = tmpl_ar_add(vpt, TMPL_ATTR_TYPE_NORMAL);
		ref->da = da;
	}

	return 0;
}

/** Replace the leaf attribute only
 *
 */
int tmpl_attr_set_leaf_da(vp_tmpl_t *vpt, fr_dict_attr_t const *da)
{
	vp_tmpl_attr_t *ref, *parent = NULL;

	tmpl_assert_type(tmpl_is_attr(vpt));
	(void)talloc_get_type_abort_const(da, fr_dict_attr_t);

	/*
	 *	Clear any existing references
	 */
	if (fr_dlist_num_elements(&vpt->data.attribute.ar) > 0) {
		if (fr_dlist_num_elements(&vpt->data.attribute.ar) > 1) {
			ref = fr_dlist_tail(&vpt->data.attribute.ar);
			parent = fr_dlist_prev(&vpt->data.attribute.ar, ref);

			if (!fr_dict_attr_common_parent(parent->ar_da, da, true)) {
				fr_strerror_printf("New leaf da and old leaf da do not share the same ancestor");
				return -1;
			}
		} else {
			ref = fr_dlist_tail(&vpt->data.attribute.ar);
		}

		/*
		 *	Free old unknown and undefined attributes...
		 */
		talloc_free_children(ref);
	} else {
		ref = tmpl_ar_add(vpt, da->flags.is_unknown ? TMPL_ATTR_TYPE_UNKNOWN : TMPL_ATTR_TYPE_NORMAL);
	}


	/*
	 *	Unknown attributes get copied
	 */
	if (da->flags.is_unknown || (parent && parent->ar_da->flags.is_unknown)) {
		ref->type = TMPL_ATTR_TYPE_UNKNOWN;
		ref->da= ref->ar_unknown = fr_dict_unknown_acopy(vpt, da);
	} else {
		ref->type = TMPL_ATTR_TYPE_NORMAL;
		ref->da = da;
	}

	return 0;
}

void tmpl_attr_set_leaf_num(vp_tmpl_t *vpt, int16_t num)
{
	vp_tmpl_attr_t *ref;

	tmpl_assert_type(tmpl_is_attr(vpt) || tmpl_is_list(vpt) || tmpl_is_attr_unparsed(vpt));

	if (fr_dlist_num_elements(&vpt->data.attribute.ar) == 0) {
		ref = tmpl_ar_add(vpt, TMPL_ATTR_TYPE_UNKNOWN);
	} else {
		ref = fr_dlist_tail(&vpt->data.attribute.ar);
	}

	ref->num = num;
}

/** Rewrite the leaf's instance number
 *
 */
void tmpl_attr_rewrite_leaf_num(vp_tmpl_t *vpt, int16_t from, int16_t to)
{
	vp_tmpl_attr_t *ref = NULL;

	tmpl_assert_type(tmpl_is_attr(vpt) || tmpl_is_list(vpt) || tmpl_is_attr_unparsed(vpt));

	if (fr_dlist_num_elements(&vpt->data.attribute.ar) == 0) return;

	ref = fr_dlist_tail(&vpt->data.attribute.ar);
	if (ref->ar_num == from) ref->ar_num = to;
}

/** Rewrite all instances of an array number
 *
 */
void tmpl_attr_rewrite_num(vp_tmpl_t *vpt, int16_t from, int16_t to)
{
	vp_tmpl_attr_t *ref = NULL;

	tmpl_assert_type(tmpl_is_attr(vpt) || tmpl_is_list(vpt) || tmpl_is_attr_unparsed(vpt));

	while ((ref = fr_dlist_next(&vpt->data.attribute.ar, ref))) if (ref->ar_num == from) ref->ar_num = to;
}

void tmpl_attr_set_leaf_tag(vp_tmpl_t *vpt, int8_t tag)
{
	vp_tmpl_attr_t *ref;

	tmpl_assert_type(tmpl_is_attr(vpt) || tmpl_is_list(vpt) || tmpl_is_attr_unparsed(vpt));

	if (fr_dlist_num_elements(&vpt->data.attribute.ar) == 0) {
		ref = tmpl_ar_add(vpt, TMPL_ATTR_TYPE_NORMAL);
	} else {
		ref = fr_dlist_tail(&vpt->data.attribute.ar);
	}
	ref->tag = tag;
}

void tmpl_attr_set_unparsed(vp_tmpl_t *vpt, char const *name, size_t len)
{
	vp_tmpl_attr_t *ref;

	tmpl_assert_type(tmpl_is_attr_unparsed(vpt));

	/*
	 *	Clear any existing references
	 */
	if (fr_dlist_num_elements(&vpt->data.attribute.ar) > 0) {
		fr_dlist_talloc_reverse_free(&vpt->data.attribute.ar);
	}

	ref = tmpl_ar_add(vpt, TMPL_ATTR_TYPE_UNPARSED);
	ref->ar_unparsed = talloc_strndup(vpt, name, len);

	fr_dlist_insert_tail(&vpt->data.attribute.ar, ref);
}

/** Resolve an undefined attribute using the specified rules
 *
 */
int tmpl_attr_resolve_undefined(vp_tmpl_t *vpt, vp_tmpl_rules_t const *rules)
{
	fr_dict_attr_t const *da;

	fr_assert_msg(tmpl_is_attr_unparsed(vpt), "Expected tmpl type 'undefined-attr', got '%s'",
		      fr_table_str_by_value(tmpl_type_table, vpt->type, "<INVALID>"));

	if (fr_dict_attr_by_qualified_name(&da, rules->dict_def, tmpl_attr_unparsed(vpt), true) != FR_DICT_ATTR_OK) {
		ssize_t		slen;
		fr_dict_attr_t	*unknown_da;

		/*
		 *	Can't find it under it's regular name.  Try an unknown attribute.
		 */
		slen = fr_dict_unknown_afrom_oid_str(vpt, &unknown_da, fr_dict_root(rules->dict_def),
						     tmpl_attr_unparsed(vpt));
		if ((slen <= 0) || (tmpl_attr_unparsed(vpt)[slen] != '\0')) {
			fr_strerror_printf_push("Failed resolving undefined attribute");
			return -1;
		}

		tmpl_attr_set_da(vpt, unknown_da);
		vpt->type = TMPL_TYPE_ATTR;
		return 0;
	}

	tmpl_attr_set_da(vpt, da);
	vpt->type = TMPL_TYPE_ATTR;

	return true;
}

/** Set the request for an attribute ref
 *
 */
void tmpl_attr_set_request(vp_tmpl_t *vpt, request_ref_t request)
{
	fr_assert_msg(tmpl_is_attr(vpt), "Expected tmpl type 'attr', got '%s'",
		      fr_table_str_by_value(tmpl_type_table, vpt->type, "<INVALID>"));

	if (fr_dlist_num_elements(&vpt->data.attribute.rr) > 0) fr_dlist_talloc_reverse_free(&vpt->data.attribute.rr);

	tmpl_rr_add(vpt, request);
}

void tmpl_attr_set_list(vp_tmpl_t *vpt, pair_list_t list)
{
	vpt->data.attribute.list = list;
}

/** Create a new tmpl from a list tmpl and a da
 *
 */
int tmpl_attr_afrom_list(TALLOC_CTX *ctx, vp_tmpl_t **out, vp_tmpl_t const *list,
			 fr_dict_attr_t const *da, int8_t tag)
{
	vp_tmpl_t *vpt;

	char attr[256];
	size_t need, len;

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_ATTR, NULL, 0, T_BARE_WORD));

	/*
	 *	Copies request refs and the list ref
	 */
	tmpl_attr_copy(vpt, list);
	tmpl_attr_set_list(vpt, tmpl_list(list));	/* Remove when lists are attributes */
	tmpl_attr_set_leaf_da(vpt, da);			/* This should add a new da when lists are attributes */
	tmpl_attr_set_leaf_num(vpt, tmpl_num(list));
	tmpl_attr_set_leaf_tag(vpt, tag);

	/*
	 *	We need to rebuild the attribute name, to be the
	 *	one we copied from the source list.
	 */
	len = tmpl_snprint(&need, attr, sizeof(attr), vpt);
	if (need) {
		fr_strerror_printf("Serialized attribute too long.  Must be < "
				   STRINGIFY(sizeof(attr)) " bytes, got %zu bytes", len);
		talloc_free(vpt);
		return -1;
	}

	vpt->len = len;
	vpt->name = talloc_typed_strdup(vpt, attr);
	vpt->quote = T_BARE_WORD;

	*out = vpt;

	return 0;
}

/** Default parser rules
 *
 * Because this is getting to be a ridiculous number of parsing rules
 * to pass in via arguments.
 *
 * Defaults are used if a NULL rules pointer is passed to the parsing function.
 */
static vp_tmpl_rules_t const default_rules = {
	.request_def = REQUEST_CURRENT,
	.list_def = PAIR_LIST_REQUEST
};

/** Parse a string into a TMPL_TYPE_ATTR_* or #TMPL_TYPE_LIST type #vp_tmpl_t
 *
 * @param[in,out] ctx		to allocate #vp_tmpl_t in.
 * @param[out] err		May be NULL.  Provides the exact error that the parser hit
 *				when processing the attribute ref.
 * @param[out] out		Where to write pointer to new #vp_tmpl_t.
 * @param[in] name		of attribute including #request_ref_t and #pair_list_t qualifiers.
 *				If only #request_ref_t #pair_list_t qualifiers are found,
 *				a #TMPL_TYPE_LIST #vp_tmpl_t will be produced.
 * @param[in] name_len		Length of name, or -1 to do strlen()
 * @param[in] rules		Rules which control parsing:
 *				- dict_def		The default dictionary to use if attributes
 *							are unqualified.
 *				- request_def		The default #REQUEST to set if no
 *							#request_ref_t qualifiers are found in name.
 *				- list_def		The default list to set if no #pair_list_t
 *							qualifiers are found in the name.
 *				- allow_unknown		If true attributes in the format accepted by
 *							#fr_dict_unknown_afrom_oid_substr will be allowed,
 *							even if they're not in the main dictionaries.
 *							If an unknown attribute is found a #TMPL_TYPE_ATTR
 *							#vp_tmpl_t will be produced.
 *							If #tmpl_afrom_attr_substr is being called on
 *							startup, the #vp_tmpl_t may be passed to
 *							#tmpl_define_unknown_attr to
 *							add the unknown attribute to the main dictionary.
 *							If the unknown attribute is not added to
 *							the main dictionary the #vp_tmpl_t cannot be used
 *							to search for a #VALUE_PAIR in a #REQUEST.
 *				- allow_undefined	If true, we don't generate a parse error on
 *							unknown attributes. If an unknown attribute is
 *							found a #TMPL_TYPE_ATTR_UNPARSED
 *							#vp_tmpl_t will be produced.
 *				- allow_foreign		If true, allow attribute names to be qualified
 *							with a protocol outside of the passed dict_def.
 *				- disallow_internal	If true, don't allow fallback to internal
 *							attributes.
 *
 * @see REMARKER to produce pretty error markers from the return value.
 *
 * @return
 *	- <= 0 on error (offset as negative integer)
 *	- > 0 on success (number of bytes parsed).
 */
ssize_t tmpl_afrom_attr_substr(TALLOC_CTX *ctx, attr_ref_error_t *err,
			       vp_tmpl_t **out, char const *name, ssize_t name_len, vp_tmpl_rules_t const *rules)
{
	char const		*p, *q;
	long			num;
	ssize_t			slen;
	vp_tmpl_t		*vpt;
	request_ref_t		request_ref;
	pair_list_t		list;
	fr_dict_attr_t const	*da;
	bool			is_raw = false;

	if (!rules) rules = &default_rules;	/* Use the defaults */

	if (err) *err = ATTR_REF_ERROR_NONE;

	if (name_len < 0) name_len = strlen(name);

	p = name;

	if (!*p) {
		fr_strerror_printf("Empty attribute reference");
		if (err) *err = ATTR_REF_ERROR_EMPTY;
		return 0;
	}

	/*
	 *	Check to see if we expect a reference prefix
	 */
	switch (rules->prefix) {
	case VP_ATTR_REF_PREFIX_YES:
		if (*p != '&') {
			fr_strerror_printf("Invalid attribute reference, missing '&' prefix");
			if (err) *err = ATTR_REF_ERROR_BAD_PREFIX;
			return 0;
		}
		p++;
		break;

	case VP_ATTR_REF_PREFIX_NO:
		if (*p == '&') {
			fr_strerror_printf("Attribute references used here must not have a '&' prefix");
			if (err) *err = ATTR_REF_ERROR_BAD_PREFIX;
			return 0;
		}
		break;

	case VP_ATTR_REF_PREFIX_AUTO:
		if (*p == '&') p++;
		break;
	}

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_ATTR, NULL, 0, T_BARE_WORD));

	/*
	 *	Search for a recognised list
	 *
	 *	There may be multiple '.' separated
	 *	components, so don't error out if
	 *	the first one doesn't match a known list.
	 *
	 *	The next check for a list qualifier
	 */
	q = p;
	p += radius_request_name(&request_ref, p, rules->request_def);

	if (rules->disallow_qualifiers && (p != q)) {
		fr_strerror_printf("It is not permitted to specify a request list here.");
		goto invalid_list;
	}
	tmpl_attr_set_request(vpt, request_ref);

	if (tmpl_request(vpt) == REQUEST_UNKNOWN) tmpl_attr_set_request(vpt, rules->request_def);

	/*
	 *	Finding a list qualifier is optional
	 *
	 *	Because the list name parser can
	 *	determine if something was a tag
	 *	or a list, we trust that when it
	 *	returns PAIR_LIST_UNKOWN that
	 *	the input string is invalid.
	 */
	q = p;
	p += radius_list_name(&list, p, rules->list_def);

	if (rules->disallow_qualifiers && (p != q)) {
		fr_strerror_printf("It is not permitted to specify a pair list here.");
	invalid_list:
		if (err) *err = ATTR_REF_ERROR_INVALID_LIST_QUALIFIER;
		slen = -(q - name);
		goto error;
	}

	if (list == PAIR_LIST_UNKNOWN) {
		fr_strerror_printf("Invalid list qualifier");
		if (err) *err = ATTR_REF_ERROR_INVALID_LIST_QUALIFIER;
		slen = -(p - name);
	error:
		talloc_free(vpt);
		return slen;
	}

	tmpl_attr_set_list(vpt, list);
	tmpl_attr_set_leaf_tag(vpt, TAG_NONE);
	tmpl_attr_set_leaf_num(vpt, NUM_ANY);

	/*
	 *	No more input after parsing the list ref, we're done.
	 */
	if (p == (name + name_len)) {
		vpt->type = TMPL_TYPE_LIST;
		goto finish;
	}

	/*
	 *	This may be just a bare list, but it can still
	 *	have instance selectors and tag selectors.
	 */
	switch (*p) {
	case '\0':
		vpt->type = TMPL_TYPE_LIST;
		goto finish;

	case '[':
		vpt->type = TMPL_TYPE_LIST;
		goto do_num;

	default:
		break;
	}

	/*
	 *	Hack to markup attributes as raw
	 */
	if (strncmp(p, "raw.", 4) == 0) {
		is_raw = true;
		p += 4;
	}

	/*
	 *	Look up by name, *including* any Attr-1.2.3.4 which was created when
	 *	parsing the configuration files.
	 */
	slen = fr_dict_attr_by_qualified_name_substr(NULL, &da,
						     rules->dict_def, &FR_SBUFF_TMP(p, strlen(p)),
						     !rules->disallow_internal);
	if (slen <= 0) {
		fr_dict_attr_t *unknown_da;

		fr_strerror();	/* Clear out any existing errors */

		/*
		 *	At this point, the OID *must* be unknown, and
		 *	not previously used.
		 */
		slen = fr_dict_unknown_afrom_oid_substr(vpt, &unknown_da,
						    	fr_dict_root(rules->dict_def), p);
		/*
		 *	Attr-1.2.3.4 is OK.
		 */
		if (slen > 0) {
			vpt->data.attribute.was_oid = true;

			if (!is_raw) {
				da = fr_dict_attr_known(fr_dict_by_da(unknown_da), unknown_da);
				if (da) {
					talloc_free(unknown_da);
					tmpl_attr_set_leaf_da(vpt, da);

					p += slen;

					goto do_num;
				}
			}

			if (!rules->allow_unknown) {
				fr_strerror_printf("Unknown attribute");
				if (err) *err = ATTR_REF_ERROR_UNKNOWN_ATTRIBUTE_NOT_ALLOWED;
				slen = -(p - name);
				goto error;
			}

			/*
			 *	Unknown attributes can be encoded, BUT
			 *	they must be of type "octets".
			 */
			fr_assert(unknown_da->type == FR_TYPE_OCTETS);
			tmpl_attr_set_leaf_da(vpt, unknown_da);
			talloc_free(unknown_da);

			p += slen;

			goto do_num; /* unknown attributes can't have tags */
		}

		/*
		 *	Can't parse it as an attribute, might be a literal string
		 *	let the caller decide.
		 *
		 *	Don't alter the fr_strerror buffer, should contain the parse
		 *	error from fr_dict_unknown_from_suboid.
		 */
		if (!rules->allow_undefined) {
			fr_strerror_printf_push("Undefined attributes not allowed here");
			if (err) *err = ATTR_REF_ERROR_UNDEFINED_ATTRIBUTE_NOT_ALLOWED;
			slen = -(p - name);
			goto error;
		}

		/*
		 *	Copy the name to a field for later resolution
		 */
		vpt->type = TMPL_TYPE_ATTR_UNPARSED;
		for (q = p; (q < (name + name_len)) && ((*q == '.') || fr_dict_attr_allowed_chars[(uint8_t) *q]); q++);
		if (q == p) {
			fr_strerror_printf("Invalid attribute name");
			if (err) *err = ATTR_REF_ERROR_INVALID_ATTRIBUTE_NAME;
			slen = -(p - name);
			goto error;
		}

		if ((q - p) > FR_DICT_ATTR_MAX_NAME_LEN) {
			fr_strerror_printf("Attribute name is too long");
			if (err) *err = ATTR_REF_ERROR_INVALID_ATTRIBUTE_NAME;
			slen = -(p - name);
			goto error;
		}
		tmpl_attr_set_unparsed(vpt, p, q - p);
		p = q;

		goto do_num;
	} else {
		tmpl_attr_set_leaf_da(vpt, da);
	}

	/*
	 *	Attribute location checks
	 */
	{
		fr_dict_t const *found_in = fr_dict_by_da(tmpl_da(vpt));

		/*
		 *	Even if allow_foreign is false, if disallow_internal is not
		 *	true, we still allow foreign
		 */
		if (found_in == fr_dict_internal()) {
			if (rules->disallow_internal) {
				fr_strerror_printf("Internal attributes not allowed here");
				if (err) *err = ATTR_REF_ERROR_INTERNAL_ATTRIBUTE_NOT_ALLOWED;
				slen = -(p - name);
				goto error;
			}
		/*
		 *	Check that the attribute we resolved was from an allowed dictionary
		 */
		}
#if 0
		else if ((rules->dict_def && (found_in != rules->dict_def))) {
		/*
		 *	@fixme - We can't enforce this until we support nested attributes
		 *	where the change of attribute context gives us a new dictionary.
		 *
		 *	i.e.
		 *
		 *	My-Dhcp-In-RADIUS-Attribute.My-DHCP-Attribute
		 *	|                          ||_ DHCP attribute
		 *	|                          |_ Lookup inside linking attribute triggers dictionary change
		 *	|_ RADIUS attribute
		 */

			if (!rules->allow_foreign) {
				fr_strerror_printf("Only attributes from the %s protocol are allowed here",
						   fr_dict_root(rules->dict_def)->name);
				if (err) *err = ATTR_REF_ERROR_FOREIGN_ATTRIBUTES_NOT_ALLOWED;
				slen = -(p - name);
				goto error;
			}
		}
#endif
	}

	/*
	 *	Parsing was successful, so advance the pointer
	 */
	p += slen;

	/*
	 *	If it's an attribute, look for a tag.
	 *
	 *	Note that we check for tags even if the attribute
	 *	isn't tagged.  This lets us print more useful error
	 *	messages.
	 */
	if (*p == ':') {
		char *end;

		if (!tmpl_da(vpt)->flags.has_tag) { /* Lists don't have a da */
			fr_strerror_printf("Attribute '%s' cannot have a tag", tmpl_da(vpt)->name);
			if (err) *err = ATTR_REF_ERROR_TAGGED_ATTRIBUTE_NOT_ALLOWED;
			slen = -(p - name);
			goto error;
		}

		/*
		 *	Allow '*' as an explicit wildcard.
		 */
		if (p[1] == '*') {
			tmpl_attr_set_leaf_tag(vpt, TAG_ANY);
			p += 2;

		} else {
			num = strtol(p + 1, &end, 10);
			if (!TAG_VALID_ZERO(num)) {
				fr_strerror_printf("Invalid tag value '%li' (should be between 0-31)", num);
				if (err) *err = ATTR_REF_ERROR_INVALID_TAG;
				slen = -((p + 1) - name);
				goto error;
			}

			tmpl_attr_set_leaf_tag(vpt, num);
			p = end;
		}

	/*
	 *	The attribute is tagged, but the admin didn't
	 *	specify one.  This means it's likely a
	 *	"search" thingy.. i.e. "find me ANY attribute,
	 *	no matter what the tag".
	 */
	} else if (tmpl_da(vpt)->flags.has_tag) {
		tmpl_attr_set_leaf_tag(vpt, TAG_ANY);
	}

do_num:
	if (*p == '\0') goto finish;

	if (*p == '[') {
		p++;

		switch (*p) {
		case '#':
			tmpl_attr_set_leaf_num(vpt, NUM_COUNT);
			p++;
			break;

		case '*':
			tmpl_attr_set_leaf_num(vpt, NUM_ALL);
			p++;
			break;

		case 'n':
			tmpl_attr_set_leaf_num(vpt, NUM_LAST);
			p++;
			break;

		default:
		{
			char *end;

			num = strtol(p, &end, 10);
			if (p == end) {
				fr_strerror_printf("Array index is not an integer");
				if (err) *err = ATTR_REF_ERROR_INVALID_ARRAY_INDEX;
				slen = -(p - name);
				goto error;
			}

			if ((num > 1000) || (num < 0)) {
				fr_strerror_printf("Invalid array reference '%li' (should be between 0-1000)", num);
				if (err) *err = ATTR_REF_ERROR_INVALID_ARRAY_INDEX;
				slen = -(p - name);
				goto error;
			}
			tmpl_attr_set_leaf_num(vpt, num);
			p = end;
		}
			break;
		}

		if (*p != ']') {
			fr_strerror_printf("No closing ']' for array index");
			if (err) *err = ATTR_REF_ERROR_INVALID_ARRAY_INDEX;
			slen = -(p - name);
			goto error;
		}
		p++;
	}

finish:
	vpt->name = talloc_strndup(vpt, name, p - name);
	vpt->len = p - name;
	vpt->quote = T_BARE_WORD;

	TMPL_VERIFY(vpt);	/* Because we want to ensure we produced something sane */

	*out = vpt;

	return vpt->len;
}

/** Parse a string into a TMPL_TYPE_ATTR_* or #TMPL_TYPE_LIST type #vp_tmpl_t
 *
 * @param[in,out] ctx		to allocate #vp_tmpl_t in.
 * @param[out] err		May be NULL.  Provides the exact error that the parser hit
 *				when processing the attribute ref.
 * @param[out] out		Where to write pointer to new #vp_tmpl_t.
 * @param[in] name		of attribute including #request_ref_t and #pair_list_t qualifiers.
 *				If only #request_ref_t #pair_list_t qualifiers are found,
 *				a #TMPL_TYPE_LIST #vp_tmpl_t will be produced.
 * @param[in] rules		Rules which control parsing.  See tmpl_afrom_attr_substr() for details.
 *
 * @note Unlike #tmpl_afrom_attr_substr this function will error out if the entire
 *	name string isn't parsed.
 */
ssize_t tmpl_afrom_attr_str(TALLOC_CTX *ctx, attr_ref_error_t *err,
			    vp_tmpl_t **out, char const *name, vp_tmpl_rules_t const *rules)
{
	ssize_t slen, name_len;

	if (!rules) rules = &default_rules;	/* Use the defaults */

	name_len = strlen(name);
	slen = tmpl_afrom_attr_substr(ctx, err, out, name, name_len, rules);
	if (slen <= 0) return slen;

	if (!fr_cond_assert(*out)) return -1;

	if (slen != name_len) {
		/* This looks wrong, but it produces meaningful errors for unknown attrs with tags */
		fr_strerror_printf("Unexpected text after %s", fr_table_str_by_value(tmpl_type_table, (*out)->type, "<INVALID>"));
		return -slen;
	}

	TMPL_VERIFY(*out);

	return slen;
}

/** Convert an arbitrary string into a #vp_tmpl_t
 *
 * @note Unlike #tmpl_afrom_attr_str return code 0 doesn't necessarily indicate failure,
 *	may just mean a 0 length string was parsed.
 *
 * @note xlats and regexes are left uncompiled.  This is to support the two pass parsing
 *	done by the modcall code.  Compilation on pass1 of that code could fail, as
 *	attributes or xlat functions registered by modules may not be available (yet).
 *
 * @note For details of attribute parsing see #tmpl_afrom_attr_substr.
 *
 * @param[in,out] ctx		To allocate #vp_tmpl_t in.
 * @param[out] out		Where to write the pointer to the new #vp_tmpl_t.
 * @param[in] in		String to convert to a #vp_tmpl_t.
 * @param[in] inlen		length of string to convert.
 * @param[in] type		of quoting around value. May be one of:
 *				- #T_BARE_WORD - If string begins with ``&``
 *				  produces #TMPL_TYPE_ATTR,
 *	  			  #TMPL_TYPE_ATTR_UNPARSED, #TMPL_TYPE_LIST or error.
 *	  			  If string does not begin with ``&`` produces
 *				  #TMPL_TYPE_UNPARSED, #TMPL_TYPE_ATTR or #TMPL_TYPE_LIST.
 *				- #T_SINGLE_QUOTED_STRING - Produces #TMPL_TYPE_UNPARSED
 *				- #T_DOUBLE_QUOTED_STRING - Produces #TMPL_TYPE_XLAT_UNPARSED or
 *				  #TMPL_TYPE_UNPARSED (if string doesn't contain ``%``).
 *				- #T_BACK_QUOTED_STRING - Produces #TMPL_TYPE_EXEC
 *				- #T_OP_REG_EQ - Produces #TMPL_TYPE_REGEX_UNPARSED
 * @param[in] rules		Parsing rules for attribute references.
 * @param[in] do_unescape	whether or not we should do unescaping.
 *				Should be false if the caller already did it.
 * @return
 *	- <= 0 on error (offset as negative integer)
 *	- > 0 on success (number of bytes parsed).
 *
 * @see REMARKER to produce pretty error markers from the return value.
 *
 * @see tmpl_afrom_attr_substr
 */
ssize_t tmpl_afrom_str(TALLOC_CTX *ctx, vp_tmpl_t **out,
		       char const *in, size_t inlen, fr_token_t type, vp_tmpl_rules_t const *rules, bool do_unescape)
{
	bool		do_xlat;
	char		quote;
	char const	*p;
	ssize_t		slen;
	fr_type_t	data_type = FR_TYPE_STRING;
	vp_tmpl_t	*vpt = NULL;
	fr_value_box_t	data;

	if (!rules) rules = &default_rules;	/* Use the defaults */

	switch (type) {
	case T_BARE_WORD:
	{
		vp_tmpl_rules_t	mrules;

		memcpy(&mrules, rules, sizeof(mrules));

		/*
		 *  No attribute names start with 0x, and if they did, the user
		 *  can just use the explicit & prefix.
		 */
		if ((in[0] == '0') && (tolower(in[1]) == 'x')) {
			size_t binlen, len;

			/*
			 *  Hex strings must contain even number of characters
			 */
			if (inlen & 0x01) {
				fr_strerror_printf("Hex string not even length");
				return -inlen;
			}

			if (inlen <= 2) {
				fr_strerror_printf("Zero length hex string is invalid");
				return -inlen;
			}

			binlen = (inlen - 2) / 2;

			vpt = tmpl_alloc(ctx, TMPL_TYPE_DATA, in, inlen, type);
			tmpl_value(vpt)->datum.ptr = talloc_array(vpt, uint8_t, binlen);
			tmpl_value_length_set(vpt, binlen);
			tmpl_value_type_set(vpt, FR_TYPE_OCTETS);

			len = fr_hex2bin(tmpl_value(vpt)->datum.ptr, binlen, in + 2, inlen - 2);
			if (len != binlen) {
				fr_strerror_printf("Hex string contains non-hex char");
				talloc_free(vpt);
				return -(len + 2);
			}
			slen = len;
			break;
		}

		/*
		 *	If we can parse it as an attribute, it's an attribute.
		 *	Otherwise, treat it as a literal.
		 */
		quote = '\0';

		mrules.allow_undefined = (in[0] == '&');

		/*
		 *	This doesn't take a length, but it does return
		 *	how many "good" bytes it parsed.  If we didn't
		 *	parse the whole string, then it's an error.
		 *	We can't define a template with garbage after
		 *	the attribute name.
		 */
		slen = tmpl_afrom_attr_substr(ctx, NULL, &vpt, in, inlen, &mrules);
		if (mrules.allow_undefined && (slen <= 0)) return slen;
		if (slen > 0) {
			if ((size_t) slen < inlen) {
				fr_strerror_printf("Unexpected text after attribute name");
				talloc_free(vpt);
				return -slen;
			}
			break;
		}
	}
		goto parse;

	case T_SINGLE_QUOTED_STRING:
		quote = '\'';

	parse:
		if (do_unescape) {
			if (fr_value_box_from_str(ctx, &data, &data_type, NULL,
						  in, inlen, quote, false) < 0) return 0;

			vpt = tmpl_alloc(ctx, TMPL_TYPE_UNPARSED, data.vb_strvalue,
					 talloc_array_length(data.vb_strvalue) - 1, type);
			talloc_free(data.datum.ptr);
		} else {
			vpt = tmpl_alloc(ctx, TMPL_TYPE_UNPARSED, in, inlen, type);
		}
		slen = vpt->len;
		break;

	case T_DOUBLE_QUOTED_STRING:
		do_xlat = false;

		p = in;
		while (*p) {
			if (do_unescape) { /* otherwise \ is just another character */
				if (*p == '\\') {
					if (!p[1]) break;
					p += 2;
					continue;
				}
			}

			if (*p == '%') {
				do_xlat = true;
				break;
			}

			p++;
		}

		/*
		 *	If the double quoted string needs to be
		 *	expanded at run time, make it an xlat
		 *	expansion.  Otherwise, convert it to be a
		 *	literal.
		 */
		if (do_unescape) {
			if (fr_value_box_from_str(ctx, &data, &data_type, NULL, in,
						  inlen, fr_token_quote[type], false) < 0) return -1;
			if (do_xlat) {
				vpt = tmpl_alloc(ctx, TMPL_TYPE_XLAT_UNPARSED, data.vb_strvalue,
						 talloc_array_length(data.vb_strvalue) - 1, type);
			} else {
				vpt = tmpl_alloc(ctx, TMPL_TYPE_UNPARSED, data.vb_strvalue,
						 talloc_array_length(data.vb_strvalue) - 1, type);
				vpt->quote = T_DOUBLE_QUOTED_STRING;
			}
			talloc_free(data.datum.ptr);
		} else {
			if (do_xlat) {
				vpt = tmpl_alloc(ctx, TMPL_TYPE_XLAT_UNPARSED, in, inlen, type);
			} else {
				vpt = tmpl_alloc(ctx, TMPL_TYPE_UNPARSED, in, inlen, type);
				vpt->quote = T_DOUBLE_QUOTED_STRING;
			}
		}
		slen = vpt->len;
		break;

	case T_BACK_QUOTED_STRING:
		if (do_unescape) {
			if (fr_value_box_from_str(ctx, &data, &data_type, NULL, in,
						  inlen, fr_token_quote[type], false) < 0) return -1;

			vpt = tmpl_alloc(ctx, TMPL_TYPE_EXEC, data.vb_strvalue,
					 talloc_array_length(data.vb_strvalue) - 1, type);
			talloc_free(data.datum.ptr);
		} else {
			vpt = tmpl_alloc(ctx, TMPL_TYPE_EXEC, in, inlen, type);
		}

		/*
		 *	Ensure that we pre-parse the exec string.
		 *	This allows us to catch parse errors as early
		 *	as possible.
		 */
		slen = xlat_tokenize_argv(vpt, &tmpl_xlat(vpt), vpt->name, talloc_array_length(vpt->name) - 1, rules);
		if (slen <= 0) {
			talloc_free(vpt);
			return slen;
		}

		slen = vpt->len;
		break;

	case T_OP_REG_EQ: /* hack */
		vpt = tmpl_alloc(ctx, TMPL_TYPE_REGEX_UNPARSED, in, inlen, T_BARE_WORD);
		slen = vpt->len;
		break;

	default:
		fr_assert(0);
		return 0;	/* 0 is an error here too */
	}

	if (!vpt) return 0;

	vpt->quote = type;

	fr_assert(slen >= 0);

	TMPL_VERIFY(vpt);
	*out = vpt;

	return slen;
}
/** @} */

/** @name Cast or convert #vp_tmpl_t
 *
 * #tmpl_cast_in_place can be used to convert #TMPL_TYPE_UNPARSED to a #TMPL_TYPE_DATA of a
 *  specified #fr_type_t.
 *
 * #tmpl_cast_in_place_str does the same as #tmpl_cast_in_place, but will always convert to
 * #fr_type_t #FR_TYPE_STRING.
 *
 * #tmpl_cast_to_vp does the same as #tmpl_cast_in_place, but outputs a #VALUE_PAIR.
 *
 * #tmpl_define_unknown_attr converts a #TMPL_TYPE_ATTR with an unknown #fr_dict_attr_t to a
 * #TMPL_TYPE_ATTR with a known #fr_dict_attr_t, by adding the unknown #fr_dict_attr_t to the main
 * dictionary, and updating the ``tmpl_da`` pointer.
 * @{
 */

/** Convert #vp_tmpl_t of type #TMPL_TYPE_UNPARSED or #TMPL_TYPE_DATA to #TMPL_TYPE_DATA of type specified
 *
 * @note Conversion is done in place.
 * @note Irrespective of whether the #vp_tmpl_t was #TMPL_TYPE_UNPARSED or #TMPL_TYPE_DATA,
 *	on successful cast it will be #TMPL_TYPE_DATA.
 *
 * @param[in,out] vpt	The template to modify. Must be of type #TMPL_TYPE_UNPARSED
 *			or #TMPL_TYPE_DATA.
 * @param[in] type	to cast to.
 * @param[in] enumv	Enumerated dictionary values associated with a #fr_dict_attr_t.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_cast_in_place(vp_tmpl_t *vpt, fr_type_t type, fr_dict_attr_t const *enumv)
{
	TMPL_VERIFY(vpt);

	fr_assert(vpt != NULL);
	fr_assert(tmpl_is_unparsed(vpt) || tmpl_is_data(vpt));

	switch (vpt->type) {
	case TMPL_TYPE_UNPARSED:
	{
		fr_type_t	concrete_type = type;

		/*
		 *	Why do we pass a pointer to a temporary type
		 *	variable? Goddamn WiMAX.
		 */
		if (fr_value_box_from_str(vpt, &vpt->data.literal, &concrete_type,
					  enumv, vpt->name, vpt->len, '\0', false) < 0) return -1;
		tmpl_value_type_set(vpt, concrete_type);
		vpt->type = TMPL_TYPE_DATA;
	}
		break;

	case TMPL_TYPE_DATA:
	{
		fr_value_box_t new;

		if (type == tmpl_value_type(vpt)) return 0;	/* noop */

		if (fr_value_box_cast(vpt, &new, type, enumv, &vpt->data.literal) < 0) return -1;

		fr_value_box_clear(&vpt->data.literal);
		fr_value_box_copy(vpt, &vpt->data.literal, &new);
	}
		break;

	default:
		fr_assert(0);
	}

	TMPL_VERIFY(vpt);

	return 0;
}

/** Convert #vp_tmpl_t of type #TMPL_TYPE_UNPARSED to #TMPL_TYPE_DATA of type #FR_TYPE_STRING
 *
 * @note Conversion is done in place.
 *
 * @param[in,out] vpt The template to modify. Must be of type #TMPL_TYPE_UNPARSED.
 */
void tmpl_cast_in_place_str(vp_tmpl_t *vpt)
{
	fr_assert(vpt != NULL);
	fr_assert(tmpl_is_unparsed(vpt));

	tmpl_value(vpt)->vb_strvalue = talloc_typed_strdup(vpt, vpt->name);
	fr_assert(tmpl_value(vpt)->vb_strvalue != NULL);

	vpt->type = TMPL_TYPE_DATA;
	tmpl_value_type_set(vpt, FR_TYPE_STRING);
	tmpl_value_length_set(vpt, talloc_array_length(tmpl_value(vpt)->vb_strvalue) - 1);
}

/** Expand a #vp_tmpl_t to a string, parse it as an attribute of type cast, create a #VALUE_PAIR from the result
 *
 * @note Like #tmpl_expand, but produces a #VALUE_PAIR.
 *
 * @param out Where to write pointer to the new #VALUE_PAIR.
 * @param request The current #REQUEST.
 * @param vpt to cast. Must be one of the following types:
 *	- #TMPL_TYPE_UNPARSED
 *	- #TMPL_TYPE_EXEC
 *	- #TMPL_TYPE_XLAT_UNPARSED
 *	- #TMPL_TYPE_XLAT
 *	- #TMPL_TYPE_ATTR
 *	- #TMPL_TYPE_DATA
 * @param cast type of #VALUE_PAIR to create.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_cast_to_vp(VALUE_PAIR **out, REQUEST *request,
		    vp_tmpl_t const *vpt, fr_dict_attr_t const *cast)
{
	int		rcode;
	VALUE_PAIR	*vp;
	char		*p;

	TMPL_VERIFY(vpt);

	*out = NULL;

	MEM(vp = fr_pair_afrom_da(request, cast));
	if (tmpl_is_data(vpt)) {
		VP_VERIFY(vp);
		fr_assert(vp->vp_type == tmpl_value_type(vpt));

		fr_value_box_copy(vp, &vp->data, tmpl_value(vpt));
		*out = vp;
		return 0;
	}

	rcode = tmpl_aexpand(vp, &p, request, vpt, NULL, NULL);
	if (rcode < 0) {
		fr_pair_list_free(&vp);
		return rcode;
	}

	/*
	 *	New escapes: strings are in binary form.
	 */
	if (vp->vp_type == FR_TYPE_STRING) {
		fr_pair_value_strcpy(vp, p);
	} else if (fr_pair_value_from_str(vp, p, rcode, '\0', false) < 0) {
		talloc_free(p);
		fr_pair_list_free(&vp);
		return -1;
	}

	*out = vp;
	return 0;
}

/** Add an unknown #fr_dict_attr_t specified by a #vp_tmpl_t to the main dictionary
 *
 * @param vpt to add. ``tmpl_da`` pointer will be updated to point to the
 *	#fr_dict_attr_t inserted into the dictionary.
 * @return
 *	- 1 noop (did nothing) - Not possible to convert tmpl.
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_define_unknown_attr(vp_tmpl_t *vpt)
{
	fr_dict_attr_t const *da;

	if (!vpt) return 1;

	TMPL_VERIFY(vpt);

	if (!tmpl_is_attr(vpt)) return 1;

	if (!tmpl_da(vpt)->flags.is_unknown) return 1;

	da = fr_dict_unknown_add(fr_dict_unconst(fr_dict_internal()), tmpl_da(vpt));
	if (!da) return -1;
	tmpl_attr_set_leaf_da(vpt, da);

	return 0;
}

/** Add an undefined #fr_dict_attr_t specified by a #vp_tmpl_t to the main dictionary
 *
 * @note fr_dict_attr_add will not return an error if the attribute already exists
 *	meaning that multiple #vp_tmpl_t specifying the same attribute can be
 *	passed to this function to be fixed up, so long as the type and flags
 *	are identical.
 *
 * @param[in] dict_def	Default dictionary to use if none is
 *			specified by the tmpl_attr_unparsed.
 * @param[in] vpt	specifying undefined attribute to add.
 *			``tmpl_da`` pointer will be updated to
 *			point to the #fr_dict_attr_t inserted
 *			into the dictionary. Lists and requests
 *			will be preserved.
 * @param[in] type	to define undefined attribute as.
 * @param[in] flags	to define undefined attribute with.
 * @return
 *	- 1 noop (did nothing) - Not possible to convert tmpl.
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_define_undefined_attr(fr_dict_t *dict_def, vp_tmpl_t *vpt,
			       fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	fr_dict_attr_t const *da;

	if (!vpt) return -1;

	TMPL_VERIFY(vpt);

	if (!tmpl_is_attr_unparsed(vpt)) return 1;

	if (fr_dict_attr_add(dict_def, fr_dict_root(fr_dict_internal()), tmpl_attr_unparsed(vpt), -1, type, flags) < 0) {
		return -1;
	}
	da = fr_dict_attr_by_name(dict_def, tmpl_attr_unparsed(vpt));
	if (!da) return -1;

	if (type != da->type) {
		fr_strerror_printf("Attribute %s of type %s already defined with type %s",
				   da->name, fr_table_str_by_value(fr_value_box_type_table, type, "<UNKNOWN>"),
				   fr_table_str_by_value(fr_value_box_type_table, da->type, "<UNKNOWN>"));
		return -1;
	}

	if (memcmp(flags, &da->flags, sizeof(*flags)) != 0) {
		fr_strerror_printf("Attribute %s already defined with different flags", da->name);
		return -1;
	}

	tmpl_attr_set_da(vpt, da);
	vpt->type = TMPL_TYPE_ATTR;

	return 0;
}
/** @} */

/** @name Resolve a #vp_tmpl_t outputting the result in various formats
 *
 * @{
 */

/** Expand a #vp_tmpl_t to a string writing the result to a buffer
 *
 * The intended use of #tmpl_expand and #tmpl_aexpand is for modules to easily convert a #vp_tmpl_t
 * provided by the conf parser, into a usable value.
 * The value returned should be raw and undoctored for #FR_TYPE_STRING and #FR_TYPE_OCTETS types,
 * and the printable (string) version of the data for all others.
 *
 * Depending what arguments are passed, either copies the value to buff, or writes a pointer
 * to a string buffer to out. This allows the most efficient access to the value resolved by
 * the #vp_tmpl_t, avoiding unecessary string copies.
 *
 * @note This function is used where raw string values are needed, which may mean the string
 *	returned may be binary data or contain unprintable chars. #fr_snprint or #fr_asprint
 *	should be used before using these values in debug statements. #is_printable can be used to
 *	check if the string only contains printable chars.
 *
 * @param[out] out		Where to write a pointer to the string buffer. On return may
 *				point to buff if buff was used to store the value. Otherwise will
 *				point to a #fr_value_box_t buffer, or the name of the template.
 *				Must not be NULL.
 * @param[out] buff		Expansion buffer, may be NULL except for the following types:
 *				- #TMPL_TYPE_EXEC
 *				- #TMPL_TYPE_XLAT_UNPARSED
 *				- #TMPL_TYPE_XLAT
 * @param[in] bufflen		Length of expansion buffer. Must be >= 2.
 * @param[in] request		Current request.
 * @param[in] vpt		to expand. Must be one of the following types:
 *				- #TMPL_TYPE_UNPARSED
 *				- #TMPL_TYPE_EXEC
 *				- #TMPL_TYPE_XLAT_UNPARSED
 *				- #TMPL_TYPE_XLAT
 *				- #TMPL_TYPE_ATTR
 *				- #TMPL_TYPE_DATA
 * @param[in] escape		xlat escape function (only used for xlat types).
 * @param[in] escape_ctx	xlat escape function data.
 * @param dst_type		FR_TYPE_* matching out pointer.  @see tmpl_expand.
 * @return
 *	- -1 on failure.
 *	- The length of data written to buff, or pointed to by out.
 */
ssize_t _tmpl_to_type(void *out,
		      uint8_t *buff, size_t bufflen,
		      REQUEST *request,
		      vp_tmpl_t const *vpt,
		      xlat_escape_t escape, void const *escape_ctx,
		      fr_type_t dst_type)
{
	fr_value_box_t		value_to_cast;
	fr_value_box_t		value_from_cast;
	fr_value_box_t const	*to_cast = &value_to_cast;
	fr_value_box_t const	*from_cast = &value_from_cast;

	VALUE_PAIR		*vp = NULL;

	fr_type_t		src_type = FR_TYPE_STRING;

	ssize_t			slen = -1;	/* quiet compiler */

	TMPL_VERIFY(vpt);

	fr_assert(!tmpl_is_list(vpt));
	fr_assert(!buff || (bufflen >= 2));

	memset(&value_to_cast, 0, sizeof(value_to_cast));
	memset(&value_from_cast, 0, sizeof(value_from_cast));

	switch (vpt->type) {
	case TMPL_TYPE_UNPARSED:
		RDEBUG4("EXPAND TMPL UNPARSED");
		value_to_cast.vb_strvalue = vpt->name;
		value_to_cast.datum.length = vpt->len;
		break;

	case TMPL_TYPE_EXEC:
	{
		RDEBUG4("EXPAND TMPL EXEC");
		if (!buff) {
			fr_strerror_printf("Missing expansion buffer for EXEC");
			return -1;
		}

		if (radius_exec_program(request, (char *)buff, bufflen, NULL, request, vpt->name, NULL,
					true, false, fr_time_delta_from_sec(EXEC_TIMEOUT)) != 0) return -1;
		value_to_cast.vb_strvalue = (char *)buff;
		value_to_cast.datum.length = strlen((char *)buff);
	}
		break;

	case TMPL_TYPE_XLAT_UNPARSED:
		RDEBUG4("EXPAND TMPL XLAT");
		if (!buff) {
			fr_strerror_printf("Missing expansion buffer for XLAT");
			return -1;
		}
		/* Error in expansion, this is distinct from zero length expansion */
		slen = xlat_eval((char *)buff, bufflen, request, vpt->name, escape, escape_ctx);
		if (slen < 0) return slen;

		/*
		 *	Undo any of the escaping that was done by the
		 *	xlat expansion function.
		 *
		 *	@fixme We need a way of signalling xlat not to escape things.
		 */
		value_to_cast.datum.length = fr_value_str_unescape(buff, (char *)buff, slen, '"');
		value_to_cast.vb_strvalue = (char *)buff;
		break;

	case TMPL_TYPE_XLAT:
		RDEBUG4("EXPAND TMPL XLAT STRUCT");
		RDEBUG2("EXPAND %s", vpt->name); /* xlat_struct doesn't do this */
		if (!buff) {
			fr_strerror_printf("Missing expansion buffer for XLAT_STRUCT");
			return -1;
		}
		/* Error in expansion, this is distinct from zero length expansion */
		slen = xlat_eval_compiled((char *)buff, bufflen, request, tmpl_xlat(vpt), escape, escape_ctx);
		if (slen < 0) return slen;

		RDEBUG2("   --> %s", (char *)buff);	/* Print pre-unescaping (so it's escaped) */

		/*
		 *	Undo any of the escaping that was done by the
		 *	xlat expansion function.
		 *
		 *	@fixme We need a way of signalling xlat not to escape things.
		 */
		value_to_cast.datum.length = fr_value_str_unescape(buff, (char *)buff, slen, '"');
		value_to_cast.vb_strvalue = (char *)buff;

		break;

	case TMPL_TYPE_ATTR:
	{
		int ret;

		RDEBUG4("EXPAND TMPL ATTR");
		ret = tmpl_find_vp(&vp, request, vpt);
		if (ret < 0) return -2;

		to_cast = &vp->data;
		src_type = vp->da->type;
	}
		break;

	case TMPL_TYPE_DATA:
	{
		int ret;

		RDEBUG4("EXPAND TMPL DATA");
		ret = tmpl_find_vp(&vp, request, vpt);
		if (ret < 0) return -2;

		to_cast = tmpl_value(vpt);
		src_type = tmpl_value_type(vpt);
	}
		break;

	/*
	 *	We should never be expanding these.
	 */
	case TMPL_TYPE_UNINITIALISED:
	case TMPL_TYPE_NULL:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_ATTR_UNPARSED:
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_REGEX_UNPARSED:
	case TMPL_TYPE_MAX:
		fr_assert(0);
		return -1;
	}

	/*
	 *	Deal with casts.
	 */
	switch (src_type) {
	case FR_TYPE_STRING:
		switch (dst_type) {
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			from_cast = to_cast;
			break;

		default:
			break;
		}
		break;

	case FR_TYPE_OCTETS:
		switch (dst_type) {
		/*
		 *	Need to use the expansion buffer for this conversion as
		 *	we need to add a \0 terminator.
		 */
		case FR_TYPE_STRING:
			if (!buff) {
				fr_strerror_printf("Missing expansion buffer for octet->string cast");
				return -1;
			}
			if (bufflen <= to_cast->datum.length) {
				fr_strerror_printf("Expansion buffer too small.  "
						   "Have %zu bytes, need %zu bytes", bufflen,
						   to_cast->datum.length + 1);
				return -1;
			}
			memcpy(buff, to_cast->vb_octets, to_cast->datum.length);
			buff[to_cast->datum.length] = '\0';
			value_from_cast.vb_strvalue = (char *)buff;
			value_from_cast.datum.length = to_cast->datum.length;
			break;

		/*
		 *	Just copy the pointer.  Length does not include \0.
		 */
		case FR_TYPE_OCTETS:
			from_cast = to_cast;
			break;

		default:
			break;
		}
		break;

	default:
	{
		int		ret;
		TALLOC_CTX	*ctx;

		/*
		 *	Same type, just set from_cast to to_cast and copy the value.
		 */
		if (src_type == dst_type) {
			from_cast = to_cast;
			break;
		}

		MEM(ctx = talloc_new(request));

		from_cast = &value_from_cast;

		/*
		 *	Data type conversion...
		 */
		ret = fr_value_box_cast(ctx, &value_from_cast, dst_type, NULL, to_cast);
		if (ret < 0) goto error;


		/*
		 *	For the dynamic types we need to copy the output
		 *	to the buffer.  Really we need a version of fr_value_box_cast
		 *	that works with buffers, but it's not a high priority...
		 */
		switch (dst_type) {
		case FR_TYPE_STRING:
			if (!buff) {
				fr_strerror_printf("Missing expansion buffer to store cast output");
			error:
				talloc_free(ctx);
				return -1;
			}
			if (from_cast->datum.length >= bufflen) {
				fr_strerror_printf("Expansion buffer too small.  "
						   "Have %zu bytes, need %zu bytes", bufflen,
						   from_cast->datum.length + 1);
				goto error;
			}
			memcpy(buff, from_cast->vb_strvalue, from_cast->datum.length);
			buff[from_cast->datum.length] = '\0';
			value_from_cast.vb_strvalue = (char *)buff;
			break;

		case FR_TYPE_OCTETS:
			if (!buff) {
				fr_strerror_printf("Missing expansion buffer to store cast output");
				goto error;
			}
			if (from_cast->datum.length > bufflen) {
				fr_strerror_printf("Expansion buffer too small.  "
						   "Have %zu bytes, need %zu bytes", bufflen, from_cast->datum.length);
				goto error;
			}
			memcpy(buff, from_cast->vb_octets, from_cast->datum.length);
			value_from_cast.vb_octets = buff;
			break;

		default:
			break;
		}

		talloc_free(ctx);	/* Free any dynamically allocated memory from the cast */
	}
	}

	RDEBUG4("Copying %zu bytes to %p from offset %zu",
		fr_value_box_field_sizes[dst_type], *((void **)out), fr_value_box_offsets[dst_type]);

	memcpy(out, ((uint8_t const *) from_cast) + fr_value_box_offsets[dst_type], fr_value_box_field_sizes[dst_type]);

	return from_cast->datum.length;
}

/** Expand a template to a string, allocing a new buffer to hold the string
 *
 * The intended use of #tmpl_expand and #tmpl_aexpand is for modules to easily convert a #vp_tmpl_t
 * provided by the conf parser, into a usable value.
 * The value returned should be raw and undoctored for #FR_TYPE_STRING and #FR_TYPE_OCTETS types,
 * and the printable (string) version of the data for all others.
 *
 * This function will always duplicate values, whereas #tmpl_expand may return a pointer to an
 * existing buffer.
 *
 * @note This function is used where raw string values are needed, which may mean the string
 *	returned may be binary data or contain unprintable chars. #fr_snprint or #fr_asprint should
 *	be used before using these values in debug statements. #is_printable can be used to check
 *	if the string only contains printable chars.
 *
 * @note The type (char or uint8_t) can be obtained with talloc_get_type, and may be used as a
 *	hint as to how to process or print the data.
 *
 * @param ctx		to allocate new buffer in.
 * @param out		Where to write pointer to the new buffer.
 * @param request	Current request.
 * @param vpt		to expand. Must be one of the following types:
 *			- #TMPL_TYPE_UNPARSED
 *			- #TMPL_TYPE_EXEC
 *			- #TMPL_TYPE_XLAT_UNPARSED
 *			- #TMPL_TYPE_XLAT
 *			- #TMPL_TYPE_ATTR
 *			- #TMPL_TYPE_DATA
 * @param escape xlat	escape function (only used for TMPL_TYPE_XLAT_UNPARSED_* types).
 * @param escape_ctx	xlat escape function data (only used for TMPL_TYPE_XLAT_UNPARSED_* types).
 * @param dst_type	FR_TYPE_* matching out pointer.  @see tmpl_aexpand.
 * @return
 *	- -1 on failure.
 *	- The length of data written to buff, or pointed to by out.
 */
ssize_t _tmpl_to_atype(TALLOC_CTX *ctx, void *out,
		       REQUEST *request,
		       vp_tmpl_t const *vpt,
		       xlat_escape_t escape, void const *escape_ctx,
		       fr_type_t dst_type)
{
	fr_value_box_t const	*to_cast = NULL;
	fr_value_box_t		from_cast;

	VALUE_PAIR		*vp = NULL;
	fr_value_box_t		value;
	bool			needs_dup = false;

	ssize_t			slen = -1;
	int			ret;

	TALLOC_CTX		*tmp_ctx = talloc_new(ctx);

	TMPL_VERIFY(vpt);

	memset(&value, 0, sizeof(value));

	switch (vpt->type) {
	case TMPL_TYPE_UNPARSED:
		RDEBUG4("EXPAND TMPL UNPARSED");

		value.datum.length = vpt->len;
		value.vb_strvalue = vpt->name;
		value.type = FR_TYPE_STRING;
		to_cast = &value;
		needs_dup = true;
		break;

	case TMPL_TYPE_EXEC:
		RDEBUG4("EXPAND TMPL EXEC");

		MEM(value.vb_strvalue = talloc_array(tmp_ctx, char, 1024));
		if (radius_exec_program(request, (char *)value.datum.ptr, 1024, NULL, request, vpt->name, NULL,
					true, false, fr_time_delta_from_sec(EXEC_TIMEOUT)) != 0) {
		error:
			talloc_free(tmp_ctx);
			return slen;
		}
		value.datum.length = strlen(value.vb_strvalue);
		value.type = FR_TYPE_STRING;
		MEM(value.vb_strvalue = talloc_realloc(tmp_ctx, value.datum.ptr, char, value.datum.length + 1));	/* Trim */
		fr_assert(value.vb_strvalue[value.datum.length] == '\0');
		to_cast = &value;
		break;

	case TMPL_TYPE_XLAT_UNPARSED:
	{
		fr_value_box_t	tmp;
		fr_type_t		src_type = FR_TYPE_STRING;

		RDEBUG4("EXPAND TMPL XLAT");

		/* Error in expansion, this is distinct from zero length expansion */
		slen = xlat_aeval(tmp_ctx, (char **)&value.datum.ptr, request, vpt->name, escape, escape_ctx);
		if (slen < 0) goto error;
		value.datum.length = slen;

		/*
		 *	Undo any of the escaping that was done by the
		 *	xlat expansion function.
		 *
		 *	@fixme We need a way of signalling xlat not to escape things.
		 */
		ret = fr_value_box_from_str(tmp_ctx, &tmp, &src_type, NULL,
					    value.vb_strvalue, value.datum.length, '"', false);
		if (ret < 0) goto error;

		value.vb_strvalue = tmp.vb_strvalue;
		value.datum.length = tmp.datum.length;
		value.type = FR_TYPE_STRING;
		to_cast = &value;
	}
		break;

	case TMPL_TYPE_XLAT:
	{
		fr_value_box_t	tmp;
		fr_type_t		src_type = FR_TYPE_STRING;

		RDEBUG4("EXPAND TMPL XLAT STRUCT");
		RDEBUG2("EXPAND %s", vpt->name); /* xlat_struct doesn't do this */

		/* Error in expansion, this is distinct from zero length expansion */
		slen = xlat_aeval_compiled(tmp_ctx, (char **)&value.datum.ptr, request, tmpl_xlat(vpt), escape, escape_ctx);
		if (slen < 0) goto error;

		value.datum.length = slen;

		/*
		 *	Undo any of the escaping that was done by the
		 *	xlat expansion function.
		 *
		 *	@fixme We need a way of signalling xlat not to escape things.
		 */
		ret = fr_value_box_from_str(tmp_ctx, &tmp, &src_type, NULL,
					    value.vb_strvalue, value.datum.length, '"', false);
		if (ret < 0) goto error;

		value.vb_strvalue = tmp.vb_strvalue;
		value.datum.length = tmp.datum.length;
		value.type = FR_TYPE_STRING;
		to_cast = &value;

		RDEBUG2("   --> %s", value.vb_strvalue);	/* Print post-unescaping */
	}
		break;

	case TMPL_TYPE_ATTR:
		RDEBUG4("EXPAND TMPL ATTR");

		ret = tmpl_find_vp(&vp, request, vpt);
		if (ret < 0) {
			talloc_free(tmp_ctx);
			return -2;
		}

		fr_assert(vp);

		to_cast = &vp->data;
		switch (to_cast->type) {
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			fr_assert(to_cast->datum.ptr);
			needs_dup = true;
			break;

		default:
			break;
		}
		break;

	case TMPL_TYPE_DATA:
	{
		RDEBUG4("EXPAND TMPL DATA");

		to_cast = tmpl_value(vpt);
		switch (to_cast->type) {
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			fr_assert(to_cast->datum.ptr);
			needs_dup = true;
			break;

		default:
			break;
		}
	}
		break;

	/*
	 *	We should never be expanding these.
	 */
	case TMPL_TYPE_UNINITIALISED:
	case TMPL_TYPE_NULL:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_REGEX_UNPARSED:
	case TMPL_TYPE_ATTR_UNPARSED:
	case TMPL_TYPE_MAX:
		fr_assert(0);
		goto error;
	}

	/*
	 *	Special case where we just copy the boxed value
	 *	directly instead of casting it.
	 */
	if (dst_type == FR_TYPE_VALUE_BOX) {
		fr_value_box_t	**vb_out = (fr_value_box_t **)out;

		MEM(*vb_out = fr_value_box_alloc_null(ctx));

		ret = needs_dup ? fr_value_box_copy(ctx, *vb_out, to_cast) : fr_value_box_steal(ctx, *vb_out, to_cast);
		talloc_free(tmp_ctx);
		if (ret < 0) {
			RPEDEBUG("Failed copying data to output box");
			TALLOC_FREE(*vb_out);
			return -1;
		}
		return 0;
	}

	/*
	 *	Don't dup the buffers unless we need to.
	 */
	if ((to_cast->type != dst_type) || needs_dup) {
		ret = fr_value_box_cast(ctx, &from_cast, dst_type, NULL, to_cast);
		if (ret < 0) goto error;
	} else {
		switch (to_cast->type) {
		case FR_TYPE_OCTETS:
		case FR_TYPE_STRING:
			/*
			 *	Ensure we don't free the output buffer when the
			 *	tmp_ctx is freed.
			 */
			if (value.datum.ptr && (talloc_parent(value.datum.ptr) == tmp_ctx)) {
				value.datum.ptr = talloc_reparent(tmp_ctx, ctx, value.datum.ptr);
			}
			break;

		default:
			break;
		}
		memcpy(&from_cast, to_cast, sizeof(from_cast));
	}

	RDEBUG4("Copying %zu bytes to %p from offset %zu",
		fr_value_box_field_sizes[dst_type], *((void **)out), fr_value_box_offsets[dst_type]);

	memcpy(out, ((uint8_t *)&from_cast) + fr_value_box_offsets[dst_type], fr_value_box_field_sizes[dst_type]);

	/*
	 *	Frees any memory allocated for temporary buffers
	 *	in this function.
	 */
	talloc_free(tmp_ctx);

	return from_cast.datum.length;
}

/** Print an attribute or list #vp_tmpl_t to a string
 *
 * @note Does not print preceding '&'.
 *
 * @param[out] need	The number of bytes we'd need to write out the next part
 *			of the template string.
 * @param[out] out	Where to write the presentation format #vp_tmpl_t string.
 * @param[in] outlen	Size of output buffer.
 * @param[in] vpt	to print.
 * @return
 *	- The number of bytes written to the out buffer.
 *	- A number >= outlen if truncation has occurred.
 */
size_t tmpl_snprint_attr_str(size_t *need, char *out, size_t outlen, vp_tmpl_t const *vpt)
{
	char const	*p;
	char		*out_p = out, *end = out_p + outlen;
	size_t		len;

	RETURN_IF_NO_SPACE_INIT(need, 1, out_p, out, end);

	if (unlikely(!vpt)) {
		*out = '\0';
		return 0;
	}

	TMPL_VERIFY(vpt);

	switch (vpt->type) {
	case TMPL_TYPE_LIST:
		/*
		 *	Don't add &current.
		 */
		if (tmpl_request(vpt) == REQUEST_CURRENT) {
			len = snprintf(out_p, end - out_p, "%s:", fr_table_str_by_value(pair_list_table, tmpl_list(vpt), ""));
			RETURN_IF_TRUNCATED(need, len, out_p, out, end);
			goto inst_and_tag;
		}

		len = snprintf(out_p, end - out_p, "%s.%s:", fr_table_str_by_value(request_ref_table, tmpl_request(vpt), ""),
			       fr_table_str_by_value(pair_list_table, tmpl_list(vpt), ""));
		RETURN_IF_TRUNCATED(need, len, out_p, out, end);
		goto inst_and_tag;

	case TMPL_TYPE_ATTR_UNPARSED:
		p = tmpl_attr_unparsed(vpt);
		goto print_name;

	case TMPL_TYPE_ATTR:
		p = tmpl_da(vpt)->name;

	print_name:
		/*
		 *	Don't add &current.
		 */
		if (tmpl_request(vpt) == REQUEST_CURRENT) {
			if (tmpl_list(vpt) == PAIR_LIST_REQUEST) {
				len = strlcpy(out_p, p, end - out_p);
				RETURN_IF_TRUNCATED(need, len, out_p, out, end);
				goto inst_and_tag;
			}

			/*
			 *	Don't add &request:
			 */
			len = snprintf(out_p, end - out_p, "%s:%s",
				       fr_table_str_by_value(pair_list_table, tmpl_list(vpt), ""), p);
			RETURN_IF_TRUNCATED(need, len, out_p, out, end);
			goto inst_and_tag;
		}

		len = snprintf(out_p, end - out_p, "%s.%s:%s",
			       fr_table_str_by_value(request_ref_table, tmpl_request(vpt), ""),
			       fr_table_str_by_value(pair_list_table, tmpl_list(vpt), ""), p);
		RETURN_IF_TRUNCATED(need, len, out_p, out, end);

	inst_and_tag:
		if (TAG_VALID(tmpl_tag(vpt))) {
			len = snprintf(out_p, end - out_p, ":%d", tmpl_tag(vpt));
			RETURN_IF_TRUNCATED(need, len, out_p, out, end);
		}

		switch (tmpl_num(vpt)) {
		case NUM_ANY:
			len = 0;
			break;

		case NUM_ALL:
			len = snprintf(out_p, end - out_p, "[*]");
			break;

		case NUM_COUNT:
			len = snprintf(out_p, end - out_p, "[#]");
			break;

		case NUM_LAST:
			len = snprintf(out_p, end - out_p, "[n]");
			break;

		default:
			len = snprintf(out_p, end - out_p, "[%i]", tmpl_num(vpt));
			break;
		}
		RETURN_IF_TRUNCATED(need, len, out_p, out, end);
		break;

	default:
		fr_assert_fail(NULL);
		return 0;
	}

	*out_p = '\0';
	return (out_p - out);
}

/** Print a #vp_tmpl_t to a string
 *
 * @param[out] need	The number of bytes we'd need to write out the next part
 *			of the template string.
 * @param[out] out	Where to write the presentation format #vp_tmpl_t string.
 * @param[in] outlen	Size of output buffer.
 * @param[in] vpt	to print.
 * @return
 *	- The number of bytes written to the out buffer. If truncation has
 *	ocurred. *need will be > 0.
 */
size_t tmpl_snprint(size_t *need, char *out, size_t outlen, vp_tmpl_t const *vpt)
{
	size_t		len;
	char const	*p;
	char		c;
	char		*out_p = out, *end = out_p + outlen;

	RETURN_IF_NO_SPACE_INIT(need, 1, out_p, out, end);

	if (!vpt) {
empty:
		*out = '\0';
		return 0;
	}
	TMPL_VERIFY(vpt);

	switch (vpt->type) {
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_ATTR_UNPARSED:
	case TMPL_TYPE_ATTR:
		*out_p++ = '&';
		return tmpl_snprint_attr_str(need, out_p, end - out_p, vpt) + 1;

	/*
	 *	Regexes have their own set of escaping rules
	 */
	case TMPL_TYPE_REGEX_UNPARSED:
	case TMPL_TYPE_REGEX:
		if ((end - out_p) <= 3) {	/* / + <c> + / + \0 */
		no_space:
			if (out_p > end) out_p = end;	/* Safety */
			*out_p = '\0';
			return outlen + 1;
		}

		*out_p++ = '/';
		len = fr_snprint(out_p, end - out_p, vpt->name, vpt->len, '\0');
		RETURN_IF_TRUNCATED(need, len, out_p, out, end);

		if ((end - out_p) <= 1) goto no_space;
		*out_p++ = '/';

		len = regex_flags_snprint(out_p, end - out_p, &tmpl_regex_flags(vpt));
		RETURN_IF_TRUNCATED(need, len, out_p, out, end);

		goto finish;

	case TMPL_TYPE_XLAT_UNPARSED:
	case TMPL_TYPE_XLAT:
		c = '"';
		goto do_literal;

	case TMPL_TYPE_EXEC:
		c = '`';
		goto do_literal;

	case TMPL_TYPE_UNPARSED:
		/*
		 *	Nasty nasty hack that needs to be fixed.
		 *
		 *	Determines what quoting to use around strings based on their content.
		 *	Should use vpt->quote, but that's not always set correctly
		 *	at the moment.
		 */
		for (p = vpt->name; *p != '\0'; p++) {
			if (*p == ' ') break;
			if (*p == '\'') break;
			if (*p == '.') continue;
			if (!fr_dict_attr_allowed_chars[(uint8_t) *p]) break;
		}
		c = *p ? '"' : '\0';

do_literal:
		if ((end - out_p) <= 3) goto no_space;	/* / + <c> + / + \0 */
		if (c != '\0') *out_p++ = c;
		len = fr_snprint(out_p, (end - out_p) - ((c == '\0') ? 0 : 1), vpt->name, vpt->len, c);
		RETURN_IF_TRUNCATED(need, len, out_p, out, end - ((c == '\0') ? 0 : 1));

		if ((end - out_p) <= 1) goto no_space;
		if (c != '\0') *out_p++ = c;
		break;

	case TMPL_TYPE_DATA:
		return fr_value_box_snprint(out, end - out_p, tmpl_value(vpt), fr_token_quote[vpt->quote]);

	default:
		goto empty;
	}

finish:
	*out_p = '\0';
	return (out_p - out);
}

#define TMPL_TAG_MATCH(_a, _t) ((_a->da == tmpl_da(_t)) && ATTR_TAG_MATCH(_a, tmpl_tag(_t)))

static void *_tmpl_cursor_next(void **prev, void *curr, void *ctx)
{
	VALUE_PAIR	*c, *p, *fc = NULL, *fp = NULL;
	vp_tmpl_t const	*vpt = ctx;
	int		num;

	if (!curr) return NULL;

	switch (vpt->type) {
	case TMPL_TYPE_ATTR:
		switch (tmpl_num(vpt)) {
		case NUM_ANY:				/* Bare attribute ref */
			if (*prev) {
			null_result:
				*prev = curr;
				return NULL;
			}
			/* FALL-THROUGH */

		case NUM_ALL:
		case NUM_COUNT:				/* Iterator is called multiple time to get the count */
			for (c = curr, p = *prev; c; p = c, c = c->next) {
			     	VP_VERIFY(c);
				if (TMPL_TAG_MATCH(c, vpt)) {
					*prev = p;
					return c;
				}
			}
			goto null_result;

		case NUM_LAST:				/* Get the last instance of a VALUE_PAIR */
			for (c = curr, p = *prev; c; p = c, c = c->next) {
			     	VP_VERIFY(c);
				if (TMPL_TAG_MATCH(c, vpt)) {
				    	fp = p;
					fc = c;
				}
			}
			*prev = fp;
			return fc;

		default:				/* Get the specified index*/
			if (*prev) goto null_result;
			for (c = curr, p = *prev, num = tmpl_num(vpt);
			     c && (num >= 0);
			     p = c, c = c->next) {
			     	VP_VERIFY(c);
				if (TMPL_TAG_MATCH(c, vpt)) {
					fp = p;
					fc = c;
					num--;
				}
			}
			if (num >= 0) goto null_result;	/* Not enough entries */
			*prev = fp;
			return fc;
		}

	case TMPL_TYPE_LIST:
		switch (tmpl_num(vpt)) {
		case NUM_ANY:				/* Bare attribute ref */
			if (*prev) goto null_result;
			/* FALL-THROUGH */

		case NUM_COUNT:				/* Iterate over the list, one attribute at a time */
		case NUM_ALL:
			VP_VERIFY(curr);
			return curr;			/* (cursor already advanced by the caller) */

		case NUM_LAST:				/* Get the last attribute in the list */
			for (c = curr, p = *prev; c; p = c, c = c->next) {
				VP_VERIFY(c);
				fp = p;
				fc = c;
			}
			*prev = fp;
			return fc;

		default:				/* Get the specified index*/
			if (*prev) goto null_result;	/* Subsequent call */
			for (c = curr, p = *prev, num = tmpl_num(vpt);
			     c && (num >= 0);
			     p = c, c = c->next) {
			     	VP_VERIFY(c);
			     	fp = p;
			     	fc = c;
			     	num--;
			}
			/* Not enough entries */
			if (num >= 0) goto null_result;
			*prev = fp;
			return fc;
		}

	default:
		fr_assert(0);
	}

	return NULL;
}

/** Initialise a #fr_cursor_t to the #VALUE_PAIR specified by a #vp_tmpl_t
 *
 * This makes iterating over the one or more #VALUE_PAIR specified by a #vp_tmpl_t
 * significantly easier.
 *
 * @param err May be NULL if no error code is required. Will be set to:
 *	- 0 on success.
 *	- -1 if no matching #VALUE_PAIR could be found.
 *	- -2 if list could not be found (doesn't exist in current #REQUEST).
 *	- -3 if context could not be found (no parent #REQUEST available).
 * @param cursor to store iterator state.
 * @param request The current #REQUEST.
 * @param vpt specifying the #VALUE_PAIR type/tag or list to iterate over.
 * @return
 *	- First #VALUE_PAIR specified by the #vp_tmpl_t.
 *	- NULL if no matching #VALUE_PAIR found, and NULL on error.
 *
 * @see tmpl_cursor_next
 */
VALUE_PAIR *tmpl_cursor_init(int *err, fr_cursor_t *cursor, REQUEST *request, vp_tmpl_t const *vpt)
{
	VALUE_PAIR	**vps, *vp = NULL;

	TMPL_VERIFY(vpt);

	fr_assert(tmpl_is_attr(vpt) || tmpl_is_list(vpt));

	if (err) *err = 0;

	if (radius_request(&request, tmpl_request(vpt)) < 0) {
		if (err) {
			*err = -3;
			fr_strerror_printf("Request context \"%s\" not available",
					   fr_table_str_by_value(request_ref_table, tmpl_request(vpt), "<INVALID>"));
		}
		return NULL;
	}
	vps = radius_list(request, tmpl_list(vpt));
	if (!vps) {
		if (err) {
			*err = -2;
			fr_strerror_printf("List \"%s\" not available in this context",
					   fr_table_str_by_value(pair_list_table, tmpl_list(vpt), "<INVALID>"));
		}
		return NULL;
	}

	vp = fr_cursor_talloc_iter_init(cursor, vps, _tmpl_cursor_next, vpt, VALUE_PAIR);
	if (!vp) {
		if (err) {
			*err = -1;
			if (tmpl_is_list(vpt)) {
				fr_strerror_printf("List \"%s\" is empty", vpt->name);
			} else {
				fr_strerror_printf("No matching \"%s\" pairs found", tmpl_da(vpt)->name);
			}
		}
		return NULL;
	}

	return vp;
}

/** Copy pairs matching a #vp_tmpl_t in the current #REQUEST
 *
 * @param ctx to allocate new #VALUE_PAIR in.
 * @param out Where to write the copied #VALUE_PAIR (s).
 * @param request The current #REQUEST.
 * @param vpt specifying the #VALUE_PAIR type/tag or list to copy.
 *	Must be one of the following types:
 *	- #TMPL_TYPE_LIST
 *	- #TMPL_TYPE_ATTR
 * @return
 *	- -1 if no matching #VALUE_PAIR could be found.
 *	- -2 if list could not be found (doesn't exist in current #REQUEST).
 *	- -3 if context could not be found (no parent #REQUEST available).
 *	- -4 on memory allocation error.
 */
int tmpl_copy_vps(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, vp_tmpl_t const *vpt)
{
	VALUE_PAIR	*vp;
	fr_cursor_t	from, to;

	TMPL_VERIFY(vpt);

	int err;

	fr_assert(tmpl_is_attr(vpt) || tmpl_is_list(vpt));

	*out = NULL;

	fr_cursor_init(&to, out);

	for (vp = tmpl_cursor_init(&err, &from, request, vpt);
	     vp;
	     vp = fr_cursor_next(&from)) {
		vp = fr_pair_copy(ctx, vp);
		if (!vp) {
			fr_pair_list_free(out);
			fr_strerror_printf("Out of memory");
			return -4;
		}
		fr_cursor_append(&to, vp);
	}

	return err;
}

/** Returns the first VP matching a #vp_tmpl_t
 *
 * @param[out] out where to write the retrieved vp.
 * @param[in] request The current #REQUEST.
 * @param[in] vpt specifying the #VALUE_PAIR type/tag to find.
 *	Must be one of the following types:
 *	- #TMPL_TYPE_LIST
 *	- #TMPL_TYPE_ATTR
 * @return
 *	- 0 on success (found matching #VALUE_PAIR).
 *	- -1 if no matching #VALUE_PAIR could be found.
 *	- -2 if list could not be found (doesn't exist in current #REQUEST).
 *	- -3 if context could not be found (no parent #REQUEST available).
 */
int tmpl_find_vp(VALUE_PAIR **out, REQUEST *request, vp_tmpl_t const *vpt)
{
	fr_cursor_t cursor;
	VALUE_PAIR *vp;

	TMPL_VERIFY(vpt);

	int err;

	vp = tmpl_cursor_init(&err, &cursor, request, vpt);
	if (out) *out = vp;

	return err;
}

/** Returns the first VP matching a #vp_tmpl_t, or if no VPs match, creates a new one.
 *
 * @param[out] out where to write the retrieved or created vp.
 * @param[in] request The current #REQUEST.
 * @param[in] vpt specifying the #VALUE_PAIR type/tag to retrieve or create.  Must be #TMPL_TYPE_ATTR.
 * @return
 *	- 1 on success a pair was created.
 *	- 0 on success a pair was found.
 *	- -1 if a new #VALUE_PAIR couldn't be found or created.
 *	- -2 if list could not be found (doesn't exist in current #REQUEST).
 *	- -3 if context could not be found (no parent #REQUEST available).
 */
int tmpl_find_or_add_vp(VALUE_PAIR **out, REQUEST *request, vp_tmpl_t const *vpt)
{
	fr_cursor_t	cursor;
	VALUE_PAIR	*vp;
	int		err;

	TMPL_VERIFY(vpt);
	fr_assert(tmpl_is_attr(vpt));

	*out = NULL;

	vp = tmpl_cursor_init(&err, &cursor, request, vpt);
	switch (err) {
	case 0:
		*out = vp;
		return 0;

	case -1:
	{
		TALLOC_CTX	*ctx;
		VALUE_PAIR	**head;

		RADIUS_LIST_AND_CTX(ctx, head, request, tmpl_request(vpt), tmpl_list(vpt));

		MEM(vp = fr_pair_afrom_da(ctx, tmpl_da(vpt)));
		*out = vp;
	}
		return 0;

	default:
		return err;
	}
}
/** @} */

#ifdef WITH_VERIFY_PTR
/** Used to check whether areas of a vp_tmpl_t are zeroed out
 *
 * @param ptr Offset to begin checking at.
 * @param len How many bytes to check.
 * @return
 *	- Pointer to the first non-zero byte.
 *	- NULL if all bytes were zero.
 */
static uint8_t const *not_zeroed(uint8_t const *ptr, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (ptr[i] != 0x00) return ptr + i;
	}

	return NULL;
}

#define CHECK_ZEROED(_vpt, _field) not_zeroed(((uint8_t const *)&(_vpt)->data) + sizeof((_vpt)->data._field), sizeof((_vpt)->data) - sizeof((_vpt)->data._field))

/** Verify fields of a vp_tmpl_t make sense
 *
 * @note If the #vp_tmpl_t is invalid, causes the server to exit.
 *
 * @param file obtained with __FILE__.
 * @param line obtained with __LINE__.
 * @param vpt to check.
 */
void tmpl_verify(char const *file, int line, vp_tmpl_t const *vpt)
{
	uint8_t const *nz;

	fr_assert(vpt);

	if (tmpl_is_uninitialised(vpt)) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: vp_tmpl_t type was "
				     "TMPL_TYPE_UNINITIALISED (uninitialised)", file, line);
	}

	if (vpt->type >= TMPL_TYPE_MAX) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: vp_tmpl_t type was %i "
				     "(outside range of tmpl_type_table)", file, line, vpt->type);
	}

	if (!vpt->name && (vpt->quote != T_INVALID)) {
		char quote = vpt->quote > T_TOKEN_LAST ? '?' : fr_token_quote[vpt->quote];

		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: Quote type '%c' (%i) was set for NULL name",
				     file, line, quote, vpt->quote);
	}

	if (vpt->name && (vpt->quote == T_INVALID)) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: No quoting type was set for name \"%.*s\"",
				     file, line, (int)vpt->len, vpt->name);
	}

	/*
	 *  Do a memcmp of the bytes after where the space allocated for
	 *  the union member should have ended and the end of the union.
	 *  These should always be zero if the union has been initialised
	 *  properly.
	 *
	 *  If they're still all zero, do TMPL_TYPE specific checks.
	 */
	switch (vpt->type) {
	case TMPL_TYPE_NULL:
		if ((nz = not_zeroed((uint8_t const *)&vpt->data, sizeof(vpt->data)))) {
			HEX_MARKER1((uint8_t const *)&vpt->data, sizeof(vpt->data),
				    nz - (uint8_t const *)&vpt->data, "non-zero memory", "");
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_NULL "
					     "has non-zero bytes in its data union", file, line);
		}
		break;

	case TMPL_TYPE_UNPARSED:
		if ((nz = not_zeroed((uint8_t const *)&vpt->data, sizeof(vpt->data)))) {
			HEX_MARKER1((uint8_t const *)&vpt->data, sizeof(vpt->data),
				    nz - (uint8_t const *)&vpt->data, "non-zero memory", "");

			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_UNPARSED "
					     "has non-zero bytes in its data union", file, line);
		}
		break;

	case TMPL_TYPE_XLAT_UNPARSED:
	case TMPL_TYPE_XLAT:
		break;

/* @todo When regexes get converted to xlat the flags field of the regex union is used
	case TMPL_TYPE_XLAT_UNPARSED:
		if (not_zeroed((uint8_t const *)&vpt->data, sizeof(vpt->data))) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_XLAT_UNPARSED "
					     "has non-zero bytes in its data union", file, line);
		}
		break;

	case TMPL_TYPE_XLAT:
		if (CHECK_ZEROED(vpt, xlat)) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_XLAT "
					     "has non-zero bytes after the data.xlat pointer in the union", file, line);
		}
		break;
*/

	case TMPL_TYPE_EXEC:
		/* tmpl_xlat(vpt) can be initialized */
		break;

	case TMPL_TYPE_ATTR_UNPARSED:
		if ((fr_dlist_num_elements(&vpt->data.attribute.ar) > 0) &&
		    ((vp_tmpl_attr_t *)fr_dlist_tail(&vpt->data.attribute.ar))->da) {
#ifndef NDEBUG
			tmpl_attr_debug(vpt);
#endif
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR_UNPARSED contains %zu "
					     "references", file, line, fr_dlist_num_elements(&vpt->data.attribute.ar));
		}
		break;

	case TMPL_TYPE_ATTR:
		if ((nz = CHECK_ZEROED(vpt, attribute))) {
			HEX_MARKER1((uint8_t const *)&vpt->data.attribute, sizeof(vpt->data.attribute),
				    nz - (uint8_t const *)&vpt->data.attribute, "non-zero memory", "");
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
					     "has non-zero bytes after the data.attribute struct in the union",
					     file, line);
		}

		if (tmpl_da(vpt)->flags.is_unknown) {
			if (tmpl_da(vpt) != tmpl_unknown(vpt)) {
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
						     "da is marked as unknown, but address is not equal to the template's "
						     "unknown da pointer", file, line);
			}
		/*
		 *	Raw attributes may not have been added to the dictionary yet
		 */
		} else {
			fr_dict_attr_t const	*da;
			fr_dict_t const		*dict;

			if (!tmpl_da(vpt)->flags.has_tag &&
			    (tmpl_tag(vpt) != TAG_NONE) && (tmpl_tag(vpt) != TAG_ANY)) {
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
						     "da is marked as not having a tag, but the template has a tag",
						     file, line);
			}

#if 0
			if (tmpl_da(vpt)->flags.has_tag &&
			    !TAG_VALID_ZERO(tmpl_tag(vpt))) {
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
						     "da is marked as not having a tag, but the template has an invalid tag",
						     file, line);
			}
#endif

			/*
			 *	Attribute may be present with multiple names
			 */
			dict = fr_dict_by_da(tmpl_da(vpt));
			if (!dict) {
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
						     "attribute \"%s\" (%s) not rooted in a dictionary",
						     file, line, tmpl_da(vpt)->name,
						     fr_table_str_by_value(fr_value_box_type_table, tmpl_da(vpt)->type, "<INVALID>"));
			}

			da = fr_dict_attr_by_name(dict, tmpl_da(vpt)->name);
			if (!da) {
				if (!tmpl_da(vpt)->flags.is_raw) {
					fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
							     "attribute \"%s\" (%s) not found in dictionary (%s)",
							     file, line, tmpl_da(vpt)->name,
							     fr_table_str_by_value(fr_value_box_type_table, tmpl_da(vpt)->type, "<INVALID>"),
							     fr_dict_root(dict)->name);
				}
				da = tmpl_da(vpt);
			}

			if ((da->type == FR_TYPE_COMBO_IP_ADDR) && (da->type != tmpl_da(vpt)->type)) {
				da = fr_dict_attr_by_type(tmpl_da(vpt), tmpl_da(vpt)->type);
				if (!da) {
					fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
							     "attribute \"%s\" variant (%s) not found in dictionary (%s)",
							     file, line, tmpl_da(vpt)->name,
							     fr_table_str_by_value(fr_value_box_type_table, tmpl_da(vpt)->type, "<INVALID>"),
							     fr_dict_root(dict)->name);
				}
			}

			if (da != tmpl_da(vpt)) {
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
						     "dictionary pointer %p \"%s\" (%s) "
						     "and global dictionary pointer %p \"%s\" (%s) differ",
						     file, line,
						     tmpl_da(vpt), tmpl_da(vpt)->name,
						     fr_table_str_by_value(fr_value_box_type_table, tmpl_da(vpt)->type, "<INVALID>"),
						     da, da->name,
						     fr_table_str_by_value(fr_value_box_type_table, da->type, "<INVALID>"));
			}

			if (tmpl_list(vpt) >= PAIR_LIST_UNKNOWN) {
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
						     "attribute \"%s\" has invalid list (%i)",
						     file, line, tmpl_da(vpt)->name, tmpl_list(vpt));
			}
		}
		break;

	case TMPL_TYPE_LIST:
		if ((nz = CHECK_ZEROED(vpt, attribute))) {
			HEX_MARKER1((uint8_t const *)&vpt->data.attribute, sizeof(vpt->data.attribute),
				    nz - (uint8_t const *)&vpt->data.attribute, "non-zero memory", "");
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_LIST"
					     "has non-zero bytes after the data.attribute struct in the union",
					     file, line);
		}

		if ((fr_dlist_num_elements(&vpt->data.attribute.ar) > 0) &&
		    ((vp_tmpl_attr_t *)fr_dlist_tail(&vpt->data.attribute.ar))->da) {
#ifndef NDEBUG
			tmpl_attr_debug(vpt);
#endif
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_LIST contains %zu "
					     "references", file, line, fr_dlist_num_elements(&vpt->data.attribute.ar));
		}
		break;

	case TMPL_TYPE_DATA:
		if ((nz = CHECK_ZEROED(vpt, literal))) {
			HEX_MARKER1((uint8_t const *)&vpt->data.attribute, sizeof(vpt->data.attribute),
				    nz - (uint8_t const *)&vpt->data.attribute, "non-zero memory", "");
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA "
					     "has non-zero bytes after the data.literal struct in the union",
					     file, line);
		}

		if (tmpl_value_type(vpt) == FR_TYPE_INVALID) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA type was "
					     "FR_TYPE_INVALID (uninitialised)", file, line);
		}

		if (tmpl_value_type(vpt) >= FR_TYPE_MAX) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA type was "
					     "%i (outside the range of fr_type_ts)", file, line, tmpl_value_type(vpt));
		}
		/*
		 *	Unlike VALUE_PAIRs we can't guarantee that VALUE_PAIR_TMPL buffers will
		 *	be talloced. They may be allocated on the stack or in global variables.
		 */
		switch (tmpl_value_type(vpt)) {
		case FR_TYPE_STRING:
			if (tmpl_value(vpt)->vb_strvalue[tmpl_value_length(vpt)] != '\0') {
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA char buffer not \\0 "
						     "terminated", file, line);
			}
			break;

		case FR_TYPE_TLV:
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA is of type TLV",
					     file, line);

		default:
			break;
		}

		break;

	case TMPL_TYPE_REGEX_UNPARSED:
#ifdef HAVE_REGEX
		if (tmpl_preg(vpt) != NULL) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX_UNPARSED "
					     "preg field was not NULL", file, line);
		}
#else
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX_UNPARSED - No regex support",
				     file, line);
#endif
		break;

	case TMPL_TYPE_REGEX:
#ifdef HAVE_REGEX
		if (tmpl_preg(vpt) == NULL) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX "
					     "comp field was NULL", file, line);
		}
#else
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX - No regex support",
				     file, line);
#endif
		break;

	case TMPL_TYPE_UNINITIALISED:
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_UNINITIALISED", file, line);

	case TMPL_TYPE_MAX:
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_MAX", file, line);
	}
}
#endif

#define return_P(_x) *error = _x;goto return_p

/** Preparse a string in preparation for passing it to tmpl_afrom_str()
 *
 *  Note that the input string is not modified, which means that the
 *  tmpl_afrom_str() function MUST un-escape it.
 *
 *  The caller should pass 'out' and 'outlen' to tmpl_afrom_str()
 *  as 'in' and 'inlen'.  The caller should also pass 'type'.
 *  The caller should also pass do_unescape=true.
 *
 * @param[out] out	start of the string to parse
 * @param[out] outlen	length of the string to parse
 * @param      in	where we start looking for the string
 * @param      inlen	length of the input string
 * @param[out] type	token type of the string.
 * @param[out] error	string describing the error
 * @param[out] castda	NULL if casting is not allowed, otherwise the cast
 * @param   require_regex whether or not to require regular expressions
 * @param   allow_xlat  whether or not "bare" xlat's are allowed
 * @return
 *	- > 0, amount of parsed string to skip, to get to the next token
 *	- <=0, -offset in 'start' where the parse error was located
 */
ssize_t tmpl_preparse(char const **out, size_t *outlen, char const *in, size_t inlen,
		      fr_token_t *type, char const **error,
		      fr_dict_attr_t const **castda, bool require_regex, bool allow_xlat)
{
	char const *p = in, *end = in + inlen;
	char quote;
	int depth;

	*type = T_INVALID;
	if (castda) *castda = NULL;

	while (isspace((int) *p) && (p < end)) p++;
	if (p >= end) return p - in;

	if (*p == '<') {
		fr_type_t cast;
		char const *q;

		if (!castda) {
			*error = "Unexpected cast";
		return_p:
			return -(p - in);
		}

		p++;
		fr_skip_whitespace(p);

		for (q = p; *q && !isspace((int) *q) && (*q != '>'); q++) {
			/* nothing */
		}

		cast = fr_table_value_by_substr(fr_value_box_type_table, p, q - p, FR_TYPE_INVALID);
		if (cast == FR_TYPE_INVALID) {
			return_P("Unknown data type");
		}

		/*
		 *	We can only cast to basic data types.  Complex ones
		 *	are forbidden.
		 */
		if (fr_dict_non_data_types[cast]) {
			return_P("Forbidden data type in cast");
		}

		*castda = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()), FR_CAST_BASE + cast);
		if (!*castda) {
			return_P("Cannot cast to this data type");
		}

		p = q;
		fr_skip_whitespace(p);
		if (*p != '>') {
			return_P("Expected '>'");
		}
		p++;

		fr_skip_whitespace(p);
	}

	if (require_regex) {
		if (castda && *castda) {
			p++;
			return_P("Invalid cast before regular expression");
		}

		/*
		 *	Allow this which is sometimes clearer.
		 */
		if (*p == 'm') {
			p++;
			quote = *(p++);
			*type = T_OP_REG_EQ;
			goto skip_string;
		}

		if (*p != '/') {
			return_P("Expected regular expression");
		}
	} /* else treat '/' as any other character */

	switch (*p) {
		/*
		 *	Allow bare xlat's
		 */
	case '%':
		if (!allow_xlat) {
			return_P("Unexpected expansion");
		}

		if (p[1] != '{') {
			p++;
			return_P("Invalid character after '%'");
		}

		/*
		 *	For now, %{...} is treated as a double-quoted
		 *	string.  Once we clean other things up, the
		 *	xlats will be treated as strongly typed values
		 *	/ lists on their own.
		 */
		*type = T_DOUBLE_QUOTED_STRING;
		depth = 0;

		/*
		 *	Xlat's are quoted by %{...} nesting, not by
		 *	escapes, so we need to do special escaping.
		 */
		*out = p;
		while (*p) {
			/*
			 *	End of expansion.  Return the entire
			 *	expansion, including the enclosing %{}
			 *	characters.
			 */
			if (*p == '}') {
				p++;
				depth--;

				if (depth == 0) {
					*outlen = p - (*out);
					return p - in;
				}
				continue;
			}

			if (*p == '\\') {
				p++;
				if (!p[1]) {
					return_P("End of string after escape");
				}

				p++;
				continue;
			}

			if ((p[0] == '%') && (p[1] == '{')) {
				if (!p[2]) {
					return_P("End of string after expansion");
				}

				p += 2;
				depth++;
				continue;
			}

			p++;
		}

		/*
		 *	End of input without end of string.
		 *	Point the error to the start of the string.
		 */
		p = *out;
		return_P("Unterminated expansion");

	case '/':
		if (!require_regex) goto bare_word;

		quote = *(p++);
		*type = T_OP_REG_EQ;
		goto skip_string;

	case '\'':
		quote = *(p++);;
		*type = T_SINGLE_QUOTED_STRING;
		goto skip_string;

	case '`':
		quote = *(p++);;
		*type = T_BACK_QUOTED_STRING;
		goto skip_string;

	case '"':
		quote = *(p++);;
		*type = T_DOUBLE_QUOTED_STRING;

		/*
		 *	We're not trying to do a *correct* parsing of
		 *	every string here.  We're trying to do a
		 *	simple parse that isn't wrong.  We therefore
		 *	accept most anything that's vaguely well
		 *	formed, and rely on the next stage to do a
		 *	more rigourous check.
		 */
	skip_string:
		*out = p;
		while (*p) {
			/*
			 *	End of string.  Tell the caller the
			 *	length of the data inside of the
			 *	string, and return the number of
			 *	characters to skip.
			 */
			if (*p == quote) {
				*outlen = p - (*out);
				p++;
				return p - in;
			}

			if (*p == '\\') {
				p++;
				if (!p[1]) {
					return_P("End of string after escape");
				}
			}
			p++;
		}

		/*
		 *	End of input without end of string.
		 *	Point the error to the start of the string.
		 */
		p = *out;
		return_P("Unterminated string");

	case '&':
		*out = p;	/* the output string starts with '&' */
		p++;
		quote = '[';
		goto skip_word;

	default:
	bare_word:
		*out = p;
		quote = '\0';

	skip_word:
		*type = T_BARE_WORD;
		depth = 0;

		/*
		 *	Allow *most* things.  But stop on spaces and special characters.
		 */
		while (*p) {
			if (isspace((int) *p)) {
				break;
			}

			if (*p == '$') {
				if (p[1] == '{') {
					p += 2;
					depth++;
					continue;

				} else if ((p[1] == 'E') &&
					   (p[2] == 'N') &&
					   (p[3] == 'V') &&
					   (p[4] == '{')) {
					p += 5;
					depth++;
					continue;

				} else {
					/*
					 *	Bare '$' is wrong...
					 */
					break;
				}
			}

			if (*p == '%') {
				if (p[1] == '{') {
					p += 2;
					depth++;
					continue;
				}

				p++;
				continue;
			}

			/*
			 *	If we're inside of a ${...} expansion,
			 *	then allow everything until the
			 *	closing '}'.  This means that we can
			 *	do ${foo[bar].baz}, among other
			 *	thingds.
			 */
			if (depth > 0) {
				if (*p == '}') {
					depth--;
				}

				p++;
				continue;
			}

			/*
			 *	'-' is special.  We allow it for
			 *	attribute names, BUT it's a
			 *	terminating token if the NEXT
			 *	character is '='.
			 *
			 *	We have the same criteria for IPv6
			 *	addresses and tagged attributes.  ':'
			 *	is allowed, but ':=' is a breaking
			 *	token.
			 */
			if ((*p == '-') || (*p == ':')) {
				if (p[1] == '=') break;
				p++;
				continue;
			}

			/*
			 *	Allowed in attribute names, and/or
			 *	host names and IP addresses, and IPv6 addresses.
			 */
			if ((*p == '.') || (*p == '/') || (*p == '_') || (*p == '*') ||
			    (*p == ']') || (*p == '@')) {
				p++;
				continue;
			}

			/*
			 *	[...] is an IPv6 address.
			 */
			if ((p == in) && (*p == '[')) {
				p++;
				continue;
			}

			/*
			 *	Allow letters and numbers
			 */
			if (((*p >= 'a') && (*p <= 'z')) ||
			    ((*p >= 'A') && (*p <= 'Z')) ||
			    ((*p >= '0') && (*p <= '9'))) {
				p++;
				continue;
			}

			/*
			 *	Allow UTF-8 sequences.
			 */
			if (*(uint8_t const *)p > 0x80) {
				p++;
				continue;
			}

			/*
			 *	If it's an attribute reference, allow
			 *	a few more things inside of a "[...]"
			 *	block.
			 */
			if (*p == quote) {
				p++;

				/*
				 *	Allow [#], etc.  But stop
				 *	immediately after the ']'.
				 */
				if ((*p == '#') || (*p == '*') || (*p == 'n')) {
					p++;

				} else {
					/*
					 *	Allow numbers as array indexes
					 */
					while ((*p >= '0') && (*p <= '9')) {
						p++;
					}

					if (*p != ']') {
						return_P("Array index is not an integer");
					}
				}

				if (*p == ']') p++;
			}

			/*
			 *	Everything else is a breaking token
			 */
			break;
		}

		/*
		 *	Give some slightly better error messages.
		 */
		if (*p == '\\') {
			return_P("Unexpected escape");
		}

		if ((*p == '"') || (*p == '\'') || (*p == '`')) {
			return_P("Unexpected start of string");
		}

		if (p == *out) {
			return_P("Empty string is invalid");
		}

		*outlen = p - (*out);
		break;
	}

	return p - in;
}

/** Return whether or not async is required for this tmpl.
 *
 *	If the tmpl is async_safe, then it will never yield.
 *	If the tmpl is not async_safe, then it may yield.
 *
 *	If the tmpl yields, then async is required.
 */
bool tmpl_async_required(vp_tmpl_t const *vpt)
{
	switch (vpt->type) {
	case TMPL_TYPE_EXEC:	/* we don't have "exec no-wait" here */
	case TMPL_TYPE_XLAT_UNPARSED:	/* we have no idea, so be safe */
		return true;

	case TMPL_TYPE_XLAT:
		return xlat_async_required(tmpl_xlat(vpt));

	default:
		return false;
	}
}
