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
 * @brief #fr_pair_t template functions
 * @file src/lib/server/tmpl_tokenize.c
 *
 * @ingroup AVP
 *
 * @copyright 2014-2020 The FreeRADIUS server project
 */
RCSID("$Id$")

#define _TMPL_PRIVATE 1

#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/hex.h>
#include <freeradius-devel/util/misc.h>

#include <freeradius-devel/util/sbuff.h>

#include <ctype.h>

/** Map #tmpl_type_t values to descriptive strings
 */
fr_table_num_ordered_t const tmpl_type_table[] = {
	{ L("uninitialised"),		TMPL_TYPE_UNINITIALISED		},

	{ L("null"),			TMPL_TYPE_NULL			},
	{ L("data"),			TMPL_TYPE_DATA			},

	{ L("attr"),			TMPL_TYPE_ATTR			},
	{ L("list"),			TMPL_TYPE_LIST			},

	{ L("exec"),			TMPL_TYPE_EXEC			},
	{ L("xlat"),			TMPL_TYPE_XLAT			},

	{ L("regex"),			TMPL_TYPE_REGEX			},
	{ L("regex-uncompiled"),	TMPL_TYPE_REGEX_UNCOMPILED	},
	{ L("regex-xlat"),		TMPL_TYPE_REGEX_XLAT		},

	{ L("unresolved"),		TMPL_TYPE_UNRESOLVED 		},
	{ L("attr-unresolved"),		TMPL_TYPE_ATTR_UNRESOLVED	},
	{ L("exec-unresolved"),		TMPL_TYPE_EXEC_UNRESOLVED	},
	{ L("xlat-unresolved"),		TMPL_TYPE_XLAT_UNRESOLVED	},
	{ L("regex-unresolved"),	TMPL_TYPE_REGEX_XLAT_UNRESOLVED	}
};
size_t tmpl_type_table_len = NUM_ELEMENTS(tmpl_type_table);

/** Attr ref types
 */
fr_table_num_ordered_t const attr_table[] = {
	{ L("normal"),		TMPL_ATTR_TYPE_NORMAL		},
	{ L("unknown"),		TMPL_ATTR_TYPE_UNKNOWN		},
	{ L("unresolved"),	TMPL_ATTR_TYPE_UNRESOLVED	}
};
size_t attr_table_len = NUM_ELEMENTS(attr_table);

/** Map keywords to #pair_list_t values
 */
fr_table_num_ordered_t const pair_list_table[] = {
	{ L("request"),		PAIR_LIST_REQUEST		},
	{ L("reply"),		PAIR_LIST_REPLY			},
	{ L("control"),		PAIR_LIST_CONTROL		},		/* New name should have priority */
	{ L("config"),		PAIR_LIST_CONTROL		},
	{ L("session-state"),	PAIR_LIST_STATE			},
};
size_t pair_list_table_len = NUM_ELEMENTS(pair_list_table);

/** Map keywords to #request_ref_t values
 */
fr_table_num_sorted_t const request_ref_table[] = {
	{ L("current"),		REQUEST_CURRENT			},
	{ L("outer"),		REQUEST_OUTER			},
	{ L("parent"),		REQUEST_PARENT			},
};
size_t request_ref_table_len = NUM_ELEMENTS(request_ref_table);


/** Special attribute reference indexes
 */
static fr_table_num_sorted_t const attr_num_table[] = {
	{ L("*"),		NUM_ALL				},
	{ L("#"),		NUM_COUNT			},
	{ L("any"),		NUM_ANY				},
	{ L("n"),		NUM_LAST			}
};
static size_t attr_num_table_len = NUM_ELEMENTS(attr_num_table);

static void attr_to_raw(tmpl_t *vpt, tmpl_attr_t *ref);

void tmpl_attr_ref_debug(const tmpl_attr_t *ar, int i)
{
	char buffer[sizeof(STRINGIFY(INT16_MAX)) + 1];

	snprintf(buffer, sizeof(buffer), "%i", ar->num);

	switch (ar->type) {
	case TMPL_ATTR_TYPE_NORMAL:
	case TMPL_ATTR_TYPE_UNKNOWN:
		if (!ar->da) {
			FR_FAULT_LOG("\t[%u] %s null%s%s%s",
				     i,
				     fr_table_str_by_value(attr_table, ar->type, "<INVALID>"),
				     ar->num != NUM_ANY ? "[" : "",
				     ar->num != NUM_ANY ? fr_table_str_by_value(attr_num_table, ar->num, buffer) : "",
				     ar->num != NUM_ANY ? "]" : "");
			return;
		}

		FR_FAULT_LOG("\t[%u] %s %s %s%s%s%s (%u)",
			     i,
			     fr_table_str_by_value(attr_table, ar->type, "<INVALID>"),
			     fr_table_str_by_value(fr_value_box_type_table, ar->da->type, "<INVALID>"),
			      ar->da->name,
			     ar->num != NUM_ANY ? "[" : "",
			     ar->num != NUM_ANY ? fr_table_str_by_value(attr_num_table, ar->num, buffer) : "",
			     ar->num != NUM_ANY ? "]" : "",
			     ar->da->attr
		);
		if (ar->da->parent) FR_FAULT_LOG("\t    parent     : %s", ar->da->parent->name);
		FR_FAULT_LOG("\t    is_raw     : %s", ar->da->flags.is_raw ? "yes" : "no");
		FR_FAULT_LOG("\t    is_unknown : %s", ar->da->flags.is_unknown ? "yes" : "no");
		break;


	case TMPL_ATTR_TYPE_UNRESOLVED:
		FR_FAULT_LOG("\t[%u] %s %s%s%s%s - unresolved",
			     i,
			     fr_table_str_by_value(attr_table, ar->type, "<INVALID>"),
			     ar->ar_unresolved,
			     ar->num != NUM_ANY ? "[" : "",
			     ar->num != NUM_ANY ? fr_table_str_by_value(attr_num_table, ar->num, buffer) : "",
			     ar->num != NUM_ANY ? "]" : "");
		break;

	default:
		FR_FAULT_LOG("\t[%u] Bad type %s(%u)",
			     i, fr_table_str_by_value(attr_table, ar->type, "<INVALID>"), ar->type);
		break;
	}
}

void tmpl_attr_ref_list_debug(fr_dlist_head_t const *ar_head)
{
	tmpl_attr_t		*ar = NULL;
	unsigned int		i = 0;

	FR_FAULT_LOG("attribute references:");
	/*
	 *	Print all the attribute references
	 */
	while ((ar = fr_dlist_next(ar_head, ar))) {
		tmpl_attr_ref_debug(ar, i);
		i++;
	}
}

void tmpl_attr_debug(tmpl_t const *vpt)
{
	tmpl_request_t		*rr = NULL;
	unsigned int		i = 0;

	switch (vpt->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_ATTR_UNRESOLVED:
	case TMPL_TYPE_LIST:
		break;

	default:
		FR_FAULT_LOG("%s can't print tmpls of type %s", __FUNCTION__,
			     fr_table_str_by_value(tmpl_type_table, vpt->type, "<INVALID>"));
		return;
	}

	FR_FAULT_LOG("tmpl_t %s (%.8x) \"%pV\" (%p)",
		     fr_table_str_by_value(tmpl_type_table, vpt->type, "<INVALID>"),
		     vpt->type,
		     fr_box_strvalue_len(vpt->name, vpt->len), vpt);

	FR_FAULT_LOG("\tquote  : %s", fr_table_str_by_value(fr_token_quotes_table, vpt->quote, "<INVALID>"));

	FR_FAULT_LOG("request references:");

	/*
	 *	Print all the request references
	 */
	while ((rr = fr_dlist_next(&vpt->data.attribute.rr, rr))) {
		FR_FAULT_LOG("\t[%u] %s (%u)", i,
			     fr_table_str_by_value(request_ref_table, rr->request, "<INVALID>"), rr->request);
		i++;
	}

	FR_FAULT_LOG("list: %s", fr_table_str_by_value(pair_list_table, vpt->data.attribute.list, "<INVALID>"));
	tmpl_attr_ref_list_debug(&vpt->data.attribute.ar);
}

void tmpl_debug(tmpl_t const *vpt)
{
	switch (vpt->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_ATTR_UNRESOLVED:
		tmpl_attr_debug(vpt);
		return;

	default:
		break;
	}

	FR_FAULT_LOG("tmpl_t %s (%.8x) \"%pR\" (%p)",
		     fr_table_str_by_value(tmpl_type_table, vpt->type, "<INVALID>"),
		     vpt->type,
		     fr_box_strvalue_len(vpt->name, vpt->len), vpt);

	FR_FAULT_LOG("\tquote      : %s", fr_table_str_by_value(fr_token_quotes_table, vpt->quote, "<INVALID>"));
	switch (vpt->type) {
	case TMPL_TYPE_NULL:
		return;

	case TMPL_TYPE_DATA:
		FR_FAULT_LOG("\ttype       : %s", fr_table_str_by_value(fr_value_box_type_table,
							    tmpl_value_type(vpt), "<INVALID>"));
		FR_FAULT_LOG("\tlen        : %zu", tmpl_value_length(vpt));
		FR_FAULT_LOG("\tvalue      : %pV", tmpl_value(vpt));

		if (tmpl_value_enumv(vpt)) FR_FAULT_LOG("\tenumv      : %s (%p)",
							tmpl_value_enumv(vpt)->name, tmpl_value_enumv(vpt));
		return;

	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_REGEX_XLAT:
	{
		char *str;

		xlat_aprint(NULL, &str, tmpl_xlat(vpt), NULL);

		FR_FAULT_LOG("\texpansion  : %pR", fr_box_strvalue_buffer(str));

		talloc_free(str);
	}
		break;

	case TMPL_TYPE_REGEX:
	{
		FR_FAULT_LOG("\tpattern    : %pR", fr_box_strvalue_len(vpt->name, vpt->len));
	}
		break;

	default:
		if (tmpl_needs_resolving(vpt)) {
			if (tmpl_is_unresolved(vpt)) {
				FR_FAULT_LOG("\tunescaped  : %pR", fr_box_strvalue_buffer(vpt->data.unescaped));
				FR_FAULT_LOG("\tlen        : %zu", talloc_array_length(vpt->data.unescaped) - 1);
			} else {
				FR_FAULT_LOG("\tunresolved : %pR", fr_box_strvalue_len(vpt->name, vpt->len));
				FR_FAULT_LOG("\tlen        : %zu", vpt->len);
			}
		} else {
			FR_FAULT_LOG("debug nyi");
		}
		break;
	}
}

/** @name Parse list and request qualifiers to #pair_list_t and #request_ref_t values
 *
 * These functions also resolve #pair_list_t and #request_ref_t values to #request_t
 * structs and the head of #fr_pair_t lists in those structs.
 *
 * For adding new #fr_pair_t to the lists, the #radius_list_ctx function can be used
 * to obtain the appropriate TALLOC_CTX pointer.
 *
 * @note These don't really have much to do with #tmpl_t. They're in the same
 *	file as they're used almost exclusively by the tmpl_* functions.
 * @{
 */

/** Resolve attribute name to a #pair_list_t value.
 *
 * Check the name string for #pair_list_t qualifiers and write a #pair_list_t value
 * for that list to out. This value may be passed to #radius_list, along with the current
 * #request_t, to get a pointer to the actual list in the #request_t.
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
	 *	It may be a list qualifier delimiter
	 */
	case ':':
	{
		char const *d = q + 1;

		if (isdigit((int) *d)) {
			while (isdigit((int) *d)) d++;

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

/** Resolve attribute name to a #request_ref_t value.
 *
 * Check the name string for qualifiers that reference a parent #request_t.
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

/** @} */

/** @name Alloc or initialise #tmpl_t
 *
 * @note Should not usually be called outside of tmpl_* functions, use one of
 *	the tmpl_*from_* functions instead.
 * @{
 */

/** Initialise fields inside a tmpl depending on its type
 *
 */
static inline CC_HINT(always_inline) void tmpl_type_init(tmpl_t *vpt, tmpl_type_t type)
{

 	switch (type) {
#ifndef HAVE_REGEX
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_REGEX_UNCOMPILED:
	case TMPL_TYPE_REGEX_XLAT:
	case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:
		fr_assert(0);
		return;
#endif

	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_ATTR_UNRESOLVED:
	case TMPL_TYPE_LIST:
		fr_dlist_talloc_init(&vpt->data.attribute.ar, tmpl_attr_t, entry);
		fr_dlist_talloc_init(&vpt->data.attribute.rr, tmpl_request_t, entry);
		break;

	default:
		break;
	}
 	vpt->type = type;
 }

/** Set the name on a pre-initialised tmpl
 *
 * @param[in] vpt	to set the name for.
 * @param[in] quote	Original quoting around the name.
 * @param[in] fmt	string.
 * @param[in] ...	format arguments.
 */
void tmpl_set_name_printf(tmpl_t *vpt, fr_token_t quote, char const *fmt, ...)
{
	va_list		ap;
	char const	*old = NULL;

	if (vpt->type != TMPL_TYPE_UNINITIALISED) old = vpt->name;

	va_start(ap, fmt);
	vpt->name = fr_vasprintf(vpt, fmt, ap);
	vpt->quote = quote;
	vpt->len = talloc_array_length(vpt->name) - 1;
	va_end(ap);

	talloc_const_free(old);	/* Free name last so it can be used in the format string */
}

/** Set the name on a pre-initialised tmpl
 *
 * @param[in] vpt	to set the name for.
 * @param[in] quote	Original quoting around the name.
 * @param[in] name	of the #tmpl_t.
 * @param[in] len	The length of the buffer (or a substring of the buffer) pointed to by name.
 *			If < 0 strlen will be used to determine the length.
 */
void tmpl_set_name_shallow(tmpl_t *vpt, fr_token_t quote, char const *name, ssize_t len)
{
	fr_assert(vpt->type != TMPL_TYPE_UNINITIALISED);

	vpt->name = name;
	vpt->len = len < 0 ? strlen(name) : (size_t)len;
	vpt->quote = quote;
}

/** Set the name on a pre-initialised tmpl
 *
 * @param[in] vpt	to set the name for.
 * @param[in] quote	Original quoting around the name.
 * @param[in] name	of the #tmpl_t.
 * @param[in] len	The length of the buffer (or a substring of the buffer) pointed to by name.
 *			If < 0 strlen will be used to determine the length.
 */
void tmpl_set_name(tmpl_t *vpt, fr_token_t quote, char const *name, ssize_t len)
{
	fr_assert(vpt->type != TMPL_TYPE_UNINITIALISED);

	talloc_const_free(vpt->name);

	vpt->name = talloc_bstrndup(vpt, name, len < 0 ? strlen(name) : (size_t)len);
	vpt->len = talloc_array_length(vpt->name) - 1;
	vpt->quote = quote;
}

/** Initialise a tmpl using a format string to create the name
 *
 * @param[in] vpt	to initialise.
 * @param[in] type	of tmpl to initialise.
 * @param[in] quote	Original quoting around the name.
 * @param[in] fmt	string.
 * @param[in] ...	format arguments.
 * @return A pointer to the newly initialised tmpl.
 */
tmpl_t *tmpl_init_printf(tmpl_t *vpt, tmpl_type_t type, fr_token_t quote, char const *fmt, ...)
{
	va_list		ap;

	memset(vpt, 0, sizeof(*vpt));
	tmpl_type_init(vpt, type);

	va_start(ap, fmt);
	vpt->name = fr_vasprintf(vpt, fmt, ap),
	vpt->len = talloc_array_length(vpt->name) - 1;
	vpt->quote = quote;
	va_end(ap);

	return vpt;
}

/** Initialise a tmpl without copying the input name string
 *
 * @note Name is not talloc_strdup'd or memcpy'd so must be available, and must not change
 *	for the lifetime of the #tmpl_t.
 *
 * @param[out] vpt	to initialise.
 * @param[in] type	to set in the #tmpl_t.
 * @param[in] quote	The type of quoting around the template name.
 * @param[in] name	of the #tmpl_t.
 * @param[in] len	The length of the buffer (or a substring of the buffer) pointed to by name.
 *			If < 0 strlen will be used to determine the length.
 * @return a pointer to the initialised #tmpl_t. The same value as vpt.
 */
tmpl_t *tmpl_init_shallow(tmpl_t *vpt, tmpl_type_t type, fr_token_t quote, char const *name, ssize_t len)
{
	memset(vpt, 0, sizeof(*vpt));
	tmpl_type_init(vpt, type);
	tmpl_set_name_shallow(vpt, quote, name, len);

	return vpt;
}

/** Initialise a tmpl using a literal string to create the name
 *
 * @param[in] vpt	to initialise.
 * @param[in] type	of tmpl to initialise.
 * @param[in] quote	Original quoting around the name.
 * @param[in] name	to set for the tmpl.
 * @param[in] len	Name length.  If < 0 strlen will be used
 *			to determine the name.
 * @return A pointer to the newly initialised tmpl.
 */
tmpl_t *tmpl_init(tmpl_t *vpt, tmpl_type_t type, fr_token_t quote, char const *name, ssize_t len)
{
	memset(vpt, 0, sizeof(*vpt));
	tmpl_type_init(vpt, type);
	tmpl_set_name(vpt, quote, name, len);

	return vpt;
}

/** Create a new heap allocated #tmpl_t
 *
 * Must be later initialised with a tmpl_init_* function.
 *
 * This function is provided to allow tmpls to be pre-allocated for talloc purposes before
 * their name is known.
 */
static inline CC_HINT(always_inline) tmpl_t *tmpl_alloc_null(TALLOC_CTX *ctx)
{
	tmpl_t *vpt;

	/*
	 *	Allocate enough memory to hold at least
	 *      one attribute reference and one request
	 *	reference.
	 */
	MEM(vpt = talloc_pooled_object(ctx, tmpl_t, 2, sizeof(tmpl_request_t) + sizeof(tmpl_attr_t)));
	vpt->type = TMPL_TYPE_UNINITIALISED;

	return vpt;
}

/** Create a new heap allocated #tmpl_t
 *
 * @param[in,out] ctx to allocate in.
 * @param[in] type to set in the #tmpl_t.
 * @param[in] name of the #tmpl_t (will be copied to a new talloc buffer parented
 *	by the #tmpl_t).
 * @param[in] len The length of the buffer (or a substring of the buffer) pointed to by name.
 *	If < 0 strlen will be used to determine the length.
 * @param[in] quote The type of quoting around the template name.
 * @return the newly allocated #tmpl_t.
 */
tmpl_t *tmpl_alloc(TALLOC_CTX *ctx, tmpl_type_t type, fr_token_t quote, char const *name, ssize_t len)
{
	tmpl_t *vpt;

	vpt = tmpl_alloc_null(ctx);
	memset(vpt, 0, sizeof(*vpt));

	tmpl_type_init(vpt, type);
	if (name) tmpl_set_name(vpt, quote, name, len);

	return vpt;
}
/** @} */

/** @name Create new #tmpl_t from a string
 *
 * @{
 */

 /** Allocate a new request reference and add it to the end of the attribute reference list
 *
 */
static tmpl_request_t *tmpl_req_ref_add(tmpl_t *vpt, request_ref_t request)
{
	tmpl_request_t	*rr;
	TALLOC_CTX	*ctx;

	if (fr_dlist_num_elements(&vpt->data.attribute.rr) == 0) {
		ctx = vpt;
	} else {
		ctx = fr_dlist_tail(&vpt->data.attribute.rr);
	}

	MEM(rr = talloc(ctx, tmpl_request_t));
	*rr = (tmpl_request_t){
		.request = request
	};
	fr_dlist_insert_tail(&vpt->data.attribute.rr, rr);

	return rr;
}

/** Allocate a new attribute reference and add it to the end of the attribute reference list
 *
 */
static tmpl_attr_t *tmpl_attr_add(tmpl_t *vpt, tmpl_attr_type_t type)
{
	tmpl_attr_t	*ar;
	TALLOC_CTX	*ctx;

	if (fr_dlist_num_elements(&vpt->data.attribute.ar) == 0) {
		ctx = vpt;
	} else {
		ctx = fr_dlist_tail(&vpt->data.attribute.ar);
	}

	MEM(ar = talloc(ctx, tmpl_attr_t));
	*ar = (tmpl_attr_t){
		.type = type,
		.num = NUM_ANY
	};
	fr_dlist_insert_tail(&vpt->data.attribute.ar, ar);

	return ar;
}

/** Create a #tmpl_t from a #fr_value_box_t
 *
 * @param[in,out] ctx	to allocate #tmpl_t in.
 * @param[out] out	Where to write pointer to new #tmpl_t.
 * @param[in] data	to convert.
 * @param[in] steal	If true, any buffers are moved to the new
 *			ctx instead of being duplicated.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_afrom_value_box(TALLOC_CTX *ctx, tmpl_t **out, fr_value_box_t *data, bool steal)
{
	char		*name;
	size_t		len;
	tmpl_t		*vpt;
	fr_token_t	quote = (data->type == FR_TYPE_STRING) ? T_SINGLE_QUOTED_STRING : T_BARE_WORD;

	MEM(vpt = talloc(ctx, tmpl_t));
	len = fr_value_box_aprint(vpt, &name, data, fr_value_escape_by_quote[quote]);
	tmpl_init_shallow(vpt, TMPL_TYPE_DATA, quote, name, len);

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

/** Copy a list of attribute and request references from one tmpl to another
 *
 */
int tmpl_attr_copy(tmpl_t *dst, tmpl_t const *src)
{
	tmpl_attr_t		*src_ar = NULL, *dst_ar;
	tmpl_request_t	*src_rr = NULL, *dst_rr;

	/*
	 *	Clear any existing attribute references
	 */
	if (fr_dlist_num_elements(&dst->data.attribute.ar) > 0) fr_dlist_talloc_reverse_free(&dst->data.attribute.ar);

	while ((src_ar = fr_dlist_next(&src->data.attribute.ar, src_ar))) {
		dst_ar = tmpl_attr_add(dst, src_ar->type);

		switch (src_ar->type) {
	 	case TMPL_ATTR_TYPE_NORMAL:
	 		dst_ar->ar_da = src_ar->ar_da;
	 		break;

	 	case TMPL_ATTR_TYPE_UNKNOWN:
	 		dst_ar->ar_unknown = fr_dict_unknown_afrom_da(dst_ar, src_ar->ar_unknown);
	 		break;

	 	case TMPL_ATTR_TYPE_UNRESOLVED:
	 		dst_ar->ar_unresolved = talloc_bstrdup(dst_ar, src_ar->ar_unresolved);
	 		break;

	 	default:
	 		if (!fr_cond_assert(0)) return -1;
	 	}
	 	dst_ar->ar_num = src_ar->ar_num;
	}

	/*
	 *	Clear any existing request references
	 */
	if (fr_dlist_num_elements(&dst->data.attribute.rr) > 0) fr_dlist_talloc_reverse_free(&dst->data.attribute.rr);

	while ((src_rr = fr_dlist_next(&src->data.attribute.rr, src_rr))) {
		MEM(dst_rr = tmpl_req_ref_add(dst, src_rr->request));
	}

	/*
	 *	Remove me...
	 */
	dst->data.attribute.list = src->data.attribute.list;

	TMPL_ATTR_VERIFY(dst);

	return 0;
}

/** Replace the current attribute reference
 *
 */
int tmpl_attr_set_da(tmpl_t *vpt, fr_dict_attr_t const *da)
{
	tmpl_attr_t *ref;

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
		ref = tmpl_attr_add(vpt, TMPL_ATTR_TYPE_UNKNOWN);
		ref->da = ref->ar_unknown = fr_dict_unknown_afrom_da(vpt, da);
	} else {
		ref = tmpl_attr_add(vpt, TMPL_ATTR_TYPE_NORMAL);
		ref->da = da;
	}

	TMPL_ATTR_VERIFY(vpt);

	return 0;
}

/** Replace the leaf attribute only
 *
 */
int tmpl_attr_set_leaf_da(tmpl_t *vpt, fr_dict_attr_t const *da)
{
	tmpl_attr_t *ref, *parent = NULL;

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
		 *	Free old unknown and unresolved attributes...
		 */
		talloc_free_children(ref);
	} else {
		ref = tmpl_attr_add(vpt, da->flags.is_unknown ? TMPL_ATTR_TYPE_UNKNOWN : TMPL_ATTR_TYPE_NORMAL);
	}


	/*
	 *	Unknown attributes get copied
	 */
	if (da->flags.is_unknown) {
		ref->type = TMPL_ATTR_TYPE_UNKNOWN;
		ref->da = ref->ar_unknown = fr_dict_unknown_afrom_da(vpt, da);
	} else {
		ref->type = TMPL_ATTR_TYPE_NORMAL;
		ref->da = da;
	}

	TMPL_ATTR_VERIFY(vpt);

	return 0;
}

void tmpl_attr_set_leaf_num(tmpl_t *vpt, int16_t num)
{
	tmpl_attr_t *ref;

	tmpl_assert_type(tmpl_is_attr(vpt) || tmpl_is_list(vpt) || tmpl_is_attr_unresolved(vpt));

	if (fr_dlist_num_elements(&vpt->data.attribute.ar) == 0) {
		ref = tmpl_attr_add(vpt, TMPL_ATTR_TYPE_UNKNOWN);
	} else {
		ref = fr_dlist_tail(&vpt->data.attribute.ar);
	}

	ref->num = num;

	TMPL_ATTR_VERIFY(vpt);
}

/** Rewrite the leaf's instance number
 *
 */
void tmpl_attr_rewrite_leaf_num(tmpl_t *vpt, int16_t from, int16_t to)
{
	tmpl_attr_t *ref = NULL;

	tmpl_assert_type(tmpl_is_attr(vpt) || tmpl_is_list(vpt) || tmpl_is_attr_unresolved(vpt));

	if (fr_dlist_num_elements(&vpt->data.attribute.ar) == 0) return;

	ref = fr_dlist_tail(&vpt->data.attribute.ar);
	if (ref->ar_num == from) ref->ar_num = to;

	TMPL_ATTR_VERIFY(vpt);
}

/** Rewrite all instances of an array number
 *
 */
void tmpl_attr_rewrite_num(tmpl_t *vpt, int16_t from, int16_t to)
{
	tmpl_attr_t *ref = NULL;

	tmpl_assert_type(tmpl_is_attr(vpt) || tmpl_is_list(vpt) || tmpl_is_attr_unresolved(vpt));

	while ((ref = fr_dlist_next(&vpt->data.attribute.ar, ref))) if (ref->ar_num == from) ref->ar_num = to;

	TMPL_ATTR_VERIFY(vpt);
}

/** Set the request for an attribute ref
 *
 */
void tmpl_attr_set_request(tmpl_t *vpt, request_ref_t request)
{
	fr_assert_msg(tmpl_is_attr(vpt), "Expected tmpl type 'attr', got '%s'",
		      fr_table_str_by_value(tmpl_type_table, vpt->type, "<INVALID>"));

	if (fr_dlist_num_elements(&vpt->data.attribute.rr) > 0) fr_dlist_talloc_reverse_free(&vpt->data.attribute.rr);

	tmpl_req_ref_add(vpt, request);

	TMPL_ATTR_VERIFY(vpt);
}

void tmpl_attr_set_list(tmpl_t *vpt, pair_list_t list)
{
	vpt->data.attribute.list = list;

	TMPL_ATTR_VERIFY(vpt);
}

/** Create a new tmpl from a list tmpl and a da
 *
 */
int tmpl_attr_afrom_list(TALLOC_CTX *ctx, tmpl_t **out, tmpl_t const *list, fr_dict_attr_t const *da)
{
	tmpl_t *vpt;

	char attr[256];
	ssize_t slen;

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_ATTR, T_BARE_WORD, NULL, 0));

	/*
	 *	Copies request refs and the list ref
	 */
	tmpl_attr_copy(vpt, list);
	tmpl_attr_set_list(vpt, tmpl_list(list));	/* Remove when lists are attributes */
	tmpl_attr_set_leaf_da(vpt, da);			/* This should add a new da when lists are attributes */
	tmpl_attr_set_leaf_num(vpt, tmpl_num(list));

	/*
	 *	We need to rebuild the attribute name, to be the
	 *	one we copied from the source list.
	 */
	slen = tmpl_print(&FR_SBUFF_OUT(attr, sizeof(attr)), vpt, TMPL_ATTR_REF_PREFIX_YES,
			  fr_value_escape_by_quote[list->quote]);
	if (slen < 0) {
		fr_strerror_printf("Serialized attribute too long.  Must be < "
				   STRINGIFY(sizeof(attr)) " bytes, got %zu bytes", (size_t)-slen);
		talloc_free(vpt);
		return -1;
	}

	vpt->len = (size_t)slen;
	vpt->name = talloc_typed_strdup(vpt, attr);
	vpt->quote = T_BARE_WORD;

	TMPL_ATTR_VERIFY(vpt);

	*out = vpt;

	return 0;
}
/** @} */

/** @name Produce a #tmpl_t from a string or substring
 *
 * @{
 */

/** Default parser rules
 *
 * Because this is getting to be a ridiculous number of parsing rules
 * to pass in via arguments.
 *
 * Defaults are used if a NULL rules pointer is passed to the parsing function.
 */
static tmpl_rules_t const default_attr_rules = {
	.request_def = REQUEST_CURRENT,
	.list_def = PAIR_LIST_REQUEST
};

/** Default formatting rules
 *
 * Control token termination, escaping and how the tmpl is printed.
 */
fr_sbuff_parse_rules_t const tmpl_parse_rules_bareword_unquoted = {

};

fr_sbuff_parse_rules_t const tmpl_parse_rules_double_unquoted = {
	.escapes = &fr_value_unescape_double
};

fr_sbuff_parse_rules_t const tmpl_parse_rules_single_unquoted = {
	.escapes = &fr_value_unescape_single
};

fr_sbuff_parse_rules_t const tmpl_parse_rules_solidus_unquoted = {
	.escapes = &fr_value_unescape_solidus
};

fr_sbuff_parse_rules_t const tmpl_parse_rules_backtick_unquoted = {
	.escapes = &fr_value_unescape_backtick
};

/** Parse rules for non-quoted strings
 *
 * These parse rules should be used for processing escape sequences in
 * data from external data sources like SQL databases and REST APIs.
 *
 * They do not include terminals to stop parsing as it assumes the values
 * are discreet, and not wrapped in quotes.
 */
fr_sbuff_parse_rules_t const *tmpl_parse_rules_unquoted[T_TOKEN_LAST] = {
	[T_BARE_WORD]			= &tmpl_parse_rules_bareword_unquoted,
	[T_DOUBLE_QUOTED_STRING]	= &tmpl_parse_rules_double_unquoted,
	[T_SINGLE_QUOTED_STRING]	= &tmpl_parse_rules_single_unquoted,
	[T_SOLIDUS_QUOTED_STRING]	= &tmpl_parse_rules_solidus_unquoted,
	[T_BACK_QUOTED_STRING]		= &tmpl_parse_rules_backtick_unquoted
};

fr_sbuff_parse_rules_t const tmpl_parse_rules_bareword_quoted = {
	.escapes = &(fr_sbuff_unescape_rules_t){
		.chr = '\\',
		/*
		 *	Allow barewords to contain whitespace
		 *	if they're escaped.
		 */
		.subs = {
			['\t'] = '\t',
			['\n'] = '\n',
			[' '] = ' '
		},
		.do_hex = false,
		.do_oct = false
	},
	.terminals = &FR_SBUFF_TERMS(
		L("\t"),
		L("\n"),
		L(" ")
	)
};

fr_sbuff_parse_rules_t const tmpl_parse_rules_double_quoted = {
	.escapes = &fr_value_unescape_double,
	.terminals = &FR_SBUFF_TERM("\"")
};

fr_sbuff_parse_rules_t const tmpl_parse_rules_single_quoted = {
	.escapes = &fr_value_unescape_single,
	.terminals = &FR_SBUFF_TERM("'")
};

fr_sbuff_parse_rules_t const tmpl_parse_rules_solidus_quoted = {
	.escapes = &fr_value_unescape_solidus,
	.terminals = &FR_SBUFF_TERM("/")
};

fr_sbuff_parse_rules_t const tmpl_parse_rules_backtick_quoted = {
	.escapes = &fr_value_unescape_backtick,
	.terminals = &FR_SBUFF_TERM("`")
};

/** Parse rules for quoted strings
 *
 * These parse rules should be used for internal parsing functions that
 * are working with configuration files.
 *
 * They include appropriate quote terminals to force functions parsing
 * quoted strings to return when they reach a quote character.
 */
fr_sbuff_parse_rules_t const *tmpl_parse_rules_quoted[T_TOKEN_LAST] = {
	[T_BARE_WORD]			= &tmpl_parse_rules_bareword_quoted,
	[T_DOUBLE_QUOTED_STRING]	= &tmpl_parse_rules_double_quoted,
	[T_SINGLE_QUOTED_STRING]	= &tmpl_parse_rules_single_quoted,
	[T_SOLIDUS_QUOTED_STRING]	= &tmpl_parse_rules_solidus_quoted,
	[T_BACK_QUOTED_STRING]		= &tmpl_parse_rules_backtick_quoted
};

/** Verify, after skipping whitespace, that a substring ends in a terminal char, or ends without further chars
 *
 * @param[in] in	the sbuff to check.
 * @param[in] p_rules	to use terminals from.
 * @return
 *	- true if substr is terminated correctly.
 *	- false if subst is not terminated correctly.
 */
static inline bool CC_HINT(always_inline) tmpl_substr_terminal_check(fr_sbuff_t *in,
								     fr_sbuff_parse_rules_t const *p_rules)
{
	fr_sbuff_marker_t	m;
	bool			ret;

	if (!fr_sbuff_extend(in)) return true;		/* we're at the end of the string */
	if (!p_rules || !p_rules->terminals) return false;	/* more stuff to parse but don't have a terminal set */

	fr_sbuff_marker(&m, in);
	ret = fr_sbuff_is_terminal(in, p_rules->terminals);
	fr_sbuff_set(in, &m);
	fr_sbuff_marker_release(&m);
	return ret;
}

/** Descriptive return values for filter parsing
 *
 */
typedef enum {
	TMPL_ATTR_REF_HAS_FILTER = 1,
	TMPL_ATTR_REF_NO_FILTER = 0,
	TMPL_ATTR_REF_BAD_FILTER = -1
} tmpl_attr_filter_t;

/** Insert an attribute reference into a tmpl
 *
 * Not all attribute references can be used to create new attributes,
 * for example those accessing instance > 0 or those that resolve
 * to special indexes.
 *
 * We mark up these references and their parents as resolve only
 * meaning that if any code needs to use a reference chain to build
 * out a pair tree, it bails out early.
 *
 * @param[in] vpt	containing the reference list.
 * @param[in] ar	to insert and check.
 */
static inline CC_HINT(always_inline) void tmpl_attr_insert(tmpl_t *vpt, tmpl_attr_t *ar)
{
	/*
	 *	Insert the reference into the list.
	 */
	fr_dlist_insert_tail(&vpt->data.attribute.ar, ar);

	switch (ar->num) {
	case 0:
	case NUM_ANY:
		break;

	default:
		ar->resolve_only = true;
		while ((ar = fr_dlist_prev(&vpt->data.attribute.ar, ar))) ar->resolve_only = true;
		break;
	}
}

/** Parse array subscript and in future other filters
 *
 * @param[out] err	Parse error code.
 * @param[in] ar	to populate filter for.
 * @param[in] name	containing more attribute ref data.
 * @return
 *	- TMPL_ATTR_REF_HAS_FILTER on success with filter parsed.
 *	- TMPL_ATTR_REF_NO_FILTER on success with no filter.
 *	- TMPL_ATTR_REF_BAD_FILTER on failure.
 */
static tmpl_attr_filter_t tmpl_attr_parse_filter(tmpl_attr_error_t *err, tmpl_attr_t *ar, fr_sbuff_t *name)
{
	/*
	 *	Parse array subscript (and eventually complex filters)
	 */
	if (!fr_sbuff_next_if_char(name, '[')) return TMPL_ATTR_REF_NO_FILTER;

	switch (*fr_sbuff_current(name)) {
	case '#':
		ar->num = NUM_COUNT;
		fr_sbuff_next(name);
		break;

	case '*':
		ar->num = NUM_ALL;
		fr_sbuff_next(name);
		break;

	case 'n':
		ar->num = NUM_LAST;
		fr_sbuff_next(name);
		break;

	default:
	{
		fr_sbuff_parse_error_t	sberr = FR_SBUFF_PARSE_OK;
		fr_sbuff_t tmp = FR_SBUFF_NO_ADVANCE(name);

		if (fr_sbuff_out(&sberr, &ar->num, &tmp) == 0) {
			if (sberr == FR_SBUFF_PARSE_ERROR_NOT_FOUND) {
				fr_strerror_printf("Invalid array index");
				if (err) *err = TMPL_ATTR_ERROR_INVALID_ARRAY_INDEX;
			error:
				return TMPL_ATTR_REF_BAD_FILTER;
			}

			fr_strerror_printf("Invalid array index");
			if (err) *err = TMPL_ATTR_ERROR_INVALID_ARRAY_INDEX;
			goto error;
		}

		if ((ar->num > 1000) || (ar->num < 0)) {
			fr_strerror_printf("Invalid array index '%hi' (should be between 0-1000)", ar->num);
			ar->num = 0;
			if (err) *err = TMPL_ATTR_ERROR_INVALID_ARRAY_INDEX;
			goto error;
		}
		fr_sbuff_set(name, &tmp);	/* Advance name _AFTER_ doing checks */
	}
		break;
	}

	/*
	 *	Always advance here, so the error
	 *	marker points to the bad char.
	 */
	if (!fr_sbuff_next_if_char(name, ']')) {
		fr_strerror_printf("No closing ']' for array index");
		if (err) *err = TMPL_ATTR_ERROR_INVALID_ARRAY_INDEX;
		goto error;
	}

	return TMPL_ATTR_REF_HAS_FILTER;
}

/** Parse an unresolved attribute, i.e. one which can't be found in the current dictionary
 *
 * This function calls itself recursively to process additional OID
 * components once we've failed to resolve one component.
 *
 * @note Do not call directly.
 *
 * @param[in] ctx		to allocate new attribute reference in.
 * @param[out] err		Parse error.
 * @param[in,out] vpt		to append this reference to.
 * @param[in] parent		Last known parent.
 * @param[in] name		to parse.
 * @param[in] rules		see tmpl_attr_afrom_attr_substr.
 * @param[in] depth		How deep we are.  Used to check for maximum nesting level.
 * @return
 *	- <0 on error.
 *	- 0 on success.
 */
static inline int tmpl_attr_afrom_attr_unresolved_substr(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
							 tmpl_t *vpt, fr_dict_attr_t const *parent,
							 fr_sbuff_t *name, tmpl_rules_t const *rules,
							 unsigned int depth)
{
	tmpl_attr_t		*ar = NULL;
	int			ret;
	char			*unresolved;
	size_t			len;

	if (depth > FR_DICT_MAX_TLV_STACK) {
		fr_strerror_printf("Attribute nesting too deep");
		if (err) *err = TMPL_ATTR_ERROR_NESTING_TOO_DEEP;
		return -1;
	}

	/*
	 *	Input too short
	 */
	if (!fr_sbuff_extend(name)) {
		fr_strerror_printf("Missing attribute reference");
		if (err) *err = TMPL_ATTR_ERROR_INVALID_NAME;
		return -1;
	}

	/*
	 *	Mark the tmpl up as an unresolved attribute reference
	 *	the attribute reference will be resolved later.
	 */
	vpt->type = TMPL_TYPE_ATTR_UNRESOLVED;

	MEM(ar = talloc(ctx, tmpl_attr_t));
	/*
	 *	Copy out a string of allowed dictionary chars to form
	 *	the unresolved attribute name.
	 *
	 *	This will be resolved later (outside of this function).
	 */
	len = fr_sbuff_out_abstrncpy_allowed(ar, &unresolved,
					     name, FR_DICT_ATTR_MAX_NAME_LEN + 1,
					     fr_dict_attr_allowed_chars);
	if (len == 0) {
		fr_strerror_printf("Invalid attribute name");
		if (err) *err = TMPL_ATTR_ERROR_INVALID_NAME;
	error:
		talloc_free(ar);
		return -1;
	}
	if (len > FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_printf("Attribute name is too long");
		if (err) *err = TMPL_ATTR_ERROR_INVALID_NAME;
		goto error;
	}

	*ar = (tmpl_attr_t){
		.ar_num = NUM_ANY,
		.ar_type = TMPL_ATTR_TYPE_UNRESOLVED,
		.ar_unresolved = unresolved,
		.ar_unresolved_parent = parent
	};

	if (tmpl_attr_parse_filter(err, ar, name) < 0) goto error;

	/*
	 *	Insert the ar into the list of attribute references
	 */
	tmpl_attr_insert(vpt, ar);

	/*
	 *	Once one OID component is created as unresolved all
	 *	future OID components are also unresolved.
	 */
	if (fr_sbuff_next_if_char(name, '.')) {
		ret = tmpl_attr_afrom_attr_unresolved_substr(ctx, err, vpt, NULL, name, rules, depth + 1);
		if (ret < 0) {
			fr_dlist_talloc_free_tail(&vpt->data.attribute.ar); /* Remove and free ar */
			return -1;
		}
	}

	return 0;
}

/** Parse an attribute reference, either an OID or attribute name
 *
 * @note Do not call directly.
 *
 * @param[in] ctx		to allocate new attribute reference in.
 * @param[out] err		Parse error.
 * @param[in,out] vpt		to append this reference to.
 * @param[in] parent		Result of parsing the previous attribute reference.
 * @param[in] name		to parse.
 * @param[in] p_rules		Formatting rules used to check for trailing garbage.
 * @param[in] t_rules		which places constraints on attribute reference parsing.
 *				Rules interpreted by this function is:
 *				- allow_unknown - If false unknown OID components
 *				  result in a parse error.
 *				- allow_unresolved - If false unknown attribute names
 *				  result in a parse error.
 *				- disallow_internal - If an attribute resolves in the
 *				  internal dictionary then that results in a parse
 *				  error.
 *				- allow_foreign - If an attribute resolves in a dictionary
 *				  that does not match the parent
 *				  (exception being FR_TYPE_GROUP) then that results
 *				  in a parse error.
 * @param[in] depth		How deep we are.  Used to check for maximum nesting level.
 * @return
 *	- <0 on error.
 *	- 0 on success.
 */
static inline int tmpl_attr_afrom_attr_substr(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
					      tmpl_t *vpt,
					      fr_dict_attr_t const *parent,
					      fr_sbuff_t *name,
					      fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
					      unsigned int depth)
{
	uint32_t		oid = 0;
	ssize_t			slen;
	tmpl_attr_t		*ar = NULL;
	fr_dict_attr_t const	*da;
	fr_sbuff_marker_t	m_s;
	tmpl_attr_filter_t	filter;
	fr_dict_attr_err_t	dict_err;

	fr_sbuff_marker(&m_s, name);

	if (depth > FR_DICT_MAX_TLV_STACK) {
		fr_strerror_printf("Attribute nesting too deep");
		if (err) *err = TMPL_ATTR_ERROR_NESTING_TOO_DEEP;
	error:
		fr_sbuff_marker_release(&m_s);
		return -1;
	}

	/*
	 *	Input too short
	 */
	if (!fr_sbuff_extend(name)) {
		fr_strerror_printf("Missing attribute reference");
		if (err) *err = TMPL_ATTR_ERROR_INVALID_NAME;
		goto error;
	}

	/*
	 *	No parent means we need to go hunting through all the dictionaries
	 */
	if (!parent) {
		slen = fr_dict_attr_by_qualified_name_substr(&dict_err, &da,
							     t_rules->dict_def,
							     name, p_rules ? p_rules->terminals : NULL,
							     !t_rules->disallow_internal);
	/*
	 *	Otherwise we're resolving in the context of the last component,
	 *	or its reference in the case of group attributes.
	 */
	} else {
		slen = fr_dict_attr_child_by_name_substr(&dict_err, &da, parent, name, false);
	}

	/*
	 *	Fatal errors related to nesting...
	 */
	switch (dict_err) {
	case FR_DICT_ATTR_NO_CHILDREN:
		if (parent && parent->flags.is_unknown) break;
		goto error;

	case FR_DICT_ATTR_NOT_DESCENDENT:
		goto error;

	default:
		break;
	}

	/*
	 *	The named component was a known attribute
	 *	so record it as a normal attribute
	 *	reference.
	 */
	if (slen > 0) {
		MEM(ar = talloc(ctx, tmpl_attr_t));
		*ar = (tmpl_attr_t){
			.ar_num = NUM_ANY,
			.ar_type = TMPL_ATTR_TYPE_NORMAL,
			.ar_da = da
		};

		goto check_attr;
	}

	/*
	 *	See if the ref begins with an unsigned integer
	 *	if it does it's probably an OID component
	 *
	 *	.<oid>
	 */
	slen = fr_sbuff_out(NULL, &oid, name);
	if (slen > 0) {
		fr_dict_attr_t *da_unknown;

		fr_strerror();	/* Clear out any existing errors */

		/*
		 *	Locating OID attributes is different than
		 *	locating named attributes because we have
		 *	significantly more numberspace overlap
		 *	between the protocols.
		 */
		if (!parent && t_rules->dict_def) parent = fr_dict_root(t_rules->dict_def);
		if (!parent && !t_rules->disallow_internal) parent = fr_dict_root(fr_dict_internal());
		if (!parent) {
			fr_strerror_printf("OID references must be qualified with a protocol when used here");
			if (err) *err = TMPL_ATTR_ERROR_UNQUALIFIED_NOT_ALLOWED;
			fr_sbuff_set(name, &m_s);
			goto error;
		}
		/*
		 *	If it's numeric and not a known attribute
		 *      then we create an unknown attribute with
		 *	the specified attribute number.
		 */
		da = fr_dict_attr_child_by_num(parent, oid);
		if (da) {
			/*
			 *	The OID component was a known attribute
			 *	so record it as a normal attribute
			 *	reference.
			 */
			MEM(ar = talloc(ctx, tmpl_attr_t));
			*ar = (tmpl_attr_t){
				.ar_num = NUM_ANY,
				.ar_type = TMPL_ATTR_TYPE_NORMAL,
				.ar_da = da,
			};
			vpt->data.attribute.was_oid = true;

			goto check_attr;
		}

		if (!t_rules->allow_unknown) {
			fr_strerror_printf("Unknown attributes not allowed here");
			if (err) *err = TMPL_ATTR_ERROR_UNKNOWN_NOT_ALLOWED;
			fr_sbuff_set(name, &m_s);
			goto error;
		}

		MEM(ar = talloc(ctx, tmpl_attr_t));

		switch (parent->type) {
		case FR_TYPE_VSA:
			da_unknown = fr_dict_unknown_vendor_afrom_num(ar, parent, oid);
			if (!da_unknown) {
				if (err) *err = TMPL_ATTR_ERROR_UNKNOWN_NOT_ALLOWED;	/* strerror set by dict function */
				goto error;
			}
			break;

		default:
			da_unknown = fr_dict_unknown_attr_afrom_num(ar, parent, oid);
			if (!da_unknown) {
				if (err) *err = TMPL_ATTR_ERROR_UNKNOWN_NOT_ALLOWED;	/* strerror set by dict function */
				goto error;
			}
			break;
		}
		da_unknown->flags.internal = 1;

		*ar = (tmpl_attr_t){
			.ar_num = NUM_ANY,
			.ar_type = TMPL_ATTR_TYPE_UNKNOWN,
			.ar_unknown = da_unknown,
			.ar_da = da_unknown,
		};
		da = da_unknown;
		vpt->data.attribute.was_oid = true;
		goto do_suffix;
	}

	/*
	 *	Can't parse it as an attribute, might be a literal string
	 *	let the caller decide.
	 *
	 *	Don't alter the fr_strerror buffer, may contain useful
	 *	errors from the dictionary code.
	 */
	if (!t_rules->allow_unresolved) {
		fr_strerror_printf_push("Unresolved attributes not allowed here");
		if (err) *err = TMPL_ATTR_ERROR_UNRESOLVED_NOT_ALLOWED;
		fr_sbuff_set(name, &m_s);
		goto error;
	}

	fr_sbuff_marker_release(&m_s);

	/*
	 *	Once we hit one unresolved attribute we have to treat
	 *	the rest of the components are unresolved as well.
	 */
	return tmpl_attr_afrom_attr_unresolved_substr(ctx, err, vpt, parent, name, t_rules, depth);

check_attr:
	/*
	 *	Attribute location (dictionary) checks
	 */
	if (!t_rules->allow_foreign || t_rules->disallow_internal) {
		fr_dict_t const *found_in = fr_dict_by_da(da);

		/*
		 *	Parent is the dict root if this is the first ref in the
		 *	chain.
		 */
		if (!parent) parent = fr_dict_root(t_rules->dict_def);

		/*
		 *	Even if allow_foreign is false, if disallow_internal is not
		 *	true, we still allow the resolution.
		 */
		if (t_rules->disallow_internal && (found_in == fr_dict_internal())) {
			fr_strerror_printf("Internal attributes not allowed here");
			if (err) *err = TMPL_ATTR_ERROR_INTERNAL_NOT_ALLOWED;
			fr_sbuff_set(name, &m_s);
			goto error;
		}
		/*
		 *	Check that the attribute we resolved was from an allowed
		 *	dictionary.
		 *
		 *	We already checked if internal attributes were disallowed
		 *	above, so we skip this check if the attribute is internal.
		 *
		 * 	The reason this checks works with foreign attributes is
		 *	because when an attr ref resolves to a group parent is not
		 *	set to that attribute, but the foreign dictionary attribute
		 *	that it references.
		 *
		 *	My-Dhcp-In-RADIUS-Attribute.My-DHCP-Attribute
		 *	|			  ||_ DHCP attribute
		 *	|			  |_ Lookup inside linking attribute triggers dictionary change
		 *	|_ RADIUS attribute
		 */
		if (found_in != fr_dict_internal() &&
		    !t_rules->allow_foreign && (found_in != fr_dict_by_da(parent))) {
			fr_strerror_printf("Foreign %s attribute found.  Only %s attributes are allowed here",
					   fr_dict_root(found_in)->name,
					   fr_dict_root(t_rules->dict_def)->name);
			if (err) *err = TMPL_ATTR_ERROR_FOREIGN_NOT_ALLOWED;
			fr_sbuff_set(name, &m_s);
			goto error;
		}
	}

do_suffix:
	/*
	 *	Parse the attribute reference filter
	 *
	 *	Error out immediately if the filter is bad
	 *	otherwise determine whether to keep the
	 *	attribute reference or omit it based on:
	 *
	 *	- Whether there was a filter present.
	 *	- The type of attribute.
	 *	- If this is the leaf attribute reference.
	 */
	if ((filter = tmpl_attr_parse_filter(err, ar, name)) == TMPL_ATTR_REF_BAD_FILTER) goto error;

	/*
	 *	At the end of the attribute reference. If there's a
	 *	trailing '.' then there's another attribute reference
	 *	we need to parse, otherwise we're done.
	 */
	fr_sbuff_marker_release(&m_s);
	fr_sbuff_marker(&m_s, name);
	if (fr_sbuff_next_if_char(name, '.')) {
		switch (da->type) {
		/*
		 *	If this is a group then the parent is the
		 *	group ref.
		 */
		case FR_TYPE_GROUP:
			parent = fr_dict_attr_ref(da);
			break;

		case FR_TYPE_STRUCT:
		case FR_TYPE_TLV:
		case FR_TYPE_VENDOR:
		case FR_TYPE_VSA:
			/*
			 *	Omit nesting types where the relationship is already
			 *	described by the dictionaries and there's no filter.
			 *
			 *	These attribute references would just use additional
			 *	memory for no real purpose.
			 *
			 *	Because we pre-allocate an attribute reference in
			 *	each tmpl talloc pool, unless the attribute
			 *	reference list contains a group, there's no performance
			 *	penalty in repeatedly allocating and freeing this ar.
			 */
			if ((filter == TMPL_ATTR_REF_NO_FILTER) && (ar->type == TMPL_ATTR_TYPE_NORMAL)) {
				TALLOC_FREE(ar);
			}
			parent = da;
			break;

		default:
			fr_strerror_printf("Parent type of nested attribute must be of "
					   "\"struct\", \"tlv\", \"vendor\", \"vsa\" or \"group\", got \"%s\"",
					   fr_table_str_by_value(fr_value_box_type_table,
					   			 da->type, "<INVALID>"));
			fr_sbuff_set(name, &m_s);
			goto error;
		}

		if (ar) tmpl_attr_insert(vpt, ar);
		if (tmpl_attr_afrom_attr_substr(ctx, err, vpt, parent, name, p_rules, t_rules, depth + 1) < 0) {
			if (ar) fr_dlist_talloc_free_tail(&vpt->data.attribute.ar); /* Remove and free ar */
			goto error;
		}
	/*
	 *	If it's a leaf we always insert the attribute
	 *	reference into the list, even if it's a
	 *	nesting attribute.
	 *
	 *	This is useful for nested update sections
	 *	where the tmpl might be the name of a new
	 *	subsection.
	 */
	} else {
		tmpl_attr_insert(vpt, ar);
	}

	fr_sbuff_marker_release(&m_s);

	return 0;
}

static inline int tmpl_request_ref_afrom_attr_substr(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
						     tmpl_t *vpt,
						     fr_sbuff_t *name,
						     fr_sbuff_parse_rules_t const *p_rules,
					      	     tmpl_rules_t const *t_rules,
					      	     unsigned int depth)
{
	request_ref_t		ref;
	size_t			ref_len;
	tmpl_request_t		*rr;
	fr_dlist_head_t		*list = &vpt->data.attribute.rr;
	fr_sbuff_marker_t	s_m;

	fr_sbuff_marker(&s_m, name);
	fr_sbuff_out_by_longest_prefix(&ref_len, &ref, request_ref_table, name, t_rules->request_def);

	/*
	 *	No match
	 */
	if (ref_len == 0) {
		/*
		 *	If depth == 0, then just use
		 *	the default request reference.
		 */
	default_ref:
		if (depth == 0) {
			MEM(rr = talloc(ctx, tmpl_request_t));
			*rr = (tmpl_request_t){
				.request = ref
			};
			fr_dlist_insert_tail(list, rr);
		}

		return 0;
	}

	/*
	 *	We don't want to misidentify the list
	 *	as being part of an attribute.
	 */
	if (!fr_sbuff_is_char(name, '.') &&
	    ((!p_rules || !p_rules->terminals) ||
	    !tmpl_substr_terminal_check(name, p_rules))) {
	    	fr_sbuff_set(name, &s_m);
	    	goto default_ref;
	}

	fr_sbuff_marker_release(&s_m);

	/*
	 *	Nesting level too deep
	 */
	if (depth > TMPL_MAX_REQUEST_REF_NESTING) {
		fr_strerror_printf("Request ref nesting too deep");
		if (err) *err = TMPL_ATTR_ERROR_NESTING_TOO_DEEP;
		return -1;
	}

	if (t_rules->attr_parent || t_rules->disallow_qualifiers) {
		fr_strerror_printf("It is not permitted to specify a request reference here");
		if (err) *err = TMPL_ATTR_ERROR_INVALID_LIST_QUALIFIER;
		return -1;
	}

	/*
	 *	Add a new entry to the dlist
	 */
	MEM(rr = talloc(ctx, tmpl_request_t));
	*rr = (tmpl_request_t){
		.request = ref
	};
	fr_dlist_insert_tail(list, rr);

	/*
	 *	Advance past the separator (if there is one)
	 */
	if (fr_sbuff_next_if_char(name, '.')) {
		if (tmpl_request_ref_afrom_attr_substr(ctx, err, vpt, name, p_rules, t_rules, depth + 1) < 0) {
			fr_dlist_talloc_free_tail(list); /* Remove and free rr */
			return -1;
		}
	}

	return 0;
}

/** Parse a string into a TMPL_TYPE_ATTR_* or #TMPL_TYPE_LIST type #tmpl_t
 *
 * @param[in,out] ctx		to allocate #tmpl_t in.
 * @param[out] err		May be NULL.  Provides the exact error that the parser hit
 *				when processing the attribute ref.
 * @param[out] out		Where to write pointer to new #tmpl_t.
 * @param[in] name		of attribute including #request_ref_t and #pair_list_t qualifiers.
 *				If only #request_ref_t #pair_list_t qualifiers are found,
 *				a #TMPL_TYPE_LIST #tmpl_t will be produced.
 * @param[in] p_rules		Formatting rules used to check for trailing garbage.
 * @param[in] t_rules		Rules which control parsing:
 *				- dict_def		The default dictionary to use if attributes
 *							are unqualified.
 *				- request_def		The default #request_t to set if no
 *							#request_ref_t qualifiers are found in name.
 *				- list_def		The default list to set if no #pair_list_t
 *							qualifiers are found in the name.
 *				- allow_unknown		If true attributes in the format accepted by
 *							#fr_dict_unknown_afrom_oid_substr will be allowed,
 *							even if they're not in the main dictionaries.
 *							If an unknown attribute is found a #TMPL_TYPE_ATTR
 *							#tmpl_t will be produced.
 *							If #tmpl_afrom_attr_substr is being called on
 *							startup, the #tmpl_t may be passed to
 *							#tmpl_attr_unknown_add to
 *							add the unknown attribute to the main dictionary.
 *							If the unknown attribute is not added to
 *							the main dictionary the #tmpl_t cannot be used
 *							to search for a #fr_pair_t in a #request_t.
 *				- allow_unresolved	If true, we don't generate a parse error on
 *							unknown attributes. If an unknown attribute is
 *							found a #TMPL_TYPE_ATTR_UNRESOLVED
 *							#tmpl_t will be produced.
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
ssize_t tmpl_afrom_attr_substr(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
			       tmpl_t **out, fr_sbuff_t *name,
			       fr_sbuff_parse_rules_t const *p_rules,
			       tmpl_rules_t const *t_rules)
{
	int		ret;
	size_t		list_len;
	tmpl_t		*vpt;
	fr_sbuff_t	our_name = FR_SBUFF_NO_ADVANCE(name);	/* Take a local copy in case we need to back track */
	bool		ref_prefix = false;
	bool		is_raw = false;

	if (!t_rules) t_rules = &default_attr_rules;	/* Use the defaults */

	if (err) *err = TMPL_ATTR_ERROR_NONE;

	if (!fr_sbuff_extend(&our_name)) {
		fr_strerror_printf("Empty attribute reference");
		if (err) *err = TMPL_ATTR_ERROR_EMPTY;
		FR_SBUFF_ERROR_RETURN(&our_name);
	}

	/*
	 *	Check to see if we expect a reference prefix
	 */
	switch (t_rules->prefix) {
	case TMPL_ATTR_REF_PREFIX_YES:
		if (!fr_sbuff_next_if_char(&our_name, '&')) {
			fr_strerror_printf("Invalid attribute reference, missing '&' prefix");
			if (err) *err = TMPL_ATTR_ERROR_BAD_PREFIX;
			FR_SBUFF_ERROR_RETURN(&our_name);
		}

		break;

	case TMPL_ATTR_REF_PREFIX_NO:
		if (fr_sbuff_is_char(&our_name, '&')) {
			fr_strerror_printf("Attribute references used here must not have a '&' prefix");
			if (err) *err = TMPL_ATTR_ERROR_BAD_PREFIX;
			FR_SBUFF_ERROR_RETURN(&our_name);
		}
		break;

	case TMPL_ATTR_REF_PREFIX_AUTO:
		fr_sbuff_next_if_char(&our_name, '&');
		break;
	}

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_ATTR, T_BARE_WORD, NULL, 0));
	vpt->data.attribute.ref_prefix = ref_prefix;

	/*
	 *	The "raw." prefix marks up the leaf attribute
	 *	as unknown if it wasn't already which allows
	 *	users to stick whatever they want in there as
	 *	a value.
	 */
	if (fr_sbuff_adv_past_strcase_literal(&our_name, "raw.")) is_raw = true;

	/*
	 *	Parse one or more request references
	 */
	ret = tmpl_request_ref_afrom_attr_substr(vpt, err, vpt, &our_name, p_rules, t_rules, 0);
	if (ret < 0) {
	error:
		talloc_free(vpt);
		FR_SBUFF_ERROR_RETURN(&our_name);
	}

	/*
	 *	Parse the list reference
	 *
	 *      This code should be removed when lists
	 *	are integrated into attribute references.
	 */
	fr_sbuff_out_by_longest_prefix(&list_len, &vpt->data.attribute.list, pair_list_table,
				       &our_name, t_rules->list_def);

	if ((t_rules->attr_parent || t_rules->disallow_qualifiers) && (list_len > 0)) {
		fr_strerror_printf("It is not permitted to specify a pair list here");
		if (err) *err = TMPL_ATTR_ERROR_INVALID_LIST_QUALIFIER;
		talloc_free(vpt);
		FR_SBUFF_ERROR_RETURN(&our_name);
	}

	/*
	 *	Parse the attribute reference
	 *
	 *      This will either be after:
	 *	- A zero length list, i.e. just after the prefix '&', in which case we require an attribue
	 *	- A ':' or '.' and then an allowed char, so we're sure it's not just a bare list ref.
	 */
	if ((list_len == 0) ||
	    (((fr_sbuff_next_if_char(&our_name, ':') && (vpt->data.attribute.old_list_sep = true)) ||
	     fr_sbuff_next_if_char(&our_name, '.')) && fr_sbuff_is_in_charset(&our_name, fr_dict_attr_allowed_chars))) {
		ret = tmpl_attr_afrom_attr_substr(vpt, err,
						  vpt, t_rules->attr_parent, &our_name, p_rules, t_rules, 0);
		if (ret < 0) goto error;

		/*
		 *	Check to see if the user wants the leaf
		 *	attribute to be raw.
		 *
		 *	We can only do the conversion now _if_
		 *	the complete hierarchy has been resolved
		 *	otherwise we'll need to do the conversion
		 *	later.
		 */
		if (tmpl_is_attr(vpt) && is_raw) tmpl_attr_to_raw(vpt);
	}

	/*
	 *	If there's no attribute references
	 *	treat this as a list reference.
	 *
	 *	Eventually we'll remove TMPL_TYPE_LIST
	 */
	if (fr_dlist_num_elements(&vpt->data.attribute.ar) == 0) {
		tmpl_attr_t *ar;

		MEM(ar = talloc_zero(vpt, tmpl_attr_t));
		switch (tmpl_attr_parse_filter(err, ar, &our_name)) {
		case 0:						/* No filter */
			talloc_free(ar);
			break;

		case 1:						/* Found a filter */
			fr_dlist_insert_tail(&vpt->data.attribute.ar, ar);
			break;

		default:					/* Parse error */
			goto error;
		}

		vpt->type = TMPL_TYPE_LIST;
	}

	tmpl_set_name(vpt, T_BARE_WORD, fr_sbuff_start(&our_name), fr_sbuff_used(&our_name));
	vpt->rules = *t_rules;	/* Record the rules */

	if (!tmpl_substr_terminal_check(&our_name, p_rules)) {
		fr_strerror_printf("Unexpected text after attribute reference");
		if (err) *err = TMPL_ATTR_ERROR_MISSING_TERMINATOR;
		talloc_free(vpt);
		*out = NULL;
		return -fr_sbuff_used(&our_name);
	}

	TMPL_VERIFY(vpt);	/* Because we want to ensure we produced something sane */

	*out = vpt;
	return fr_sbuff_set(name, &our_name);
}

/** Parse a string into a TMPL_TYPE_ATTR_* or #TMPL_TYPE_LIST type #tmpl_t
 *
 * @param[in,out] ctx		to allocate #tmpl_t in.
 * @param[out] err		May be NULL.  Provides the exact error that the parser hit
 *				when processing the attribute ref.
 * @param[out] out		Where to write pointer to new #tmpl_t.
 * @param[in] name		of attribute including #request_ref_t and #pair_list_t qualifiers.
 *				If only #request_ref_t #pair_list_t qualifiers are found,
 *				a #TMPL_TYPE_LIST #tmpl_t will be produced.
 * @param[in] rules		Rules which control parsing.  See tmpl_afrom_attr_substr() for details.
 *
 * @note Unlike #tmpl_afrom_attr_substr this function will error out if the entire
 *	name string isn't parsed.
 */
ssize_t tmpl_afrom_attr_str(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
			    tmpl_t **out, char const *name, tmpl_rules_t const *rules)
{
	ssize_t slen, name_len;

	if (!rules) rules = &default_attr_rules;	/* Use the defaults */

	name_len = strlen(name);
	slen = tmpl_afrom_attr_substr(ctx, err, out, &FR_SBUFF_IN(name, name_len), NULL, rules);
	if (slen <= 0) return slen;

	if (!fr_cond_assert(*out)) return -1;

	if (slen != name_len) {
		/* This looks wrong, but it produces meaningful errors for unknown attrs */
		fr_strerror_printf("Unexpected text after %s",
				   fr_table_str_by_value(tmpl_type_table, (*out)->type, "<INVALID>"));
		return -slen;
	}

	TMPL_VERIFY(*out);

	return slen;
}

/** Parse a truth value
 *
 * @param[in] ctx	to allocate tmpl to.
 * @param[out] out	where to write tmpl.
 * @param[in] in	sbuff to parse.
 * @param[in] p_rules	formatting rules.
 * @return
 *	- 0 sbuff does not contain a boolean value.
 *	- > 0 how many bytes were parsed.
 */
static ssize_t tmpl_afrom_bool_substr(TALLOC_CTX *ctx, tmpl_t **out, fr_sbuff_t *in,
				      fr_sbuff_parse_rules_t const *p_rules)
{
	fr_sbuff_t	our_in = FR_SBUFF_NO_ADVANCE(in);
	bool		a_bool;
	tmpl_t		*vpt;

	if (!fr_sbuff_out(NULL, &a_bool, &our_in)) {
		fr_strerror_printf("Not a boolean value");
		return 0;
	}

	if (!tmpl_substr_terminal_check(&our_in, p_rules)) {
		fr_strerror_printf("Unexpected text after bool");
		return -fr_sbuff_used(in);
	}

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_DATA, T_BARE_WORD, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in)));

	fr_value_box_init(&vpt->data.literal, FR_TYPE_BOOL, NULL, false);
	vpt->data.literal.vb_bool = a_bool;

	*out = vpt;

	return fr_sbuff_set(in, &our_in);
}

/** Parse bareword as an octet string
 *
 * @param[in] ctx	to allocate tmpl to.
 * @param[out] out	where to write tmpl.
 * @param[in] in	sbuff to parse.
 * @param[in] p_rules	formatting rules.
 * @return
 *	- < 0 negative offset where parse error occurred.
 *	- 0 sbuff does not contain a hex string.
 *	- > 0 how many bytes were parsed.
 */
static ssize_t tmpl_afrom_octets_substr(TALLOC_CTX *ctx, tmpl_t **out, fr_sbuff_t *in,
					fr_sbuff_parse_rules_t const *p_rules)
{
	fr_sbuff_t	our_in = FR_SBUFF_NO_ADVANCE(in);
	tmpl_t		*vpt;
	char		*hex;
	size_t		binlen, len;
	uint8_t		*bin;

	if (!fr_sbuff_adv_past_strcase_literal(&our_in, "0x")) return 0;

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_DATA, T_BARE_WORD, NULL, 0));

	/*
	 *	This allows stream parsing to work correctly
	 *      we could be less lazy and copy hex data in
	 *      chunks, but never mind...
	 */
	len = fr_sbuff_out_abstrncpy_allowed(vpt, &hex, &our_in, SIZE_MAX, sbuff_char_class_hex);
	if (len & 0x01) {
		fr_strerror_printf("Hex string not even length");
	error:
		talloc_free(vpt);
		return -fr_sbuff_used(&our_in);
	}
	if (len == 0) {
		fr_strerror_printf("Zero length hex string is invalid");
		goto error;
	}

	if (!tmpl_substr_terminal_check(&our_in, p_rules)) {
		fr_strerror_printf("Unexpected text after hex string");
		goto error;
	}

	bin = (uint8_t *)hex;
	binlen = len / 2;

	tmpl_set_name(vpt, T_BARE_WORD, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in));

	(void)fr_hex2bin(NULL, &FR_DBUFF_TMP(bin, binlen), &FR_SBUFF_IN(hex, len), false);
	MEM(bin = talloc_realloc_size(vpt, bin, binlen));	/* Realloc to the correct length */
	(void)fr_value_box_memdup_shallow(&vpt->data.literal, NULL, bin, binlen, false);

	*out = vpt;

	return fr_sbuff_set(in, &our_in);
}

/** Parse bareword as an IPv4 address or prefix
 *
 * @param[in] ctx	to allocate tmpl to.
 * @param[out] out	where to write tmpl.
 * @param[in] in	sbuff to parse.
 * @param[in] p_rules	formatting rules.
 * @return
 *	- 0 sbuff does not contain an IPv4 address or prefix.
 *	- > 0 how many bytes were parsed.
 */
static ssize_t tmpl_afrom_ipv4_substr(TALLOC_CTX *ctx, tmpl_t **out, fr_sbuff_t *in,
				      fr_sbuff_parse_rules_t const *p_rules)
{
	tmpl_t		*vpt;
	fr_sbuff_t	our_in = FR_SBUFF_NO_ADVANCE(in);
	uint8_t		octet;
	fr_type_t	type;

	/*
	 *	Check for char sequence
	 *
	 *	xxx.xxxx.xxx.xxx
	 */
	if (!(fr_sbuff_out(NULL, &octet, &our_in) && fr_sbuff_next_if_char(&our_in, '.') &&
	      fr_sbuff_out(NULL, &octet, &our_in) && fr_sbuff_next_if_char(&our_in, '.') &&
	      fr_sbuff_out(NULL, &octet, &our_in) && fr_sbuff_next_if_char(&our_in, '.') &&
	      fr_sbuff_out(NULL, &octet, &our_in))) {
	error:
		return -fr_sbuff_used(&our_in);
	}

	/*
	 *	If it has a trailing '/' then it's probably
	 *	an IP prefix.
	 */
	if (fr_sbuff_next_if_char(&our_in, '/')) {
		if (!fr_sbuff_out(NULL, &octet, &our_in)) {
			fr_strerror_printf("IPv4 CIDR mask malformed");
			goto error;
		}

		if (octet > 32) {
			fr_strerror_printf("IPv4 CIDR mask too high");
			goto error;
		}

		type = FR_TYPE_IPV4_PREFIX;
	} else {
		type = FR_TYPE_IPV4_ADDR;
	}

	if (!tmpl_substr_terminal_check(&our_in, p_rules)) {
		fr_strerror_printf("Unexpected text after IPv4 string or prefix");
		goto error;
	}

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_DATA, T_BARE_WORD, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in)));
	if (fr_value_box_from_str(vpt, &vpt->data.literal, &type, NULL,
				  fr_sbuff_start(&our_in), fr_sbuff_used(&our_in), '\0', false) < 0) {
		talloc_free(vpt);
		goto error;
	}
	*out = vpt;

	return fr_sbuff_set(in, &our_in);
}

/** Parse bareword as an IPv6 address or prefix
 *
 * @param[in] ctx		to allocate tmpl to.
 * @param[out] out		where to write tmpl.
 * @param[in] in		sbuff to parse.
 * @param[in] p_rules		formatting rules.
 * @return
 *	- 0 sbuff does not contain an IPv4 address or prefix.
 *	- > 0 how many bytes were parsed.
 */
static ssize_t tmpl_afrom_ipv6_substr(TALLOC_CTX *ctx, tmpl_t **out, fr_sbuff_t *in,
				      fr_sbuff_parse_rules_t const *p_rules)
{
	tmpl_t			*vpt;
	fr_sbuff_t		our_in = FR_SBUFF_NO_ADVANCE(in);
	fr_sbuff_marker_t	m;
	fr_type_t		type;
	size_t			len;
	char			*sep_a, *sep_b;

	static bool ipv6_chars[UINT8_MAX + 1] = {
		['0'] = true, ['1'] = true, ['2'] = true, ['3'] = true, ['4'] = true,
		['5'] = true, ['6'] = true, ['7'] = true, ['8'] = true, ['9'] = true,
		['a'] = true, ['b'] = true, ['c'] = true, ['d'] = true, ['e'] = true,
		['f'] = true,
		['A'] = true, ['B'] = true, ['C'] = true, ['D'] = true,	['E'] = true,
		['F'] = true,
		[':'] = true, ['.'] = true
	};

	/*
	 *	Drop a marker to pin the start of the
	 *	address in the buffer.
	 */
	fr_sbuff_marker(&m, &our_in);

	/*
	 *	Check for something looking like an IPv6 address
	 */
	len = fr_sbuff_adv_past_allowed(&our_in, FR_IPADDR_STRLEN + 1, ipv6_chars);
	if ((len < 3) || (len > FR_IPADDR_STRLEN)) {
	error:
		return -fr_sbuff_used(&our_in);
	}

	/*
	 *	Got ':' after '.', this isn't allowed.
	 *
	 *	We need this check else IPv4 gets parsed
	 *	as blank IPv6 address.
	 */
	sep_a = memchr(fr_sbuff_current(&m), '.', len);
	if (sep_a && (!(sep_b = memchr(fr_sbuff_current(&m), ':', len)) || (sep_b > sep_a))) {
		fr_strerror_printf("First IPv6 component separator was a '.'");
		goto error;
	}

	/*
	 *	The v6 parse function will happily turn
	 *	integers into v6 addresses *sigh*.
	 */
	sep_a = memchr(fr_sbuff_current(&m), ':', len);
	if (!sep_a) {
		fr_strerror_printf("No IPv6 component separator");
		goto error;
	}

	/*
	 *	Handle scope
	 */
	if (fr_sbuff_next_if_char(&our_in, '%')) {
		len = fr_sbuff_adv_until(&our_in, IFNAMSIZ + 1, p_rules->terminals, '\0');
		if ((len < 1) || (len > IFNAMSIZ)) {
			fr_strerror_printf("IPv6 scope too long");
			goto error;
		}
	}

	/*
	 *	...and finally the prefix.
	 */
	if (fr_sbuff_next_if_char(&our_in, '/')) {
		uint8_t		mask;

		if (!fr_sbuff_out(NULL, &mask, &our_in)) {
			fr_strerror_printf("IPv6 CIDR mask malformed");
			goto error;
		}
		if (mask > 128) {
			fr_strerror_printf("IPv6 CIDR mask too high");
			goto error;
		}

		type = FR_TYPE_IPV6_PREFIX;
	} else {
		type = FR_TYPE_IPV6_ADDR;
	}

	if (!tmpl_substr_terminal_check(&our_in, p_rules)) {
		fr_strerror_printf("Unexpected text after IPv6 string or prefix");
		goto error;
	}

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_DATA, T_BARE_WORD, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in)));
	if (fr_value_box_from_str(vpt, &vpt->data.literal, &type, NULL,
				  fr_sbuff_start(&our_in), fr_sbuff_used(&our_in), '\0', false) < 0) {
		talloc_free(vpt);
		goto error;
	}
	*out = vpt;

	return fr_sbuff_set(in, &our_in);
}

/** Try and parse signed or unsigned integers
 *
 * @param[in] ctx	to allocate tmpl to.
 * @param[out] out	where to write tmpl.
 * @param[in] in	sbuff to parse.
 * @param[in] p_rules	formatting rules.
 * @return
 *	- 0 sbuff does not contain an integer.
 *	- > 0 how many bytes were parsed.
 */
static ssize_t tmpl_afrom_integer_substr(TALLOC_CTX *ctx, tmpl_t **out, fr_sbuff_t *in,
					 fr_sbuff_parse_rules_t const *p_rules)
{
	tmpl_t	*vpt;
	fr_sbuff_t	our_in = FR_SBUFF_NO_ADVANCE(in);
	ssize_t		slen;
	fr_value_box_t	*vb;

	/*
	 *	Pick the narrowest signed type
	 */
	if (fr_sbuff_is_char(&our_in, '-')) {
		int64_t		a_int;

		slen = fr_sbuff_out(NULL, &a_int, &our_in);
		if (slen <= 0) return 0;

		if (!tmpl_substr_terminal_check(&our_in, p_rules)) {
			fr_strerror_printf("Unexpected text after signed integer");
		error:
			return -fr_sbuff_used(&our_in);
		}

		MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_DATA,
				     T_BARE_WORD, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in)));
		vb = tmpl_value(vpt);
		if (a_int >= INT8_MIN) {
			fr_value_box_init(vb, FR_TYPE_INT8, NULL, false);
			vb->vb_int8 = (int8_t)a_int;
		} else if (a_int >= INT16_MIN) {
			fr_value_box_init(vb, FR_TYPE_INT16, NULL, false);
			vb->vb_int16 = (int16_t)a_int;
		} else if (a_int >= INT32_MIN) {
			fr_value_box_init(vb, FR_TYPE_INT32, NULL, false);
			vb->vb_int32 = (int32_t)a_int;
		} else {
			fr_value_box_init(vb, FR_TYPE_INT64, NULL, false);
			vb->vb_int64 = (int64_t)a_int;
		}
	/*
	 *	Pick the narrowest unsigned type
	 */
	} else {
		uint64_t	a_uint;

		slen = fr_sbuff_out(NULL, &a_uint, &our_in);
		if (slen <= 0) return slen;

		if (!tmpl_substr_terminal_check(&our_in, p_rules)) {
			fr_strerror_printf("Unexpected text after unsigned integer");
			goto error;
		}

		MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_DATA,
				     T_BARE_WORD, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in)));
		vb = tmpl_value(vpt);
		if (a_uint <= UINT8_MAX) {
			fr_value_box_init(vb, FR_TYPE_UINT8, NULL, false);
			vb->vb_uint8 = (uint8_t)a_uint;
		} else if (a_uint <= UINT16_MAX) {
			fr_value_box_init(vb, FR_TYPE_UINT16, NULL, false);
			vb->vb_uint16 = (uint16_t)a_uint;
		} else if (a_uint <= UINT32_MAX) {
			fr_value_box_init(vb, FR_TYPE_UINT32, NULL, false);
			vb->vb_uint32 = (uint32_t)a_uint;
		} else {
			fr_value_box_init(vb, FR_TYPE_UINT64, NULL, false);
			vb->vb_uint64 = (uint64_t)a_uint;
		}
	}

	*out = vpt;

	return fr_sbuff_set(in, &our_in);
}

/** Convert an arbitrary string into a #tmpl_t
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
 * @param[in,out] ctx		To allocate #tmpl_t in.
 * @param[out] out		Where to write the pointer to the new #tmpl_t.
 * @param[in] in		String to parse.
 * @param[in] quote		Quoting around the tmpl.  Determines what we
 *				attempt to parse the string as.
 * @param[in] p_rules		Formatting rules for the tmpl.
 * @param[in] t_rules		Validation rules for attribute references.
 * @return
 *	- <= 0 on error (offset as negative integer)
 *	- > 0 on success (number of bytes parsed).
 *
 * @see REMARKER to produce pretty error markers from the return value.
 *
 * @see tmpl_afrom_attr_substr
 */
ssize_t tmpl_afrom_substr(TALLOC_CTX *ctx, tmpl_t **out,
			  fr_sbuff_t *in, fr_token_t quote,
			  fr_sbuff_parse_rules_t const *p_rules,
			  tmpl_rules_t const *t_rules)
{
	fr_sbuff_t	our_in = FR_SBUFF_NO_ADVANCE(in);

	ssize_t		slen;
	char		*str;

	tmpl_t		*vpt = NULL;

	if (!t_rules) t_rules = &default_attr_rules;	/* Use the defaults */

	*out = NULL;

	switch (quote) {
	case T_BARE_WORD:
		/*
		 *	Skip other bareword types if
		 *	we find a '&' prefix.
		 */
		if (fr_sbuff_is_char(&our_in, '&')) return tmpl_afrom_attr_substr(ctx, NULL, out, in,
										  p_rules, t_rules);

		/*
		 *	Allow bareword xlats if we
		 *	find a '%' prefix.
		 */
		if (fr_sbuff_is_char(&our_in, '%')) {
			tmpl_type_t	type = TMPL_TYPE_XLAT;
			xlat_exp_t	*head = NULL;
			xlat_flags_t	flags = {};

			vpt = tmpl_alloc_null(ctx);
			if (!t_rules->at_runtime) {
				slen = xlat_tokenize(vpt, &head, &flags, &our_in, p_rules, t_rules);
			} else {
				slen = xlat_tokenize_ephemeral(vpt, &head, &flags, &our_in, p_rules, t_rules);
			}

			if (!head) return slen;

			if (flags.needs_resolving) type |= TMPL_FLAG_UNRESOLVED;

			tmpl_init(vpt, type, quote, fr_sbuff_start(&our_in), slen);
			vpt->data.xlat.ex = head;
			vpt->data.xlat.flags = flags;

			*out = vpt;

			TMPL_VERIFY(vpt);

			return fr_sbuff_set(in, &our_in);
		}

		/*
		 *	See if it's a boolean value
		 */
		slen = tmpl_afrom_bool_substr(ctx, out, &our_in, p_rules);
		if (slen > 0) {
		done_bareword:
			TMPL_VERIFY(*out);

			return fr_sbuff_set(in, &our_in);
		}

		/*
		 *	See if it's an octets string
		 */
		slen = tmpl_afrom_octets_substr(ctx, out, &our_in, p_rules);
		if (slen > 0) goto done_bareword;

		/*
		 *	See if it's an IPv4 address or prefix
		 */
		slen = tmpl_afrom_ipv4_substr(ctx, out, &our_in, p_rules);
		if (slen > 0) goto done_bareword;

		/*
		 *	See if it's an IPv6 address or prefix
		 */
		slen = tmpl_afrom_ipv6_substr(ctx, out, &our_in, p_rules);
		if (slen > 0) goto done_bareword;

		/*
		 *	See if it's a float
		 */
//		slen = tmpl_afrom_float_substr(ctx, out, &our_in);
//		if (slen > 0) return fr_sbuff_set(in, &our_in);

		/*
		 *	See if it's a mac address
		 */
//		slen = tmpl_afrom_mac_address_substr(ctx, out, &our_in);
//		if (slen > 0) return fr_sbuff_set(in, &our_in);

		/*
		 *	See if it's a integer
		 */
		slen = tmpl_afrom_integer_substr(ctx, out, &our_in, p_rules);
		if (slen > 0) goto done_bareword;

		/*
		 *	See if it's an attribute reference
		 *	without the prefix.
		 */
		slen = tmpl_afrom_attr_substr(ctx, NULL, out, &our_in, p_rules, t_rules);
		if (slen > 0) goto done_bareword;

		vpt = tmpl_alloc_null(ctx);

		/*
		 *	If it doesn't match any other type
		 *	of bareword, assume it's an enum
		 *	value.
		 */
		slen = fr_sbuff_out_aunescape_until(vpt, &str, &our_in, SIZE_MAX,
						    p_rules ? p_rules->terminals : NULL,
						    p_rules ? p_rules->escapes : NULL);
		if (slen == 0) {
			fr_strerror_printf("Empty bareword is invalid");
			talloc_free(vpt);
			return 0;
		}

		tmpl_init(vpt, TMPL_TYPE_UNRESOLVED, T_BARE_WORD, fr_sbuff_start(&our_in), slen);
		vpt->data.unescaped = str;
		*out = vpt;

		return fr_sbuff_set(in, &our_in);

	case T_SINGLE_QUOTED_STRING:
		vpt = tmpl_alloc_null(ctx);
		slen = fr_sbuff_out_aunescape_until(vpt, &str, &our_in, SIZE_MAX,
						    p_rules ? p_rules->terminals : NULL,
						    p_rules ? p_rules->escapes : NULL);
		tmpl_init(vpt, TMPL_TYPE_UNRESOLVED, quote, fr_sbuff_start(&our_in), slen);
		vpt->data.unescaped = str;
		break;

	case T_DOUBLE_QUOTED_STRING:
	{
		xlat_exp_t	*head = NULL;
		xlat_flags_t	flags = {};

		vpt = tmpl_alloc_null(ctx);

		if (!t_rules->at_runtime) {
			slen = xlat_tokenize(vpt, &head, &flags, &our_in, p_rules, t_rules);
		} else {
			slen = xlat_tokenize_ephemeral(vpt, &head, &flags, &our_in, p_rules, t_rules);
		}
		if (!head) return slen;

		/*
		 *	If the string doesn't contain an xlat, just
		 *	convert the xlat expansion into an unescaped
		 *	literal for parsing later.
		 */
		if (xlat_to_literal(vpt, &str, &head)) {
			tmpl_init(vpt, TMPL_TYPE_UNRESOLVED, quote, fr_sbuff_start(&our_in), slen);
			vpt->data.unescaped = str;	/* Store the unescaped string for parsing later */

		/*
		 *	If the string actually contains an xlat
		 *	store the compiled xlat.
		 */
		} else {
			tmpl_type_t	type = TMPL_TYPE_XLAT;

			if (flags.needs_resolving) type |= TMPL_FLAG_UNRESOLVED;

			tmpl_init(vpt, type, quote, fr_sbuff_start(&our_in), slen);
			vpt->data.xlat.ex = head;
			vpt->data.xlat.flags = flags;
		}
	}
		break;

	case T_BACK_QUOTED_STRING:
	{
		tmpl_type_t		type = TMPL_TYPE_EXEC;
		xlat_exp_t		*head = NULL;
		xlat_flags_t		flags = {};

		vpt = tmpl_alloc_null(ctx);

		/*
		 *	Ensure that we pre-parse the exec string.
		 *	This allows us to catch parse errors as early
		 *	as possible.
		 *
		 *	FIXME - We need an ephemeral version of this
		 *	too.
		 */
		slen = xlat_tokenize_argv(vpt, &head, &flags, &our_in, p_rules, t_rules);
		if (slen < 0) {
			fr_sbuff_advance(&our_in, slen * -1);
			talloc_free(vpt);
			return slen;
		}

		if (flags.needs_resolving) type |= TMPL_FLAG_UNRESOLVED;

		tmpl_init(vpt, type, quote, fr_sbuff_start(&our_in), slen);
		vpt->data.xlat.ex = head;
		vpt->data.xlat.flags = flags;
	}
		break;

	case T_SOLIDUS_QUOTED_STRING:
	{

		xlat_exp_t		*head = NULL;
		xlat_flags_t		flags = {};

		vpt = tmpl_alloc_null(ctx);

		slen = xlat_tokenize(vpt, &head, &flags, &our_in, p_rules, t_rules);
		if (!head) return slen;

		/*
		 *	Check if the string actually contains an xlat
		 *	if it doesn't, we unfortunately still
		 *	can't compile it here, as we don't know if it
		 *	should be ephemeral or what flags should be used
		 *	during the compilation.
		 *
		 *	The caller will need to do the compilation
		 *	after we return.
		 */

		if (xlat_to_literal(vpt, &str, &head)) {
			tmpl_init(vpt, TMPL_TYPE_REGEX_UNCOMPILED, quote, fr_sbuff_start(&our_in), slen);
			vpt->data.unescaped = str;	/* Store the unescaped string for compilation later */

		/*
		 *	Mark the regex up as a regex-xlat which
		 *	will need expanding before evaluation, and can never
		 *	be pre-compiled.
		 */
		} else {
			tmpl_type_t type = TMPL_TYPE_REGEX_XLAT;

			if (flags.needs_resolving) type |= TMPL_FLAG_UNRESOLVED;

			tmpl_init(vpt, type, quote, fr_sbuff_start(&our_in), slen);
			vpt->data.xlat.ex = head;
			vpt->data.xlat.flags = flags;
		}
	}
		break;

	default:
		fr_assert(0);
		return 0;	/* 0 is an error here too */
	}

	TMPL_VERIFY(vpt);
	*out = vpt;

	return fr_sbuff_set(in, &our_in);
}

/** Parse a cast specifier
 *
 * @param[out] out	Where to write the cast type.
 *			Will default to FR_TYPE_INVALID.
 * @param[in] in	String containing the cast marker.
 * @return
 *	- 0 no cast specifier found.
 *	- >0 the number of bytes parsed.
 *	- <0 offset of parse error.
 */
ssize_t tmpl_cast_from_substr(fr_type_t *out, fr_sbuff_t *in)
{
	fr_sbuff_t		our_in = FR_SBUFF_NO_ADVANCE(in);
	fr_sbuff_marker_t	m;
	fr_type_t		cast = FR_TYPE_INVALID;
	ssize_t			slen;

	if (fr_sbuff_next_if_char(&our_in, '<')) {
		fr_sbuff_marker(&m, &our_in);
		fr_sbuff_out_by_longest_prefix(&slen, &cast, fr_value_box_type_table, &our_in, FR_TYPE_INVALID);
		if (cast == FR_TYPE_INVALID) {
			fr_strerror_printf("Unknown data type");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}
		if (fr_dict_non_data_types[cast]) {
			fr_strerror_printf("Forbidden data type in cast");
			FR_SBUFF_MARKER_ERROR_RETURN(&m);
		}
		if (!fr_sbuff_next_if_char(&our_in, '>')) {
			fr_strerror_printf("Unterminated cast");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}
		fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX);
	}
	if (out) *out = cast;

	return fr_sbuff_set(in, &our_in);
}

/** Set a cast for a tmpl
 *
 * @param[in,out] vpt	to set cast for.
 * @param[in] type	to set.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_cast_set(tmpl_t *vpt, fr_type_t type)
{
	if (fr_dict_non_data_types[type]) {
		fr_strerror_printf("Forbidden data type in cast");
		return -1;
	}

	vpt->cast = type;

	return 0;
}

#ifdef HAVE_REGEX
/** Parse a set of regular expression flags
 *
 * @param[out] vpt	Write the flags to the regex flags field in this #tmpl_t.
 * @param[in] in	Where to parse the flag string from.
 * @param[in] terminals	That mark the end of the regex flag string.
 * @return
 *	- 0 no flags found.
 *	- >0 the number of bytes of flags parsed.
 *	- <0 offset of parse error.
 */
ssize_t tmpl_regex_flags_substr(tmpl_t *vpt, fr_sbuff_t *in, fr_sbuff_term_t const *terminals)
{
	ssize_t slen;
	int	err = 0;

	fr_assert(tmpl_is_regex_uncompiled(vpt) || tmpl_is_regex_xlat(vpt) || tmpl_is_regex_xlat_unresolved(vpt));

	slen = regex_flags_parse(&err, &vpt->data.reg.flags, in, terminals, true);
	switch (err) {
	case 0:
		break;

	case -1:	/* Non-flag and non-terminal */
	case -2:	/* Duplicate flag */
		return slen;
	}

	return slen;
}
#endif
/** @} */

/** @name Change a #tmpl_t type, usually by casting or resolving a reference
 *
 * #tmpl_cast_in_place can be used to convert #TMPL_TYPE_UNRESOLVED to a #TMPL_TYPE_DATA of a
 * specified #fr_type_t.
 *
 * #tmpl_attr_unknown_add converts a #TMPL_TYPE_ATTR with an unknown #fr_dict_attr_t to a
 * #TMPL_TYPE_ATTR with a known #fr_dict_attr_t, by adding the unknown #fr_dict_attr_t to the main
 * dictionary, and updating the ``tmpl_da`` pointer.
 * @{
 */

/** Convert #tmpl_t of type #TMPL_TYPE_UNRESOLVED or #TMPL_TYPE_DATA to #TMPL_TYPE_DATA of type specified
 *
 * @note Conversion is done in place.
 * @note Irrespective of whether the #tmpl_t was #TMPL_TYPE_UNRESOLVED or #TMPL_TYPE_DATA,
 *	on successful cast it will be #TMPL_TYPE_DATA.
 *
 * @param[in,out] vpt	The template to modify. Must be of type #TMPL_TYPE_UNRESOLVED
 *			or #TMPL_TYPE_DATA.
 * @param[in] type	to cast to.
 * @param[in] enumv	Enumerated dictionary values associated with a #fr_dict_attr_t.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_cast_in_place(tmpl_t *vpt, fr_type_t type, fr_dict_attr_t const *enumv)
{
	TMPL_VERIFY(vpt);

	fr_assert(tmpl_is_unresolved(vpt) || tmpl_is_data(vpt));

	switch (vpt->type) {
	case TMPL_TYPE_UNRESOLVED:
	{
		char *unescaped = vpt->data.unescaped;

		/*
		 *	Why do we pass a pointer to a temporary type
		 *	variable? Goddamn WiMAX.
		 */
		if (fr_value_box_from_str(vpt, &vpt->data.literal, &type,
					  enumv, unescaped, talloc_array_length(unescaped) - 1,
					  '\0', false) < 0) return -1;
		talloc_free(unescaped);
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

	case TMPL_TYPE_ATTR:	/* FIXME - We should check cast compatibility with resolved attrs */
	case TMPL_TYPE_ATTR_UNRESOLVED:
		vpt->cast = type;
		break;

	default:
		fr_assert(0);
	}

	/*
	 *	Fixup quoting
	 */
	switch (type) {
	case FR_TYPE_STRING:
		switch (vpt->quote) {
		case T_SINGLE_QUOTED_STRING:
		case T_DOUBLE_QUOTED_STRING:
			break;

		default:
			vpt->quote = T_SINGLE_QUOTED_STRING;
			break;
		}
		break;

	default:
		vpt->quote = T_BARE_WORD;
		break;
	}

	TMPL_VERIFY(vpt);

	return 0;
}

/** Resolve an unresolved attribute
 *
 * Multi-pass parsing fixups for attribute references.
 */
static inline CC_HINT(always_inline) int tmpl_attr_resolve(tmpl_t *vpt)
{
	tmpl_attr_t		*ar = NULL;
	fr_dict_attr_t const	*parent = NULL;
	fr_dict_attr_t const	*da;

	fr_assert(tmpl_is_attr_unresolved(vpt));

	/*
	 *	First ref is special as it can resolve in the
	 *	internal dictionary or the protocol specific
	 *	dictionary.
	 */
	ar = fr_dlist_head(&vpt->data.attribute.ar);
	if (ar->type == TMPL_ATTR_TYPE_UNRESOLVED) {
		da = fr_dict_attr_by_qualified_oid(NULL, vpt->rules.dict_def,
						   ar->ar_unresolved, true);
		if (!da) {
			parent = fr_dict_root(vpt->rules.dict_def);
			goto unknown;
		}

		ar->da = da;
		ar->type = TMPL_ATTR_TYPE_NORMAL;
		parent = ar->da;
	} else {
		parent = ar->da;
	}

	/*
	 *	Loop, resolving each unresolved attribute in turn
	 */
	while ((ar = fr_dlist_next(&vpt->data.attribute.ar, ar))) {
		ssize_t		slen;
		bool		is_raw;

		if ((ar->type == TMPL_ATTR_TYPE_NORMAL) || (ar->type == TMPL_ATTR_TYPE_UNKNOWN)) break;

		is_raw = ar->ar_unresolved_raw;

		slen = fr_dict_attr_child_by_name_substr(NULL, &da, parent,
							 &FR_SBUFF_IN(ar->ar_unresolved, strlen(ar->ar_unresolved)),
							 false);
		if (slen <= 0) {
			fr_dict_attr_t	*unknown_da;
			fr_sbuff_t	sbuff;

		unknown:
			sbuff = FR_SBUFF_IN(ar->ar_unresolved,
					    talloc_array_length(ar->ar_unresolved) - 1);

			/*
			 *	Can't find it under its regular name.  Try an unknown attribute.
			 */
			slen = fr_dict_unknown_afrom_oid_substr(vpt, NULL, &unknown_da, parent,
								&sbuff, NULL);
			if ((slen <= 0) || (fr_sbuff_remaining(&sbuff))) {
				fr_strerror_printf_push("Failed resolving unresolved attribute");
				return -1;
			}

			ar->type = TMPL_ATTR_TYPE_UNKNOWN;
			ar->da = ar->unknown.da = unknown_da;
			parent = ar->da;
			continue;
		}

		/*
		 *	Known attribute, just rewrite.
		 */
		ar->da = da;
		parent = ar->da;

		/*
		 *	If the user wanted the leaf
		 *	to be raw, and it's not, correct
		 *	that now.
		 */
		if (is_raw) attr_to_raw(vpt, ar);
	}

	vpt->type ^= TMPL_FLAG_UNRESOLVED;

	TMPL_VERIFY(vpt);

	return 0;
}

/** Resolve an unresolved xlat, i.e. one containing unresolved attribute references or xlat functions
 *
 * Multi-pass parsing fixups for attribute references.
 *
 * Works for base types:
 * - TMPL_TYPE_XLAT
 * - TMPL_TYPE_EXEC
 * - TMPL_TYPE_REGEX_XLAT
 *
 * @param[in] vpt	Containing the xlat expansion to resolve.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(always_inline) int tmpl_xlat_resolve(tmpl_t *vpt)
{
	if (xlat_resolve(&vpt->data.xlat.ex, &vpt->data.xlat.flags, false) < 0) return -1;

	vpt->type ^= TMPL_FLAG_UNRESOLVED;

	return 0;
}

/** Attempt to resolve functions and attributes in xlats and attribute references
 *
 * @param[in,out] vpt	to resolve.  Should be of type TMPL_TYPE_XLAT_UNRESOLVED
 *			or TMPL_TYPE_ATTR_UNRESOLVED.  All other types will be
 *			noops.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_resolve(tmpl_t *vpt)
{
	int ret = 0;

	if (!tmpl_needs_resolving(vpt)) return 0;	/* Nothing to do */

	/*
	 *	The xlat component of the #tmpl_t needs resolving.
	 */
	if (tmpl_contains_xlat(vpt)) {
		ret = tmpl_xlat_resolve(vpt);
	/*
	 *	The attribute reference needs resolving.
	 */
	} else if (tmpl_contains_attr(vpt)) {
		ret = tmpl_attr_resolve(vpt);

	/*
	 *	Convert unresolved tmpls into literal string values.
	 */
	} else if (tmpl_is_unresolved(vpt)) {
		char *unescaped = vpt->data.unescaped;	/* Copy the pointer before zeroing the union */

		fr_value_box_init_null(&vpt->data.literal);

		fr_value_box_bstrdup_buffer_shallow(NULL, &vpt->data.literal, NULL, unescaped, false);

		/*
		 *	Attempt to process the cast
		 */
		if (vpt->cast != FR_TYPE_INVALID) {
			ret = fr_value_box_cast_in_place(vpt, &vpt->data.literal, vpt->cast, NULL);
			if (ret < 0) goto done;
		}
		vpt->type = TMPL_TYPE_DATA;
	}

done:
	TMPL_VERIFY(vpt);

	return ret;
}

/** Reset the tmpl, leaving only the name in place
 *
 * After calling this function, the tmpl type will revert to TMPL_TYPE_UNRESOLVED
 * and only the name and quoting will be preserved.
 *
 * @param[in] vpt	to reset.
 */
void tmpl_unresolve(tmpl_t *vpt)
{
	tmpl_t	tmp = {
			.type = TMPL_TYPE_UNRESOLVED,
			.name = vpt->name,
			.len = vpt->len,
			.quote = vpt->quote
		};

	switch (vpt->type) {
	case TMPL_TYPE_UNINITIALISED:
	case TMPL_TYPE_MAX:
		fr_assert(0);
		break;

	case TMPL_TYPE_NULL:
	case TMPL_TYPE_UNRESOLVED:
	case TMPL_TYPE_REGEX_UNCOMPILED:
		break;

	case TMPL_TYPE_DATA:
		fr_value_box_clear(&vpt->data.literal);
		break;

	/*
	 *	These types contain dynamically allocated
	 *	attribute and request references.
	 */
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_ATTR_UNRESOLVED:
		fr_dlist_talloc_free(&vpt->data.attribute.ar);
		fr_dlist_talloc_free(&vpt->data.attribute.rr);
		break;

	/*
	 *	These all store an xlat expansion
	 */
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_REGEX_XLAT:
	case TMPL_TYPE_EXEC_UNRESOLVED:
	case TMPL_TYPE_XLAT_UNRESOLVED:
	case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:
		xlat_exp_free(&vpt->data.xlat.ex);
		break;

	case TMPL_TYPE_REGEX:
		talloc_free(vpt->data.reg.ex);
		break;

	}

	memcpy(vpt, &tmp, sizeof(*vpt));

	TMPL_VERIFY(vpt);
}

/** Convert an attribute reference to an xlat expansion
 *
 * This is where a user attempts to use an attribute reference which is actually
 * a virtual attribute.
 *
 * @param[in] ctx		to convert new tmpl in.
 * @param[in,out] vpt_p		pointer to #tmpl_t of TMPL_TYPE_ATTR | TMPL_TYPE_ATTR_UNPARSED.
 */
int tmpl_attr_to_xlat(TALLOC_CTX *ctx, tmpl_t **vpt_p)
{

	tmpl_t	*vpt;
	tmpl_t	*attr = *vpt_p;

	/*
	 *	First alloc a new tmpl to hold the xlat expansion
	 */
	vpt = tmpl_alloc(ctx, TMPL_TYPE_XLAT, attr->quote, attr->name, attr->len);

	/*
	 *	...then wrap the old tmpl_t in an xlat expansion
	 *	doing conversion to a virtual attribute if necessary.
	 */
	if (xlat_from_tmpl_attr(vpt, &vpt->data.xlat.ex, &vpt->data.xlat.flags, vpt_p) < 0) {
		talloc_free(vpt);
		return -1;
	}

	if (vpt->data.xlat.flags.needs_resolving) vpt->type |= TMPL_FLAG_UNRESOLVED;

	*vpt_p = vpt;

	return 0;
}

static void attr_to_raw(tmpl_t *vpt, tmpl_attr_t *ref)
{
	if (!ref) return;

	switch (ref->type) {
	case TMPL_ATTR_TYPE_NORMAL:
	{
		ref->da = ref->ar_unknown = fr_dict_unknown_afrom_da(vpt, ref->da);
		ref->ar_unknown->type = FR_TYPE_OCTETS;
		ref->ar_unknown->flags.is_raw = 1;
		ref->ar_unknown->flags.is_unknown = 1;
		ref->type = TMPL_ATTR_TYPE_UNKNOWN;
	}
		break;

	case TMPL_ATTR_TYPE_UNKNOWN:
		ref->ar_unknown->type = FR_TYPE_OCTETS;
		ref->ar_unknown->flags.is_raw = 1;
		break;

	case TMPL_ATTR_TYPE_UNRESOLVED:
		ref->ar_unresolved_raw = true;
		break;
	}

	TMPL_ATTR_VERIFY(vpt);
}

/** Covert the leaf attribute of a tmpl to a unknown/raw type
 *
 */
void tmpl_attr_to_raw(tmpl_t *vpt)
{
	attr_to_raw(vpt, fr_dlist_tail(&vpt->data.attribute.ar));
}

/** Convert an abstract da into a concrete one
 *
 * Usually used to fixup combo ip addresses
 */
int tmpl_attr_abstract_to_concrete(tmpl_t *vpt, fr_type_t type)
{
	fr_dict_attr_t const	*abstract;
	fr_dict_attr_t const	*concrete;
	tmpl_attr_t	*ref;

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

	TMPL_ATTR_VERIFY(vpt);

	return 0;
}

/** Add an unknown #fr_dict_attr_t specified by a #tmpl_t to the main dictionary
 *
 * @param vpt to add. ``tmpl_da`` pointer will be updated to point to the
 *	#fr_dict_attr_t inserted into the dictionary.
 * @return
 *	- 1 noop (did nothing) - Not possible to convert tmpl.
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_attr_unknown_add(tmpl_t *vpt)
{
	tmpl_attr_t		*ar = NULL, *next_ar = NULL;;

	if (!vpt) return 1;

	tmpl_assert_type(tmpl_is_attr(vpt));

	TMPL_VERIFY(vpt);

	if (!tmpl_da(vpt)->flags.is_unknown) return 1;	/* Ensure at least the leaf is unknown */

	while ((ar = fr_dlist_next(&vpt->data.attribute.ar, ar))) {
		fr_dict_attr_t const	*unknown, *known;

		switch (ar->type) {
		case TMPL_ATTR_TYPE_NORMAL:		/* Skip */
			continue;

		case TMPL_ATTR_TYPE_UNRESOLVED:		/* Shouldn't have been called */
			fr_assert(0);
			return -1;

		case TMPL_ATTR_TYPE_UNKNOWN:
			break;
		}

		unknown = ar->ar_da;
		known = fr_dict_unknown_add(fr_dict_unconst(fr_dict_by_da(unknown)), unknown);
		if (!known) return -1;

		/*
		 *	Fixup the parent of the next unknown
		 *	now it's known.
		 */
		next_ar = fr_dlist_next(&vpt->data.attribute.ar, ar);
		if (next_ar && (next_ar->type == TMPL_ATTR_TYPE_UNKNOWN) &&
		    (next_ar->ar_da->parent == unknown)) {
			if (fr_dict_attr_unknown_parent_to_known(fr_dict_attr_unconst(next_ar->ar_da),
								 known) < 0) return -1;
		}

		/*
		 *	Convert the ref to a normal type.
		 *	At runtime there should be no
		 *	"unknown" references as they should
		 *	have all been added to a
		 *	dictionary.
		 */
		ar->type = TMPL_ATTR_TYPE_NORMAL;

		/*
		 *	If the attribute is *NOT* raw then
		 *	swap the canonical unknown with the
		 *	one that was previously associated
		 *	with the tmpl.
		 *
		 *	This establishes the unknown attribute
		 *	in the dictionary if it was really
		 *	unknown whilst not mucking up the
		 *	types for raw attributes.
		 */
		if (!ar->ar_da->flags.is_raw) {
			fr_dict_unknown_free(&ar->ar_da);
			ar->ar_da = known;
		} else if (!fr_cond_assert(!next_ar)) {
			fr_strerror_printf("Only the leaf may be raw");
			return -1;
		}
	}

	return 0;
}

/** Add an unresolved #fr_dict_attr_t specified by a #tmpl_t to the main dictionary
 *
 * @note fr_dict_attr_add will not return an error if the attribute already exists
 *	meaning that multiple #tmpl_t specifying the same attribute can be
 *	passed to this function to be fixed up, so long as the type and flags
 *	are identical.
 *
 * @param[in] dict_def	Default dictionary to use if none is
 *			specified by the tmpl_attr_unresolved.
 * @param[in] vpt	specifying unresolved attribute to add.
 *			``tmpl_da`` pointer will be updated to
 *			point to the #fr_dict_attr_t inserted
 *			into the dictionary. Lists and requests
 *			will be preserved.
 * @param[in] type	to define unresolved attribute as.
 * @param[in] flags	to define unresolved attribute with.
 * @return
 *	- 1 noop (did nothing) - Not possible to convert tmpl.
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_attr_unresolved_add(fr_dict_t *dict_def, tmpl_t *vpt,
			     fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	fr_dict_attr_t const *da;

	if (!vpt) return -1;

	TMPL_VERIFY(vpt);

	if (!tmpl_is_attr_unresolved(vpt)) return 1;

	if (fr_dict_attr_add(dict_def,
			     fr_dict_root(fr_dict_internal()), tmpl_attr_unresolved(vpt), -1, type, flags) < 0) {
		return -1;
	}
	da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_def), tmpl_attr_unresolved(vpt));
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

#ifdef HAVE_REGEX
/** Convert a TMPL_TYPE_REGEX_UNCOMPILED into a TMPL_TYPE_REGEX
 *
 * Other regex types become noops.
 */
ssize_t tmpl_regex_compile(tmpl_t *vpt, bool subcaptures)
{
	ssize_t slen;
	char	*unescaped = vpt->data.unescaped;

	if (tmpl_is_regex_xlat(vpt) || tmpl_is_regex(vpt)) return 0;	/* Don't need compiling */

	fr_assert(tmpl_is_regex_uncompiled(vpt));

	slen = regex_compile(vpt, &vpt->data.reg.ex,
			     unescaped, talloc_array_length(unescaped) - 1,
			     &vpt->data.reg.flags, subcaptures, vpt->rules.at_runtime);
	if (slen <= 0) return vpt->quote != T_BARE_WORD ? slen - 1 : slen;	/* Account for the quoting */
	talloc_free(unescaped);

	vpt->type = TMPL_TYPE_REGEX;

	TMPL_VERIFY(vpt);

	return slen;
}
#endif
/** @} */

/** @name Print the contents of a #tmpl_t
 * @{
 */

/** Print an attribute or list #tmpl_t to a string
 *
 * This function is the direct counterpart to #tmpl_afrom_attr_substr.
 *
 * @param[in] out		Where to write the presentation format #tmpl_t string.
 * @param[in] vpt		to print.
 * @param[in] ar_prefix		Whether to print the '&' at the beginning of attribute
 *				references.
 *				- TMPL_ATTR_REF_PREFIX_YES	- always print.
 *				- TMPL_ATTR_REF_PREFIX_NO	- never print.
 *				- TMPL_ATTR_REF_PREFIX_AUTO	- print if the original tmpl
 *								  was prefixed.
 * @return
 *	- >0 the number of bytes written to the out buffer.
 *	- 0 invalid argument.
 *	- <0 the number of bytes we would have needed to complete the print.
 */
ssize_t tmpl_attr_print(fr_sbuff_t *out, tmpl_t const *vpt, tmpl_attr_prefix_t ar_prefix)
{
	tmpl_request_t		*rr = NULL;
	tmpl_attr_t		*ar = NULL;
	fr_dict_attr_t const	*parent = NULL;
	fr_da_stack_t		stack;
	char			printed_rr = false;
	fr_sbuff_t		our_out = FR_SBUFF_NO_ADVANCE(out);

	if (unlikely(!vpt)) return 0;

	TMPL_VERIFY(vpt);

	/*
	 *	Only print things we can print...
	 */
	switch (vpt->type) {
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_ATTR_UNRESOLVED:
	case TMPL_TYPE_ATTR:
		break;

	default:
		return 0;
	}

	/*
	 *	Handle printing the request reference
	 *	prefix.
	 */
	if ((ar_prefix == TMPL_ATTR_REF_PREFIX_YES) ||
	    ((ar_prefix == TMPL_ATTR_REF_PREFIX_AUTO) && vpt->data.attribute.ref_prefix)) {
		FR_SBUFF_IN_CHAR_RETURN(&our_out, '&');
	}

	/*
	 *	Print request references
	 */
	while ((rr = fr_dlist_next(&vpt->data.attribute.rr, rr))) {
		if (rr->request == REQUEST_CURRENT) continue;	/* Don't print the default request */

		FR_SBUFF_IN_TABLE_STR_RETURN(&our_out, request_ref_table, rr->request, "<INVALID>");
		printed_rr = true;
	}

	/*
	 *	Print list
	 */
	if (tmpl_list(vpt) != PAIR_LIST_REQUEST) {	/* Don't print the default list */
		if (printed_rr) FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');

		FR_SBUFF_IN_TABLE_STR_RETURN(&our_out, pair_list_table, tmpl_list(vpt), "<INVALID>");
		if (fr_dlist_num_elements(&vpt->data.attribute.ar)) {
			FR_SBUFF_IN_CHAR_RETURN(&our_out, vpt->data.attribute.old_list_sep ? ':' : '.');
		}
	} else if (printed_rr) {			/* Request qualifier with no list qualifier */
		if (fr_dlist_num_elements(&vpt->data.attribute.ar)) {
			FR_SBUFF_IN_CHAR_RETURN(&our_out, vpt->data.attribute.old_list_sep ? ':' : '.');
		}
	}

	/*
	 *
	 *	If the leaf attribute is unknown and raw we
	 *	add the .raw prefix.
	 *
	 *	If the leaf attribute is unknown and not raw
	 *	we add the .unknown prefix.
	 *
	 */
	if (!tmpl_is_list(vpt) && (ar = fr_dlist_tail(&vpt->data.attribute.ar))) {
		switch (ar->type) {
		case TMPL_ATTR_TYPE_NORMAL:
		case TMPL_ATTR_TYPE_UNKNOWN:
			if (ar->ar_da->flags.is_raw) FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "raw.");
			break;

		case TMPL_ATTR_TYPE_UNRESOLVED:
			if (ar->ar_unresolved_raw) FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "raw.");
			break;
		}

		/*
		 *	Get the correct root
		 */
		ar = fr_dlist_head(&vpt->data.attribute.ar);
		switch (ar->type) {
		case TMPL_ATTR_TYPE_NORMAL:
		case TMPL_ATTR_TYPE_UNKNOWN:
			fr_proto_da_stack_build(&stack, ar->ar_da);
			parent = stack.da[0];
			break;

		case TMPL_ATTR_TYPE_UNRESOLVED:
			fr_proto_da_stack_build(&stack, ar->ar_unresolved_parent);
			parent = stack.da[0];
			break;
		}
	}

	/*
	 *	Print attribute identifiers
	 */
	ar = NULL;
	while ((ar = fr_dlist_next(&vpt->data.attribute.ar, ar))) {
		fr_dict_attr_t const *ref = NULL;

		if (!tmpl_is_list(vpt)) switch(ar->type) {
		case TMPL_ATTR_TYPE_NORMAL:
		case TMPL_ATTR_TYPE_UNKNOWN:
		{
			unsigned int i;

			fr_proto_da_stack_build_partial(&stack, parent, ar->ar_da);

			/*
			 *	Print from our parent depth to the AR we're processing
			 *
			 *	For refs we skip the attribute pointed to be the ref
			 *	and just print its children.
			 */
			for (i = (parent->depth - 1) + (ar != fr_dlist_head(&vpt->data.attribute.ar));
			     i < ar->ar_da->depth;
			     i++) {
				FR_SBUFF_IN_STRCPY_RETURN(&our_out, stack.da[i]->name);

				/*
				 *	Print intermediary separators
				 *	if necessary.
				 */
				if ((i + 1) < ar->ar_da->depth) FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');
			}

			parent = ar->ar_da;
			ref = fr_dict_attr_ref(parent);
			if (ref) parent = ref;	/* Follow refs */
		}
			break;

		/*
		 *	For unresolved attribute we print the raw identifier we
		 *	got when parsing the tmpl.
		 */
		case TMPL_ATTR_TYPE_UNRESOLVED:
		{
			unsigned int i;

			/*
			 *	This is the first unresolved component in a potential
			 *	chain of unresolved components.  Print the path up to
			 *	the last known parent.
			 */
			if (ar->ar_unresolved_parent) {
				for (i = (parent->depth - 1); i < ar->ar_unresolved_parent->depth; i++) {
					FR_SBUFF_IN_STRCPY_RETURN(&our_out, stack.da[i]->name);
					FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');
				}
			}
			/*
			 *	Then print the unresolved component
			 */
			FR_SBUFF_IN_BSTRCPY_BUFFER_RETURN(&our_out, ar->ar_unresolved);
			break;
		}
		}

		/*
		 *	Add array subscript.
		 *
		 *	Will later be complex filters.
		 */
		switch (ar->ar_num) {
		case NUM_ANY:
			break;

		case NUM_ALL:
			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "[*]");
			break;

		case NUM_COUNT:
			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "[#]");
			break;

		case NUM_LAST:
			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "[n]");
			break;

		default:
			FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "[%i]", ar->ar_num);
			break;
		}

		if (fr_dlist_next(&vpt->data.attribute.ar, ar)) FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');
	}
	return fr_sbuff_set(out, &our_out);
}

/** Print a #tmpl_t to a string
 *
 * This function should primarily be used for regenerating vpt->name when the contents
 * of the #tmpl_t is changed programatically, or when the #tmpl_t is being serialized
 * in some non-standard way, i.e. as a value for a field in a database.
 *
 * This function is the direct counterpart to #tmpl_afrom_substr.
 *
 * @note Does not print flags for regular expressions, as the quoting char is needed
 *	 to separate the elements of the expression.
 *	 Call regex_flags_print to write the flags values to the output buffer.
 *
 * @param[out] out		Where to write the presentation format #tmpl_t string.
 * @param[in] vpt		to print.
 * @param[in] ar_prefix		Whether to print the '&' at the beginning of attribute
 *				references.
 *				- TMPL_ATTR_REF_PREFIX_YES	- always print.
 *				- TMPL_ATTR_REF_PREFIX_NO	- never print.
 *				- TMPL_ATTR_REF_PREFIX_AUTO	- print if the original tmpl
 *								  was prefixed.
 * @param[in] e_rules		Escaping rules used to print strings.
 * @return
 *	- >0 the number of bytes written to the out buffer.
 *	- 0 invalid argument.
 *	- <0 the number of bytes we would have needed to complete the print.
 */
ssize_t tmpl_print(fr_sbuff_t *out, tmpl_t const *vpt,
		   tmpl_attr_prefix_t ar_prefix, fr_sbuff_escape_rules_t const *e_rules)
{
	fr_sbuff_t	our_out = FR_SBUFF_NO_ADVANCE(out);

	if (unlikely(!vpt)) return 0;

	TMPL_VERIFY(vpt);

	switch (vpt->type) {
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_ATTR_UNRESOLVED:
	case TMPL_TYPE_ATTR:
		FR_SBUFF_RETURN(tmpl_attr_print, &our_out, vpt, ar_prefix);
		break;

	case TMPL_TYPE_DATA:
	        FR_SBUFF_RETURN(fr_value_box_print, &our_out, tmpl_value(vpt), e_rules);
		break;

	case TMPL_TYPE_REGEX:
		FR_SBUFF_IN_BSTRNCPY_RETURN(&our_out, vpt->name, vpt->len);	/* Fixme - double escapes */
		break;

	case TMPL_TYPE_REGEX_UNCOMPILED:
		FR_SBUFF_IN_ESCAPE_BUFFER_RETURN(&our_out, vpt->data.unescaped, e_rules);
		break;

	case TMPL_TYPE_UNINITIALISED:
	case TMPL_TYPE_NULL:
	case TMPL_TYPE_MAX:
		break;

	/*
	 *	The remaining types will either
	 *	be xlat expansions, or need
	 *	resolving, in which case the
	 *	unescaped string is available
	 *	in vpt->unescaped.
	 */
	default:
		if (tmpl_contains_xlat(vpt)) {
			FR_SBUFF_RETURN(xlat_print, &our_out, tmpl_xlat(vpt), e_rules);
			break;
		}

		if (tmpl_needs_resolving(vpt)) {
			FR_SBUFF_IN_ESCAPE_BUFFER_RETURN(&our_out, vpt->data.unescaped, e_rules);
			break;
		}

		fr_assert_fail("Can't print invalid tmpl type %s",
			       fr_table_str_by_value(tmpl_type_table, vpt->type, "<INVALID>"));
		break;
	}

	return fr_sbuff_set(out, &our_out);
}

/** Print a #tmpl_t to a string with quotes
 *
 * This function should be used when the tmpl is embedded in some other construct
 * in the server's configuration.
 *
 * It adds standard quoting around tmpl's used as operands in expressions and applies
 * the correct escaping rules.
 *
 * @param[out] out		Where to write the presentation format #tmpl_t string.
 * @param[in] vpt		to print.
 * @param[in] ar_prefix		Whether to print the '&' at the beginning of attribute
 *				references.
 *				- TMPL_ATTR_REF_PREFIX_YES	- always print.
 *				- TMPL_ATTR_REF_PREFIX_NO	- never print.
 *				- TMPL_ATTR_REF_PREFIX_AUTO	- print if the original tmpl
 *								  was prefixed.
 * @return
 *	- >0 the number of bytes written to the out buffer.
 *	- 0 invalid argument.
 *	- <0 the number of bytes we would have needed to complete the print.
 */
ssize_t tmpl_print_quoted(fr_sbuff_t *out, tmpl_t const *vpt, tmpl_attr_prefix_t ar_prefix)
{
	fr_sbuff_t our_out = FR_SBUFF_NO_ADVANCE(out);

	char quote = fr_token_quote[vpt->quote];

	if (quote != '\0') FR_SBUFF_IN_CHAR_RETURN(&our_out, quote);
	FR_SBUFF_RETURN(tmpl_print, &our_out, vpt,
			ar_prefix, fr_value_escape_by_quote[vpt->quote]);
	if (quote != '\0') FR_SBUFF_IN_CHAR_RETURN(&our_out, quote);

	/*
	 *	Optionally print the flags
	 */
	if (vpt->type & TMPL_FLAG_REGEX) FR_SBUFF_RETURN(regex_flags_print, &our_out, tmpl_regex_flags(vpt));

	return fr_sbuff_set(out, &our_out);
}
/** @} */


#ifdef WITH_VERIFY_PTR
/** Used to check whether areas of a tmpl_t are zeroed out
 *
 * @param ptr Offset to begin checking at.
 * @param len How many bytes to check.
 * @return
 *	- Pointer to the first non-zero byte.
 *	- NULL if all bytes were zero.
 */
static uint8_t const *is_zeroed(uint8_t const *ptr, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (ptr[i] != 0x00) return ptr + i;
	}

	return NULL;
}

/** Verify that unused regions of the struct are zeroed out
 *
 */
#define CHECK_ZEROED(_vpt, _field) is_zeroed(((uint8_t const *)&(_vpt)->data) + sizeof((_vpt)->data._field), sizeof((_vpt)->data) - sizeof((_vpt)->data._field))


/** Print hex data
 *
 */
#define PRINT_NON_ZEROED(_vpt, _field, _nz_ptr) \
do { \
	DEBUG("Expected live portion %p-%p (0-%zu)", \
	      _vpt, \
	      (uint8_t const *)&(_vpt)->data + sizeof((_vpt)->data._field), \
	      sizeof((_vpt)->data._field)); \
	DEBUG("Expected zero portion %p-%p (%zu-%zu)", \
	      (uint8_t const *)&(_vpt)->data + sizeof((_vpt)->data._field), \
	      (uint8_t const *)&(_vpt)->data + sizeof((_vpt)->data), \
	      sizeof((_vpt)->data._field), sizeof((_vpt)->data)); \
	HEX_MARKER1((uint8_t const *)&vpt->data, sizeof(vpt->data), nz - (uint8_t const *)&vpt->data, "non-zero memory", ""); \
} while (0)


/** Verify the attribute reference in a tmpl_t make sense
 *
 * @note If the attribute refernece is is invalid, causes the server to exit.
 *
 * @param file obtained with __FILE__.
 * @param line obtained with __LINE__.
 * @param vpt to check.
 */
void tmpl_attr_verify(char const *file, int line, tmpl_t const *vpt)
{
	tmpl_attr_t	*ar = NULL;
	tmpl_attr_t  	*slow = NULL, *fast = NULL;
	tmpl_attr_t	*seen_unknown = NULL;
	tmpl_attr_t	*seen_unresolved = NULL;

	fr_assert(tmpl_is_attr_unresolved(vpt) || tmpl_is_attr(vpt) || tmpl_is_list(vpt));

	/*
	 *	Loop detection
	 */
	while ((slow = fr_dlist_next(&vpt->data.attribute.ar, slow)) &&
	       (fast = fr_dlist_next(&vpt->data.attribute.ar, fast))) {

		/*
		 *	Advances twice as fast as slow...
		 */
		fast = fr_dlist_next(&vpt->data.attribute.ar, fast);
		fr_fatal_assert_msg(fast != slow,
				    "CONSISTENCY CHECK FAILED %s[%u]:  Looping reference list found.  "
				    "Fast pointer hit slow pointer at \"%s\"",
				    file, line,
				    slow->type == TMPL_ATTR_TYPE_UNRESOLVED ? slow->ar_unresolved :
				    slow->da ? slow->da->name : "(null-attr)");
	}

	/*
	 *	Lineage type check
	 *
	 *	Known attribute cannot come after unresolved or unknown attributes
	 *	Unknown attributes cannot come after unresolved attributes
	 */
	while ((ar = fr_dlist_next(&vpt->data.attribute.ar, ar))) {
		switch (ar->type) {
		case TMPL_ATTR_TYPE_NORMAL:
			if (seen_unknown) {
				tmpl_attr_debug(vpt);
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: "
						     "TMPL_TYPE_ATTR known attribute \"%s\" "
						     "occurred after unknown attribute "
						     "in attr ref list",
						     file, line,
						     ar->da->name,
						     ar->unknown.da->name);
			}
			if (seen_unresolved) {
				tmpl_attr_debug(vpt);
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: "
						     "TMPL_TYPE_ATTR known attribute \"%s\" "
						     "occurred after unresolved attribute \"%s\""
						     "in attr ref list",
						     file, line,
						     ar->da->name,
						     ar->ar_unresolved);
			}
			break;

		case TMPL_ATTR_TYPE_UNRESOLVED:
			seen_unresolved = ar;
			break;

		case TMPL_ATTR_TYPE_UNKNOWN:
			seen_unknown = ar;
			if (seen_unresolved) {
				tmpl_attr_debug(vpt);
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: "
						     "TMPL_TYPE_ATTR unknown attribute \"%s\" "
						     "occurred after unresolved attribute "
						     "in attr ref list",
						     file, line, ar->da->name,
						     ar->ar_unresolved);
			}
			break;
		}
	}
}

/** Verify fields of a tmpl_t make sense
 *
 * @note If the #tmpl_t is invalid, causes the server to exit.
 *
 * @param file obtained with __FILE__.
 * @param line obtained with __LINE__.
 * @param vpt to check.
 */
void tmpl_verify(char const *file, int line, tmpl_t const *vpt)
{
	uint8_t const *nz;

	fr_assert(vpt);

	if (tmpl_is_uninitialised(vpt)) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: tmpl_t type was "
				     "TMPL_TYPE_UNINITIALISED (uninitialised)", file, line);
	}

	if (vpt->type >= TMPL_TYPE_MAX) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: tmpl_t type was %i "
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
		if ((nz = is_zeroed((uint8_t const *)&vpt->data, sizeof(vpt->data)))) {
			HEX_MARKER1((uint8_t const *)&vpt->data, sizeof(vpt->data),
				    nz - (uint8_t const *)&vpt->data, "non-zero memory", "");
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_NULL "
					     "has non-zero bytes in its data union", file, line);
		}
		break;

	case TMPL_TYPE_UNRESOLVED:
		if (!vpt->data.unescaped) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_UNRESOLVED "
					     "unescaped field is NULL", file, line);
		 }
		break;

	case TMPL_TYPE_XLAT_UNRESOLVED:
		if (!tmpl_xlat_flags(vpt)->needs_resolving) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_XLAT_UNRESOLVED "
					     "does not have xlat_flags_t -> need_pass2 set", file, line);
		}
		if (!tmpl_xlat(vpt)) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_XLAT_UNRESOLVED "
					     "has a NULL xlat.ex field", file, line);

		}
		break;

	case TMPL_TYPE_XLAT:
		if (!vpt->data.xlat.ex) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_XLAT "
					     "has a NULL xlat.ex field", file, line);

		}
		break;

/* @todo When regexes get converted to xlat the flags field of the regex union is used
	case TMPL_TYPE_XLAT_UNRESOLVED:
		if (is_zeroed((uint8_t const *)&vpt->data, sizeof(vpt->data))) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_XLAT_UNRESOLVED "
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
	case TMPL_TYPE_EXEC_UNRESOLVED:
		/* tmpl_xlat(vpt) can be initialized */
		break;

	case TMPL_TYPE_ATTR_UNRESOLVED:
		if ((fr_dlist_num_elements(&vpt->data.attribute.ar) > 0) &&
		    ((tmpl_attr_t *)fr_dlist_tail(&vpt->data.attribute.ar))->da) {
#ifndef NDEBUG
			tmpl_attr_debug(vpt);
#endif
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR_UNRESOLVED contains %zu "
					     "references", file, line, fr_dlist_num_elements(&vpt->data.attribute.ar));
		}
		break;

	case TMPL_TYPE_ATTR:
		if ((nz = CHECK_ZEROED(vpt, attribute))) {
			PRINT_NON_ZEROED(vpt, attribute, nz);
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

			da = tmpl_da(vpt);

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

			if (!tmpl_da(vpt)->flags.is_unknown && !tmpl_da(vpt)->flags.is_raw && (da != tmpl_da(vpt))) {
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

			tmpl_attr_verify(file, line, vpt);
		}
		break;

	case TMPL_TYPE_LIST:
		if ((nz = CHECK_ZEROED(vpt, attribute))) {
			PRINT_NON_ZEROED(vpt, attribute, nz);
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_LIST"
					     "has non-zero bytes after the data.attribute struct in the union",
					     file, line);
		}

		if ((fr_dlist_num_elements(&vpt->data.attribute.ar) > 0) &&
		    ((tmpl_attr_t *)fr_dlist_tail(&vpt->data.attribute.ar))->da) {
#ifndef NDEBUG
			tmpl_attr_debug(vpt);
#endif
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_LIST contains %zu "
					     "references", file, line, fr_dlist_num_elements(&vpt->data.attribute.ar));
		}
		break;

	case TMPL_TYPE_DATA:
		if ((nz = CHECK_ZEROED(vpt, literal))) {
			PRINT_NON_ZEROED(vpt, literal, nz);
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
		 *	Unlike fr_pair_ts we can't guarantee that fr_pair_t_TMPL buffers will
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

	case TMPL_TYPE_REGEX_UNCOMPILED:
	case TMPL_TYPE_REGEX_XLAT:
	case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:
#ifndef HAVE_REGEX
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX_XLAT_UNRESOLVED - No regex support",
				     file, line);
#endif
		break;

	case TMPL_TYPE_REGEX:
#ifdef HAVE_REGEX
		if (tmpl_regex(vpt) == NULL) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_REGEX "
					     "reg.ex field was NULL", file, line);
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

/** Preparse a string in preparation for passing it to tmpl_afrom_substr()
 *
 *  Note that the input string is not modified, which means that the
 *  tmpl_afrom_substr() function MUST un-escape it.
 *
 *  The caller should pass 'out' and 'outlen' to tmpl_afrom_substr()
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
 *	If the tmpl is needs_async, then it is async
 *	If the tmpl is not needs_async, then it will not yield
 *
 *	If the tmpl yields, then async is required.
 */
bool tmpl_async_required(tmpl_t const *vpt)
{
	switch (vpt->type) {
	case TMPL_TYPE_EXEC:	/* we don't have "exec no-wait" here */
	case TMPL_TYPE_XLAT_UNRESOLVED:	/* we have no idea, so be safe */
		return true;

	case TMPL_TYPE_XLAT:
		return xlat_async_required(tmpl_xlat(vpt));

	default:
		return false;
	}
}
