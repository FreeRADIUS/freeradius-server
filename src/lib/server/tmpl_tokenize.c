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
#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/misc.h>

#include <freeradius-devel/util/sbuff.h>

#include <ctype.h>

/** Define a global variable for specifying a default request reference
 *
 * @param[in] _name	what the global variable should be called.
 * @param[in] _ref	one of the values of tmpl_request_ref_t
 *			- REQUEST_CURRENT
 *			- REQUEST_OUTER,
 *			- REQUEST_PARENT,
 *			- REQUEST_UNKNOWN
 */
#define TMPL_REQUEST_REF_DEF(_name, _def) \
static tmpl_request_t _name ## _entry = { \
	.entry = { \
		.entry = { \
			.next = &_name.head.entry, \
			.prev = &_name.head.entry \
		} \
	}, \
	.request = _def \
}; \
FR_DLIST_HEAD(tmpl_request_list) _name = { \
	.head = { \
		.offset = offsetof(tmpl_request_t, entry), \
		.entry = { \
			.next = &_name ## _entry.entry.entry, \
			.prev = &_name ## _entry.entry.entry, \
		}, \
		.num_elements = 1, \
	} \
}

/** Use the current request as the default
 *
 * Used as .attr.request_def = &tmpl_request_def_current;
 */
TMPL_REQUEST_REF_DEF(tmpl_request_def_current, REQUEST_CURRENT);

/** Use the outer request as the default
 *
 * Used as .attr.request_def = &tmpl_request_def_outer;
 */
TMPL_REQUEST_REF_DEF(tmpl_request_def_outer, REQUEST_OUTER);

/** Use the parent request as the default
 *
 * Used as .attr.request_def = &tmpl_request_def_parent;
 */
TMPL_REQUEST_REF_DEF(tmpl_request_def_parent, REQUEST_PARENT);

/** Default parser rules
 *
 * Because this is getting to be a ridiculous number of parsing rules
 * to pass in via arguments.
 *
 * Defaults are used if a NULL rules pointer is passed to the parsing function.
 */
static tmpl_rules_t const default_rules = {

};


/* clang-format off */
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
static fr_table_num_ordered_t const attr_table[] = {
	{ L("normal"),		TMPL_ATTR_TYPE_NORMAL		},
	{ L("unknown"),		TMPL_ATTR_TYPE_UNKNOWN		},
	{ L("unresolved"),	TMPL_ATTR_TYPE_UNRESOLVED	}
};
static size_t attr_table_len = NUM_ELEMENTS(attr_table);

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

/** Map keywords to #tmpl_request_ref_t values
 */
fr_table_num_sorted_t const tmpl_request_ref_table[] = {
	{ L("current"),		REQUEST_CURRENT			},
	{ L("outer"),		REQUEST_OUTER			},
	{ L("parent"),		REQUEST_PARENT			},
};
size_t tmpl_request_ref_table_len = NUM_ELEMENTS(tmpl_request_ref_table);


/** Special attribute reference indexes
 */
static fr_table_num_sorted_t const attr_num_table[] = {
	{ L("*"),		NUM_ALL				},
	{ L("#"),		NUM_COUNT			},
	{ L("u"),		NUM_UNSPEC			},
	{ L("n"),		NUM_LAST			}
};
static size_t attr_num_table_len = NUM_ELEMENTS(attr_num_table);
/* clang-format on */

static void attr_to_raw(tmpl_t *vpt, tmpl_attr_t *ref);

/*
 *	Can't use |= or ^= else we get out of range errors
 */
#define UNRESOLVED_SET(_flags) (*(_flags) = (*(_flags) | TMPL_FLAG_UNRESOLVED))
#define RESOLVED_SET(_flags) (*(_flags) = (*(_flags) & ~TMPL_FLAG_UNRESOLVED))

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

void tmpl_attr_ref_debug(const tmpl_attr_t *ar, int i)
{
	char buffer[sizeof(STRINGIFY(INT16_MAX)) + 1];

	snprintf(buffer, sizeof(buffer), "%i", ar->ar_num);

	switch (ar->type) {
	case TMPL_ATTR_TYPE_NORMAL:
	case TMPL_ATTR_TYPE_UNKNOWN:
		if (!ar->da) {
			FR_FAULT_LOG("\t[%u] %s null%s%s%s",
				     i,
				     fr_table_str_by_value(attr_table, ar->type, "<INVALID>"),
				     ar->ar_num != NUM_UNSPEC ? "[" : "",
				     ar->ar_num != NUM_UNSPEC ? fr_table_str_by_value(attr_num_table, ar->ar_num, buffer) : "",
				     ar->ar_num != NUM_UNSPEC ? "]" : "");
			return;
		}

		FR_FAULT_LOG("\t[%u] %s %s %s%s%s%s (%p) attr %u",
			     i,
			     fr_table_str_by_value(attr_table, ar->type, "<INVALID>"),
			     fr_type_to_str(ar->da->type),
			     ar->da->name,
			     ar->ar_num != NUM_UNSPEC ? "[" : "",
			     ar->ar_num != NUM_UNSPEC ? fr_table_str_by_value(attr_num_table, ar->ar_num, buffer) : "",
			     ar->ar_num != NUM_UNSPEC ? "]" : "",
			     ar->da,
			     ar->da->attr
		);
		FR_FAULT_LOG("\t    is_raw     : %s", ar->da->flags.is_raw ? "yes" : "no");
		FR_FAULT_LOG("\t    is_unknown : %s", ar->da->flags.is_unknown ? "yes" : "no");
		if (ar->ar_parent) FR_FAULT_LOG("\t    parent     : %s (%p)", ar->ar_parent->name, ar->ar_parent);
		break;


	case TMPL_ATTR_TYPE_UNRESOLVED:
		/*
		 *	Type reveals unresolved status
		 *	so we don't need to add it explicitly
		 */
		FR_FAULT_LOG("\t[%u] %s %s%s%s%s",
			     i,
			     fr_table_str_by_value(attr_table, ar->type, "<INVALID>"),
			     ar->ar_unresolved,
			     ar->ar_num != NUM_UNSPEC ? "[" : "",
			     ar->ar_num != NUM_UNSPEC ? fr_table_str_by_value(attr_num_table, ar->ar_num, buffer) : "",
			     ar->ar_num != NUM_UNSPEC ? "]" : "");
		if (ar->ar_parent) 			FR_FAULT_LOG("\t    parent     : %s", ar->ar_parent->name);
		if (ar->ar_unresolved_namespace)	FR_FAULT_LOG("\t    namespace  : %s", ar->ar_unresolved_namespace->name);
		break;

	default:
		FR_FAULT_LOG("\t[%u] Bad type %s(%u)",
			     i, fr_table_str_by_value(attr_table, ar->type, "<INVALID>"), ar->type);
		break;
	}
}

void tmpl_attr_ref_list_debug(FR_DLIST_HEAD(tmpl_attr_list) const *ar_head)
{
	tmpl_attr_t		*ar = NULL;
	unsigned int		i = 0;

	FR_FAULT_LOG("attribute references:");
	/*
	 *	Print all the attribute references
	 */
	while ((ar = tmpl_attr_list_next(ar_head, ar))) {
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
			     tmpl_type_to_str(vpt->type));
		return;
	}

	FR_FAULT_LOG("tmpl_t %s (%.8x) \"%pV\" (%p)",
		     tmpl_type_to_str(vpt->type),
		     vpt->type,
		     fr_box_strvalue_len(vpt->name, vpt->len), vpt);

	FR_FAULT_LOG("\tcast       : %s", fr_type_to_str(tmpl_rules_cast(vpt)));
	FR_FAULT_LOG("\tquote      : %s", fr_table_str_by_value(fr_token_quotes_table, vpt->quote, "<INVALID>"));

	FR_FAULT_LOG("request references:");

	/*
	 *	Print all the request references
	 */
	while ((rr = tmpl_request_list_next(&vpt->data.attribute.rr, rr))) {
		FR_FAULT_LOG("\t[%u] %s (%u)", i,
			     fr_table_str_by_value(tmpl_request_ref_table, rr->request, "<INVALID>"), rr->request);
		i++;
	}

	FR_FAULT_LOG("list: %s", fr_table_str_by_value(pair_list_table, vpt->data.attribute.list, "<INVALID>"));
	tmpl_attr_ref_list_debug(tmpl_attr(vpt));
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
		     tmpl_type_to_str(vpt->type),
		     vpt->type,
		     fr_box_strvalue_len(vpt->name, vpt->len), vpt);

	FR_FAULT_LOG("\tcast       : %s", fr_type_to_str(tmpl_rules_cast(vpt)));
	FR_FAULT_LOG("\tquote      : %s", fr_table_str_by_value(fr_token_quotes_table, vpt->quote, "<INVALID>"));
	switch (vpt->type) {
	case TMPL_TYPE_NULL:
		return;

	case TMPL_TYPE_DATA:
		FR_FAULT_LOG("\ttype       : %s", fr_type_to_str(tmpl_value_type(vpt)));
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

/** @name Parse list and request qualifiers to #pair_list_t and #tmpl_request_ref_t values
 *
 * These functions also resolve #pair_list_t and #tmpl_request_ref_t values to #request_t
 * structs and the head of #fr_pair_t lists in those structs.
 *
 * For adding new #fr_pair_t to the lists, the #tmpl_list_ctx function can be used
 * to obtain the appropriate TALLOC_CTX pointer.
 *
 * @note These don't really have much to do with #tmpl_t. They're in the same
 *	file as they're used almost exclusively by the tmpl_* functions.
 * @{
 */

/** Resolve attribute name to a #pair_list_t value.
 *
 * Check the name string for #pair_list_t qualifiers and write a #pair_list_t value
 * for that list to out. This value may be passed to #tmpl_pair_list, along with the current
 * #request_t, to get a pointer to the actual list in the #request_t.
 *
 * If we're sure we've definitely found a list qualifier token delimiter (``:``) but the
 * string doesn't match a #tmpl_pair_list qualifier, return 0 and write #PAIR_LIST_UNKNOWN
 * to out.
 *
 * If we can't find a string that looks like a request qualifier, set out to def, and
 * return 0.
 *
 * @note #tmpl_pair_list_name should be called before passing a name string that may
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
 * @see tmpl_pair_list
 */
size_t tmpl_pair_list_name(tmpl_pair_list_t *out, char const *name, tmpl_pair_list_t def)
{
	char const *p = name;
	char const *q;

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

 /** Allocate a new request reference and add it to the end of the attribute reference list
 *
 */
static inline CC_HINT(always_inline) CC_HINT(nonnull(2,3))
void tmpl_request_ref_list_copy(TALLOC_CTX *ctx,
			        FR_DLIST_HEAD(tmpl_request_list) *out, FR_DLIST_HEAD(tmpl_request_list) const *in)
{
	tmpl_request_t	*rr = NULL;
	tmpl_request_t	*n_rr = NULL;

	/*
	 *	Duplicate the complete default list
	 */
	while ((rr = tmpl_request_list_next(in, rr))) {
		MEM(n_rr = talloc(ctx, tmpl_request_t));
		*n_rr = (tmpl_request_t){
			.request = rr->request
		};
		tmpl_request_list_insert_tail(out, n_rr);
		ctx = n_rr;	/* Chain the contexts */
	}
}

 /** Allocate a new request reference list and copy request references into it
 *
 */
static inline CC_HINT(always_inline) CC_HINT(nonnull(2,3))
void tmpl_request_ref_list_acopy(TALLOC_CTX *ctx,
			         FR_DLIST_HEAD(tmpl_request_list) **out, FR_DLIST_HEAD(tmpl_request_list) const *in)
{
	FR_DLIST_HEAD(tmpl_request_list) *rql;

	MEM(rql = talloc_zero(ctx, FR_DLIST_HEAD(tmpl_request_list)));
	tmpl_request_list_talloc_init(rql);

	tmpl_request_ref_list_copy(rql, rql, in);

	*out = rql;
}

/** Dump a request list to stderr
 *
 */
void tmpl_request_ref_list_debug(FR_DLIST_HEAD(tmpl_request_list) const *rql)
{
	tmpl_request_t *rr = NULL;

	while ((rr = tmpl_request_list_next(rql, rr))) {
		FR_FAULT_LOG("request - %s (%u)",
			     fr_table_str_by_value(tmpl_request_ref_table, rr->request, "<INVALID>"),
			     rr->request);
	}
}

/** Compare a list of request qualifiers
 *
 * @param[in] a		first list.  If NULL tmpl_request_def_current will be used.
 * @param[in] b		second list.  If NULL tmpl_request_def_current will be used.
 * @return
 *	- >0 a > b
 *	- 0 a == b
 *	- <0 a < b
 */
int8_t tmpl_request_ref_list_cmp(FR_DLIST_HEAD(tmpl_request_list) const *a, FR_DLIST_HEAD(tmpl_request_list) const *b)
{
	tmpl_request_t *a_rr = NULL, *b_rr = NULL;

	/*
	 *	NULL, uninit, empty are all equivalent
	 *	to tmpl_request_def_current.
	 *
	 *	We need all these equivalent checks to
	 *	deal with uninitialised tmpl rules.
	 */
	if (!a || !tmpl_request_list_initialised(a) || tmpl_request_list_empty(a)) a = &tmpl_request_def_current;
	if (!b || !tmpl_request_list_initialised(b) || tmpl_request_list_empty(b)) b = &tmpl_request_def_current;

	/*
	 *	Fast path...
	 */
	if (a == b) return 0;

	for (;;) {
		a_rr = tmpl_request_list_next(a, a_rr);
		b_rr = tmpl_request_list_next(b, b_rr);

		if (!a_rr || !b_rr) return CMP(tmpl_request_list_num_elements(a), tmpl_request_list_num_elements(b));

		CMP_RETURN(a_rr, b_rr, request);
	}
}

/** Parse one or more request references, writing the list to out
 *
 * @parma[in] ctx	to allocate request refs in.
 * @param[out] err	If !NULL where to write the parsing error.
 * @param[in] in	Sbuff to read request references from.
 * @param[in] p_rules	Parse rules.
 * @param[in] at_rules	Default list and other rules.
 * @return
 *	- >= 0 the number of bytes parsed.
 *      - <0 negative offset for where the error occurred
 */
static fr_slen_t tmpl_request_ref_list_from_substr(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
						   FR_DLIST_HEAD(tmpl_request_list) *out,
						   fr_sbuff_t *in,
						   fr_sbuff_parse_rules_t const *p_rules,
						   tmpl_attr_rules_t const *at_rules)
{
	tmpl_request_ref_t	ref;
	tmpl_request_t		*rr;
	size_t			ref_len;
	fr_sbuff_t		our_in = FR_SBUFF(in);
	tmpl_request_t		*tail = tmpl_request_list_tail(out);
	unsigned int		depth = 0;
	fr_sbuff_marker_t	m;

	if (!at_rules) at_rules = &default_rules.attr;

	/*
	 *	We could make the caller do this but as this
	 *	function is intended to help populate tmpl rules,
	 *	just be nice...
	 */
	if (!tmpl_request_list_initialised(out)) tmpl_request_list_talloc_init(out);

	fr_sbuff_marker(&m, &our_in);
	for (depth = 0; depth < TMPL_MAX_REQUEST_REF_NESTING; depth++) {
		bool end;


		/*
		 *	Search for a known request reference like
		 *	'current', or 'parent'.
		 */
		fr_sbuff_out_by_longest_prefix(&ref_len, &ref, tmpl_request_ref_table, &our_in, REQUEST_UNKNOWN);

		/*
		 *	No match
		 */
		if (ref_len == 0) {
			/*
			 *	If depth == 0, we're at the start
			 *	so just use the default request
			 *	reference.
			 */
		default_ref:
			if ((depth == 0) && at_rules->request_def) {
				tmpl_request_ref_list_copy(ctx, out, at_rules->request_def);
			}
			break;
		}

		/*
		 *	We don't want to misidentify the list
		 *	as being part of an attribute.
		 */
		if (!fr_sbuff_is_char(&our_in, '.') && (fr_sbuff_is_in_charset(&our_in, fr_dict_attr_allowed_chars) || !tmpl_substr_terminal_check(&our_in, p_rules))) {
			goto default_ref;
		}

		if (at_rules->parent || at_rules->disallow_qualifiers) {
			fr_strerror_const("It is not permitted to specify a request reference here");
			if (err) *err = TMPL_ATTR_ERROR_INVALID_LIST_QUALIFIER;

			fr_sbuff_set(&our_in, in);	/* Marker at the start */
		error:
			tmpl_request_list_talloc_free_to_tail(out, tail);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		/*
		 *	Add a new entry to the dlist
		 */
		MEM(rr = talloc(ctx, tmpl_request_t));
		*rr = (tmpl_request_t){
			.request = ref
		};
		tmpl_request_list_insert_tail(out, rr);

		/*
		 *	Advance past the separator (if there is one)
		 */
		end = !fr_sbuff_next_if_char(&our_in, '.');

		/*
		 *	Update to the last successfully parsed component
		 *
		 *	This makes it easy to backtrack from refs like
		 *
		 *		parent.outer-realm-name
		 */
		fr_sbuff_set(&m, &our_in);

		if (end) break;
	}

	/*
	 *	Nesting level too deep
	 */
	if (depth > TMPL_MAX_REQUEST_REF_NESTING) {
		fr_strerror_const("Request ref nesting too deep");
		if (err) *err = TMPL_ATTR_ERROR_NESTING_TOO_DEEP;
		goto error;	/* Leave marker at the end */
	}

	FR_SBUFF_SET_RETURN(in, &m);

}

/** Parse one or more request references, allocing a new list and adding the references to it
 *
 * This can be used to create request ref lists for rules and for tmpls.
 *
 * @parma[in] ctx	to allocate request refs in.
 * @param[out] err	If !NULL where to write the parsing error.
 * @param[in] in	Sbuff to read request references from.
 * @param[in] p_rules	Parse rules.
 * @param[in] at_rules	Default list and other rules.
 * @return
 *	- >= 0 the number of bytes parsed.
 *      - <0 negative offset for where the error occurred
 */
fr_slen_t tmpl_request_ref_list_afrom_substr(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
					     FR_DLIST_HEAD(tmpl_request_list) **out,
					     fr_sbuff_t *in,
					     fr_sbuff_parse_rules_t const *p_rules,
					     tmpl_attr_rules_t const *at_rules)
{
	fr_slen_t	slen;

	FR_DLIST_HEAD(tmpl_request_list) *rql;

	MEM(rql = talloc_zero(ctx, FR_DLIST_HEAD(tmpl_request_list)));
	tmpl_request_list_talloc_init(rql);

	slen = tmpl_request_ref_list_from_substr(rql, err, rql, in, p_rules, at_rules);
	if (slen < 0) {
		talloc_free(rql);
		return slen;
	}

	*out = rql;

	return slen;
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
		tmpl_attr_list_talloc_init(tmpl_attr(vpt));
		tmpl_request_list_talloc_init(&vpt->data.attribute.rr);
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

/** Change the default dictionary in the tmpl's resolution rules
 *
 * @param[in] vpt	to alter.
 * @param[in] dict	to set.
 */
void tmpl_set_dict_def(tmpl_t *vpt, fr_dict_t const *dict)
{
	vpt->rules.attr.dict_def = dict;
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
	vpt->name = fr_vasprintf(vpt, fmt, ap);
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
 * @param[in] t_rules	used during parsing.
 * @return a pointer to the initialised #tmpl_t. The same value as vpt.
 */
tmpl_t *tmpl_init_shallow(tmpl_t *vpt, tmpl_type_t type, fr_token_t quote,
			  char const *name, ssize_t len, tmpl_rules_t const *t_rules)
{
	memset(vpt, 0, sizeof(*vpt));
	tmpl_type_init(vpt, type);
	tmpl_set_name_shallow(vpt, quote, name, len);
	if (t_rules) vpt->rules = *t_rules;

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
 * @param[in] t_rules	used during parsing.
 * @return A pointer to the newly initialised tmpl.
 */
tmpl_t *tmpl_init(tmpl_t *vpt, tmpl_type_t type, fr_token_t quote,
		  char const *name, ssize_t len, tmpl_rules_t const *t_rules)
{
	memset(vpt, 0, sizeof(*vpt));
	tmpl_type_init(vpt, type);
	tmpl_set_name(vpt, quote, name, len);
	if (t_rules) vpt->rules = *t_rules;

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

/** Allocate a new attribute reference and add it to the end of the attribute reference list
 *
 */
static tmpl_attr_t *tmpl_attr_add(tmpl_t *vpt, tmpl_attr_type_t type)
{
	tmpl_attr_t	*ar;
	TALLOC_CTX	*ctx;

	if (tmpl_attr_list_num_elements(tmpl_attr(vpt)) == 0) {
		ctx = vpt;
	} else {
		ctx = tmpl_attr_list_tail(tmpl_attr(vpt));
	}

	MEM(ar = talloc(ctx, tmpl_attr_t));
	*ar = (tmpl_attr_t){
		.type = type,
		.filter = {
			.num = NUM_UNSPEC
		}
	};
	tmpl_attr_list_insert_tail(tmpl_attr(vpt), ar);

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
	fr_slen_t	slen;
	tmpl_t		*vpt;
	fr_token_t	quote = (data->type == FR_TYPE_STRING) ? T_SINGLE_QUOTED_STRING : T_BARE_WORD;

	MEM(vpt = talloc(ctx, tmpl_t));
	slen = fr_value_box_aprint(vpt, &name, data, fr_value_escape_by_quote[quote]);
	if (slen < 0) {
	error:
		talloc_free(vpt);
		return -1;
	}

	tmpl_init_shallow(vpt, TMPL_TYPE_DATA, quote, name, slen, NULL);

	if (steal) {
		if (fr_value_box_steal(vpt, tmpl_value(vpt), data) < 0) goto error;
	} else {
		if (fr_value_box_copy(vpt, tmpl_value(vpt), data) < 0) goto error;
	}
	*out = vpt;

	return 0;
}

/** Copy a list of attribute and request references from one tmpl to another
 *
 */
int tmpl_attr_copy(tmpl_t *dst, tmpl_t const *src)
{
	tmpl_attr_t *src_ar = NULL, *dst_ar;

	/*
	 *	Clear any existing attribute references
	 */
	if (tmpl_attr_list_num_elements(tmpl_attr(dst)) > 0) tmpl_attr_list_talloc_reverse_free(tmpl_attr(dst));

	while ((src_ar = tmpl_attr_list_next(tmpl_attr(src), src_ar))) {
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
	 *	and copy the ones from the source.
	 */
	tmpl_request_list_talloc_reverse_free(&dst->data.attribute.rr);
	tmpl_request_ref_list_copy(dst, &dst->data.attribute.rr, &src->data.attribute.rr);

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
	if (tmpl_attr_list_num_elements(tmpl_attr(vpt)) > 0) {
		tmpl_attr_list_talloc_reverse_free(tmpl_attr(vpt));
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
	ref->ar_parent = fr_dict_root(fr_dict_by_da(da));	/* Parent is the root of the dictionary */

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
	if (tmpl_attr_list_num_elements(tmpl_attr(vpt)) > 0) {
		if (tmpl_attr_list_num_elements(tmpl_attr(vpt)) > 1) {
			ref = tmpl_attr_list_tail(tmpl_attr(vpt));
			parent = tmpl_attr_list_prev(tmpl_attr(vpt), ref);

			if (!fr_dict_attr_common_parent(parent->ar_da, da, true)) {
				fr_strerror_const("New leaf da and old leaf da do not share the same ancestor");
				return -1;
			}
		} else {
			ref = tmpl_attr_list_tail(tmpl_attr(vpt));
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
	/*
	 *	FIXME - Should be calculated from existing ar
	 */
	ref->ar_parent = fr_dict_root(fr_dict_by_da(da));	/* Parent is the root of the dictionary */

	TMPL_ATTR_VERIFY(vpt);

	return 0;
}

void tmpl_attr_set_leaf_num(tmpl_t *vpt, int16_t num)
{
	tmpl_attr_t *ar;

	tmpl_assert_type(tmpl_is_attr(vpt) || tmpl_is_list(vpt) || tmpl_is_attr_unresolved(vpt));

	if (tmpl_attr_list_num_elements(tmpl_attr(vpt)) == 0) {
		ar = tmpl_attr_add(vpt, TMPL_ATTR_TYPE_UNKNOWN);
	} else {
		ar = tmpl_attr_list_tail(tmpl_attr(vpt));
	}

	ar->ar_num = num;

	TMPL_ATTR_VERIFY(vpt);
}

/** Rewrite the leaf's instance number
 *
 */
void tmpl_attr_rewrite_leaf_num(tmpl_t *vpt, int16_t from, int16_t to)
{
	tmpl_attr_t *ref = NULL;

	tmpl_assert_type(tmpl_is_attr(vpt) || tmpl_is_list(vpt) || tmpl_is_attr_unresolved(vpt));

	if (tmpl_attr_list_num_elements(tmpl_attr(vpt)) == 0) return;

	ref = tmpl_attr_list_tail(tmpl_attr(vpt));
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

	while ((ref = tmpl_attr_list_next(tmpl_attr(vpt), ref))) if (ref->ar_num == from) ref->ar_num = to;

	TMPL_ATTR_VERIFY(vpt);
}

/** Set the request for an attribute ref
 *
 */
void tmpl_attr_set_request_ref(tmpl_t *vpt, FR_DLIST_HEAD(tmpl_request_list) const *request_def)
{
	fr_assert_msg(tmpl_is_attr(vpt), "Expected tmpl type 'attr', got '%s'",
		      tmpl_type_to_str(vpt->type));

	/*
	 *	Clear any existing request references
	 */
	tmpl_request_list_talloc_reverse_free(&vpt->data.attribute.rr);
	tmpl_request_ref_list_copy(vpt, &vpt->data.attribute.rr, request_def);

	TMPL_ATTR_VERIFY(vpt);
}

void tmpl_attr_set_list(tmpl_t *vpt, tmpl_pair_list_t list)
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
	tmpl_attr_list_insert_tail(tmpl_attr(vpt), ar);

	switch (ar->ar_num) {
	case 0:
	case NUM_UNSPEC:
		break;

	default:
		ar->resolve_only = true;
		while ((ar = tmpl_attr_list_prev(tmpl_attr(vpt), ar))) ar->resolve_only = true;
		break;
	}
}

/** Parse array subscript and in future other filters
 *
 * @param[out] err	Parse error code.
 * @param[in] ar	to populate filter for.
 * @param[in] name	containing more attribute ref data.
 * @param[in] t_rules	see tmpl_attr_afrom_attr_substr.
 * @return
 *	- >0 if a filter was parsed.
 *	- 0 if no filter was available.
 *	- <0 on filter parse error.
 */
static fr_slen_t tmpl_attr_parse_filter(tmpl_attr_error_t *err, tmpl_attr_t *ar,
					fr_sbuff_t *name, tmpl_attr_rules_t const *t_rules)
{
	fr_sbuff_t our_name = FR_SBUFF(name);

	/*
	 *	Parse array subscript (and eventually complex filters)
	 */
	if (!fr_sbuff_next_if_char(&our_name, '[')) return 0;

	if (t_rules->disallow_filters) {
		fr_strerror_const("Filters not allowed here");
		if (err) *err = TMPL_ATTR_ERROR_FILTER_NOT_ALLOWED;
		fr_sbuff_set_to_start(&our_name);
		FR_SBUFF_ERROR_RETURN(&our_name);
	}

	ar->ar_filter_type = TMPL_ATTR_FILTER_TYPE_INDEX;
	fr_sbuff_switch(&our_name, '\0') {
	case '#':
		ar->ar_num = NUM_COUNT;
		fr_sbuff_next(&our_name);
		break;

	case '*':
		ar->ar_num = NUM_ALL;
		fr_sbuff_next(&our_name);
		break;

	case 'n':
		ar->ar_num = NUM_LAST;
		fr_sbuff_next(&our_name);
		break;

	/* Used as EOB here */
	missing_closing:
	case '\0':
		fr_strerror_const("No closing ']' for array index");
		if (err) *err = TMPL_ATTR_ERROR_INVALID_ARRAY_INDEX;
	error:
		FR_SBUFF_ERROR_RETURN(&our_name);

	default:
	{
		fr_sbuff_parse_error_t	sberr = FR_SBUFF_PARSE_OK;
		fr_sbuff_t tmp = FR_SBUFF(&our_name);

		if (fr_sbuff_out(&sberr, &ar->ar_num, &tmp) < 0) {
			if (sberr == FR_SBUFF_PARSE_ERROR_NOT_FOUND) {
				fr_strerror_const("Invalid array index");
				if (err) *err = TMPL_ATTR_ERROR_INVALID_ARRAY_INDEX;
				goto error;
			}

			fr_strerror_const("Invalid array index");
			if (err) *err = TMPL_ATTR_ERROR_INVALID_ARRAY_INDEX;
			goto error;
		}

		if ((ar->ar_num > 1000) || (ar->ar_num < 0)) {
			fr_strerror_printf("Invalid array index '%hi' (should be between 0-1000)", ar->ar_num);
			ar->ar_num = 0;
			if (err) *err = TMPL_ATTR_ERROR_INVALID_ARRAY_INDEX;
			goto error;
		}
		fr_sbuff_set(&our_name, &tmp);	/* Advance name _AFTER_ doing checks */
	}
		break;
	}

	/*
	 *	Always advance here, so the error
	 *	marker points to the bad char.
	 */
	if (!fr_sbuff_next_if_char(&our_name, ']')) goto missing_closing;

	FR_SBUFF_SET_RETURN(name, &our_name);
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
 * @param[in] t_rules		see tmpl_attr_afrom_attr_substr.
 * @param[in] depth		How deep we are.  Used to check for maximum nesting level.
 * @return
 *	- <0 on error.
 *	- 0 on success.
 */
static inline CC_HINT(nonnull(3,6))
int tmpl_attr_afrom_attr_unresolved_substr(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
					   tmpl_t *vpt,
					   fr_dict_attr_t const *parent, fr_dict_attr_t const *namespace,
					   fr_sbuff_t *name, tmpl_attr_rules_t const *t_rules,
					   unsigned int depth)
{
	tmpl_attr_t		*ar = NULL;
	int			ret;
	char			*unresolved;
	size_t			len;

	if (depth > FR_DICT_MAX_TLV_STACK) {
		fr_strerror_const("Attribute nesting too deep");
		if (err) *err = TMPL_ATTR_ERROR_NESTING_TOO_DEEP;
		return -1;
	}

	/*
	 *	Input too short
	 */
	if (!fr_sbuff_extend(name)) {
		fr_strerror_const("Missing attribute reference");
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
		fr_strerror_const("Invalid attribute name");
		if (err) *err = TMPL_ATTR_ERROR_INVALID_NAME;
	error:
		talloc_free(ar);
		return -1;
	}
	if (len > FR_DICT_ATTR_MAX_NAME_LEN) {
		fr_strerror_const("Attribute name is too long");
		if (err) *err = TMPL_ATTR_ERROR_INVALID_NAME;
		goto error;
	}

	*ar = (tmpl_attr_t){
		.ar_num = NUM_UNSPEC,
		.ar_type = TMPL_ATTR_TYPE_UNRESOLVED,
		.ar_unresolved = unresolved,
		.ar_unresolved_namespace = namespace,
		.ar_parent = parent,
	};

	if (tmpl_attr_parse_filter(err, ar, name, t_rules) < 0) goto error;

	/*
	 *	Insert the ar into the list of attribute references
	 */
	tmpl_attr_insert(vpt, ar);

	/*
	 *	Once one OID component is created as unresolved all
	 *	future OID components are also unresolved.
	 */
	if (fr_sbuff_next_if_char(name, '.')) {
		ret = tmpl_attr_afrom_attr_unresolved_substr(ctx, err, vpt, NULL, NULL, name, t_rules, depth + 1);
		if (ret < 0) {
			tmpl_attr_list_talloc_free_tail(&vpt->data.attribute.ar); /* Remove and free ar */
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
 * @param[in] parent		Parent to associate with the attribute reference.
 * @param[in] namespace		Where to search to resolve the next reference.
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
					      fr_dict_attr_t const *parent, fr_dict_attr_t const *namespace,
					      fr_sbuff_t *name,
					      fr_sbuff_parse_rules_t const *p_rules, tmpl_attr_rules_t const *t_rules,
					      unsigned int depth)
{
	uint32_t		oid = 0;
	tmpl_attr_t		*ar = NULL;
	fr_dict_attr_t const	*da;
	fr_sbuff_marker_t	m_s;
	fr_dict_attr_err_t	dict_err;
	fr_dict_attr_t const	*our_parent = parent;

	fr_sbuff_marker(&m_s, name);

	if (depth > FR_DICT_MAX_TLV_STACK) {
		fr_strerror_const("Attribute nesting too deep");
		if (err) *err = TMPL_ATTR_ERROR_NESTING_TOO_DEEP;
	error:
		fr_sbuff_marker_release(&m_s);
		FR_SBUFF_ERROR_RETURN(name);
	}

	/*
	 *	Input too short
	 */
	if (!fr_sbuff_extend(name)) {
		fr_strerror_const("Missing attribute reference");
		if (err) *err = TMPL_ATTR_ERROR_INVALID_NAME;
		goto error;
	}

	/*
	 *	No parent means we need to go hunting through all the dictionaries
	 */
	if (!our_parent) {
		(void)fr_dict_attr_search_by_qualified_name_substr(&dict_err, &da,
								   t_rules->dict_def,
								   name, p_rules ? p_rules->terminals : NULL,
								   !t_rules->disallow_internal,
								   t_rules->allow_foreign);
		/*
		 *	We can't know which dictionary the
		 *	attribute will be resolved in, so the
		 *	only way of recording what the parent
		 *	is by looking at the da.
		 */
		if (da) our_parent = da->parent;
	/*
	 *	Otherwise we're resolving in the context of the last component,
	 *	or its reference in the case of group attributes.
	 */
	} else {
		(void)fr_dict_attr_by_name_substr(&dict_err,
						  &da,
						  namespace,
						  name,
						  p_rules ? p_rules->terminals : NULL);
		/*
		 *	Allow fallback to internal attributes
		 *	if the parent was a group, and we're
		 *	allowing internal resolution.
		 *
		 *	Discard any errors here... It's more
		 *	useful to have the original.
		 */
		if (!da && !vpt->rules.attr.disallow_internal &&
		    (ar = tmpl_attr_list_tail(&vpt->data.attribute.ar)) &&
		    (ar->type == TMPL_ATTR_TYPE_NORMAL) && (ar->ar_da->type == FR_TYPE_GROUP)) {
			(void)fr_dict_attr_by_name_substr(NULL,
							  &da, fr_dict_root(fr_dict_internal()),
							  name,
							  p_rules ? p_rules->terminals : NULL);
			if (da) {
				dict_err = FR_DICT_ATTR_OK;
				our_parent = fr_dict_root(fr_dict_internal());
			}
		}
	}

	/*
	 *	Fatal errors related to nesting...
	 */
	switch (dict_err) {
	case FR_DICT_ATTR_NO_CHILDREN:
		if (our_parent && our_parent->flags.is_unknown) break;
		goto error;

	case FR_DICT_ATTR_NOT_DESCENDENT:
		goto error;

	default:
		/*
		 *	The named component was a known attribute
		 *	so record it as a normal attribute
		 *	reference.
		 */
		if (da) {
			MEM(ar = talloc(ctx, tmpl_attr_t));
			*ar = (tmpl_attr_t){
				.ar_num = NUM_UNSPEC,
				.ar_type = TMPL_ATTR_TYPE_NORMAL,
				.ar_da = da,
				.ar_parent = our_parent
			};
			goto check_attr;
		}
		break;
	}

	/*
	 *	Locating OID/Unresolved attributes is
	 *	different than locating named attributes
	 *	because we have significantly more numberspace
	 *	overlap between the protocols so we can't just go
	 *	hunting and expect to hit the right
	 *	dictionary.
	 *
	 *	FIXME - We should really fix the above named
	 *	resolution calls to hunt for a dictionary prefix
	 *	first, and then run the rest of the logic in this
	 *	function.
	 */
	if (!namespace && t_rules->dict_def) our_parent = namespace = fr_dict_root(t_rules->dict_def);
	if (!namespace && !t_rules->disallow_internal) our_parent = namespace = fr_dict_root(fr_dict_internal());
	if (!namespace) {
		fr_strerror_const("Attribute references must be qualified with a protocol when used here");
		if (err) *err = TMPL_ATTR_ERROR_UNQUALIFIED_NOT_ALLOWED;
		fr_sbuff_set(name, &m_s);
		goto error;
	}

	/*
	 *	See if the ref begins with an unsigned integer
	 *	if it does it's probably an OID component
	 *
	 *	.<oid>
	 */
	if (fr_sbuff_out(NULL, &oid, name) > 0) {
		fr_dict_attr_t *da_unknown;

		fr_strerror_clear();	/* Clear out any existing errors */

		/*
		 *	If it's numeric and not a known attribute
		 *      then we create an unknown attribute with
		 *	the specified attribute number.
		 */
		da = fr_dict_attr_child_by_num(namespace, oid);
		if (da) {
			/*
			 *	The OID component was a known attribute
			 *	so record it as a normal attribute
			 *	reference.
			 */
			MEM(ar = talloc(ctx, tmpl_attr_t));
			*ar = (tmpl_attr_t){
				.ar_num = NUM_UNSPEC,
				.ar_type = TMPL_ATTR_TYPE_NORMAL,
				.ar_da = da,
				.ar_parent = our_parent,
			};
			vpt->data.attribute.was_oid = true;

			goto check_attr;
		}

		if (!t_rules->allow_unknown) {
			fr_strerror_const("Unknown attributes not allowed here");
			if (err) *err = TMPL_ATTR_ERROR_UNKNOWN_NOT_ALLOWED;
			fr_sbuff_set(name, &m_s);
			goto error;
		}

		MEM(ar = talloc(ctx, tmpl_attr_t));
		switch (namespace->type) {
		case FR_TYPE_VSA:
			da_unknown = fr_dict_unknown_vendor_afrom_num(ar, namespace, oid);
			if (!da_unknown) {
				if (err) *err = TMPL_ATTR_ERROR_UNKNOWN_NOT_ALLOWED;	/* strerror set by dict function */
				goto error;
			}
			break;

		default:
			da_unknown = fr_dict_unknown_attr_afrom_num(ar, namespace, oid);
			if (!da_unknown) {
				if (err) *err = TMPL_ATTR_ERROR_UNKNOWN_NOT_ALLOWED;	/* strerror set by dict function */
				goto error;
			}
			break;
		}
		da_unknown->flags.internal = 1;

		*ar = (tmpl_attr_t){
			.ar_num = NUM_UNSPEC,
			.ar_type = TMPL_ATTR_TYPE_UNKNOWN,
			.ar_unknown = da_unknown,
			.ar_da = da_unknown,
			.ar_parent = our_parent,
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
		fr_strerror_const_push("Unresolved attributes are not allowed here");
		if (err) *err = TMPL_ATTR_ERROR_UNRESOLVED_NOT_ALLOWED;
		fr_sbuff_set(name, &m_s);
		goto error;
	}

	fr_sbuff_marker_release(&m_s);

	/*
	 *	Once we hit one unresolved attribute we have to treat
	 *	the rest of the components are unresolved as well.
	 */
	return tmpl_attr_afrom_attr_unresolved_substr(ctx, err, vpt, our_parent, namespace, name, t_rules, depth);

check_attr:
	/*
	 *	Attribute location (dictionary) checks
	 */
	if (!t_rules->allow_foreign || t_rules->disallow_internal) {
		fr_dict_t const *found_in = fr_dict_by_da(da);
		fr_dict_t const *dict_def = t_rules->dict_def ? t_rules->dict_def : fr_dict_internal();

		/*
		 *	Parent is the dict root if this is the first ref in the
		 *	chain.
		 */
		if (!our_parent) our_parent = fr_dict_root(dict_def);

		/*
		 *	Even if allow_foreign is false, if disallow_internal is not
		 *	true, we still allow the resolution.
		 */
		if (t_rules->disallow_internal && (found_in == fr_dict_internal())) {
			fr_strerror_const("Internal attributes not allowed here");
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
		    !t_rules->allow_foreign && (found_in != fr_dict_by_da(our_parent))) {
			fr_strerror_printf("Foreign %s attribute found.  Only %s attributes are allowed here",
					   fr_dict_root(found_in)->name,
					   fr_dict_root(dict_def)->name);
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
	if (tmpl_attr_parse_filter(err, ar, name, t_rules) < 0) goto error;

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
		 *
		 *	The dictionary resolution functions will
		 *	automatically follow the ref, so we don't
		 *	need to do it here, especially as some
		 *	of the logic in this function depends
		 *	on having the group attribute and not what
		 *	it points to.
		 */
		case FR_TYPE_GROUP:
			our_parent = namespace = fr_dict_attr_ref(da);

			/*
			 *	if there's a real dictionary, and this reference is to group which is in fact
			 *	the internal dict, then just keep using our dict_def.
			 */
			if (t_rules->dict_def && (namespace == fr_dict_root(fr_dict_internal()))) {
				our_parent = namespace = fr_dict_root(t_rules->dict_def);
			}
			break;

		case FR_TYPE_STRUCT:
		case FR_TYPE_TLV:
		case FR_TYPE_VENDOR:
		case FR_TYPE_VSA:
		is_union:
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
			 *
			 *	Flatten / nested migration hack. :(
			 */
			if (main_config && main_config->tmpl_tokenize_all_nested) {
				our_parent = da;	/* Only update the parent if we're not stripping */

			} else if (ar_filter_is_none(ar) && ar_is_normal(ar)) {
				TALLOC_FREE(ar);
			} else {
				our_parent = da;	/* Only update the parent if we're not stripping */
			}
			namespace = da;
			break;

		default:
			if (fr_dict_attr_is_key_field(da)) goto is_union;

			fr_strerror_printf("Parent type of nested attribute %s must be of type "
					   "\"struct\", \"tlv\", \"vendor\", \"vsa\" or \"group\", got \"%s\"",
					   da->name,
					   fr_type_to_str(da->type));
			fr_sbuff_set(name, &m_s);
			goto error;
		}

		if (ar) tmpl_attr_insert(vpt, ar);
		if (tmpl_attr_afrom_attr_substr(ctx, err, vpt, our_parent, namespace, name, p_rules, t_rules, depth + 1) < 0) {
			if (ar) tmpl_attr_list_talloc_free_tail(&vpt->data.attribute.ar); /* Remove and free ar */
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

	if (tmpl_is_attr(vpt) && (tmpl_rules_cast(vpt) == tmpl_da(vpt)->type)) vpt->rules.cast = FR_TYPE_NULL;

	fr_sbuff_marker_release(&m_s);
	return 0;
}

/** Parse a string into a TMPL_TYPE_ATTR_* or #TMPL_TYPE_LIST type #tmpl_t
 *
 * @param[in,out] ctx		to allocate #tmpl_t in.
 * @param[out] err		May be NULL.  Provides the exact error that the parser hit
 *				when processing the attribute ref.
 * @param[out] out		Where to write pointer to new #tmpl_t.
 * @param[in] name		of attribute including #tmpl_request_ref_t and #pair_list_t qualifiers.
 *				If only #tmpl_request_ref_t #pair_list_t qualifiers are found,
 *				a #TMPL_TYPE_LIST #tmpl_t will be produced.
 * @param[in] p_rules		Formatting rules used to check for trailing garbage.
 * @param[in] t_rules		Rules which control parsing:
 *				- dict_def		The default dictionary to use if attributes
 *							are unqualified.
 *				- request_def		The default #request_t to set if no
 *							#tmpl_request_ref_t qualifiers are found in name.
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
 *				- disallow_filters
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
	int				ret;
	size_t				list_len = 0;
	tmpl_t				*vpt;
	fr_sbuff_t			our_name = FR_SBUFF(name);	/* Take a local copy in case we need to back track */
	bool				ref_prefix = false;
	bool				is_raw = false;
	tmpl_attr_rules_t const		*t_attr_rules;
	fr_sbuff_marker_t		m_l;

	if (!t_rules) t_rules = &default_rules;
	t_attr_rules = &t_rules->attr;

	if (err) *err = TMPL_ATTR_ERROR_NONE;

	if (!fr_sbuff_extend(&our_name)) {
		fr_strerror_const("Empty attribute reference");
		if (err) *err = TMPL_ATTR_ERROR_EMPTY;
		FR_SBUFF_ERROR_RETURN(&our_name);
	}

	/*
	 *	Check to see if we expect a reference prefix
	 */
	switch (t_attr_rules->prefix) {
	case TMPL_ATTR_REF_PREFIX_YES:
		if (!fr_sbuff_next_if_char(&our_name, '&')) {
			fr_strerror_const("Invalid attribute reference, missing '&' prefix");
			if (err) *err = TMPL_ATTR_ERROR_BAD_PREFIX;
			FR_SBUFF_ERROR_RETURN(&our_name);
		}

		break;

	case TMPL_ATTR_REF_PREFIX_NO:
		if (fr_sbuff_is_char(&our_name, '&')) {
			fr_strerror_const("Attribute references used here must not have a '&' prefix");
			if (err) *err = TMPL_ATTR_ERROR_BAD_PREFIX;
			FR_SBUFF_ERROR_RETURN(&our_name);
		}
		break;

	case TMPL_ATTR_REF_PREFIX_AUTO:
		/*
		 *	'&' prefix can be there, but doesn't have to be
		 */
		(void) fr_sbuff_next_if_char(&our_name, '&');
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
	ret = tmpl_request_ref_list_from_substr(vpt, NULL,
					      &vpt->data.attribute.rr,
					      &our_name,
					      p_rules,
				              t_attr_rules);
	if (ret < 0) {
	error:
		*out = NULL;
		talloc_free(vpt);
		FR_SBUFF_ERROR_RETURN(&our_name);
	}

	fr_sbuff_marker(&m_l, &our_name);

	if (!t_attr_rules->list_as_attr) {
		/*
		 *	Parse the list reference
		 *
		 *      This code should be removed when lists
		 *	are integrated into attribute references.
		 */
		fr_sbuff_out_by_longest_prefix(&list_len, &vpt->data.attribute.list, pair_list_table,
					       &our_name, t_attr_rules->list_def);

		/*
		 *	Check if we need to backtrack
		 *
		 *	Lists can be followed by a '.', '[', or the end of the attribute reference
		 *
		 *	If we don't find any of those things it wasn't an actual list match
		 *	but one of the list identifiers matched part of an attribute reference.
		 *
		 *	i.e. reply with reply-message.
		 */
		if ((list_len > 0) && !fr_sbuff_is_char(&our_name, '.') &&
		    !fr_sbuff_is_char(&our_name, '[') && !tmpl_substr_terminal_check(&our_name, p_rules)) {
			fr_sbuff_set(&our_name, &m_l);
			list_len = 0;
			vpt->data.attribute.list = t_attr_rules->list_def;
		}

		if ((t_attr_rules->parent || t_attr_rules->disallow_qualifiers) && (list_len > 0)) {
			fr_strerror_const("It is not permitted to specify a pair list here");
			if (err) *err = TMPL_ATTR_ERROR_INVALID_LIST_QUALIFIER;
			talloc_free(vpt);
			FR_SBUFF_ERROR_RETURN(&our_name);
		}
	}

	/*
	 *	Parse the attribute reference
	 *
	 *      This will either be after:
	 *	- A zero length list, i.e. just after the prefix '&', in which case we require an attribue
	 *	- '.' and then an allowed char, so we're sure it's not just a bare list ref.
	 */
	if ((list_len == 0) ||
	    (fr_sbuff_next_if_char(&our_name, '.') && fr_sbuff_is_in_charset(&our_name, fr_dict_attr_allowed_chars))) {
		ret = tmpl_attr_afrom_attr_substr(vpt, err,
						  vpt,
						  t_attr_rules->parent, t_attr_rules->parent,
						  &our_name, p_rules, t_attr_rules, 0);
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

		/*
		 *	Check to see what the first attribute reference
		 *	was.  If it wasn't a known list group attribute
		 *	and we're parsing in list_as_attr mode, then
		 *	we need to add in a default list.
		 */
		if (t_attr_rules->list_as_attr) {
			tmpl_attr_t *ar;

			ar = tmpl_attr_list_head(&vpt->data.attribute.ar);
			fr_assert(ar != NULL);

			if ((ar->ar_type != TMPL_ATTR_TYPE_NORMAL) ||
			    ((ar->ar_da != request_attr_request) &&
			     (ar->ar_da != request_attr_reply) &&
			     (ar->ar_da != request_attr_control) &&
			     (ar->ar_da != request_attr_state))) {
				MEM(ar = talloc(vpt, tmpl_attr_t));
				*ar = (tmpl_attr_t){
					.ar_type = TMPL_ATTR_TYPE_NORMAL,
					.ar_parent = fr_dict_root(fr_dict_internal())
				};

				switch (t_attr_rules->list_def) {
				default:
				case PAIR_LIST_REQUEST:
					ar->ar_da = request_attr_request;
					break;

				case PAIR_LIST_REPLY:
					ar->ar_da = request_attr_reply;
					break;

				case PAIR_LIST_CONTROL:
					ar->ar_da = request_attr_control;
					break;

				case PAIR_LIST_STATE:
					ar->ar_da = request_attr_state;
					break;
				}

				/*
				 *	Prepend the list ref so it gets evaluated
				 *	first.
				 */
				tmpl_attr_list_insert_head(&vpt->data.attribute.ar, ar);
			}
		}
	}

	/*
	 *	If there's no attribute references
	 *	treat this as a list reference.
	 *
	 *	Eventually we'll remove TMPL_TYPE_LIST
	 */
	if (!t_attr_rules->list_as_attr && (tmpl_attr_list_num_elements(&vpt->data.attribute.ar) == 0)) {
		tmpl_attr_t *ar;
		fr_slen_t slen;

		MEM(ar = talloc_zero(vpt, tmpl_attr_t));
		slen = tmpl_attr_parse_filter(err, ar, &our_name, t_attr_rules);
		if (slen == 0) {				/* No filter */
			talloc_free(ar);
		} else if (slen > 0) {				/* Found a filter */
			tmpl_attr_list_insert_tail(&vpt->data.attribute.ar, ar);
		} else if (slen < 0) {				/* Filter error */
			goto error;
		}
		vpt->type = TMPL_TYPE_LIST;
	}

	tmpl_set_name(vpt, T_BARE_WORD, fr_sbuff_start(&our_name), fr_sbuff_used(&our_name));
	vpt->rules = *t_rules;	/* Record the rules */

	/*
	 *	If there are actual requests, duplicate them
	 *	and move them into the list.
	 *
	 *	A NULL request_def pointer is equivalent to the
	 *	current request.
	 */
	if (t_rules->attr.request_def) {
		tmpl_request_ref_list_acopy(vpt, &vpt->rules.attr.request_def, t_rules->attr.request_def);
	}

	if (tmpl_is_attr(vpt)) {
		/*
		 *	Suppress useless casts.
		 */
		if (tmpl_da(vpt)->type == tmpl_rules_cast(vpt)) {
			vpt->rules.cast = FR_TYPE_NULL;
		}

		/*
		 *	Ensure that the list is set correctly, so that
		 *	the returned vpt just doesn't just match the
		 *	input rules, it is also internally consistent.
		 */
		if (t_attr_rules->list_as_attr) {
			tmpl_attr_t *ar;

			ar = tmpl_attr_list_head(tmpl_attr(vpt));
			fr_assert(ar != NULL);

			if (ar->ar_da == request_attr_request) {
				vpt->rules.attr.list_def = PAIR_LIST_REQUEST;

			} else if (ar->ar_da == request_attr_reply) {
				vpt->rules.attr.list_def = PAIR_LIST_REPLY;

			} else if (ar->ar_da == request_attr_control) {
				vpt->rules.attr.list_def = PAIR_LIST_CONTROL;

			} else if (ar->ar_da == request_attr_state) {
				vpt->rules.attr.list_def = PAIR_LIST_STATE;
			}

			vpt->data.attribute.list = vpt->rules.attr.list_def;
		}
	}

	if (!tmpl_substr_terminal_check(&our_name, p_rules)) {
		fr_strerror_const("Unexpected text after attribute reference");
		if (err) *err = TMPL_ATTR_ERROR_MISSING_TERMINATOR;
		goto error;
	}

	/*
	 *	If everything was resolved correctly
	 *	we now need to check the cast type.
	 */
	if (!tmpl_needs_resolving(vpt) && !fr_type_is_null(t_rules->cast) &&
	    !fr_type_cast(t_rules->cast, tmpl_da(vpt)->type)) {
		fr_strerror_printf("Cannot cast type '%s' to '%s'",
				   fr_type_to_str(tmpl_da(vpt)->type), fr_type_to_str(t_rules->cast));
		if (err) *err = TMPL_ATTR_ERROR_BAD_CAST;
		fr_sbuff_set_to_start(&our_name);
		goto error;
	}

	TMPL_VERIFY(vpt);	/* Because we want to ensure we produced something sane */

	*out = vpt;
	FR_SBUFF_SET_RETURN(name, &our_name);
}

/** Parse a string into a TMPL_TYPE_ATTR_* or #TMPL_TYPE_LIST type #tmpl_t
 *
 * @param[in,out] ctx		to allocate #tmpl_t in.
 * @param[out] err		May be NULL.  Provides the exact error that the parser hit
 *				when processing the attribute ref.
 * @param[out] out		Where to write pointer to new #tmpl_t.
 * @param[in] name		of attribute including #tmpl_request_ref_t and #pair_list_t qualifiers.
 *				If only #tmpl_request_ref_t #pair_list_t qualifiers are found,
 *				a #TMPL_TYPE_LIST #tmpl_t will be produced.
 * @param[in] t_rules		Rules which control parsing.  See tmpl_afrom_attr_substr() for details.
 *
 * @note Unlike #tmpl_afrom_attr_substr this function will error out if the entire
 *	name string isn't parsed.
 */
ssize_t tmpl_afrom_attr_str(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
			    tmpl_t **out, char const *name, tmpl_rules_t const *t_rules)
{
	ssize_t slen, name_len;

	if (!t_rules) t_rules = &default_rules;	/* Use the defaults */

	name_len = strlen(name);
	slen = tmpl_afrom_attr_substr(ctx, err, out, &FR_SBUFF_IN(name, name_len), NULL, t_rules);
	if (slen <= 0) return slen;

	if (!fr_cond_assert(*out)) return -1;

	if (slen != name_len) {
		/* This looks wrong, but it produces meaningful errors for unknown attrs */
		fr_strerror_printf("Unexpected text after %s",
				   tmpl_type_to_str((*out)->type));
		return -slen;
	}

	TMPL_VERIFY(*out);

	return slen;
}

/** Create TMPL_TYPE_DATA from a string
 *
 * @param[in] ctx		to allocate tmpl to.
 * @param[out] out		where to write tmpl.
 * @param[in] in		sbuff to parse.
 * @param[in] quote		surrounding the operand to parse.
 * @param[in] t_rules		specifying the cast and any enumeration values.
 * @param[in] allow_enum	Whether parsing the value as an enum should be allowed.
 * @param[in] p_rules		formatting rules.
 * @return
 *	- <0 on error
 *	- >=0 on success.
 */
static fr_slen_t tmpl_afrom_value_substr(TALLOC_CTX *ctx, tmpl_t **out, fr_sbuff_t *in,
					 fr_token_t quote,
					 tmpl_rules_t const *t_rules, bool allow_enum,
					 fr_sbuff_parse_rules_t const *p_rules)
{
	fr_sbuff_t	our_in = FR_SBUFF(in);
	fr_value_box_t	tmp;
	tmpl_t		*vpt;

	if (!fr_type_is_leaf(t_rules->cast)) {
		fr_strerror_printf("%s is not a valid cast type",
				   fr_type_to_str(t_rules->cast));
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	vpt = tmpl_alloc_null(ctx);
	if (fr_value_box_from_substr(vpt, &tmp,
				     t_rules->cast, allow_enum ? t_rules->enumv : NULL,
				     &our_in, p_rules, false) < 0) {
		talloc_free(vpt);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	tmpl_init(vpt, TMPL_TYPE_DATA, quote, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in), t_rules);

	fr_value_box_copy_shallow(NULL, tmpl_value(vpt), &tmp);

	*out = vpt;

	if (tmpl_rules_cast(vpt) == tmpl_value_type(vpt)) vpt->rules.cast = FR_TYPE_NULL;

	TMPL_VERIFY(vpt);

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Parse a truth value
 *
 * @param[in] ctx	to allocate tmpl to.
 * @param[out] out	where to write tmpl.
 * @param[in] in	sbuff to parse.
 * @param[in] p_rules	formatting rules.
 * @return
 *	- < 0 sbuff does not contain a boolean value.
 *	- > 0 how many bytes were parsed.
 */
static fr_slen_t tmpl_afrom_bool_substr(TALLOC_CTX *ctx, tmpl_t **out, fr_sbuff_t *in,
					fr_sbuff_parse_rules_t const *p_rules)
{
	fr_sbuff_t	our_in = FR_SBUFF(in);
	bool		a_bool;
	tmpl_t		*vpt;

	if (fr_sbuff_out(NULL, &a_bool, &our_in) < 0) {
		fr_strerror_const("Not a boolean value");
		return 0;
	}

	if (!tmpl_substr_terminal_check(&our_in, p_rules)) {
		fr_strerror_const("Unexpected text after bool");
		FR_SBUFF_ERROR_RETURN(in);
	}

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_DATA, T_BARE_WORD, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in)));

	fr_value_box_init(&vpt->data.literal, FR_TYPE_BOOL, NULL, false);
	vpt->data.literal.vb_bool = a_bool;

	*out = vpt;

	FR_SBUFF_SET_RETURN(in, &our_in);
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
static fr_slen_t tmpl_afrom_octets_substr(TALLOC_CTX *ctx, tmpl_t **out, fr_sbuff_t *in,
					  fr_sbuff_parse_rules_t const *p_rules)
{
	fr_sbuff_t	our_in = FR_SBUFF(in);
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
		fr_strerror_const("Hex string not even length");
	error:
		talloc_free(vpt);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}
	if (len == 0) {
		fr_strerror_const("Zero length hex string is invalid");
		goto error;
	}

	if (!tmpl_substr_terminal_check(&our_in, p_rules)) {
		fr_strerror_const("Unexpected text after hex string");
		goto error;
	}

	bin = (uint8_t *)hex;
	binlen = len / 2;

	tmpl_set_name(vpt, T_BARE_WORD, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in));

	(void)fr_base16_decode(NULL, &FR_DBUFF_TMP(bin, binlen), &FR_SBUFF_IN(hex, len), false);
	MEM(bin = talloc_realloc_size(vpt, bin, binlen));	/* Realloc to the correct length */
	(void)fr_value_box_memdup_shallow(&vpt->data.literal, NULL, bin, binlen, false);

	*out = vpt;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Parse bareword as an IPv4 address or prefix
 *
 * @param[in] ctx	to allocate tmpl to.
 * @param[out] out	where to write tmpl.
 * @param[in] in	sbuff to parse.
 * @param[in] p_rules	formatting rules.
 * @return
 *	- < 0 sbuff does not contain an IPv4 address or prefix.
 *	- > 0 how many bytes were parsed.
 */
static fr_slen_t tmpl_afrom_ipv4_substr(TALLOC_CTX *ctx, tmpl_t **out, fr_sbuff_t *in,
					fr_sbuff_parse_rules_t const *p_rules)
{
	tmpl_t		*vpt;
	fr_sbuff_t	our_in = FR_SBUFF(in);
	uint8_t		octet;
	fr_type_t	type;

	/*
	 *	Check for char sequence
	 *
	 *	xxx.xxx.xxx.xxx
	 */
	if (!(fr_sbuff_out(NULL, &octet, &our_in) && fr_sbuff_next_if_char(&our_in, '.') &&
	      fr_sbuff_out(NULL, &octet, &our_in) && fr_sbuff_next_if_char(&our_in, '.') &&
	      fr_sbuff_out(NULL, &octet, &our_in) && fr_sbuff_next_if_char(&our_in, '.') &&
	      fr_sbuff_out(NULL, &octet, &our_in))) {
	error:
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	If it has a trailing '/' then it's probably
	 *	an IP prefix.
	 */
	if (fr_sbuff_next_if_char(&our_in, '/')) {
		if (fr_sbuff_out(NULL, &octet, &our_in) < 0) {
			fr_strerror_const("IPv4 CIDR mask malformed");
			goto error;
		}

		if (octet > 32) {
			fr_strerror_const("IPv4 CIDR mask too high");
			goto error;
		}

		type = FR_TYPE_IPV4_PREFIX;
	} else {
		type = FR_TYPE_IPV4_ADDR;
	}

	if (!tmpl_substr_terminal_check(&our_in, p_rules)) {
		fr_strerror_const("Unexpected text after IPv4 string or prefix");
		goto error;
	}

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_DATA, T_BARE_WORD, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in)));
	if (fr_value_box_from_substr(vpt, &vpt->data.literal, type, NULL,
				     &FR_SBUFF_REPARSE(&our_in),
				     NULL, false) < 0) {
		talloc_free(vpt);
		goto error;
	}
	*out = vpt;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Parse bareword as an IPv6 address or prefix
 *
 * @param[in] ctx		to allocate tmpl to.
 * @param[out] out		where to write tmpl.
 * @param[in] in		sbuff to parse.
 * @param[in] p_rules		formatting rules.
 * @return
 *	- < 0 sbuff does not contain an IPv4 address or prefix.
 *	- > 0 how many bytes were parsed.
 */
static fr_slen_t tmpl_afrom_ipv6_substr(TALLOC_CTX *ctx, tmpl_t **out, fr_sbuff_t *in,
					fr_sbuff_parse_rules_t const *p_rules)
{
	tmpl_t			*vpt;
	fr_sbuff_t		our_in = FR_SBUFF(in);
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
	 *
	 *	Minimum string is '::'
	 */
	len = fr_sbuff_adv_past_allowed(&our_in, FR_IPADDR_STRLEN + 1, ipv6_chars, NULL);
	if ((len < 2) || (len > FR_IPADDR_STRLEN)) {
	error:
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	Got ':' after '.', this isn't allowed.
	 *
	 *	We need this check else IPv4 gets parsed
	 *	as blank IPv6 address.
	 */
	sep_a = memchr(fr_sbuff_current(&m), '.', len);
	if (sep_a && (!(sep_b = memchr(fr_sbuff_current(&m), ':', len)) || (sep_b > sep_a))) {
		fr_strerror_const("First IPv6 component separator was a '.'");
		goto error;
	}

	/*
	 *	The v6 parse function will happily turn
	 *	integers into v6 addresses *sigh*.
	 */
	sep_a = memchr(fr_sbuff_current(&m), ':', len);
	if (!sep_a) {
		fr_strerror_const("No IPv6 component separator");
		goto error;
	}

	/*
	 *	Handle scope
	 */
	if (fr_sbuff_next_if_char(&our_in, '%')) {
		len = fr_sbuff_adv_until(&our_in, IFNAMSIZ + 1, p_rules->terminals, '\0');
		if ((len < 1) || (len > IFNAMSIZ)) {
			fr_strerror_const("IPv6 scope too long");
			goto error;
		}
	}

	/*
	 *	...and finally the prefix.
	 */
	if (fr_sbuff_next_if_char(&our_in, '/')) {
		uint8_t		mask;

		if (fr_sbuff_out(NULL, &mask, &our_in) < 0) {
			fr_strerror_const("IPv6 CIDR mask malformed");
			goto error;
		}
		if (mask > 128) {
			fr_strerror_const("IPv6 CIDR mask too high");
			goto error;
		}

		type = FR_TYPE_IPV6_PREFIX;
	} else {
		type = FR_TYPE_IPV6_ADDR;
	}

	if (!tmpl_substr_terminal_check(&our_in, p_rules)) {
		fr_strerror_const("Unexpected text after IPv6 string or prefix");
		goto error;
	}

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_DATA, T_BARE_WORD, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in)));
	if (fr_value_box_from_substr(vpt, &vpt->data.literal, type, NULL,
				     &FR_SBUFF_REPARSE(&our_in),
				     NULL, false) < 0) {
		talloc_free(vpt);
		goto error;
	}
	*out = vpt;

	FR_SBUFF_SET_RETURN(in, &our_in);
}


/** Try and parse signed or unsigned integers
 *
 * @param[in] ctx	to allocate tmpl to.
 * @param[out] out	where to write tmpl.
 * @param[in] in	sbuff to parse.
 * @param[in] p_rules	formatting rules.
 * @return
 *	- < 0 sbuff does not contain a mac address.
 *	- > 0 how many bytes were parsed.
 */
static ssize_t tmpl_afrom_ether_substr(TALLOC_CTX *ctx, tmpl_t **out, fr_sbuff_t *in,
				       fr_sbuff_parse_rules_t const *p_rules)
{
	tmpl_t			*vpt;
	fr_sbuff_t		our_in = FR_SBUFF(in);
	uint8_t			buff[6];
	fr_dbuff_t		dbuff;
	fr_value_box_t		*vb;
	fr_sbuff_parse_error_t	err;

	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	fr_base16_decode(&err, &dbuff, &our_in, true);
	if (err != FR_SBUFF_PARSE_OK) return 0;

	if (!fr_sbuff_next_if_char(&our_in, ':')) return 0;

	fr_base16_decode(&err, &dbuff, &our_in, true);
	if (err != FR_SBUFF_PARSE_OK) return 0;

	if (!fr_sbuff_next_if_char(&our_in, ':')) return 0;

	fr_base16_decode(&err, &dbuff, &our_in, true);
	if (err != FR_SBUFF_PARSE_OK) return 0;

	if (!fr_sbuff_next_if_char(&our_in, ':')) return 0;

	fr_base16_decode(&err, &dbuff, &our_in, true);
	if (err != FR_SBUFF_PARSE_OK) return 0;

	if (!fr_sbuff_next_if_char(&our_in, ':')) return 0;

	fr_base16_decode(&err, &dbuff, &our_in, true);
	if (err != FR_SBUFF_PARSE_OK) return 0;

	if (!fr_sbuff_next_if_char(&our_in, ':')) return 0;

	fr_base16_decode(&err, &dbuff, &our_in, true);
	if (err != FR_SBUFF_PARSE_OK) return 0;

	if (!tmpl_substr_terminal_check(&our_in, p_rules)) {
		fr_strerror_const("Unexpected text after mac address");
		return 0;
	}

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_DATA,
			     T_BARE_WORD, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in)));
	vb = tmpl_value(vpt);

	fr_value_box_init(vb, FR_TYPE_ETHERNET, NULL, false);
	/* coverity[uninit_use_in_call] */
	memcpy(vb->vb_ether, buff, sizeof(vb->vb_ether));

	*out = vpt;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Try and parse signed or unsigned integers
 *
 * @param[in] ctx	to allocate tmpl to.
 * @param[out] out	where to write tmpl.
 * @param[in] in	sbuff to parse.
 * @param[in] p_rules	formatting rules.
 * @return
 *	- < 0 sbuff does not contain an integer.
 *	- > 0 how many bytes were parsed.
 */
static fr_slen_t tmpl_afrom_integer_substr(TALLOC_CTX *ctx, tmpl_t **out, fr_sbuff_t *in,
					   fr_sbuff_parse_rules_t const *p_rules)
{
	tmpl_t		*vpt;
	fr_sbuff_t	our_in = FR_SBUFF(in);
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
			fr_strerror_const("Unexpected text after signed integer");
		error:
			FR_SBUFF_ERROR_RETURN(&our_in);
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
			fr_strerror_const("Unexpected text after unsigned integer");
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

	FR_SBUFF_SET_RETURN(in, &our_in);
}

static ssize_t tmpl_afrom_float_substr(TALLOC_CTX *ctx, tmpl_t **out, fr_sbuff_t *in,
				       fr_sbuff_parse_rules_t const *p_rules)
{
	tmpl_t		*vpt;
	fr_sbuff_t	our_in = FR_SBUFF(in);
	double		a_float;
	ssize_t		slen;
	fr_value_box_t	*vb;

	slen = fr_sbuff_out(NULL, &a_float, &our_in);
	if (slen <= 0) return 0;

	if (!tmpl_substr_terminal_check(&our_in, p_rules)) {
		fr_strerror_const("Unexpected text after float");
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_DATA,
			     T_BARE_WORD, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in)));
	vb = tmpl_value(vpt);
	fr_value_box_init(vb, FR_TYPE_FLOAT64, NULL, false);
	vb->vb_float64 = a_float;

	*out = vpt;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

static ssize_t tmpl_afrom_time_delta(TALLOC_CTX *ctx, tmpl_t **out, fr_sbuff_t *in,
				     fr_sbuff_parse_rules_t const *p_rules)
{
	tmpl_t		*vpt;
	fr_sbuff_t	our_in = FR_SBUFF(in);
	fr_time_delta_t	a_delta;
	fr_slen_t	slen;
	fr_value_box_t	*vb;

	slen = fr_time_delta_from_substr(&a_delta, &our_in, FR_TIME_RES_SEC, true, p_rules ? p_rules->terminals : NULL);
	if (slen <= 0) return 0;

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_DATA,
			     T_BARE_WORD, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in)));
	vb = tmpl_value(vpt);
	fr_value_box_init(vb, FR_TYPE_TIME_DELTA, NULL, false);
	vb->vb_time_delta = a_delta;

	*out = vpt;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Convert an arbitrary string into a #tmpl_t
 *
 * @note Unlike #tmpl_afrom_attr_str return code 0 doesn't necessarily indicate failure,
 *	may just mean a 0 length string was parsed. Check to see if the function emitted
 *	a #tmpl_t in *out.
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
 *	- < 0 on error (offset as negative integer)
 *	- >= 0 on success (number of bytes parsed).
 *
 * @see REMARKER to produce pretty error markers from the return value.
 *
 * @see tmpl_afrom_attr_substr
 */
fr_slen_t tmpl_afrom_substr(TALLOC_CTX *ctx, tmpl_t **out,
			    fr_sbuff_t *in, fr_token_t quote,
			    fr_sbuff_parse_rules_t const *p_rules,
			    tmpl_rules_t const *t_rules)
{
	fr_sbuff_t		our_in = FR_SBUFF(in);

	fr_slen_t		slen;
	fr_sbuff_parse_error_t	sberr;
	char			*str;

	tmpl_t			*vpt = NULL;

	if (!t_rules) t_rules = &default_rules;	/* Use the defaults */

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
			xlat_exp_head_t	*head = NULL;

			vpt = tmpl_alloc_null(ctx);
			if (!t_rules->at_runtime) {
				slen = xlat_tokenize(vpt, &head, &our_in, p_rules, t_rules);
			} else {
				slen = xlat_tokenize_ephemeral(vpt, &head,
							       t_rules->xlat.runtime_el, &our_in,
							       p_rules, t_rules);
			}

			if (slen < 0) FR_SBUFF_ERROR_RETURN(&our_in);

			if (xlat_needs_resolving(head)) UNRESOLVED_SET(&type);

			tmpl_init(vpt, type, quote, fr_sbuff_start(&our_in), slen, t_rules);
			vpt->data.xlat.ex = head;

			*out = vpt;

			TMPL_VERIFY(vpt);

			FR_SBUFF_SET_RETURN(in, &our_in);
		}

		/*
		 *	Deal with explicit casts...
		 */
		if (!fr_type_is_null(t_rules->cast)) return tmpl_afrom_value_substr(ctx, out, in, quote,
										    t_rules, true, p_rules);

		/*
		 *	See if it's a boolean value
		 */
		slen = tmpl_afrom_bool_substr(ctx, out, &our_in, p_rules);
		if (slen > 0) {
		done_bareword:
			TMPL_VERIFY(*out);

			FR_SBUFF_SET_RETURN(in, &our_in);
		}
		fr_assert(!*out);

		/*
		 *	See if it's an octets string
		 */
		slen = tmpl_afrom_octets_substr(ctx, out, &our_in, p_rules);
		if (slen > 0) goto done_bareword;
		fr_assert(!*out);

		/*
		 *	See if it's a mac address
		 *
		 *	Needs to be before IPv6 as the pton functions
		 *	are too greedy, and on macOS will happily
		 *	convert a mac address to an IPv6 address.
		 */
		slen = tmpl_afrom_ether_substr(ctx, out, &our_in, p_rules);
		if (slen > 0) goto done_bareword;
		fr_assert(!*out);

		/*
		 *	See if it's an IPv4 address or prefix
		 */
		slen = tmpl_afrom_ipv4_substr(ctx, out, &our_in, p_rules);
		if (slen > 0) goto done_bareword;
		fr_assert(!*out);

		/*
		 *	See if it's an IPv6 address or prefix
		 */
		slen = tmpl_afrom_ipv6_substr(ctx, out, &our_in, p_rules);
		if (slen > 0) goto done_bareword;
		fr_assert(!*out);

		/*
		 *	See if it's a integer
		 */
		slen = tmpl_afrom_integer_substr(ctx, out, &our_in, p_rules);
		if (slen > 0) goto done_bareword;
		fr_assert(!*out);

		/*
		 *	See if it's a float
		 */
		slen = tmpl_afrom_float_substr(ctx, out, &our_in, p_rules);
		if (slen > 0) goto done_bareword;
		fr_assert(!*out);

		/*
		 *	See if it's a time delta
		 *
		 *	We do this after floats and integers so that
		 *	they get parsed as integer and float types
		 *	and not time deltas.
		 */
		slen = tmpl_afrom_time_delta(ctx, out, &our_in, p_rules);
		if (slen > 0) goto done_bareword;
		fr_assert(!*out);

		/*
		 *	See if it's an attribute reference
		 *	without the prefix.
		 */
		slen = tmpl_afrom_attr_substr(ctx, NULL, out, &our_in, p_rules, t_rules);
		if (slen > 0) goto done_bareword;
		fr_assert(!*out);

		/*
		 *	Attempt to resolve enumeration values
		 */
		vpt = tmpl_alloc_null(ctx);

		/*
		 *	If it doesn't match any other type
		 *	of bareword, assume it's an enum
		 *	value.
		 */
		if (fr_dict_enum_name_afrom_substr(vpt, &str, &sberr, &our_in, p_rules ? p_rules->terminals : NULL) < 0) {
			/*
			 *	Produce our own errors which make
			 *	more sense in the context of tmpls
			 */
			switch (sberr) {
			case FR_SBUFF_PARSE_ERROR_NOT_FOUND:
				fr_strerror_const("No operand found.  Expected &ref, literal, "
						  "'quoted literal', \"%{expansion}\", or enum value");
				break;

			case FR_SBUFF_PARSE_ERROR_FORMAT:
				fr_strerror_const("enum values must contain at least one alpha character");
				break;

			default:
				fr_strerror_const("Unexpected text after enum value.  Expected operator");
				break;
			}
		bareword_error:
			talloc_free(vpt);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		/*
		 *	If we have an enumv in the rules then
		 *	do the lookup now and fail early.
		 */
		if (t_rules->enumv) {
			fr_dict_enum_value_t *dv;

			dv = fr_dict_enum_by_name(t_rules->enumv, str, slen);
			if (!dv) {
				fr_strerror_printf("enum value '%s' is not an enumeration of attribute '%s'",
						   vpt->data.unescaped, t_rules->enumv->name);
				goto bareword_error;
			}

			if (unlikely(fr_value_box_copy(vpt, tmpl_value(vpt), dv->value) < 0)) {
				fr_strerror_const("Failed copying enum");
				goto bareword_error;
			}
			tmpl_init(vpt, TMPL_TYPE_DATA, quote,
				  fr_sbuff_start(&our_in), fr_sbuff_used(&our_in), t_rules);

			talloc_free(str);
		} else {
			tmpl_init(vpt, TMPL_TYPE_UNRESOLVED, quote,
				  fr_sbuff_start(&our_in), fr_sbuff_used(&our_in), t_rules);
			vpt->data.unescaped = str;
		}
		*out = vpt;

		FR_SBUFF_SET_RETURN(in, &our_in);

	case T_SINGLE_QUOTED_STRING:
		/*
		 *	Single quoted strings can be cast
		 *	to a specific data type immediately
		 *	as they cannot contain expansions.
		 */
		if (!fr_type_is_null(t_rules->cast)) return tmpl_afrom_value_substr(ctx, out, in, quote,
										    t_rules, false,
										    p_rules);
		vpt = tmpl_alloc_null(ctx);
		slen = fr_sbuff_out_aunescape_until(vpt, &str, &our_in, SIZE_MAX,
						    p_rules ? p_rules->terminals : NULL,
						    p_rules ? p_rules->escapes : NULL);
		tmpl_init(vpt, TMPL_TYPE_UNRESOLVED, quote, fr_sbuff_start(&our_in), slen, t_rules);
		vpt->data.unescaped = str;
		break;

	case T_DOUBLE_QUOTED_STRING:
	{
		xlat_exp_head_t	*head = NULL;
		tmpl_type_t	type = TMPL_TYPE_XLAT;

		vpt = tmpl_alloc_null(ctx);

		if (!t_rules->at_runtime) {
			slen = xlat_tokenize(vpt, &head, &our_in, p_rules, t_rules);
		} else {
			slen = xlat_tokenize_ephemeral(vpt, &head, t_rules->xlat.runtime_el,
						       &our_in, p_rules, t_rules);
		}
		if (slen < 0) FR_SBUFF_ERROR_RETURN(&our_in);

		/*
		 *	If the string doesn't contain an xlat,
		 *	and we want to cast it as a specific
		 *	type, then do the conversion now.
		 */
		if (xlat_is_literal(head)) {
			if (!fr_type_is_null(t_rules->cast)) {
				talloc_free(vpt);		/* Also frees any nodes */

				return tmpl_afrom_value_substr(ctx, out,
							       in, quote,
							       t_rules, false, p_rules);
			}

			/*
			 *	If the string doesn't contain an xlat
			 *	and there's no cast, we just store
			 *	the string for conversion later.
			 */
			if (xlat_to_string(vpt, &str, &head)) {
				TALLOC_FREE(head);

				tmpl_init(vpt, TMPL_TYPE_UNRESOLVED, quote,
				         fr_sbuff_start(&our_in), slen, t_rules);
				vpt->data.unescaped = str;	/* Store the unescaped string for parsing later */
				break;
			}
		}

		/*
		 *	If the string actually contains an xlat
		 *	store the compiled xlat.
		 */
		if (xlat_needs_resolving(head)) UNRESOLVED_SET(&type);

		tmpl_init(vpt, type, quote, fr_sbuff_start(&our_in), slen, t_rules);
		vpt->data.xlat.ex = head;
	}
		break;

	case T_BACK_QUOTED_STRING:
	{
		tmpl_type_t		type = TMPL_TYPE_EXEC;
		xlat_exp_head_t		*head = NULL;

		vpt = tmpl_alloc_null(ctx);

		/*
		 *	Ensure that we pre-parse the exec string.
		 *	This allows us to catch parse errors as early
		 *	as possible.
		 *
		 *	FIXME - We need an ephemeral version of this
		 *	too.
		 */
		slen = xlat_tokenize_argv(vpt, &head, &our_in, p_rules, t_rules);
		if (slen < 0) {
			talloc_free(vpt);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		if (xlat_needs_resolving(head)) UNRESOLVED_SET(&type);

		tmpl_init(vpt, type, quote, fr_sbuff_start(&our_in), slen, t_rules);
		vpt->data.xlat.ex = head;
	}
		break;

	case T_SOLIDUS_QUOTED_STRING:
	{
		xlat_exp_head_t		*head = NULL;
		tmpl_type_t		type = TMPL_TYPE_REGEX_XLAT;

		if (!fr_type_is_null(t_rules->cast)) {
			fr_strerror_const("Casts cannot be used with regular expressions");
			fr_sbuff_set_to_start(&our_in);	/* Point to the cast */
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		vpt = tmpl_alloc_null(ctx);

		if (!t_rules->at_runtime) {
			slen = xlat_tokenize(vpt, &head, &our_in, p_rules, t_rules);
		} else {
			slen = xlat_tokenize_ephemeral(vpt, &head,
						       t_rules->xlat.runtime_el, &our_in,
						       p_rules, t_rules);
		}

		if (slen < 0) FR_SBUFF_ERROR_RETURN(&our_in);

		/*
		 *	Check if the string actually contains an xlat
		 *	if it doesn't, we unfortunately still
		 *	can't compile the regex here, as we don't know if
		 *	it should be ephemeral or what flags should be used
		 *	during the compilation.
		 *
		 *	The caller will need to do the compilation after we
		 *	return.
		 */
		if (xlat_to_string(vpt, &str, &head)) {
			tmpl_init(vpt, TMPL_TYPE_REGEX_UNCOMPILED, quote,
				  fr_sbuff_start(&our_in), slen, t_rules);
			vpt->data.unescaped = str;	/* Store the unescaped string for compilation later */
			break;
		}
		/*
		 *	Mark the regex up as a regex-xlat which
		 *	will need expanding before evaluation, and can never
		 *	be pre-compiled.
		 */
		if (xlat_needs_resolving(head)) UNRESOLVED_SET(&type);

		tmpl_init(vpt, type, quote, fr_sbuff_start(&our_in), slen, t_rules);
		vpt->data.xlat.ex = head;
	}
		break;

	default:
		fr_assert(0);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	TMPL_VERIFY(vpt);
	*out = vpt;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Copy a tmpl
 *
 * Fully duplicates the contents of a tmpl including any nested attribute
 * references.
 *
 * @param[in] ctx	to perform allocations under.
 * @param[in] in	tmpl to duplicate.
 * @return
 *	- NULL on error.
 *      - A new tmpl on success.
 */
tmpl_t *tmpl_copy(TALLOC_CTX *ctx, tmpl_t const *in)
{
	tmpl_t *vpt;

	MEM(vpt = tmpl_alloc(ctx, in->type, in->quote, in->name, in->len));
	vpt->rules = in->rules;

	/*
	 *	Copy over the unescaped data
	 */
	if (tmpl_is_unresolved(vpt) || tmpl_is_regex_uncompiled(vpt)) {
		if (unlikely(!(vpt->data.unescaped = talloc_bstrdup(vpt, in->data.unescaped)))) {
		error:
			talloc_free(vpt);
			return NULL;
		}
	}

	/*
	 *	Copy attribute references
	 */
	if (tmpl_contains_attr(vpt) && unlikely(tmpl_attr_copy(vpt, in) < 0)) goto error;

	/*
	 *	Copy flags for all regex flavours (and possibly recompile the regex)
	 */
	if (tmpl_contains_regex(vpt)) {
		vpt->data.reg_flags = in->data.reg_flags;

		/*
		 *	If the tmpl contains a _compiled_ regex
		 *	then convert it back to an uncompiled
		 *	regex and recompile.
		 *
		 *	Most of the regex libraries don't allow
		 *	copying compiled expressions.
		 */
		 if (tmpl_is_regex(vpt)) {
			vpt->type = TMPL_TYPE_REGEX_UNCOMPILED;
			if (unlikely(!(vpt->data.unescaped = talloc_bstrdup(vpt, in->data.reg.src)))) goto error;
			if (unlikely(tmpl_regex_compile(vpt, vpt->data.reg.subcaptures) < 0)) goto error;
			return vpt;
		}
	}

	/*
	 *	Copy the xlat component
	 */
	if (tmpl_contains_xlat(vpt) && unlikely(xlat_copy(vpt, &vpt->data.xlat.ex, in->data.xlat.ex) < 0)) goto error;

	return vpt;
}

/** Parse a cast specifier
 *
 *  Note that casts are
 *
 *	(foo)
 *
 *  and NOT
 *
 *	( foo )
 *
 *  Not for any particular reason, but to emphasize a bit that they're
 *  not mathematical expressions.
 *
 * @param[out] rules	to set the cast type in.
 * @param[in] in	String containing the cast marker.
 * @return
 *	- 0 no cast specifier found.
 *	- >0 the number of bytes parsed.
 *	- <0 offset of parse error.
 */
ssize_t tmpl_cast_from_substr(tmpl_rules_t *rules, fr_sbuff_t *in)
{
	char			close = '\0';
	fr_sbuff_t		our_in = FR_SBUFF(in);
	fr_sbuff_marker_t	m;
	fr_type_t		cast;
	ssize_t			slen;

	if (fr_sbuff_next_if_char(&our_in, '<')) {
		close = '>';

	} else if (fr_sbuff_next_if_char(&our_in, '(')) {
		close = ')';

	} else {
		if (rules) rules->cast = FR_TYPE_NULL;
		return 0;
	}

	fr_sbuff_marker(&m, &our_in);
	fr_sbuff_out_by_longest_prefix(&slen, &cast, fr_type_table, &our_in, FR_TYPE_NULL);
	if (fr_type_is_null(cast)) {
		fr_strerror_const("Unknown data type");
		FR_SBUFF_ERROR_RETURN(&our_in);
	}
	if (fr_type_is_non_leaf(cast)) {
		fr_strerror_printf("Forbidden data type '%s' in cast", fr_type_to_str(cast));
		FR_SBUFF_ERROR_RETURN(&m);
	}

	if (!fr_sbuff_next_if_char(&our_in, close)) {
		fr_strerror_const("Unterminated cast");
		FR_SBUFF_ERROR_RETURN(&our_in);
	}
	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);

	if (rules) rules->cast = cast;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Set a cast for a tmpl
 *
 * @param[in,out] vpt	to set cast for.
 * @param[in] dst_type	to set.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_cast_set(tmpl_t *vpt, fr_type_t dst_type)
{
	fr_type_t src_type;

	switch (dst_type) {
	default:
		fr_strerror_printf("Forbidden data type '%s' in cast",
				   fr_type_to_str(dst_type));
		return -1;

	/*
	 *	We can always remove a cast.
	 */
	case FR_TYPE_NULL:
		goto done;

	/*
	 *	Only "base" data types are allowed.  Structural types
	 *	and horrid WiMAX crap is forbidden.
	 */
	case FR_TYPE_LEAF:
		break;
	}

	switch (vpt->type) {
	/*
	 *	This should have been fixed before we got here.
	 */
	case TMPL_TYPE_ATTR_UNRESOLVED:

	/*
	 *	By default, tmpl types cannot be cast to anything.
	 */
	default:
		fr_strerror_const("Cannot use cast here.");
		return -1;

	/*
	 *	These tmpl types are effectively of data type
	 *	"string", so they can be cast to anything.
	 */
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_UNRESOLVED:
	case TMPL_TYPE_EXEC_UNRESOLVED:
	case TMPL_TYPE_XLAT_UNRESOLVED:
		break;

	case TMPL_TYPE_DATA:
		src_type = tmpl_value_type(vpt);
		goto check_types;

	case TMPL_TYPE_ATTR:
		src_type = tmpl_da(vpt)->type;


		/*
		 *	Suppress casts where they are duplicate.
		 */
	check_types:
		if (src_type == dst_type) {
			tmpl_rules_cast(vpt) = FR_TYPE_NULL;
			return 0;
		}

		if (!fr_type_cast(dst_type, src_type)) {
			fr_strerror_printf("Cannot cast type '%s' to '%s'",
					   fr_type_to_str(src_type),
					   fr_type_to_str(dst_type));
			return -1;
		}
		break;
	}

done:
	vpt->rules.cast = dst_type;
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
	fr_slen_t	slen;
	int		err = 0;

	fr_assert(tmpl_is_regex_uncompiled(vpt) || tmpl_is_regex_xlat(vpt) || tmpl_is_regex_xlat_unresolved(vpt));

	slen = regex_flags_parse(&err, &vpt->data.reg_flags, in, terminals, true);
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

/** Determine the correct quoting after a cast
 *
 * @param[in] existing_quote	Exiting quotation type.
 * @param[in] type		Cast type.
 * @param[in] enumv		Enumeration values.
 */
static inline CC_HINT(always_inline)
fr_token_t tmpl_cast_quote(fr_token_t existing_quote,
 			   fr_type_t type, fr_dict_attr_t const *enumv,
 			   char const *unescaped, size_t unescaped_len)
{
	if (!fr_type_is_string(type)) return T_BARE_WORD;

	if (enumv && fr_dict_enum_by_name(enumv, unescaped, unescaped_len)) return T_BARE_WORD;

	/*
	 *	Leave the original quoting if it's
	 *	single or double, else default to
	 *	single quoting.
	 */
	switch (existing_quote) {
	case T_SINGLE_QUOTED_STRING:
	case T_DOUBLE_QUOTED_STRING:
		return existing_quote;

	default:
		return T_SINGLE_QUOTED_STRING;
	}
}


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
		 *	We're trying to convert an unresolved (bareword)
		 *	tmpl to octets.
		 *
		 *	tmpl_afrom_substr uses the 0x prefix as type
		 *	inference, so if it was a hex string the tmpl
		 *	type would not have fallen through to
		 *	unresolved.
		 *
		 *	That means if we're trying to resolve it here
		 *	it's really a printable string, not a sequence
		 *	of hexits, so we just want the binary
		 *	representation of that string, and not the hex
		 *	to bin conversion.
		 */
		if (fr_type_is_octets(type)) {
			if (fr_value_box_memdup(vpt, &vpt->data.literal, enumv,
					        (uint8_t const *)unescaped, talloc_array_length(unescaped) - 1,
					        false) < 0) return -1;
		} else {
			if (fr_value_box_from_str(vpt, &vpt->data.literal, type,
						  enumv,
						  unescaped, talloc_array_length(unescaped) - 1,
						  NULL, false) < 0) return -1;
		}
		vpt->type = TMPL_TYPE_DATA;
		vpt->quote = tmpl_cast_quote(vpt->quote, type, enumv,
					     unescaped, talloc_array_length(unescaped) - 1);
		talloc_free(unescaped);

		/*
		 *	The data is now of the correct type, so we don't need to keep a cast.
		 */
		vpt->rules.cast = FR_TYPE_NULL;
	}
		break;

	case TMPL_TYPE_DATA:
	{
		if (type == tmpl_value_type(vpt)) return 0;	/* noop */

		/*
		 *	Enumerations aren't used when casting between
		 *	data types.  They're only used when processing
		 *	unresolved tmpls.
		 *
		 *	i.e. TMPL_TYPE_UNRESOLVED != TMPL_TYPE_DATA(FR_TYPE_STRING)
		 */
		if (fr_value_box_cast_in_place(vpt, &vpt->data.literal, type, NULL) < 0) return -1;

		/*
		 *	Strings get quoted, everything else is a bare
		 *	word...
		 */
		if (fr_type_is_string(type)) {
			vpt->quote = T_SINGLE_QUOTED_STRING;
		} else {
			vpt->quote = T_BARE_WORD;
		}

		/*
		 *	The data is now of the correct type, so we don't need to keep a cast.
		 */
		vpt->rules.cast = FR_TYPE_NULL;
	}
		break;

	case TMPL_TYPE_ATTR:
		/*
		 *	Suppress casts to the same type.
		 */
		if (tmpl_da(vpt)->type == type) {
			vpt->rules.cast = FR_TYPE_NULL;
			break;
		}
		FALL_THROUGH;

	case TMPL_TYPE_ATTR_UNRESOLVED:
		vpt->rules.cast = type;
		break;

	default:
		fr_assert(0);
	}
	TMPL_VERIFY(vpt);

	return 0;
}

/** Resolve an unresolved attribute
 *
 * Multi-pass parsing fixups for attribute references.
 *
 * @param[in]	vpt		to resolve.
 * @param[in]	tr_rules	Combined with the original parse rules for
 *				additional resolution passes.
 * @return
 *	- 0 if all references were resolved.
 *	- -1 if there are unknown attributes which need
 *	    adding to the global dictionary first.
 *	- -2 if there are attributes we couldn't resolve.
 */
static inline CC_HINT(always_inline) int tmpl_attr_resolve(tmpl_t *vpt, tmpl_res_rules_t const *tr_rules)
{
	tmpl_attr_t		*ar = NULL, *next, *prev;
	fr_dict_attr_t const	*da;
	fr_dict_t const		*dict_def;

	fr_assert(tmpl_is_attr_unresolved(vpt));

	TMPL_VERIFY(vpt);

	dict_def = vpt->rules.attr.dict_def;
	if (!dict_def || tr_rules->force_dict_def) dict_def = tr_rules->dict_def;

	/*
	 *	First component is special becase we may need
	 *	to search for it in multiple dictionaries.
	 *
	 *	This emulates what's done in the initial
	 *	tokenizer function.
	 */
	ar = tmpl_attr_list_head(tmpl_attr(vpt));
	if (ar->type == TMPL_ATTR_TYPE_UNRESOLVED) {
		(void)fr_dict_attr_search_by_name_substr(NULL,
							 &da,
							 dict_def,
							 &FR_SBUFF_IN(ar->ar_unresolved,
							 	      talloc_array_length(ar->ar_unresolved) - 1),
							 NULL,
							 !vpt->rules.attr.disallow_internal,
							 vpt->rules.attr.allow_foreign);
		if (!da) return -2;	/* Can't resolve, maybe the caller can resolve later */

		ar->ar_type = TMPL_ATTR_TYPE_NORMAL;
		ar->ar_da = da;
		ar->ar_parent = fr_dict_root(fr_dict_by_da(da));

		/*
		 *	Record the dictionary that was
		 *	successfully used for resolution.
		 */
		vpt->rules.attr.dict_def = tr_rules->dict_def;

		/*
		 *	Reach into the next reference
		 *	and correct its parent and
		 *	namespace.
		 */
		next = tmpl_attr_list_next(tmpl_attr(vpt), ar);
		if (next) {
			next->ar_parent = da;
			next->ar_unresolved_namespace = da;
		}
	}

	/*
	 *	Loop, resolving each unresolved attribute in turn
	 */
	while ((ar = tmpl_attr_list_next(tmpl_attr(vpt), ar))) {
		switch (ar->type) {
		case TMPL_ATTR_TYPE_NORMAL:
			continue;	/* Don't need to resolve */

		case TMPL_ATTR_TYPE_UNKNOWN:
			return -1;	/* Unknown attributes must be resolved first */

		default:
			break;
		}

		(void)fr_dict_attr_by_name_substr(NULL,
						  &da,
						  ar->ar_unresolved_namespace,
						  &FR_SBUFF_IN(ar->ar_unresolved,
						  	       talloc_array_length(ar->ar_unresolved) - 1),
						  NULL);
		/*
		 *	Still can't resolve, check to see if
		 *	the last attribute reference was a
		 *	group.
		 *
		 *	If it was, then we may be able to
		 *	fall back to resolving the attribute
		 *	in the internal dictionary.
		 */
		if (!da) {
			prev = tmpl_attr_list_prev(tmpl_attr(vpt), ar);
			if (!vpt->rules.attr.disallow_internal && prev && (prev->ar_da->type == FR_TYPE_GROUP)) {
				(void)fr_dict_attr_by_name_substr(NULL,
								  &da,
								  fr_dict_root(fr_dict_internal()),
								  &FR_SBUFF_IN(ar->ar_unresolved,
									       talloc_array_length(ar->ar_unresolved) - 1),
								  NULL);
			}
			if (!da) return -2;
		}

		/*
		 *	Known attribute, just rewrite.
		 */
		ar->ar_type = TMPL_ATTR_TYPE_NORMAL;
		ar->ar_da = da;

		/*
		 *	Parent should have been corrected in
		 *	the previous loop iteration.
		 */
		fr_assert(ar->ar_parent && !ar->ar_parent->flags.is_unknown);

		/*
		 *	Reach into the next reference
		 *	and correct its parent.
		 */
		next = tmpl_attr_list_next(tmpl_attr(vpt), ar);
		if (next) {
			next->ar_parent = da;
			next->ar_unresolved_namespace = da;
		}

		/*
		 *	If the user wanted the leaf
		 *	to be raw, and it's not, correct
		 *	that now.
		 */
		if (ar->ar_unresolved_raw) attr_to_raw(vpt, ar);

		/*
		 *	Remove redundant attributes
		 *
		 *	If it's not a group or does not specify
		 *	an index, the ar is redundant and should
		 *	be removed.
		 */
		prev = tmpl_attr_list_prev(tmpl_attr(vpt), ar);
		if (prev && (prev->ar_da->type != FR_TYPE_GROUP) && (prev->ar_num == NUM_UNSPEC)) {
			tmpl_attr_list_remove(tmpl_attr(vpt), prev);
			ar->ar_parent = prev->ar_parent;
			talloc_free(prev);
		}
	}

	RESOLVED_SET(&vpt->type);
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
 * @param[in]	vpt		Containing the xlat expansion to resolve.
 * @param[in]	tr_rules	Combined with the original parse rules for
 *				additional resolution passes.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(always_inline)
int tmpl_xlat_resolve(tmpl_t *vpt, tmpl_res_rules_t const *tr_rules)
{
	if (xlat_resolve(vpt->data.xlat.ex,
			 &(xlat_res_rules_t){
			 	.tr_rules = tr_rules,
			 	.allow_unresolved = false
			 }) < 0) return -1;

	fr_assert(!xlat_needs_resolving(vpt->data.xlat.ex));

	RESOLVED_SET(&vpt->type);
	TMPL_VERIFY(vpt);

	return 0;
}

/** Attempt to resolve functions and attributes in xlats and attribute references
 *
 * @note If resolution is successful, the rules->attr.dict_def field will be modified to
 *	 reflect the dictionary resolution was successful in.
 *
 * @param[in,out] 	vpt		to resolve.  Should be of type TMPL_TYPE_XLAT_UNRESOLVED
 *					or TMPL_TYPE_ATTR_UNRESOLVED.  All other types will be
 *					noops.
 * @param[in]		tr_rules	Combined with the original parse rules for
 *					additional resolution passes.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int tmpl_resolve(tmpl_t *vpt, tmpl_res_rules_t const *tr_rules)
{
	static tmpl_res_rules_t const default_tr_rules;

	int ret = 0;

	if (!tmpl_needs_resolving(vpt)) return 0;	/* Nothing to do */

	if (!tr_rules) tr_rules = &default_tr_rules;

	/*
	 *	Sanity check.  There shouldn't be conflicting
	 *	enumvs between the original rules and resolution
	 *	rules.
	 *
	 *	Either the enumv was available during parsing
	 *	and shouldn't have changed during subsequent
	 *	resolution passes, or it wasn't available at
	 *	parse-time, but now is.
	 */
	if (tr_rules->enumv && tmpl_rules_enumv(vpt) && !tmpl_rules_enumv(vpt)->flags.is_unknown &&
	    (tr_rules->enumv != tmpl_rules_enumv(vpt))) {
	    	fr_strerror_printf("mismatch between parse-time enumv '%s' and resolution-time enumv '%s'",
	    			   tmpl_rules_enumv(vpt)->name, tr_rules->enumv->name);

	    	return -1;
	}

	/*
	 *	The xlat component of the #tmpl_t needs resolving.
	 *
	 *	This includes exec tmpls, which are largely xlats
	 *	"under the hood".
	 */
	if (tmpl_contains_xlat(vpt)) {
		ret = tmpl_xlat_resolve(vpt, tr_rules);

	/*
	 *	The attribute reference needs resolving.
	 */
	} else if (tmpl_contains_attr(vpt)) {
		fr_type_t		dst_type = tmpl_rules_cast(vpt);

		ret = tmpl_attr_resolve(vpt, tr_rules);
		if (ret < 0) return ret;

		if (dst_type == tmpl_da(vpt)->type) {
			vpt->rules.cast = FR_TYPE_NULL;
		}


	/*
	 *	Convert unresolved tmpls int enumvs, or failing that, string values.
	 */
	} else if (tmpl_is_unresolved(vpt)) {
		fr_type_t		dst_type = tmpl_rules_cast(vpt);
		fr_dict_attr_t const	*enumv = tmpl_rules_enumv(vpt);

		/*
		 *	If there wasn't an enumv set in the
		 *	original rules, and we now have one
		 *	(possibly because the other side of a
		 *	binary expression has been resolved),
		 *	then use the new enumv.
		 */
		if (!enumv) enumv = tr_rules->enumv;

		/*
		 *	If we've got no explicit casting to do
		 *	check if we've got either an existing
		 *	enumv, or one which came in from the
		 *	resolution rules, and infer our data type
		 *	from that.
		 */
		if (fr_type_is_null(dst_type)) {
			/*
			 *	Infer the cast from the enumv type.
			 */
			if (enumv) {
				dst_type = enumv->type;
			} else {
				dst_type = FR_TYPE_STRING;	/* Default to strings */
			}
		}

		/*
		 *	tmpl_cast_in_place first resolves using
		 *	the enumv, _then_ casts using the type.
		 */
		if (tmpl_cast_in_place(vpt, dst_type, enumv) < 0) return -1;

		TMPL_VERIFY(vpt);
	/*
	 *	Catch any other cases of unresolved things
	 *	we need to address.  We put the assert here
	 *	so we don't end up running inappropriate
	 *	code for non-debug builds.
	 */
	} else {
		fr_assert(0);
	}

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
		tmpl_attr_list_talloc_free(tmpl_attr(vpt));
		tmpl_request_list_talloc_free(&vpt->data.attribute.rr);
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
		TALLOC_FREE(vpt->data.xlat.ex);
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
	if (xlat_from_tmpl_attr(vpt, &vpt->data.xlat.ex, vpt_p) < 0) {
		talloc_free(vpt);
		return -1;
	}

	if (xlat_needs_resolving(vpt->data.xlat.ex)) UNRESOLVED_SET(&vpt->type);

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
	attr_to_raw(vpt, tmpl_attr_list_tail(tmpl_attr(vpt)));
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
	tmpl_attr_t		*ar = NULL, *next = NULL;

	if (!vpt) return 1;

	/*
	 *	Can't do this for expressions parsed at runtime
	 */
	if (vpt->rules.at_runtime) return 1;

	tmpl_assert_type(tmpl_is_attr(vpt));

	TMPL_VERIFY(vpt);

	if (!tmpl_da(vpt)->flags.is_unknown) return 1;	/* Ensure at least the leaf is unknown */

	while ((ar = tmpl_attr_list_next(tmpl_attr(vpt), ar))) {
		fr_dict_attr_t const	*unknown, *known;

		switch (ar->type) {
		case TMPL_ATTR_TYPE_NORMAL:		/* Skip */
			continue;

		case TMPL_ATTR_TYPE_UNRESOLVED:		/* Shouldn't have been called */
			fr_strerror_const("Remaining attributes are unresolved");
			return -1;

		case TMPL_ATTR_TYPE_UNKNOWN:
			break;
		}

		unknown = ar->ar_unknown;
		known = fr_dict_unknown_add(fr_dict_unconst(fr_dict_by_da(unknown)), unknown);
		if (!known) return -1;

		/*
		 *	Fixup the parent of the next unknown
		 *	now it's known.
		 */
		next = tmpl_attr_list_next(tmpl_attr(vpt), ar);
		if (next && (next->type == TMPL_ATTR_TYPE_UNKNOWN) &&
		    (next->ar_da->parent == unknown)) {
			if (fr_dict_attr_unknown_parent_to_known(fr_dict_attr_unconst(next->ar_da),
								 known) < 0) return -1;
			next->ar_parent = known;
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
		} else if (!fr_cond_assert(!next)) {
			fr_strerror_const("Only the leaf may be raw");
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
				   da->name, fr_type_to_str(type),
				   fr_type_to_str(da->type));
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
			     &vpt->data.reg_flags, subcaptures, vpt->rules.at_runtime);
	if (slen <= 0) return vpt->quote != T_BARE_WORD ? slen - 1 : slen;	/* Account for the quoting */

	vpt->type = TMPL_TYPE_REGEX;
	vpt->data.reg.src = unescaped;			/* Keep this around for debugging and copying */
	vpt->data.reg.subcaptures = subcaptures;

	TMPL_VERIFY(vpt);

	return slen;
}
#endif
/** @} */

/** @name Print the contents of a #tmpl_t
 * @{
 */
fr_slen_t tmpl_request_ref_list_print(fr_sbuff_t *out, FR_DLIST_HEAD(tmpl_request_list) const *rql)
{
	fr_sbuff_t		our_out = FR_SBUFF(out);
	tmpl_request_t		*rr = tmpl_request_list_head(rql);

	/*
	 *	Print request references
	 */
	while (rr) {
		FR_SBUFF_IN_TABLE_STR_RETURN(&our_out, tmpl_request_ref_table, rr->request, "<INVALID>");
		rr = tmpl_request_list_next(rql, rr);
		if (rr) FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');
	}

	FR_SBUFF_SET_RETURN(out, &our_out);
}

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
fr_slen_t tmpl_attr_print(fr_sbuff_t *out, tmpl_t const *vpt, tmpl_attr_prefix_t ar_prefix)
{
	tmpl_attr_t		*ar = NULL;
	fr_da_stack_t		stack;
	char			printed_rr = false;
	fr_sbuff_t		our_out = FR_SBUFF(out);
	fr_slen_t		slen;

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
	slen = tmpl_request_ref_list_print(&our_out, &vpt->data.attribute.rr);
	if (slen > 0) printed_rr = true;
	if (slen < 0) return slen;

	/*
	 *	Print list
	 */
	if (tmpl_list(vpt) != PAIR_LIST_REQUEST) {	/* Don't print the default list */
		if (printed_rr) FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');

		FR_SBUFF_IN_TABLE_STR_RETURN(&our_out, pair_list_table, tmpl_list(vpt), "<INVALID>");
		if (tmpl_attr_list_num_elements(tmpl_attr(vpt))) FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');

	/*
	 *	Request qualifier with no list qualifier
	 */
	} else if (printed_rr) {
		if (tmpl_attr_list_num_elements(tmpl_attr(vpt))) FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');
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
	if (!tmpl_is_list(vpt) && (ar = tmpl_attr_list_tail(tmpl_attr(vpt)))) {
		switch (ar->type) {
		case TMPL_ATTR_TYPE_NORMAL:
		case TMPL_ATTR_TYPE_UNKNOWN:
			if (ar->ar_da->flags.is_raw) FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "raw.");
			break;

		case TMPL_ATTR_TYPE_UNRESOLVED:
			if (ar->ar_unresolved_raw) FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "raw.");
			break;
		}
	}

	/*
	 *	Print attribute identifiers
	 */
	ar = NULL;
	while ((ar = tmpl_attr_list_next(tmpl_attr(vpt), ar))) {
		if (!tmpl_is_list(vpt)) switch(ar->type) {
		case TMPL_ATTR_TYPE_NORMAL:
		case TMPL_ATTR_TYPE_UNKNOWN:
		{
			int	i, depth = 0;

			fr_assert(ar->ar_parent);	/* All normal and unknown attributes must have parents */

			fr_proto_da_stack_build_partial(&stack, ar->ar_parent, ar->ar_da);

			/*
			 *	First component in the list has everything built
			 */
			if (ar == tmpl_attr_list_head(tmpl_attr(vpt))) {
				depth = ar->ar_parent->depth - 1;	/* Adjust for array index */
			/*
			 *	Everything else skips the first component
			 */
			} else {
				depth = ar->ar_parent->depth;
			}

			/*
			 *	Root attributes will be skipped by the build
			 *	function, so da[0] contains the attribute
			 *	we're looking for.
			 */
			if (depth < 0) depth = 0;

			/*
			 *	Print from our parent depth to the AR we're processing
			 *
			 *	For refs we skip the attribute pointed to be the ref
			 *	and just print its children.
			 */
			for (i = depth; (unsigned int)i < ar->ar_da->depth; i++) {
				FR_SBUFF_IN_STRCPY_RETURN(&our_out, stack.da[i]->name);

				/*
				 *	Print intermediary separators
				 *	if necessary.
				 */
				if (((unsigned int)i + 1) < ar->ar_da->depth) FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');
			}
		}
			break;

		/*
		 *	For unresolved attribute we print the raw identifier we
		 *	got when parsing the tmpl.
		 */
		case TMPL_ATTR_TYPE_UNRESOLVED:
		{
			unsigned int	i, depth;

			/*
			 *	This is the first unresolved component in a potential
			 *	chain of unresolved components.  Print the path up to
			 *	the last known parent.
			 */
			if (ar->ar_parent && !ar->ar_parent->flags.is_root) {
				fr_proto_da_stack_build_partial(&stack, ar->ar_parent, ar->ar_parent);
				if (ar->ar_parent->flags.is_root) {
					depth = 0;
				} else {
					depth = ar->ar_parent->depth - 1;
				}

				for (i = depth; i < ar->ar_parent->depth; i++) {
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
		case NUM_UNSPEC:
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

		if (tmpl_attr_list_next(&vpt->data.attribute.ar, ar)) FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');
	}
	FR_SBUFF_SET_RETURN(out, &our_out);
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
fr_slen_t tmpl_print(fr_sbuff_t *out, tmpl_t const *vpt,
		     tmpl_attr_prefix_t ar_prefix, fr_sbuff_escape_rules_t const *e_rules)
{
	fr_sbuff_t	our_out = FR_SBUFF(out);

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
			       tmpl_type_to_str(vpt->type));
		break;
	}

	FR_SBUFF_SET_RETURN(out, &our_out);
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
fr_slen_t tmpl_print_quoted(fr_sbuff_t *out, tmpl_t const *vpt, tmpl_attr_prefix_t ar_prefix)
{
	fr_sbuff_t our_out = FR_SBUFF(out);

	char quote = fr_token_quote[vpt->quote];

	if (quote != '\0') FR_SBUFF_IN_CHAR_RETURN(&our_out, quote);
	FR_SBUFF_RETURN(tmpl_print, &our_out, vpt,
			ar_prefix, fr_value_escape_by_quote[vpt->quote]);
	if (quote != '\0') FR_SBUFF_IN_CHAR_RETURN(&our_out, quote);

	/*
	 *	Optionally print the flags
	 */
	if (vpt->type & TMPL_FLAG_REGEX) FR_SBUFF_RETURN(regex_flags_print, &our_out, tmpl_regex_flags(vpt));

	FR_SBUFF_SET_RETURN(out, &our_out);
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
	while ((slow = tmpl_attr_list_next(tmpl_attr(vpt), slow)) &&
	       (fast = tmpl_attr_list_next(tmpl_attr(vpt), fast))) {

		/*
		 *	Advances twice as fast as slow...
		 */
		fast = tmpl_attr_list_next(tmpl_attr(vpt), fast);
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
	if (!tmpl_is_list(vpt)) while ((ar = tmpl_attr_list_next(tmpl_attr(vpt), ar))) {
		switch (ar->type) {
		case TMPL_ATTR_TYPE_NORMAL:
			if (seen_unknown) {
				tmpl_attr_debug(vpt);
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: "
						     "TMPL_TYPE_ATTR known attribute \"%s\" "
						     "occurred after unknown attribute %s "
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
			fr_fatal_assert_msg(ar->ar_parent,
					    "CONSISTENCY CHECK FAILED %s[%u]: attr ref missing parent",
					    file, line);
			break;

		case TMPL_ATTR_TYPE_UNRESOLVED:
			seen_unresolved = ar;
			fr_fatal_assert_msg(ar->ar_unresolved_namespace,
					    "CONSISTENCY CHECK FAILED %s[%u]: unresolved attr ref missing namespace",
					    file, line);
			break;

		case TMPL_ATTR_TYPE_UNKNOWN:
			seen_unknown = ar;
			if (seen_unresolved) {
				tmpl_attr_debug(vpt);
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: "
						     "TMPL_TYPE_ATTR unknown attribute \"%s\" "
						     "occurred after unresolved attribute %s "
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
		char quote = vpt->quote >= T_TOKEN_LAST ? '?' : fr_token_quote[vpt->quote];

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
		if (!vpt->data.xlat.ex) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_XLAT "
					     "has a NULL xlat.ex field", file, line);

		}

		if (!xlat_needs_resolving(vpt->data.xlat.ex)) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_XLAT_UNRESOLVED "
					     "does not have 'needs resolving' flag set", file, line);
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
		if ((tmpl_attr_list_num_elements(tmpl_attr(vpt)) > 0) &&
		    ((tmpl_attr_t *)tmpl_attr_list_tail(tmpl_attr(vpt)))->da) {
#ifndef NDEBUG
			tmpl_attr_debug(vpt);
#endif
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR_UNRESOLVED contains %u "
					     "references", file, line, tmpl_attr_list_num_elements(tmpl_attr(vpt)));
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
						     fr_type_to_str(tmpl_da(vpt)->type));
			}

			da = tmpl_da(vpt);
			if (!tmpl_da(vpt)->flags.is_unknown && !tmpl_da(vpt)->flags.is_raw && (da != tmpl_da(vpt))) {
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
						     "dictionary pointer %p \"%s\" (%s) "
						     "and global dictionary pointer %p \"%s\" (%s) differ",
						     file, line,
						     tmpl_da(vpt), tmpl_da(vpt)->name,
						     fr_type_to_str(tmpl_da(vpt)->type),
						     da, da->name,
						     fr_type_to_str(da->type));
			}

			if (!vpt->rules.attr.list_as_attr && (tmpl_list(vpt) >= PAIR_LIST_UNKNOWN)) {
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

		if ((tmpl_attr_list_num_elements(tmpl_attr(vpt)) > 0) &&
		    ((tmpl_attr_t *)tmpl_attr_list_tail(tmpl_attr(vpt)))->da) {
#ifndef NDEBUG
			tmpl_attr_debug(vpt);
#endif
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_LIST contains %u "
					     "references", file, line, tmpl_attr_list_num_elements(tmpl_attr(vpt)));
		}
		break;

	case TMPL_TYPE_DATA:
		if ((nz = CHECK_ZEROED(vpt, literal))) {
			PRINT_NON_ZEROED(vpt, literal, nz);
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA "
					     "has non-zero bytes after the data.literal struct in the union",
					     file, line);
		}

		if (fr_type_is_null(tmpl_value_type(vpt))) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA type was "
					     "FR_TYPE_NULL (uninitialised)", file, line);
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

		case FR_TYPE_STRUCTURAL:
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

#define return_P(_x) fr_strerror_const(_x);goto return_p

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
 * @param[out] castda	NULL if casting is not allowed, otherwise the cast
 * @param   require_regex whether or not to require regular expressions
 * @param   allow_xlat  whether or not "bare" xlat's are allowed
 * @return
 *	- > 0, amount of parsed string to skip, to get to the next token
 *	- <=0, -offset in 'start' where the parse error was located
 */
ssize_t tmpl_preparse(char const **out, size_t *outlen, char const *in, size_t inlen,
		      fr_token_t *type,
		      fr_dict_attr_t const **castda, bool require_regex, bool allow_xlat)
{
	char const *p = in, *end = in + inlen;
	char quote;
	char close;
	int depth;

	*type = T_INVALID;
	if (castda) *castda = NULL;

	while (isspace((int) *p) && (p < end)) p++;
	if (p >= end) return p - in;

	if (*p == '<') {
		fr_type_t cast;
		char const *q;

		if (!castda) {
			fr_strerror_const("Unexpected cast");
		return_p:
			return -(p - in);
		}

		p++;
		fr_skip_whitespace(p);

		for (q = p; *q && !isspace((int) *q) && (*q != '>'); q++) {
			/* nothing */
		}

		cast = fr_table_value_by_substr(fr_type_table, p, q - p, FR_TYPE_NULL);
		if (fr_type_is_null(cast)) {
			return_P("Unknown data type");
		}

		/*
		 *	We can only cast to basic data types.  Complex ones
		 *	are forbidden.
		 */
		if (fr_type_is_non_leaf(cast)) {
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

		if ((p[1] != '{') && (p[1] != '(')) {
			p++;
			return_P("Invalid character after '%'");
		}

		/*
		 *	For now, %{...} / %(...) is treated as a double-quoted
		 *	string.  Once we clean other things up, the
		 *	xlats will be treated as strongly typed values
		 *	/ lists on their own.
		 */
		if (*type == T_INVALID) *type = T_BARE_WORD;
		depth = 0;
		close = (p[1] == '{') ? '}' : ')';

		/*
		 *	Xlat's are quoted by %{...} / %(...) nesting, not by
		 *	escapes, so we need to do special escaping.
		 */
		*out = p;
		while (*p) {
			/*
			 *	End of expansion.  Return the entire
			 *	expansion, including the enclosing %{}
			 *	characters.
			 */
			if ((*p == '}') || (*p == ')')) {
				bool match = (*p == close);

				p++;
				depth--;

				if (depth == 0) {
					if (!match) break;

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

			if ((p[0] == '%') && ((p[1] == '{') || (p[1] == '('))) {
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
		quote = *(p++);
		*type = T_SINGLE_QUOTED_STRING;
		goto skip_string;

	case '`':
		quote = *(p++);
		*type = T_BACK_QUOTED_STRING;
		goto skip_string;

	case '"':
		quote = *(p++);
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

				if (*p == ']') {
					p++;
					continue;
				}
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
#ifndef HAVE_REGEX
	case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:
#endif
		return true;

#ifndef HAVE_REGEX
	case TMPL_TYPE_REGEX_XLAT:
#endif
	case TMPL_TYPE_XLAT:
		return xlat_async_required(tmpl_xlat(vpt));

	default:
		return false;
	}
}

/** Initialize a set of rules from a parent set of rules, and a parsed tmpl_t
 *
 */
void tmpl_rules_child_init(TALLOC_CTX *ctx, tmpl_rules_t *out, tmpl_rules_t const *parent, tmpl_t *vpt)
{
	fr_dict_attr_t const *da;
	fr_dict_attr_t const *ref;
	fr_dict_t const *dict, *internal;

	*out = *parent;
	out->parent = parent;

	if (!tmpl_is_attr(vpt)) return;

	da = tmpl_da(vpt);

	/*
	 *	The input tmpl is a leaf.  We must parse the child as
	 *	a normal attribute reference (as with the parent tmpl).
	 */
	if (!fr_type_structural[da->type]) {
		return;
	}

	if (vpt->rules.attr.request_def) {
		tmpl_request_ref_list_acopy(ctx, &out->attr.request_def, vpt->rules.attr.request_def);
	}
	out->attr.list_def = tmpl_list(vpt);

	/*
	 *	Parse the child attributes in the context of the parent struct / tlv / whatever.
	 */
	if (da->type != FR_TYPE_GROUP) {
		out->attr.dict_def = fr_dict_by_da(da);
		out->attr.parent = da;
		return;
	}

	ref = fr_dict_attr_ref(da);
	dict = fr_dict_by_da(ref);
	internal = fr_dict_internal();

	/*
	 *	Groups MAY change dictionaries.  If so, then swap the dictionary and the parent.
	 */
	if ((dict != internal) && (dict != out->attr.dict_def)) {
		out->attr.dict_def = dict;
		out->attr.parent = ref;
	}

	/*
	 *	Otherwise the reference is swapping FROM a protocol
	 *	dictionary TO the internal dictionary, and TO an
	 *	internal group.  We fall back to leaving well enough
	 *	alone, and leave things as-is.  This allows internal
	 *	grouping attributes to appear anywhere.
	 */
}
