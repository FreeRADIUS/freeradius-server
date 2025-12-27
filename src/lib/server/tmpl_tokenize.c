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

#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/skip.h>

/*
 *	For xlat_exp_head_alloc(), because xlat_copy() doesn't create an output head.
 */
#include <freeradius-devel/unlang/xlat_priv.h>

/** Define a global variable for specifying a default request reference
 *
 * @param[in] _name	what the global variable should be called.
 * @param[in] _ref	one of the values of tmpl_request_ref_t
 *			- REQUEST_CURRENT
 *			- REQUEST_OUTER,
 *			- REQUEST_PARENT,
 *			- REQUEST_UNKNOWN
 */
#define TMPL_REQUEST_REF_DEF(_name, _ref) \
static tmpl_request_t _name ## _entry = { \
	.entry = { \
		.entry = { \
			.next = &_name.head.entry, \
			.prev = &_name.head.entry \
		} \
	}, \
	.request = _ref \
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
 * Used as .attr.request_def = \&tmpl_request_def_current;
 */
TMPL_REQUEST_REF_DEF(tmpl_request_def_current, REQUEST_CURRENT);

/** Use the outer request as the default
 *
 * Used as .attr.request_def = \&tmpl_request_def_outer;
 */
TMPL_REQUEST_REF_DEF(tmpl_request_def_outer, REQUEST_OUTER);

/** Use the parent request as the default
 *
 * Used as .attr.request_def = \&tmpl_request_def_parent;
 */
TMPL_REQUEST_REF_DEF(tmpl_request_def_parent, REQUEST_PARENT);

/** Default parser rules
 *
 * Because this is getting to be a ridiculous number of parsing rules
 * to pass in via arguments.
 *
 * Defaults are used if a NULL rules pointer is passed to the parsing function.
 */
#define DEFAULT_RULES tmpl_rules_t default_rules = { .attr = { .list_def = request_attr_request }}

#define CHECK_T_RULES do { \
	if (!t_rules) { \
		t_rules = &default_rules; \
	} \
  } while (0)


/* clang-format off */
/** Map #tmpl_type_t values to descriptive strings
 */
fr_table_num_ordered_t const tmpl_type_table[] = {
	{ L("uninitialised"),		TMPL_TYPE_UNINITIALISED		},

	{ L("data"),			TMPL_TYPE_DATA			},

	{ L("attr"),			TMPL_TYPE_ATTR			},

	{ L("exec"),			TMPL_TYPE_EXEC			},
	{ L("xlat"),			TMPL_TYPE_XLAT			},

	{ L("regex"),			TMPL_TYPE_REGEX			},
	{ L("regex-uncompiled"),	TMPL_TYPE_REGEX_UNCOMPILED	},
	{ L("regex-xlat"),		TMPL_TYPE_REGEX_XLAT		},

	{ L("data-unresolved"),		TMPL_TYPE_DATA_UNRESOLVED 	},
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
	{ L("unspecified"),	TMPL_ATTR_TYPE_UNSPEC	},
	{ L("unknown"),		TMPL_ATTR_TYPE_UNKNOWN		},
	{ L("unresolved"),	TMPL_ATTR_TYPE_UNRESOLVED	}
};
static size_t attr_table_len = NUM_ELEMENTS(attr_table);

/** We can print "current", but we shouldn't parse the "current" in a configuration.
 */
static fr_table_num_sorted_t const tmpl_request_ref_print_table[] = {
	{ L("current"),		REQUEST_CURRENT			},
	{ L("outer"),		REQUEST_OUTER			},
	{ L("parent"),		REQUEST_PARENT			},
};
static size_t tmpl_request_ref_print_table_len = NUM_ELEMENTS(tmpl_request_ref_print_table);

/** Map keywords to #tmpl_request_ref_t values
 */
fr_table_num_sorted_t const tmpl_request_ref_table[] = {
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

void tmpl_attr_ref_debug(FILE *fp, const tmpl_attr_t *ar, int i)
{
	char buffer[sizeof(STRINGIFY(INT16_MAX)) + 1];

	snprintf(buffer, sizeof(buffer), "%i", ar->ar_num);

	switch (ar->type) {
	case TMPL_ATTR_TYPE_NORMAL:
	case TMPL_ATTR_TYPE_UNSPEC:
	case TMPL_ATTR_TYPE_UNKNOWN:
		if (!ar->da) {
			fprintf(fp, "\t[%u] %s null%s%s%s\n",
				i,
				fr_table_str_by_value(attr_table, ar->type, "<INVALID>"),
				ar->ar_num != NUM_UNSPEC ? "[" : "",
				ar->ar_num != NUM_UNSPEC ? fr_table_str_by_value(attr_num_table, ar->ar_num, buffer) : "",
				ar->ar_num != NUM_UNSPEC ? "]" : "");
			return;
		}

		fprintf(fp, "\t[%u] %s %s %s%s%s%s (%p) attr %u\n ",
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
		fprintf(fp, "\t    is_raw     : %s\n", ar_is_raw(ar) ? "yes" : "no");
		fprintf(fp, "\t    is_unknown : %s\n", ar_is_unknown(ar) ? "yes" : "no");
		if (ar->ar_parent) fprintf(fp, "\t    parent     : %s (%p)\n", ar->ar_parent->name, ar->ar_parent);
		break;


	case TMPL_ATTR_TYPE_UNRESOLVED:
		/*
		 *	Type reveals unresolved status
		 *	so we don't need to add it explicitly
		 */
		fprintf(fp, "\t[%u] %s %s%s%s%s\n",
			i,
			fr_table_str_by_value(attr_table, ar->type, "<INVALID>"),
			ar->ar_unresolved,
			ar->ar_num != NUM_UNSPEC ? "[" : "",
			ar->ar_num != NUM_UNSPEC ? fr_table_str_by_value(attr_num_table, ar->ar_num, buffer) : "",
			ar->ar_num != NUM_UNSPEC ? "]" : "");
		if (ar->ar_parent) 			fprintf(fp, "\t    parent     : %s\n", ar->ar_parent->name);
		if (ar->ar_unresolved_namespace)	fprintf(fp, "\t    namespace  : %s\n", ar->ar_unresolved_namespace->name);
		break;

	default:
		fprintf(fp, "\t[%u] Bad type %s(%u)\n",
			     i, fr_table_str_by_value(attr_table, ar->type, "<INVALID>"), ar->type);
		break;
	}
}

void tmpl_attr_ref_list_debug(FILE *fp, FR_DLIST_HEAD(tmpl_attr_list) const *ar_head)
{
	tmpl_attr_t		*ar = NULL;
	unsigned int		i = 0;

	fprintf(fp, "attribute references:\n");
	/*
	 *	Print all the attribute references
	 */
	while ((ar = tmpl_attr_list_next(ar_head, ar))) {
		tmpl_attr_ref_debug(fp, ar, i);
		i++;
	}
}

void tmpl_attr_debug(FILE *fp, tmpl_t const *vpt)
{
	tmpl_request_t		*rr = NULL;
	unsigned int		i = 0;

	switch (vpt->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_ATTR_UNRESOLVED:
		break;

	default:
		fprintf(fp, "%s can't print tmpls of type %s\n", __FUNCTION__,
			tmpl_type_to_str(vpt->type));
		return;
	}

	fprintf(fp, "tmpl_t %s (%.8x) \"%pV\" (%p)\n",
		tmpl_type_to_str(vpt->type),
		vpt->type,
		fr_box_strvalue_len(vpt->name, vpt->len), vpt);

	fprintf(fp, "\tcast       : %s\n", fr_type_to_str(tmpl_rules_cast(vpt)));
	fprintf(fp, "\tquote      : %s\n", fr_table_str_by_value(fr_token_quotes_table, vpt->quote, "<INVALID>"));

	fprintf(fp, "request references:");

	/*
	 *	Print all the request references
	 */
	while ((rr = tmpl_request_list_next(&vpt->data.attribute.rr, rr))) {
		fprintf(fp, "\t[%u] %s (%u)\n", i,
			     fr_table_str_by_value(tmpl_request_ref_print_table, rr->request, "<INVALID>"), rr->request);
		i++;
	}

	fprintf(fp, "list: %s\n", tmpl_list_name(tmpl_list(vpt), "<INVALID>"));
	tmpl_attr_ref_list_debug(fp, tmpl_attr(vpt));
}

void tmpl_debug(FILE *fp, tmpl_t const *vpt)
{
	switch (vpt->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_ATTR_UNRESOLVED:
		tmpl_attr_debug(fp, vpt);
		return;

	default:
		break;
	}

	fprintf(fp, "tmpl_t %s (%.8x) \"%pR\" (%p)\n",
		tmpl_type_to_str(vpt->type),
		vpt->type,
		vpt->name, vpt);

	fprintf(fp, "\tcast       : %s\n", fr_type_to_str(tmpl_rules_cast(vpt)));
	fprintf(fp, "\tquote      : %s\n", fr_table_str_by_value(fr_token_quotes_table, vpt->quote, "<INVALID>"));
	switch (vpt->type) {
	case TMPL_TYPE_DATA:
		fprintf(fp, "\ttype       : %s\n", fr_type_to_str(tmpl_value_type(vpt)));
		fprintf(fp, "\tlen        : %zu\n", tmpl_value_length(vpt));
		fprintf(fp, "\tvalue      : %pV\n", tmpl_value(vpt));

		if (tmpl_value_enumv(vpt)) fprintf(fp, "\tenumv      : %s (%p)",
						   tmpl_value_enumv(vpt)->name, tmpl_value_enumv(vpt));
		return;

	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_REGEX_XLAT:
	{
		char *str;

		xlat_aprint(NULL, &str, tmpl_xlat(vpt), NULL);

		fprintf(fp, "\texpansion  : %s\n", str);

		talloc_free(str);
	}
		break;

	case TMPL_TYPE_REGEX:
	{
		fprintf(fp, "\tpattern    : %s\n", vpt->name);
	}
		break;

	default:
		if (tmpl_needs_resolving(vpt)) {
			if (tmpl_is_data_unresolved(vpt)) {
				fprintf(fp, "\tunescaped  : %s\n", vpt->data.unescaped);
				fprintf(fp, "\tlen        : %zu\n", talloc_array_length(vpt->data.unescaped) - 1);
			} else {
				fprintf(fp, "\tunresolved : %s\n", vpt->name);
				fprintf(fp, "\tlen        : %zu\n", vpt->len);
			}
		} else {
			fprintf(fp, "debug nyi\n");
		}
		break;
	}
}

/** @name Parse list and request qualifiers to #fr_pair_list_t and #tmpl_request_ref_t values
 *
 * These functions also resolve #fr_pair_list_t and #tmpl_request_ref_t values to #request_t
 * structs and the head of #fr_pair_t lists in those structs.
 *
 * For adding new #fr_pair_t to the lists, the #tmpl_list_ctx function can be used
 * to obtain the appropriate TALLOC_CTX pointer.
 *
 * @note These don't really have much to do with #tmpl_t. They're in the same
 *	file as they're used almost exclusively by the tmpl_* functions.
 * @{
 */

/** Parse one a single list reference
 *
 * @param[out] da_p	attribute representing a list.
 * @param[in] in	Sbuff to read request references from.
 * @return
 *	- > 0 the number of bytes parsed.
 *      - 0 no list qualifier found.
 */
fr_slen_t tmpl_attr_list_from_substr(fr_dict_attr_t const **da_p, fr_sbuff_t *in)
{
	fr_dict_attr_t const *da;
	fr_sbuff_t our_in = FR_SBUFF(in);

	if (((fr_sbuff_adv_past_strcase(&our_in, request_attr_request->name, request_attr_request->name_len)) &&
	     (da = request_attr_request)) ||
	    ((fr_sbuff_adv_past_strcase(&our_in, request_attr_reply->name, request_attr_reply->name_len)) &&
	     (da = request_attr_reply)) ||
	    ((fr_sbuff_adv_past_strcase(&our_in, request_attr_control->name, request_attr_control->name_len)) &&
	     (da = request_attr_control)) ||
	    ((fr_sbuff_adv_past_strcase(&our_in, request_attr_state->name, request_attr_state->name_len)) &&
	     (da = request_attr_state))) {
		/* note: no local variables */
		*da_p = da;
		FR_SBUFF_SET_RETURN(in, &our_in);
	}

	return 0;
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
			     fr_table_str_by_value(tmpl_request_ref_print_table, rr->request, "<INVALID>"),
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

static fr_dict_attr_t const *tmpl_namespace(tmpl_rules_t const *t_rules)
{
	if (!t_rules) {
		return NULL;
	}

	if (t_rules->attr.namespace) {
		if (request_attr_is_list(t_rules->attr.namespace)) {
			return NULL;
		}

		if (t_rules->attr.namespace->type != FR_TYPE_GROUP) {
			return t_rules->attr.namespace;
		}

		if (t_rules->attr.namespace->flags.local) {
			return t_rules->attr.namespace;
		}

		if (t_rules->attr.namespace->flags.internal && t_rules->attr.dict_def) {
			return fr_dict_root(t_rules->attr.dict_def);
		}

		return fr_dict_attr_ref(t_rules->attr.namespace);
	}

	if (t_rules->attr.dict_def) {
		return fr_dict_root(t_rules->attr.dict_def);
	}

	return NULL;
}

/** Parse one or more request references, writing the list to out
 *
 * @param[in] ctx	to allocate request refs in.
 * @param[out] err	If !NULL where to write the parsing error.
 * @param[in] out	The list to write to.
 * @param[in] in	Sbuff to read request references from.
 * @param[in] t_rules	Default list and other rules.
 * @param[out] namespace the namespace to use
 * @return
 *	- >= 0 the number of bytes parsed.
 *      - <0 negative offset for where the error occurred
 */
static fr_slen_t  CC_HINT(nonnull(1,3,4,6)) tmpl_request_ref_list_from_substr(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
										FR_DLIST_HEAD(tmpl_request_list) *out,
										fr_sbuff_t *in,
										tmpl_rules_t const *t_rules,
										fr_dict_attr_t const **namespace)
{
	tmpl_request_ref_t	ref;
	tmpl_request_t		*rr;
	fr_sbuff_t		our_in = FR_SBUFF(in);
	tmpl_request_t		*tail = tmpl_request_list_tail(out);
	fr_sbuff_marker_t	m;

	/*
	 *	The caller needs to know the default namespace for resolving the attribute.
	 *
	 *	But the first round can't have "namespace" set to the root, otherwise things complain.
	 */
	*namespace = tmpl_namespace(t_rules);
	if (*namespace && (*namespace)->flags.is_root) *namespace = NULL;

	/*
	 *	We could make the caller do this but as this
	 *	function is intended to help populate tmpl rules,
	 *	just be nice...
	 */
	if (!tmpl_request_list_initialised(out)) tmpl_request_list_talloc_init(out);

	/*
	 *	We're in a name space, OR lists are forbidden, don't allow list qualifiers.
	 */
	if (*namespace || (t_rules && (t_rules->attr.list_presence == TMPL_ATTR_LIST_FORBID))) {
		if (fr_sbuff_is_str_literal(&our_in, "outer.") ||
		    fr_sbuff_is_str_literal(&our_in, "parent.")) {
			fr_strerror_const("request list qualifiers are not allowed here");
			if (err) *err = TMPL_ATTR_ERROR_LIST_NOT_ALLOWED;

			fr_sbuff_set(&our_in, in);	/* Marker at the start */
	error:
			tmpl_request_list_talloc_free_to_tail(out, tail);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		return 0;
	}

	/*
	 *	See if there is a known reference.
	 */
	fr_sbuff_marker(&m, &our_in);
	if (fr_sbuff_adv_past_str_literal(&our_in, "outer.")) {
		ref = REQUEST_OUTER;

	} else if (fr_sbuff_adv_past_str_literal(&our_in, "parent.")) {
		ref = REQUEST_PARENT;

	} else {
		/*
		 *	No recognized string.  Set the default list if it was specified.
		 */
		if (t_rules && t_rules->attr.request_def) tmpl_request_ref_list_copy(ctx, out, t_rules->attr.request_def);

		return 0;
	}

	/*
	 *	Add a new entry to the dlist
	 */
	MEM(rr = talloc(ctx, tmpl_request_t));
	*rr = (tmpl_request_t){
		.request = ref
	};
	tmpl_request_list_insert_tail(out, rr);

	if (ref == REQUEST_OUTER) {
		/*
		 *	No parent?  Guess.
		 *
		 *	If there is a parent, we use the outermost one.
		 */
		if (!t_rules->parent) {
			t_rules = NULL;

		} else while (t_rules->parent) {
			t_rules = t_rules->parent;
		}

	} else {
		int depth = 1;

		t_rules = t_rules->parent;

		while (fr_sbuff_adv_past_str_literal(&our_in, "parent.")) {
			if (t_rules) t_rules = t_rules->parent;
			depth++;

			/*
			 *	Nesting level too deep
			 */
			if (depth > TMPL_MAX_REQUEST_REF_NESTING) {
				fr_strerror_const("Request ref nesting too deep");
				if (err) *err = TMPL_ATTR_ERROR_NESTING_TOO_DEEP;
				goto error;	/* Leave marker at the end */
			}

			MEM(rr = talloc(ctx, tmpl_request_t));
			*rr = (tmpl_request_t){
				.request = ref
			};
			tmpl_request_list_insert_tail(out, rr);
		}
	}

	/*
	 *	If we mix and match the references, that's wrong.
	 */
	if (fr_sbuff_is_str_literal(&our_in, "outer.") || fr_sbuff_is_str_literal(&our_in, "parent.")) {
		if (err) *err = TMPL_ATTR_ERROR_INVALID_REQUEST_REF;
		fr_strerror_const("Invalid list reference - cannot mix 'outer' and 'parent' references");
		goto error;
	}

	/*
	 *	Now that we have the correct set of tmpl_rules, update the namespace to match.
	 *
	 *	This can have "namespace" set to a dict root, because it is not _our_ dict root. It is an
	 *	outer / parent one.
	 */
	*namespace = tmpl_namespace(t_rules);

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Parse one or more request references, allocing a new list and adding the references to it
 *
 * This can be used to create request ref lists for rules and for tmpls.
 *
 * @param[in] ctx	to allocate request refs in.
 * @param[out] err	If !NULL where to write the parsing error.
 * @param[out] out	The new list.
 * @param[in] in	Sbuff to read request references from.
 * @return
 *	- >= 0 the number of bytes parsed.
 *      - <0 negative offset for where the error occurred
 */
fr_slen_t tmpl_request_ref_list_afrom_substr(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
					     FR_DLIST_HEAD(tmpl_request_list) **out,
					     fr_sbuff_t *in)
{
	fr_slen_t	slen;
	fr_dict_attr_t const *namespace;

	FR_DLIST_HEAD(tmpl_request_list) *rql;

	MEM(rql = talloc_zero(ctx, FR_DLIST_HEAD(tmpl_request_list)));
	tmpl_request_list_talloc_init(rql);

	slen = tmpl_request_ref_list_from_substr(rql, err, rql, in, NULL, &namespace);
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

/** Set escape parameters for the tmpl output
 *
 * @param[in] vpt	to alter.
 * @param[in] escape	to set.
 */
void tmpl_set_escape(tmpl_t *vpt, tmpl_escape_t const *escape)
{
	vpt->rules.escape = *escape;
}

/** Change the default dictionary in the tmpl's resolution rules
 *
 * @param[in] vpt	to alter.
 * @param[in] xlat	to set.
 */
void tmpl_set_xlat(tmpl_t *vpt, xlat_exp_head_t *xlat)
{
	fr_assert((vpt->type == TMPL_TYPE_XLAT) || (vpt->type == TMPL_TYPE_EXEC));

	tmpl_xlat(vpt) = xlat;
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
			.type = TMPL_ATTR_FILTER_TYPE_NONE,
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
		if (unlikely(fr_value_box_copy(vpt, tmpl_value(vpt), data) < 0)) goto error;
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

		case TMPL_ATTR_TYPE_UNSPEC:	/* Nothing to copy */
			break;

	 	case TMPL_ATTR_TYPE_UNKNOWN:
	 		dst_ar->ar_unknown = fr_dict_attr_unknown_copy(dst_ar, src_ar->ar_unknown);
	 		break;

	 	case TMPL_ATTR_TYPE_UNRESOLVED:
	 		dst_ar->ar_unresolved = talloc_bstrdup(dst_ar, src_ar->ar_unresolved);
	 		break;

	 	default:
	 		if (!fr_cond_assert(0)) return -1;
	 	}
	 	dst_ar->ar_num = src_ar->ar_num;
		dst_ar->ar_filter_type = src_ar->ar_filter_type;
		dst_ar->parent = src_ar->parent;
	}

	/*
	 *	Clear any existing request references
	 *	and copy the ones from the source.
	 */
	tmpl_request_list_talloc_reverse_free(&dst->data.attribute.rr);
	tmpl_request_ref_list_copy(dst, &dst->data.attribute.rr, &src->data.attribute.rr);

	/*
	 *	Ensure that we copy over any parsing rules, defaults, etc.
	 */
	dst->rules = src->rules;

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
		ref->da = ref->ar_unknown = fr_dict_attr_unknown_copy(vpt, da);
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

		/*
		 *
		 */
		ref->ar_filter_type = TMPL_ATTR_FILTER_TYPE_NONE;
		ref->ar_num = NUM_UNSPEC;

	} else {
		ref = tmpl_attr_add(vpt, da->flags.is_unknown ? TMPL_ATTR_TYPE_UNKNOWN : TMPL_ATTR_TYPE_NORMAL);
	}


	/*
	 *	Unknown attributes get copied
	 */
	if (da->flags.is_unknown) {
		ref->da = ref->ar_unknown = fr_dict_attr_unknown_copy(vpt, da);
	} else {
		ref->da = da;
	}

	/*
	 *	FIXME - Should be calculated from existing ar
	 */
	ref->ar_parent = fr_dict_root(fr_dict_by_da(da));	/* Parent is the root of the dictionary */

	TMPL_ATTR_VERIFY(vpt);

	return 0;
}

/** Rewrite the leaf's instance number
 *
 *  This function is _only_ called from the compiler, for "update" and "foreach" keywords.  In those cases,
 *  the user historically did "foo-bar", but really meant "foo-bar[*]".  We silently update that for
 *  "update" sections, and complain about it in "foreach" sections.
 *
 *  As the server now supports multiple types of leaf references, we do the rewrite _only_ from "none" (no
 *  filter), OR where it's a numerical index, AND the index hasn't been specified.
 */
void tmpl_attr_rewrite_leaf_num(tmpl_t *vpt, int16_t to)
{
	tmpl_attr_t *ref = NULL;

	tmpl_assert_type(tmpl_is_attr(vpt) || tmpl_is_attr_unresolved(vpt));

	if (tmpl_attr_list_num_elements(tmpl_attr(vpt)) == 0) return;

	ref = tmpl_attr_list_tail(tmpl_attr(vpt));

	if (ref->ar_filter_type == TMPL_ATTR_FILTER_TYPE_NONE) {
		ref->ar_filter_type = TMPL_ATTR_FILTER_TYPE_INDEX;
		ref->ar_num = to;

	} else if (ref->ar_filter_type != TMPL_ATTR_FILTER_TYPE_INDEX) {
		return;

	} else if (ref->ar_num == NUM_UNSPEC) {
		ref->ar_num = to;
	}

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

void tmpl_attr_set_list(tmpl_t *vpt, fr_dict_attr_t const *list)
{
	tmpl_attr_t *ref = tmpl_attr_list_head(tmpl_attr(vpt));
	if (tmpl_attr_is_list_attr(ref)) ref->da = list;

	TMPL_ATTR_VERIFY(vpt);
}

/** Create a new tmpl from a list tmpl and a da
 *
 */
int tmpl_attr_afrom_list(TALLOC_CTX *ctx, tmpl_t **out, tmpl_t const *list, fr_dict_attr_t const *da)
{
	tmpl_t *vpt;
	tmpl_attr_t *ar;

	char attr[256];
	ssize_t slen;

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_ATTR, T_BARE_WORD, NULL, 0));

	/*
	 *	Copies request refs and the list ref
	 */
	tmpl_attr_copy(vpt, list);
	tmpl_attr_set_list(vpt, tmpl_list(list));

	if (da->flags.is_unknown) {
		ar = tmpl_attr_add(vpt, TMPL_ATTR_TYPE_UNKNOWN);
		ar->da = ar->ar_unknown = fr_dict_attr_unknown_copy(vpt, da);
	} else {
		ar = tmpl_attr_add(vpt, TMPL_ATTR_TYPE_NORMAL);
		ar->ar_da = da;
	}

	ar->ar_parent = fr_dict_root(fr_dict_by_da(da));

	/*
	 *	We need to rebuild the attribute name, to be the
	 *	one we copied from the source list.
	 */
	slen = tmpl_print(&FR_SBUFF_OUT(attr, sizeof(attr)), vpt,
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
 * @param[in] at_rules	see tmpl_attr_afrom_attr_substr.
 * @return
 *	- >0 if a filter was parsed.
 *	- 0 if no filter was available.
 *	- <0 on filter parse error.
 */
static fr_slen_t tmpl_attr_parse_filter(tmpl_attr_error_t *err, tmpl_attr_t *ar,
					fr_sbuff_t *name, tmpl_attr_rules_t const *at_rules)
{
	fr_sbuff_t our_name = FR_SBUFF(name);

	/*
	 *	Parse array subscript (and eventually complex filters)
	 */
	if (!fr_sbuff_next_if_char(&our_name, '[')) return 0;

	if (at_rules->disallow_filters || tmpl_attr_is_list_attr(ar)) {
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

	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	{
		ssize_t rcode;
		fr_sbuff_parse_error_t	sberr = FR_SBUFF_PARSE_OK;
		fr_sbuff_t tmp = FR_SBUFF(&our_name);

		/*
		 *	All digits (not hex).
		 */
		rcode = fr_sbuff_out(&sberr, &ar->ar_num, &tmp);
		if ((rcode < 0) || !fr_sbuff_is_char(&tmp, ']')) goto parse_tmpl;

		if ((ar->ar_num > 1000) || (ar->ar_num < 0)) {
			fr_strerror_printf("Invalid array index '%hi' (should be between 0-1000)", ar->ar_num);
			ar->ar_num = 0;
			goto error;
		}

		fr_sbuff_set(&our_name, &tmp);	/* Advance name _AFTER_ doing checks */
		break;
	}

	case '"':
	case '\'':
	case '`':
	case '/':
		fr_strerror_const("Invalid data type for array index");
		goto error;

	/* Used as EOB here */
	missing_closing:
	case '\0':
		fr_strerror_const("No closing ']' for array index");
	error:
		if (err) *err = TMPL_ATTR_ERROR_INVALID_ARRAY_INDEX;
		FR_SBUFF_ERROR_RETURN(&our_name);

	case '(':		/* (...) expression */
	{
		fr_sbuff_t tmp = FR_SBUFF(&our_name);
		fr_slen_t slen;
		tmpl_rules_t t_rules;
		fr_sbuff_parse_rules_t p_rules;
		fr_sbuff_term_t const filter_terminals = FR_SBUFF_TERMS(L("]"));


		tmp = FR_SBUFF(&our_name);
		t_rules = (tmpl_rules_t) {};
		t_rules.attr = *at_rules;

		/*
		 *	Unspecified child, we can create a filter starting from the children.
		 *
		 *	@todo - When parsing the condition, we need to ensure that the condition contains a
		 *	reference to the current cursor, and we need to decide what that syntax is.
		 */
		if (ar->type == TMPL_ATTR_TYPE_UNSPEC) {
			if (at_rules->dict_def) t_rules.attr.namespace = fr_dict_root(at_rules->dict_def);

		} else {
			if (!ar->ar_da || !fr_type_is_structural(ar->ar_da->type)) {
				fr_strerror_printf("Invalid filter - cannot use filter on leaf attributes");
				ar->ar_num = 0;
				goto error;
			}
			t_rules.attr.namespace = ar->ar_da;
		}

		p_rules = (fr_sbuff_parse_rules_t) {
			.terminals = &filter_terminals,
			.escapes = NULL
		};

		/*
		 *	Check if it's a condition.
		 */
		slen = xlat_tokenize_condition(ar, &ar->ar_cond, &tmp, &p_rules, &t_rules);
		if (slen < 0) goto error;

		if (xlat_impure_func(ar->ar_cond)) {
			fr_strerror_const("Condition in attribute index cannot depend on functions which call external databases");
			goto error;
		}

		ar->ar_filter_type = TMPL_ATTR_FILTER_TYPE_CONDITION;
		fr_sbuff_set(&our_name, &tmp);	/* Advance name _AFTER_ doing checks */
		break;
	}

	case '%':		/* ${...} expansion */
	{
		fr_sbuff_t tmp = FR_SBUFF(&our_name);
		fr_slen_t slen;
		tmpl_rules_t t_rules;
		fr_sbuff_parse_rules_t p_rules;
		fr_sbuff_term_t const filter_terminals = FR_SBUFF_TERMS(L("]"));

		if (!fr_sbuff_is_str(&our_name, "%{", 2)) {
			fr_strerror_const("Invalid expression in attribute index");
			goto error;
		}

		tmp = FR_SBUFF(&our_name);
		t_rules = (tmpl_rules_t) {};
		t_rules.attr = *at_rules;

		p_rules = (fr_sbuff_parse_rules_t) {
			.terminals = &filter_terminals,
			.escapes = NULL
		};

		/*
		 *	Check if it's an expression.
		 */
		slen = xlat_tokenize_expression(ar, &ar->ar_expr, &tmp, &p_rules, &t_rules);
		if (slen < 0) goto error;

		if (xlat_impure_func(ar->ar_expr)) {
			fr_strerror_const("Expression in attribute index cannot depend on functions which call external databases");
			goto error;
		}

		ar->ar_filter_type = TMPL_ATTR_FILTER_TYPE_EXPR;

		fr_sbuff_set(&our_name, &tmp);	/* Advance name _AFTER_ doing checks */
		break;
	}

	case 'n':
		/*
		 *	[n] is the last one
		 *
		 *	[nope] is a reference to "nope".
		 */
		if (fr_sbuff_is_str(&our_name, "n]", 2)) {
			ar->ar_num = NUM_LAST;
			fr_sbuff_next(&our_name);
			break;
		}
		FALL_THROUGH;

	default:
	parse_tmpl:
	{
		fr_sbuff_t tmp = FR_SBUFF(&our_name);
		ssize_t slen;
		tmpl_rules_t t_rules;
		fr_sbuff_parse_rules_t p_rules;
		fr_sbuff_term_t const filter_terminals = FR_SBUFF_TERMS(L("]"));

		tmp = FR_SBUFF(&our_name);
		t_rules = (tmpl_rules_t) {};
		t_rules.attr = *at_rules;

		/*
		 *	Don't reset namespace, we always want to start searching from the top level of the
		 *	dictionaries.
		 */

		p_rules = (fr_sbuff_parse_rules_t) {
			.terminals = &filter_terminals,
			.escapes = NULL
		};

		/*
		 *	@todo - for some reason, the tokenize_condition code allows for internal
		 *	vs protocol vs local attributes, whereas the tmpl function only accepts
		 *	internal ones.
		 */
		slen = tmpl_afrom_substr(ar, &ar->ar_tmpl, &tmp, T_BARE_WORD, &p_rules, &t_rules);
		if (slen <= 0) goto error;

		if (!tmpl_is_attr(ar->ar_tmpl)) {
			fr_strerror_printf("Invalid array index '%s'", ar->ar_tmpl->name);
			goto error;
		}

		/*
		 *	Arguably we _could_ say &User-Name["foo"] matches all user-name with value "foo",
		 *	but that would confuse the issue for &Integer-Thing[4].
		 *
		 *	For matching therefore, we really need to have a way to define "self".
		 */
		if (!fr_type_numeric[tmpl_attr_tail_da(ar->ar_tmpl)->type]) {
			fr_strerror_const("Invalid data type for array index (must be numeric)");
			goto error;
		}

		ar->ar_filter_type = TMPL_ATTR_FILTER_TYPE_TMPL;
		fr_sbuff_set(&our_name, &tmp);	/* Advance name _AFTER_ doing checks */
		break;
	}
	}

	/*
	 *	Always advance here, so the error
	 *	marker points to the bad char.
	 */
	if (!fr_sbuff_next_if_char(&our_name, ']')) goto missing_closing;

	FR_SBUFF_SET_RETURN(name, &our_name);
}

extern fr_dict_attr_t const *tmpl_attr_unspec;

static inline CC_HINT(nonnull(3,4))
fr_slen_t tmpl_attr_ref_from_unspecified_substr(tmpl_attr_t *ar, tmpl_attr_error_t *err,
						tmpl_t *vpt,
						fr_sbuff_t *name, tmpl_attr_rules_t const *at_rules)
{
	fr_slen_t	slen;

	*ar = (tmpl_attr_t){
		.ar_num = NUM_UNSPEC,	/* May be changed by tmpl_attr_parse_filter */
		.ar_type = TMPL_ATTR_TYPE_UNSPEC,
		.ar_da = tmpl_attr_unspec,
	};

	slen = tmpl_attr_parse_filter(err, ar, name, at_rules);
	if (slen < 0) {
		return slen;

	/*
	 * No filters and no previous elements is the equivalent of '&'
	 * which is not allowed.
	 *
	 * &[<filter>] is allowed as this lets us perform filtering operations
	 * at the root.
	 */
	} else if ((slen == 0) && (tmpl_attr_num_elements(vpt) == 0)) {
		fr_strerror_const("Invalid attribute name");
		if (err) *err = TMPL_ATTR_ERROR_INVALID_NAME;
		return -1;
	}

	tmpl_attr_insert(vpt,  ar);

	return slen;
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
 * @param[in] namespace		in which the attribute will be resolved.
 * @param[in] name		to parse.
 * @param[in] at_rules		see tmpl_attr_afrom_attr_substr.
 * @return
 *	- <0 on error.
 *	- 0 on success.
 */
static inline CC_HINT(nonnull(3,6))
fr_slen_t tmpl_attr_ref_afrom_unresolved_substr(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
						tmpl_t *vpt,
						fr_dict_attr_t const *parent, fr_dict_attr_t const *namespace,
						fr_sbuff_t *name, tmpl_attr_rules_t const *at_rules)
{
	tmpl_attr_t		*ar = NULL, *ar_curr;
	fr_sbuff_t		our_name = FR_SBUFF(name);
	fr_slen_t		slen;
	char			*unresolved;

	/*
	 *	Point we free from if something goes wrong.
	 */
	ar_curr = tmpl_attr_list_tail(tmpl_attr(vpt));
	for (;;) {
		MEM(ar = talloc(ctx, tmpl_attr_t));
		/*
		*	Copy out a string of allowed dictionary chars to form
		*	the unresolved attribute name.
		*
		*	This will be resolved later (outside of this function).
		*/
		slen = fr_sbuff_out_abstrncpy_allowed(ar, &unresolved,
						      &our_name, FR_DICT_ATTR_MAX_NAME_LEN + 1,
						      fr_dict_attr_allowed_chars);
		if (slen == 0) {
			slen = tmpl_attr_ref_from_unspecified_substr(ar, err, vpt, &our_name, at_rules);
			if (slen < 0) {
				fr_sbuff_advance(&our_name, +slen);
			error:
				talloc_free(ar);
				tmpl_attr_list_talloc_free_to_tail(tmpl_attr(vpt), ar_curr);
				return -1;
			}
			return fr_sbuff_set(name, &our_name);
		} else if (slen > FR_DICT_ATTR_MAX_NAME_LEN) {
			fr_strerror_const("Attribute name is too long");
			if (err) *err = TMPL_ATTR_ERROR_INVALID_NAME;
			goto error;
		}

		*ar = (tmpl_attr_t){
			.ar_num = NUM_UNSPEC,
			.ar_type = TMPL_ATTR_TYPE_UNRESOLVED,
			.ar_unresolved = unresolved,
			.ar_unresolved_namespace = namespace,
			.ar_parent = parent
		};

		if (tmpl_attr_parse_filter(err, ar, &our_name, at_rules) < 0) goto error;

		/*
		*	Insert the ar into the list of attribute references
		*/
		tmpl_attr_insert(vpt, ar);

		/*
		*	Once one OID component is created as unresolved all
		*	future OID components are also unresolved.
		*/
		if (!fr_sbuff_next_if_char(&our_name, '.')) break;
	}

	/*
	 *	Mark the tmpl up as an unresolved attribute reference
	 *	the attribute reference will be resolved later.
	 */
	vpt->type = TMPL_TYPE_ATTR_UNRESOLVED;

	return fr_sbuff_set(name, &our_name);
}

/*
 *	Add attr_ref when we've parsed an intermediate dictionary name
 *	which is itself a ref.
 */
static void tmpl_attr_ref_fixup(TALLOC_CTX *ctx, tmpl_t *vpt, fr_dict_attr_t const *da, fr_dict_attr_t const *parent)
{
	tmpl_attr_t *ar;

	if (tmpl_attr_tail_da(vpt) == da) return;

	if (da->parent != parent) tmpl_attr_ref_fixup(ctx, vpt, da->parent, parent);

	MEM(ar = talloc(ctx, tmpl_attr_t));
	*ar = (tmpl_attr_t) {
		.ar_num = NUM_UNSPEC,
		.ar_type = TMPL_ATTR_TYPE_NORMAL,
		.ar_da = da,
		.ar_parent = da->parent,
	};

	tmpl_attr_insert(vpt, ar);
}

/** Parse an attribute reference, either an OID or attribute name
 *
 * @note Do not call directly.
 *
 * @param[in] ctx		to allocate new attribute reference in.
 * @param[out] err		Parse error.
 * @param[in,out] vpt		to append this reference to.
 * @param[in] parent		Parent where the attribute will be placed (group, struct, tlv, etc).
 * @param[in] namespace		Where the child attribute will be parsed from (dict root, struct member, TLV child, etc)
 * @param[in] name		to parse.
 * @param[in] p_rules		Formatting rules used to check for trailing garbage.
 * @param[in] at_rules		which places constraints on attribute reference parsing.
 *				Rules interpreted by this function is:
 *				- allow_unknown - If false unknown OID components
 *				  result in a parse error.
 *				- allow_unresolved - If false unknown attribute names
 *				  result in a parse error.
 *				- allow_foreign - If an attribute resolves in a dictionary
 *				  that does not match the parent
 *				  (exception being FR_TYPE_GROUP) then that results
 *				  in a parse error.
 * @param[in] depth		How deep we are.  Used to check for maximum nesting level.
 * @return
 *	- <0 on error.
 *	- 0 on success.
 */
static int tmpl_attr_afrom_attr_substr(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
				       tmpl_t *vpt,
				       fr_dict_attr_t const *parent, fr_dict_attr_t const *namespace,
				       fr_sbuff_t *name,
				       fr_sbuff_parse_rules_t const *p_rules, tmpl_attr_rules_t const *at_rules,
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
		talloc_free(ar);
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
	 *	Maybe there's no child namespace (struct member, tlv child, etc).  In which case we must
	 *	search from the default dictionary root.
	 *
	 *	This search is probably wrong in some cases.  See the comments below around FR_TYPE_GROUP.
	 *
	 *	If we change out the dictionaries, we should arguably also change dict_def in the
	 *	tmpl_attr_rules_t.  On top of that, the "dict_attr_search" functions take a #fr_dict_t
	 *	pointer, and not a pointer to the dict root.  So we can't pass them a namespace.
	 */
	if (!namespace) {
		fr_assert(parent == NULL);

		(void)fr_dict_attr_search_by_qualified_name_substr(&dict_err, &da,
								   at_rules->dict_def,
								   name, p_rules ? p_rules->terminals : NULL,
								   true,
								   at_rules->allow_foreign);
		/*
		 *	The attribute was found either in the dict_def root, OR in the internal root, OR if
		 *	!dict_def && allow_foreign, in some other dictionary root.
		 *
		 *	Otherwise we're still not sure what the attribute is.  It may end up being an
		 *	unresolved one.
		 */
		if (da) {
			our_parent = da->parent;

			if (!our_parent->flags.is_root) {
				tmpl_attr_ref_fixup(ctx, vpt, our_parent, fr_dict_root(da->dict));
			}
		}
	} else {
		fr_assert(parent != NULL);

		/*
		 *	Otherwise we're resolving the next piece in the context of where-ever we ended up from
		 *	parsing the last bit.
		 *
		 *	The "parent" could be the same as "namespace", if both are at a dictionary root, OR
		 *	both are from a struct / tlv attribute.

		 *	Or, "parent" could be a grouping attribute (e.g. request), and "namespace" could be
		 *	the dictionary root.
		 */
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
		if (!da) {
			ar = tmpl_attr_list_tail(&vpt->data.attribute.ar);
			if (!ar || ((ar->type == TMPL_ATTR_TYPE_NORMAL) && (ar->ar_da->type == FR_TYPE_GROUP))) {
				fr_dict_attr_t const *internal_root = fr_dict_root(fr_dict_internal());

				(void)fr_dict_attr_by_name_substr(NULL,
								  &da, internal_root,
								  name,
								  p_rules ? p_rules->terminals : NULL);
				if (da) {
					dict_err = FR_DICT_ATTR_OK;
					our_parent = internal_root;
				}
			}
			ar = NULL;

		} else {
			/*
			 *	If we searched in a local dictionary, but found a real attribute
			 *	switch the namespace.
			 */
			if (!da->flags.local && namespace->flags.local) namespace = our_parent = fr_dict_root(da->dict);
		}
	}

	/*
	 *	Fatal errors related to nesting...
	 */
	switch (dict_err) {
	case FR_DICT_ATTR_NO_CHILDREN:
		fr_assert(our_parent != NULL);
		if (our_parent->flags.is_unknown) break;
		goto error;

	case FR_DICT_ATTR_NOT_DESCENDENT:
		goto error;

	default:
		if (!da) break;

		/*
		 *	The named component was a known attribute
		 *	so record it as a normal attribute
		 *	reference.
		 */
		fr_assert(our_parent != NULL);

		/*
		 *	We had an alias in the same namespace,
		 *	go add more things in.
		 */
		if (da->parent != our_parent) {
			fr_assert(namespace == our_parent);
			tmpl_attr_ref_fixup(ctx, vpt, da->parent, our_parent);
		}

		goto alloc_ar;
	}

	/*
	 *	At this point we haven't found a known attribute.  What remains MUST be an OID component, OR an
	 *	unresolved attribute.
	 *
	 *	The default is to parse the OIDs in the current namespace.  If there is none, then we parse
	 *	the OIDs and unresolved attributes in the dict_def.  And if that doesn't exist, in the
	 *	internal dictionaries.
	 *
	 *	Note that we do NOT allow unknown attributes in the internal dictionary.  Those attributes are
	 *	generally just DEFINEs, and their numbers have no meaning.
	 */
	if (!namespace) {
		if (at_rules->dict_def) {
			our_parent = namespace = fr_dict_root(at_rules->dict_def);
		} else {
			our_parent = namespace = fr_dict_root(fr_dict_internal());
		}
	}

	fr_assert(our_parent != NULL);
	fr_assert(namespace != NULL);

	/*
	 *	See if the ref begins with an unsigned integer
	 *	if it does it's probably an OID component
	 *
	 *	.<oid>
	 */
	if (fr_sbuff_out(NULL, &oid, name) > 0) {
		if (!at_rules->allow_oid) {
			uint8_t c = fr_sbuff_char(name, '\0');

			/*
			 *	This extra test is to give the user better errors.  The string "3G" is parsed
			 *	as "3", and then an error of "what the heck do you mean by G?"
			 *
			 *	In contrast, the string "3." is parsed as "3", and then "nope, that's not an attribute reference".
			 */
			if (c != '.') {
				fr_strerror_const("Unexpected text after attribute reference");
				if (err) *err = TMPL_ATTR_ERROR_MISSING_TERMINATOR;
			} else {
				fr_strerror_const("Numerical attribute references are not allowed here");
				if (err) *err = TMPL_ATTR_ERROR_INVALID_OID;

				fr_sbuff_set(name, &m_s);
			}
			goto error;
		}

		our_parent = namespace = fr_dict_unlocal(namespace);

		fr_assert(ar == NULL);

		fr_strerror_clear();	/* Clear out any existing errors */

		if (fr_dict_by_da(namespace) == fr_dict_internal()) goto disallow_unknown;

		/*
		 *	The OID component was a known attribute
		 *	so record it as a normal attribute
		 *	reference.
		 */
		da = fr_dict_attr_child_by_num(namespace, oid);
		if (da) {
			fr_assert(da->parent == our_parent);
			goto alloc_ar;
		}

		if (!at_rules->allow_unknown) {
		disallow_unknown:
			fr_strerror_const("Unknown attributes not allowed here");
			if (err) *err = TMPL_ATTR_ERROR_UNKNOWN_NOT_ALLOWED;
			fr_sbuff_set(name, &m_s);
			goto error;
		}

		/*
		 *	If it's numeric and not a known attribute
		 *      then we create an unknown attribute with
		 *	the specified attribute number.
		 */
		MEM(ar = talloc(ctx, tmpl_attr_t));

		/*
		 *	VSAs have VENDORs as children.  All others are just normal things.
		 */
		switch (namespace->type) {
		case FR_TYPE_VSA:
			da = fr_dict_attr_unknown_vendor_afrom_num(ar, namespace, oid);
			break;

		default:
			da  = fr_dict_attr_unknown_raw_afrom_num(ar, namespace, oid);
			break;
		}

		if (!da) {
			if (err) *err = TMPL_ATTR_ERROR_UNKNOWN_NOT_ALLOWED;	/* strerror set by dict function */
			goto error;
		}

		*ar = (tmpl_attr_t){
			.ar_num = NUM_UNSPEC,
			.ar_type = TMPL_ATTR_TYPE_UNKNOWN,
			.ar_unknown = UNCONST(fr_dict_attr_t *, da),
			.ar_da = da,
			.ar_parent = our_parent,
		};
		goto do_suffix;
	}

	/*
	 *	Can't parse it as an attribute, might be a literal string
	 *	let the caller decide.
	 *
	 *	Don't alter the fr_strerror buffer, may contain useful
	 *	errors from the dictionary code.
	 */
	if (!at_rules->allow_unresolved && !(at_rules->allow_wildcard && fr_sbuff_is_char(name, '['))) {
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
	return tmpl_attr_ref_afrom_unresolved_substr(ctx, err, vpt, our_parent, namespace, name, at_rules);

alloc_ar:
	/*
	 *	We have a da, remove any of the errors recorded from failed
	 *	searches to find the attribute to avoid misleading messages
	 *	if something else fails.
	 */
	fr_strerror_clear();

	MEM(ar = talloc(ctx, tmpl_attr_t));
	*ar = (tmpl_attr_t) {
		.ar_num = NUM_UNSPEC,
		.ar_type = TMPL_ATTR_TYPE_NORMAL,
		.ar_da = da,
		.ar_parent = da->parent,
	};

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
	if (tmpl_attr_parse_filter(err, ar, name, at_rules) < 0) goto error;

	/*
	 *	Local variables are always unitary.
	 *
	 *	[0] is allowed, as is [n], [*], and [#].  But [1], etc. aren't allowed.
	 */
	if (da->flags.local && (ar->ar_num > 0)) {
		fr_strerror_printf("Invalid array reference for local variable");
		if (err) *err = TMPL_ATTR_ERROR_INVALID_ARRAY_INDEX;
		fr_sbuff_set(name, &m_s);
		goto error;
	}

	/*
	 *	At the end of the attribute reference. If there's a
	 *	trailing '.' then there's another attribute reference
	 *	we need to parse, otherwise we're done.
	 */
	fr_sbuff_marker_release(&m_s);
	fr_sbuff_marker(&m_s, name);

	if (fr_sbuff_next_if_char(name, '.')) {
		fr_dict_attr_t const *ref;

		switch (da->type) {
		case FR_TYPE_GROUP:
			ref = fr_dict_attr_ref(da);

			/*
			 *	If the ref is outside of the internal namespace, then we use it.
			 *
			 *	If the ref is inside of the internal namespace (e.g. "request"), then we do
			 *	something else.
			 *
			 *	If we were given a root dictionary on input, use that.  We have to follow this
			 *	dictionary because this function calls itself recursively, WITHOUT updating
			 *	"dict_def" in the attr_rules.  So the dict-def there is whatever got passed
			 *	into tmpl_afrom_attr_substr(), BEFORE the "parent.parent.parent..." parsing.
			 *	Which means that in many cases, the "dict_def" is completely irrelevant.
			 *
			 *	If there is no parent on input, then we just use dict_def.
			 *
			 *	Otherwise we search through all of the dictionaries.
			 *
			 *	Note that we cannot put random protocol attributes into an internal attribute
			 *	of type "group".
			 */
			if (ref != fr_dict_root(fr_dict_internal())) {
				our_parent = namespace = ref;

			} else if (parent && parent->flags.is_root) {
				our_parent = namespace = parent;

			} else if (at_rules->dict_def) {
				our_parent = namespace = fr_dict_root(at_rules->dict_def);

			} else {
				our_parent = namespace = NULL;
			}
			break;

		case FR_TYPE_STRUCTURAL_EXCEPT_GROUP:
			/*
			 *	Structural types are parented and namespaced from their parent da.
			 */
			namespace = our_parent = da;
			break;

		default:
			fr_strerror_printf("Attribute %s of data type '%s' cannot have child attributes", da->name, fr_type_to_str(da->type));
			fr_sbuff_set(name, &m_s);
			goto error;
		}

		if (ar) tmpl_attr_insert(vpt, ar);

		if (tmpl_attr_afrom_attr_substr(ctx, err, vpt, our_parent, namespace, name, p_rules, at_rules, depth + 1) < 0) {
			if (ar) {
				tmpl_attr_list_talloc_free_tail(&vpt->data.attribute.ar); /* Remove and free ar */
				ar = NULL;
			}
			goto error;
		}

	/*
	 *	If it's a leaf we always insert the attribute
	 *	reference into the list, even if it's a
	 *	nesting attribute.
	 *
	 *	This is useful for nested edit sections
	 *	where the tmpl might be the name of a new
	 *	subsection.
	 */
	} else {
		tmpl_attr_insert(vpt, ar);
	}

	/*
	 *	Remove unnecessary casts.
	 */
	if (tmpl_is_attr(vpt) && tmpl_attr_tail_is_normal(vpt) &&
	    (tmpl_rules_cast(vpt) == tmpl_attr_tail_da(vpt)->type)) vpt->rules.cast = FR_TYPE_NULL;

	TMPL_VERIFY(vpt);

	fr_sbuff_marker_release(&m_s);
	return 0;
}

static int attr_to_raw(tmpl_t *vpt, tmpl_attr_t *ref)
{
	switch (ref->type) {
	case TMPL_ATTR_TYPE_NORMAL:
	{
		ref->da = ref->ar_unknown = fr_dict_attr_unknown_afrom_da(vpt, ref->da);
		if (!ref->da) return -1;

		ref->ar_unknown->type = FR_TYPE_OCTETS;
		ref->is_raw = 1;
		ref->type = TMPL_ATTR_TYPE_UNKNOWN;
	}
		break;
	case TMPL_ATTR_TYPE_UNSPEC:	/* noop */
		break;

	case TMPL_ATTR_TYPE_UNKNOWN:
		ref->ar_unknown->type = FR_TYPE_OCTETS;
		ref->is_raw = 1;
		break;

	case TMPL_ATTR_TYPE_UNRESOLVED:
		ref->is_raw = true;
		break;
	}

	TMPL_ATTR_VERIFY(vpt);

	return 0;
}

/** Parse a string into a TMPL_TYPE_ATTR_* type #tmpl_t
 *
 * @param[in,out] ctx		to allocate #tmpl_t in.
 * @param[out] err		May be NULL.  Provides the exact error that the parser hit
 *				when processing the attribute ref.
 * @param[out] out		Where to write pointer to new #tmpl_t.
 * @param[in] name		of attribute including #tmpl_request_ref_t and #fr_pair_list_t qualifiers.
 * @param[in] p_rules		Formatting rules used to check for trailing garbage.
 * @param[in] t_rules		Rules which control parsing:
 *				- dict_def		The default dictionary to use if attributes
 *							are unqualified.
 *				- request_def		The default #request_t to set if no
 *							#tmpl_request_ref_t qualifiers are found in name.
 *				- list_def		The default list to set if no #fr_pair_list_t
 *							qualifiers are found in the name.
 *				- allow_unknown		If true, numerical attributes will be allowed,
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
	tmpl_t				*vpt;
	fr_sbuff_t			our_name = FR_SBUFF(name);	/* Take a local copy in case we need to back track */
	bool				is_raw = false;
	tmpl_attr_rules_t const		*at_rules;
	tmpl_attr_rules_t		my_attr_rules;
	fr_sbuff_marker_t		m_l;
	fr_dict_attr_t const		*namespace;
	DEFAULT_RULES;

	CHECK_T_RULES;

	at_rules = &t_rules->attr;

	if (err) *err = TMPL_ATTR_ERROR_NONE;

	if (!fr_sbuff_extend(&our_name)) {
		fr_strerror_const("Empty attribute reference");
		if (err) *err = TMPL_ATTR_ERROR_EMPTY;
		FR_SBUFF_ERROR_RETURN(&our_name);
	}

	/*
	 *	'&' prefix is ignored.
	 */
	if (fr_sbuff_next_if_char(&our_name, '&') && check_config && at_rules->ci) {
		cf_log_warn(at_rules->ci, "Using '&' is no longer necessary when referencing attributes, and should be deleted.");
	}

	/*
	 *	We parsed the tmpl as User-Name, but NOT %{User-Name}.
	 */
	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_ATTR, T_BARE_WORD, NULL, 0));

	/*
	 *	The "raw." prefix marks up the leaf attribute
	 *	as unknown if it wasn't already which allows
	 *	users to stick whatever they want in there as
	 *	a value.
	 */
	if (fr_sbuff_adv_past_strcase_literal(&our_name, "raw.")) {
		my_attr_rules = *at_rules;
		my_attr_rules.allow_oid = true;
		at_rules = &my_attr_rules;

		is_raw = true;
	}

	/*
	 *	Parse one or more request references
	 */
	ret = tmpl_request_ref_list_from_substr(vpt, err,
						&vpt->data.attribute.rr,
						&our_name,
						t_rules,
						&namespace);
	if (ret < 0) {
	error:
		*out = NULL;
		talloc_free(vpt);
		FR_SBUFF_ERROR_RETURN(&our_name);
	}

	fr_sbuff_marker(&m_l, &our_name);

	/*
	 *	Parse the list and / or attribute reference
	 */
	ret = tmpl_attr_afrom_attr_substr(vpt, err,
					  vpt,
					  namespace, namespace,
					  &our_name, p_rules, at_rules, 0);
	if (ret < 0) goto error;

	if (!tmpl_substr_terminal_check(&our_name, p_rules)) {
		fr_strerror_const("Unexpected text after attribute reference");
		if (err) *err = TMPL_ATTR_ERROR_MISSING_TERMINATOR;
		goto error;
	}

	/*
	 *	Check whether the tmpl has a list qualifier.
	 */
	switch (at_rules->list_presence) {
	case TMPL_ATTR_LIST_ALLOW:
		break;

	case TMPL_ATTR_LIST_FORBID:
		if (tmpl_attr_is_list_attr(tmpl_attr_list_head(tmpl_attr(vpt)))) {
			fr_strerror_const("List qualifiers are not allowed here.");
			if (err) *err = TMPL_ATTR_ERROR_LIST_NOT_ALLOWED;
			goto error;
		}
		break;

	case TMPL_ATTR_LIST_REQUIRE:
		if (!tmpl_attr_is_list_attr(tmpl_attr_list_head(tmpl_attr(vpt)))) {
			fr_strerror_const("List qualifier is required, but no list was found.");
			if (err) *err = TMPL_ATTR_ERROR_LIST_MISSING;
			goto error;
		}
		break;
	}

	tmpl_set_name(vpt, T_BARE_WORD, fr_sbuff_start(&our_name), fr_sbuff_used(&our_name));
	vpt->rules = *t_rules;	/* Record the rules */

	/*
	 *	Check to see if the user wants the leaf
	 *	attribute to be raw.
	 *
	 *	We can only do the conversion now _if_
	 *	the complete hierarchy has been resolved
	 *	otherwise we'll need to do the conversion
	 *	later.
	 */
	if (tmpl_is_attr(vpt)) {
		tmpl_attr_t	*ar = tmpl_attr_list_head(tmpl_attr(vpt));
		bool		is_local = ar->ar_da->flags.local;
		bool		allow_local = is_local;

		/*
		 *	Convert known attributes to raw ones if requested.
		 */
		if (is_raw) {
			/*
			 *	Local variables cannot be raw.
			 */
			if (is_local) {
				fr_strerror_printf("Local attributes cannot be 'raw'");
				if (err) *err = TMPL_ATTR_ERROR_UNKNOWN_NOT_ALLOWED;
				fr_sbuff_set(&our_name, &m_l);
				goto error;
			}
			ret = attr_to_raw(vpt, tmpl_attr_list_tail(tmpl_attr(vpt)));
			if (ret < 0) goto error;
		}

		/*
		 *	We can transition from local to non-local, but not the other way around.
		 */
		for (;
		     ar != NULL;
		     ar = tmpl_attr_list_next(tmpl_attr(vpt), ar)) {
			if (ar->ar_da->flags.local == allow_local) continue;

			if (!ar->ar_da->flags.local && allow_local) {
				allow_local = false;
				continue;
			}

			if (ar->ar_da->flags.local) {
				fr_strerror_printf("Local attributes cannot be used in any list");
				if (err) *err = TMPL_ATTR_ERROR_FOREIGN_NOT_ALLOWED;
				fr_sbuff_set(&our_name, &m_l);
				goto error;
			}
		}

		/*
		 *	Local variables are named "foo", but are always put into the local list.
		 *
		 *	We add the list after checking for non-local -> local transition, as
		 *	request_attr_local isn't a local attribute.
		 *
		 *	When the list is forbidden, we're creating a local attribute inside of a local
		 *	TLV.
		 */
		if (is_local && (at_rules->list_presence != TMPL_ATTR_LIST_FORBID)) {
			MEM(ar = talloc(vpt, tmpl_attr_t));
			*ar = (tmpl_attr_t){
				.ar_type = TMPL_ATTR_TYPE_NORMAL,
				.ar_da = request_attr_local,
				.ar_parent = fr_dict_root(fr_dict_internal())
			};

			/*
			 *	Prepend the local list ref so it gets evaluated
			 *	first.
			 */
			tmpl_attr_list_insert_head(tmpl_attr(vpt), ar);
		}
	}

	/*
	 *	If a list wasn't already specified, then add one now.
	 */
	if (!tmpl_attr_is_list_attr(tmpl_attr_list_head(tmpl_attr(vpt)))) {
		tmpl_attr_t *ar;

		MEM(ar = talloc(vpt, tmpl_attr_t));
		*ar = (tmpl_attr_t){
			.ar_type = TMPL_ATTR_TYPE_NORMAL,
			.ar_parent = fr_dict_root(fr_dict_internal())
		};

		fr_assert(at_rules->list_def);
		ar->ar_da = at_rules->list_def;

		/*
		 *	Prepend the list ref so it gets evaluated
		 *	first.
		 */
		tmpl_attr_list_insert_head(tmpl_attr(vpt), ar);
	}

	/*
	 *	If there is a default request (parent, outer, etc.), add it to the ar list.
	 *
	 *	A NULL request_def pointer is equivalent to the current request.
	 */
	if (t_rules->attr.request_def) {
		tmpl_request_ref_list_acopy(vpt, &vpt->rules.attr.request_def, t_rules->attr.request_def);
	}

	/*
	 *	Now that all of the lists are set correctly, do some final validation and updates on the
	 *	attribute.
	 */
	if (tmpl_is_attr(vpt)) {
		tmpl_attr_t *ar;

		/*
		 *	Ensure that the list is set correctly, so that the returned vpt just doesn't just
		 *	match the input rules, it is also internally consistent.
		 */
		ar = tmpl_attr_list_head(tmpl_attr(vpt));
		fr_assert(ar != NULL);

		if (tmpl_attr_is_list_attr(ar)) vpt->rules.attr.list_def = ar->ar_da;

		if (tmpl_attr_tail_is_normal(vpt)) {
			/*
			 *	Suppress useless casts.
			 */
			if (tmpl_attr_tail_da(vpt)->type == tmpl_rules_cast(vpt)) {
				vpt->rules.cast = FR_TYPE_NULL;
			}

			/*
			 *	Check if the cast is allowed.  This lets us give better errors at compile time.
			 */
			if ((tmpl_rules_cast(vpt)!= FR_TYPE_NULL) &&
			    !fr_type_cast(tmpl_rules_cast(vpt), tmpl_attr_tail_da(vpt)->type)) {
				fr_strerror_printf("Cannot cast type '%s' to '%s'",
					   fr_type_to_str(tmpl_attr_tail_da(vpt)->type), fr_type_to_str(t_rules->cast));
				if (err) *err = TMPL_ATTR_ERROR_BAD_CAST;
				fr_sbuff_set_to_start(&our_name);
				goto error;
			}
		}
	}

	TMPL_VERIFY(vpt);	/* Because we want to ensure we produced something sane */

	*out = vpt;
	FR_SBUFF_SET_RETURN(name, &our_name);
}

/** Parse a string into a TMPL_TYPE_ATTR_* type #tmpl_t
 *
 * @param[in,out] ctx		to allocate #tmpl_t in.
 * @param[out] err		May be NULL.  Provides the exact error that the parser hit
 *				when processing the attribute ref.
 * @param[out] out		Where to write pointer to new #tmpl_t.
 * @param[in] name		of attribute including #tmpl_request_ref_t and #fr_pair_list_t qualifiers.
 * @param[in] t_rules		Rules which control parsing.  See tmpl_afrom_attr_substr() for details.
 *
 * @note Unlike #tmpl_afrom_attr_substr this function will error out if the entire
 *	name string isn't parsed.
 */
ssize_t tmpl_afrom_attr_str(TALLOC_CTX *ctx, tmpl_attr_error_t *err,
			    tmpl_t **out, char const *name, tmpl_rules_t const *t_rules)
{
	ssize_t slen, name_len;
	DEFAULT_RULES;

	CHECK_T_RULES;

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
	fr_type_t	cast = FR_TYPE_STRING;

	if (!fr_type_is_null(t_rules->cast)) cast = t_rules->cast;

	if (!fr_type_is_leaf(cast)) {
		fr_strerror_printf("%s is not a valid cast type",
				   fr_type_to_str(cast));
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	vpt = tmpl_alloc_null(ctx);
	if (fr_value_box_from_substr(vpt, &tmp,
				     cast, allow_enum ? t_rules->enumv : NULL,
				     &our_in, p_rules) < 0) {
		talloc_free(vpt);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}
	fr_value_box_mark_safe_for(&tmp, t_rules->literals_safe_for);

	tmpl_init(vpt, TMPL_TYPE_DATA, quote, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in), t_rules);

	fr_value_box_copy_shallow(NULL, tmpl_value(vpt), &tmp);

	*out = vpt;

	if (cast == tmpl_value_type(vpt)) vpt->rules.cast = FR_TYPE_NULL;

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
	fr_type_t	type;
	int		count;
	uint32_t	ipaddr;
	uint8_t		addr[4] = {}, prefix = 32;

	for (count = 0; count < 4; count++) {
		if (!fr_sbuff_out(NULL, &addr[count], &our_in)) FR_SBUFF_ERROR_RETURN(&our_in);

		if (count == 3) break;

		if (fr_sbuff_next_if_char(&our_in, '.')) continue;

		if (!fr_sbuff_is_char(&our_in, '/')) FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	If it has a trailing '/' then it's an IP prefix.
	 */
	if (fr_sbuff_next_if_char(&our_in, '/')) {
		if (fr_sbuff_out(NULL, &prefix, &our_in) < 0) {
			fr_strerror_const("IPv4 CIDR mask malformed");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		if (prefix > 32) {
			fr_strerror_const("IPv4 CIDR mask too high");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		type = FR_TYPE_IPV4_PREFIX;
	} else {
		type = FR_TYPE_IPV4_ADDR;
	}

	if (!tmpl_substr_terminal_check(&our_in, p_rules)) {
		fr_strerror_const("Unexpected text after IPv4 string or prefix");
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	MEM(vpt = tmpl_alloc(ctx, TMPL_TYPE_DATA, T_BARE_WORD, fr_sbuff_start(&our_in), fr_sbuff_used(&our_in)));
	fr_value_box_init(&vpt->data.literal, type, NULL, false);
	vpt->data.literal.vb_ip.af = AF_INET;
	vpt->data.literal.vb_ip.prefix = prefix;

	/*
	 *	Zero out lower bits
	 */
	ipaddr = (((uint32_t) addr[0]) << 24) | (((uint32_t) addr[1]) << 16) | (((uint32_t) addr[2]) << 8) | addr[3];
	if (prefix < 32) {
		ipaddr &= ~((uint32_t) 0) << (32 - prefix);
	}
	vpt->data.literal.vb_ip.addr.v4.s_addr = htonl(ipaddr);

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
				     NULL) < 0) {
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
	uint8_t			buff[6] = {};
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

/*
 *	::value
 *
 *	Treated as enum name.  Note that this check MUST be done after the test for IPv6, as
 *	"::1" is an allowed IPv6 address.
 *
 *	@todo - Mark this up as an enum name?  Or do we really care?  Maybe we want to allow
 *
 *		Service-Type == 'Framed-User'
 *
 *	or
 *
 *		Service-Type == "Framed-User'
 *
 *	as the second one allows for xlat expansions of enum names.
 *
 *	We probably do want to forbid the single-quoted form of enums,
 *	as that doesn't seem to make sense.
 *
 *	We also need to distinguish unresolved bare words as enums
 *	(with :: prefix) from unresolved attributes without an & prefix.
 */
static ssize_t tmpl_afrom_enum(TALLOC_CTX *ctx, tmpl_t **out, fr_sbuff_t *in,
			       fr_sbuff_parse_rules_t const *p_rules,
			       tmpl_rules_t const *t_rules)
{
	tmpl_t		*vpt;
	fr_sbuff_parse_error_t	sberr;
	fr_sbuff_t	our_in = FR_SBUFF(in);
	fr_sbuff_t	*enum_buff;

	FR_SBUFF_TALLOC_THREAD_LOCAL(&enum_buff, 1024, SIZE_MAX);

	/*
	 *	If there isn't a "::" prefix, then check for migration flags, and enum.
	 *
	 *	If we require an enum prefix, then the input can't be an enum, and we don't do any more
	 *	parsing.
	 *
	 *	Otherwise if there's no prefix and no enumv, we know this input can't be an enum name.
	 */
	if (!fr_sbuff_adv_past_str_literal(&our_in, "::")) {
		return 0;

	} else if (t_rules->enumv &&
		   ((t_rules->enumv->type == FR_TYPE_IPV6_ADDR) ||
		   ((t_rules->enumv->type == FR_TYPE_IPV6_PREFIX)))) {

		/*
		 *	We can't have enumerated names for IPv6 addresses.
		 *
		 *	@todo - allow them ONLY if the RHS string is a valid enum name.
		 */
		return 0;
	}

	/*
	 *	Need to store the value with the prefix, because the value box functions
	 *	expect it to be there...
	 */
	fr_sbuff_in_strcpy_literal(enum_buff, "::");

	vpt = tmpl_alloc_null(ctx);

	/*
	 *	If it doesn't match any other type of bareword, parse it as an enum name.
	 *
	 *	Note that we don't actually try to resolve the enum name.  The caller is responsible
	 *	for doing that.
	 */
	if (fr_dict_enum_name_from_substr(enum_buff, &sberr, &our_in, p_rules ? p_rules->terminals : NULL) < 0) {
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
			fr_strerror_const("Unexpected text after enum value.");
			break;
		}

		talloc_free(vpt);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	If there's a valid enum name, then we use it.  Otherwise we leave name resolution to run time.
	 */
	if (t_rules->enumv) {
		fr_dict_enum_value_t const *dv;

		dv = fr_dict_enum_by_name(t_rules->enumv, fr_sbuff_start(enum_buff), fr_sbuff_used(enum_buff));
		if (dv) {
			tmpl_init(vpt, TMPL_TYPE_DATA, T_BARE_WORD,
				  fr_sbuff_start(&our_in), fr_sbuff_used(&our_in), t_rules);
			if (unlikely(fr_value_box_copy(vpt, &vpt->data.literal, dv->value) < 0)) {
				talloc_free(vpt);
				return -1;
			}
			vpt->data.literal.enumv = t_rules->enumv;

			*out = vpt;
			FR_SBUFF_SET_RETURN(in, &our_in);
		}
	}

	/*
	 *	Either there's no enum, or the enum name didn't match one of the listed ones.  There's no
	 *	point in waiting for an enum which might be declared later.  That's not possible, so we fall
	 *	back to parsing the various data types.
	 */
	if (t_rules->at_runtime) return 0;

	tmpl_init(vpt, TMPL_TYPE_DATA_UNRESOLVED, T_BARE_WORD,
		  fr_sbuff_start(&our_in), fr_sbuff_used(&our_in), t_rules);
	MEM(vpt->data.unescaped = talloc_bstrndup(vpt, fr_sbuff_start(enum_buff), fr_sbuff_used(enum_buff)));
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
	DEFAULT_RULES;

	CHECK_T_RULES;

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
			slen = xlat_tokenize(vpt, &head, &our_in, p_rules, t_rules);
			if (slen <= 0) FR_SBUFF_ERROR_RETURN(&our_in);

			if (xlat_needs_resolving(head)) {
				UNRESOLVED_SET(&type);
				goto set_tmpl;

			} else if (fr_dlist_num_elements(&head->dlist) == 1) {
				xlat_exp_t *node = xlat_exp_head(head);
				tmpl_t *hoisted;

				if (node->type != XLAT_TMPL) goto set_tmpl;

				/*
				 *	We were asked to parse a tmpl.  But it turned out to be an xlat %{...}
				 *
				 *	If that xlat is identically a tmpl such as %{User-Name}, then we just
				 *	hoist the tmpl to this node.  Otherwise at run time, we will have an
				 *	extra bounce through the xlat code, for no real reason.
				 */
				hoisted = node->vpt;

				(void) talloc_steal(ctx, hoisted);
				talloc_free(vpt);
				vpt = hoisted;

			} else {
			set_tmpl:
				tmpl_init(vpt, type, quote, fr_sbuff_start(&our_in), slen, t_rules);
				vpt->data.xlat.ex = head;
			}

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
		 *	We're at runtime and have a data type.  Just parse it as that data type, without doing
		 *	endless "maybe it's this thing" attempts.
		 */
		if (t_rules->at_runtime && t_rules->enumv) {
			tmpl_rules_t my_t_rules = *t_rules;

			fr_assert(fr_type_is_leaf(t_rules->enumv->type));

			my_t_rules.cast = my_t_rules.enumv->type;

			return tmpl_afrom_value_substr(ctx, out, in, quote, &my_t_rules, true, p_rules);
		}

		/*
		 *	Prefer enum names to IPv6 addresses.
		 */
		if (t_rules->enumv && fr_sbuff_is_str_literal(&our_in, "::")) {
			slen = tmpl_afrom_enum(ctx, out, &our_in, p_rules, t_rules);
			if (slen > 0) goto done_bareword;
			fr_assert(!*out);
		}

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

		slen = tmpl_afrom_enum(ctx, out, &our_in, p_rules, t_rules);
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
		 *	We can't parse it as anything, that's an error.
		 *
		 *	But it may be an enumeration value for an
		 *	attribute which is loaded later.  In which
		 *	case we allow parsing the enumeration.
		 */
		if (!fr_sbuff_is_str_literal(&our_in, "::")) {
			/*
			 *	Return the error string from parsing the attribute!
			 */
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		/*
		 *	Attempt to resolve enumeration values
		 */
		vpt = tmpl_alloc_null(ctx);

		/*
		 *	If it doesn't match any other type of bareword, parse it as an enum name.
		 *
		 *	Note that we don't actually try to resolve the enum name.  The caller is responsible
		 *	for doing that.
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
				fr_strerror_const("Unexpected text after enum value.");
				break;
			}

			talloc_free(vpt);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		tmpl_init(vpt, TMPL_TYPE_DATA_UNRESOLVED, quote,
			  fr_sbuff_start(&our_in), fr_sbuff_used(&our_in), t_rules);
		vpt->data.unescaped = str;
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
		tmpl_init(vpt, TMPL_TYPE_DATA_UNRESOLVED, quote, fr_sbuff_start(&our_in), slen, t_rules);
		vpt->data.unescaped = str;
		break;

	case T_DOUBLE_QUOTED_STRING:
	{
		xlat_exp_head_t	*head = NULL;
		tmpl_type_t	type = TMPL_TYPE_XLAT;

		vpt = tmpl_alloc_null(ctx);

		slen = xlat_tokenize(vpt, &head, &our_in, p_rules, t_rules);
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

				tmpl_init(vpt, TMPL_TYPE_DATA_UNRESOLVED, quote,
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
		slen = xlat_tokenize_argv(vpt, &head, &our_in, NULL, p_rules, t_rules, true);
		if ((slen <= 0) || !head) {
			talloc_free(vpt);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		/*
		 *	Ensure any xlats produced are bootstrapped
		 *	so that their instance data will be created.
		 */
		if (xlat_finalize(head, t_rules->xlat.runtime_el) < 0) {
			fr_strerror_const("Failed to bootstrap xlat");
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
		tmpl_rules_t		arg_t_rules = *t_rules;

		arg_t_rules.literals_safe_for = FR_REGEX_SAFE_FOR;

		if (!fr_type_is_null(t_rules->cast)) {
			fr_strerror_const("Casts cannot be used with regular expressions");
			fr_sbuff_set_to_start(&our_in);	/* Point to the cast */
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		vpt = tmpl_alloc_null(ctx);

		slen = xlat_tokenize(vpt, &head, &our_in, p_rules, &arg_t_rules);
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
		fr_assert_msg(0, "Unknown quote type %i", quote);
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
	if (tmpl_is_data_unresolved(vpt) || tmpl_is_regex_uncompiled(vpt)) {
		if (unlikely(!(vpt->data.unescaped = talloc_bstrdup(vpt, in->data.unescaped)))) {
		error:
			talloc_free(vpt);
			return NULL;
		}
	}

	/*
	 *	Copy attribute references
	 */
	else if (tmpl_contains_attr(vpt)) {
		if (unlikely(tmpl_attr_copy(vpt, in) < 0)) goto error;

	/*
	 *	Copy flags for all regex flavours (and possibly recompile the regex)
	 */
	} else if (tmpl_contains_regex(vpt)) {
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

	/*
	 *	Copy the xlat component.
	 *
	 *	@todo - in general we can't copy an xlat, as the instances need resolving!
	 *
	 *	We add an assertion here because nothing allocates the head, and we need it.
	 */
	} else if (tmpl_contains_xlat(vpt)) {
		fr_assert(in->data.xlat.ex != NULL);

		vpt->data.xlat.ex = xlat_exp_head_alloc(vpt);
		if (!vpt->data.xlat.ex) goto error;

		if (unlikely(xlat_copy(vpt, vpt->data.xlat.ex, in->data.xlat.ex) < 0)) goto error;

	} else if (tmpl_is_data(vpt)) {
		if (unlikely(fr_value_box_copy(vpt, &vpt->data.literal, &in->data.literal) < 0)) goto error;

	} else {
		fr_assert(0);	/* copy of this type is unimplemented */
	}

	TMPL_VERIFY(vpt);

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

	if (fr_sbuff_next_if_char(&our_in, '(')) {
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
	case TMPL_TYPE_DATA_UNRESOLVED:
	case TMPL_TYPE_EXEC_UNRESOLVED:
	case TMPL_TYPE_XLAT_UNRESOLVED:
		break;

	case TMPL_TYPE_DATA:
		src_type = tmpl_value_type(vpt);
		goto check_types;

	case TMPL_TYPE_ATTR:
		{
			fr_dict_attr_t const *da = tmpl_attr_tail_da(vpt);

			/*
			 *	If the attribute has an enum, then the cast means "use the raw value, and not
			 *	the enum name".
			 */
			if (da->type == dst_type) {
				if (da->flags.has_value) goto done;
				return 0;
			}
			src_type = da->type;
		}

		/*
		 *	Suppress casts where they are duplicate, unless there's an enumv.  In which case the
		 *	cast means "don't print the enumv value, just print the raw data".
		 */
	check_types:
		if (src_type == dst_type) {
			/*
			 *	Cast with enumv means "use the raw value, and not the enum name".
			 */
			if (tmpl_rules_enumv(vpt)) {
				tmpl_rules_enumv(vpt) = NULL;
				goto done;
			}
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

/** @name Change a #tmpl_t type, usually by casting or resolving a reference
 *
 * #tmpl_cast_in_place can be used to convert #TMPL_TYPE_DATA_UNRESOLVED to a #TMPL_TYPE_DATA of a
 * specified #fr_type_t.
 *
 * #tmpl_attr_unknown_add converts a #TMPL_TYPE_ATTR with an unknown #fr_dict_attr_t to a
 * #TMPL_TYPE_ATTR with a known #fr_dict_attr_t, by adding the unknown #fr_dict_attr_t to the main
 * dictionary, and updating the ``tmpl_attr_tail_da`` pointer.
 * @{
 */

/** Determine the correct quoting after a cast
 *
 * @param[in] existing_quote	Exiting quotation type.
 * @param[in] type		Cast type.
 * @param[in] enumv		Enumeration values.
 * @param[in] unescaped		The unescaped value of an enumeration.
 * @param[in] unescaped_len	Length of unescaped.
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


/** Convert #tmpl_t of type #TMPL_TYPE_DATA_UNRESOLVED or #TMPL_TYPE_DATA to #TMPL_TYPE_DATA of type specified
 *
 * @note Conversion is done in place.
 * @note Irrespective of whether the #tmpl_t was #TMPL_TYPE_DATA_UNRESOLVED or #TMPL_TYPE_DATA,
 *	on successful cast it will be #TMPL_TYPE_DATA.
 *
 * @param[in,out] vpt	The template to modify. Must be of type #TMPL_TYPE_DATA_UNRESOLVED
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

	fr_assert(tmpl_is_data_unresolved(vpt) || tmpl_is_data(vpt));

	switch (vpt->type) {
	case TMPL_TYPE_DATA_UNRESOLVED:
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
						  NULL) < 0) return -1;
		}
		vpt->type = TMPL_TYPE_DATA;
		vpt->quote = tmpl_cast_quote(vpt->quote, type, enumv,
					     unescaped, talloc_array_length(unescaped) - 1);
		talloc_free(unescaped);
		fr_value_box_mark_safe_for(&vpt->data.literal, vpt->rules.literals_safe_for);

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
		 *	i.e. TMPL_TYPE_DATA_UNRESOLVED != TMPL_TYPE_DATA(FR_TYPE_STRING)
		 */
		if (fr_value_box_cast_in_place(vpt, &vpt->data.literal, type, NULL) < 0) return -1;
//		fr_value_box_mark_safe_for(&vpt->data.literal, vpt->rules.literals_safe_for); ??? is this necessary?

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
		if (tmpl_attr_tail_da(vpt)->type == type) {
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
	fr_dict_attr_t const	*da, *namespace;
	fr_dict_t const		*dict_def;

	fr_assert(tmpl_is_attr_unresolved(vpt));

	TMPL_VERIFY(vpt);

	dict_def = vpt->rules.attr.dict_def;
	if (!dict_def || tr_rules->force_dict_def) dict_def = tr_rules->dict_def;

	/*
	 *	First component is special because we may need
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
							 true,
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
		case TMPL_ATTR_TYPE_UNSPEC:
			continue;	/* Don't need to resolve */

		case TMPL_ATTR_TYPE_UNKNOWN:
			return -1;	/* Unknown attributes must be resolved first */

		default:
			break;
		}

		prev = tmpl_attr_list_prev(tmpl_attr(vpt), ar);

		/*
		 *	If the parent is a list AR, then use the default dictionary for the namespace
		 */
		namespace = (prev && dict_def && tmpl_attr_is_list_attr(prev)) ? fr_dict_root(dict_def) : ar->ar_unresolved_namespace;

		(void)fr_dict_attr_by_name_substr(NULL,
						  &da,
						  namespace,
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
			if (prev && (prev->ar_da->type == FR_TYPE_GROUP)) {
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
	static tmpl_res_rules_t const default_tr_rules = {};

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

		fr_assert(vpt->quote == T_BARE_WORD); /* 'User-Name' or "User-Name" is not allowed. */

		ret = tmpl_attr_resolve(vpt, tr_rules);
		if (ret < 0) return ret;

		if (dst_type == tmpl_attr_tail_da(vpt)->type) {
			vpt->rules.cast = FR_TYPE_NULL;
		}

	/*
	 *	Convert unresolved tmpls into enumvs, or failing that, string values.
	 *
	 *	Unresolved tmpls are by definition TMPL_TYPE_DATA.
	 */
	} else if (tmpl_is_data_unresolved(vpt)) {
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
		 *	We don't have an explicit output type.  Try to
		 *	interpret the data os the enumv data type, OR
		 *	if all else fails, it's a string.
		 */
		if (fr_type_is_null(dst_type)) {
			/*
			 *	Infer the cast from the enumv type.
			 */
			if (enumv) {
				dst_type = enumv->type;

			} else if (vpt->quote != T_BARE_WORD) {
				dst_type = FR_TYPE_STRING;	/* quoted strings are strings */

			} else if (strncmp(vpt->data.unescaped, "::", 2) != 0) {
				/*
				 *	The rest of the code should have errored out before this.
				 */
				fr_strerror_printf("Failed resolving data '%s' - it is not an attribute name or a quoted string", vpt->data.unescaped);
				return -1;

			} else {
				/*
				 *	It's a valid enum ::NAME which was added _after_ the dictionaries were
				 *	loaded.  That's fine.  fr_value_box_from_substr() will skip over the
				 *	"::", and parse the enum name.
				 */
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

	TMPL_VERIFY(vpt);

	return ret;
}

/** Reset the tmpl, leaving only the name in place
 *
 * After calling this function, the tmpl type will revert to TMPL_TYPE_DATA_UNRESOLVED
 * and only the name and quoting will be preserved.
 *
 * @param[in] vpt	to reset.
 */
void tmpl_unresolve(tmpl_t *vpt)
{
	tmpl_t	tmp = {
			.type = TMPL_TYPE_DATA_UNRESOLVED,
			.name = vpt->name,
			.len = vpt->len,
			.quote = vpt->quote
		};

	switch (vpt->type) {
	case TMPL_TYPE_UNINITIALISED:
	case TMPL_TYPE_MAX:
		fr_assert(0);
		break;

	case TMPL_TYPE_DATA_UNRESOLVED:
	case TMPL_TYPE_REGEX_UNCOMPILED:
		break;

	case TMPL_TYPE_DATA:
		fr_value_box_clear(&vpt->data.literal);
		break;

	/*
	 *	These types contain dynamically allocated
	 *	attribute and request references.
	 */
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

/** Add an unknown #fr_dict_attr_t specified by a #tmpl_t to the main dictionary
 *
 * @param vpt to add. ``tmpl_attr_tail_da`` pointer will be updated to point to the
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

	if (!tmpl_attr_tail_is_unknown(vpt)) return 1;	/* Ensure at least the leaf is unknown */

	while ((ar = tmpl_attr_list_next(tmpl_attr(vpt), ar))) {
		fr_dict_attr_t const	*unknown, *known;

		switch (ar->type) {
		case TMPL_ATTR_TYPE_NORMAL:		/* Skip */
		case TMPL_ATTR_TYPE_UNSPEC:
			continue;

		case TMPL_ATTR_TYPE_UNRESOLVED:		/* Shouldn't have been called */
			fr_strerror_const("Remaining attributes are unresolved");
			return -1;

		case TMPL_ATTR_TYPE_UNKNOWN:
			break;
		}

		unknown = ar->ar_unknown;
		known = fr_dict_attr_unknown_add(fr_dict_unconst(fr_dict_by_da(unknown)), unknown);
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
		if (!ar_is_raw(ar)) {
			fr_dict_attr_unknown_free(&ar->ar_da);
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
 *			specified by the tmpl_attr_tail_unresolved.
 * @param[in] vpt	specifying unresolved attribute to add.
 *			``tmpl_attr_tail_da`` pointer will be updated to
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
int tmpl_attr_tail_unresolved_add(fr_dict_t *dict_def, tmpl_t *vpt,
				  fr_type_t type, fr_dict_attr_flags_t const *flags)
{
	fr_dict_attr_t const *da;
	fr_dict_attr_flags_t our_flags = *flags;

	our_flags.name_only = true;

	if (!vpt) return -1;

	TMPL_VERIFY(vpt);

	if (!tmpl_is_attr_unresolved(vpt)) return 1;

	if (fr_dict_attr_add(dict_def,
			     fr_dict_root(fr_dict_internal()), tmpl_attr_tail_unresolved(vpt), 0, type, &our_flags) < 0) {
		return -1;
	}
	da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_def), tmpl_attr_tail_unresolved(vpt));
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
		FR_SBUFF_IN_TABLE_STR_RETURN(&our_out, tmpl_request_ref_print_table, rr->request, "<INVALID>");
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
 * @return
 *	- >0 the number of bytes written to the out buffer.
 *	- 0 invalid argument.
 *	- <0 the number of bytes we would have needed to complete the print.
 */
fr_slen_t tmpl_attr_print(fr_sbuff_t *out, tmpl_t const *vpt)
{
	tmpl_attr_t		*ar = NULL;
	fr_da_stack_t		stack;
	fr_sbuff_t		our_out = FR_SBUFF(out);
	fr_slen_t		slen;

	TMPL_VERIFY(vpt);

	/*
	 *	Only print things we can print...
	 */
	switch (vpt->type) {
	case TMPL_TYPE_ATTR_UNRESOLVED:
	case TMPL_TYPE_ATTR:
		break;

	default:
		fr_assert(0);
		return 0;
	}

	/*
	 *	Print request references
	 */
	slen = tmpl_request_ref_list_print(&our_out, &vpt->data.attribute.rr);
	if (slen > 0) FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');
	if (slen < 0) return slen;

	/*
	 *
	 *	If the leaf attribute is unknown and raw we
	 *	add the raw. prefix.
	 *
	 *	If the leaf attribute is unknown and not raw
	 *	we add the .unknown prefix.
	 *
	 */
	if (tmpl_attr_tail_is_raw(vpt)) FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "raw.");

	/*
	 *	Print attribute identifiers
	 */
	ar = NULL;
	while ((ar = tmpl_attr_list_next(tmpl_attr(vpt), ar))) {
		switch(ar->type) {
		case TMPL_ATTR_TYPE_UNSPEC:
			break;

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
			 *
			 * 	In addition skip printing "request." in most cases.
			 */
			if ((stack.da[depth] == request_attr_request) && tmpl_attr_list_next(tmpl_attr(vpt), ar) &&
			    (ar->filter.type == TMPL_ATTR_FILTER_TYPE_NONE)) continue;

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

		if (ar_filter_is_none(ar)) {
			/* do nothing */

		} else if (ar_filter_is_num(ar)) {
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

		} else if (ar_filter_is_cond(ar)) {
			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "[");
			(void) xlat_print(&our_out, ar->ar_cond, NULL);
			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "]");

		} else {
			fr_assert(0);
		}

		if (tmpl_attr_list_next(tmpl_attr(vpt), ar)) FR_SBUFF_IN_CHAR_RETURN(&our_out, '.');
	}
	FR_SBUFF_SET_RETURN(out, &our_out);
}

/** Print a #tmpl_t to a string
 *
 * This function should primarily be used for regenerating vpt->name when the contents
 * of the #tmpl_t is changed programmatically, or when the #tmpl_t is being serialized
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
 * @param[in] e_rules		Escaping rules used to print strings.
 * @return
 *	- >0 the number of bytes written to the out buffer.
 *	- 0 invalid argument.
 *	- <0 the number of bytes we would have needed to complete the print.
 */
fr_slen_t tmpl_print(fr_sbuff_t *out, tmpl_t const *vpt,
		     fr_sbuff_escape_rules_t const *e_rules)
{
	fr_sbuff_t	our_out = FR_SBUFF(out);

	TMPL_VERIFY(vpt);

	switch (vpt->type) {
	case TMPL_TYPE_ATTR_UNRESOLVED:
	case TMPL_TYPE_ATTR:
		FR_SBUFF_RETURN(tmpl_attr_print, &our_out, vpt);
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
	case TMPL_TYPE_MAX:
		fr_sbuff_terminate(out);
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

		fr_assert_fail("Can't print invalid tmpl type %s", tmpl_type_to_str(vpt->type));

		/*
		 *	Ensure we do something sane for non-debug builds
		 */
		fr_sbuff_terminate(out);
		return 0;
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
 * @return
 *	- >0 the number of bytes written to the out buffer.
 *	- 0 invalid argument.
 *	- <0 the number of bytes we would have needed to complete the print.
 */
fr_slen_t tmpl_print_quoted(fr_sbuff_t *out, tmpl_t const *vpt)
{
	fr_sbuff_t our_out = FR_SBUFF(out);

	char quote = fr_token_quote[vpt->quote];

	if (quote != '\0') FR_SBUFF_IN_CHAR_RETURN(&our_out, quote);
	FR_SBUFF_RETURN(tmpl_print, &our_out, vpt,
			fr_value_escape_by_quote[vpt->quote]);
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
 * @note If the attribute reference is is invalid, causes the server to exit.
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

	fr_assert(tmpl_is_attr_unresolved(vpt) || tmpl_is_attr(vpt));

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
				tmpl_attr_debug(stderr, vpt);
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: "
						     "TMPL_TYPE_ATTR known attribute \"%s\" "
						     "occurred after unknown attribute %s "
						     "in attr ref list",
						     file, line,
						     ar->da->name,
						     ar->unknown.da->name);
			}
			if (seen_unresolved) {
				tmpl_attr_debug(stderr, vpt);
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

			if (ar->ar_parent->type != FR_TYPE_GROUP) {
				fr_fatal_assert_msg(ar->ar_parent == ar->ar_da->parent,
						    "CONSISTENCY CHECK FAILED %s[%u]: attr ref has wrong parent: "
						    "Expected %s, got %s",
						    file, line,
						    ar->ar_da->parent->name,
						    ar->ar_parent->name);

			}
			break;

		case TMPL_ATTR_TYPE_UNSPEC:
			if (seen_unknown) {
				tmpl_attr_debug(stderr, vpt);
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: "
						     "TMPL_TYPE_ATTR unspecified attribute "
						     "occurred after unknown attribute %s "
						     "in attr ref list",
						     file, line,
						     ar->unknown.da->name);
			}
			if (seen_unresolved) {
				tmpl_attr_debug(stderr, vpt);
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: "
						     "TMPL_TYPE_ATTR unspecified attribute "
						     "occurred after unresolved attribute \"%s\""
						     "in attr ref list",
						     file, line,
						     ar->ar_unresolved);
			}
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
				tmpl_attr_debug(stderr, vpt);
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
	case TMPL_TYPE_DATA_UNRESOLVED:
		if (!vpt->data.unescaped) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_DATA_UNRESOLVED "
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
			tmpl_attr_debug(stderr, vpt);
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

		if (tmpl_attr_tail_is_unspecified(vpt)) {
			fr_assert(vpt->rules.cast == FR_TYPE_NULL);
			break;
		}

		if (tmpl_attr_tail_is_unknown(vpt)) {
			if (tmpl_attr_tail_da(vpt) != tmpl_attr_tail_unknown(vpt)) {
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
			dict = fr_dict_by_da(tmpl_attr_tail_da(vpt));
			if (!dict) {
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
						     "attribute \"%s\" (%s) not rooted in a dictionary",
						     file, line, tmpl_attr_tail_da(vpt)->name,
						     fr_type_to_str(tmpl_attr_tail_da(vpt)->type));
			}

			da = tmpl_attr_tail_da(vpt);
			if (!tmpl_attr_tail_is_raw(vpt) && (da != tmpl_attr_tail_da(vpt))) {
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: TMPL_TYPE_ATTR "
						     "dictionary pointer %p \"%s\" (%s) "
						     "and global dictionary pointer %p \"%s\" (%s) differ",
						     file, line,
						     tmpl_attr_tail_da(vpt), tmpl_attr_tail_da(vpt)->name,
						     fr_type_to_str(tmpl_attr_tail_da(vpt)->type),
						     da, da->name,
						     fr_type_to_str(da->type));
			}

			tmpl_attr_verify(file, line, vpt);
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

static const bool array_terminal[UINT8_MAX + 1] = {
	[ ']' ] = true,
};

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
 * @return
 *	- > 0, amount of parsed string to skip, to get to the next token
 *	- <=0, -offset in 'start' where the parse error was located
 */
ssize_t tmpl_preparse(char const **out, size_t *outlen, char const *in, size_t inlen,
		      fr_token_t *type)
{
	char const *p = in, *end = in + inlen;
	char quote;
	char close;
	int depth;
	bool triple;

	*type = T_INVALID;

	while (isspace((uint8_t) *p) && (p < end)) p++;
	if (p >= end) return p - in;

	switch (*p) {
		/*
		 *	Allow bare xlat's
		 */
	case '%':
		if (p[1] != '{') {
			char const *q;

			q = p + 1;

			/*
			 *	Function syntax: %foo(...)
			 */
			while ((q < end) && (isalnum((int) *q) || (*q == '.') || (*q == '_') || (*q == '-'))) {
				q++;
			}

			if (*q != '(') {
				p++;
				fr_strerror_const("Invalid character after '%'");
			return_p:
				return -(p - in);
			}

			/*
			 *	Return the whole %foo(...) string.
			 */
			*out = p;
			if (*type == T_INVALID) *type = T_BARE_WORD;
			close = ')';

			p = q + 1;
			depth = 1;
			goto loop;
		}

		/*
		 *	For now, %{...} is treated as a double-quoted
		 *	string.  Once we clean other things up, the
		 *	xlats will be treated as strongly typed values
		 *	/ lists on their own.
		 */
		if (*type == T_INVALID) *type = T_BARE_WORD;
		depth = 0;
		close = '}';

		/*
		 *	Xlat's are quoted by %{...} / %(...) nesting, not by
		 *	escapes, so we need to do special escaping.
		 */
		*out = p;
	loop:
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

			/*
			 *	Allow (...) and {...}
			 */
			if ((*p == '{') || (*p == '(')) {
				p++;
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
		goto bare_word;

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
		 *	more rigorous check.
		 */
	skip_string:
		if ((inlen > 3) && (p[0] == quote) && (p[1] == quote)) {
			triple = true;
			p += 2;
		} else {
			triple = false;
		}
		*out = p;

		while (*p) {
			if (p >= end) goto unterminated;

			/*
			 *	End of string.  Tell the caller the
			 *	length of the data inside of the
			 *	string, and return the number of
			 *	characters to skip.
			 */
			if (*p == quote) {
				if (!triple) {
					*outlen = p - (*out);
					p++;
					return p - in;

				}

				if (((end - p) >= 3) && (p[1] == quote) && (p[2] == quote)) {
					*outlen = p - (*out);
					p += 3;
					return p - in;
				}

				p++;
				continue;
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
		unterminated:
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
		quote = '['; /* foo[1] is OK */

	skip_word:
		*type = T_BARE_WORD;
		depth = 0;

		/*
		 *	Allow *most* things.  But stop on spaces and special characters.
		 */
		while (*p) {
			if (isspace((uint8_t) *p)) {
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
			if (*p == '[') {
				if (quote != '[') {
					return_P("Invalid location for '['");
				}

				p++;

				/*
				 *	Allow [#], etc.  But stop
				 *	immediately after the ']'.
				 */
				if ((*p == '#') || (*p == '*') || (*p == 'n')) {
					p++;

				} else {
					ssize_t slen;
					bool eol = false;

					slen = fr_skip_condition(p, end, array_terminal, &eol);
					if (slen < 0) {
						p += -slen;
						return -(p - in);
					}
					p += slen;
					continue;
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
	case TMPL_TYPE_XLAT:	/* synchronous xlats use unlang_interpret_synchronous() */
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
	/* don't set ->parent=parent, that is only for switching subrequest, etc. */

	if (!tmpl_is_attr(vpt)) return;

	da = tmpl_attr_tail_da(vpt);

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
		out->attr.namespace = da;
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
		out->attr.namespace = ref;
	}

	/*
	 *	Otherwise the reference is swapping FROM a protocol
	 *	dictionary TO the internal dictionary, and TO an
	 *	internal group.  We fall back to leaving well enough
	 *	alone, and leave things as-is.  This allows internal
	 *	grouping attributes to appear anywhere.
	 */
}

static void tmpl_attr_rules_debug(tmpl_attr_rules_t const *at_rules)
{
	FR_FAULT_LOG("\tdict_def          = %s", at_rules->dict_def ? fr_dict_root(at_rules->dict_def)->name : "");
	FR_FAULT_LOG("\tnamespace         = %s", at_rules->namespace ? at_rules->namespace->name : "");

	FR_FAULT_LOG("\tlist_def          = %s", at_rules->list_def ? at_rules->list_def->name : "");

	FR_FAULT_LOG("\tallow_unknown     = %u", at_rules->allow_unknown);
	FR_FAULT_LOG("\tallow_unresolved  = %u", at_rules->allow_unresolved);
	FR_FAULT_LOG("\tallow_wildcard    = %u", at_rules->allow_wildcard);
	FR_FAULT_LOG("\tallow_foreign     = %u", at_rules->allow_foreign);
	FR_FAULT_LOG("\tdisallow_filters  = %u", at_rules->disallow_filters);
}


void tmpl_rules_debug(tmpl_rules_t const *rules)
{
	FR_FAULT_LOG("\tparent     = %p", rules->parent);
	FR_FAULT_LOG("    attr {");
	tmpl_attr_rules_debug(&rules->attr);
	FR_FAULT_LOG("    }");
	FR_FAULT_LOG("\tenumv      = %s", rules->enumv ? rules->enumv->name : "");
	FR_FAULT_LOG("\tcast       = %s", fr_type_to_str(rules->cast));
	FR_FAULT_LOG("\tat_runtime = %u", rules->at_runtime);
	FR_FAULT_LOG("\tliterals_safe_for = %lx", rules->literals_safe_for);

}
