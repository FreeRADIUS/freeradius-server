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
 * @file xlat_tokenize.c
 * @brief String expansion ("translation").  Tokenizes xlat expansion strings.
 *
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2017-2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/regex.h>
#include <freeradius-devel/unlang/xlat_priv.h>

#include <ctype.h>

#undef XLAT_DEBUG
#undef XLAT_HEXDUMP
#ifdef DEBUG_XLAT
#  define XLAT_DEBUG(_fmt, ...)			DEBUG3("%s[%i] "_fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#  define XLAT_HEXDUMP(_data, _len, _fmt, ...)	HEXDUMP3(_data, _len, "%s[%i] "_fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#  define XLAT_DEBUG(...)
#  define XLAT_HEXDUMP(...)
#endif

/** These rules apply to literals and function arguments inside of an expansion
 *
 */
static fr_sbuff_unescape_rules_t const xlat_unescape = {
	.name = "xlat",
	.chr = '\\',
	.subs = {
		['a'] = '\a',
		['b'] = '\b',
		['e'] = '\\',
		['n'] = '\n',
		['r'] = '\r',
		['t'] = '\t',
		['v'] = '\v',
		['\\'] = '\\',
		['%'] = '%',	/* Expansion begin */
		['}'] = '}'	/* Expansion end */
	},
	.do_hex = true,
	.do_oct = true
};

/** These rules apply to literals and function arguments inside of an expansion
 *
 */
static fr_sbuff_escape_rules_t const xlat_escape = {
	.name = "xlat",
	.chr = '\\',
	.subs = {
		['\a'] = 'a',
		['\b'] = 'b',
		['\n'] = 'n',
		['\r'] = 'r',
		['\t'] = 't',
		['\v'] = 'v',
		['\\'] = '\\',
		['%'] = '%',	/* Expansion begin */
		['}'] = '}'	/* Expansion end */
	},
	.esc = {
		SBUFF_CHAR_UNPRINTABLES_LOW,
		SBUFF_CHAR_UNPRINTABLES_EXTENDED
	},
	.do_utf8 = true,
	.do_oct = true
};

/** Parse rules for literals inside of an expansion
 *
 * These rules are used to parse literals as arguments to functions and
 * on the RHS of alternations.
 *
 * The caller sets the literal parse rules for outside of expansions when they
 * call xlat_tokenize.
 */
static fr_sbuff_parse_rules_t const xlat_expansion_rules = {
	.escapes = &xlat_unescape,
	.terminals = &FR_SBUFF_TERM("}")	/* These get merged with other literal terminals */
};

static fr_sbuff_parse_rules_t const xlat_multi_arg_rules = {
	.escapes = &xlat_unescape,
	.terminals = &FR_SBUFF_TERM(")")	/* These get merged with other literal terminals */
};

/** Allocate an xlat node with no name, and no type set
 *
 * @param[in] ctx	to allocate node in.
 * @return A new xlat node.
 */
static inline CC_HINT(always_inline) xlat_exp_t *xlat_exp_alloc_null(TALLOC_CTX *ctx)
{
	xlat_exp_t *node;

	MEM(node = talloc_zero(ctx, xlat_exp_t));

	return node;
}

/** Allocate an xlat node
 *
 * @param[in] ctx	to allocate node in.
 * @param[in] type	of the node.
 * @param[in] in	original input string.
 * @param[in] inlen	the length of the original input string.
 * @return A new xlat node.
 */
static inline CC_HINT(always_inline) xlat_exp_t *xlat_exp_alloc(TALLOC_CTX *ctx, xlat_type_t type,
								char const *in, size_t inlen)
{
	xlat_exp_t *node;

	node = xlat_exp_alloc_null(ctx);
	node->type = type;
	if (in) node->fmt = talloc_bstrndup(node, in, inlen);

	return node;
}

/** Set the type of an xlat node
 *
 * @param[in] node	to set type for.
 * @param[in] type	to set.
 */
static inline CC_HINT(always_inline) void xlat_exp_set_type(xlat_exp_t *node, xlat_type_t type)
{
	node->type = type;
}

#if 0
/** Set the format string for an xlat node
 *
 * @param[in] node	to set fmt for.
 * @param[in] fmt	talloced buffer to set as the fmt string.
 */
static inline CC_HINT(always_inline) void xlat_exp_set_name_buffer(xlat_exp_t *node, char const *fmt)
{
	if (node->fmt) talloc_const_free(node->fmt);
	node->fmt = talloc_bstrdup(node, fmt);
}
#endif

/** Set the format string for an xlat node
 *
 * @param[in] node	to set fmt for.
 * @param[in] fmt	talloced buffer to set as the fmt string.
 */
static inline CC_HINT(always_inline) void xlat_exp_set_name_buffer_shallow(xlat_exp_t *node, char const *fmt)
{
	if (node->fmt) talloc_const_free(node->fmt);
	node->fmt = fmt;
}

/** Merge flags from child to parent
 *
 * For pass2, if either the parent or child is marked up for pass2, then the parent
 * is marked up for pass2.
 *
 * For needs_async, if both the parent and the child are needs_async, the parent is
 * needs_async.
 */
static inline CC_HINT(always_inline) void xlat_flags_merge(xlat_flags_t *parent, xlat_flags_t const *child)
{
	parent->needs_async |= child->needs_async;
	parent->needs_resolving |= child->needs_resolving;
}

/** Free a linked list of xlat nodes
 *
 * @param[in,out] head	to free.  Will be set to NULL
 */
void xlat_exp_free(xlat_exp_t **head)
{
	xlat_exp_t *to_free = *head, *next;

	while (to_free) {
		next = to_free->next;
		talloc_free(to_free);
		to_free = next;
	};
	*head = NULL;
}

static int xlat_tokenize_expansion(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *in,
				   tmpl_rules_t const *t_rules);

static int xlat_tokenize_literal(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags,
				 fr_sbuff_t *in, bool brace,
				 fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules);

static inline int xlat_tokenize_alternation(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *in,
					    tmpl_rules_t const *t_rules)
{
	xlat_exp_t	*node;

	XLAT_DEBUG("ALTERNATE <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	node = xlat_exp_alloc_null(ctx);
	xlat_exp_set_type(node, XLAT_ALTERNATE);
	if (xlat_tokenize_expansion(node, &node->child, &node->flags, in, t_rules) < 0) {
	error:
		*head = NULL;
		talloc_free(node);
		return -1;
	}

	if (!fr_sbuff_adv_past_str_literal(in, ":-")) {
		fr_strerror_const("Expected ':-' after first expansion");
		goto error;
	}

	/*
	 *	Allow the RHS to be empty as a special case.
	 */
	if (fr_sbuff_next_if_char(in, '}')) {
		node->alternate = xlat_exp_alloc(node, XLAT_LITERAL, "", 0);
		xlat_flags_merge(&node->flags, &node->child->flags);
		*head = node;
		return 0;
	}

	/*
	 *	Parse the alternate expansion.
	 */
	if (xlat_tokenize_literal(node, &node->alternate, &node->flags, in,
				  true, &xlat_expansion_rules, t_rules) < 0) goto error;

	if (!node->alternate) {
		talloc_free(node);
		fr_strerror_const("Empty expansion is invalid");
		goto error;
	}

	if (!fr_sbuff_next_if_char(in, '}')) {
		fr_strerror_const("Missing closing brace");
		goto error;
	}

	xlat_flags_merge(flags, &node->flags);
	*head = node;

	return 0;
}

#ifdef HAVE_REGEX
/** Parse an xlat reference
 *
 * Allows access to a subcapture groups
 * @verbatim %{<num>} @endverbatim
 *
 */
static inline int xlat_tokenize_regex(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *in)
{
	uint8_t			num;
	xlat_exp_t		*node;
	fr_sbuff_parse_error_t	err;
	fr_sbuff_marker_t	m_s;

	XLAT_DEBUG("REGEX <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	fr_sbuff_marker(&m_s, in);

	fr_sbuff_out(&err, &num, in);
	if (err != FR_SBUFF_PARSE_OK) {
	invalid_ref:
		fr_strerror_printf("Invalid regex reference.  Must be in range 0-%u", REQUEST_MAX_REGEX);
		fr_sbuff_marker_release(&m_s);
		return -1;
	}

	if (num > REQUEST_MAX_REGEX) {
		fr_sbuff_set(in, &m_s);
		goto invalid_ref;
	}

	if (!fr_sbuff_is_char(in, '}')) {
		if (!fr_sbuff_remaining(in)) {
			fr_strerror_const("Missing closing brace");
			fr_sbuff_marker_release(&m_s);
			return -1;
		}
		fr_sbuff_set(in, &m_s);
		fr_sbuff_marker_release(&m_s);
		return 1;
	}

	node = xlat_exp_alloc(ctx, XLAT_REGEX, fr_sbuff_current(&m_s), fr_sbuff_behind(&m_s));
	node->regex_index = num;
	node->flags.needs_async = false;

	fr_sbuff_marker_release(&m_s);
	fr_sbuff_next(in);	/* Skip '}' */

	xlat_flags_merge(flags, &node->flags);
	*head = node;

	return 0;
}
#endif

static inline int xlat_validate_function_mono(xlat_exp_t *node)
{
	fr_assert(node->type == XLAT_FUNC);

	if (node->call.func->args && node->call.func->args->required &&
	    (node->child->type == XLAT_LITERAL) && (talloc_array_length(node->child->fmt) == 1)) {
		fr_strerror_const("Missing required input");
		return -1;
	}

	return 0;
}

/** Parse an xlat function and its child argument
 *
 * Parses a function call string in the format
 * @verbatim %{<func>:<argument>} @endverbatim
 *
 * @return
 *	- 0 if the string was parsed into a function.
 *	- <0 on parse error.
 */
static inline int xlat_tokenize_function_mono(TALLOC_CTX *ctx, xlat_exp_t **head,
					      xlat_flags_t *flags, fr_sbuff_t *in,
					      tmpl_rules_t const *rules)
{
	xlat_exp_t		*node;
	xlat_t			*func;
	fr_sbuff_marker_t	m_s;

	/*
	 *	Special characters, spaces, etc. cannot be
	 *	module names.
	 */
	static bool const	func_chars[UINT8_MAX + 1] = {
					SBUFF_CHAR_CLASS_ALPHA_NUM,
					['.'] = true, ['-'] = true, ['_'] = true,
				};

	XLAT_DEBUG("FUNC <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	/*
	 *	%{module:args}
	 */
	fr_sbuff_marker(&m_s, in);
	fr_sbuff_adv_past_allowed(in, SIZE_MAX, func_chars, NULL);

	if (!fr_sbuff_is_char(in, ':')) {
		fr_strerror_const("Can't find function/argument separator");
	bad_function:
		*head = NULL;
		fr_sbuff_set(in, &m_s);		/* backtrack */
		fr_sbuff_marker_release(&m_s);
		return -1;
	}

	func = xlat_func_find(fr_sbuff_current(&m_s), fr_sbuff_behind(&m_s));

	/*
	 *	Allocate a node to hold the function
	 */
	node = xlat_exp_alloc(ctx, XLAT_FUNC, fr_sbuff_current(&m_s), fr_sbuff_behind(&m_s));
	if (!func) {
		if (!rules || !rules->allow_unresolved) {
			fr_strerror_const("Unresolved expansion functions are not allowed here");
			goto bad_function;
		}
		xlat_exp_set_type(node, XLAT_FUNC_UNRESOLVED);
		node->flags.needs_resolving = true;	/* Needs resolution during pass2 */
	} else {
		if (func->input_type == XLAT_INPUT_ARGS) {
			fr_strerror_const("Function takes defined arguments and should "
					  "be called using %(func:args) syntax");
		error:
			head = NULL;
			talloc_free(node);
			return -1;
		}
		node->call.func = func;
		node->flags.needs_async = func->needs_async;
	}

	fr_sbuff_next(in);			/* Skip the ':' */
	XLAT_DEBUG("FUNC-ARGS <-- %s ... %pV",
		   node->fmt, fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	fr_sbuff_marker_release(&m_s);

	/*
	 *	Now parse the child nodes that form the
	 *	function's arguments.
	 */
	if (xlat_tokenize_literal(node, &node->child, &node->flags, in, true, &xlat_expansion_rules, rules) < 0) {
		goto error;
	}

	/*
	 *	Check there's input if it's needed
	 */
	if ((node->type == XLAT_FUNC) && (xlat_validate_function_mono(node) < 0)) goto error;

	if (!fr_sbuff_next_if_char(in, '}')) {
		fr_strerror_const("Missing closing brace");
		goto error;
	}

	xlat_flags_merge(flags, &node->flags);
	*head = node;

	return 0;
}

static inline int xlat_validate_function_args(xlat_exp_t *node)
{
	xlat_arg_parser_t const *arg_p;
	xlat_exp_t		*child = node->child;

	fr_assert(node->type == XLAT_FUNC);

	for (arg_p = node->call.func->args; arg_p->type != FR_TYPE_NULL; arg_p++) {
		if (!arg_p->required) break;

		if (!child) {
			fr_strerror_printf("Missing required arg %u",
					   (unsigned int)(arg_p - node->call.func->args) + 1);
			return -1;
		}

		child = child->next;
	}

	return 0;
}

/** Parse an xlat function and its child arguments
 *
 * Parses a function call string in the format
 * @verbatim %(<func>:<arguments>) @endverbatim
 *
 * @return
 *	- 0 if the string was parsed into a function.
 *	- <0 on parse error.
 */
static inline int xlat_tokenize_function_args(TALLOC_CTX *ctx, xlat_exp_t **head,
					      xlat_flags_t *flags, fr_sbuff_t *in,
					      tmpl_rules_t const *rules)
{
	xlat_exp_t		*node;
	xlat_t			*func;
	fr_sbuff_marker_t	m_s;

	/*
	 *	Special characters, spaces, etc. cannot be
	 *	module names.
	 */
	static bool const	func_chars[UINT8_MAX + 1] = {
					SBUFF_CHAR_CLASS_ALPHA_NUM,
					['.'] = true, ['-'] = true, ['_'] = true,
				};

	XLAT_DEBUG("FUNC <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	/*
	 *	%{module:args}
	 */
	fr_sbuff_marker(&m_s, in);
	fr_sbuff_adv_past_allowed(in, SIZE_MAX, func_chars, NULL);

	if (!fr_sbuff_is_char(in, ':')) {
		fr_strerror_const("Can't find function/argument separator");
	bad_function:
		*head = NULL;
		fr_sbuff_set(in, &m_s);		/* backtrack */
		fr_sbuff_marker_release(&m_s);
		return -1;
	}

	func = xlat_func_find(fr_sbuff_current(&m_s), fr_sbuff_behind(&m_s));

	/*
	 *	Allocate a node to hold the function
	 */
	node = xlat_exp_alloc(ctx, XLAT_FUNC, fr_sbuff_current(&m_s), fr_sbuff_behind(&m_s));
	if (!func) {
		if (!rules || !rules->allow_unresolved) {
			fr_strerror_const("Unresolved expansion functions are not allowed here");
			goto bad_function;
		}
		xlat_exp_set_type(node, XLAT_FUNC_UNRESOLVED);
		node->flags.needs_resolving = true;	/* Needs resolution during pass2 */
	} else {
		if (func && (func->input_type != XLAT_INPUT_ARGS)) {
			fr_strerror_const("Function should be called using the syntax %{func:arg}");
		error:
			talloc_free(node);
			return -1;
		}
		node->call.func = func;
		node->flags.needs_async = func->needs_async;
	}

	fr_sbuff_next(in);			/* Skip the ':' */
	XLAT_DEBUG("FUNC-ARGS <-- %s ... %pV",
		   node->fmt, fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	fr_sbuff_marker_release(&m_s);

	/*
	 *	Now parse the child nodes that form the
	 *	function's arguments.
	 */
	if (xlat_tokenize_argv(node, &node->child, &node->flags, in, &xlat_multi_arg_rules, rules) < 0) {
		goto error;
	}

	/*
	 *	Check we have all the required arguments
	 */
	if ((node->type == XLAT_FUNC) && (xlat_validate_function_args(node) < 0)) goto error;

	if (!fr_sbuff_next_if_char(in, ')')) {
		fr_strerror_const("Missing closing brace");
		goto error;
	}

	xlat_flags_merge(flags, &node->flags);
	*head = node;

	return 0;
}

static int xlat_resolve_virtual_attribute(xlat_exp_t *node, tmpl_t *vpt)
{
	xlat_t	*func;

	if (tmpl_is_attr(vpt)) {
		func = xlat_func_find(tmpl_da(vpt)->name, -1);
	} else {
		func = xlat_func_find(tmpl_attr_unresolved(vpt), -1);
	}
	if (func) {
		xlat_exp_set_type(node, XLAT_VIRTUAL);
		xlat_exp_set_name_buffer_shallow(node, vpt->name);

		XLAT_DEBUG("VIRTUAL <-- %pV",
			   fr_box_strvalue_len(vpt->name, vpt->len));
		node->call.func = func;
		node->attr = vpt;	/* Store for context */
		node->flags.needs_async = func->needs_async;

		return 0;
	}

	return -1;
}

/** Parse an attribute ref or a virtual attribute
 *
 */
static inline int xlat_tokenize_attribute(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *in,
					  fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	ssize_t			slen;
	tmpl_attr_error_t	err;
	tmpl_t			*vpt = NULL;
	xlat_exp_t		*node;

	fr_sbuff_marker_t	m_s;

	XLAT_DEBUG("ATTRIBUTE <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	/*
	 *	We need a local copy as we always allow unknowns.
	 *	This is because not all attribute references
	 *	reference real attributes in the dictionaries,
	 *	and instead are "virtual" attributes like
	 *	Foreach-Variable-N.
	 */
	tmpl_rules_t		 our_t_rules;

	if (t_rules) {
		memcpy(&our_t_rules, t_rules, sizeof(our_t_rules));
	} else {
		memset(&our_t_rules, 0, sizeof(our_t_rules));
	}

	our_t_rules.allow_unresolved = true;		/* So we can check for virtual attributes later */
  	our_t_rules.prefix = TMPL_ATTR_REF_PREFIX_NO;	/* Must be NO to stop %{&User-Name} */

	fr_sbuff_marker(&m_s, in);

	MEM(node = xlat_exp_alloc_null(ctx));
	slen = tmpl_afrom_attr_substr(node, &err, &vpt, in, p_rules, &our_t_rules);
	if (slen <= 0) {
		fr_sbuff_advance(in, slen * -1);

		/*
		 *	If the parse error occurred before the ':'
		 *	then the error is changed to 'Unknown module',
		 *	as it was more likely to be a bad module name,
		 *	than a request qualifier.
		 */
		if (err == TMPL_ATTR_ERROR_MISSING_TERMINATOR) fr_sbuff_set(in, &m_s);
	error:
		*head = NULL;
		fr_sbuff_marker_release(&m_s);
		talloc_free(node);
		return -1;
	}

	/*
	 *	Deal with virtual attributes.
	 */
	if (tmpl_is_attr(vpt) && tmpl_da(vpt)->flags.virtual) {
		if (tmpl_attr_count(vpt) > 1) {
			fr_strerror_const("Virtual attributes cannot be nested.");
			goto error;
		}

		/*
		 *	This allows xlat functions to be
		 *	used to provide values for virtual
		 *	attributes.  If we fail to resolve
		 *	a virtual attribute to a function
		 *	it's likely going to be handled as
		 *	a virtual attribute by
		 *	xlat_eval_pair_virtual
		 *
		 *	We really need a virtual attribute
		 *	registry so we can check if the
		 *	attribute is valid.
		 */
		if (xlat_resolve_virtual_attribute(node, vpt) < 0) goto do_attr;
	/*
	 *	Deal with unresolved attributes.
	 */
	} else if (tmpl_is_attr_unresolved(vpt)) {
		/*
		 *	Could it be a virtual attribute?
		 */
		if ((tmpl_attr_count(vpt) == 1) && (xlat_resolve_virtual_attribute(node, vpt) == 0)) goto done;

		if (!t_rules || !t_rules->allow_unresolved) {
			talloc_free(vpt);

			fr_strerror_const("Unresolved attributes not allowed in expansions here");
			fr_sbuff_set(in, &m_s);		/* Error at the start of the attribute */
			goto error;
		}

		/*
		 *	We don't know it's virtual but
		 *	we don't know it's not either...
		 *
		 *	Mark it up as virtual-unresolved
		 *	and let the resolution code figure
		 *	this out in a later pass.
		 */
		xlat_exp_set_type(node, XLAT_VIRTUAL_UNRESOLVED);
		xlat_exp_set_name_buffer_shallow(node, vpt->name);
		node->attr = vpt;
		node->flags.needs_resolving = true;
	/*
	 *	Deal with normal attribute (or list)
	 */
	} else {
	do_attr:
		xlat_exp_set_type(node, XLAT_ATTRIBUTE);
		xlat_exp_set_name_buffer_shallow(node, vpt->name);
		node->attr = vpt;
	}

done:
	if (!fr_sbuff_next_if_char(in, '}')) {
		fr_strerror_const("Missing closing brace");
		goto error;
	}

	xlat_flags_merge(flags, &node->flags);
	*head = node;
	fr_sbuff_marker_release(&m_s);
	return 0;
}

static int xlat_tokenize_expansion(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *in,
				   tmpl_rules_t const *t_rules)
{
	size_t			len;
	fr_sbuff_marker_t	s_m;
	char			hint;
	int			ret;
	fr_sbuff_term_t		hint_tokens = FR_SBUFF_TERMS(
					L(" "),		/* First special token is a ' ' - Likely a syntax error */
					L(":"),		/* First special token is a ':' i.e. '%{func:' */
					L("["),		/* First special token is a '[' i.e. '%{attr[<idx>]}' */
					L("}")		/* First special token is a '}' i.e. '%{<attrref>}' */
				);

	fr_sbuff_parse_rules_t	attr_p_rules = {
					.escapes = &xlat_unescape,
					.terminals = &FR_SBUFF_TERM("}")
				};

	XLAT_DEBUG("EXPANSION <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	/*
	 *	%{...}:-bar}
	 */
	if (fr_sbuff_adv_past_str_literal(in, "%{")) {
		return xlat_tokenize_alternation(ctx, head, flags, in, t_rules);
	}

	/*
	 *	:-bar}
	 */
	if (fr_sbuff_is_str_literal(in, ":-")) {
		fr_strerror_const("First item in alternation cannot be empty");
		return -2;
	}

#ifdef HAVE_REGEX
	/*
	 *	Handle regex's %{<num>} specially.
	 */
	if (fr_sbuff_is_digit(in)) {
		ret = xlat_tokenize_regex(ctx, head, flags, in);
		if (ret <= 0) return ret;
	}
#endif /* HAVE_REGEX */

	/*
	 *	%{Attr-Name}
	 *	%{Attr-Name[#]}
	 *	%{request.Attr-Name}
	 *	%{mod:foo}
	 */

	/*
	 *	Check for empty expressions %{} %{: %{[
	 */
	fr_sbuff_marker(&s_m, in);
	len = fr_sbuff_adv_until(in, SIZE_MAX, &hint_tokens, '\0');

	/*
	 *      This means the end of a string not containing any of the other
	 *	tokens was reached.
	 *
	 *	e.g. '%{myfirstxlat'
	 */
	if (!fr_sbuff_remaining(in)) {
		fr_strerror_const("Missing closing brace");
		fr_sbuff_marker_release(&s_m);
		return -1;
	}

	hint = *fr_sbuff_current(in);

	XLAT_DEBUG("EXPANSION HINT TOKEN '%c'", hint);
	if (len == 0) {
		switch (hint) {
		case '}':
			fr_strerror_const("Empty expression is invalid");
			return -1;

		case ':':
			fr_strerror_const("Missing expansion function");
			return -1;

		case '[':
			fr_strerror_const("Missing attribute name");
			return -1;

		default:
			break;
		}
	}

	/*
	 *      Hint token is a ':' it's an xlat function %{<func>:<args}
	 */
	switch (hint) {
	case ':':
	{
		fr_sbuff_set(in, &s_m);		/* backtrack */
		fr_sbuff_marker_release(&s_m);

		ret = xlat_tokenize_function_mono(ctx, head, flags, in, t_rules);
		if (ret <= 0) return ret;
	}
		break;

	/*
	 *	Hint token is a:
	 *	- '[' - Which is an attribute index, so it must be an attribute.
	 *      - '}' - The end of the expansion, which means it was a bareword.
	 */
	case '.':
	case '}':
	case '[':
		fr_sbuff_set(in, &s_m);		/* backtrack */
		fr_sbuff_marker_release(&s_m);

		if (xlat_tokenize_attribute(ctx, head, flags, in, &attr_p_rules, t_rules) < 0) return -1;
		break;

	/*
	 *	Hint token was whitespace
	 *
	 *	e.g. '%{my '
	 */
	default:
		/*
		 *	Box print is so we get \t \n etc..
		 */
		fr_strerror_printf("Invalid char '%pV' in expression", fr_box_strvalue_len(fr_sbuff_current(in), 1));
		return -1;
	}

	return 0;
}

/** Parse an xlat literal i.e. a non-expansion or non-function
 *
 * When this function is being used outside of an xlat expansion, i.e. on a string
 * which contains one or more xlat expansions, it uses the terminal grammar and
 * escaping rules of that string type.
 *
 * Which this function is being used inside of an xlat expansion, it uses xlat specific
 * terminal grammar and escaping rules.
 *
 * This allows us to be smart about processing quotes within the expansions themselves.
 *
 * @param[in] ctx		to allocate nodes in.  Note: All nodes will be
 *				allocated in the same ctx.  This is to allow
 *				manipulation by xlat instantiation functions
 *				later.
 * @param[out] head		Where to write the first child node.
 * @param[out] flags		where we store flags information for the parent.
 * @param[in] in		sbuff to parse.
 * @param[in] brace		true if we're inside a braced expansion, else false.
 * @param[in] p_rules		that control parsing.
 * @param[in] t_rules		that control attribute reference and xlat function parsing.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int xlat_tokenize_literal(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags,
				 fr_sbuff_t *in, bool brace,
				 fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	xlat_exp_t			*node = NULL;
	size_t				len;
	fr_sbuff_term_t			expansions = FR_SBUFF_TERMS(
						L("%("),
						L("%C"),
						L("%D"),
						L("%G"),
						L("%H"),
						L("%I"),
						L("%M"),
						L("%S"),
						L("%T"),
						L("%Y"),
						L("%c"),
						L("%d"),
						L("%e"),
						L("%l"),
						L("%m"),
						L("%n"),
						L("%s"),
						L("%t"),
						L("%v"),
						L("%{")
					);
	fr_sbuff_term_t			*tokens;
	fr_cursor_t			cursor;
	fr_sbuff_unescape_rules_t const	*escapes;

	*head = NULL;

	fr_cursor_init(&cursor, head);
	escapes = p_rules ? p_rules->escapes : NULL;
	tokens = p_rules && p_rules->terminals ?
			fr_sbuff_terminals_amerge(NULL, p_rules->terminals, &expansions) : &expansions;

	for (;;) {
		char *str;

		/*
		 *	pre-allocate the node so we don't have to steal it later.
		 */
		node = xlat_exp_alloc_null(ctx);

		/*
		 *	Find the next token
		 */
		len = fr_sbuff_out_aunescape_until(node, &str, in, SIZE_MAX, tokens, escapes);

		/*
		 *	It's a literal, create a literal node...
		 */
		if (len > 0) {
			xlat_exp_set_type(node, XLAT_LITERAL);
			xlat_exp_set_name_buffer_shallow(node, str);

			XLAT_DEBUG("LITERAL (%s)<-- %pV",
				   escapes ? escapes->name : "(none)",
				   fr_box_strvalue_len(str, talloc_array_length(str) - 1));
			XLAT_HEXDUMP((uint8_t const *)str, talloc_array_length(str) - 1, " LITERAL ");
			node->flags.needs_async = false; /* literals are always true */
			fr_cursor_insert(&cursor, node);
			node = NULL;
		}

		if (fr_sbuff_adv_past_str_literal(in, "%{")) {
			if (len == 0) TALLOC_FREE(node); /* Free the empty node */

			if (xlat_tokenize_expansion(ctx, &node, flags, in, t_rules) < 0) {
			error:
				talloc_free(node);
				fr_cursor_head(&cursor);
				fr_cursor_free_list(&cursor);

				/*
				 *	Free our temporary array of terminals
				 */
				if (tokens != &expansions) talloc_free(tokens);
				return -1;
			}
			fr_cursor_insert(&cursor, node);
			node = NULL;
			continue;
		}

		/*
		 *	xlat function call with discreet arguments
		 */
		if (fr_sbuff_adv_past_str_literal(in, "%(")) {
			if (len == 0) TALLOC_FREE(node); /* Free the empty node */

			if (xlat_tokenize_function_args(ctx, &node, flags, in, t_rules) < 0) goto error;
			fr_cursor_insert(&cursor, node);
			node = NULL;
			continue;
		}

		/*
		 *	%[a-z] - A one letter expansion
		 */
		if (fr_sbuff_next_if_char(in, '%') && fr_sbuff_is_alpha(in)) {
			XLAT_DEBUG("ONE-LETTER <-- %pV",
				   fr_box_strvalue_len(str, talloc_array_length(str) - 1));

			if (len == 0) {
				talloc_free_children(node);	/* re-use empty nodes */
			} else {
				node = xlat_exp_alloc_null(ctx);
			}

			fr_sbuff_out_abstrncpy(node, &str, in, 1);
			xlat_exp_set_type(node, XLAT_ONE_LETTER);
			xlat_exp_set_name_buffer_shallow(node, str);

			node->flags.needs_async = false; /* literals are always true */
			xlat_flags_merge(flags, &node->flags);
			fr_cursor_insert(&cursor, node);
			node = NULL;
			continue;
		}

		/*
		 *	We were told to look for a brace, but we ran off of
		 *	the end of the string before we found one.
		 */
		if (brace) {
			if (len == 0) TALLOC_FREE(node); /* Free the empty node */

			if (!fr_sbuff_is_char(in, '}')) {
				fr_strerror_const("Missing closing brace");
				goto error;
			}
		/*
		 *	We're parsing the string *containing* the xlat
		 *	expansions.
		 */
		} else {
			/*	If we have an empty node, finish building it and
			 *	emit it.
			 *
			 *	We're about to return, and it's a useful
			 *	indication to the caller that this wasn't a parse
			 *	error but just an empty string.
			 */
			if (len == 0) {
				/*
				 *	This isn't the only node in the sequence
				 *	don't emit an empty trailing literal.
				 */
				if (*head) {
					talloc_free(node);
					break;
				}

				xlat_exp_set_type(node, XLAT_LITERAL);
				xlat_exp_set_name_buffer_shallow(node, str);

				XLAT_DEBUG("LITERAL <-- (empty)");
				node->flags.needs_async = false; /* literals are always true */
				xlat_flags_merge(flags, &node->flags);
				fr_cursor_insert(&cursor, node);
			}
		}
		break;
	}

	/*
	 *	Free our temporary array of terminals
	 */
	if (tokens != &expansions) talloc_free(tokens);

	return 0;
}

static fr_table_num_sorted_t const xlat_quote_table[] = {
	{ L("\""),	T_DOUBLE_QUOTED_STRING	},	/* Don't re-order, backslash throws off ordering */
	{ L("'"),	T_SINGLE_QUOTED_STRING	},
	{ L("`"),	T_BACK_QUOTED_STRING	}
};
static size_t xlat_quote_table_len = NUM_ELEMENTS(xlat_quote_table);

void xlat_debug(xlat_exp_t const *node)
{
	fr_assert(node != NULL);
	while (node) {
		switch (node->type) {
		case XLAT_LITERAL:
			INFO("literal --> %s", node->fmt);
			break;

		case XLAT_GROUP:
			INFO("child --> %s", node->fmt);
			INFO("{");
			xlat_debug(node->child);
			INFO("}");
			break;

		case XLAT_ONE_LETTER:
			INFO("percent --> %c", node->fmt[0]);
			break;

		case XLAT_ATTRIBUTE:
			fr_assert(tmpl_da(node->attr) != NULL);
			INFO("attribute --> %s", tmpl_da(node->attr)->name);
			fr_assert(node->child == NULL);
			if (tmpl_num(node->attr) != NUM_ANY) {
				INFO("{");
				INFO("ref  %d", tmpl_request(node->attr));
				INFO("list %d", tmpl_list(node->attr));
				if (tmpl_num(node->attr) != NUM_ANY) {
					if (tmpl_num(node->attr) == NUM_COUNT) {
						INFO("[#]");
					} else if (tmpl_num(node->attr) == NUM_ALL) {
						INFO("[*]");
					} else {
						INFO("[%d]", tmpl_num(node->attr));
					}
				}
				INFO("}");
			}
			break;

		case XLAT_VIRTUAL:
			fr_assert(node->fmt != NULL);
			INFO("virtual --> %s", node->fmt);
			break;

		case XLAT_VIRTUAL_UNRESOLVED:
			fr_assert(node->fmt != NULL);
			INFO("virtual-unresolved --> %s", node->fmt);
			break;

		case XLAT_FUNC:
			fr_assert(node->call.func != NULL);
			INFO("xlat --> %s", node->call.func->name);
			if (node->child) {
				INFO("{");
				xlat_debug(node->child);
				INFO("}");
			}
			break;

		case XLAT_FUNC_UNRESOLVED:
			INFO("xlat-unresolved --> %s", node->fmt);
			if (node->child) {
				INFO("{");
				xlat_debug(node->child);
				INFO("}");
			}
			break;

#ifdef HAVE_REGEX
		case XLAT_REGEX:
			INFO("regex-var --> %d", node->regex_index);
			break;
#endif

		case XLAT_ALTERNATE:
			DEBUG("XLAT-IF {");
			xlat_debug(node->child);
			DEBUG("}");
			DEBUG("XLAT-ELSE {");
			xlat_debug(node->alternate);
			DEBUG("}");
			break;

		case XLAT_INVALID:
			DEBUG("XLAT-INVALID");
			break;
		}
		node = node->next;
	}
}

/** Reconstitute an xlat expression from its constituent nodes
 *
 * @param[in] out	Where to write the output string.
 * @param[in] head	First node to print.
 * @param[in] e_rules	Specifying how to escape literal values.
 */
ssize_t xlat_print(fr_sbuff_t *out, xlat_exp_t const *head, fr_sbuff_escape_rules_t const *e_rules)
{
	ssize_t			slen;
	size_t			at_in = fr_sbuff_used_total(out);
	xlat_exp_t const	*node = head;

	if (!node) return 0;

	while (node) {
		switch (node->type) {
		case XLAT_GROUP:
			if (node->quote != T_BARE_WORD) FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->quote]);
			xlat_print(out, node->child, fr_value_escape_by_quote[node->quote]);
			if (node->quote != T_BARE_WORD) FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->quote]);
			if (node->next) FR_SBUFF_IN_CHAR_RETURN(out, ' ');	/* Add ' ' between args */
			goto next;

		case XLAT_LITERAL:
			FR_SBUFF_IN_ESCAPE_BUFFER_RETURN(out, node->fmt, e_rules);
			goto next;

		case XLAT_ONE_LETTER:
			FR_SBUFF_IN_CHAR_RETURN(out, '%', node->fmt[0]);
			goto next;

		default:
			break;
		}

		FR_SBUFF_IN_STRCPY_LITERAL_RETURN(out, "%{");
		switch (node->type) {
		case XLAT_ATTRIBUTE:
			slen = tmpl_attr_print(out, node->attr, TMPL_ATTR_REF_PREFIX_NO);
			if (slen < 0) {
			error:
				return slen;
			}
			break;
#ifdef HAVE_REGEX
		case XLAT_REGEX:
			FR_SBUFF_IN_SPRINTF_RETURN(out, "%i", node->regex_index);
			break;
#endif
		case XLAT_VIRTUAL:
			FR_SBUFF_IN_BSTRCPY_BUFFER_RETURN(out, node->call.func->name);
			break;

		case XLAT_VIRTUAL_UNRESOLVED:
			FR_SBUFF_IN_BSTRCPY_BUFFER_RETURN(out, node->fmt);
			break;

		case XLAT_FUNC:
			FR_SBUFF_IN_BSTRCPY_BUFFER_RETURN(out, node->call.func->name);
			FR_SBUFF_IN_CHAR_RETURN(out, ':');

			if (node->child) {
				slen = xlat_print(out, node->child, &xlat_escape);
				if (slen < 0) goto error;
			}
			break;

		case XLAT_FUNC_UNRESOLVED:
			FR_SBUFF_IN_BSTRCPY_BUFFER_RETURN(out, node->fmt);
			FR_SBUFF_IN_CHAR_RETURN(out, ':');

			if (node->child) {
				slen = xlat_print(out, node->child, &xlat_escape);
				if (slen < 0) goto error;
			}
			break;

		case XLAT_ALTERNATE:
			slen = xlat_print(out, node->child, &xlat_escape);
			if (slen < 0) goto error;

			FR_SBUFF_IN_STRCPY_LITERAL_RETURN(out, ":-");
			slen = xlat_print(out, node->alternate, &xlat_escape);
			if (slen < 0) goto error;
			break;

			fr_assert_fail(NULL);
			break;

		case XLAT_INVALID:
		case XLAT_LITERAL:
		case XLAT_ONE_LETTER:
		case XLAT_GROUP:
			fr_assert_fail(NULL);
			break;
		}
		FR_SBUFF_IN_CHAR_RETURN(out, '}');
	next:
		node = node->next;
	}

	return fr_sbuff_used_total(out) - at_in;
}

/** Tokenize an xlat expansion at runtime
 *
 * This is used for runtime parsing of xlat expansions, such as those we receive from datastores
 * like LDAP or SQL.
 *
 * @param[in] ctx	to allocate dynamic buffers in.
 * @param[out] head	the head of the xlat list / tree structure.
 * @param[in,out] flags	that control evaluation and parsing.
 * @param[in] in	the format string to expand.
 * @param[in] p_rules	from the encompassing grammar.
 * @param[in] t_rules	controlling how attribute references are parsed.
 * @return
 *	- >0 on success.
 *	- 0 and *head == NULL - Parse failure on first char.
 *	- 0 and *head != NULL - Zero length expansion
 *	- <0 the negative offset of the parse failure.
 */
ssize_t xlat_tokenize_ephemeral(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags,
			        fr_sbuff_t *in,
			        fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	fr_sbuff_t	our_in = FR_SBUFF_NO_ADVANCE(in);
	xlat_flags_t	tmp_flags = {};

	if (!flags) flags = &tmp_flags;

	*head = NULL;

	fr_strerror_clear();	/* Clear error buffer */
	if (xlat_tokenize_literal(ctx, head, flags,
				  &our_in, false, p_rules, t_rules) < 0) return -fr_sbuff_used(&our_in);

	/*
	 *	Zero length expansion, return a zero length node.
	 */
	if (fr_sbuff_used(&our_in) == 0) *head = xlat_exp_alloc(ctx, XLAT_LITERAL, "", 0);

	/*
	 *	Create ephemeral instance data for the xlat
	 */
	if (xlat_instantiate_ephemeral(*head) < 0) {
		fr_strerror_const("Failed performing ephemeral instantiation for xlat");
		TALLOC_FREE(*head);
		return 0;
	}

	return fr_sbuff_set(in, &our_in);
}

/** Tokenize an xlat expansion into a series of XLAT_TYPE_CHILD arguments
 *
 * @param[in] ctx		to allocate nodes in.  Note: All nodes will be
 *				allocated in the same ctx.  This is to allow
 *				manipulation by xlat instantiation functions
 *				later.
 * @param[out] head		the head of the xlat list / tree structure.
 * @param[out] flags		Populated with parameters that control xlat
 *				evaluation and multi-pass parsing.
 * @param[in] in		the format string to expand.
 * @param[in] p_rules		controlling how to parse the string outside of
 *				any expansions.
 * @param[in] t_rules		controlling how attribute references are parsed.
 * @return
 *	- <=0 on error.
 *	- >0  on success which is the number of characters parsed.
 */
ssize_t xlat_tokenize_argv(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *in,
			   fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	fr_sbuff_t			our_in = FR_SBUFF_NO_ADVANCE(in);
	ssize_t				slen;
	fr_cursor_t			cursor;
	fr_sbuff_marker_t		m;
	fr_sbuff_parse_rules_t const	*our_p_rules;	/* Bareword parse rules */
	fr_sbuff_parse_rules_t		tmp_p_rules;
	xlat_flags_t			tmp_flags = {};

	if (!flags) flags = &tmp_flags;

	*head = NULL;

	if (p_rules && p_rules->terminals) {
		tmp_p_rules = (fr_sbuff_parse_rules_t){	/* Stack allocated due to CL scope */
			.terminals = fr_sbuff_terminals_amerge(NULL, p_rules->terminals,
							       tmpl_parse_rules_bareword_quoted.terminals),
			.escapes = (p_rules->escapes ? p_rules->escapes : tmpl_parse_rules_bareword_quoted.escapes)
		};
		our_p_rules = &tmp_p_rules;
	} else {
		our_p_rules = &tmpl_parse_rules_bareword_quoted;
	}

	/*
	 *	skip spaces at the beginning as we
	 *	don't want them to become a whitespace
	 *	literal.
	 */
	fr_sbuff_adv_past_whitespace(in, SIZE_MAX, NULL);
	fr_sbuff_marker(&m, &our_in);

	fr_cursor_init(&cursor, head);
	while (fr_sbuff_extend(&our_in)) {
		xlat_exp_t	*node = NULL;
		fr_token_t	quote;
		char		*fmt;
		size_t		len;

		fr_sbuff_set(&m, &our_in);	/* Record start of argument */

		fr_sbuff_out_by_longest_prefix(&slen, &quote, xlat_quote_table, &our_in, T_BARE_WORD);

		/*
		 *	Alloc a new node to hold the child nodes
		 *	that make up the argument.
		 */
		node = xlat_exp_alloc_null(ctx);
		xlat_exp_set_type(node, XLAT_GROUP);
		node->quote = quote;

		switch (quote) {
		/*
		 *	Barewords --may-contain=%{expansions}
		 */
		case T_BARE_WORD:
			if (xlat_tokenize_literal(node, &node->child, &node->flags, &our_in,
						  false, our_p_rules, t_rules) < 0) {
			error:
				if (our_p_rules != &tmpl_parse_rules_bareword_quoted) {
					talloc_const_free(our_p_rules->terminals);
				}
				talloc_free(node);
				fr_cursor_head(&cursor);
				fr_cursor_free_list(&cursor);

				return -fr_sbuff_used(&our_in);	/* error */
			}
			xlat_flags_merge(flags, &node->flags);
			break;

		/*
		 *	"Double quoted strings may contain %{expansions}"
		 */
		case T_DOUBLE_QUOTED_STRING:
			if (xlat_tokenize_literal(node, &node->child, &node->flags, &our_in,
						  false, &tmpl_parse_rules_double_quoted, t_rules) < 0) goto error;
			xlat_flags_merge(flags, &node->flags);
			break;

		/*
		 *	'Single quoted strings get parsed as literals'
		 */
		case T_SINGLE_QUOTED_STRING:
		{
			char		*str;

			node->child = xlat_exp_alloc_null(node);
			xlat_exp_set_type(node->child, XLAT_LITERAL);
			node->flags.needs_async = false;	/* Literals are always needs_async */

			slen = fr_sbuff_out_aunescape_until(node->child, &str, &our_in, SIZE_MAX,
							    tmpl_parse_rules_single_quoted.terminals,
							    tmpl_parse_rules_single_quoted.escapes);
			if (slen < 0) goto error;
			xlat_exp_set_name_buffer_shallow(node->child, str);
			xlat_flags_merge(flags, &node->flags);
		}
			break;

		/*
		 *	`back quoted strings aren't supported`
		 */
		case T_BACK_QUOTED_STRING:
			fr_strerror_const("Unexpected `...` string");
			goto error;

		default:
			fr_assert(0);
			break;
		}

		if ((quote != T_BARE_WORD) && !fr_sbuff_next_if_char(&our_in, fr_token_quote[quote])) { /* Quoting */
			fr_strerror_const("Unterminated string");
			fr_sbuff_set(&our_in, &m);
			goto error;
		}

		fmt = talloc_bstrndup(node, fr_sbuff_current(&m), fr_sbuff_behind(&m));
		xlat_exp_set_name_buffer_shallow(node, fmt);

		xlat_flags_merge(flags, &node->flags);
		fr_cursor_insert(&cursor, node);
		node = NULL;

		/*
		 *	If we're not and the end of the string
		 *	and there's no whitespace between tokens
		 *	then error.
		 */
		fr_sbuff_set(&m, &our_in);
		len = fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);

		/*
		 *	Check to see if we have a terminal char
		 */
		if ((p_rules && p_rules->terminals) && fr_sbuff_is_terminal(&our_in, p_rules->terminals)) break;

		/*
		 *	Otherwise, if we can extend, and found
		 *	no additional whitespace, it means two
		 *	arguments were smushed together.
		 */
		if (fr_sbuff_extend(&our_in) && (len == 0)) {
			fr_strerror_const("Unexpected text after argument");
			goto error;
		}
	}

	if (our_p_rules != &tmpl_parse_rules_bareword_quoted) talloc_const_free(our_p_rules->terminals);

	return fr_sbuff_set(in, &our_in);
}

/** Tokenize an xlat expansion
 *
 * @param[in] ctx	to allocate dynamic buffers in.
 * @param[out] head	the head of the xlat list / tree structure.
 * @param[in,out] flags	that control evaluation and parsing.
 * @param[in] in	the format string to expand.
 * @param[in] p_rules	controlling how the string containing the xlat
 *			expansions should be parsed.
 * @param[in] t_rules	controlling how attribute references are parsed.
 * @return
 *	- >0 on success.
 *	- 0 and *head == NULL - Parse failure on first char.
 *	- 0 and *head != NULL - Zero length expansion
 *	- < 0 the negative offset of the parse failure.
 */
ssize_t xlat_tokenize(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *in,
		      fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	fr_sbuff_t	our_in = FR_SBUFF_NO_ADVANCE(in);
	xlat_flags_t	tmp_flags = {};

	if (!flags) flags = &tmp_flags;
	*head = NULL;

	fr_strerror_clear();	/* Clear error buffer */

	if (xlat_tokenize_literal(ctx, head, flags,
				  &our_in, false, p_rules, t_rules) < 0) return -fr_sbuff_used(&our_in);

	/*
	 *	Add nodes that need to be bootstrapped to
	 *	the registry.
	 */
	if (xlat_bootstrap(*head) < 0) {
		TALLOC_FREE(*head);
		return 0;
	}

	return fr_sbuff_set(in, &our_in);
}

/** Check to see if the expansion consists entirely of literal elements
 *
 * @param[in] head	to check.
 * @return
 *	- true if expansion contains only literal elements.
 *	- false if expansion contains expandable elements.
 */
bool xlat_is_literal(xlat_exp_t const *head)
{
	xlat_exp_t const *node;

	for (node = head;
	     node;
	     node = node->next) {
		if (node->type != XLAT_LITERAL) return false;
	}

	return true;
}

/** Convert an xlat node to an unescaped literal string and free the original node
 *
 * @param[in] ctx	to allocate the new string in.
 * @param[out] str	a duplicate of the node's fmt string.
 * @param[in,out] head	to convert.
 * @return
 *	- true	the tree consists of a single literal node which was converted.
 *      - false the tree was more complex than a single literal, op was a noop.
 */
bool xlat_to_literal(TALLOC_CTX *ctx, char **str, xlat_exp_t **head)
{
	xlat_exp_t 		*node;
	fr_sbuff_t		out;
	fr_sbuff_uctx_talloc_t	tctx;
	size_t			len = 0;

	if (!*head) return false;

	/*
	 *	Instantiation functions may chop
	 *	up the node list into multiple
	 *	literals, so we need to walk the
	 *	list until we find a non-literal.
	 */
	for (node = *head; node; node = node->next) {
		if (!xlat_is_literal(node)) return false;
		len += talloc_array_length(node->fmt) - 1;
	}

	fr_sbuff_init_talloc(ctx, &out, &tctx, len, SIZE_MAX);
	for (node = *head; node; node = node->next) fr_sbuff_in_bstrcpy_buffer(&out, node->fmt);

	*str = fr_sbuff_buff(&out);	/* No need to trim, should be the correct length */

	return true;
}

/** Walk over an xlat tree recursively, resolving any unresolved functions or references
 *
 * @param[in,out] head		of xlat tree to resolve.
 * @param[in,out] flags		that control evaluation and parsing.
 * @param[in] allow_unresolved	Don't error out if we can't resolve a function or attribute.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_resolve(xlat_exp_t **head, xlat_flags_t *flags, bool allow_unresolved)
{
	xlat_exp_t	*node;
	xlat_flags_t	our_flags;

	if (!flags->needs_resolving) return 0;			/* Already done */

	our_flags = *flags;
	our_flags.needs_resolving = false;			/* We flip this if not all resolutions are successful */

	for (node = *head; node; node = node->next) {
		if (!node->flags.needs_resolving) continue;	/* This node and non of its children need resolving */

		switch (node->type) {
		case XLAT_GROUP:
			return xlat_resolve(&node->child, &node->flags, allow_unresolved);

		/*
		 *	Alternate expansion a || b
		 *
		 *	Do resolution for a OR b
		 */
		case XLAT_ALTERNATE:
		{
			xlat_flags_t	child_flags = node->flags, alt_flags = node->flags;

			if ((xlat_resolve(&node->child, &child_flags, allow_unresolved) < 0) ||
			    (xlat_resolve(&node->alternate, &alt_flags, allow_unresolved) < 0)) return -1;

			xlat_flags_merge(&child_flags, &alt_flags);
			node->flags = child_flags;
		}
			break;

		/*
		 *	A resolved function with unresolved args
		 */
		case XLAT_FUNC:
			if (xlat_resolve(&node->child, &node->flags, allow_unresolved) < 0) return -1;
			xlat_flags_merge(&our_flags, &node->flags);
			break;

		/*
		 *	An unresolved function.
		 */
		case XLAT_FUNC_UNRESOLVED:
		{
			xlat_t		*func;
			xlat_flags_t	child_flags = node->flags;


			/*
			 *	We can't tell if it's just the function
			 *	that needs resolving or its children too.
			 */
			if (xlat_resolve(&node->child, &child_flags, allow_unresolved) < 0) return -1;

			/*
			 *	Try and find the function
			 */
			func = xlat_func_find(node->fmt, talloc_array_length(node->fmt) - 1);
			if (!func) {
				/*
				 *	FIXME - Produce proper error with marker
				 */
				if (!allow_unresolved) {
					fr_strerror_printf("Failed resolving function \"%pV\"",
							   fr_box_strvalue_buffer(node->fmt));
					return -1;
				}
				our_flags.needs_resolving = true;	/* Still unresolved nodes */
				break;
			}

			xlat_exp_set_type(node, XLAT_FUNC);
			node->call.func = func;

			/*
			 *	Check input arguments of our freshly
			 *	resolved function
			 */
			switch (node->call.func->input_type) {
			case XLAT_INPUT_UNPROCESSED:
				break;

			case XLAT_INPUT_MONO:
				if (xlat_validate_function_mono(node) < 0) return -1;
				break;

			case XLAT_INPUT_ARGS:
				if (xlat_validate_function_args(node) < 0) return -1;
				break;
			}

			/*
			 *	Reset node flags
			 */
			node->flags = (xlat_flags_t){ .needs_async = func->needs_async };

			/*
			 *	Merge the result of trying to resolve
			 *	the child nodes.
			 */
			xlat_flags_merge(&node->flags, &child_flags);

			/*
			 *	Add the freshly resolved function
			 *	to the bootstrap tree.
			 */
			if (xlat_bootstrap_func(node) < 0) return -1;
		}
			break;
		/*
		 *	This covers unresolved attributes as well as
		 *	unresolved functions.
		 */
		case XLAT_VIRTUAL_UNRESOLVED:
		{
			xlat_t *func;
			char const *name;

			if (node->attr->type == TMPL_TYPE_ATTR_UNRESOLVED) {
				name = tmpl_attr_unresolved(node->attr);
			} else {
				fr_assert(node->attr->type == TMPL_TYPE_ATTR);
				name = tmpl_da(node->attr)->name;
			}

			func = xlat_func_find(name, -1);
			if (func) {
				xlat_exp_set_type(node, XLAT_VIRTUAL);
				node->attr = node->attr;	/* Shift to the right location */
				node->call.func = func;

				/*
				 *	Reset node flags
				 */
				node->flags = (xlat_flags_t){ .needs_async = func->needs_async };
				break;
			}

			/*
			 *	Try and resolve (in-place) as an attribute
			 */
			if ((tmpl_resolve(node->attr) < 0) || (node->attr->type != TMPL_TYPE_ATTR)) {
				/*
				 *	FIXME - Produce proper error with marker
				 */
				if (!allow_unresolved) {
				error_unresolved:
					fr_strerror_printf_push("Failed resolving attribute in expansion %%{%s}",
								node->fmt);
					return -1;
				}
				our_flags.needs_resolving = true;	/* Still unresolved nodes */
				break;
			}

			/*
			 *	Just need to flip the type as the tmpl
			 *	should already have been fixed up
			 */
			xlat_exp_set_type(node, XLAT_ATTRIBUTE);

			/*
			 *	Reset node flags
			 */
			node->flags = (xlat_flags_t){ };
		}
			break;

		case XLAT_ATTRIBUTE:
			if (!allow_unresolved) goto error_unresolved;
			break;

		default:
			fr_assert(0);	/* Should not have been marked as unresolved */
			return -1;
		}

		xlat_flags_merge(&our_flags, &node->flags);
	}

	*flags = our_flags;	/* Update parent flags - not merge, replacement */

	return 0;
}


/** Try to convert an xlat to a tmpl for efficiency
 *
 * @param ctx to allocate new tmpl_t in.
 * @param node to convert.
 * @return
 *	- NULL if unable to convert (not necessarily error).
 *	- A new #tmpl_t.
 */
tmpl_t *xlat_to_tmpl_attr(TALLOC_CTX *ctx, xlat_exp_t *node)
{
	tmpl_t *vpt;

	if (node->next || (node->type != XLAT_ATTRIBUTE) || !tmpl_is_attr(node->attr)) return NULL;

	/*
	 *   Concat means something completely different as an attribute reference
	 *   Count isn't implemented.
	 */
	if ((tmpl_num(node->attr) == NUM_COUNT) || (tmpl_num(node->attr) == NUM_ALL)) return NULL;

	vpt = tmpl_alloc(ctx, TMPL_TYPE_ATTR, T_BARE_WORD, node->fmt, talloc_array_length(node->fmt) - 1);
	if (!vpt) return NULL;

	tmpl_attr_copy(vpt, node->attr);

	TMPL_VERIFY(vpt);

	return vpt;
}

/** Convert attr tmpl to an xlat for &attr[*]
 *
 * @param[in] ctx	to allocate new expansion in.
 * @param[out] head	Where to write new xlat node.
 * @param[out] flags	Where to write xlat resolution flags.
 * @param[in,out] vpt_p	to convert to xlat expansion.
 *			Will be set to NULL on completion
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_from_tmpl_attr(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, tmpl_t **vpt_p)
{
	xlat_exp_t	*node;
	xlat_t		*func;
	tmpl_t		*vpt = *vpt_p;

	if (!tmpl_is_attr(vpt) && !tmpl_is_attr_unresolved(vpt)) return 0;

	/*
	 *	If it's a single attribute reference
	 *	see if it's actually a virtual attribute.
	 */
	if (tmpl_attr_count(vpt) == 1) {
		if (tmpl_is_attr(vpt) && tmpl_da(vpt)->flags.virtual) {
			func = xlat_func_find(tmpl_da(vpt)->name, -1);
			if (!func) {
			unresolved:
				node = xlat_exp_alloc(ctx, XLAT_VIRTUAL_UNRESOLVED, vpt->name, vpt->len);

				/*
				 *	FIXME - Need a tmpl_copy function to
				 *	the assignment of the tmpl to the new
				 *	xlat expression
				 */
				node->attr = talloc_move(node, vpt_p);
				node->flags = (xlat_flags_t) { .needs_resolving = true };
				*head = node;
				xlat_flags_merge(flags, &node->flags);
				return 0;
			}

		virtual:
			node = xlat_exp_alloc(ctx, XLAT_VIRTUAL, vpt->name, vpt->len);
			node->attr = talloc_move(node, vpt_p);
			node->call.func = func;
			*head = node;
			node->flags = (xlat_flags_t) { .needs_async = func->needs_async };
		} else if (tmpl_is_attr_unresolved(vpt)) {
			func = xlat_func_find(tmpl_attr_unresolved(vpt), -1);
			if (!func) goto unresolved;
			goto virtual;
		}
	}

	node = xlat_exp_alloc(ctx, XLAT_ATTRIBUTE, vpt->name, vpt->len);
	node->attr = talloc_move(node, vpt_p);

	return 0;
}
