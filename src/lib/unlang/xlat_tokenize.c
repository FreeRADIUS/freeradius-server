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
 * @copyright 2017-2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 * @copyright 2000,2006 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/regex.h>
#include <freeradius-devel/unlang/xlat_priv.h>

#undef XLAT_DEBUG
#undef XLAT_HEXDUMP
#ifdef DEBUG_XLAT
#  define XLAT_DEBUG(_fmt, ...)			DEBUG3("%s[%i] "_fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#  define XLAT_HEXDUMP(_data, _len, _fmt, ...)	HEXDUMP3(_data, _len, "%s[%i] "_fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#  define XLAT_DEBUG(...)
#  define XLAT_HEXDUMP(...)
#endif

/** These rules apply to literal values and function arguments inside of an expansion
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

/** These rules apply to literal values and function arguments inside of an expansion
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

/** Parse rules for literal values inside of an expansion
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

/** Allocate an xlat node to call an xlat function
 *
 * @param[in] ctx	to allocate the new node in.
 * @param[in] func	to call.
 * @param[in] args	Arguments to the function.  Will be copied,
 *			and freed when the new xlat node is freed.
 */
xlat_exp_t *xlat_exp_func_alloc(TALLOC_CTX *ctx, xlat_t *func, xlat_exp_head_t const *args)
{
	xlat_exp_t *node;

	MEM(node = xlat_exp_alloc(ctx, XLAT_FUNC, func->name, strlen(func->name)));
	node->call.func = func;
	if (unlikely(xlat_copy(node, &node->call.args, args) < 0)) {
		talloc_free(node);
		return NULL;
	}
	node->flags = func->flags;
	xlat_flags_merge(&node->flags, &args->flags);

	/*
	 *	If the function is pure, AND it's arguments are pure,
	 *	then remember that we need to call a pure function.
	 */
	node->flags.can_purify = (func->flags.pure && args->flags.pure) | args->flags.can_purify;

	return node;
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

static int xlat_tokenize_string(xlat_exp_head_t *head, fr_sbuff_t *in, bool brace,
				fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules);

static inline int xlat_tokenize_alternation(xlat_exp_head_t *head, fr_sbuff_t *in,
					    tmpl_rules_t const *t_rules, bool func_args)
{
	xlat_exp_t	*node;

	XLAT_DEBUG("ALTERNATE <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	node = xlat_exp_alloc_null(head);
	xlat_exp_set_type(node, XLAT_ALTERNATE);
	MEM(node->alternate[0] = xlat_exp_head_alloc(node));
	MEM(node->alternate[1] = xlat_exp_head_alloc(node));

	if (func_args) {
		if (xlat_tokenize_function_args(node->alternate[0], in, t_rules) < 0) {
		error:
			talloc_free(node);
			return -1;
		}
	} else {
		if (xlat_tokenize_expansion(node->alternate[0], in, t_rules) < 0) goto error;
	}

	if (!fr_sbuff_adv_past_str_literal(in, ":-")) {
		fr_strerror_const("Expected ':-' after first expansion");
		goto error;
	}
	node->flags = node->alternate[0]->flags;

	/*
	 *	Allow the RHS to be empty as a special case.
	 */
	if (fr_sbuff_next_if_char(in, '}')) goto done;

	/*
	 *	Parse the alternate expansion.
	 */
	if (xlat_tokenize_string(node->alternate[1], in,
				  true, &xlat_expansion_rules, t_rules) < 0) goto error;

	if (!xlat_exp_head(node->alternate[1])) {
		talloc_free(node);
		fr_strerror_const("Empty expansion is invalid");
		goto error;
	}

	if (!fr_sbuff_next_if_char(in, '}')) {
		fr_strerror_const("Missing closing brace");
		goto error;
	}
	xlat_flags_merge(&node->flags, &node->alternate[1]->flags);

done:
	xlat_exp_insert_tail(head, node);

	return 0;
}

#ifdef HAVE_REGEX
/** Parse an xlat reference
 *
 * Allows access to a subcapture groups
 * @verbatim %{<num>} @endverbatim
 *
 */
static inline int xlat_tokenize_regex(xlat_exp_head_t *head, fr_sbuff_t *in)
{
	uint8_t			num;
	xlat_exp_t		*node;
	fr_sbuff_parse_error_t	err;
	fr_sbuff_marker_t	m_s;

	XLAT_DEBUG("REGEX <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	fr_sbuff_marker(&m_s, in);

	(void) fr_sbuff_out(&err, &num, in);
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

	node = xlat_exp_alloc(head, XLAT_REGEX, fr_sbuff_current(&m_s), fr_sbuff_behind(&m_s));
	node->regex_index = num;
	node->flags.needs_async = false;

	fr_sbuff_marker_release(&m_s);
	fr_sbuff_next(in);	/* Skip '}' */

	xlat_exp_insert_tail(head, node);

	return 0;
}
#endif

int xlat_validate_function_mono(xlat_exp_t *node)
{
	fr_assert(node->type == XLAT_FUNC);

	if (node->call.func->args && node->call.func->args->required && !xlat_exp_head(node->call.args)) {
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
static inline int xlat_tokenize_function_mono(xlat_exp_head_t *head,
					      fr_sbuff_t *in,
					      tmpl_rules_t const *t_rules)
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

	XLAT_DEBUG("FUNC-MONO <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	/*
	 *	%{module:args}
	 */
	fr_sbuff_marker(&m_s, in);
	fr_sbuff_adv_past_allowed(in, SIZE_MAX, func_chars, NULL);

	if (!fr_sbuff_is_char(in, ':')) {
		fr_strerror_const("Can't find function/argument separator");
	bad_function:
		fr_sbuff_set(in, &m_s);		/* backtrack */
		fr_sbuff_marker_release(&m_s);
		return -1;
	}

	func = xlat_func_find(fr_sbuff_current(&m_s), fr_sbuff_behind(&m_s));

	/*
	 *	Allocate a node to hold the function
	 */
	MEM(node = xlat_exp_alloc(head, XLAT_FUNC, fr_sbuff_current(&m_s), fr_sbuff_behind(&m_s)));
	MEM(node->call.args = xlat_exp_head_alloc(node));
	if (!func) {
		if (!t_rules || !t_rules->attr.allow_unresolved) {
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
			talloc_free(node);
			return -1;
		}
		node->call.func = func;
		node->flags = func->flags;
	}

	/*
	 *	Record the calling style, this is useful
	 *	for checking later with unresolved
	 *	functions, for printing accurate debug
	 *	info, and for weird xlats like the
	 *	redundant xlat
	 */
	node->call.input_type = XLAT_INPUT_MONO;

	fr_sbuff_next(in);			/* Skip the ':' */
	XLAT_DEBUG("FUNC-ARGS <-- %s ... %pV",
		   node->fmt, fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	fr_sbuff_marker_release(&m_s);

	/*
	 *	Now parse the child nodes that form the
	 *	function's arguments.
	 */
	if (xlat_tokenize_string(node->call.args, in, true, &xlat_expansion_rules, t_rules) < 0) {
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

	xlat_flags_merge(&node->flags, &node->call.args->flags);

	if (!func) {
		node->flags.can_purify = node->call.args->flags.can_purify;
	} else {
		node->flags.can_purify = (node->call.func->flags.pure && node->call.args->flags.pure) | node->call.args->flags.can_purify;
	}

	xlat_exp_insert_tail(head, node);

	return 0;
}

static int xlat_validate_function_arg(xlat_arg_parser_t const *arg_p, xlat_exp_t *arg)
{
	ssize_t slen;
	xlat_exp_t *node;
	fr_value_box_t box;

	/*
	 *	The caller doesn't care about the type, OR the type is string, which it already is.
	 */
	if ((arg_p->type == FR_TYPE_VOID) || (arg_p->type == FR_TYPE_STRING)) {
		return 0;
	}

	node = xlat_exp_head(arg->group);

	/*
	 *	@todo - check arg_p->single, and complain.
	 */
	if (xlat_exp_next(arg->group, node)) return 0;

	/*
	 *	@todo - These checks are relatively basic.  We should do better checks, such as if the
	 *	expected type is not string/octets, and the passed arguments are multiple things, then
	 *	die?
	 *
	 *	And check also the 'concat' flag?
	 */
	if (node->type != XLAT_BOX) return 0;

	/*
	 *	Boxes are always strings, because of xlat_tokenize_string()
	 */
	fr_assert(node->data.type == FR_TYPE_STRING);

	fr_value_box_init_null(&box);

	/*
	 *	The entire string must be parseable as the data type we expect.
	 */
	slen = fr_value_box_from_str(node, &box, arg_p->type, NULL, /* no enum */
				     node->data.vb_strvalue, node->data.vb_length,
				     NULL, /* no parse rules */
				     node->data.tainted);
	if (slen <= 0) return -1;

	/*
	 *	Replace the string value with the parsed data type.
	 */
	fr_value_box_clear(&node->data);
	fr_value_box_copy(node, &node->data, &box);

	return 0;
}

int xlat_validate_function_args(xlat_exp_t *node)
{
	xlat_arg_parser_t const *arg_p;
	xlat_exp_t		*arg = xlat_exp_head(node->call.args);
	int			i = 0;

	fr_assert(node->type == XLAT_FUNC);

	for (arg_p = node->call.func->args, i = 0; arg_p->type != FR_TYPE_NULL; arg_p++) {
		if (!arg_p->required) break;

		if (!arg) {
			fr_strerror_printf("Missing required arg %u",
					   (unsigned int)(arg_p - node->call.func->args) + 1);
			return -1;
		}

		/*
		 *	All arguments MUST be put into a group, even
		 *	if they're just one element.
		 */
		fr_assert(arg->type == XLAT_GROUP);

		if (xlat_validate_function_arg(arg_p, arg) < 0) {
			fr_strerror_printf("Failed parsing argument %d as type '%s'", i, fr_type_to_str(arg_p->type));
			return -1;
		}

		arg = xlat_exp_next(node->call.args, arg);
		i++;
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
int xlat_tokenize_function_args(xlat_exp_head_t *head, fr_sbuff_t *in,
				tmpl_rules_t const *t_rules)
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

	XLAT_DEBUG("FUNC-ARGS <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	/*
	 *	%(module:args)
	 */
	fr_sbuff_marker(&m_s, in);
	fr_sbuff_adv_past_allowed(in, SIZE_MAX, func_chars, NULL);

	if (!fr_sbuff_is_char(in, ':')) {
		fr_strerror_const("Can't find function/argument separator");
	bad_function:
		fr_sbuff_set(in, &m_s);		/* backtrack */
		fr_sbuff_marker_release(&m_s);
		return -1;
	}

	func = xlat_func_find(fr_sbuff_current(&m_s), fr_sbuff_behind(&m_s));

	/*
	 *	Allocate a node to hold the function
	 */
	node = xlat_exp_alloc(head, XLAT_FUNC, fr_sbuff_current(&m_s), fr_sbuff_behind(&m_s));
	if (!func) {
		if (!t_rules || !t_rules->attr.allow_unresolved) {
			fr_strerror_const("Unresolved expansion functions are not allowed here");
			goto bad_function;
		}
		xlat_exp_set_type(node, XLAT_FUNC_UNRESOLVED);
		node->flags.needs_resolving = true;	/* Needs resolution during pass2 */
	} else {
		if (func && (func->input_type != XLAT_INPUT_ARGS)) {
			fr_strerror_const("Function should be called using %{func:arg} syntax");
		error:
			talloc_free(node);
			return -1;
		}
		node->call.func = func;
		node->flags = func->flags;
	}

	/*
	 *	Record the calling style, this is useful
	 *	for checking later with unresolved
	 *	functions, for printing accurate debug
	 *	info, and for weird xlats like the
	 *	redundant xlat
	 */
	node->call.input_type = XLAT_INPUT_ARGS;

	fr_sbuff_next(in);			/* Skip the ':' */
	XLAT_DEBUG("FUNC-ARGS <-- %s ... %pV",
		   node->fmt, fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	fr_sbuff_marker_release(&m_s);

	/*
	 *	Now parse the child nodes that form the
	 *	function's arguments.
	 */
	if (xlat_tokenize_argv(node, &node->call.args, in, &xlat_multi_arg_rules, t_rules) < 0) {
		goto error;
	}
	xlat_flags_merge(&node->flags, &node->call.args->flags);

	/*
	 *	Check we have all the required arguments
	 */
	if (node->type == XLAT_FUNC) {
		if (xlat_validate_function_args(node) < 0) goto error;

		node->flags.can_purify = (node->call.func->flags.pure && node->call.args->flags.pure) | node->call.args->flags.can_purify;
	}

	if (!fr_sbuff_next_if_char(in, ')')) {
		fr_strerror_const("Missing closing brace");
		goto error;
	}

	xlat_exp_insert_tail(head, node);
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
	if (!func) return -1;

	xlat_exp_set_type(node, XLAT_VIRTUAL);
	xlat_exp_set_name_buffer_shallow(node, vpt->name);

	XLAT_DEBUG("VIRTUAL <-- %pV",
		   fr_box_strvalue_len(vpt->name, vpt->len));
	node->call.func = func;
	node->flags = func->flags;

	return 0;
}

/** Parse an attribute ref or a virtual attribute
 *
 */
static inline int xlat_tokenize_attribute(xlat_exp_head_t *head, fr_sbuff_t *in,
					  fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	tmpl_attr_error_t	err;
	tmpl_t			*vpt = NULL;
	xlat_exp_t		*node;

	fr_sbuff_marker_t	m_s;
	tmpl_rules_t		 our_t_rules;

	XLAT_DEBUG("ATTRIBUTE <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	/*
	 *	We need a local copy as we always allow unknowns.
	 *	This is because not all attribute references
	 *	reference real attributes in the dictionaries,
	 *	and instead are "virtual" attributes like
	 *	Foreach-Variable-N.
	 */
	if (t_rules) {
		memset(&our_t_rules, 0, sizeof(our_t_rules));
		our_t_rules = *t_rules;
	} else {
		memset(&our_t_rules, 0, sizeof(our_t_rules));
	}

	our_t_rules.attr.allow_unresolved = true;		/* So we can check for virtual attributes later */
  	our_t_rules.attr.prefix = TMPL_ATTR_REF_PREFIX_NO;	/* Must be NO to stop %{&User-Name} */

	fr_sbuff_marker(&m_s, in);

	MEM(node = xlat_exp_alloc_null(head));
	if (tmpl_afrom_attr_substr(node, &err, &vpt, in, p_rules, &our_t_rules) < 0) {
		/*
		 *	If the parse error occurred before the ':'
		 *	then the error is changed to 'Unknown module',
		 *	as it was more likely to be a bad module name,
		 *	than a request qualifier.
		 */
		if (err == TMPL_ATTR_ERROR_MISSING_TERMINATOR) fr_sbuff_set(in, &m_s);
	error:
		fr_sbuff_marker_release(&m_s);
		talloc_free(node);
		FR_SBUFF_ERROR_RETURN(in);
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
		if ((tmpl_attr_count(vpt) == (size_t) (1 + vpt->rules.attr.list_as_attr)) && (xlat_resolve_virtual_attribute(node, vpt) == 0)) goto done;

		if (!t_rules || !t_rules->attr.allow_unresolved) {
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
		node->vpt = vpt;
		node->flags.needs_resolving = true;
	/*
	 *	Deal with normal attribute (or list)
	 */
	} else {
	do_attr:
		xlat_exp_set_type(node, XLAT_TMPL);
		xlat_exp_set_name_buffer_shallow(node, vpt->name);
		node->vpt = vpt;
	}

done:
	/*
	 *	Attributes and module calls aren't pure.
	 */
	node->flags.pure = false;

	if (!fr_sbuff_next_if_char(in, '}')) {
		fr_strerror_const("Missing closing brace");
		goto error;
	}

	xlat_exp_insert_tail(head, node);

	fr_sbuff_marker_release(&m_s);
	return 0;
}

int xlat_tokenize_expansion(xlat_exp_head_t *head, fr_sbuff_t *in,
			    tmpl_rules_t const *t_rules)
{
	size_t			len;
	fr_sbuff_marker_t	s_m;
	char			hint;
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
		return xlat_tokenize_alternation(head, in, t_rules, false);
	}

	/*
	 *	%(...):-bar}
	 */
	if (fr_sbuff_adv_past_str_literal(in, "%(")) {
		return xlat_tokenize_alternation(head, in, t_rules, true);
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
	 *	Handle regex's %{<num>} specially.  But '3GPP-Foo' is an attribute.  :(
	 */
	if (fr_sbuff_is_digit(in)) {
		int ret;

		ret = xlat_tokenize_regex(head, in);
		if (ret <= 0) return ret;

		/* ret==1 means "nope, it's an attribute" */
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
	if (!fr_sbuff_extend(in)) {
		fr_strerror_const("Missing closing brace");
		fr_sbuff_marker_release(&s_m);
		return -1;
	}

	hint = fr_sbuff_char(in, '\0');

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
		fr_sbuff_set(in, &s_m);		/* backtrack */
		fr_sbuff_marker_release(&s_m);

		return xlat_tokenize_function_mono(head, in, t_rules);

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

		return xlat_tokenize_attribute(head, in, &attr_p_rules, t_rules);

	/*
	 *	Hint token was whitespace
	 *
	 *	e.g. '%{my '
	 */
	default:
		break;
	}

	/*
	 *	Box print is so we get \t \n etc..
	 */
	fr_strerror_printf("Invalid char '%pV' in expression", fr_box_strvalue_len(fr_sbuff_current(in), 1));
	return -1;
}

/** Parse an xlat string i.e. a non-expansion or non-function
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
 * @param[in] head		to allocate nodes in, and where to write the first
 *				child, and where the flags are stored.
 * @param[in] in		sbuff to parse.
 * @param[in] brace		true if we're inside a braced expansion, else false.
 * @param[in] p_rules		that control parsing.
 * @param[in] t_rules		that control attribute reference and xlat function parsing.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int xlat_tokenize_string(xlat_exp_head_t *head,
				fr_sbuff_t *in, bool brace,
				fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	xlat_exp_t			*node = NULL;
	fr_slen_t			slen;
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
						L("%{")
					);
	fr_sbuff_term_t			*tokens;
	fr_sbuff_unescape_rules_t const	*escapes;

	XLAT_DEBUG("STRING <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	escapes = p_rules ? p_rules->escapes : NULL;
	tokens = p_rules && p_rules->terminals ?
			fr_sbuff_terminals_amerge(NULL, p_rules->terminals, &expansions) : &expansions;

	for (;;) {
		char *str;

		/*
		 *	pre-allocate the node so we don't have to steal it later.
		 */
		node = xlat_exp_alloc_null(head);

		/*
		 *	Find the next token
		 */
		slen = fr_sbuff_out_aunescape_until(node, &str, in, SIZE_MAX, tokens, escapes);

		/*
		 *	It's a value box, create an appropriate node
		 */
		if (slen > 0) {
			xlat_exp_set_type(node, XLAT_BOX);
			xlat_exp_set_name_buffer_shallow(node, str);
			fr_value_box_strdup_shallow(&node->data, NULL, str, false);
			node->flags.constant = true;

			XLAT_DEBUG("VALUE-BOX (%s)<-- %pV",
				   escapes ? escapes->name : "(none)",
				   fr_box_strvalue_len(str, talloc_array_length(str) - 1));
			XLAT_HEXDUMP((uint8_t const *)str, talloc_array_length(str) - 1, " VALUE-BOX ");

			xlat_exp_insert_tail(head, node);
		} else if (slen < 0) {
		error:
			talloc_free(node);

			/*
			 *	Free our temporary array of terminals
			 */
			if (tokens != &expansions) talloc_free(tokens);
			return -1;
		}

		if (fr_sbuff_adv_past_str_literal(in, "%{")) {
			if (slen == 0) TALLOC_FREE(node); /* Free the empty node */

			if (xlat_tokenize_expansion(head, in, t_rules) < 0) goto error;
			continue;
		}

		/*
		 *	xlat function call with discreet arguments
		 */
		if (fr_sbuff_adv_past_str_literal(in, "%(")) {
			if (slen == 0) TALLOC_FREE(node); /* Free the empty node */

			if (xlat_tokenize_function_args(head, in, t_rules) < 0) goto error;
			continue;
		}

		/*
		 *	%[a-z] - A one letter expansion
		 */
		if (fr_sbuff_next_if_char(in, '%') && fr_sbuff_is_alpha(in)) {
			XLAT_DEBUG("ONE-LETTER <-- %pV",
				   fr_box_strvalue_len(str, talloc_array_length(str) - 1));

			if (slen == 0) {
				talloc_free_children(node);	/* re-use empty nodes */
			} else {
				node = xlat_exp_alloc_null(head);
			}

			fr_sbuff_out_abstrncpy(node, &str, in, 1);
			xlat_exp_set_type(node, XLAT_ONE_LETTER);
			xlat_exp_set_name_buffer_shallow(node, str);

#ifdef STATIC_ANALYZER
			if (!node->fmt) goto error;
#endif

			/*
			 *	%% is pure.  Everything else is not.
			 */
			node->flags.pure = (node->fmt[0] == '%');
			node->flags.needs_async = false;

			xlat_exp_insert_tail(head, node);
			continue;
		}

		/*
		 *	We were told to look for a brace, but we ran off of
		 *	the end of the string before we found one.
		 */
		if (brace) {
			if (slen == 0) TALLOC_FREE(node); /* Free the empty node */

			if (!fr_sbuff_is_char(in, '}')) {
				fr_strerror_const("Missing closing brace");
				goto error;
			}
		/*
		 *	Empty input, emit no arguments
		 */
		} else if (slen == 0) {
			TALLOC_FREE(node);
			XLAT_DEBUG("VALUE-BOX <-- (empty)");
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

static void _xlat_debug(xlat_exp_head_t const *head, int depth)
{
	int i = 0;
#ifndef NDEBUG
	bool needs_resolving = false;
#endif

#define INFO_INDENT(_fmt, ...)  INFO("%*s"_fmt, depth * 2, " ", ## __VA_ARGS__)

	fr_assert(head != NULL);

	INFO_INDENT("head flags = { %s %s %s %s }",
		    head->flags.needs_resolving ? "need_resolving" : "",
		    head->flags.needs_async ? "need_async" : "",
		    head->flags.pure ? "pure" : "",
		    head->flags.can_purify ? "can_purify" : "");

	xlat_exp_foreach(head, node) {
		INFO_INDENT("[%d] flags = { %s %s %s %s }", i++,
			    node->flags.needs_resolving ? "need_resolving" : "",
			    node->flags.needs_async ? "need_async" : "",
			    node->flags.pure ? "pure" : "",
			    node->flags.can_purify ? "can_purify" : "");

#ifndef NDEBUG
		if (node->flags.needs_resolving) fr_assert(head->flags.needs_resolving);

		if (!head->flags.needs_resolving) fr_assert(!node->flags.needs_resolving);

		needs_resolving |= node->flags.needs_resolving;
#endif

		if (node->quote != T_BARE_WORD) INFO_INDENT("quote = %c", fr_token_quote[node->quote]);

		switch (node->type) {
		case XLAT_BOX:
			INFO_INDENT("value %s --> %pV", fr_type_to_str(node->data.type), &node->data);
			break;

		case XLAT_GROUP:
			INFO_INDENT("group");
			INFO_INDENT("{");
			_xlat_debug(node->group, depth + 1);
			INFO_INDENT("}");
			break;

		case XLAT_ONE_LETTER:
			INFO_INDENT("percent (%c)", node->fmt[0]);
			break;

		case XLAT_TMPL:
		{
			if (tmpl_is_attr(node->vpt)) {
				fr_assert(!node->flags.pure);
				INFO_INDENT("attribute (%s)", tmpl_da(node->vpt)->name);
				if (tmpl_num(node->vpt) != NUM_UNSPEC) {
					FR_DLIST_HEAD(tmpl_request_list) const *list;
					tmpl_request_t *rr = NULL;

					INFO_INDENT("{");

					/*
					 *	Loop over the request references
					 */
					list = tmpl_request(node->vpt);
					while ((rr = tmpl_request_list_next(list, rr))) {
						INFO_INDENT("ref  %d", rr->request);
					}
					INFO_INDENT("list %d", tmpl_list(node->vpt));
					if (tmpl_num(node->vpt) != NUM_UNSPEC) {
						if (tmpl_num(node->vpt) == NUM_COUNT) {
							INFO_INDENT("[#]");
						} else if (tmpl_num(node->vpt) == NUM_ALL) {
							INFO_INDENT("[*]");
						} else {
							INFO_INDENT("[%d]", tmpl_num(node->vpt));
						}
					}
					INFO_INDENT("}");
				}
			} else if (tmpl_is_data(node->vpt)) {
				INFO_INDENT("tmpl (%s) type %s", node->fmt, fr_type_to_str(tmpl_value_type(node->vpt)));
			} else {
				INFO_INDENT("tmpl (%s)", node->fmt);
			}
		}
			break;

		case XLAT_VIRTUAL:
			fr_assert(node->fmt != NULL);
			INFO_INDENT("virtual (%s)", node->fmt);
			break;

		case XLAT_VIRTUAL_UNRESOLVED:
			fr_assert(node->fmt != NULL);
			INFO_INDENT("virtual-unresolved (%s)", node->fmt);
			break;

		case XLAT_FUNC:
			fr_assert(node->call.func != NULL);
			INFO_INDENT("xlat (%s)", node->call.func->name);
			if (xlat_exp_head(node->call.args)) {
				INFO_INDENT("{");
				_xlat_debug(node->call.args, depth + 1);
				INFO_INDENT("}");
			}
			break;

		case XLAT_FUNC_UNRESOLVED:
			INFO_INDENT("xlat-unresolved (%s)", node->fmt);
			if (xlat_exp_head(node->call.args)) {
				INFO_INDENT("{");
				_xlat_debug(node->call.args, depth + 1);
				INFO_INDENT("}");
			}
			break;

#ifdef HAVE_REGEX
		case XLAT_REGEX:
			INFO_INDENT("regex-var -- %d", node->regex_index);
			break;
#endif

		case XLAT_ALTERNATE:
			DEBUG("XLAT-IF {");
			_xlat_debug(node->alternate[0], depth + 1);
			DEBUG("}");
			DEBUG("XLAT-ELSE {");
			_xlat_debug(node->alternate[1], depth + 1);
			DEBUG("}");
			break;

		case XLAT_INVALID:
			DEBUG("XLAT-INVALID");
			break;
		}
	}

	fr_assert(needs_resolving == head->flags.needs_resolving);
}

void xlat_debug(xlat_exp_head_t const *head)
{
	_xlat_debug(head, 0);
}

ssize_t xlat_print_node(fr_sbuff_t *out, xlat_exp_head_t const *head, xlat_exp_t const *node, fr_sbuff_escape_rules_t const *e_rules)
{
	ssize_t			slen;
	size_t			at_in = fr_sbuff_used_total(out);
	char			close;

	if (!node) return 0;

	switch (node->type) {
	case XLAT_GROUP:
		if (node->quote != T_BARE_WORD) FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->quote]);
		xlat_print(out, node->group, fr_value_escape_by_quote[node->quote]);
		if (node->quote != T_BARE_WORD) FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->quote]);

		if (xlat_exp_next(head, node)) FR_SBUFF_IN_CHAR_RETURN(out, ' ');      /* Add ' ' between args */
		goto done;

	case XLAT_BOX:
		/*
		 *	@todo - respect node->quote here, too.  Which also means updating the parser.
		 */
		if (node->quote == T_BARE_WORD) {
			FR_SBUFF_RETURN(fr_value_box_print, out, &node->data, e_rules);
		} else {
			FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->quote]);
			FR_SBUFF_RETURN(fr_value_box_print, out, &node->data, fr_value_escape_by_quote[node->quote]);
			FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->quote]);
		}
		goto done;

	case XLAT_TMPL:
		if (node->vpt->rules.cast != FR_TYPE_NULL) {
			FR_SBUFF_IN_CHAR_RETURN(out, '(');
			FR_SBUFF_IN_STRCPY_RETURN(out, fr_type_to_str(node->vpt->rules.cast));
			FR_SBUFF_IN_CHAR_RETURN(out, ')');
		}

		if (tmpl_is_data(node->vpt)) {
			FR_SBUFF_RETURN(fr_value_box_print_quoted, out, tmpl_value(node->vpt), node->vpt->quote);
			goto done;
		}
		if (tmpl_needs_resolving(node->vpt)) {
			if (node->vpt->quote != T_BARE_WORD) {
				FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->vpt->quote]);
			}
			FR_SBUFF_IN_STRCPY_RETURN(out, node->vpt->name); /* @todo - escape it? */
			if (node->vpt->quote != T_BARE_WORD) {
				FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->vpt->quote]);
			}
			goto done;
		}

		if (tmpl_is_xlat(node->vpt)) {
			xlat_print(out, tmpl_xlat(node->vpt), fr_value_escape_by_quote[node->quote]);
			goto done;
		}

		if (tmpl_contains_xlat(node->vpt)) { /* exec */
			FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->vpt->quote]);
			xlat_print(out, tmpl_xlat(node->vpt), fr_value_escape_by_quote[node->quote]);
			FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->vpt->quote]);
			goto done;
		}

		/*
		 *	Regexes need their own print routine, as they need to print the flags, too.
		 *
		 *	Regexes should also "eat" their arguments into their instance data, so that we should
		 *	never try to print a regex.
		 */
		fr_assert(!tmpl_contains_regex(node->vpt));

		// attr or list
		fr_assert(tmpl_is_list(node->vpt) || tmpl_is_attr(node->vpt));
		fr_assert(talloc_parent(node->vpt) == node);
		fr_assert(!node->flags.pure);

		/*
		 *	We prefer the name from the configuration file, otherwise when we get
		 *	&User-Name on input, the tmpl_printer will print the full path, as
		 *	&request[0].User-Name.
		 */
		if (node->vpt->name[0] == '&') {
			FR_SBUFF_IN_STRCPY_RETURN(out, node->fmt);
			goto done;
		}
		break;

	case XLAT_ONE_LETTER:
		FR_SBUFF_IN_CHAR_RETURN(out, '%', node->fmt[0]);
		goto done;

	case XLAT_FUNC:
		/*
		 *	We have a callback for printing this node, go
		 *	call it.
		 */
		if (node->call.func->print) {
			slen = node->call.func->print(out, node, node->call.inst->data, e_rules);
			if (slen < 0) return slen;
			goto done;
		}
		break;

	default:
		break;
	}

	/*
	 *	Now print %(...) or %{...}
	 */
	if ((node->type == XLAT_FUNC) && (node->call.func->input_type == XLAT_INPUT_ARGS)) {
		FR_SBUFF_IN_STRCPY_LITERAL_RETURN(out, "%(");
		close = ')';
	} else {
		FR_SBUFF_IN_STRCPY_LITERAL_RETURN(out, "%{");
		close = '}';
	}

	switch (node->type) {
	case XLAT_TMPL:
		slen = tmpl_attr_print(out, node->vpt, TMPL_ATTR_REF_PREFIX_NO);
		if (slen < 0) return slen;
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

		if (xlat_exp_head(node->call.args)) {
			slen = xlat_print(out, node->call.args, &xlat_escape);
			if (slen < 0) return slen;
		}
		break;

	case XLAT_FUNC_UNRESOLVED:
		FR_SBUFF_IN_BSTRCPY_BUFFER_RETURN(out, node->fmt);
		FR_SBUFF_IN_CHAR_RETURN(out, ':');

		if (xlat_exp_head(node->call.args)) {
			slen = xlat_print(out, node->call.args, &xlat_escape);
			if (slen < 0) return slen;
		}
		break;

	case XLAT_ALTERNATE:
		slen = xlat_print(out, node->alternate[0], &xlat_escape);
		if (slen < 0) return slen;

		FR_SBUFF_IN_STRCPY_LITERAL_RETURN(out, ":-");
		slen = xlat_print(out, node->alternate[1], &xlat_escape);
		if (slen < 0) return slen;
		break;

		fr_assert_fail(NULL);
		break;

	case XLAT_INVALID:
	case XLAT_BOX:
	case XLAT_ONE_LETTER:
	case XLAT_GROUP:
		fr_assert_fail(NULL);
		break;
	}
	FR_SBUFF_IN_CHAR_RETURN(out, close);

done:
	return fr_sbuff_used_total(out) - at_in;
}

/** Reconstitute an xlat expression from its constituent nodes
 *
 * @param[in] out	Where to write the output string.
 * @param[in] head	First node to print.
 * @param[in] e_rules	Specifying how to escape literal values.
 */
ssize_t xlat_print(fr_sbuff_t *out, xlat_exp_head_t const *head, fr_sbuff_escape_rules_t const *e_rules)
{
	ssize_t			slen;
	size_t			at_in = fr_sbuff_used_total(out);

	xlat_exp_foreach(head, node) {
		slen = xlat_print_node(out, head, node, e_rules);
		if (slen < 0) return slen - (fr_sbuff_used_total(out) - at_in);
	}

	return fr_sbuff_used_total(out) - at_in;
}


/** Tokenize an xlat expansion at runtime
 *
 * This is used for runtime parsing of xlat expansions, such as those we receive from datastores
 * like LDAP or SQL.
 *
 * @param[in] ctx	to allocate dynamic buffers in.
 * @param[out] out	the head of the xlat list / tree structure.
 * @param[in] el	for registering any I/O handlers.
 * @param[in] in	the format string to expand.
 * @param[in] p_rules	from the encompassing grammar.
 * @param[in] t_rules	controlling how attribute references are parsed.
 * @return
 *	- >0 on success.
 *	- 0 and *head == NULL - Parse failure on first char.
 *	- 0 and *head != NULL - Zero length expansion
 *	- <0 the negative offset of the parse failure.
 */
fr_slen_t xlat_tokenize_ephemeral(TALLOC_CTX *ctx, xlat_exp_head_t **out,
				  fr_event_list_t *el, fr_sbuff_t *in,
			          fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	fr_sbuff_t	our_in = FR_SBUFF(in);
	tmpl_rules_t	our_t_rules = {};
	xlat_exp_head_t *head;

	MEM(head = xlat_exp_head_alloc(ctx));

	if (t_rules) {
		head->dict = t_rules->attr.dict_def;
		our_t_rules = *t_rules;
	}

	our_t_rules.xlat.runtime_el = el;

	fr_strerror_clear();	/* Clear error buffer */
	if (xlat_tokenize_string(head, &our_in,
				 false, p_rules, &our_t_rules) < 0) {
		talloc_free(head);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	Zero length expansion, return a zero length node.
	 */
	if (!xlat_exp_head(head)) {
		*out = head;
		return 0;
	}

	/*
	 *	Create ephemeral instance data for the xlat
	 */
	if (xlat_instantiate_ephemeral(head, el) < 0) {
		fr_strerror_const("Failed performing ephemeral instantiation for xlat");
		talloc_free(head);
		return 0;
	}

	*out = head;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Tokenize an xlat expansion into a series of XLAT_TYPE_CHILD arguments
 *
 * @param[in] ctx		to allocate nodes in.  Note: All nodes will be
 *				allocated in the same ctx.  This is to allow
 *				manipulation by xlat instantiation functions
 *				later.
 * @param[out] out		the head of the xlat list / tree structure.
 * @param[in] in		the format string to expand.
 * @param[in] p_rules		controlling how to parse the string outside of
 *				any expansions.
 * @param[in] t_rules		controlling how attribute references are parsed.
 * @return
 *	- < 0 on error.
 *	- >0  on success which is the number of characters parsed.
 */
fr_slen_t xlat_tokenize_argv(TALLOC_CTX *ctx, xlat_exp_head_t **out, fr_sbuff_t *in,
			     fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	fr_sbuff_t			our_in = FR_SBUFF(in);
	ssize_t				slen;
	fr_sbuff_marker_t		m;
	fr_sbuff_parse_rules_t const	*our_p_rules;	/* Bareword parse rules */
	fr_sbuff_parse_rules_t		tmp_p_rules;
	xlat_exp_head_t			*head;

	MEM(head = xlat_exp_head_alloc(ctx));
	if (t_rules) head->dict = t_rules->attr.dict_def;

	if (p_rules && p_rules->terminals) {
		tmp_p_rules = (fr_sbuff_parse_rules_t){	/* Stack allocated due to CL scope */
			.terminals = fr_sbuff_terminals_amerge(NULL, p_rules->terminals,
							       value_parse_rules_bareword_quoted.terminals),
			.escapes = (p_rules->escapes ? p_rules->escapes : value_parse_rules_bareword_quoted.escapes)
		};
		our_p_rules = &tmp_p_rules;
	} else {
		our_p_rules = &value_parse_rules_bareword_quoted;
	}

	/*
	 *	skip spaces at the beginning as we
	 *	don't want them to become a whitespace
	 *	literal.
	 */
	fr_sbuff_adv_past_whitespace(in, SIZE_MAX, NULL);
	fr_sbuff_marker(&m, &our_in);

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
		MEM(node = xlat_exp_alloc_null(head));
		xlat_exp_set_type(node, XLAT_GROUP);
		MEM(node->group = xlat_exp_head_alloc(node));
		node->quote = quote;

		switch (quote) {
		/*
		 *	Barewords --may-contain=%{expansions}
		 */
		case T_BARE_WORD:
			if (xlat_tokenize_string(node->group, &our_in,
						  false, our_p_rules, t_rules) < 0) {
			error:
				if (our_p_rules != &value_parse_rules_bareword_quoted) {
					talloc_const_free(our_p_rules->terminals);
				}
				talloc_free(head);

				FR_SBUFF_ERROR_RETURN(&our_in);	/* error */
			}
			break;

		/*
		 *	"Double quoted strings may contain %{expansions}"
		 */
		case T_DOUBLE_QUOTED_STRING:
			if (xlat_tokenize_string(node->group, &our_in,
						  false, &value_parse_rules_double_quoted, t_rules) < 0) goto error;
			break;

		/*
		 *	'Single quoted strings get parsed as literal strings'
		 */
		case T_SINGLE_QUOTED_STRING:
		{
			char		*str;
			xlat_exp_t	*child;

			child = xlat_exp_alloc_null(node->group);
			xlat_exp_set_type(child, XLAT_BOX);
			node->flags.constant = true;

			slen = fr_sbuff_out_aunescape_until(child, &str, &our_in, SIZE_MAX,
							    value_parse_rules_single_quoted.terminals,
							    value_parse_rules_single_quoted.escapes);
			if (slen < 0) goto error;

			xlat_exp_set_name_buffer_shallow(child, str);
			fr_value_box_strdup_shallow(&child->data, NULL, str, false);
			xlat_exp_insert_tail(node->group, child);
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

		node->flags = node->group->flags;

		xlat_exp_insert_tail(head, node);

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

	if (our_p_rules != &value_parse_rules_bareword_quoted) talloc_const_free(our_p_rules->terminals);

	*out = head;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Tokenize an xlat expansion
 *
 * @param[in] ctx	to allocate dynamic buffers in.
 * @param[out] out	the head of the xlat list / tree structure.
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
fr_slen_t xlat_tokenize(TALLOC_CTX *ctx, xlat_exp_head_t **out, fr_sbuff_t *in,
			fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	fr_sbuff_t	our_in = FR_SBUFF(in);
	xlat_exp_head_t	*head;

	MEM(head = xlat_exp_head_alloc(ctx));
	if (t_rules) head->dict = t_rules->attr.dict_def;

	fr_strerror_clear();	/* Clear error buffer */

	if (xlat_tokenize_string(head, &our_in,
				  false, p_rules, t_rules) < 0) {
		talloc_free(head);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	Add nodes that need to be bootstrapped to
	 *	the registry.
	 */
	if (xlat_exp_head(head) && (xlat_bootstrap(head) < 0)) {
		talloc_free(head);
		return 0;
	}

	*out = head;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Check to see if the expansion consists entirely of value-box elements
 *
 * @param[in] head	to check.
 * @return
 *	- true if expansion contains only literal elements.
 *	- false if expansion contains expandable elements.
 */
bool xlat_is_literal(xlat_exp_head_t const *head)
{
	xlat_exp_foreach(head, node) {
		if (node->type != XLAT_BOX) return false;
	}

	return true;
}

/** Check to see if the expansion needs resolving
 *
 * @param[in] head	to check.
 * @return
 *	- true if expansion needs resolving
 *	- false otherwise
 */
bool xlat_needs_resolving(xlat_exp_head_t const *head)
{
	return head->flags.needs_resolving;
}

/** Convert an xlat node to an unescaped literal string and free the original node
 *
 *  This is really "unparse the xlat nodes, and convert back to their original string".
 *
 * @param[in] ctx	to allocate the new string in.
 * @param[out] str	a duplicate of the node's fmt string.
 * @param[in,out] head	to convert.
 * @return
 *	- true	the tree consists of a single value node which was converted.
 *      - false the tree was more complex than a single literal, op was a noop.
 */
bool xlat_to_string(TALLOC_CTX *ctx, char **str, xlat_exp_head_t **head)
{
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
	xlat_exp_foreach(*head, node) {
		if (node->type != XLAT_BOX) return false;
		len += talloc_array_length(node->fmt) - 1;
	}

	fr_sbuff_init_talloc(ctx, &out, &tctx, len, SIZE_MAX);

	xlat_exp_foreach(*head, node) {
		fr_sbuff_in_bstrcpy_buffer(&out, node->fmt);
	}

	*str = fr_sbuff_buff(&out);	/* No need to trim, should be the correct length */

	return true;
}

/** Walk over an xlat tree recursively, resolving any unresolved functions or references
 *
 * @param[in,out] head		of xlat tree to resolve.
 * @param[in] xr_rules		Specifies rules to use for resolution passes after initial
 *      			tokenization.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_resolve(xlat_exp_head_t *head, xlat_res_rules_t const *xr_rules)
{
	static xlat_res_rules_t		xr_default;
	xlat_flags_t			our_flags;

	if (!head->flags.needs_resolving) return 0;			/* Already done */

	if (!xr_rules) xr_rules = &xr_default;

	our_flags = head->flags;
	our_flags.needs_resolving = false;			/* We flip this if not all resolutions are successful */
	our_flags.pure = true;					/* we flip this if the children are not pure */

	xlat_exp_foreach(head, node) {
		/*
		 *	This node and none of its children need resolving
		 */
		if (!node->flags.needs_resolving) {
			xlat_flags_merge(&our_flags, &node->flags);
			continue;
		}

		switch (node->type) {
		case XLAT_GROUP:
			if (xlat_resolve(node->group, xr_rules) < 0) return -1;
			node->flags = node->group->flags;
			break;

		/*
		 *	Alternate expansion a || b
		 *
		 *	Do resolution for a OR b
		 */
		case XLAT_ALTERNATE:
			if ((xlat_resolve(node->alternate[0], xr_rules) < 0) ||
			    (xlat_resolve(node->alternate[1], xr_rules) < 0)) return -1;

			node->flags = node->alternate[0]->flags;
			xlat_flags_merge(&node->flags, &node->alternate[1]->flags);
			break;

		/*
		 *	An unresolved function.
		 */
		case XLAT_FUNC_UNRESOLVED:
			/*
			 *	Try to find the function
			 */
			node->call.func = xlat_func_find(node->fmt, talloc_array_length(node->fmt) - 1);
			if (!node->call.func) {
				/*
				 *	FIXME - Produce proper error with marker
				 */
				if (!xr_rules->allow_unresolved) {
					fr_strerror_printf("Failed resolving function \"%pV\"",
							   fr_box_strvalue_buffer(node->fmt));
					return -1;
				}
				break;
			}

			xlat_exp_set_type(node, XLAT_FUNC);

			/*
			 *	Check input arguments of our freshly
			 *	resolved function
			 */
			switch (node->call.func->input_type) {
			case XLAT_INPUT_UNPROCESSED:
				break;

			case XLAT_INPUT_MONO:
				if (node->call.input_type != XLAT_INPUT_MONO) {
					fr_strerror_const("Function should be called using %{func:arg} syntax");
					return -1;

				}
				if (xlat_validate_function_mono(node) < 0) return -1;
				break;

			case XLAT_INPUT_ARGS:
				if (node->call.input_type != XLAT_INPUT_ARGS) {
					fr_strerror_const("Function takes defined arguments and should "
							  "be called using %(func:args) syntax");
					return -1;
				}
				if (xlat_validate_function_args(node) < 0) return -1;
				break;
			}

			/*
			 *	Add the freshly resolved function
			 *	to the bootstrap tree.
			 */
			if (xlat_bootstrap_func(node) < 0) return -1;

			/*
			 *	The function is now resolved, so we go through the normal process of resolving
			 *	its arguments, etc.
			 */
			FALL_THROUGH;

		/*
		 *	A resolved function with unresolved args
		 */
		case XLAT_FUNC:
			node->flags = node->call.func->flags;

			if (node->call.func->resolve) {
				void *inst = node->call.inst ? node->call.inst->data : NULL;

				if (node->call.func->resolve(node, inst, xr_rules) < 0) return -1;
			} else {
				if (xlat_resolve(node->call.args, xr_rules) < 0) return -1;
			}

			xlat_flags_merge(&node->flags, &node->call.args->flags);
			node->flags.can_purify = (node->call.func->flags.pure && node->call.args->flags.pure) | node->call.args->flags.can_purify;
			break;

		/*
		 *	This covers unresolved attributes as well as
		 *	unresolved functions.
		 */
		case XLAT_VIRTUAL_UNRESOLVED:
		{
			if (xlat_resolve_virtual_attribute(node, node->vpt) == 0) break;

			/*
			 *	Try and resolve (in-place) as an attribute
			 */
			if ((tmpl_resolve(node->vpt, xr_rules->tr_rules) < 0) ||
			    (node->vpt->type != TMPL_TYPE_ATTR)) {
				/*
				 *	FIXME - Produce proper error with marker
				 */
				if (!xr_rules->allow_unresolved) {
				error_unresolved:
					if (node->quote == T_BARE_WORD) {
						fr_strerror_printf_push("Failed resolving expansion: %s",
									node->fmt);
					} else {
						fr_strerror_printf_push("Failed resolving expansion: %c%s%c",
									fr_token_quote[node->quote], node->fmt, fr_token_quote[node->quote]);
					}
					return -1;
				}
				break;
			}

			/*
			 *	Just need to flip the type as the tmpl should already have been fixed up
			 */
			xlat_exp_set_type(node, XLAT_TMPL);

			/*
			 *	Reset node flags.  Attributes aren't pure, and don't need further resolving.
			 */
			node->flags = (xlat_flags_t){ };
		}
			break;

		case XLAT_TMPL:
			/*
			 *	Double-quoted etc. strings may contain xlats, so we try to resolve them now.
			 *	Or, convert them to data.
			 */
			if (tmpl_resolve(node->vpt, xr_rules->tr_rules) < 0) return -1;

			node->flags.needs_resolving = false;
			node->flags.pure = tmpl_is_data(node->vpt);
			break;


		default:
			fr_assert(0);	/* Should not have been marked as unresolved */
			return -1;
		}

		if (node->flags.needs_resolving && !xr_rules->allow_unresolved) goto error_unresolved;

		xlat_flags_merge(&our_flags, &node->flags);
	}

	head->flags = our_flags;

	return 0;
}


/** Try to convert an xlat to a tmpl for efficiency
 *
 * @param ctx to allocate new tmpl_t in.
 * @param head to convert.
 * @return
 *	- NULL if unable to convert (not necessarily error).
 *	- A new #tmpl_t.
 */
tmpl_t *xlat_to_tmpl_attr(TALLOC_CTX *ctx, xlat_exp_head_t *head)
{
	tmpl_t *vpt;
	xlat_exp_t *node = xlat_exp_head(head);

	if (!node || (node->type != XLAT_TMPL) || !tmpl_is_attr(node->vpt)) return NULL;

	/*
	 *   Concat means something completely different as an attribute reference
	 *   Count isn't implemented.
	 */
	if ((tmpl_num(node->vpt) == NUM_COUNT) || (tmpl_num(node->vpt) == NUM_ALL)) return NULL;

	vpt = tmpl_alloc(ctx, TMPL_TYPE_ATTR, T_BARE_WORD, node->fmt, talloc_array_length(node->fmt) - 1);
	if (!vpt) return NULL;

	tmpl_attr_copy(vpt, node->vpt);

	TMPL_VERIFY(vpt);

	return vpt;
}

/** Convert attr tmpl to an xlat for &attr[*]
 *
 * @param[in] ctx	to allocate new expansion in.
 * @param[out] out	Where to write new xlat node.
 * @param[in,out] vpt_p	to convert to xlat expansion.
 *			Will be set to NULL on completion
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_from_tmpl_attr(TALLOC_CTX *ctx, xlat_exp_head_t **out, tmpl_t **vpt_p)
{
	xlat_exp_t	*node;
	xlat_t		*func;
	tmpl_t		*vpt = *vpt_p;
	xlat_exp_head_t *head;

	if (!tmpl_is_attr(vpt) && !tmpl_is_attr_unresolved(vpt)) return 0;

	MEM(head = xlat_exp_head_alloc(ctx));

	/*
	 *	If it's a single attribute reference
	 *	see if it's actually a virtual attribute.
	 */
	if (tmpl_attr_count(vpt) == 1) {
		if (tmpl_is_attr(vpt) && tmpl_da(vpt)->flags.virtual) {
			func = xlat_func_find(tmpl_da(vpt)->name, -1);
			if (!func) {
			unresolved:
				node = xlat_exp_alloc(head, XLAT_VIRTUAL_UNRESOLVED, vpt->name, vpt->len);

				/*
				 *	FIXME - Need a tmpl_copy function to
				 *	the assignment of the tmpl to the new
				 *	xlat expression
				 */
				node->vpt = talloc_move(node, vpt_p);
				node->flags = (xlat_flags_t) { .needs_resolving = true };
				goto done;
			}

		virtual:
			node = xlat_exp_alloc(head, XLAT_VIRTUAL, vpt->name, vpt->len);
			node->vpt = talloc_move(node, vpt_p);
			node->call.func = func;
			node->flags = func->flags;
			goto done;

		} else if (tmpl_is_attr_unresolved(vpt)) {
			func = xlat_func_find(tmpl_attr_unresolved(vpt), -1);
			if (!func) goto unresolved;
			goto virtual;
		}
	}

	node = xlat_exp_alloc(head, XLAT_TMPL, vpt->name, vpt->len);
	node->vpt = talloc_move(node, vpt_p);
	fr_assert(!node->flags.pure);

done:
	xlat_exp_insert_tail(head, node);

	*out = head;
	return 0;
}

/** Copy all nodes in the input list to the output list
 *
 * @param[in] ctx	to allocate new nodes in.
 * @param[out] out	Where to write new nodes.
 * @param[in] in	Input nodes.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_copy(TALLOC_CTX *ctx, xlat_exp_head_t **out, xlat_exp_head_t const *in)
{
	xlat_exp_head_t *head;

	if (!in) {
		*out = NULL;
		return 0;
	}

	MEM(head = xlat_exp_head_alloc(ctx));
	head->flags = in->flags;

	/*
	 *	Copy everything in the list of nodes
	 */
	xlat_exp_foreach(in, p) {
		xlat_exp_t *node;

		MEM(node = xlat_exp_alloc(ctx, p->type, p->fmt, talloc_array_length(p->fmt) - 1));
		node->quote = p->quote;
		node->flags = p->flags;

		switch (p->type) {
		case XLAT_INVALID:
			fr_strerror_printf("Cannot copy xlat node of type \"invalid\"");
		error:
			talloc_free(head);
			return -1;

		case XLAT_BOX:
			if (unlikely(fr_value_box_copy(node, &node->data, &p->data) < 0)) goto error;
			break;

		case XLAT_ONE_LETTER: /* Done with format */
		case XLAT_FUNC_UNRESOLVED:
		case XLAT_VIRTUAL_UNRESOLVED:
			break;

		case XLAT_FUNC:
		case XLAT_VIRTUAL:
			/*
			 *	Only copy the function pointer, and whether this
			 *	is ephemeral.
			 *
			 *	All instance data is specific to the xlat node and
			 *	cannot be duplicated.
			 *
			 *	The node xlat nodes will need to be registered in
			 *	the xlat instantiation table later.
			 */
			node->call.func = p->call.func;
			node->call.ephemeral = p->call.ephemeral;
			if (unlikely(xlat_copy(node, &node->call.args, p->call.args) < 0)) goto error;
			break;

		case XLAT_TMPL:
			node->vpt = tmpl_copy(node, p->vpt);
			continue;

#ifdef HAVE_REGEX
		case XLAT_REGEX:
			node->regex_index = p->regex_index;
			break;
#endif

		case XLAT_ALTERNATE:
			if (unlikely(xlat_copy(node, &node->alternate[0], p->alternate[0]) < 0)) goto error;
			if (unlikely(xlat_copy(node, &node->alternate[1], p->alternate[1]) < 0)) goto error;
			break;

		case XLAT_GROUP:
			if (unlikely(xlat_copy(node, &node->group, p->group) < 0)) goto error;
			break;
		}

		xlat_exp_insert_tail(head, node);
	}

	*out = head;
	return 0;
}
