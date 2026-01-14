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
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/value.h>
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
 * These rules are used to parse literals as arguments to functions.
 *
 * The caller sets the literal parse rules for outside of expansions when they
 * call xlat_tokenize.
 */
static fr_sbuff_parse_rules_t const xlat_function_arg_rules = {
	.escapes = &xlat_unescape,
	.terminals = &FR_SBUFF_TERMS( /* These get merged with other literal terminals */
				L(")"),
				L(","),
		),
};

#ifdef HAVE_REGEX
/** Parse an xlat reference
 *
 * Allows access to a subcapture groups
 * @verbatim %{<num>} @endverbatim
 */
int xlat_tokenize_regex(xlat_exp_head_t *head, xlat_exp_t **out, fr_sbuff_t *in, fr_sbuff_marker_t *m_s)
{
	uint8_t			num;
	xlat_exp_t		*node;
	fr_sbuff_parse_error_t	err;

	XLAT_DEBUG("REGEX <-- %.*s", (int) fr_sbuff_remaining(in), fr_sbuff_current(in));

	/*
	 *	Not a number, ignore it.
	 */
	(void) fr_sbuff_out(&err, &num, in);
	if (err != FR_SBUFF_PARSE_OK) return 0;

	/*
	 *	Not %{\d+}, ignore it.
	 */
	if (!fr_sbuff_is_char(in, '}')) return 0;

	/*
	 *	It is a regex ref, but it has to be a valid one.
	 */
	if (num > REQUEST_MAX_REGEX) {
		fr_strerror_printf("Invalid regex reference.  Must be in range 0-%d", REQUEST_MAX_REGEX);
		fr_sbuff_set(in, m_s);
		return -1;
	}

	MEM(node = xlat_exp_alloc(head, XLAT_REGEX, fr_sbuff_current(m_s), fr_sbuff_behind(m_s)));
	node->regex_index = num;

	*out = node;

	(void) fr_sbuff_advance(in, 1); /* must be '}' */
	return 1;
}
#endif

bool const xlat_func_chars[UINT8_MAX + 1] = {
	SBUFF_CHAR_CLASS_ALPHA_NUM,
	['.'] = true, ['-'] = true, ['_'] = true,
};


/** Normalize an xlat which contains a tmpl.
 *
 *  Constant data is turned into XLAT_BOX, and some other thingies are done.
 */
static int xlat_tmpl_normalize(xlat_exp_t *node)
{
	tmpl_t *vpt = node->vpt;

	/*
	 *	Any casting, etc. has to be taken care of in the xlat expression parser, and not here.
	 */
	fr_assert(tmpl_rules_cast(vpt) == FR_TYPE_NULL);

	if (tmpl_is_attr_unresolved(node->vpt)) {
		return 0;
	}

	/*
	 *	Add in unknown attributes, by defining them in the local dictionary.
	 */
	if (tmpl_is_attr(vpt)) {
		if (tmpl_attr_unknown_add(vpt) < 0) {
			fr_strerror_printf("Failed defining attribute %s", tmpl_attr_tail_da(vpt)->name);
			return -1;
		}

		return 0;
	}

	if (!tmpl_contains_data(vpt)) {
		fr_assert(!tmpl_contains_regex(vpt));
		return 0;
	}

	if (tmpl_is_data_unresolved(vpt) && (tmpl_resolve(vpt, NULL) < 0)) return -1;

	/*
	 *	Hoist data to an XLAT_BOX instead of an XLAT_TMPL
	 */
	fr_assert(tmpl_is_data(vpt));

	/*
	 *	Print "true" and "false" instead of "yes" and "no".
	 */
	if ((tmpl_value_type(vpt) == FR_TYPE_BOOL) && !tmpl_value_enumv(vpt)) {
		tmpl_value_enumv(vpt) = attr_expr_bool_enum;
	}

	/*
	 *	Convert the XLAT_TMPL to XLAT_BOX
	 */
	xlat_exp_set_type(node, XLAT_BOX);

	return 0;
}

/**  Validate and sanity check function arguments.
 *
 */
static int xlat_validate_function_arg(xlat_arg_parser_t const *arg_p, xlat_exp_t *arg, int argc)
{
	xlat_exp_t *node;

	fr_assert(arg->type == XLAT_GROUP);

	/*
	 *	"is_argv" does dual duty.  One, it causes xlat_print() to print spaces in between arguments.
	 *
	 *	Two, it is checked by xlat_frame_eval_repeat(), which then does NOT concatenate strings in
	 *	place.  Instead, it just passes the strings though to xlat_process_arg_list().  Which calls
	 *	xlat_arg_stringify(), and that does the escaping and final concatenation.
	 */
	arg->group->is_argv = (arg_p->func != NULL) | arg_p->will_escape;

	node = xlat_exp_head(arg->group);

	if (!node) {
		if (!arg_p->required) return 0;

		fr_strerror_const("Missing argument");
		return -1;
	}

	/*
	 *	The caller doesn't care about the type, we don't do any validation.
	 */
	if (arg_p->type == FR_TYPE_VOID) return 0;

	/*
	 *	A cursor should be (for now) a named string.
	 */
	if (arg_p->type == FR_TYPE_PAIR_CURSOR) {
		if (node->type == XLAT_BOX) {
		check_box:
			if (node->data.type != FR_TYPE_STRING) {
				fr_strerror_printf("Cursor must be a string attribute reference, not %s",
						   fr_type_to_str(node->data.type));
				return -1;
			}

			return 0;
		}

		/*
		 *	The expression parser should not allow anything else here.
		 */
		fr_assert((node->type == XLAT_TMPL) || (node->type == XLAT_GROUP));

		/*
		 *	Func, etc.
		 */
		if (node->type != XLAT_TMPL) return 0;

		if (tmpl_rules_cast(node->vpt) != FR_TYPE_NULL) {
			fr_strerror_const("Cursor cannot have cast");
			return -1;
		}

		if (xlat_tmpl_normalize(node) < 0) return -1;

		if (node->type == XLAT_BOX) goto check_box;

		if (!tmpl_is_attr(node->vpt)) {
			fr_strerror_printf("Invalid argument - expected attribute reference");
			return -1;
		}

		/*
		 *	Bare attribute references are allowed, but are marked up as "return a cursor to this
		 *	thing, don't return a value".
		 */
		arg->group->cursor = true;
		return 0;
	}

	/*
	 *	An attribute argument results in an FR_TYPE_ATTR box, rather than the value of the attribute
	 */
	if (arg_p->type == FR_TYPE_ATTR) {
		if (node->type != XLAT_TMPL) {
			fr_strerror_printf("Attribute must be a bare word, not %s", fr_type_to_str(node->data.type));
			return -1;
		}

		if (xlat_tmpl_normalize(node) < 0) return -1;

		if (!tmpl_is_attr(node->vpt)) {
			fr_strerror_printf("Invalid argument - expected attribute reference");
			return -1;
		}

		arg->group->is_attr = true;
		return 0;
	}

	/*
	 *	The argument is either ONE tmpl / value-box, OR is an
	 *	xlat group which contains a double-quoted string.
	 */
	fr_assert(fr_dlist_num_elements(&arg->group->dlist) == 1);

	/*
	 *	Do at least somewhat of a pass of normalizing the nodes, even if there are more than one.
	 */
	if (node->type == XLAT_TMPL) {
		return xlat_tmpl_normalize(node);
	}

	/*
	 *	@todo - probably move the double-quoted string "node->flags.constant" check here, to more
	 *	clearly separate parsing from normalization.
	 */

	if (node->type != XLAT_BOX) {
		return 0;
	}

	/*
	 *	If it's the correct data type, then we don't need to do anything.
	 */
	if (arg_p->type == node->data.type) {
		return 0;
	}

	/*
	 *	Cast (or parse) the input data to the expected argument data type.
	 */
	if (fr_value_box_cast_in_place(node, &node->data, arg_p->type, NULL) < 0) {
		fr_strerror_printf("Invalid argument %d - %s", argc, fr_strerror());
		return -1;
	}

	return 0;
}

int xlat_validate_function_args(xlat_exp_t *node)
{
	xlat_arg_parser_t const *arg_p;
	xlat_exp_t		*arg = xlat_exp_head(node->call.args);
	int			i = 1;

	fr_assert(node->type == XLAT_FUNC);

	/*
	 *	Check the function definition against what the user passed in.
	 */
	if (!node->call.func->args) {
		if (node->call.args) {
			fr_strerror_const("Too many arguments to function call, expected 0");
			return -1;
		}

		/*
		 *	Function takes no arguments, and none were passed in.  There's nothing to verify.
		 */
		return 0;
	}

	if (!node->call.args) {
		fr_strerror_const("Too few arguments to function call");
		return -1;
	}

	/*
	 *	The function both has arguments defined, and the user has supplied them.
	 */
	for (arg_p = node->call.func->args, i = 0; arg_p->type != FR_TYPE_NULL; arg_p++) {
		if (!arg_p->required) break;

		if (!arg) {
			fr_strerror_printf("Missing required argument %u",
					   (unsigned int)(arg_p - node->call.func->args) + 1);
			return -1;
		}

		/*
		 *	All arguments MUST be put into a group, even
		 *	if they're just one element.
		 */
		fr_assert(arg->type == XLAT_GROUP);

		if (xlat_validate_function_arg(arg_p, arg, i) < 0) return -1;

		arg = xlat_exp_next(node->call.args, arg);
		i++;
	}

	/*
	 *	@todo - check if there is a trailing argument.  But for functions which take no arguments, the
	 *	"arg" is an empty group.
	 */

	return 0;
}

/** Parse an xlat function and its child argument
 *
 * Parses a function call string in the format
 * @verbatim %<func>(<argument>) @endverbatim
 *
 * @return
 *	- 0 if the string was parsed into a function.
 *	- <0 on parse error.
 */
static CC_HINT(nonnull) int xlat_tokenize_function_args(xlat_exp_head_t *head, fr_sbuff_t *in, tmpl_rules_t const *t_rules)
{
	char c;
	xlat_exp_t *node;
	xlat_t *func;
	fr_sbuff_marker_t m_s;
	tmpl_rules_t my_t_rules;

	fr_sbuff_marker(&m_s, in);

	XLAT_DEBUG("NEW <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	/*
	 *	The caller ensures that the first character after the percent exists, and is alphanumeric.
	 */
	c = fr_sbuff_char(in, '\0');

	/*
	 *	Even if it is alphanumeric, only a limited set of characters are one-letter expansions.
	 *
	 *	And even then only if the character after them is a terminal character.
	 */
	if (strchr("cCdDeGHIlmMnSstTY", c) != NULL) {
		char n;

		fr_sbuff_next(in);

		/*
		 *	End of buffer == one letter expansion.
		 */
		n = fr_sbuff_char(in, '\0');
		if (!n) goto one_letter;

		/*
		 *	%Y() is the new format.
		 */
		if (n == '(') {
			fr_sbuff_next(in);

			if (!fr_sbuff_next_if_char(in, ')')) {
				fr_strerror_const("Missing closing brace ')'");
				return -1;
			}

			goto one_letter;
		}

		/*
		 *	%M. or %Y- is a one-letter expansion followed by the other character.
		 */
		if (!sbuff_char_alpha_num[(unsigned int) n]) {
		one_letter:
			XLAT_DEBUG("ONE-LETTER <-- %c", c);
			node = xlat_exp_alloc_null(head);

			xlat_exp_set_name(node, fr_sbuff_current(&m_s), 1);
			xlat_exp_set_type(node, XLAT_ONE_LETTER); /* needs node->fmt to be set */

			fr_sbuff_marker_release(&m_s);

#ifdef STATIC_ANALYZER
			if (!node->fmt) return -1;
#endif

			xlat_exp_insert_tail(head, node);
			return 0;
		}

		/*
		 *	Anything else, it must be a full function name.
		 */
		fr_sbuff_set(in, &m_s);
	}

	fr_sbuff_adv_past_allowed(in, SIZE_MAX, xlat_func_chars, NULL);

	func = xlat_func_find(fr_sbuff_current(&m_s), fr_sbuff_behind(&m_s));

	if (!fr_sbuff_is_char(in, '(')) {
		fr_strerror_printf("Missing '('");
		return -1;
	}

	/*
	 *	Allocate a node to hold the function
	 */
	node = xlat_exp_alloc(head, XLAT_FUNC, fr_sbuff_current(&m_s), fr_sbuff_behind(&m_s));
	if (!func) {
		if (!t_rules->attr.allow_unresolved|| t_rules->at_runtime) {
			fr_strerror_const("Unresolved expansion functions are not allowed here");
			fr_sbuff_set(in, &m_s);		/* backtrack */
			fr_sbuff_marker_release(&m_s);
			return -1;
		}
		xlat_exp_set_type(node, XLAT_FUNC_UNRESOLVED);

	} else {
		xlat_exp_set_func(node, func, t_rules->attr.dict_def);
	}

	fr_sbuff_marker_release(&m_s);

	(void) fr_sbuff_next(in); /* skip the '(' */

	/*
	 *	The caller might want the _output_ cast to something.  But that doesn't mean we cast each
	 *	_argument_ to the xlat function.
	 */
	if (t_rules->cast != FR_TYPE_NULL) {
		my_t_rules = *t_rules;
		my_t_rules.cast = FR_TYPE_NULL;
		t_rules = &my_t_rules;
	}

	/*
	 *	Now parse the child nodes that form the
	 *	function's arguments.
	 */
	if (xlat_tokenize_argv(node, &node->call.args, in, func ? func->args : NULL,
			       &xlat_function_arg_rules, t_rules, false) < 0) {
	error:
		talloc_free(node);
		return -1;
	}

	if (!fr_sbuff_next_if_char(in, ')')) {
		fr_strerror_const("Missing closing brace ')'");
		goto error;
	}

	xlat_exp_finalize_func(node);

	xlat_exp_insert_tail(head, node);
	return 0;
}

/** Parse an attribute ref or a virtual attribute
 *
 */
static CC_HINT(nonnull(1,2,4)) ssize_t xlat_tokenize_attribute(xlat_exp_head_t *head, fr_sbuff_t *in,
							       fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	tmpl_attr_error_t	err;
	tmpl_t			*vpt = NULL;
	xlat_exp_t		*node;

	fr_sbuff_marker_t	m_s;
	tmpl_rules_t		our_t_rules;
	fr_sbuff_t		our_in = FR_SBUFF(in);

	XLAT_DEBUG("ATTRIBUTE <-- %.*s", (int) fr_sbuff_remaining(in), fr_sbuff_current(in));

	/*
	 *	We are called from %{foo}.  So we don't use attribute prefixes.
	 */
	our_t_rules = *t_rules;
	our_t_rules.attr.allow_wildcard = true;

	fr_sbuff_marker(&m_s, in);

	MEM(node = xlat_exp_alloc_null(head));
	if (tmpl_afrom_attr_substr(node, &err, &vpt, &our_in, p_rules, &our_t_rules) < 0) {
		/*
		 *	If the parse error occurred before a terminator,
		 *	then the error is changed to 'Unknown module',
		 *	as it was more likely to be a bad module name,
		 *	than a request qualifier.
		 */
		if (err == TMPL_ATTR_ERROR_MISSING_TERMINATOR) fr_sbuff_set(&our_in, &m_s);
	error:
		fr_sbuff_marker_release(&m_s);
		talloc_free(node);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	Deal with unresolved attributes.
	 */
	if (tmpl_is_attr_unresolved(vpt)) {
		if (!t_rules->attr.allow_unresolved) {
			talloc_free(vpt);

			fr_strerror_const("Unresolved attributes not allowed in expansions here");
			fr_sbuff_set(&our_in, &m_s);		/* Error at the start of the attribute */
			goto error;
		}
	}

	/*
	 *	Deal with normal attribute (or list)
	 */
	xlat_exp_set_type(node, XLAT_TMPL);
	xlat_exp_set_vpt(node, vpt);

	/*
	 *	Remember that it was %{User-Name}
	 *
	 *	This is a temporary hack until all of the unit tests
	 *	pass without '&'.
	 */
	UNCONST(tmpl_attr_rules_t *, &vpt->rules.attr)->xlat = true;

	xlat_exp_insert_tail(head, node);

	fr_sbuff_marker_release(&m_s);
	return fr_sbuff_set(in, &our_in);
}

static bool const tmpl_attr_allowed_chars[UINT8_MAX + 1] = {
	SBUFF_CHAR_CLASS_ALPHA_NUM,
	['-'] = true, ['/'] = true, ['_'] = true,			// fr_dict_attr_allowed_chars
	['.'] = true, ['*'] = true, ['#'] = true,
	['['] = true, [']'] = true, 					// tmpls and attribute arrays
};

static CC_HINT(nonnull(1,2)) int xlat_tokenize_expansion(xlat_exp_head_t *head, fr_sbuff_t *in,
							 tmpl_rules_t const *t_rules)
{
	size_t			len;
	int			ret;
	fr_sbuff_marker_t	m_s;
	char			hint;
	fr_sbuff_term_t		hint_tokens = FR_SBUFF_TERMS(
					L(" "),		/* First special token is a ' ' - Likely a syntax error */
					L("["),		/* First special token is a '[' i.e. '%{attr[<idx>]}' */
					L("}")		/* First special token is a '}' i.e. '%{<attrref>}' */
				);

	fr_sbuff_parse_rules_t	attr_p_rules = {
					.escapes = &xlat_unescape,
					.terminals = &FR_SBUFF_TERM("}")
				};
#ifdef HAVE_REGEX
	xlat_exp_t		*node;
#endif

	XLAT_DEBUG("EXPANSION <-- %.*s", (int) fr_sbuff_remaining(in), fr_sbuff_current(in));

	fr_sbuff_marker(&m_s, in);

#ifdef HAVE_REGEX
	ret = xlat_tokenize_regex(head, &node, in, &m_s);
	if (ret < 0) return ret;

	if (ret == 1) {
		fr_assert(node != NULL);
		xlat_exp_insert_tail(head, node);
		return 0;
	}

	fr_sbuff_set(in, &m_s);		/* backtrack to the start of the expression */
#endif /* HAVE_REGEX */

	/*
	 *	See if it's an attribute reference, with possible array stuff.
	 */
	len = fr_sbuff_adv_past_allowed(in, SIZE_MAX, tmpl_attr_allowed_chars, NULL);
	if (fr_sbuff_is_char(in, '}')) {
		if (!len) goto empty_disallowed;
		goto check_for_attr;
	}

	if (!fr_sbuff_extend(in)) {
		fr_strerror_const("Missing closing brace '}'");
		fr_sbuff_marker_release(&m_s);
		return -1;
	}

	/*
	 *	It must be an expression.
	 *
	 *	We wrap the xlat in a group, and then mark the group to be hoisted.
	 */
	{
		tmpl_rules_t my_rules;

		fr_sbuff_set(in, &m_s);		/* backtrack to the start of the expression */

		MEM(node = xlat_exp_alloc(head, XLAT_GROUP, NULL, 0));

		if (t_rules) {
			my_rules = *t_rules;
			my_rules.enumv = NULL;
			my_rules.cast = FR_TYPE_NULL;
			t_rules = &my_rules;
		}

		ret = xlat_tokenize_expression(node, &node->group, in, &attr_p_rules, t_rules);
		if (ret <= 0) {
			talloc_free(node);
			return ret;
		}

		if (!fr_sbuff_is_char(in, '}')) {
			fr_strerror_const("Missing closing brace '}'");
			return -1;
		}

		xlat_exp_set_name(node, fr_sbuff_current(&m_s), fr_sbuff_behind(&m_s));
		node->flags = node->group->flags;

		/*
		 *	Print it as %{...}.  Then when we're evaluating a string, hoist the results.
		 */
		node->flags.xlat = true;
		node->hoist = true;

		xlat_exp_insert_tail(head, node);

		(void) fr_sbuff_next(in); /* skip '}' */
		return ret;
	}

check_for_attr:
	fr_sbuff_set(in, &m_s);		/* backtrack */

	/*
	 *	%{Attr-Name}
	 *	%{Attr-Name[#]}
	 *	%{request.Attr-Name}
	 */

	/*
	 *	Check for empty expressions %{} %{: %{[
	 */
	fr_sbuff_marker(&m_s, in);
	len = fr_sbuff_adv_until(in, SIZE_MAX, &hint_tokens, '\0');

	/*
	 *      This means the end of a string not containing any of the other
	 *	tokens was reached.
	 *
	 *	e.g. '%{myfirstxlat'
	 */
	if (!fr_sbuff_extend(in)) {
		fr_strerror_const("Missing closing brace '}'");
		fr_sbuff_marker_release(&m_s);
		return -1;
	}

	hint = fr_sbuff_char(in, '\0');

	XLAT_DEBUG("EXPANSION HINT TOKEN '%c'", hint);
	if (len == 0) {
		switch (hint) {
		case '}':
		empty_disallowed:
			fr_strerror_const("Empty expressions are invalid");
			return -1;

		case '[':
			fr_strerror_const("Missing attribute name");
			return -1;

		default:
			break;
		}
	}

	switch (hint) {
	/*
	 *	Hint token is a:
	 *	- '[' - Which is an attribute index, so it must be an attribute.
	 *      - '}' - The end of the expansion, which means it was a bareword.
	 */
	case '.':
	case '}':
	case '[':
		fr_sbuff_set(in, &m_s);		/* backtrack */
		fr_sbuff_marker_release(&m_s);

		if (xlat_tokenize_attribute(head, in, &attr_p_rules, t_rules) < 0) return -1;

		if (!fr_sbuff_next_if_char(in, '}')) {
			fr_strerror_const("Missing closing brace '}'");
			return -1;
		}

		return 0;

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
 * @param[out] head		to allocate nodes in, and where to write the first
 *				child, and where the flags are stored.
 * @param[in] in		sbuff to parse.
 * @param[in] p_rules		that control parsing.
 * @param[in] t_rules		that control attribute reference and xlat function parsing.
 * @return
 *	- <0 on failure
 *	- >=0 for number of bytes parsed
 */
static CC_HINT(nonnull(1,2,4)) ssize_t xlat_tokenize_input(xlat_exp_head_t *head, fr_sbuff_t *in,
							   fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	xlat_exp_t			*node = NULL;
	fr_slen_t			slen;
	fr_sbuff_term_t			terminals = FR_SBUFF_TERMS(
						L("%"),
					);
	fr_sbuff_term_t			*tokens;
	fr_sbuff_unescape_rules_t const	*escapes;
	fr_sbuff_t			our_in = FR_SBUFF(in);

	XLAT_DEBUG("STRING <-- %.*s", (int) fr_sbuff_remaining(in), fr_sbuff_current(in));

	escapes = p_rules ? p_rules->escapes : NULL;
	tokens = p_rules && p_rules->terminals ?
			fr_sbuff_terminals_amerge(NULL, p_rules->terminals, &terminals) : &terminals;

	for (;;) {
		char *str;
		fr_sbuff_marker_t m_s;

		/*
		 *	pre-allocate the node so we don't have to steal it later.
		 */
		node = xlat_exp_alloc(head, XLAT_BOX, NULL, 0);

		/*
		 *	Find the next token
		 */
		fr_sbuff_marker(&m_s, &our_in);
		slen = fr_sbuff_out_aunescape_until(node, &str, &our_in, SIZE_MAX, tokens, escapes);

		if (slen < 0) {
		error:
			talloc_free(node);

			/*
			 *	Free our temporary array of terminals
			 */
			if (tokens != &terminals) talloc_free(tokens);
			fr_sbuff_marker_release(&m_s);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		/*
		 *	It's a value box, create an appropriate node
		 */
		if (slen > 0) {
		do_value_box:
			xlat_exp_set_name_shallow(node, str);
			fr_value_box_bstrndup(node, &node->data, NULL, str, talloc_array_length(str) - 1, false);
			fr_value_box_mark_safe_for(&node->data, t_rules->literals_safe_for);

			if (!escapes) {
				XLAT_DEBUG("VALUE-BOX %s <-- %.*s", str,
					   (int) fr_sbuff_behind(&m_s), fr_sbuff_current(&m_s));
			} else {
				XLAT_DEBUG("VALUE-BOX (%s) %s <-- %.*s", escapes->name, str,
					   (int) fr_sbuff_behind(&m_s), fr_sbuff_current(&m_s));
			}
			XLAT_HEXDUMP((uint8_t const *)str, talloc_array_length(str) - 1, " VALUE-BOX ");

			xlat_exp_insert_tail(head, node);

			node = NULL;
			fr_sbuff_marker_release(&m_s);
			continue;
		}

		/*
		 *	We have parsed as much as we can as unescaped
		 *	input.  Either some text (and added the node
		 *	to the list), or zero text.  We now try to
		 *	parse '%' expansions.
		 */

		/*
		 *	Attribute, function call, or other expansion.
		 */
		if (fr_sbuff_adv_past_str_literal(&our_in, "%{")) {
			TALLOC_FREE(node); /* nope, couldn't use it */

			if (xlat_tokenize_expansion(head, &our_in, t_rules) < 0) goto error;

			if (fr_sbuff_is_str_literal(&our_in, ":-")) {
				fr_strerror_const("Old style alternation of %{...:-...} is no longer supported");
				goto error;
			}

		next:
			fr_sbuff_marker_release(&m_s);
			continue;
		}

		/*
		 *	More migration hacks: allow %foo(...)
		 */
		if (fr_sbuff_next_if_char(&our_in, '%')) {
			/*
			 *	% non-alphanumeric, create a value-box for just the "%" character.
			 */
			if (!fr_sbuff_is_alnum(&our_in)) {
				if (fr_sbuff_next_if_char(&our_in, '%')) { /* nothing */ }

				str = talloc_typed_strdup(node, "%");
				goto do_value_box;
			}

			TALLOC_FREE(node); /* nope, couldn't use it */

			/*
			 *	Tokenize the function arguments using the new method.
			 */
			if (xlat_tokenize_function_args(head, &our_in, t_rules) < 0) goto error;
			goto next;
		}

		/*
		 *	Nothing we recognize.  Just return nothing.
		 */
		TALLOC_FREE(node);
		XLAT_DEBUG("VALUE-BOX <-- (empty)");
		fr_sbuff_marker_release(&m_s);
		break;
	}

	/*
	 *	Free our temporary array of terminals
	 */
	if (tokens != &terminals) talloc_free(tokens);

	return fr_sbuff_set(in, &our_in);
}

static fr_table_num_sorted_t const xlat_quote_table[] = {
	{ L("\""),	T_DOUBLE_QUOTED_STRING	},	/* Don't re-order, backslash throws off ordering */
	{ L("'"),	T_SINGLE_QUOTED_STRING	},
	{ L("`"),	T_BACK_QUOTED_STRING	}
};
static size_t xlat_quote_table_len = NUM_ELEMENTS(xlat_quote_table);

#define INFO_INDENT(_fmt, ...)  INFO("%*s"_fmt, depth * 2, " ", ## __VA_ARGS__)

static void _xlat_debug_head(xlat_exp_head_t const *head, int depth);
static void _xlat_debug_node(xlat_exp_t const *node, int depth, bool print_flags)
{
	INFO_INDENT("{ -- %s", node->fmt);
#ifndef NDEBUG
//	INFO_INDENT("  %s:%d", node->file, node->line);
#endif

	if (print_flags) {
		INFO_INDENT("flags = %s %s %s %s %s",
			    node->flags.needs_resolving ? "need_resolving" : "",
			    node->flags.pure ? "pure" : "",
			    node->flags.can_purify ? "can_purify" : "",
			    node->flags.constant ? "constant" : "",
			    node->flags.xlat ? "xlat" : "");
	}

	depth++;

	if (node->quote != T_BARE_WORD) INFO_INDENT("quote = %c", fr_token_quote[node->quote]);

	switch (node->type) {
	case XLAT_BOX:
		INFO_INDENT("value %s --> %pV", fr_type_to_str(node->data.type), &node->data);
		break;

	case XLAT_GROUP:
		INFO_INDENT("group");
		INFO_INDENT("{");
		_xlat_debug_head(node->group, depth + 1);
		INFO_INDENT("}");
		break;

	case XLAT_ONE_LETTER:
		INFO_INDENT("percent (%c)", node->fmt[0]);
		break;

	case XLAT_TMPL:
	{
		if (tmpl_cast_get(node->vpt) != FR_TYPE_NULL) {
			INFO_INDENT("cast (%s)", fr_type_to_str(tmpl_cast_get(node->vpt)));
		}

		if (tmpl_is_attr(node->vpt)) {
			fr_assert(!node->flags.pure);
			if (tmpl_attr_tail_da(node->vpt)) INFO_INDENT("tmpl attribute (%s)", tmpl_attr_tail_da(node->vpt)->name);
			if (tmpl_attr_tail_num(node->vpt) != NUM_UNSPEC) {
				FR_DLIST_HEAD(tmpl_request_list) const *list;
				tmpl_request_t *rr = NULL;

				INFO_INDENT("{");

				/*
				 *	Loop over the request references
				 */
				list = tmpl_request(node->vpt);
				while ((rr = tmpl_request_list_next(list, rr))) {
					INFO_INDENT("ref  %u", rr->request);
				}
				INFO_INDENT("list %s", tmpl_list_name(tmpl_list(node->vpt), "<INVALID>"));
				if (tmpl_attr_tail_num(node->vpt) != NUM_UNSPEC) {
					if (tmpl_attr_tail_num(node->vpt) == NUM_COUNT) {
						INFO_INDENT("[#]");
					} else if (tmpl_attr_tail_num(node->vpt) == NUM_ALL) {
						INFO_INDENT("[*]");
					} else {
						INFO_INDENT("[%d]", tmpl_attr_tail_num(node->vpt));
					}
				}
				INFO_INDENT("}");
			}
		} else if (tmpl_is_data(node->vpt)) {
			INFO_INDENT("tmpl (%s) type %s", node->fmt, fr_type_to_str(tmpl_value_type(node->vpt)));

		} else if (tmpl_is_xlat(node->vpt)) {
			INFO_INDENT("tmpl xlat (%s)", node->fmt);
			_xlat_debug_head(tmpl_xlat(node->vpt), depth + 1);

		} else {
			INFO_INDENT("tmpl (%s)", node->fmt);
		}
	}
		break;

	case XLAT_FUNC:
		fr_assert(node->call.func != NULL);
		INFO_INDENT("func (%s)", node->call.func->name);
		if (xlat_exp_head(node->call.args)) {
			INFO_INDENT("{");
			_xlat_debug_head(node->call.args, depth + 1);
			INFO_INDENT("}");
		}
		break;

	case XLAT_FUNC_UNRESOLVED:
		INFO_INDENT("func-unresolved (%s)", node->fmt);
		if (xlat_exp_head(node->call.args)) {
			INFO_INDENT("{");
			_xlat_debug_head(node->call.args, depth + 1);
			INFO_INDENT("}");
		}
		break;

#ifdef HAVE_REGEX
	case XLAT_REGEX:
		INFO_INDENT("regex-var -- %d", node->regex_index);
		break;
#endif

	case XLAT_INVALID:
		DEBUG("XLAT-INVALID");
		break;
	}

	depth--;
	INFO_INDENT("}");
}

void xlat_debug(xlat_exp_t const *node)
{
	_xlat_debug_node(node, 0, true);
}

static void _xlat_debug_head(xlat_exp_head_t const *head, int depth)
{
	int i = 0;

	fr_assert(head != NULL);

	INFO_INDENT("head flags = %s %s %s %s %s",
		    head->flags.needs_resolving ? "need_resolving," : "",
		    head->flags.pure ? "pure" : "",
		    head->flags.can_purify ? "can_purify" : "",
		    head->flags.constant ? "constant" : "",
		    head->flags.xlat ? "xlat" : "");

	depth++;

	xlat_exp_foreach(head, node) {
		INFO_INDENT("[%d] flags = %s %s %s %s %s", i++,
			    node->flags.needs_resolving ? "need_resolving" : "",
			    node->flags.pure ? "pure" : "",
			    node->flags.can_purify ? "can_purify" : "",
			    node->flags.constant ? "constant" : "",
			    node->flags.xlat ? "xlat" : "");

		_xlat_debug_node(node, depth, false);
	}
}

void xlat_debug_head(xlat_exp_head_t const *head)
{
	_xlat_debug_head(head, 0);
}

ssize_t xlat_print_node(fr_sbuff_t *out, xlat_exp_head_t const *head, xlat_exp_t const *node,
			fr_sbuff_escape_rules_t const *e_rules, char c)
{
	ssize_t			slen;
	size_t			at_in = fr_sbuff_used_total(out);
	char			close;

	if (!node) return 0;

	if (node->flags.xlat) FR_SBUFF_IN_CHAR_RETURN(out, '%', '{');

	switch (node->type) {
	case XLAT_GROUP:
		if (node->quote != T_BARE_WORD) FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->quote]);
		xlat_print(out, node->group, fr_value_escape_by_quote[node->quote]);
		if (node->quote != T_BARE_WORD) FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->quote]);

		if (xlat_exp_next(head, node)) {
			if (c) FR_SBUFF_IN_CHAR_RETURN(out, c);

			if (head->is_argv) FR_SBUFF_IN_CHAR_RETURN(out, ' ');      /* Add ' ' between args */
		}
		goto done;

	case XLAT_BOX:
		/*
		 *	@todo - respect node->quote here, too.  Which also means updating the parser.
		 */
		if (node->quote == T_BARE_WORD) {
			if (node->data.enumv &&
			    (strncmp(node->fmt, "::", 2) == 0)) {
				FR_SBUFF_IN_STRCPY_LITERAL_RETURN(out, "::");
			}

			FR_SBUFF_RETURN(fr_value_box_print, out, &node->data, e_rules);
		} else {
			FR_SBUFF_RETURN(fr_value_box_print_quoted, out, &node->data, node->quote);
		}
		goto done;

	case XLAT_TMPL:
		if (node->vpt->rules.cast != FR_TYPE_NULL) {
			FR_SBUFF_IN_CHAR_RETURN(out, '(');
			FR_SBUFF_IN_STRCPY_RETURN(out, fr_type_to_str(node->vpt->rules.cast));
			FR_SBUFF_IN_CHAR_RETURN(out, ')');
		}

		if (tmpl_is_data(node->vpt)) {
			/*
			 *	Manually add enum prefix when printing.
			 */
			if (node->vpt->data.literal.enumv &&
			    ((node->vpt->data.literal.type != FR_TYPE_BOOL) || da_is_bit_field(node->vpt->data.literal.enumv)) &&
			    (strncmp(node->fmt, "::", 2) == 0)) {
				FR_SBUFF_IN_CHAR_RETURN(out, ':', ':');
			}
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

		if (tmpl_contains_xlat(node->vpt)) { /* xlat and exec */
			if (node->vpt->quote == T_BARE_WORD) {
				xlat_print(out, tmpl_xlat(node->vpt), NULL);
			} else {
				FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->vpt->quote]);
				xlat_print(out, tmpl_xlat(node->vpt), fr_value_escape_by_quote[node->quote]);
				FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->vpt->quote]);
			}
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
		fr_assert(tmpl_is_attr(node->vpt));
		fr_assert(talloc_parent(node->vpt) == node);
		fr_assert(!node->flags.pure);

		/*
		 *	No '&', print the name, BUT without any attribute prefix.
		 */
		if (!node->vpt->rules.attr.xlat) {
			char const *p = node->fmt;

			if (*p == '&') p++;

			FR_SBUFF_IN_STRCPY_RETURN(out, p);
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
	if ((node->type == XLAT_FUNC) || (node->type == XLAT_FUNC_UNRESOLVED)) {
		FR_SBUFF_IN_CHAR_RETURN(out, '%'); /* then the name */
		close = ')';
	} else {
		FR_SBUFF_IN_STRCPY_LITERAL_RETURN(out, "%{");
		close = '}';
	}

	switch (node->type) {
	case XLAT_TMPL:
		slen = tmpl_attr_print(out, node->vpt);
		if (slen < 0) return slen;
		break;

#ifdef HAVE_REGEX
	case XLAT_REGEX:
		FR_SBUFF_IN_SPRINTF_RETURN(out, "%i", node->regex_index);
		break;
#endif

	case XLAT_FUNC:
		FR_SBUFF_IN_BSTRCPY_BUFFER_RETURN(out, node->call.func->name);
		FR_SBUFF_IN_CHAR_RETURN(out, '(');

		goto print_args;

	case XLAT_FUNC_UNRESOLVED:
		FR_SBUFF_IN_BSTRCPY_BUFFER_RETURN(out, node->fmt);
		FR_SBUFF_IN_CHAR_RETURN(out, '(');

	print_args:
		if (xlat_exp_head(node->call.args)) {
			xlat_exp_foreach(node->call.args, child) {
				slen = xlat_print_node(out, node->call.args, child, &xlat_escape, ',');
				if (slen < 0) return slen;
			}
		}
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
	if (node->flags.xlat) FR_SBUFF_IN_CHAR_RETURN(out, '}');

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
		slen = xlat_print_node(out, head, node, e_rules, 0);
		if (slen < 0) {
			/* coverity[return_overflow] */
			return slen - (fr_sbuff_used_total(out) - at_in);
		}
	}

	return fr_sbuff_used_total(out) - at_in;
}

#if 0
static void xlat_safe_for(xlat_exp_head_t *head, fr_value_box_safe_for_t safe_for)
{
	xlat_exp_foreach(head, node) {
		switch (node->type) {
		case XLAT_BOX:
			if (node->data.safe_for != safe_for) {
				ERROR("FAILED %lx %lx - %s", node->data.safe_for, safe_for, node->fmt);
			}
			fr_assert(node->data.safe_for == safe_for);
			break;

		case XLAT_GROUP:
			xlat_safe_for(node->group, safe_for);
			break;

		case XLAT_TMPL:
			if (!tmpl_is_xlat(node->vpt)) break;

			xlat_safe_for(tmpl_xlat(node->vpt), safe_for);
			break;

		default:
			break;
		}
	}
}
#endif


fr_slen_t xlat_tokenize_word(TALLOC_CTX *ctx, xlat_exp_t **out, fr_sbuff_t *in, fr_token_t quote,
			     fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	int		triple = 1;
	ssize_t		slen;
	fr_sbuff_t	our_in = FR_SBUFF(in);
	xlat_exp_t	*node;
	fr_sbuff_marker_t m;

	/*
	 *	Triple-quoted strings have different terminal conditions.
	 */
	switch (quote) {
	case T_SOLIDUS_QUOTED_STRING:
		fr_strerror_const("Unexpected regular expression");
		fr_sbuff_advance(in, -1); /* to the actual '/' */
		our_in = FR_SBUFF(in);
		FR_SBUFF_ERROR_RETURN(&our_in);

	default:
		fr_assert(0);
		FR_SBUFF_ERROR_RETURN(&our_in);

	case T_BARE_WORD:
#ifdef HAVE_REGEX
		fr_sbuff_marker(&m, &our_in);

		/*
		 *	Regular expression expansions are %{...}
		 */
		if (fr_sbuff_adv_past_str_literal(&our_in, "%{")) {
			int ret;
			fr_sbuff_marker_t m_s;

			fr_sbuff_marker(&m_s, &our_in);

			ret = xlat_tokenize_regex(ctx, &node, &our_in, &m_s);
			if (ret < 0) FR_SBUFF_ERROR_RETURN(&our_in);

			if (ret == 1) goto done;

			fr_sbuff_set(&our_in, &m);
		}
#endif /* HAVE_REGEX */

#if 0
		/*
		 *	Avoid a bounce through tmpls for %{...} and %func()
		 *
		 *	@todo	%{...}	  --> tokenize expression
		 *		%foo(..)  --> tokenize_function_args (and have that function look for ()
		 *		%Y or %Y() --> one letter
		 */
		if (fr_sbuff_is_char(&our_in, '%')) {
			xlat_exp_head_t *head = NULL;

			MEM(head = xlat_exp_head_alloc(ctx));

			slen = xlat_tokenize_input(head, &our_in, p_rules, t_rules);
			if (slen <= 0) {
				talloc_free(head);
				FR_SBUFF_ERROR_RETURN(&our_in);
			}

			fr_assert(fr_dlist_num_elements(&head->dlist) == 1);

			node = fr_dlist_pop_head(&head->dlist);
			fr_assert(node != NULL);
			(void) talloc_steal(ctx, node);
			talloc_free(head);
			goto done;
		}
#endif
		break;

	case T_DOUBLE_QUOTED_STRING:
	case T_SINGLE_QUOTED_STRING:
	case T_BACK_QUOTED_STRING:
		p_rules = value_parse_rules_quoted[quote];

		if (fr_sbuff_remaining(&our_in) >= 2) {
			char const *p = fr_sbuff_current(&our_in);
			char c = fr_token_quote[quote];

			/*
			 *	"""foo "quote" and end"""
			 */
			if ((p[0] == c) && (p[1] == c)) {
				triple = 3;
				(void) fr_sbuff_advance(&our_in, 2);
				p_rules = value_parse_rules_3quoted[quote];
			}
		}
		break;
	}

	switch (quote) {
		/*
		 *	`foo` is a tmpl, and is NOT a group.
		 */
	case T_BACK_QUOTED_STRING:
	case T_BARE_WORD:
		MEM(node = xlat_exp_alloc(ctx, XLAT_TMPL, NULL, 0));
		node->quote = quote;

		/*
		 *	tmpl_afrom_substr does pretty much all the work of
		 *	parsing the operand.  It pays attention to the cast on
		 *	our_t_rules, and will try to parse any data there as
		 *	of the correct type.
		 */
		slen = tmpl_afrom_substr(node, &node->vpt, &our_in, quote, p_rules, t_rules);
		if (slen <= 0) {
			fr_sbuff_advance(&our_in, -slen - 1); /* point to the correct offset */

		error:
			talloc_free(node);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}
		xlat_exp_set_vpt(node, node->vpt); /* sets flags */

		if (xlat_tmpl_normalize(node) < 0) goto error;

		if (quote == T_BARE_WORD) goto done;

		break;		/* exec - look for closing quote */

		/*
		 *	"Double quoted strings may contain %{expansions}"
		 */
	case T_DOUBLE_QUOTED_STRING:
		MEM(node = xlat_exp_alloc(ctx, XLAT_GROUP, NULL, 0));
		node->quote = quote;

		fr_sbuff_marker(&m, &our_in);
		XLAT_DEBUG("ARGV double quotes <-- %.*s", (int) fr_sbuff_remaining(&our_in), fr_sbuff_current(&our_in));

		if (xlat_tokenize_input(node->group, &our_in, p_rules, t_rules) < 0) goto error;

		node->flags = node->group->flags;
		node->hoist = true;
		xlat_exp_set_name(node, fr_sbuff_current(&m), fr_sbuff_behind(&m));

		/*
		 *	There's no expansion in the string.  Hoist the value-box.
		 */
		if (node->flags.constant) {
			xlat_exp_t *child;

			/*
			 *	The list is either empty, or else it has one child, which is the constant
			 *	node.
			 */
			if (fr_dlist_num_elements(&node->group->dlist) == 0) {
				xlat_exp_set_type(node, XLAT_BOX);

				fr_value_box_init(&node->data, FR_TYPE_STRING, NULL, false);
				fr_value_box_strdup(node, &node->data, NULL, "", false);

			} else {
				fr_assert(fr_dlist_num_elements(&node->group->dlist) == 1);

				child = talloc_steal(ctx, xlat_exp_head(node->group));
				talloc_free(node);
				node = child;
			}

			fr_assert(node->type == XLAT_BOX);

			node->quote = quote; /* not the same node! */
		}
		break;

		/*
		 *	'Single quoted strings get parsed as literal strings'
		 */
	case T_SINGLE_QUOTED_STRING:
	{
		char		*str;

		XLAT_DEBUG("ARGV single quotes <-- %.*s", (int) fr_sbuff_remaining(&our_in), fr_sbuff_current(&our_in));

		node = xlat_exp_alloc(ctx, XLAT_BOX, NULL, 0);
		node->quote = quote;

		slen = fr_sbuff_out_aunescape_until(node, &str, &our_in, SIZE_MAX, p_rules->terminals, p_rules->escapes);
		if (slen < 0) goto error;

		xlat_exp_set_name_shallow(node, str);
		fr_value_box_strdup(node, &node->data, NULL, str, false);
		fr_value_box_mark_safe_for(&node->data, t_rules->literals_safe_for);	/* Literal values are treated as implicitly safe */
	}
		break;

	default:
		fr_strerror_const("Internal sanity check failed in tokenizing expansion word");
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	Ensure that the string ends with the correct number of quotes.
	 */
	do {
		if (!fr_sbuff_is_char(&our_in, fr_token_quote[quote])) {
			fr_strerror_const("Unterminated string");
			fr_sbuff_set_to_start(&our_in);
			goto error;
		}

		fr_sbuff_advance(&our_in, 1);
	} while (--triple > 0);

done:
	*out = node;

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
 * @param[in] xlat_args		the arguments
 * @param[in] p_rules		controlling how to parse the string outside of
 *				any expansions.
 * @param[in] t_rules		controlling how attribute references are parsed.
 * @param[in] spaces		whether the arguments are delimited by spaces
 * @return
 *	- < 0 on error.
 *	- >0  on success which is the number of characters parsed.
 */
fr_slen_t xlat_tokenize_argv(TALLOC_CTX *ctx, xlat_exp_head_t **out, fr_sbuff_t *in,
			     xlat_arg_parser_t const *xlat_args,
			     fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules, bool spaces)
{
	int				argc;
	fr_sbuff_t			our_in = FR_SBUFF(in);
	ssize_t				slen;
	fr_sbuff_marker_t		m;
	fr_sbuff_parse_rules_t const	*our_p_rules;		/* Bareword parse rules */
	fr_sbuff_parse_rules_t		tmp_p_rules;
	xlat_exp_head_t			*head;
	xlat_arg_parser_t const		*arg = NULL, *arg_start;
	tmpl_rules_t			arg_t_rules;

	if (xlat_args) {
		arg_start = arg = xlat_args;	/* Track the arguments as we parse */
	} else {
		static xlat_arg_parser_t const	default_arg[] = { { .variadic = XLAT_ARG_VARIADIC_EMPTY_SQUASH, .type = FR_TYPE_VOID  },
								  XLAT_ARG_PARSER_TERMINATOR };
		arg_start = arg = &default_arg[0];
	}
	arg_t_rules = *t_rules;

	if (unlikely(spaces)) {
		fr_assert(p_rules != &xlat_function_arg_rules);
		if (p_rules) {	/* only for tmpl_tokenize, and back-ticks */
			fr_assert(p_rules->terminals);

			tmp_p_rules = (fr_sbuff_parse_rules_t){	/* Stack allocated due to CL scope */
				.terminals = fr_sbuff_terminals_amerge(NULL, p_rules->terminals,
								       value_parse_rules_bareword_quoted.terminals),
				.escapes = (p_rules->escapes ? p_rules->escapes : value_parse_rules_bareword_quoted.escapes)
			};
			our_p_rules = &tmp_p_rules;
		} else {
			our_p_rules = &value_parse_rules_bareword_quoted;
		}

	} else {
		if (!p_rules) {
			p_rules = &xlat_function_arg_rules;
		} else {
			fr_assert(p_rules == &xlat_function_arg_rules);
		}
		fr_assert(p_rules->terminals);

		our_p_rules = p_rules;

		/*
		 *	The arguments to a function are NOT the output data type of the function.
		 *
		 *	We do NOT check for quotation characters.  We DO update t_rules to strip any casts.  The
		 *	OUTPUT of the function is cast to the relevant data type, but each ARGUMENT is just an
		 *	expression with no given data type.  Parsing the expression is NOT done with the cast of
		 *	arg->type, as that means each individual piece of the expression is parsed as the type.  We
		 *	have to cast on the final _output_ of the expression, and we allow the _input_ pieces of the
		 *	expression to be just about anything.
		 */
		arg_t_rules.enumv = NULL;
		arg_t_rules.cast = FR_TYPE_NULL;
		arg_t_rules.attr.namespace = NULL;
		arg_t_rules.attr.request_def = NULL;
		arg_t_rules.attr.list_def = request_attr_request;
		arg_t_rules.attr.list_presence = TMPL_ATTR_LIST_ALLOW;
	}

	MEM(head = xlat_exp_head_alloc(ctx));

	/*
	 *	skip spaces at the beginning as we don't want them to become a whitespace literal.
	 */
	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);
	fr_sbuff_marker(&m, &our_in);
	argc = 1;

	while (fr_sbuff_extend(&our_in)) {
		xlat_exp_t	*node = NULL;
		fr_token_t	quote;
		size_t		len;

		arg_t_rules.literals_safe_for = arg->safe_for;

		fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);
		fr_sbuff_set(&m, &our_in);	/* Record start of argument */

		MEM(node = xlat_exp_alloc(ctx, XLAT_GROUP, NULL, 0)); /* quote = T_BARE_WORD */

		if (likely(!spaces)) {
			/*
			 *	We've reached the end of the arguments, don't try to tokenize anything else.
			 */
			if (fr_sbuff_is_char(&our_in, ')')) {
				slen = 0;

			} else {
				/*
				 *	Parse a full expression as an argv, all the way to a terminal character.
				 *	We use the input parse rules here.
				 */
				slen = xlat_tokenize_expression(node, &node->group, &our_in, our_p_rules, &arg_t_rules);
			}
		} else {
			fr_sbuff_out_by_longest_prefix(&slen, &quote, xlat_quote_table, &our_in, T_BARE_WORD);

			node->quote = quote;

			if (quote == T_BARE_WORD) {
				/*
				 *	Each argument is a bare word all by itself, OR an xlat thing all by itself.
				 */
				slen = xlat_tokenize_input(node->group, &our_in, our_p_rules, &arg_t_rules);

			} else {
				xlat_exp_t *child = NULL;

				slen = xlat_tokenize_word(node->group, &child, &our_in, quote, our_p_rules, &arg_t_rules);
				if (child) {
					fr_assert(slen > 0);

					xlat_exp_insert_tail(node->group, child);
				}
			}
		}

		if (slen < 0) {
		error:
			if (our_p_rules == &tmp_p_rules) talloc_const_free(our_p_rules->terminals);
			talloc_free(head);

			FR_SBUFF_ERROR_RETURN(&our_in);	/* error */
		}
		fr_assert(node != NULL);

		/*
		 *	No data, but the argument was required.  Complain.
		 */
		if (!slen && arg->required) {
			fr_strerror_printf("Missing required arg %u", argc);
			goto error;
		}

		fr_assert(node->type == XLAT_GROUP);
		node->flags = node->group->flags;

		/*
		 *	Check number of arguments.
		 */
		if (arg->type == FR_TYPE_NULL) {
			fr_strerror_printf("Too many arguments, expected %zu, got %d",
					   (size_t) (arg - arg_start), argc);
			fr_sbuff_set(&our_in, &m);
			goto error;
		}

		if (!node->fmt) xlat_exp_set_name(node, fr_sbuff_current(&m), fr_sbuff_behind(&m));

		/*
		 *	Ensure that the function args are correct.
		 */
		if (xlat_validate_function_arg(arg, node, argc) < 0) {
			fr_sbuff_set(&our_in, &m);
			goto error;
		}

		xlat_exp_insert_tail(head, node);

		/*
		 *	If we're not and the end of the string
		 *	and there's no whitespace between tokens
		 *	then error.
		 */
		fr_sbuff_set(&m, &our_in);
		len = fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);

               /*
		*	Commas are in the list of terminals, but we skip over them, and keep parsing more
		*	arguments.
		*/
		if (!spaces) {
			fr_assert(p_rules && p_rules->terminals);

			if (fr_sbuff_next_if_char(&our_in, ',')) goto next;

			if (fr_sbuff_is_char(&our_in, ')')) break;

			if (fr_sbuff_eof(&our_in)) {
				fr_strerror_printf("Missing ')' after argument %d", argc);
				goto error;
			}

			fr_strerror_printf("Unexpected text after argument %d", argc);
			goto error;
		}

		/*
		 *	Check to see if we have a terminal char, which at this point has to be '``.
		 */
		if (our_p_rules->terminals) {
			if (fr_sbuff_is_terminal(&our_in, our_p_rules->terminals)) break;

			if (fr_sbuff_eof(&our_in)) {
				fr_strerror_printf("Unexpected end of input string after argument %d", argc);
				goto error;
			}
		}

		/*
		 *	Otherwise, if we can extend, and found
		 *	no additional whitespace, it means two
		 *	arguments were smushed together.
		 */
		if (fr_sbuff_extend(&our_in) && (len == 0)) {
			fr_strerror_const("Unexpected text after argument");
			goto error;
		}
	next:
		if (!arg->variadic) {
			arg++;
			argc++;

			if (arg->type == FR_TYPE_NULL) {
				fr_strerror_printf("Too many arguments, expected %zu, got %d",
						   (size_t) (arg - arg_start), argc);
				goto error;
			}
		}
	}

	if (our_p_rules == &tmp_p_rules) talloc_const_free(our_p_rules->terminals);

	XLAT_HEAD_VERIFY(head);
	*out = head;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Tokenize an xlat expansion
 *
 * @param[in] ctx			to allocate dynamic buffers in.
 * @param[out] out			the head of the xlat list / tree structure.
 * @param[in] in			the format string to expand.
 * @param[in] p_rules			controlling how the string containing the xlat
 *					expansions should be parsed.
 * @param[in] t_rules			controlling how attribute references are parsed.
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

	fr_assert(!t_rules || !t_rules->at_runtime || (t_rules->xlat.runtime_el != NULL));

	MEM(head = xlat_exp_head_alloc(ctx));
	fr_strerror_clear();	/* Clear error buffer */

	if (xlat_tokenize_input(head, &our_in, p_rules, t_rules) < 0) {
		talloc_free(head);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	Add nodes that need to be bootstrapped to
	 *	the registry.
	 */
	if (xlat_finalize(head, t_rules->xlat.runtime_el) < 0) {
		talloc_free(head);
		return 0;
	}

	XLAT_HEAD_VERIFY(head);
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
	xlat_t				*func;

	if (!head->flags.needs_resolving) return 0;			/* Already done */

	if (!xr_rules) xr_rules = &xr_default;

	our_flags = XLAT_FLAGS_INIT;

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
		 *	An unresolved function.
		 */
		case XLAT_FUNC_UNRESOLVED:
			/*
			 *	Try to find the function
			 */
			func = xlat_func_find(node->fmt, talloc_array_length(node->fmt) - 1);
			if (!func) {
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
			xlat_exp_set_func(node, func, xr_rules->tr_rules->dict_def);

			/*
			 *	Check input arguments of our freshly resolved function
			 */
			if (xlat_validate_function_args(node) < 0) return -1;

			/*
			 *	Add the freshly resolved function
			 *	to the bootstrap tree.
			 */
			if (xlat_instance_register_func(node) < 0) return -1;

			/*
			 *	The function is now resolved, so we go through the normal process of resolving
			 *	its arguments, etc.
			 */
			FALL_THROUGH;

		/*
		 *	A resolved function with unresolved args.  We re-initialize the flags from the
		 *	function definition, resolve the arguments, and update the flags.
		 */
		case XLAT_FUNC:
			node->flags = node->call.func->flags;

			if (node->call.func->resolve) {
				void *inst = node->call.inst ? node->call.inst->data : NULL;

				if (node->call.func->resolve(node, inst, xr_rules) < 0) return -1;

			} else if (node->call.args) {
				if (xlat_resolve(node->call.args, xr_rules) < 0) return -1;

			} /* else the function takes no arguments */

			node->flags.needs_resolving = false;
			xlat_exp_finalize_func(node);
			break;

		case XLAT_TMPL:
			/*
			 *	Resolve any nested xlats in regexes, exec, or xlats.
			 */
			if (tmpl_resolve(node->vpt, xr_rules->tr_rules) < 0) return -1;

			fr_assert(!tmpl_needs_resolving(node->vpt));
			node->flags.needs_resolving = false;

			if (xlat_tmpl_normalize(node) < 0) return -1;
			break;

		default:
			fr_assert(0);	/* boxes, one letter, etc. should not have been marked as unresolved */
			return -1;
		}

		xlat_flags_merge(&our_flags, &node->flags);
	}

	head->flags = our_flags;

	fr_assert(!head->flags.needs_resolving);

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
	if ((tmpl_attr_tail_num(node->vpt) == NUM_COUNT) || (tmpl_attr_tail_num(node->vpt) == NUM_ALL)) return NULL;

	vpt = tmpl_alloc(ctx, TMPL_TYPE_ATTR, T_BARE_WORD, node->fmt, talloc_array_length(node->fmt) - 1);
	if (!vpt) return NULL;

	tmpl_attr_copy(vpt, node->vpt);

	TMPL_VERIFY(vpt);

	return vpt;
}

bool xlat_impure_func(xlat_exp_head_t const *head)
{
	return head->flags.impure_func;
}

/*
 *	Try to determine the output data type of an expansion.
 *
 *	This is only a best guess for now.
 */
fr_type_t xlat_data_type(xlat_exp_head_t const *head)
{
	xlat_exp_t *node;

	node = xlat_exp_head(head);
	fr_assert(node);

	if (xlat_exp_next(head, node)) return FR_TYPE_NULL;

	if (node->quote != T_BARE_WORD) return FR_TYPE_STRING;

	if (node->type == XLAT_FUNC) {
		return node->call.func->return_type;
	}

	if (node->type == XLAT_TMPL) {
		return tmpl_data_type(node->vpt);
	}

	return FR_TYPE_NULL;
}
