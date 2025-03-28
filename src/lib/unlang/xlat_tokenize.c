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

extern const bool xlat_func_bare_words;

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


static int xlat_validate_function_arg(xlat_arg_parser_t const *arg_p, xlat_exp_t *arg, int argc)
{
	xlat_exp_t *node;

	/*
	 *	The caller doesn't care about the type, we don't do any validation.
	 *
	 *	@todo - maybe check single / required?
	 */
	if (arg_p->type == FR_TYPE_VOID) {
		return 0;
	}

	node = xlat_exp_head(arg->group);

	if (!node) {
		if (!arg_p->required) return 0;

		fr_strerror_const("Missing argument");
		return -1;
	}

	/*
	 *	@todo - check arg_p->single, and complain.
	 */
	if (xlat_exp_next(arg->group, node)) {
		return 0;
	}

	/*
	 *	Hoist constant factors.
	 */
	if (node->type == XLAT_TMPL) {
		/*
		 *	@todo - hoist the xlat, and then check the hoisted value again.
		 *	However, there seem to be few cases where this is used?
		 */
		if (tmpl_is_xlat(node->vpt)) {
			return 0;

			/*
			 *	Raw data can be hoisted to a value-box in this xlat node.
			 */
		} else if (tmpl_is_data(node->vpt)) {
			tmpl_t *vpt = node->vpt;

			fr_assert(tmpl_rules_cast(vpt) == FR_TYPE_NULL);

			fr_value_box_steal(node, &node->data, tmpl_value(vpt));
			talloc_free(vpt);
			xlat_exp_set_type(node, XLAT_BOX);
			fr_value_box_mark_safe_for(&node->data, arg_p->safe_for);

		} else {
			fr_assert(!tmpl_is_data_unresolved(node->vpt));
			fr_assert(!tmpl_contains_regex(node->vpt));

			/*
			 *	Can't cast the attribute / exec/ etc. to the expected data type of the
			 *	argument, that has to happen at run-time.
			 */
			return 0;
		}
	}

	/*
	 *	@todo - These checks are relatively basic.  We should do better checks, such as if the
	 *	expected type is not string/octets, and the passed arguments are multiple things, then die?
	 *
	 *	If the node is pure, then we should arguably try to purify it now.
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

fr_slen_t xlat_validate_function_args(xlat_exp_t *node)
{
	xlat_arg_parser_t const *arg_p;
	xlat_exp_t		*arg = xlat_exp_head(node->call.args);
	int			i = 1;

	fr_assert(node->type == XLAT_FUNC);

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
	 *	The caller ensures that the first character aftet the percent exists, and is alphanumeric.
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
				fr_strerror_const("Missing ')'");
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

			xlat_exp_set_type(node, XLAT_ONE_LETTER);
			xlat_exp_set_name(node, fr_sbuff_current(&m_s), 1);

			fr_sbuff_marker_release(&m_s);

#ifdef STATIC_ANALYZER
			if (!node->fmt) return -1;
#endif

			/*
			 *	%% is pure.  Everything else is not.
			 */
			node->flags.pure = (node->fmt[0] == '%');

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
		node->flags.needs_resolving = true;	/* Needs resolution during pass2 */
	} else {
		node->call.func = func;
		node->call.dict = t_rules->attr.dict_def;
		node->flags = func->flags;
		node->flags.impure_func = !func->flags.pure;
		node->call.input_type = func->input_type;
	}

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
	if (xlat_tokenize_argv(node, &node->call.args, in, func,
			       &xlat_function_arg_rules, t_rules, false) < 0) {
error:
		talloc_free(node);
		return -1;
	}

	xlat_flags_merge(&node->flags, &node->call.args->flags);

	if (!fr_sbuff_next_if_char(in, ')')) {
		fr_strerror_const("Missing closing brace");
		goto error;
	}

	/*
	 *	Validate the arguments.
	 */
	if (node->type == XLAT_FUNC) {
		switch (node->call.input_type) {
		case XLAT_INPUT_UNPROCESSED:
			break;

		case XLAT_INPUT_ARGS:
			node->flags.can_purify = (node->call.func->flags.pure && node->call.args->flags.pure) | node->call.args->flags.can_purify;
			break;
		}
	}

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
	our_t_rules.attr.prefix = TMPL_ATTR_REF_PREFIX_NO;

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

		/*
		 *	Try to resolve it later
		 */
		node->flags.needs_resolving = true;
	}

	/*
	 *	Deal with normal attribute (or list)
	 */
	xlat_exp_set_type(node, XLAT_TMPL);
	xlat_exp_set_name_shallow(node, vpt->name);
	node->vpt = vpt;

	/*
	 *	Remember that it was %{User-Name}
	 *
	 *	This is a temporary hack until all of the unit tests
	 *	pass without '&'.
	 */
	UNCONST(tmpl_attr_rules_t *, &vpt->rules.attr)->xlat = true;

	/*
	 *	Attributes and module calls aren't pure.
	 */
	node->flags.pure = false;

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
		fr_strerror_const("Missing closing brace");
		fr_sbuff_marker_release(&m_s);
		return -1;
	}

	/*
	 *	It must be an expression.
	 *
	 *	We wrap the xlat in a tmpl, so that the result is just a value, and not wrapped in another
	 *	XLAT_GROUP, which turns into a wrapper of FR_TYPE_GROUP in the value-box.
	 */
	{
		xlat_exp_head_t *child;
		tmpl_rules_t my_rules;

		fr_sbuff_set(in, &m_s);		/* backtrack to the start of the expression */

		MEM(node = xlat_exp_alloc(head, XLAT_TMPL, NULL, 0));
		MEM(node->vpt = tmpl_alloc(node, TMPL_TYPE_XLAT, T_BARE_WORD, "", 1));

		if (t_rules) {
			my_rules = *t_rules;
			my_rules.enumv = NULL;
			my_rules.cast = FR_TYPE_NULL;
			t_rules = &my_rules;
		}

		ret = xlat_tokenize_expression(node->vpt, &child, in, &attr_p_rules, t_rules);
		if (ret <= 0) {
			talloc_free(node);
			return ret;
		}

		if (!fr_sbuff_is_char(in, '}')) {
			fr_strerror_const("Missing closing brace");
			return -1;
		}

		xlat_exp_set_name(node, fr_sbuff_current(&m_s), fr_sbuff_behind(&m_s));
		tmpl_set_name_shallow(node->vpt, T_BARE_WORD, node->fmt, fr_sbuff_behind(&m_s));

		tmpl_set_xlat(node->vpt, child);
		xlat_exp_insert_tail(head, node);

		child->flags.xlat = true;
		node->flags = child->flags;
		fr_assert(tmpl_xlat(node->vpt) != NULL);

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
		fr_strerror_const("Missing closing brace");
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
			fr_strerror_const("Missing closing brace");
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
			fr_value_box_strdup(node, &node->data, NULL, str, false);
			fr_value_box_mark_safe_for(&node->data, t_rules->literals_safe_for);
			node->flags.constant = true;
			fr_assert(node->flags.pure);

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
static void _xlat_debug_node(xlat_exp_t const *node, int depth)
{
	INFO_INDENT("{ -- %s", node->fmt);
#ifndef NDEBUG
//	INFO_INDENT("  %s:%d", node->file, node->line);
#endif
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
			if (tmpl_attr_tail_da(node->vpt)) INFO_INDENT("attribute (%s)", tmpl_attr_tail_da(node->vpt)->name);
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
	_xlat_debug_node(node, 0);
}

static void _xlat_debug_head(xlat_exp_head_t const *head, int depth)
{
	int i = 0;

	fr_assert(head != NULL);

	INFO_INDENT("head flags = %s %s %s",
		    head->flags.needs_resolving ? "need_resolving," : "",
		    head->flags.pure ? "pure" : "",
		    head->flags.can_purify ? "can_purify" : "");

	depth++;

	xlat_exp_foreach(head, node) {
		INFO_INDENT("[%d] flags = %s %s %s ", i++,
			    node->flags.needs_resolving ? "need_resolving" : "",
			    node->flags.pure ? "pure" : "",
			    node->flags.can_purify ? "can_purify" : "");

		_xlat_debug_node(node, depth);
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

	switch (node->type) {
	case XLAT_GROUP:
		if (node->quote != T_BARE_WORD) FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->quote]);
		xlat_print(out, node->group, fr_value_escape_by_quote[node->quote]);
		if (node->quote != T_BARE_WORD) FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[node->quote]);

		if (xlat_exp_next(head, node)) {
			if (c) FR_SBUFF_IN_CHAR_RETURN(out, c);
			FR_SBUFF_IN_CHAR_RETURN(out, ' ');      /* Add ' ' between args */
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
			 *	@todo - until such time as the value
			 *	box functions print "::" before enum
			 *	names.
			 *
			 *	Arguably it should _always_ print the
			 *	"::" before enum names, even if the
			 *	input didn't have "::".  But that's
			 *	addressed when the prefix is required,
			 *	OR when the value-box functions are
			 *	updated.
			 */
			if (node->vpt->data.literal.enumv &&
			    (strncmp(node->fmt, "::", 2) == 0)) {
				FR_SBUFF_IN_STRCPY_LITERAL_RETURN(out, "::");
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
				if (node->flags.xlat) FR_SBUFF_IN_CHAR_RETURN(out, '%', '{');
				xlat_print(out, tmpl_xlat(node->vpt), NULL);
				if (node->flags.xlat) FR_SBUFF_IN_CHAR_RETURN(out, '}');
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


/** Tokenize an xlat expansion into a series of XLAT_TYPE_CHILD arguments
 *
 * @param[in] ctx		to allocate nodes in.  Note: All nodes will be
 *				allocated in the same ctx.  This is to allow
 *				manipulation by xlat instantiation functions
 *				later.
 * @param[out] out		the head of the xlat list / tree structure.
 * @param[in] in		the format string to expand.
 * @param[in] xlat		we're tokenizing arguments for.
 * @param[in] p_rules		controlling how to parse the string outside of
 *				any expansions.
 * @param[in] t_rules		controlling how attribute references are parsed.
 * @param[in] spaces		whether the arguments are delimited by spaces
 * @return
 *	- < 0 on error.
 *	- >0  on success which is the number of characters parsed.
 */
fr_slen_t xlat_tokenize_argv(TALLOC_CTX *ctx, xlat_exp_head_t **out, fr_sbuff_t *in,
			     xlat_t const *xlat,
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

	if (xlat && xlat->args) {
		arg_start = arg = xlat->args;	/* Track the arguments as we parse */
	} else {
		static xlat_arg_parser_t const	default_arg[] = { { .variadic = XLAT_ARG_VARIADIC_EMPTY_SQUASH, .type = FR_TYPE_VOID  },
								  XLAT_ARG_PARSER_TERMINATOR };
		arg_start = arg = &default_arg[0];
	}
	arg_t_rules = *t_rules;

	if (spaces) {
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
		fr_assert(p_rules == &xlat_function_arg_rules);
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
		if (!xlat_func_bare_words) {
			arg_t_rules.enumv = NULL;
			arg_t_rules.cast = FR_TYPE_NULL;
			arg_t_rules.attr.namespace = NULL;
			arg_t_rules.attr.request_def = NULL;
			arg_t_rules.attr.list_def = request_attr_request;
			arg_t_rules.attr.list_presence = TMPL_ATTR_LIST_ALLOW;
		}
	}

	MEM(head = xlat_exp_head_alloc(ctx));

	/*
	 *	skip spaces at the beginning as we don't want them to become a whitespace literal.
	 */
	fr_sbuff_adv_past_whitespace(in, SIZE_MAX, NULL);
	fr_sbuff_marker(&m, &our_in);
	argc = 1;

	while (fr_sbuff_extend(&our_in)) {
		xlat_exp_t	*node = NULL;
		fr_token_t	quote;
		size_t		len;

		fr_sbuff_set(&m, &our_in);	/* Record start of argument */
		arg_t_rules.literals_safe_for = arg->safe_for;

		/*
		 *	Whitespace isn't significant for comma-separated argvs
		 */
		if (!spaces) fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);

		/*
		 *	Alloc a new node to hold the child nodes
		 *	that make up the argument.
		 */
		MEM(node = xlat_exp_alloc(head, XLAT_GROUP, NULL, 0));

		if (!spaces && !xlat_func_bare_words) {
			quote = T_BARE_WORD;
			node->quote = quote;
			goto tokenize_expression;
		}

		fr_sbuff_out_by_longest_prefix(&slen, &quote, xlat_quote_table, &our_in, T_BARE_WORD);
		node->quote = quote;

		switch (quote) {
		/*
		 *	Barewords --may-contain=%{expansions}
		 */
		case T_BARE_WORD:
			XLAT_DEBUG("ARGV bare word <-- %.*s", (int) fr_sbuff_remaining(&our_in), fr_sbuff_current(&our_in));

			/*
			 *	&User-Name is an attribute reference
			 *
			 *	@todo - move '&' to be a _dcursor_. and not an attribute reference.
			 *
			 *	@todo - Perhaps &"foo" can dynamically create the string, and then pass it to
			 *	the the tmpl tokenizer, and then pass the tmpl to the function.  Which also
			 *	means that we need to be able to have a fr_value_box_t which holds a ptr to a
			 *	tmpl.  And update the function arguments to say "we want a tmpl, not a
			 *	string".
			 */
			if (spaces || xlat_func_bare_words) {
				/*
				 *	Spaces - each argument is a bare word all by itself, OR an xlat thing all by itself.
				 *
				 *	No spaces - each arugment is an expression, which can have embedded spaces.
				 */
				slen = xlat_tokenize_input(node->group, &our_in, our_p_rules, &arg_t_rules);

			} else {
			tokenize_expression:
				if (fr_sbuff_is_char(&our_in, ')')) {
					/*
					 *	%foo()
					 */
					slen = 0;

				} else {
					slen = xlat_tokenize_expression(node, &node->group, &our_in, our_p_rules, &arg_t_rules);
				}
			}
			if (slen < 0) {
			error:
				if (our_p_rules == &tmp_p_rules) talloc_const_free(our_p_rules->terminals);
				talloc_free(head);

				FR_SBUFF_ERROR_RETURN(&our_in);	/* error */
			}

			/*
			 *	No data, but the argument was required.  Complain.
			 */
			if (!slen && arg->required) {
				fr_strerror_printf("Missing required arg %u", argc);
				goto error;
			}

			/*
			 *	Validate the argument immediately on parsing it, and not later.
			 */
			if (arg->type == FR_TYPE_NULL) {
				fr_strerror_printf("Too many arguments, expected %zu, got %d",
						   (size_t) (arg - arg_start), argc);
				goto error;
			}

			/*
			 *	Ensure that the function args are correct.
			 */
			if (xlat_validate_function_arg(arg, node, argc) < 0) {
				fr_sbuff_set(&our_in, &m);
				goto error;
			}
			break;

		/*
		 *	"Double quoted strings may contain %{expansions}"
		 */
		case T_DOUBLE_QUOTED_STRING:
			XLAT_DEBUG("ARGV double quotes <-- %.*s", (int) fr_sbuff_remaining(&our_in), fr_sbuff_current(&our_in));

			if (xlat_tokenize_input(node->group, &our_in,
						&value_parse_rules_double_quoted, &arg_t_rules) < 0) goto error;
			break;

		/*
		 *	'Single quoted strings get parsed as literal strings'
		 */
		case T_SINGLE_QUOTED_STRING:
		{
			char		*str;
			xlat_exp_t	*child;

			XLAT_DEBUG("ARGV single quotes <-- %.*s", (int) fr_sbuff_remaining(&our_in), fr_sbuff_current(&our_in));

			child = xlat_exp_alloc(node->group, XLAT_BOX, NULL, 0);
			slen = fr_sbuff_out_aunescape_until(child, &str, &our_in, SIZE_MAX,
							    value_parse_rules_single_quoted.terminals,
							    value_parse_rules_single_quoted.escapes);
			if (slen < 0) goto error;

			xlat_exp_set_name_shallow(child, str);
			fr_value_box_strdup(child, &child->data, NULL, str, false);
			fr_value_box_mark_safe_for(&child->data, arg->safe_for);	/* Literal values are treated as implicitly safe */
			child->flags.constant = true;
			fr_assert(child->flags.pure);
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

		xlat_exp_set_name(node, fr_sbuff_current(&m), fr_sbuff_behind(&m));

		/*
		 *	Assert that the parser has created things which are safe for the current argument.
		 *
		 *	@todo - function should be marked up with safe_for, and not each individual argument.
		 */
//		xlat_safe_for(node->group, arg->safe_for);

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
			node->call.dict = xr_rules->tr_rules->dict_def;

			/*
			 *	Check input arguments of our freshly
			 *	resolved function
			 */
			switch (node->call.func->input_type) {
			case XLAT_INPUT_UNPROCESSED:
				break;

			case XLAT_INPUT_ARGS:
				if (node->call.input_type != XLAT_INPUT_ARGS) {
					fr_strerror_const("Function takes defined arguments and should "
							  "be called using %func(args) syntax");
					return -1;
				}
				if (xlat_validate_function_args(node) < 0) return -1;
				break;
			}

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
			node->flags.impure_func = !node->call.func->flags.pure;
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

		if (node->flags.needs_resolving && !xr_rules->allow_unresolved) {
			if (node->quote == T_BARE_WORD) {
				fr_strerror_printf_push("Failed resolving attribute: %s",
							node->fmt);
			} else {
				fr_strerror_printf_push("Failed resolving attribute: %c%s%c",
							fr_token_quote[node->quote], node->fmt, fr_token_quote[node->quote]);
			}
		}

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

	if (node->type == XLAT_FUNC) {
		return node->call.func->return_type;
	}

	if (node->type == XLAT_TMPL) {
		return tmpl_data_type(node->vpt);
	}

	return FR_TYPE_NULL;
}
