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
 * @file xlat_expr.c
 * @brief Tokenizers and support functions for xlat expressions
 *
 * @copyright 2021 The FreeRADIUS server project
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/unlang/xlat_priv.h>
#include <freeradius-devel/util/calc.h>
#include <freeradius-devel/server/tmpl_dcursor.h>

#undef XLAT_DEBUG
#ifdef DEBUG_XLAT
#  define XLAT_DEBUG(_fmt, ...)			DEBUG3("%s[%i] "_fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#  define XLAT_DEBUG(...)
#endif

/*
 *	The new tokenizer accepts most things which are accepted by the old one.  Many of the errors will be
 *	different, though.
 *
 *	@todo - add a "output" fr_type_t to xlat_t, which is mainly used by the comparison functions.  Right
 *	now it will happily parse things like:
 *
 *		(1 < 2) < 3
 *
 *	though the result of (1 < 2) is a boolean, so the result is always true.  We probably want to have
 *	that as a compile-time error / check.  This can probably just be done with xlat_purify() ?  which
 *	doesn't need to interpret the LHS, but just knows its limits.  We perhaps want a "range compare"
 *	function, which just checks ranges on one side against values on the right.
 *
 *	Even worse, when we do "((bool) 1) < 3", the RHS is cast to the type of the LHS by
 *	tmpl_afrom_substr(). This is because we pass the LHS data type recursively down, which works most of
 *	the time, but not all of the time.  There are currently hacks in the "upcast" code here to fix this,
 *	but it's a hack.
 *
 *	@todo - add instantiation routines for assignment operations.  This lets us do things
 *	like:
 *		if ((&foo += 4) > 6) ...
 *
 *	However, this would also require us adding an edit list pointer to the xlat evaluation functions,
 *	which is not trivial.  Or, maybe we attach it to the request somehow?
 */

static xlat_exp_t *xlat_exists_alloc(TALLOC_CTX *ctx, xlat_exp_t *child);

static void xlat_func_append_arg(xlat_exp_t *head, xlat_exp_t *node, bool exists)
{
	xlat_exp_t *group;

	fr_assert(head->type == XLAT_FUNC);

	if (node->type == XLAT_GROUP) {
		xlat_exp_insert_tail(head->call.args, node);
		xlat_flags_merge(&head->flags, &head->call.args->flags);
		return;
	}

	/*
	 *	Wrap existence checks for attribute reference.
	 */
	if (exists && (node->type == XLAT_TMPL) && tmpl_contains_attr(node->vpt)) {
		node = xlat_exists_alloc(head, node);
	}

	group = xlat_exp_alloc_null(head->call.args);
	xlat_exp_set_type(group, XLAT_GROUP);
	group->quote = T_BARE_WORD;

	group->fmt = node->fmt;	/* not entirely correct, but good enough for now */
	group->flags = node->flags;

	MEM(group->group = xlat_exp_head_alloc(group));
	talloc_steal(group->group, node);
	xlat_exp_insert_tail(group->group, node);

	xlat_exp_insert_tail(head->call.args, group);

	xlat_flags_merge(&head->flags, &head->call.args->flags);
}


/** Allocate a specific cast node.
 *
 *  With the first argument being a UINT8 of the data type.
 *  See xlat_func_cast() for the implementation.
 *
 */
static xlat_exp_t *xlat_exists_alloc(TALLOC_CTX *ctx, xlat_exp_t *child)
{
	xlat_exp_t *node;

	/*
	 *	Create an "exists" node.
	 */
	MEM(node = xlat_exp_alloc(ctx, XLAT_FUNC, "exists", 6));
	MEM(node->call.args = xlat_exp_head_alloc(node));
	MEM(node->call.func = xlat_func_find("exists", 6));
	fr_assert(node->call.func != NULL);
	node->flags = node->call.func->flags;

	fr_assert(child->type == XLAT_TMPL);
	fr_assert(tmpl_contains_attr(child->vpt));
	node->fmt = child->vpt->name;

	xlat_func_append_arg(node, child, false);

	return node;
}


static int reparse_rcode(TALLOC_CTX *ctx, xlat_exp_t **p_arg, bool allow)
{
	rlm_rcode_t rcode;
	ssize_t slen;
	size_t len;
	xlat_t *func;
	xlat_exp_t *arg = *p_arg;
	xlat_exp_t *node;

	if ((arg->type != XLAT_TMPL) || (arg->quote != T_BARE_WORD)) return 0;

	if (!tmpl_is_unresolved(arg->vpt)) return 0;

	len = talloc_array_length(arg->vpt->name) - 1;

	/*
	 *	Check for module return codes.  If we find one,
	 *	replace it with a function call that returns "true" if
	 *	the current module code matches what we supplied here.
	 */
	fr_sbuff_out_by_longest_prefix(&slen, &rcode, rcode_table,
				       &FR_SBUFF_IN(arg->vpt->name, len), T_BARE_WORD);
	if (slen < 0) return 0;

	/*
	 *	It did match, so it must match exactly.
	 *
	 *	@todo - what about (ENUM == &Attr), where the ENUM starts with "ok"?
	 *	Maybe just fix that later. Or, if it's a typo such as
	 */
	if (((size_t) slen) != len) {
		fr_strerror_const("Unexpected text - attribute names must prefixed with '&'");
		return -1;
	}

	/*
	 *	For unary operations.
	 *
	 *	-RCODE is not allowed.
	 *	~RCODE is not allowed.
	 *	!RCODE is allowed.
	 */
	if (!allow) {
		fr_strerror_const("Invalid operation on module return code");
		return -1;
	}

	func = xlat_func_find("rcode", 5);
	fr_assert(func != NULL);

	/*
	 *	@todo - free the arg, and replace it with XLAT_BOX of uint32.  Then also update func_rcode()
	 *	to take UINT32 or string...
	 */
	if (tmpl_cast_in_place(arg->vpt, FR_TYPE_STRING, NULL) < 0) {
		return -1;
	}

	MEM(node = xlat_exp_alloc(ctx, XLAT_FUNC, arg->vpt->name, len));
	MEM(node->call.args = xlat_exp_head_alloc(node));
	node->call.func = func;
	node->flags = func->flags;

	/*
	 *	Doesn't need resolving, isn't pure, doesn't need anything else.
	 */
	arg->flags = (xlat_flags_t) { };

	xlat_func_append_arg(node, arg, false);

	*p_arg = node;

	return 0;
}


static fr_slen_t xlat_expr_print_unary(fr_sbuff_t *out, xlat_exp_t const *node, UNUSED void *inst, fr_sbuff_escape_rules_t const *e_rules)
{
	size_t	at_in = fr_sbuff_used_total(out);

	FR_SBUFF_IN_STRCPY_RETURN(out, fr_tokens[node->call.func->token]);
	xlat_print_node(out, node->call.args, xlat_exp_head(node->call.args), e_rules);

	return fr_sbuff_used_total(out) - at_in;
}

static fr_slen_t xlat_expr_print_binary(fr_sbuff_t *out, xlat_exp_t const *node, UNUSED void *inst, fr_sbuff_escape_rules_t const *e_rules)
{
	size_t	at_in = fr_sbuff_used_total(out);
	xlat_exp_t *child = xlat_exp_head(node->call.args);

	fr_assert(child != NULL);

	FR_SBUFF_IN_CHAR_RETURN(out, '(');
	xlat_print_node(out, node->call.args, child, e_rules); /* prints a space after the first argument */

	/*
	 *	@todo - when things like "+" support more than 2 arguments, print them all out
	 *	here.
	 */
	FR_SBUFF_IN_STRCPY_RETURN(out, fr_tokens[node->call.func->token]);
	FR_SBUFF_IN_CHAR_RETURN(out, ' ');

	child = xlat_exp_next(node->call.args, child);
	fr_assert(child != NULL);

	xlat_print_node(out, node->call.args, child, e_rules);

	FR_SBUFF_IN_CHAR_RETURN(out, ')');

	return fr_sbuff_used_total(out) - at_in;
}

static int xlat_expr_resolve_binary(xlat_exp_t *node, UNUSED void *inst, xlat_res_rules_t const *xr_rules)
{
	xlat_exp_t *arg1, *arg2;
	xlat_exp_t *a, *b;
	tmpl_res_rules_t my_tr_rules;

	XLAT_DEBUG("RESOLVE %s\n", node->fmt);

	arg1 = xlat_exp_head(node->call.args);
	fr_assert(arg1);
	fr_assert(arg1->type == XLAT_GROUP);

	arg2 = xlat_exp_next(node->call.args, arg1);
	fr_assert(arg2);
	fr_assert(arg2->type == XLAT_GROUP);

	a = xlat_exp_head(arg1->group);
	b = xlat_exp_head(arg2->group);

	/*
	 *	We have many things here, just call resolve recursively.
	 */
	if (xlat_exp_next(arg1->group, a) || (xlat_exp_next(arg2->group, b))) goto resolve;

	/*
	 *	Anything else must get resolved at run time.
	 */
	if ((a->type != XLAT_TMPL) || (b->type != XLAT_TMPL)) goto resolve;

	/*
	 *	The tr_rules should always contain dict_def
	 */
	fr_assert(xr_rules); /* always set by xlat_resolve() */
	if (xr_rules->tr_rules) {
		my_tr_rules = *xr_rules->tr_rules;
	} else {
		my_tr_rules = (tmpl_res_rules_t) { };
	}

	/*
	 *	The LHS attribute dictates the enumv for the RHS one.
	 */
	if (tmpl_contains_attr(a->vpt)) {
		XLAT_DEBUG("\ta - %s %s\n", a->fmt, b->fmt);

		if (a->flags.needs_resolving) {
			XLAT_DEBUG("\tresolve attr a\n");
			if (tmpl_resolve(a->vpt, &my_tr_rules) < 0) return -1;
			a->flags.needs_resolving = false;
		}

		my_tr_rules.enumv = tmpl_da(a->vpt);

		XLAT_DEBUG("\tresolve other b\n");
		if (tmpl_resolve(b->vpt, &my_tr_rules) < 0) return -1;

		b->flags.needs_resolving = false;
		b->flags.pure = tmpl_is_data(b->vpt);
		b->flags.constant = b->flags.pure;
		goto flags;
	}

	if (tmpl_contains_attr(b->vpt)) {
		XLAT_DEBUG("\tb -  %s %s\n", a->fmt, b->fmt);

		if (b->flags.needs_resolving) {
			XLAT_DEBUG("\tresolve attr b\n");
			if (tmpl_resolve(b->vpt, &my_tr_rules) < 0) return -1;

			b->flags.needs_resolving = false;
		}

		my_tr_rules.enumv = tmpl_da(b->vpt);

		XLAT_DEBUG("\tresolve other a\n");
		if (tmpl_resolve(a->vpt, &my_tr_rules) < 0) return -1;

		a->flags.needs_resolving = false;
		a->flags.pure = tmpl_is_data(a->vpt);
		a->flags.constant = a->flags.pure;
		goto flags;
	}

resolve:
	/*
	 *	This call will fix everything recursively.
	 */
	return xlat_resolve(node->call.args, xr_rules);

flags:
	arg1->flags = arg1->group->flags = a->flags;
	arg2->flags = arg2->group->flags = b->flags;
	xlat_flags_merge(&node->call.args->flags, &arg2->flags);

	fr_assert(!a->flags.needs_resolving);
	fr_assert(!b->flags.needs_resolving);

	fr_assert(!arg1->flags.needs_resolving);
	fr_assert(!arg2->flags.needs_resolving);

	node->call.args->flags.needs_resolving = false;

	return 0;
}

static xlat_arg_parser_t const binary_op_xlat_args[] = {
	{ .required = true, .type = FR_TYPE_VOID },
	{ .required = true, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t xlat_binary_op(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    request_t *request, fr_value_box_list_t *in,
				    fr_token_t op,
				    fr_type_t default_type, fr_dict_attr_t const *enumv)
{
	int rcode;
	fr_value_box_t	*dst, *a, *b;

	MEM(dst = fr_value_box_alloc_null(ctx));

	/*
	 *	Each argument is a FR_TYPE_GROUP, with one or more elements in a list.
	 */
	a = fr_dlist_head(in);
	b = fr_dlist_next(in, a);

#ifdef STATIC_ANALYZER
	if (!a || !b) return XLAT_ACTION_FAIL;
#else
	fr_assert(a != NULL);
	fr_assert(b != NULL);
#endif

	fr_assert(a->type == FR_TYPE_GROUP);
	fr_assert(b->type == FR_TYPE_GROUP);

	if (!fr_equality_op[op]) {
		if (fr_dlist_num_elements(&a->vb_group) != 1) {
			REDEBUG("Expected one value as the first argument, got %d",
				fr_dlist_num_elements(&a->vb_group));
			return XLAT_ACTION_FAIL;
		}

		if (fr_dlist_num_elements(&b->vb_group) != 1) {
			REDEBUG("Expected one value as the second argument, got %d",
				fr_dlist_num_elements(&b->vb_group));
			return XLAT_ACTION_FAIL;
		}

		rcode = fr_value_calc_binary_op(dst, dst, default_type,
						fr_dlist_head(&a->vb_group),
						op,
						fr_dlist_head(&b->vb_group));
	} else {
		rcode = fr_value_calc_list_cmp(dst, dst, &a->vb_group, op, &b->vb_group);
	}
	if (rcode < 0) {
		RPEDEBUG("Failed calculating result, returning NULL");
		goto done;
	}

	/*
	 *	Over-write, but only if it's present.  Otherwise leave
	 *	any existing enum alone.
	 */
	if (enumv) dst->enumv = enumv;

done:
	fr_dcursor_append(out, dst);
	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_paircmp_xlat_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/*
 *	Wrapper around &LDAP-Group == "foo"
 */
static xlat_action_t xlat_paircmp_func(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*dst, *vb_da, *vb;
	fr_dict_attr_t const *da;
	char const *p;

	vb_da = fr_dlist_head(in);
	vb = fr_dlist_next(in, vb_da);

#ifdef STATIC_ANALYZER
	if (!vb_da || !vb) return XLAT_ACTION_FAIL;
#endif

	p = vb_da->vb_strvalue;
	if (*p == '&') p++;

	da = fr_dict_attr_by_name(NULL, fr_dict_root(fr_dict_internal()), p);
	if (!da) {
		RERROR("Unknown attribute '%s'", vb_da->vb_strvalue);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	These callbacks only implement equality.  Nothing else works.
	 */
	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum, false));
	dst->vb_bool = (paircmp_virtual(request, da, T_OP_CMP_EQ, vb) == 0);
	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;
}

#define XLAT_BINARY_FUNC(_name, _op)  \
static xlat_action_t xlat_func_ ## _name(TALLOC_CTX *ctx, fr_dcursor_t *out, \
				   xlat_ctx_t const *xctx, \
				   request_t *request, fr_value_box_list_t *in)  \
{ \
	return xlat_binary_op(ctx, out, xctx, request, in, _op, FR_TYPE_NULL, NULL); \
}

XLAT_BINARY_FUNC(op_add, T_ADD)
XLAT_BINARY_FUNC(op_sub, T_SUB)
XLAT_BINARY_FUNC(op_mul, T_MUL)
XLAT_BINARY_FUNC(op_div, T_DIV)
XLAT_BINARY_FUNC(op_mod, T_MOD)
XLAT_BINARY_FUNC(op_and, T_AND)
XLAT_BINARY_FUNC(op_or,  T_OR)
XLAT_BINARY_FUNC(op_xor,  T_XOR)
XLAT_BINARY_FUNC(op_rshift, T_RSHIFT)
XLAT_BINARY_FUNC(op_lshift, T_LSHIFT)

#define XLAT_CMP_FUNC(_name, _op)  \
static xlat_action_t xlat_func_ ## _name(TALLOC_CTX *ctx, fr_dcursor_t *out, \
				   xlat_ctx_t const *xctx, \
				   request_t *request, fr_value_box_list_t *in)  \
{ \
	return xlat_binary_op(ctx, out, xctx, request, in, _op, FR_TYPE_BOOL, attr_expr_bool_enum); \
}

XLAT_CMP_FUNC(cmp_eq,  T_OP_CMP_EQ)
XLAT_CMP_FUNC(cmp_ne,  T_OP_NE)
XLAT_CMP_FUNC(cmp_lt,  T_OP_LT)
XLAT_CMP_FUNC(cmp_le,  T_OP_LE)
XLAT_CMP_FUNC(cmp_gt,  T_OP_GT)
XLAT_CMP_FUNC(cmp_ge,  T_OP_GE)

typedef struct {
	fr_token_t	op;
	regex_t		*regex;		//!< precompiled regex
	xlat_exp_t	*xlat;		//!< to expand
	fr_regex_flags_t *regex_flags;
} xlat_regex_inst_t;

typedef struct {
	bool			last_success;
	fr_value_box_list_t	list;
} xlat_regex_rctx_t;

static fr_slen_t xlat_expr_print_regex(fr_sbuff_t *out, xlat_exp_t const *node, void *instance, fr_sbuff_escape_rules_t const *e_rules)
{
	size_t			at_in = fr_sbuff_used_total(out);
	xlat_exp_t		*child = xlat_exp_head(node->call.args);
	xlat_regex_inst_t	*inst = instance;

	fr_assert(child != NULL);

	FR_SBUFF_IN_CHAR_RETURN(out, '(');
	xlat_print_node(out, node->call.args, child, e_rules);

	/*
	 *	A space is printed after the first argument only if
	 *	there's a second one.  So add one if we "ate" the second argument.
	 */
	FR_SBUFF_IN_CHAR_RETURN(out, ' ');

	FR_SBUFF_IN_STRCPY_RETURN(out, fr_tokens[node->call.func->token]);
	FR_SBUFF_IN_CHAR_RETURN(out, ' ');

	fr_assert(tmpl_contains_regex(inst->xlat->vpt));

	if (inst->xlat->quote == T_SINGLE_QUOTED_STRING) FR_SBUFF_IN_CHAR_RETURN(out, 'm');
	FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[inst->xlat->quote]);
	FR_SBUFF_IN_STRCPY_RETURN(out, inst->xlat->vpt->name);
	FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[inst->xlat->quote]);

	FR_SBUFF_RETURN(regex_flags_print, out, inst->regex_flags);

	FR_SBUFF_IN_CHAR_RETURN(out, ')');

	return fr_sbuff_used_total(out) - at_in;
}


/*
 *	Each argument is it's own head, because we do NOT always want
 *	to go to the next argument.
 */
static int xlat_instantiate_regex(xlat_inst_ctx_t const *xctx)
{
	xlat_regex_inst_t	*inst = talloc_get_type_abort(xctx->inst, xlat_regex_inst_t);
	xlat_exp_t		*lhs, *rhs, *regex;

	lhs = xlat_exp_head(xctx->ex->call.args);
	rhs = xlat_exp_next(xctx->ex->call.args, lhs);

	(void) fr_dlist_remove(&xctx->ex->call.args->dlist, rhs);

	fr_assert(rhs);
	fr_assert(rhs->type == XLAT_GROUP);
	regex = xlat_exp_head(rhs->group);
	fr_assert(tmpl_contains_regex(regex->vpt));

	inst->op = xctx->ex->call.func->token;
	inst->regex_flags = tmpl_regex_flags(regex->vpt);

	inst->xlat = talloc_steal(inst, regex);
	talloc_free(rhs);	/* group wrapper is no longer needed */

	/*
	 *	The RHS is more then just one regex node, it has to be dynamically expanded.
	 */
	if (tmpl_contains_xlat(regex->vpt)) {
		return 0;
	}

	if (tmpl_is_unresolved(regex->vpt)) {
		fr_strerror_const("Regex must be resolved before instantiation");
		return -1;
	}

	/*
	 *	Must have been caught in the parse phase.
	 */
	fr_assert(tmpl_is_regex(regex->vpt));

	inst->regex = tmpl_regex(regex->vpt);

	return 0;
}


static const fr_sbuff_escape_rules_t regex_escape_rules = {
	.name = "regex",
	.chr = '\\',
	.subs = {
		['$'] = '$',
		['('] = '(',
		['*'] = '*',
		['+'] = '+',
		['.'] = '.',
		['/'] = '/',
		['?'] = '?',
		['['] = '[',
		['\\'] = '\\',
		['^'] = '^',
		['`'] = '`',
		['|'] = '|',
		['\a'] = 'a',
		['\b'] = 'b',
		['\n'] = 'n',
		['\r'] = 'r',
		['\t'] = 't',
		['\v'] = 'v'
	},
	.esc = {
		SBUFF_CHAR_UNPRINTABLES_LOW,
		SBUFF_CHAR_UNPRINTABLES_EXTENDED
	},
	.do_utf8 = true,
	.do_oct = true
};

static xlat_arg_parser_t const regex_op_xlat_args[] = {
	{ .required = true, .type = FR_TYPE_STRING },
	{ .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};


/** Perform a regular expressions comparison between two operands
 *
 * @param[in] request		The current request.
 * @param[in] in		list of item or items
 * @param[in,out] preg		Pointer to pre-compiled or runtime-compiled
 *				regular expression.  In the case of runtime-compiled
 *				the pattern may be stolen by the `regex_sub_to_request`
 *				function as the original pattern is needed to resolve
 *				capture groups.
 *				The caller should only free the `regex_t *` if it
 *				compiled it, and the pointer has not been set to NULL
 *				when this function returns.
 * @param[in] op		the operation to perform.
 * @return
 *	- -1 on failure.
 *	- 0 for "no match".
 *	- 1 for "match".
 */
static xlat_action_t xlat_regex_match(TALLOC_CTX *ctx, request_t *request, fr_value_box_list_t *in, regex_t **preg,
				      fr_dcursor_t *out, fr_token_t op)
{
	uint32_t	subcaptures;
	int		ret = 0;

	fr_regmatch_t	*regmatch;
	fr_value_box_t	*dst;
	fr_value_box_t	*arg, *vb;
	fr_sbuff_t	*agg;
	char const	*subject;
	size_t		len;

	FR_SBUFF_TALLOC_THREAD_LOCAL(&agg, 256, 8192);

	arg = fr_dlist_head(in);
	fr_assert(arg != NULL);
	fr_assert(arg->type == FR_TYPE_GROUP);

	subcaptures = regex_subcapture_count(*preg);
	if (!subcaptures) subcaptures = REQUEST_MAX_REGEX + 1;	/* +1 for %{0} (whole match) capture group */
	MEM(regmatch = regex_match_data_alloc(NULL, subcaptures));

	while ((vb = fr_dlist_pop_head(&arg->vb_group)) != NULL) {
		if (vb->type == FR_TYPE_STRING) {
			subject = vb->vb_strvalue;
			len = vb->vb_length;

		} else {
			fr_value_box_list_t	list;

			fr_value_box_list_init(&list);
			fr_dlist_insert_head(&list, vb);
			vb = NULL;

			/*
			 *	Concatenate everything, and escape untrusted inputs.
			 */
			if (fr_value_box_list_concat_as_string(NULL, agg, &list, NULL, 0, &regex_escape_rules,
							       FR_VALUE_BOX_LIST_FREE_BOX, true, false) < 0) {
				RPEDEBUG("Failed concatenating regular expression string");
				talloc_free(regmatch);
				return XLAT_ACTION_FAIL;
			}

			subject = fr_sbuff_start(agg);
			len = fr_sbuff_used(agg);
		}

		/*
		 *	Evaluate the expression
		 */
		ret = regex_exec(*preg, subject, len, regmatch);
		switch (ret) {
		default:
			RPEDEBUG("REGEX failed");
			talloc_free(vb);
			talloc_free(regmatch);
			return XLAT_ACTION_FAIL;

		case 0:
			regex_sub_to_request(request, NULL, NULL);	/* clear out old entries */
			continue;

		case 1:
			RDEBUG("MATCH");
			regex_sub_to_request(request, preg, &regmatch);
			talloc_free(vb);
			goto done;

		}

		talloc_free(vb);
	}

done:
	talloc_free(regmatch);	/* free if not consumed */

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum, false));
	dst->vb_bool = (ret == (op == T_OP_REG_EQ));

	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;
}

static xlat_action_t xlat_regex_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *in)
{
	xlat_regex_inst_t const *inst = talloc_get_type_abort_const(xctx->inst, xlat_regex_inst_t);
	xlat_regex_rctx_t	*rctx = talloc_get_type_abort(xctx->rctx, xlat_regex_rctx_t);
	ssize_t			slen;
	regex_t			*preg = NULL;
	fr_sbuff_t		*agg;

	FR_SBUFF_TALLOC_THREAD_LOCAL(&agg, 256, 8192);

	/*
	 *	If the expansions fails, then we fail the entire thing.
	 */
	if (!rctx->last_success) {
		talloc_free(rctx);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *      Because we expanded the RHS ourselves, the "concat"
	 *      flag to the RHS argument is ignored.  So we just
	 *      concatenate it here.  We escape the various untrusted inputs.
	 */
	if (fr_value_box_list_concat_as_string(NULL, agg, &rctx->list, NULL, 0, &regex_escape_rules,
					       FR_VALUE_BOX_LIST_FREE_BOX, true, false) < 0) {
		RPEDEBUG("Failed concatenating regular expression string");
		return XLAT_ACTION_FAIL;
	}

	fr_assert(inst->regex == NULL);

	slen = regex_compile(rctx, &preg, fr_sbuff_start(agg), fr_sbuff_used(agg),
			     tmpl_regex_flags(inst->xlat->vpt), true, true); /* flags, allow subcaptures, at runtime */
	if (slen <= 0) return XLAT_ACTION_FAIL;

	return xlat_regex_match(ctx, request, in, &preg, out, inst->op);
}

static xlat_action_t xlat_regex_op(TALLOC_CTX *ctx, fr_dcursor_t *out,
				   xlat_ctx_t const *xctx,
				   request_t *request, fr_value_box_list_t *in,
				   fr_token_t op)
{
	xlat_regex_inst_t const	*inst = talloc_get_type_abort_const(xctx->inst, xlat_regex_inst_t);
	xlat_regex_rctx_t	*rctx;
	regex_t			*preg;

	/*
	 *	Just run precompiled regexes.
	 */
	if (inst->regex) {
		preg = tmpl_regex(inst->xlat->vpt);

		return xlat_regex_match(ctx, request, in, &preg, out, op);
	}

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), xlat_regex_rctx_t));
	fr_value_box_list_init(&rctx->list);

	if (unlang_xlat_yield(request, xlat_regex_resume, NULL, rctx) != XLAT_ACTION_YIELD) {
	fail:
		talloc_free(rctx);
		return XLAT_ACTION_FAIL;
	}

	if (unlang_xlat_push(ctx, &rctx->last_success, &rctx->list,
			     request, tmpl_xlat(inst->xlat->vpt), UNLANG_SUB_FRAME) < 0) goto fail;

	return XLAT_ACTION_PUSH_UNLANG;
}

#define XLAT_REGEX_FUNC(_name, _op)  \
static xlat_action_t xlat_func_ ## _name(TALLOC_CTX *ctx, fr_dcursor_t *out, \
				   xlat_ctx_t const *xctx, \
				   request_t *request, fr_value_box_list_t *in)  \
{ \
	return xlat_regex_op(ctx, out, xctx, request, in, _op); \
}

XLAT_REGEX_FUNC(reg_eq,  T_OP_REG_EQ)
XLAT_REGEX_FUNC(reg_ne,  T_OP_REG_NE)

typedef struct {
	bool		stop_on_match;
	int		argc;
	xlat_exp_head_t	**argv;
} xlat_logical_inst_t;

typedef struct {
	bool			last_success;
	fr_value_box_t		*box;		//!< output value-box
	int			current;
	fr_value_box_list_t	list;
} xlat_logical_rctx_t;

static fr_slen_t xlat_expr_print_logical(fr_sbuff_t *out, xlat_exp_t const *node, void *instance, fr_sbuff_escape_rules_t const *e_rules)
{
	size_t	at_in = fr_sbuff_used_total(out);
	xlat_logical_inst_t *inst = instance;
	xlat_exp_head_t *head;

	FR_SBUFF_IN_CHAR_RETURN(out, '(');

	/*
	 *	We might get called before the node is instantiated.
	 */
	if (!inst->argv) {
		head = node->call.args;

		fr_assert(head != NULL);

		xlat_exp_foreach(head, child) {
			xlat_print_node(out, head, child, e_rules);

			if (!xlat_exp_next(head, child)) break;

			FR_SBUFF_IN_STRCPY_RETURN(out, fr_tokens[node->call.func->token]);
			FR_SBUFF_IN_CHAR_RETURN(out, ' ');
		}
	} else {
		int i;

		for (i = 0; i < inst->argc; i++) {
			xlat_print(out, inst->argv[i], e_rules);
			if (i == (inst->argc - 1)) break;

			FR_SBUFF_IN_CHAR_RETURN(out, ' ');
			FR_SBUFF_IN_STRCPY_RETURN(out, fr_tokens[node->call.func->token]);
			if ((i + 1) < inst->argc) FR_SBUFF_IN_CHAR_RETURN(out, ' ');
		}
	}

	FR_SBUFF_IN_CHAR_RETURN(out, ')');

	return fr_sbuff_used_total(out) - at_in;
}

/*
 *	Each argument is it's own head, because we do NOT always want
 *	to go to the next argument.
 */
static int xlat_instantiate_logical(xlat_inst_ctx_t const *xctx)
{
	xlat_logical_inst_t	*inst = talloc_get_type_abort(xctx->inst, xlat_logical_inst_t);

	inst->argc = xlat_flatten_compiled_argv(inst, &inst->argv, xctx->ex->call.args);
	inst->stop_on_match = (xctx->ex->call.func->token == T_LOR);

	return 0;
}

/*
 *	This returns "false" for "ignore this argument"
 *
 *	result is "false" for "delete this argument"
 *	result is "true" for "return this argument".
 */
static bool xlat_node_matches_bool(xlat_exp_t *parent, xlat_exp_head_t *head, bool sense, bool *result)
{
	fr_value_box_t *box;
	xlat_exp_t *node;

	if (!head->flags.pure) return false;

	node = xlat_exp_head(head);
	if (!node || xlat_exp_next(head, node)) {
		return false;
	}

	if (node->type == XLAT_BOX) {
		box = &node->data;
		goto check;
	}

	if (node->type != XLAT_TMPL) {
		return false;
	}

	if (!tmpl_is_data(node->vpt)) {
		return false;
	}

	box = tmpl_value(node->vpt);

check:
	/*
	 *	On "true", replace the entire logical operation with the value-box.
	 *
	 *	On "false", omit this argument, and go to the next one.
	 */
	*result = (fr_value_box_is_truthy(box) == sense);

	if (!*result) return true;

	xlat_inst_remove(parent);

	parent->type = XLAT_BOX;
	fr_value_box_copy(parent, &parent->data, box);
	parent->flags = (xlat_flags_t) { .pure = true, .constant = true, };

	talloc_free_children(parent);

	return true;
}

/** Undo work which shouldn't have been done.  :(
 *
 */
static void xlat_ungroup(xlat_exp_head_t *head)
{
	xlat_exp_t *group, *node;

	group = xlat_exp_head(head);
	if (!group || xlat_exp_next(head, group)) return;

	if (group->type != XLAT_GROUP) return;

	node = xlat_exp_head(group->group);
	if (!node || xlat_exp_next(group->group, node)) return;

	(void) fr_dlist_remove(&head->dlist, group);
	(void) fr_dlist_remove(&group->group->dlist, node);
	(void) talloc_steal(head, node);

	talloc_free(group);

	fr_dlist_insert_tail(&head->dlist, node);
	head->flags = node->flags;
}

/** If any argument resolves to inst->stop_on_match, the entire thing is a bool of inst->stop_on_match.
 *
 *  If any argument resolves to !inst->stop_on_match, it is removed.
 */
static int xlat_expr_logical_purify(xlat_exp_t *node, void *instance, request_t *request)
{
	int i, j;
	int deleted = 0;
	bool result;
	xlat_logical_inst_t *inst = talloc_get_type_abort(instance, xlat_logical_inst_t);
	xlat_exp_head_t *group;

	fr_assert(node->type == XLAT_FUNC);

	/*
	 *	Don't check the last argument.  If everything else gets deleted, then we just return the last
	 *	argument.
	 */
	for (i = 0; i < inst->argc; i++) {
		/*
		 *	The argument is pure, so we purify it before
		 *	doing any other checks.
		 */
		if (inst->argv[i]->flags.can_purify) {
			if (xlat_purify_list(inst->argv[i], request) < 0) return -1;

			/*
			 *	xlat_purify_list expects that its outputs will be arguments to functions, so
			 *	they're grouped.  We con't need that, so we ungroup them here.
			 */
			xlat_ungroup(inst->argv[i]);
		}

		/*
		 *	This returns "false" for "ignore".
		 *
		 *	result is "false" for "delete this argument"
		 *	result is "true" for "return this argument".
		 */
		if (!xlat_node_matches_bool(node, inst->argv[i], inst->stop_on_match, &result)) {
			continue;
		}

		/*
		 *	0 && EXPR --> 0.
		 *	1 || EXPR --> 1
		 *
		 *	Parent is now an XLAT_BOX, so we're done.
		 */
		if (result) return 0;

		/*
		 *	We're at the last argument.  If we've deleted everything else, then just leave the
		 *	last argument alone.  Otherwise some arguments remain, so we can delete the last one.
		 */
		if (((i + 1) == inst->argc) && (deleted == i)) break;

		TALLOC_FREE(inst->argv[i]);
		deleted++;
	}

	if (!deleted) return 0;

	/*
	 *	Pack the array.  We insert at i, and read from j.  We don't need to read the deleted entries,
	 *	as they all MUST be NULL.
	 */
	i = 0;
	j = -1;
	while (i < (inst->argc - deleted)) {
		if (inst->argv[i]) {
			i++;
			continue;
		}

		/*
		 *	Start searching from the next entry, OR start seaching from where we left off before.
		 */
		if (j < 0) j = i + 1;

		/*
		 *	Find the first non-NULL entry, and insert it in argv[i].  We search here until the end
		 *	of the array, because we may have deleted entries from the start of the array.
		 */
		while (j < inst->argc) {
			if (inst->argv[j]) break;
			j++;
		}

		/*
		 *	Move the entry down, and clear out the tail end of the array.
		 */
		inst->argv[i++] = inst->argv[j];
		inst->argv[j++] = NULL;
	}

	inst->argc -= deleted;

	if (inst->argc > 1) return 0;

	/*
	 *	Only one argument left/  We can hoist the child into ourselves, and omit the logical operation.
	 */
	group = inst->argv[0];
	fr_assert(group != NULL);
	talloc_steal(node, group);

	xlat_inst_remove(node);
	node->type = XLAT_GROUP;
	node->fmt = group->fmt;
	node->group = group;
	node->flags = group->flags;

	return 0;
}

/** See if the input is truthy or not.
 *
 *  @param[in,out] dst	pre-initialized value-box containing the output box
 *  @param[in]     in   list of value-boxes to check
 *  @param[in] logical_or whether or not we're checking for ||.  false is &&
 *  @return
 *	- false if no match.
 *	- true for match, with dst updated to contain the relevant box.
 *
 *  Empty lists are not truthy.
 */
static bool xlat_logical_match(fr_value_box_t **dst, fr_value_box_list_t const *in, bool logical_or)
{
	fr_value_box_t *last = NULL;

	/*
	 *	Empty lists are !truthy.
	 */
	if (!fr_dlist_num_elements(in)) {
		return false;
	}

	/*
	 *	Loop over the input list.  If the box is a group, then do this recursively.
	 */
	fr_value_box_foreach(in, box) {
		if (fr_box_is_group(box)) {
			if (!xlat_logical_match(dst, &box->vb_group, logical_or)) return false;
			continue;
		}

		if (logical_or) {
			if (fr_value_box_is_truthy(box)) {
				last = box; /* stop at the first matching one, and return it. */
				break;
			}

			continue;
		}

		/*
		 *	Must be logical &&
		 */
		if (fr_value_box_is_truthy(box)) {
			last = box;
			continue;
		}

		/*
		 *	Stop on the first "false"
		 */
		return false;
	}

	if (last) {
		fr_value_box_clear(*dst);
		fr_value_box_copy(*dst, *dst, last);
	}

	return true;
}

static xlat_action_t xlat_logical_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 xlat_ctx_t const *xctx,
					 request_t *request, fr_value_box_list_t *in);

/** Process one argument of a logical operation.
 *
 *  If we see a list in a truthy context, then we DON'T expand the list.  Instead, we return a bool which
 *  indicates if the list was empty (or not).  This prevents us from returning a whole mess of value-boxes
 *  when the user just wanted to see if the list existed.
 *
 *  Otherwise, we expand the xlat, and continue.
 */
static xlat_action_t xlat_logical_process_arg(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					      xlat_ctx_t const *xctx,
					      request_t *request, UNUSED fr_value_box_list_t *in)
{
	xlat_logical_inst_t const *inst = talloc_get_type_abort_const(xctx->inst, xlat_logical_inst_t);
	xlat_logical_rctx_t	*rctx = talloc_get_type_abort(xctx->rctx, xlat_logical_rctx_t);

	/*
	 *	Push the xlat onto the stack for expansion.
	 */
	if (unlang_xlat_yield(request, xlat_logical_resume, NULL, rctx) != XLAT_ACTION_YIELD) {
	fail:
		talloc_free(rctx->box);
		talloc_free(rctx);
		return XLAT_ACTION_FAIL;
	}

	if (unlang_xlat_push(rctx, &rctx->last_success, &rctx->list,
			     request, inst->argv[rctx->current], UNLANG_SUB_FRAME) < 0) goto fail;

	return XLAT_ACTION_PUSH_UNLANG;
}

/*
 *  We've evaluated an expression.  Let's see if we need to continue.
 */
static xlat_action_t xlat_logical_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 xlat_ctx_t const *xctx,
					 request_t *request, fr_value_box_list_t *in)
{
	xlat_logical_inst_t const *inst = talloc_get_type_abort_const(xctx->inst, xlat_logical_inst_t);
	xlat_logical_rctx_t	*rctx = talloc_get_type_abort(xctx->rctx, xlat_logical_rctx_t);

	/*
	 *	If one of the expansions fails, then we fail the
	 *	entire thing.
	 */
	if (!rctx->last_success) {
		talloc_free(rctx->box);
		talloc_free(rctx);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Recursively check groups.  i.e. we effectively flatten each list.
	 *
	 *	(a, b, c) || (d, e, f) == a || b || c || d || e || f
	 */
	if (!xlat_logical_match(&rctx->box, &rctx->list, inst->stop_on_match)) {
		/*
		 *	If nothing matches, we return a "false" box.
		 */
		if (rctx->box->type != FR_TYPE_BOOL) {
			fr_value_box_clear(rctx->box);
			fr_value_box_init(rctx->box, FR_TYPE_BOOL, NULL, false);
		}
		rctx->box->vb_bool = false;

		/*
		 *	Try for another match, if possible.
		 */
		if (inst->stop_on_match) goto next;

		/*
		 *	Otherwise we stop on failure, with the boolean
		 *	we just updated.
		 */
		goto done;
	}

	if (inst->stop_on_match) {
	done:
		fr_dcursor_append(out, rctx->box);

		talloc_free(rctx);
		return XLAT_ACTION_DONE;
	}

next:
	fr_dlist_talloc_free(&rctx->list);
	rctx->current++;

	/*
	 *	Nothing to expand, return the final value we saw.
	 */
	if (rctx->current >= inst->argc) {
		goto done;
	}

	return xlat_logical_process_arg(ctx, out, xctx, request, in);
}

/** Process logical &&, ||
 *
 */
static xlat_action_t xlat_func_logical(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *in)
{
	xlat_logical_rctx_t	*rctx;

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), xlat_logical_rctx_t));
	rctx->current = 0;
	MEM(rctx->box = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum, false));
	fr_value_box_list_init(&rctx->list);

	(UNCONST(xlat_ctx_t *, xctx))->rctx = rctx; /* ensure it's there before a resume! */

	return xlat_logical_process_arg(ctx, out, xctx, request, in);
}


static xlat_arg_parser_t const unary_op_xlat_args[] = {
	{ .required = true, .single = true, .concat = true },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t xlat_func_unary_op(TALLOC_CTX *ctx, fr_dcursor_t *out,
					UNUSED xlat_ctx_t const *xctx,
					request_t *request, fr_value_box_list_t *in, fr_token_t op)
{
	int rcode;
	fr_value_box_t *dst, *group, *vb;

	/*
	 *	We do some basic type checks here.
	 */
	group = fr_dlist_head(in);
	vb = fr_dlist_head(&group->vb_group);

	/*
	 *	-NULL is an error
	 *	~NULL is an error
	 *	!NULL is handled by xlat_func_unary_not
	 */
	if (!vb) {
		fr_strerror_printf("Input is empty");
		return XLAT_ACTION_FAIL;
	}

	if (!fr_type_is_leaf(vb->type) || fr_type_is_variable_size(vb->type)) {
		REDEBUG("Cannot perform operation on data type %s", fr_type_to_str(vb->type));
		return XLAT_ACTION_FAIL;
	}

	MEM(dst = fr_value_box_alloc_null(ctx));

	/*
	 *	We rely on this function to do the remainder of the type checking.
	 */
	rcode = fr_value_calc_unary_op(dst, dst, op, vb);
	if ((rcode < 0) || fr_type_is_null(dst->type)) {
		RPEDEBUG("Failed calculating result, returning NULL");
		fr_value_box_init_null(dst);
	}

	fr_dcursor_append(out, dst);
	return XLAT_ACTION_DONE;
}


static xlat_action_t xlat_func_unary_not(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 UNUSED xlat_ctx_t const *xctx,
					 UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t *dst, *group, *vb;

	group = fr_dlist_head(in);
	vb = fr_dlist_head(&group->vb_group);

	/*
	 *	Don't call calc_unary_op(), because we want the enum names.
	 */
	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum, false));

	/*
	 *	!NULL = true
	 */
	if (!vb) {
		dst->vb_bool = true;
	} else {
		dst->vb_bool = !fr_value_box_is_truthy(vb);
	}

	fr_dcursor_append(out, dst);
	return XLAT_ACTION_DONE;
}

static xlat_action_t xlat_func_unary_minus(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   xlat_ctx_t const *xctx,
					   request_t *request, fr_value_box_list_t *in)
{
	return xlat_func_unary_op(ctx, out, xctx, request, in, T_SUB);
}

static xlat_action_t xlat_func_unary_complement(TALLOC_CTX *ctx, fr_dcursor_t *out,
						xlat_ctx_t const *xctx,
						request_t *request, fr_value_box_list_t *in)
{
	return xlat_func_unary_op(ctx, out, xctx, request, in, T_COMPLEMENT);
}

/** Convert XLAT_BOX arguments to XLAT_TMPL
 *
 *  xlat_tokenize() just makes all unknown arguments into XLAT_BOX, of data type FR_TYPE_STRING.  Whereas
 *  xlat_tokenize_expr() calls tmpl_afrom_substr(), which tries hard to create a particular data type.
 *
 *  This function fixes up calls of the form %(op_add: 3 4), which normally passes 2 arguments of "3" and "4",
 *  so that the arguments are instead passed as integers 3 and 4.
 *
 *  This fixup isn't *strictly* necessary, but it's good to have no surprises in the code, if the user creates
 *  an expression manually.
 */
static int xlat_function_args_to_tmpl(xlat_inst_ctx_t const *xctx)
{
	xlat_exp_foreach(xctx->ex->call.args, arg) {
		ssize_t slen;
		xlat_exp_t *node;
		tmpl_t *vpt;

		fr_assert(arg->type == XLAT_GROUP);

		node = xlat_exp_head(arg->group);
		if (!node) continue;
		if (node->type != XLAT_BOX) continue;
		if (node->data.type != FR_TYPE_STRING) continue;

		/*
		 *	Try to parse it.  If we can't, leave it for a run-time error.
		 */
		slen = tmpl_afrom_substr(node, &vpt, &FR_SBUFF_IN(node->data.vb_strvalue, node->data.vb_length),
					 node->quote, NULL, NULL);
		if (slen <= 0) continue;
		if ((size_t) slen < node->data.vb_length) continue;

		/*
		 *	Leave it as XLAT_BOX, but with the (guessed) new data type.
		 */
		fr_value_box_clear(&node->data);
		fr_value_box_copy(node, &node->data, tmpl_value(vpt));
		talloc_free(vpt);
	}

	return 0;
}


static xlat_arg_parser_t const xlat_func_rcode_arg = {
	.concat = true, .type = FR_TYPE_STRING,
};

/** Return the rcode as a string, or bool match if the argument is an rcode name
 *
 * Example:
@verbatim
"%{rcode:}" == "handled"
"%{rcode:handled}" == true
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_rcode(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     UNUSED xlat_ctx_t const *xctx,
				     request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*vb;
	fr_value_box_t	*src = fr_dlist_head(in);

	/*
	 *	Query the rcode if there's no argument.  Otherwise do a boolean check if the passed string
	 *	matches the current rcode.
	 */
	if (!src) {
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_UINT32, attr_module_return_code, false));
		vb->datum.int32 = request->rcode;
	} else {
		rlm_rcode_t rcode;

		rcode = fr_table_value_by_str(rcode_table, src->vb_strvalue, RLM_MODULE_NOT_SET);

		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum, false));
		vb->vb_bool = (request->rcode == rcode);
	}

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

typedef struct {
	tmpl_t const		*vpt;		//!< the attribute reference
	xlat_exp_head_t		*xlat;		//!< the xlat which needs expanding
} xlat_exists_inst_t;

typedef struct {
	bool			last_success;
	fr_value_box_list_t	list;
} xlat_exists_rctx_t;

static xlat_arg_parser_t const xlat_func_exists_arg = {
	.concat = true, .type = FR_TYPE_STRING,
};

/*
 *	We just print the xlat as-is.
 */
static fr_slen_t xlat_expr_print_exists(fr_sbuff_t *out, UNUSED xlat_exp_t const *node, void *instance, fr_sbuff_escape_rules_t const *e_rules)
{
	size_t			at_in = fr_sbuff_used_total(out);
	xlat_exists_inst_t	*inst = instance;

	xlat_print(out, inst->xlat, e_rules);

	return fr_sbuff_used_total(out) - at_in;
}

/*
 *	Don't expand the argument if it's already an attribute reference.
 */
static int xlat_instantiate_exists(xlat_inst_ctx_t const *xctx)
{
	xlat_exists_inst_t	*inst = talloc_get_type_abort(xctx->inst, xlat_exists_inst_t);
	xlat_exp_t		*arg, *xlat;

	arg = xlat_exp_head(xctx->ex->call.args);
	(void) fr_dlist_remove(&xctx->ex->call.args->dlist, arg);

	fr_assert(arg->type == XLAT_GROUP);
	xlat = xlat_exp_head(arg->group);

	inst->xlat = talloc_steal(inst, arg->group);
	talloc_free(arg);

	/*
	 *	If it's an attribute, we can cache a reference to it.
	 */
	if ((xlat->type == XLAT_TMPL) && (tmpl_contains_attr(xlat->vpt))) {
		inst->vpt = xlat->vpt;
	}

	return 0;
}

static xlat_action_t xlat_attr_exists(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      request_t *request, tmpl_t const *vpt, bool do_free)
{
	fr_pair_t		*vp;
	fr_value_box_t		*dst;
	fr_dcursor_t		cursor;
	tmpl_dcursor_ctx_t	cc;

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum, false));

	vp = tmpl_dcursor_init(NULL, NULL, &cc, &cursor, request, vpt);
	if (!vp) {
		dst->vb_bool = tmpl_is_attr(vpt) && tmpl_da(vpt)->flags.virtual;
	} else {
		dst->vb_bool = true;
	}

	if (do_free) talloc_const_free(vpt);
	tmpl_dcursor_clear(&cc);
	fr_dcursor_append(out, dst);
	return XLAT_ACTION_DONE;
}

static xlat_action_t xlat_exists_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
					xlat_ctx_t const *xctx,
					request_t *request, UNUSED fr_value_box_list_t *in)
{
	xlat_exists_rctx_t	*rctx = talloc_get_type_abort(xctx->rctx, xlat_exists_rctx_t);
	ssize_t			slen;
	tmpl_t			*vpt;
	fr_value_box_t		*vb;
	fr_sbuff_t		*agg;

	FR_SBUFF_TALLOC_THREAD_LOCAL(&agg, 256, 8192);

	/*
	 *	If the expansions fails, then we fail the entire thing.
	 */
	if (!rctx->last_success) {
	fail:
		talloc_free(rctx);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Because we expanded the RHS ourselves, the "concat"
	 *	flag to the RHS argument is ignored.  So we just
	 *	concatenate it here.  We escape the various untrusted inputs.
	 */
	if (fr_value_box_list_concat_as_string(NULL, agg, &rctx->list, NULL, 0, NULL,
					       FR_VALUE_BOX_LIST_FREE_BOX, true, true) < 0) {
		RPEDEBUG("Failed concatenating attribute name string");
		return XLAT_ACTION_FAIL;
	}

	vb = fr_dlist_head(&rctx->list);

	slen = tmpl_afrom_attr_str(ctx, NULL, &vpt, vb->vb_strvalue,
				   &(tmpl_rules_t) {
					   .attr = {
						   .dict_def = request->dict,
						   .request_def = &tmpl_request_def_current,
						   .list_def = PAIR_LIST_REQUEST,
						   .prefix = TMPL_ATTR_REF_PREFIX_AUTO,
						   .allow_unknown = false,
						   .allow_unresolved = false,
						   .list_as_attr = true,
					   },
						   });
	if (slen <= 0) goto fail;

	talloc_free(rctx);	/* no longer needed */
	return xlat_attr_exists(ctx, out, request, vpt, true);
}

/** See if a named attribute exists
 *
 * Example:
@verbatim
"%{exists:&Foo}" == true
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_exists(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     xlat_ctx_t const *xctx,
				     request_t *request, UNUSED fr_value_box_list_t *in)
{
	xlat_exists_inst_t const *inst = talloc_get_type_abort_const(xctx->inst, xlat_exists_inst_t);
	xlat_exists_rctx_t	*rctx;

	/*
	 *	We return "true" if the attribute exists.  Otherwise we return "false".
	 *
	 *	Except for virtual attributes.  If we're testing for
	 *	their existence, we always return "true".
	 */
	if (inst->vpt) {
		return xlat_attr_exists(ctx, out, request, inst->vpt, false);
	}

	/*
	 *	Expand the xlat into a string.
	 */
	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), xlat_exists_rctx_t));
	fr_value_box_list_init(&rctx->list);

	if (unlang_xlat_yield(request, xlat_exists_resume, NULL, rctx) != XLAT_ACTION_YIELD) {
	fail:
		talloc_free(rctx);
		return XLAT_ACTION_FAIL;
	}

	if (unlang_xlat_push(ctx, &rctx->last_success, &rctx->list,
			     request, inst->xlat, UNLANG_SUB_FRAME) < 0) goto fail;

	return XLAT_ACTION_PUSH_UNLANG;
}

#undef XLAT_REGISTER_BINARY_OP
#define XLAT_REGISTER_BINARY_OP(_op, _name) \
do { \
	if (!(xlat = xlat_register(NULL, "op_" STRINGIFY(_name), xlat_func_op_ ## _name, XLAT_FLAG_PURE))) return -1; \
	xlat_func_args(xlat, binary_op_xlat_args); \
	xlat_internal(xlat); \
	xlat_print_set(xlat, xlat_expr_print_binary); \
	xlat_async_instantiate_set(xlat, xlat_function_args_to_tmpl, NULL, NULL, NULL); \
	xlat->token = _op; \
} while (0)

#undef XLAT_REGISTER_BINARY_CMP
#define XLAT_REGISTER_BINARY_CMP(_op, _name) \
do { \
	if (!(xlat = xlat_register(NULL, "cmp_" STRINGIFY(_name), xlat_func_cmp_ ## _name, XLAT_FLAG_PURE))) return -1; \
	xlat_func_args(xlat, binary_op_xlat_args); \
	xlat_internal(xlat); \
	xlat_print_set(xlat, xlat_expr_print_binary); \
	xlat_resolve_set(xlat, xlat_expr_resolve_binary); \
	xlat->token = _op; \
} while (0)

#undef XLAT_REGISTER_NARY_OP
#define XLAT_REGISTER_NARY_OP(_op, _name, _func_name) \
do { \
	if (!(xlat = xlat_register(NULL, STRINGIFY(_name), xlat_func_ ## _func_name, XLAT_FLAG_PURE))) return -1; \
	xlat_async_instantiate_set(xlat, xlat_instantiate_ ## _func_name, xlat_ ## _func_name ## _inst_t, NULL, NULL); \
	xlat_internal(xlat); \
	xlat_print_set(xlat, xlat_expr_print_ ## _func_name); \
	xlat_purify_set(xlat, xlat_expr_logical_purify); \
	xlat->token = _op; \
} while (0)

#undef XLAT_REGISTER_REGEX_OP
#define XLAT_REGISTER_REGEX_OP(_op, _name) \
do { \
	if (!(xlat = xlat_register(NULL, STRINGIFY(_name), xlat_func_ ## _name, XLAT_FLAG_PURE))) return -1; \
	xlat_func_args(xlat, regex_op_xlat_args); \
	xlat_async_instantiate_set(xlat, xlat_instantiate_regex, xlat_regex_inst_t, NULL, NULL); \
	xlat_print_set(xlat, xlat_expr_print_regex); \
	xlat_internal(xlat); \
	xlat->token = _op; \
} while (0)

#define XLAT_REGISTER_MONO(_xlat, _func, _arg) \
do { \
	if (!(xlat = xlat_register(NULL, _xlat, _func, NULL))) return -1; \
	xlat_func_mono(xlat, &_arg); \
	xlat_internal(xlat); \
} while (0)

#define XLAT_REGISTER_UNARY(_op, _xlat, _func) \
do { \
	if (!(xlat = xlat_register(NULL, _xlat, _func, XLAT_FLAG_PURE))) return -1; \
	xlat_func_args(xlat, unary_op_xlat_args); \
	xlat_internal(xlat); \
	xlat_print_set(xlat, xlat_expr_print_unary); \
	xlat->token = _op; \
} while (0)

int xlat_register_expressions(void)
{
	xlat_t *xlat;

	XLAT_REGISTER_BINARY_OP(T_ADD, add);
	XLAT_REGISTER_BINARY_OP(T_SUB, sub);
	XLAT_REGISTER_BINARY_OP(T_MUL, mul);
	XLAT_REGISTER_BINARY_OP(T_DIV, div);
	XLAT_REGISTER_BINARY_OP(T_MOD, mod);
	XLAT_REGISTER_BINARY_OP(T_AND, and);
	XLAT_REGISTER_BINARY_OP(T_OR, or);
	XLAT_REGISTER_BINARY_OP(T_XOR, xor);
	XLAT_REGISTER_BINARY_OP(T_RSHIFT, rshift);
	XLAT_REGISTER_BINARY_OP(T_LSHIFT, lshift);

	XLAT_REGISTER_BINARY_CMP(T_OP_CMP_EQ, eq);
	XLAT_REGISTER_BINARY_CMP(T_OP_NE, ne);
	XLAT_REGISTER_BINARY_CMP(T_OP_LT, lt);
	XLAT_REGISTER_BINARY_CMP(T_OP_LE, le);
	XLAT_REGISTER_BINARY_CMP(T_OP_GT, gt);
	XLAT_REGISTER_BINARY_CMP(T_OP_GE, ge);

	XLAT_REGISTER_REGEX_OP(T_OP_REG_EQ, reg_eq);
	XLAT_REGISTER_REGEX_OP(T_OP_REG_NE, reg_ne);

	/*
	 *	&&, ||
	 *
	 *	@todo - remove tmpl_resolve() from tokenize_field(), and add xlat_resolve_logical_or() / xlat_resolve_logical_and()
	 *	functions which do partial resolution.
	 */
	XLAT_REGISTER_NARY_OP(T_LAND, logical_and, logical);
	XLAT_REGISTER_NARY_OP(T_LOR, logical_or, logical);

	XLAT_REGISTER_MONO("rcode", xlat_func_rcode, xlat_func_rcode_arg);
	XLAT_REGISTER_MONO("exists", xlat_func_exists, xlat_func_exists_arg);
	xlat_async_instantiate_set(xlat, xlat_instantiate_exists, xlat_exists_inst_t, NULL, NULL);
	xlat_print_set(xlat, xlat_expr_print_exists);

	/*
	 *	-EXPR
	 *	~EXPR
	 *	!EXPR
	 */
	XLAT_REGISTER_UNARY(T_SUB, "unary_minus", xlat_func_unary_minus);
	XLAT_REGISTER_UNARY(T_COMPLEMENT, "unary_complement", xlat_func_unary_complement);
	XLAT_REGISTER_UNARY(T_NOT, "unary_not", xlat_func_unary_not);

	/*
	 *	Callback wrapper around old paircmp() API.
	 */
	if (!(xlat = xlat_register(NULL, "paircmp", xlat_paircmp_func, NULL))) return -1; /* never pure! */
	xlat_func_args(xlat, xlat_paircmp_xlat_args);
	xlat_internal(xlat);

	return 0;
}

/*
 *	Must use the same names as above.
 */
static const fr_sbuff_term_elem_t binary_ops[T_TOKEN_LAST] = {
	[ T_ADD ]		= L("op_add"),
	[ T_SUB ]		= L("op_sub"),
	[ T_MUL ]		= L("op_mul"),
	[ T_DIV ]		= L("op_div"),
	[ T_MOD ]		= L("op_mod"),
	[ T_AND ]		= L("op_and"),
	[ T_OR ]		= L("op_or"),
	[ T_XOR ]		= L("op_xor"),
	[ T_RSHIFT ]		= L("op_rshift"),
	[ T_LSHIFT ]		= L("op_lshift"),

	[ T_LAND ]		= L("logical_and"),
	[ T_LOR ]		= L("logical_or"),

	[ T_OP_CMP_EQ ]		= L("cmp_eq"),
	[ T_OP_NE ]		= L("cmp_ne"),
	[ T_OP_LT ]		= L("cmp_lt"),
	[ T_OP_LE ]		= L("cmp_le"),
	[ T_OP_GT ]		= L("cmp_gt"),
	[ T_OP_GE ]		= L("cmp_ge"),

	[ T_OP_REG_EQ ]		= L("reg_eq"),
	[ T_OP_REG_NE ]		= L("reg_ne"),
};

/*
 *	Which are logical operations
 */
static const bool logical_ops[T_TOKEN_LAST] = {
	[T_LAND] = true,
	[T_LOR] = true,
};

/*
 *	Allow for BEDMAS ordering.  Gross ordering is first number,
 *	fine ordering is second number.  Unused operators are assigned as zero.
 *
 *	Larger numbers are higher precedence.
 */
#define P(_x, _y) (((_x) << 4) | (_y))

static const int precedence[T_TOKEN_LAST] = {
	[T_INVALID]	= 0,

	/*
	 *	Assignment operators go here as P(1,n)
	 *
	 *	+= -= *= /= %= <<= >>= &= ^= |=
	 *
	 *	We want the output of the assignment operators to be the result of the assignment.  This means
	 *	that the assignments can really only be done for simple attributes, and not tmpls with filters
	 *	which select multiple attributes.
	 *
	 *	Which (for now) means that we likely want to disallow assignments in expressions.  That's
	 *	fine, as this isn't C, and we're not sure that it makes sense to do something like:
	 *
	 *		if ((&foo += 5) > 60) ...
	 *
	 *	Or maybe it does.  Who knows?
	 */

	[T_LOR]		= P(2,0),
	[T_LAND]	= P(2,1),

	[T_OR]		= P(3,0),
	[T_XOR]		= P(3,1),
	[T_AND]		= P(3,2),

	[T_OP_REG_EQ]	= P(4,0),
	[T_OP_REG_NE]	= P(4,0),

	[T_OP_CMP_EQ]	= P(4,1),
	[T_OP_NE]	= P(4,1),

	[T_OP_LT]	= P(5,0),
	[T_OP_LE]	= P(5,0),
	[T_OP_GT]	= P(5,0),
	[T_OP_GE]	= P(5,0),

	[T_RSHIFT]	= P(6,0),
	[T_LSHIFT]	= P(6,0),

	[T_SUB]		= P(7,0),
	[T_ADD]		= P(7,1),

	[T_MOD]		= P(8,0),
	[T_MUL]		= P(8,1),
	[T_DIV]		= P(8,2),

	[T_LBRACE]	= P(10,0),
};

#define fr_sbuff_skip_whitespace(_x) \
	do { \
		while (isspace((int) fr_sbuff_char(_x, '\0'))) fr_sbuff_advance(_x, 1); \
	} while (0)

static ssize_t tokenize_expression(xlat_exp_head_t *head, xlat_exp_t **out, fr_sbuff_t *in,
				   fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
				   fr_token_t prev, fr_sbuff_parse_rules_t const *bracket_rules,
				   fr_sbuff_parse_rules_t const *input_rules, bool cond);

static ssize_t tokenize_field(xlat_exp_head_t *head, xlat_exp_t **out, fr_sbuff_t *in,
			      fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
			      fr_sbuff_parse_rules_t const *bracket_rules, char *out_c, bool cond);

static fr_table_num_sorted_t const expr_quote_table[] = {
	{ L("\""),	T_DOUBLE_QUOTED_STRING	},	/* Don't re-order, backslash throws off ordering */
	{ L("'"),	T_SINGLE_QUOTED_STRING	},
	{ L("/"),	T_SOLIDUS_QUOTED_STRING	},
	{ L("`"),	T_BACK_QUOTED_STRING	}
};
static size_t expr_quote_table_len = NUM_ELEMENTS(expr_quote_table);


/*
 *	Look for prefix operators
 *
 *	+ = ignore
 *	- = unary_minus(next)
 *	! = unary_not(next)
 *	~ = unary_xor(0, next)
 *	(expr) = recurse, and parse expr
 *
 *	as a special case, <type> is a cast.  Which lets us know how
 *	to parse the next thing we get.  Otherwise, parse the thing as
 *	int64_t.
 */
static fr_slen_t tokenize_unary(xlat_exp_head_t *head, xlat_exp_t **out, fr_sbuff_t *in,
				fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
				fr_sbuff_parse_rules_t const *bracket_rules, char *out_c, bool cond)
{
	xlat_exp_t		*node = NULL, *unary = NULL;
	xlat_t			*func = NULL;
	fr_sbuff_t		our_in = FR_SBUFF(in);
	char			c = '\0';

	XLAT_DEBUG("UNARY <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	/*
	 *	Handle !-~ by adding a unary function to the xlat
	 *	node, with the first argument being the _next_ thing
	 *	we allocate.
	 */
	if (fr_sbuff_next_if_char(&our_in, '!')) { /* unary not */
		func = xlat_func_find("unary_not", 9);
		fr_assert(func != NULL);
		c = '!';
		goto check_for_double;

	}
	else if (fr_sbuff_next_if_char(&our_in, '-')) { /* unary minus */
		fr_sbuff_skip_whitespace(&our_in);

		/*
		 *	-4 is a number, not minus(4).
		 */
		if (fr_sbuff_is_digit(&our_in)) goto field;

		func = xlat_func_find("unary_minus", 11);
		fr_assert(func != NULL);
		c = '-';
		goto check_for_double;

	}
	else if (fr_sbuff_next_if_char(&our_in, '~')) { /* unary complement */
		func = xlat_func_find("unary_complement", 16);
		fr_assert(func != NULL);
		c = '~';
		goto check_for_double;

	}
	else if (fr_sbuff_next_if_char(&our_in, '+')) { /* ignore unary + */
		c = '+';

	check_for_double:
		fr_sbuff_skip_whitespace(&our_in);
		fr_sbuff_skip_whitespace(&our_in);
		if (fr_sbuff_is_char(&our_in, c)) {
			fr_strerror_const("Double operator is invalid");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}
	}

	/*
	 *	Maybe we have a unary not / etc.  If so, make sure
	 *	that we return that, and not the child node
	 */
	if (!func) {
	field:
		return tokenize_field(head, out, in, p_rules, t_rules, bracket_rules, out_c, cond);
	}

	/*
	 *	Tokenize_field may reset this if the operation is wrapped inside of another expression.
	 */
	*out_c = c;

	MEM(unary = xlat_exp_alloc(head, XLAT_FUNC, func->name, strlen(func->name)));
	MEM(unary->call.args = xlat_exp_head_alloc(unary));
	unary->fmt = fr_tokens[func->token];
	unary->call.func = func;
	unary->flags = func->flags;

	if (tokenize_field(unary->call.args, &node, &our_in, p_rules, t_rules, bracket_rules, out_c, (c == '!')) < 0) {
		talloc_free(unary);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	if (!node) {
		fr_strerror_const("Empty expression is invalid");
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	Convert raw rcodes to xlat's.
	 *
	 *	@todo - if it's '!', and the node is tmpl_is_list, or tmpl_contains_attr
	 *	re-write it to an existence check function, with node->fmt the node->vpt->name.
	 *
	 */
	if (reparse_rcode(head, &node, (c == '!')) < 0) {
		talloc_free(unary);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	xlat_func_append_arg(unary, node, (c == '!'));
	unary->flags.can_purify = (unary->call.func->flags.pure && unary->call.args->flags.pure) | unary->call.args->flags.can_purify;

	/*
	 *	Don't add it to head->flags, that will be done when it's actually inserted.
	 */

	*out = unary;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/** Allocate a specific cast node.
 *
 *  With the first argument being a UINT8 of the data type.
 *  See xlat_func_cast() for the implementation.
 *
 */
static xlat_exp_t *expr_cast_alloc(TALLOC_CTX *ctx, fr_type_t type)
{
	xlat_exp_t *cast, *node;

	/*
	 *	Create a "cast" node.  The first argument is a UINT8 value-box of the cast type.  The RHS is
	 *	whatever "node" comes next.
	 */
	MEM(cast = xlat_exp_alloc(ctx, XLAT_FUNC, "cast", 4));
	MEM(cast->call.args = xlat_exp_head_alloc(cast));
	MEM(cast->call.func = xlat_func_find("cast", 4));
	fr_assert(cast->call.func != NULL);
	cast->flags = cast->call.func->flags;

	/*
	 *	Create argv[0] UINT8, with "Cast-Base" as
	 *	the "da".  This allows the printing routines
	 *	to print the name of the type, and not the
	 *	number.
	 */
	MEM(node = xlat_exp_alloc_null(cast));
	xlat_exp_set_type(node, XLAT_BOX);
	node->flags.constant = true;
	xlat_exp_set_name_buffer_shallow(node,
					 talloc_strdup(node,
						       fr_table_str_by_value(fr_type_table,
									     type, "<INVALID>")));

	fr_value_box_init(&node->data, FR_TYPE_UINT8, attr_cast_base, false);
	node->data.vb_uint8 = type;

	xlat_func_append_arg(cast, node, false);

	return cast;
}

static fr_slen_t expr_cast_from_substr(fr_type_t *cast, fr_sbuff_t *in)
{
	char			close = '\0';
	fr_sbuff_t		our_in = FR_SBUFF(in);
	fr_sbuff_marker_t	m;
	ssize_t			slen;

	if (fr_sbuff_next_if_char(&our_in, '<')) {
		close = '>';

	} else if (fr_sbuff_next_if_char(&our_in, '(')) {
		close = ')';

	} else {
	no_cast:
		*cast = FR_TYPE_NULL;
		return 0;
	}

	fr_sbuff_marker(&m, &our_in);
	fr_sbuff_out_by_longest_prefix(&slen, cast, fr_type_table, &our_in, FR_TYPE_NULL);
	if (fr_type_is_null(*cast)) goto no_cast;

	if (!fr_type_is_leaf(*cast)) {
		fr_strerror_printf("Invalid data type '%s' in cast", fr_type_to_str(*cast));
		FR_SBUFF_ERROR_RETURN(&our_in)
	}

	if (!fr_sbuff_next_if_char(&our_in, close)) {
		fr_strerror_const("Unterminated cast");
		FR_SBUFF_ERROR_RETURN(&our_in)
	}
	fr_sbuff_adv_past_whitespace(&our_in, SIZE_MAX, NULL);

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/*
 *	Tokenize the RHS of a regular expression.
 */
static fr_slen_t tokenize_regex_rhs(xlat_exp_head_t *head, xlat_exp_t **out, fr_sbuff_t *in,
				    tmpl_rules_t const *t_rules,
				    fr_sbuff_parse_rules_t const *bracket_rules)
{
	ssize_t			slen;
	xlat_exp_t		*node = NULL;
	fr_sbuff_t		our_in = FR_SBUFF(in);
	fr_sbuff_marker_t	opand_m, flag;
	tmpl_t			*vpt;
	fr_token_t		quote = T_SOLIDUS_QUOTED_STRING;

	XLAT_DEBUG("REGEX_RHS <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	fr_sbuff_skip_whitespace(&our_in);

	/*
	 *	Record where the operand begins for better error offsets later
	 */
	fr_sbuff_marker(&opand_m, &our_in);

	/*
	 *	Regexes cannot have casts or sub-expressions.
	 */
	if (!fr_sbuff_next_if_char(&our_in, '/')) {
		/*
		 *	Allow for m'...' ala Perl
		 */
		if (!fr_sbuff_is_str(&our_in, "m'", 2)) {
			fr_strerror_const("Expected regular expression");
			goto error;
		}

		fr_sbuff_advance(&our_in, 2);
		quote = T_SINGLE_QUOTED_STRING;
	}

	/*
	 *	Allocate the xlat node now so the talloc hierarchy is correct
	 */
	MEM(node = xlat_exp_alloc_null(head));
	xlat_exp_set_type(node, XLAT_TMPL);

	/*
	 *	tmpl_afrom_substr does pretty much all the work of parsing the operand.  Note that we pass '/'
	 *	as the quote, so that the tmpl gets parsed as a regex.
	 */
	(void) tmpl_afrom_substr(node, &vpt, &our_in, T_SOLIDUS_QUOTED_STRING, value_parse_rules_quoted[quote], t_rules);
	if (!vpt) {
	error:
		talloc_free(node);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	@todo - allow for the RHS to be an attribute, too?
	 */

	/*
	 *	It would be nice if tmpl_afrom_substr() did this :(
	 */
	if (!fr_sbuff_next_if_char(&our_in, fr_token_quote[quote])) {
		fr_strerror_const("Unterminated regular expression");
		goto error;
	}

	/*
	 *	Remember where the flags start
	 */
	fr_sbuff_marker(&flag, &our_in);
	if (tmpl_regex_flags_substr(vpt, &our_in, bracket_rules->terminals) < 0) {
		talloc_free(node);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	fr_sbuff_skip_whitespace(&our_in);

	/*
	 *	Try to compile regular expressions, but only if
	 *	they're not being dynamically expanded.
	 */
	if (!tmpl_contains_xlat(vpt)) {
		slen = tmpl_regex_compile(vpt, true);
		if (slen <= 0) goto error;
	}

	node->vpt = vpt;
	node->quote = quote;
	node->fmt = vpt->name;

	node->flags.pure = !tmpl_contains_xlat(node->vpt);
	node->flags.needs_resolving = tmpl_needs_resolving(node->vpt);

	*out = node;

	FR_SBUFF_SET_RETURN(in, &our_in);
}


/*
 *	Tokenize a field without unary operators.
 */
static fr_slen_t tokenize_field(xlat_exp_head_t *head, xlat_exp_t **out, fr_sbuff_t *in,
				fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
				fr_sbuff_parse_rules_t const *bracket_rules, char *out_c, bool cond)
{
	ssize_t			slen;
	xlat_exp_t		*node = NULL;
	fr_sbuff_t		our_in = FR_SBUFF(in);
	fr_sbuff_marker_t	opand_m;
	tmpl_rules_t		our_t_rules = *t_rules;
	tmpl_t			*vpt;
	fr_token_t		quote;

	XLAT_DEBUG("FIELD <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	/*
	 *	Allow for explicit casts.  Non-leaf types are forbidden.
	 */
	if (expr_cast_from_substr(&our_t_rules.cast, &our_in) < 0) return -1;

	/*
	 *	If we still have '(', then recurse for other expressions
	 *
	 *	Tokenize the sub-expression, ensuring that we stop at ')'.
	 *
	 *	Note that if we have a sub-expression, then we don't use the hinting for "type".
	 *	That's because we're parsing a complete expression here (EXPR).  So the intermediate
	 *	nodes in the expression can be almost anything.  And we only cast it to the final
	 *	value when we get the output of the expression.
	 */
	if (fr_sbuff_next_if_char(&our_in, '(')) {
		xlat_exp_t *cast = NULL;
		xlat_exp_head_t *my_head = head;

		if (!fr_type_is_null(our_t_rules.cast)) {
			MEM(cast = expr_cast_alloc(head, our_t_rules.cast));
			my_head = cast->call.args;
		}

		/*
		 *	No input rules means "ignore external terminal sequences, as we're expecting a ')' as
		 *	our terminal sequence.
		 */
		if (tokenize_expression(my_head, &node, &our_in, bracket_rules, t_rules, T_INVALID, bracket_rules, NULL, cond) < 0) {
			talloc_free(cast);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		if (!fr_sbuff_next_if_char(&our_in, ')')) {
			talloc_free(cast);
			fr_strerror_printf("Failed to find trailing ')'");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		/*
		 *	Wrap the entire sub-expression in a "cast", and then return the cast as the parsed node.
		 */
		if (cast) {
			xlat_func_append_arg(cast, node, false);
			node = cast;
		}

		/*
		 *	We've parsed one "thing", so we stop.  The
		 *	next thing shoud be an operator, not another
		 *	value.
		 */
		*out_c = '\0';
		goto done;
	}

	/*
	 *	Record where the operand begins for better error offsets later
	 */
	fr_sbuff_marker(&opand_m, &our_in);

	fr_sbuff_out_by_longest_prefix(&slen, &quote, expr_quote_table, &our_in, T_BARE_WORD);

	switch (quote) {
	default:
	case T_BARE_WORD:
		p_rules = bracket_rules;
		break;

	case T_SOLIDUS_QUOTED_STRING:
		fr_strerror_const("Unexpected regular expression");
		fr_sbuff_set(&our_in, &opand_m);	/* Error points to the quoting char at the start of the string */
		goto error;

	case T_BACK_QUOTED_STRING:
	case T_DOUBLE_QUOTED_STRING:
	case T_SINGLE_QUOTED_STRING:
		p_rules = value_parse_rules_quoted[quote];
		break;
	}

	/*
	 *	Allocate the xlat node now so the talloc hierarchy is correct
	 */
	MEM(node = xlat_exp_alloc_null(head));
	xlat_exp_set_type(node, XLAT_TMPL);

	/*
	 *	tmpl_afrom_substr does pretty much all the work of
	 *	parsing the operand.  It pays attention to the cast on
	 *	our_t_rules, and will try to parse any data there as
	 *	of the correct type.
	 */
	if (tmpl_afrom_substr(node, &vpt, &our_in, quote, p_rules, &our_t_rules) < 0) {
	error:
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	if (quote != T_BARE_WORD) {
		if (!fr_sbuff_is_char(&our_in, fr_token_quote[quote])) {
			fr_strerror_const("Unterminated string");
			fr_sbuff_set(&our_in, &opand_m);
			goto error;
		}

		fr_sbuff_advance(&our_in, 1);

		/*
		 *	Quoted strings just get resolved now.
		 *
		 *	@todo - this means that things like
		 *
		 *		&Session-Timeout == '10'
		 *
		 *	are run-time errors, instead of load-time parse errors.
		 *
		 *	On the other hand, if people assign static strings to non-string
		 *	attributes... they sort of deserve what they get.
		 */
		if (tmpl_is_unresolved(vpt) && (tmpl_resolve(vpt, NULL) < 0)) goto error;
	}

	fr_sbuff_skip_whitespace(&our_in);

	/*
	 *	Do various tmpl fixups.
	 */

	/*
	 *	Don't keep an intermediate tmpl for xlats.  Just hoist
	 *	the xlat to be a child of this node. Exec and regexes
	 *	are left alone, as they are handled by different code.
	 *
	 *	However, we also add a cast if the tmpl had a cast.
	 *	And if there was no cast, but the input was a string,
	 *	then we cast the result to a string, too.
	 */
	if (tmpl_is_xlat(vpt) || tmpl_is_xlat_unresolved(vpt)) {
		xlat_exp_head_t *xlat = tmpl_xlat(vpt);
		xlat_exp_t *cast;
		fr_type_t type;

		talloc_steal(node, xlat);
		node->fmt = talloc_typed_strdup(node, vpt->name);
		talloc_free(vpt);

		xlat_exp_set_type(node, XLAT_GROUP);
		node->quote = quote;
		node->group = xlat;

		node->flags = xlat->flags;

		if (quote != T_BARE_WORD) {
			if (tmpl_rules_cast(vpt) != FR_TYPE_NULL) {
				type = tmpl_rules_cast(vpt);

			} else {
				type = FR_TYPE_STRING;

				/*
				 *	The string is T_DOUBLE_QUOTED_STRING, or T_BACK_QUOTED_STRING,
				 *	both of which have double-quoting rules.
				 *
				 *	'foo' can't contain an xlat.
				 *	/foo/ is forbidden, as we don't expect a regex here.
				 *
				 *	We rely on xlat_func_cast() to see the `string` cast, and then to
				 *	_print_ the result to a string.
				 */
			}

			MEM(cast = expr_cast_alloc(head, type));
			xlat_func_append_arg(cast, node, false);
			node = cast;
		}

	} else {
		/*
		 *	Else we're not hoisting, set the node to the VPT
		 */
		node->vpt = vpt;
		node->quote = quote;
		node->fmt = vpt->name;

		node->flags.pure = tmpl_is_data(node->vpt);
		node->flags.constant = node->flags.pure;
		node->flags.needs_resolving = tmpl_needs_resolving(node->vpt);
	}

	/*
	 *	Try and add any unknown attributes to the dictionary
	 *	immediately.  This means any future references point
	 *	to the same da.
	 */
	if (tmpl_is_attr(vpt)) {
		fr_assert(!node->flags.pure);
		if (tmpl_attr_unknown_add(vpt) < 0) {
			fr_strerror_printf("Failed defining attribute %s", tmpl_da(vpt)->name);
			fr_sbuff_set(&our_in, &opand_m);
			goto error;
		}
	}

	if (tmpl_is_data(vpt)) {
		/*
		 *	Print "true" and "false" instead of "yes" and "no".
		 */
		if ((tmpl_value_type(vpt) == FR_TYPE_BOOL) && !tmpl_value_enumv(vpt)) {
			tmpl_value_enumv(vpt) = attr_expr_bool_enum;
		}

		node->flags.constant = true;
	}

	fr_assert(!tmpl_contains_regex(vpt));

done:
	*out = node;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

/*
 *	A mapping of operators to tokens.
 */
static fr_table_num_ordered_t const expr_assignment_op_table[] = {
	{ L("!="),	T_OP_NE			},

	{ L("&"),	T_AND			},
	{ L("&&"),	T_LAND			},
	{ L("*"),	T_MUL			},
	{ L("+"),	T_ADD			},
	{ L("-"),	T_SUB			},
	{ L("/"),	T_DIV			},
	{ L("%"),	T_MOD			},
	{ L("^"),	T_XOR			},

	{ L("|"),	T_OR			},
	{ L("||"),	T_LOR			},

	{ L("<"),	T_OP_LT			},
	{ L("<<"),	T_LSHIFT    		},
	{ L("<="),	T_OP_LE			},

	{ L("="),	T_OP_EQ			},
	{ L("=="),	T_OP_CMP_EQ		},

	{ L("=~"),	T_OP_REG_EQ		},
	{ L("!~"),	T_OP_REG_NE		},

	{ L(">"),	T_OP_GT			},
	{ L(">="),	T_OP_GE			},
	{ L(">>"),	T_RSHIFT    		},

};
static size_t const expr_assignment_op_table_len = NUM_ELEMENTS(expr_assignment_op_table);

static bool valid_type(xlat_exp_t *node)
{
	fr_dict_attr_t const *da;

#ifdef STATIC_ANALYZER
	if (!node) return false;
#endif

	if (node->type != XLAT_TMPL) return true;

	if (tmpl_is_list(node->vpt)) {
	list:
		fr_strerror_const("Cannot use list references in condition");
		return false;
	}

	if (!tmpl_is_attr(node->vpt)) return true;

	da = tmpl_da(node->vpt);
	if (fr_type_is_structural(da->type)) {
		if (da->dict == fr_dict_internal()) goto list;

		fr_strerror_const("Cannot use structural types in condition");
		return false;
	}

	return true;
}


/** Tokenize a mathematical operation.
 *
 *	(EXPR)
 *	!EXPR
 *	A OP B
 *
 *	If "out" is NULL then the expression is added to "head".
 *	Otherwise, it's returned to the caller.
 */
static fr_slen_t tokenize_expression(xlat_exp_head_t *head, xlat_exp_t **out, fr_sbuff_t *in,
				     fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
				     fr_token_t prev, fr_sbuff_parse_rules_t const *bracket_rules,
				     fr_sbuff_parse_rules_t const *input_rules, bool cond)
{
	xlat_exp_t	*lhs = NULL, *rhs, *node;
	xlat_t		*func = NULL;
	fr_token_t	op;
	ssize_t		slen;
	fr_sbuff_marker_t  m_lhs, m_op, m_rhs;
	fr_sbuff_t	our_in = FR_SBUFF(in);
	xlat_exp_head_t *args;
	char c = '\0';

	XLAT_DEBUG("EXPRESSION <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	fr_sbuff_skip_whitespace(&our_in);

	fr_sbuff_marker(&m_lhs, &our_in);

	/*
	 *	Get the LHS of the operation.
	 */
	slen = tokenize_unary(head, &lhs, &our_in, p_rules, t_rules, bracket_rules, &c, cond);
	if (slen < 0) FR_SBUFF_ERROR_RETURN(&our_in);

	if (slen == 0) {
		fr_assert(lhs == NULL);
		*out = NULL;
		FR_SBUFF_SET_RETURN(in, &our_in);
	}

redo:
	rhs = NULL;

#ifdef STATIC_ANALYZER
	if (!lhs) return 0;	/* shut up stupid analyzer */
#else
	fr_assert(lhs != NULL);
#endif

	fr_sbuff_skip_whitespace(&our_in);

	/*
	 *	No more input, we're done.
	 */
	if (fr_sbuff_extend(&our_in) == 0) {
	done:
		*out = lhs;
		FR_SBUFF_SET_RETURN(in, &our_in);
	}

	/*
	 *	')' is a terminal, even if we didn't expect it.
	 *	Because if we didn't expect it, then it's an error.
	 *
	 *	If we did expect it, then we return whatever we found,
	 *	and let the caller eat the ')'.
	 */
	if (fr_sbuff_is_char(&our_in, ')')) {
		if (!bracket_rules) {
			fr_strerror_printf("Unexpected ')'");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		goto done;
	}
	fr_sbuff_skip_whitespace(&our_in);

	/*
	 *	We hit a terminal sequence, stop.
	 */
	if (input_rules && fr_sbuff_is_terminal(&our_in, input_rules->terminals)) goto done;

	/*
	 *	Remember where we were after parsing the LHS.
	 */
	fr_sbuff_marker(&m_op, &our_in);

	/*
	 *	Get the operator.
	 */
	XLAT_DEBUG("    operator <-- %pV", fr_box_strvalue_len(fr_sbuff_current(&our_in), fr_sbuff_remaining(&our_in)));
	fr_sbuff_out_by_longest_prefix(&slen, &op, expr_assignment_op_table, &our_in, T_INVALID);
	if (op == T_INVALID) {
		talloc_free(lhs);
		fr_strerror_printf("Invalid operator");
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	if (!binary_ops[op].str) {
		fr_strerror_printf("Invalid operator");
		fr_sbuff_set(&our_in, &m_op);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	fr_assert(precedence[op] != 0);

	/*
	 *	a * b + c ... = (a * b) + c ...
	 *
	 *	Feed the current expression to the caller, who will
	 *	take care of continuing.
	 */
	if (precedence[op] <= precedence[prev]) {
		fr_sbuff_set(&our_in, &m_op);
		goto done;
	}

	/*
	 *	&Foo and !&Foo are permitted as the LHS of || and &&
	 */
	if (((c == '!') || (c == '~')) && (op != T_LAND) && (op != T_LOR)) {
		fr_strerror_printf("Operator '%c' is only applied to the left hand side of the '%s' operation, add (..) to evaluate the operation first", c, fr_tokens[op]);
	fail_lhs:
		fr_sbuff_set(&our_in, &m_lhs);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	fr_sbuff_skip_whitespace(&our_in);
	fr_sbuff_marker(&m_rhs, &our_in);

#if 0
	/*
	 *	If LHS is attr && structural, allow only == and !=, then check that the RHS is {}.
	 *
	 *	However, we don't want the LHS evaluated, so just re-write it as an "exists" xlat?
	 *
	 *	@todo - check lists for equality?
	 */
	if ((lhs->type == XLAT_TMPL) && tmpl_is_attr(lhs->vpt) && fr_type_is_structural(tmpl_da(lhs->vpt)->type)) {
		if ((op != T_OP_CMP_EQ) && (op != T_OP_NE)) {
			fr_strerror_printf("Invalid operatord '%s' for left hand side structural attribute", fr_tokens[op]);
			fr_sbuff_set(&our_in, &m_op);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		fr_assert(0);
	}
#endif

	/*
	 *	We now parse the RHS, allowing a (perhaps different) cast on the RHS.
	 */
	XLAT_DEBUG("    recurse RHS <-- %pV", fr_box_strvalue_len(fr_sbuff_current(&our_in), fr_sbuff_remaining(&our_in)));
	if ((op == T_OP_REG_EQ) || (op == T_OP_REG_NE)) {
		slen = tokenize_regex_rhs(head, &rhs, &our_in, t_rules, bracket_rules);
	} else {
		slen = tokenize_expression(head, &rhs, &our_in, p_rules, t_rules, op, bracket_rules, input_rules, cond);
	}
	if (slen < 0) {
		talloc_free(lhs);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

#ifdef STATIC_ANALYZER
	if (!rhs) return -1;
#endif

	func = xlat_func_find(binary_ops[op].str, binary_ops[op].len);
	fr_assert(func != NULL);

	/*
	 *	If it's a logical operator, check for rcodes, and then
	 *	try to purify the results.
	 */
	if (logical_ops[op]) {
		if (reparse_rcode(head, &rhs, true) < 0) {
		fail_rhs:
			fr_sbuff_set(&our_in, &m_rhs);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		if ((lhs->type == XLAT_FUNC) && (lhs->call.func->token == op)) {
			xlat_func_append_arg(lhs, rhs, cond);

			lhs->call.args->flags.can_purify |= rhs->flags.can_purify | rhs->flags.pure;
			lhs->flags.can_purify = lhs->call.args->flags.can_purify;
			goto redo;
		}

		if (reparse_rcode(head, &lhs, true) < 0) goto fail_lhs;
		goto purify;
	}

	/*
	 *	Complain on comparisons between invalid data types.
	 *
	 *	@todo - allow
	 *
	 *		&structural == {}
	 *		&structural != {}
	 *
	 *	as special cases, so we can check lists for emptiness.
	 */
	if (fr_equality_op[op]) {
		if (!valid_type(lhs)) goto fail_lhs;
		if (!valid_type(rhs)) goto fail_rhs;

		/*
		 *	Peephole optimization.  If both LHS
		 *	and RHS are static values, then just call the
		 *	relevant condition code to get the result.
		 */
		if (cond) {
			int rcode;

		purify:
			rcode = xlat_purify_op(head, &node, lhs, op, rhs);
			if (rcode < 0) goto fail_lhs;

			if (rcode) {
				lhs = node;
				goto redo;
			}
		}
	}

	/*
	 *	Create the function node, with the LHS / RHS arguments.
	 */
	MEM(node = xlat_exp_alloc(head, XLAT_FUNC, fr_tokens[op], strlen(fr_tokens[op])));
	MEM(node->call.args = args = xlat_exp_head_alloc(node));
	node->fmt = fr_tokens[op];
	node->call.func = func;
	node->flags = func->flags;

	xlat_func_append_arg(node, lhs, logical_ops[op] && cond);
	xlat_func_append_arg(node, rhs, logical_ops[op] && cond);

	fr_assert(xlat_exp_head(node->call.args) != NULL);

	/*
	 *	Logical operations can be purified if ANY of their arguments can be purified.
	 */
	if (logical_ops[op]) {
		xlat_exp_foreach(node->call.args, arg) {
			node->call.args->flags.can_purify |= arg->flags.can_purify | arg->flags.pure;
			if (node->call.args->flags.can_purify) break;
		}
		node->flags.can_purify = node->call.args->flags.can_purify;

	} else {
		node->flags.can_purify = (node->call.func->flags.pure && node->call.args->flags.pure) | node->call.args->flags.can_purify;
	}

	lhs = node;
	goto redo;
}

static const fr_sbuff_term_t bracket_terms = FR_SBUFF_TERMS(
	L(""),
	L(")"),
);

static const fr_sbuff_term_t operator_terms = FR_SBUFF_TERMS(
	L("\t"),
	L("\n"),
	L("\r"),
	L(" "),
	L("!"),
	L("%"),
	L("&"),
	L("*"),
	L("+"),
	L("-"),
	L("/"),
	L("<"),
	L("="),
	L(">"),
	L("^"),
	L("|"),
	L("~"),
);

static fr_slen_t xlat_tokenize_expression_internal(TALLOC_CTX *ctx, xlat_exp_head_t **out, fr_sbuff_t *in,
						   fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules, bool cond)
{
	ssize_t slen;
	fr_sbuff_parse_rules_t *bracket_rules = NULL;
	fr_sbuff_parse_rules_t *terminal_rules = NULL;
	tmpl_rules_t my_rules = { };
	xlat_exp_head_t *head;
	xlat_exp_t *node = NULL;

	/*
	 *	Whatever the caller passes, ensure that we have a
	 *	terminal rule which ends on operators, and a terminal
	 *	rule which ends on ')'.
	 */
	MEM(bracket_rules = talloc_zero(ctx, fr_sbuff_parse_rules_t));
	MEM(terminal_rules = talloc_zero(ctx, fr_sbuff_parse_rules_t));
	if (p_rules) {
		*bracket_rules = *p_rules;
		*terminal_rules = *p_rules;

		if (p_rules->terminals) {
			MEM(terminal_rules->terminals = fr_sbuff_terminals_amerge(terminal_rules,
										  p_rules->terminals,
										  &operator_terms));
		} else {
			terminal_rules->terminals = &operator_terms;
		}
	} else {
		terminal_rules->terminals = &operator_terms;
	}
	MEM(bracket_rules->terminals = fr_sbuff_terminals_amerge(bracket_rules,
								 terminal_rules->terminals,
								 &bracket_terms));

	MEM(head = xlat_exp_head_alloc(ctx));
	if (t_rules) {
		head->dict = t_rules->attr.dict_def;
	} else {
		t_rules = &my_rules;
	}

	slen = tokenize_expression(head, &node, in, terminal_rules, t_rules, T_INVALID, bracket_rules, p_rules, cond);
	talloc_free(bracket_rules);
	talloc_free(terminal_rules);

	if (slen < 0) {
		talloc_free(head);
		FR_SBUFF_ERROR_RETURN(in);
	}

	if (!node) {
		*out = head;
		return slen;
	}

	/*
	 *	Convert raw rcodes to xlat's.
	 */
	if (reparse_rcode(head, &node, true) < 0) {
		talloc_free(head);
		return -1;
	}

	/*
	 *	Convert raw existence checks to existence functions.
	 */
	if (cond && (node->type == XLAT_TMPL) && tmpl_contains_attr(node->vpt)) {
		node = xlat_exists_alloc(head, node);
	}

	xlat_exp_insert_tail(head, node);

	/*
	 *	Add nodes that need to be bootstrapped to
	 *	the registry.
	 */
	if (xlat_bootstrap(head) < 0) {
		talloc_free(head);
		return -1;
	}

	*out = head;
	return slen;
}

fr_slen_t xlat_tokenize_expression(TALLOC_CTX *ctx, xlat_exp_head_t **out, fr_sbuff_t *in,
				 fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	return xlat_tokenize_expression_internal(ctx, out, in, p_rules, t_rules, false);
}

fr_slen_t xlat_tokenize_condition(TALLOC_CTX *ctx, xlat_exp_head_t **out, fr_sbuff_t *in,
				 fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	return xlat_tokenize_expression_internal(ctx, out, in, p_rules, t_rules, true);
}


/** Tokenize an xlat expression at runtime
 *
 * This function is only for testing.  It should be deleted when
 * expressions are integrated into the main xlat parser.
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
fr_slen_t xlat_tokenize_ephemeral_expression(TALLOC_CTX *ctx, xlat_exp_head_t **out,
					     fr_event_list_t *el, fr_sbuff_t *in,
					     fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	ssize_t slen;
	fr_sbuff_parse_rules_t *bracket_rules = NULL;
	fr_sbuff_parse_rules_t *terminal_rules = NULL;
	tmpl_rules_t my_rules = { };
	xlat_exp_head_t *head;
	xlat_exp_t *node = NULL;

	/*
	 *	Whatever the caller passes, ensure that we have a
	 *	terminal rule which ends on operators, and a terminal
	 *	rule which ends on ')'.
	 */
	MEM(bracket_rules = talloc_zero(ctx, fr_sbuff_parse_rules_t));
	MEM(terminal_rules = talloc_zero(ctx, fr_sbuff_parse_rules_t));
	if (p_rules) {
		*bracket_rules = *p_rules;
		*terminal_rules = *p_rules;

		if (p_rules->terminals) {
			MEM(terminal_rules->terminals = fr_sbuff_terminals_amerge(terminal_rules,
										  p_rules->terminals,
										  &operator_terms));
		} else {
			terminal_rules->terminals = &operator_terms;
		}
	} else {
		terminal_rules->terminals = &operator_terms;
	}
	MEM(bracket_rules->terminals = fr_sbuff_terminals_amerge(bracket_rules,
								 terminal_rules->terminals,
								 &bracket_terms));
	MEM(head = xlat_exp_head_alloc(ctx));


	if (t_rules) {
		my_rules = *t_rules;
		head->dict = t_rules->attr.dict_def;
	}

	my_rules.xlat.runtime_el = el;
	my_rules.at_runtime = true;

	slen = tokenize_expression(head, &node, in, terminal_rules, &my_rules, T_INVALID, bracket_rules, p_rules, false);
	talloc_free(bracket_rules);
	talloc_free(terminal_rules);

	if (slen < 0) {
		talloc_free(head);
		FR_SBUFF_ERROR_RETURN(in);
	}

	if (!node) {
		*out = head;
		return slen;
	}

	/*
	 *	Convert raw rcodes to xlat's.
	 */
	if (reparse_rcode(head, &node, true) < 0) {
		talloc_free(head);
		return -1;
	}

	xlat_exp_insert_tail(head, node);

	/*
	 *	Create ephemeral instance data for the xlat
	 */
	if (xlat_instantiate_ephemeral(head, el) < 0) {
		talloc_free(head);
		return -1;
	}

	*out = head;
	return slen;
}

/**  Allow callers to see if an xlat is truthy
 *
 *  So the caller can cache it, and needs to check fewer things at run
 *  time.
 *
 *  @param[in] head	of the xlat to check
 *  @param[out] out	truthiness of the box
 *  @return
 *	- false - xlat is not truthy, *out is unchanged.
 *	- true - xlat is truthy, *out is the result of fr_value_box_is_truthy()
 */
bool xlat_is_truthy(xlat_exp_head_t const *head, bool *out)
{
	xlat_exp_t const *node;
	fr_value_box_t const *box;

	/*
	 *	Only pure / constant things can be truthy.
	 */
	if (!head->flags.pure) goto return_false;

	node = xlat_exp_head(head);
	if (!node) {
		*out = false;
		return true;
	}

	if (xlat_exp_next(head, node)) goto return_false;

	if (node->type == XLAT_BOX) {
		box = &node->data;

	} else if ((node->type == XLAT_TMPL) && tmpl_is_data(node->vpt)) {
		box = tmpl_value(node->vpt);

	} else {
	return_false:
		*out = false;
		return false;
	}

	*out = fr_value_box_is_truthy(box);
	return true;
}
