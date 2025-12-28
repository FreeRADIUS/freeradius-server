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
#include <freeradius-devel/util/debug.h>
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

	/*
	 *	Wrap existence checks for attribute reference.
	 */
	if (exists && (node->type == XLAT_TMPL) && tmpl_contains_attr(node->vpt)) {
		node = xlat_exists_alloc(head, node);
	}

	if (!head->call.args) {
		MEM(head->call.args = xlat_exp_head_alloc(head));
		head->call.args->is_argv = true;
	}

	/*
	 *	Wrap it in a group.
	 */
	group = xlat_exp_alloc(head->call.args, XLAT_GROUP, NULL, 0);
	group->quote = T_BARE_WORD;

	xlat_exp_set_name_shallow(group, node->fmt); /* not entirely correct, but good enough for now */
	group->flags = node->flags;

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

	fr_assert(child->type == XLAT_TMPL);
	fr_assert(tmpl_contains_attr(child->vpt));

	/*
	 *	Create an "exists" node.
	 */
	MEM(node = xlat_exp_alloc(ctx, XLAT_FUNC, "exists", 6));
	xlat_exp_set_name_shallow(node, child->vpt->name);

	MEM(node->call.func = xlat_func_find("exists", 6));
	fr_assert(node->call.func != NULL);

	/*
	 *	The attribute may need resolving, in which case we have to set the flag as appropriate.
	 */
	node->flags = (xlat_flags_t) { .needs_resolving = tmpl_needs_resolving(child->vpt)};

	if (!node->flags.needs_resolving) node->call.dict = tmpl_attr_tail_da(child->vpt)->dict;

	xlat_func_append_arg(node, child, false);

	return node;
}


static fr_slen_t xlat_expr_print_unary(fr_sbuff_t *out, xlat_exp_t const *node, UNUSED void *inst, fr_sbuff_escape_rules_t const *e_rules)
{
	size_t	at_in = fr_sbuff_used_total(out);

	FR_SBUFF_IN_STRCPY_RETURN(out, fr_tokens[node->call.func->token]);
	xlat_print_node(out, node->call.args, xlat_exp_head(node->call.args), e_rules, 0);

	return fr_sbuff_used_total(out) - at_in;
}

static fr_slen_t xlat_expr_print_binary(fr_sbuff_t *out, xlat_exp_t const *node, UNUSED void *inst, fr_sbuff_escape_rules_t const *e_rules)
{
	size_t	at_in = fr_sbuff_used_total(out);
	xlat_exp_t *child = xlat_exp_head(node->call.args);

	fr_assert(child != NULL);

	FR_SBUFF_IN_CHAR_RETURN(out, '(');
	xlat_print_node(out, node->call.args, child, e_rules, 0); /* prints a space after the first argument */

	FR_SBUFF_IN_STRCPY_RETURN(out, fr_tokens[node->call.func->token]);
	FR_SBUFF_IN_CHAR_RETURN(out, ' ');

	child = xlat_exp_next(node->call.args, child);
	fr_assert(child != NULL);

	xlat_print_node(out, node->call.args, child, e_rules, 0);

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

		my_tr_rules.enumv = tmpl_attr_tail_da(a->vpt);

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

		my_tr_rules.enumv = tmpl_attr_tail_da(b->vpt);

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

static void fr_value_box_init_zero(fr_value_box_t *vb, fr_type_t type)
{
	switch (type) {
	case FR_TYPE_STRING:
		fr_value_box_strdup_shallow(vb, NULL, "", false);
		break;

	case FR_TYPE_OCTETS:
		fr_value_box_memdup_shallow(vb, NULL, (void const *) "", 0, false);
		break;

	default:
		fr_value_box_init(vb, type, NULL, false);
		break;
	}
}

static xlat_arg_parser_t const binary_op_xlat_args[] = {
	{ .required = false, .type = FR_TYPE_VOID },
	{ .required = false, .type = FR_TYPE_VOID },
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
	fr_value_box_t one, two;

	MEM(dst = fr_value_box_alloc_null(ctx));

	/*
	 *	Each argument is a FR_TYPE_GROUP, with one or more elements in a list.
	 */
	a = fr_value_box_list_head(in);
	if (!a) {
		REDEBUG("Left argument to %s is missing", fr_tokens[op]);
		return XLAT_ACTION_FAIL;
	}

	b = fr_value_box_list_next(in, a);
	if (!b) {
		REDEBUG("Right argument to %s is missing", fr_tokens[op]);
		return XLAT_ACTION_FAIL;
	}

	fr_assert(!fr_comparison_op[op]);

	if (fr_value_box_list_num_elements(&a->vb_group) > 1) {
		REDEBUG("Expected one value as the first argument, got %u",
			fr_value_box_list_num_elements(&a->vb_group));
		return XLAT_ACTION_FAIL;
	}
	a = fr_value_box_list_head(&a->vb_group);

	if (fr_value_box_list_num_elements(&b->vb_group) > 1) {
		REDEBUG("Expected one value as the second argument, got %u",
			fr_value_box_list_num_elements(&b->vb_group));
		return XLAT_ACTION_FAIL;
	}
	b = fr_value_box_list_head(&b->vb_group);

	if (!a) {
		a = &one;
		fr_value_box_init_zero(a, b->type);
	}

	if (!b) {
		b = &two;
		fr_value_box_init_zero(b, a->type);
	}

	rcode = fr_value_calc_binary_op(dst, dst, default_type, a, op, b);
	if (rcode < 0) {
		RPEDEBUG("Failed calculating '%pV %s %pV'", a, fr_tokens[op], b);
		talloc_free(dst);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Over-write, but only if it's present.  Otherwise leave
	 *	any existing enum alone.
	 */
	if (enumv) dst->enumv = enumv;
	fr_dcursor_append(out, dst);

	VALUE_BOX_LIST_VERIFY((fr_value_box_list_t *)out->dlist);
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

static xlat_arg_parser_t const binary_cmp_xlat_args[] = {
	{ .required = false, .type = FR_TYPE_VOID },
	{ .required = false, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/*
 *	@todo - arguably this function should process its own arguments, like logical_or.
 *
 *	That way it can return XLAT_ACTION_FAIL if either argument fails to be found,
 *	or if the comparison matches, it returns the RHS value.  This behavior will
 *	let us to multiple comparisons, like:
 *
 *		if (0 < x < 5) ...
 *
 *	Which is then syntactic sugar for
 *
 *		if ((0 < x) < 5) ...
 *
 *	That means the comparisons no longer return "bool", so if we
 *	want to do this, the change has to be made before v4 is
 *	released.
 *
 *	Other operators like "+=" would return their LHS value.  But in order to do that, we would have to
 *	update the expression parser to allow in-place edits, and that may be a fair bit of work.
 *
 *	It also lets us do more interesting selectors, such as:
 *
 *		foo || (0 < x)
 *
 *	which if "foo" doesn't exist, evaluates the RHS, and then returns "x" only if x is greater than zero.
 *	This short-hand can remove a lot of complex / nested "if" conditions.
 *
 *	It could also allow us to do better attribute filtering:
 *
 *		foo := (0 < foo < 5)
 *
 *	Which ensures that "foo" has value only 1..4.
 *
 *	It would be nice to have a syntax for "self", so we could instead do:
 *
 *		foo := (0 < $$ < 5)
 *
 *	Which could then also be used inside of attribute selectors:
 *
 *		foreach foo (Vendor-Specific.Cisco.AVPair[$$ =~ /^x/]) { ...
 *
 *	and now that we have pair cursors as value-boxes, this becomes a lot easier.
 *	"$$" then becomes syntactic sugar for "the pair at the current cursor".
 *
 *	It also means tracking somehow the value of $$ in the interpreter?  Maybe as a short-hand, just update
 *	the #request_t to add a #fr_pair_t of the current cursor value.  This is a horrible hack, but would be
 *	easy to do.  It doesn't allow nested cursors, but whatever.  The syntax for that would be hard to get
 *	right.
 */
static xlat_action_t xlat_cmp_op(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 UNUSED xlat_ctx_t const *xctx,
				 UNUSED request_t *request, fr_value_box_list_t *in,
				 fr_token_t op)
{
	int rcode;
	fr_value_box_t	*dst, *a, *b;

	/*
	 *	Each argument is a FR_TYPE_GROUP, with one or more elements in a list.
	 */
	a = fr_value_box_list_head(in);
	if (!a) {
		REDEBUG("Left argument to %s is missing", fr_tokens[op]);
		return XLAT_ACTION_FAIL;
	}

	b = fr_value_box_list_next(in, a);
	if (!b) {
		REDEBUG("Right argument to %s is missing", fr_tokens[op]);
		return XLAT_ACTION_FAIL;
	}

	fr_assert(a->type == FR_TYPE_GROUP);
	fr_assert(b->type == FR_TYPE_GROUP);

	fr_assert(fr_comparison_op[op]);

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum));

	rcode = fr_value_calc_list_cmp(dst, dst, &a->vb_group, op, &b->vb_group);
	if (rcode < 0) {
		talloc_free(dst);
		return XLAT_ACTION_FAIL;
	}

	fr_assert(dst->type == FR_TYPE_BOOL);
	dst->enumv = attr_expr_bool_enum;

	fr_dcursor_append(out, dst);
	VALUE_BOX_LIST_VERIFY((fr_value_box_list_t *)out->dlist);
	return XLAT_ACTION_DONE;
}


#define XLAT_CMP_FUNC(_name, _op)  \
static xlat_action_t xlat_func_ ## _name(TALLOC_CTX *ctx, fr_dcursor_t *out, \
				   xlat_ctx_t const *xctx, \
				   request_t *request, fr_value_box_list_t *in)  \
{ \
	return xlat_cmp_op(ctx, out, xctx, request, in, _op); \
}

XLAT_CMP_FUNC(cmp_eq,  T_OP_CMP_EQ)
XLAT_CMP_FUNC(cmp_ne,  T_OP_NE)
XLAT_CMP_FUNC(cmp_lt,  T_OP_LT)
XLAT_CMP_FUNC(cmp_le,  T_OP_LE)
XLAT_CMP_FUNC(cmp_gt,  T_OP_GT)
XLAT_CMP_FUNC(cmp_ge,  T_OP_GE)
XLAT_CMP_FUNC(cmp_eq_type,  T_OP_CMP_EQ_TYPE)
XLAT_CMP_FUNC(cmp_ne_type,  T_OP_CMP_NE_TYPE)

typedef struct {
	fr_token_t	op;
	regex_t		*regex;		//!< precompiled regex
	xlat_exp_t	*xlat;		//!< to expand
	fr_regex_flags_t *regex_flags;
} xlat_regex_inst_t;

typedef struct {
	unlang_result_t		last_result;
	fr_value_box_list_t	list;
} xlat_regex_rctx_t;

static fr_slen_t xlat_expr_print_regex(fr_sbuff_t *out, xlat_exp_t const *node, void *instance, fr_sbuff_escape_rules_t const *e_rules)
{
	size_t			at_in = fr_sbuff_used_total(out);
	xlat_exp_t		*child = xlat_exp_head(node->call.args);
	xlat_regex_inst_t	*inst = instance;

	fr_assert(child != NULL);

	FR_SBUFF_IN_CHAR_RETURN(out, '(');
	xlat_print_node(out, node->call.args, child, e_rules, 0);

	/*
	 *	A space is printed after the first argument only if
	 *	there's a second one.  So add one if we "ate" the second argument.
	 */
	if (inst->xlat) FR_SBUFF_IN_CHAR_RETURN(out, ' ');

	FR_SBUFF_IN_STRCPY_RETURN(out, fr_tokens[node->call.func->token]);
	FR_SBUFF_IN_CHAR_RETURN(out, ' ');

	/*
	 *	Regexes which aren't instantiated: only for unit tests.
	 */
	if (!inst->xlat) {
		child = xlat_exp_next(node->call.args, child);

		fr_assert(child != NULL);
		fr_assert(!xlat_exp_next(node->call.args, child));
		fr_assert(child->type == XLAT_GROUP);

		FR_SBUFF_IN_CHAR_RETURN(out, '/');
		FR_SBUFF_IN_STRCPY_RETURN(out, child->fmt);
		FR_SBUFF_IN_CHAR_RETURN(out, '/');

		child = xlat_exp_head(child->group);
		fr_assert(child->type == XLAT_TMPL);

		/*
		 *	The RHS may be a group
		 */
		FR_SBUFF_RETURN(regex_flags_print, out, tmpl_regex_flags(child->vpt));
		goto done;
	}

	fr_assert(tmpl_contains_regex(inst->xlat->vpt));

	if (inst->xlat->quote == T_SINGLE_QUOTED_STRING) FR_SBUFF_IN_CHAR_RETURN(out, 'm');
	FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[inst->xlat->quote]);
	FR_SBUFF_IN_STRCPY_RETURN(out, inst->xlat->vpt->name);
	FR_SBUFF_IN_CHAR_RETURN(out, fr_token_quote[inst->xlat->quote]);

	FR_SBUFF_RETURN(regex_flags_print, out, inst->regex_flags);

done:
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

	if (tmpl_is_data_unresolved(regex->vpt)) {
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


static xlat_arg_parser_t const regex_op_xlat_args[] = {
	{ .required = true, .type = FR_TYPE_STRING },
	{ .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_arg_parser_t const regex_search_xlat_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },  /* regex string */
	{ .required = true, .concat = false, .type = FR_TYPE_STRING }, /* broken out things to match */
	{ .required = false, .concat = true, .type = FR_TYPE_STRING }, /* flags */
	XLAT_ARG_PARSER_TERMINATOR
};


/** Perform a regular expressions comparison between two operands
 *
 * @param[in] ctx		to allocate resulting box in.
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
 * @param[out] out		Where result is written.
 * @param[in] op		the operation to perform.
 * @return
 *	- -1 on failure.
 *	- 0 for "no match".
 *	- 1 for "match".
 */
static xlat_action_t xlat_regex_do_op(TALLOC_CTX *ctx, request_t *request, fr_value_box_list_t *in, regex_t **preg,
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
	fr_value_box_t	safety = {};

	FR_SBUFF_TALLOC_THREAD_LOCAL(&agg, 256, 8192);

	arg = fr_value_box_list_head(in);
	fr_assert(arg != NULL);
	fr_assert(arg->type == FR_TYPE_GROUP);

	subcaptures = regex_subcapture_count(*preg);
	if (!subcaptures) subcaptures = REQUEST_MAX_REGEX + 1;	/* +1 for %{0} (whole match) capture group */
	MEM(regmatch = regex_match_data_alloc(NULL, subcaptures));

	while ((vb = fr_value_box_list_pop_head(&arg->vb_group)) != NULL) {
		if (vb->type == FR_TYPE_STRING) {
			subject = vb->vb_strvalue;
			len = vb->vb_length;
			fr_value_box_safety_copy(&safety, vb);

		} else {
			fr_value_box_list_t	list;

			fr_value_box_list_init(&list);
			fr_value_box_list_insert_head(&list, vb);
			fr_value_box_mark_safe_for(&safety, FR_VALUE_BOX_SAFE_FOR_ANY);

			vb = NULL;

			/*
			 *	Concatenate everything, and escape untrusted inputs.
			 */
			if (fr_value_box_list_concat_as_string(&safety, agg, &list, NULL, 0, &regex_escape_rules,
							       FR_VALUE_BOX_LIST_FREE_BOX, FR_REGEX_SAFE_FOR, true) < 0) {
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
			regex_sub_to_request(request, NULL, NULL, NULL);	/* clear out old entries */
			continue;

		case 1:
			regex_sub_to_request(request, preg, &regmatch, &safety);
			talloc_free(vb);
			goto done;

		}

		talloc_free(vb);
	}

done:
	talloc_free(regmatch);	/* free if not consumed */

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum));
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
	if (!XLAT_RESULT_SUCCESS(&rctx->last_result)) {
		talloc_free(rctx);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *      Because we expanded the RHS ourselves, the "concat"
	 *      flag to the RHS argument is ignored.  So we just
	 *      concatenate it here.  We escape the various untrusted inputs.
	 */
	if (fr_value_box_list_concat_as_string(NULL, agg, &rctx->list, NULL, 0, &regex_escape_rules,
					       FR_VALUE_BOX_LIST_FREE_BOX, FR_REGEX_SAFE_FOR, true) < 0) {
		RPEDEBUG("Failed concatenating regular expression string");
		return XLAT_ACTION_FAIL;
	}

	fr_assert(inst->regex == NULL);

	slen = regex_compile(rctx, &preg, fr_sbuff_start(agg), fr_sbuff_used(agg),
			     tmpl_regex_flags(inst->xlat->vpt), true, true); /* flags, allow subcaptures, at runtime */
	if (slen <= 0) return XLAT_ACTION_FAIL;

	return xlat_regex_do_op(ctx, request, in, &preg, out, inst->op);
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

		return xlat_regex_do_op(ctx, request, in, &preg, out, op);
	}

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), xlat_regex_rctx_t));
	fr_value_box_list_init(&rctx->list);

	if (unlang_xlat_yield(request, xlat_regex_resume, NULL, 0, rctx) != XLAT_ACTION_YIELD) {
	fail:
		talloc_free(rctx);
		return XLAT_ACTION_FAIL;
	}

	if (unlang_xlat_push(ctx, &rctx->last_result, &rctx->list,
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

static xlat_action_t xlat_func_regex_search(TALLOC_CTX *ctx, fr_dcursor_t *out,
					    UNUSED xlat_ctx_t const *xctx,
					    request_t *request, fr_value_box_list_t *in)
{
	ssize_t			slen;
	regex_t			*preg;
	fr_value_box_t		*regex;
	xlat_action_t		action;

	RDEBUG("IN IS %pM", in);

	regex = fr_value_box_list_pop_head(in);
	fr_assert(regex);
	fr_assert(regex->type == FR_TYPE_STRING);

	slen = regex_compile(ctx, &preg, regex->vb_strvalue, regex->vb_length,
			     NULL, true, true); /* flags, allow subcaptures, at runtime */
	if (slen <= 0) {
		RPEDEBUG("Failed parsing regular expression %pV", regex);
		talloc_free(regex);
		return XLAT_ACTION_FAIL;
	}

	action = xlat_regex_do_op(ctx, request, in, &preg, out, T_OP_REG_EQ);
	talloc_free(regex);
	talloc_free(preg);
	return action;
}

typedef struct {
	bool		stop_on_match;
	xlat_func_t	callback;
	int		argc;
	xlat_exp_head_t	**argv;
} xlat_logical_inst_t;

typedef struct {
	TALLOC_CTX		*ctx;
	unlang_result_t		last_result;
	fr_value_box_t		*box;		//!< output value-box
	int			current;
	fr_value_box_list_t	list;
} xlat_logical_rctx_t;

static fr_slen_t xlat_expr_print_nary(fr_sbuff_t *out, xlat_exp_t const *node, void *instance, fr_sbuff_escape_rules_t const *e_rules)
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
			xlat_print_node(out, head, child, e_rules, 0);

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
 *	This returns "false" for "ignore this argument"
 *
 *	result is "false" for "delete this argument"
 *	result is "true" for "return this argument".
 */
static bool xlat_node_matches_bool(bool *result, xlat_exp_t *parent, xlat_exp_head_t *head, bool sense)
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

	xlat_instance_unregister_func(parent);

	xlat_exp_set_type(parent, XLAT_BOX);
	if (!fr_cond_assert(fr_value_box_copy(parent, &parent->data, box) == 0)) return false;

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
	int			i, j;
	int			deleted = 0;
	bool			result;
	xlat_logical_inst_t	*inst = talloc_get_type_abort(instance, xlat_logical_inst_t);
	xlat_exp_head_t		*group;

	fr_assert(node->type == XLAT_FUNC);

	/*
	 *	Don't check the last argument.  If everything else gets deleted,
	 *	then we just return the last argument.
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
		if (!xlat_node_matches_bool(&result, node, inst->argv[i], inst->stop_on_match)) continue;

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
		 *	Start searching from the next entry, OR start searching from where we left off before.
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
	 *	Only one argument left.  We can hoist the child into ourselves, and omit the logical operation.
	 */
	group = inst->argv[0];
	fr_assert(group != NULL);
	talloc_steal(node, group);

	xlat_instance_unregister_func(node);
	xlat_exp_set_type(node, XLAT_GROUP);

	/* re-print, with purified nodes removed */
	{
		char *name;

		MEM(xlat_aprint(node, &name, group, NULL) >= 0);
		xlat_exp_set_name_shallow(node, name);
	}

	talloc_free(node->group);
	node->group = group;
	node->flags = group->flags;

	return 0;
}

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
	if (unlang_xlat_yield(request, inst->callback, NULL, 0, rctx) != XLAT_ACTION_YIELD) {
	fail:
		talloc_free(rctx->box);
		talloc_free(rctx);
		return XLAT_ACTION_FAIL;
	}

	if (unlang_xlat_push(rctx, &rctx->last_result, &rctx->list,
			     request, inst->argv[rctx->current], UNLANG_SUB_FRAME) < 0) goto fail;

	return XLAT_ACTION_PUSH_UNLANG;
}

/** See if the input is truthy or not.
 *
 *  @param[in]     rctx our ctx
 *  @param[in]     in   list of value-boxes to check
 *  @return
 *	- false if there are no truthy values. The last box is copied to the rctx.
 *	  This is to allow us to return default values which may not be truthy,
 *	  e.g. %{&Counter || 0} or %{&Framed-IP-Address || 0.0.0.0}.
 *	  If we don't copy the last box to the rctx, the expression just returns NULL
 *	  which is never useful...
 *	- true if we find a truthy value.  The first truthy box is copied to the rctx.
 *
 *  Empty lists are not truthy.
 */
static bool xlat_logical_or(xlat_logical_rctx_t *rctx, fr_value_box_list_t const *in)
{
	fr_value_box_t	*last = NULL;
	bool		ret = false;

	/*
	 *	Empty lists are !truthy.
	 */
	if (!fr_value_box_list_num_elements(in)) return false;

	/*
	 *	Loop over the input list.  We CANNOT do groups.
	 */
	fr_value_box_list_foreach(in, box) {
		fr_assert(fr_type_is_leaf(box->type) || fr_type_is_null(box->type));

		last = box;

		/*
		 *	Remember the last box we found.
		 *
		 *	If it's truthy, then we stop immediately.
		 */
		if (fr_value_box_is_truthy(box)) {
			ret = true;
			break;
		}
	}

	if (!rctx->box) {
		MEM(rctx->box = fr_value_box_alloc_null(rctx->ctx));
	} else {
		fr_value_box_clear(rctx->box);
	}
	if (last && !fr_cond_assert(fr_value_box_copy(rctx->box, rctx->box, last) == 0)) return false;

	return ret;
}

/*
 *  We've evaluated an expression.  Let's see if we need to continue with ||
 */
static xlat_action_t xlat_logical_or_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
					    xlat_ctx_t const *xctx,
					    request_t *request, fr_value_box_list_t *in)
{
	xlat_logical_inst_t const *inst = talloc_get_type_abort_const(xctx->inst, xlat_logical_inst_t);
	xlat_logical_rctx_t	*rctx = talloc_get_type_abort(xctx->rctx, xlat_logical_rctx_t);
	bool			match;

	/*
	 *	If the expansions fails, then we fail the entire thing.
	 */
	if (!XLAT_RESULT_SUCCESS(&rctx->last_result)) {
		talloc_free(rctx->box);
		talloc_free(rctx);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Recursively check groups.  i.e. we effectively flatten each list.
	 *
	 *	(a, b, c) || (d, e, f) == a || b || c || d || e || f
	 */
	match = xlat_logical_or(rctx, &rctx->list);
	if (match) goto done;

	fr_value_box_list_talloc_free(&rctx->list);

	rctx->current++;

	/*
	 *	Nothing to expand, return the final value we saw.
	 */
	if (rctx->current >= inst->argc) {
	done:
		/*
		 *	Otherwise we stop on failure, with the boolean
		 *	we just updated.
		 */
		if (rctx->box) fr_dcursor_append(out, rctx->box);

		talloc_free(rctx);
		return XLAT_ACTION_DONE;
	}

	return xlat_logical_process_arg(ctx, out, xctx, request, in);
}

/** See if the input is truthy or not.
 *
 *  @param[in]     rctx our ctx
 *  @param[in]     in   list of value-boxes to check
 *  @return
 *	- false on failure
 *	- true for match, with dst updated to contain the relevant box.
 *
 *  Empty lists are not truthy.
 */
static bool xlat_logical_and(xlat_logical_rctx_t *rctx, fr_value_box_list_t const *in)
{
	fr_value_box_t *found = NULL;

	/*
	 *	Empty lists are !truthy.
	 */
	if (!fr_value_box_list_num_elements(in)) return false;

	/*
	 *	Loop over the input list.  We CANNOT do groups.
	 */
	fr_value_box_list_foreach(in, box) {
		fr_assert(fr_type_is_leaf(box->type));

		/*
		 *	Remember the last box we found.
		 *
		 *	If it's truthy, then we keep going either
		 *	until the end, or until we get a "false".
		 */
		if (fr_value_box_is_truthy(box)) {
			found = box;
			continue;
		}

		/*
		 *	Stop on the first "false"
		 */
		return false;
	}

	if (!found) return false;

	if (!rctx->box) {
		MEM(rctx->box = fr_value_box_alloc_null(rctx));
	} else {
		fr_value_box_clear(rctx->box);
	}
	if (!fr_cond_assert(fr_value_box_copy(rctx->box, rctx->box, found) == 0)) return false;

	return true;
}

/*
 *  We've evaluated an expression.  Let's see if we need to continue with &&
 */
static xlat_action_t xlat_logical_and_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
					     xlat_ctx_t const *xctx,
					     request_t *request, fr_value_box_list_t *in)
{
	xlat_logical_inst_t const *inst = talloc_get_type_abort_const(xctx->inst, xlat_logical_inst_t);
	xlat_logical_rctx_t	*rctx = talloc_get_type_abort(xctx->rctx, xlat_logical_rctx_t);
	bool			match;

	/*
	 *	If the expansions fails, then we fail the entire thing.
	 */
	if (!XLAT_RESULT_SUCCESS(&rctx->last_result)) {
		talloc_free(rctx->box);
		talloc_free(rctx);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Recursively check groups.  i.e. we effectively flatten each list.
	 *
	 *	(a, b, c) && (d, e, f) == a && b && c && d && e && f
	 */
	match = xlat_logical_and(rctx, &rctx->list);
	if (!match) return XLAT_ACTION_DONE;

	fr_value_box_list_talloc_free(&rctx->list);

	rctx->current++;

	/*
	 *	Nothing to expand, return the final value we saw.
	 */
	if (rctx->current >= inst->argc) {
		/*
		 *	Otherwise we stop on failure, with the boolean
		 *	we just updated.
		 */
		fr_assert(rctx->box != NULL);
		fr_dcursor_append(out, rctx->box);

		talloc_free(rctx);
		return XLAT_ACTION_DONE;
	}

	return xlat_logical_process_arg(ctx, out, xctx, request, in);
}

/*
 *	Each argument is it's own head, because we do NOT always want
 *	to go to the next argument.
 */
static int xlat_instantiate_logical(xlat_inst_ctx_t const *xctx)
{
	xlat_logical_inst_t	*inst = talloc_get_type_abort(xctx->inst, xlat_logical_inst_t);

	inst->argc = xlat_flatten_to_argv(inst, &inst->argv, xctx->ex->call.args);
	if (xctx->ex->call.func->token == T_LOR) {
		inst->callback = xlat_logical_or_resume;
		inst->stop_on_match = true;
	} else {
		inst->callback = xlat_logical_and_resume;
		inst->stop_on_match = false;
	}

	return 0;
}


/** Process logical &&, ||
 *
 */
static xlat_action_t xlat_func_logical(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *in)
{
	xlat_logical_rctx_t	*rctx;
	xlat_logical_inst_t const *inst = talloc_get_type_abort_const(xctx->inst, xlat_logical_inst_t);

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), xlat_logical_rctx_t));
	rctx->ctx = ctx;
	rctx->current = 0;

	if (inst->stop_on_match) {
		rctx->box = NULL;
	} else {
		MEM(rctx->box = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum));
		rctx->box->vb_bool = true;
	}
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
	group = fr_value_box_list_head(in);
	vb = fr_value_box_list_head(&group->vb_group);

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
		talloc_free(dst);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, dst);
	return XLAT_ACTION_DONE;
}


static xlat_action_t xlat_func_unary_not(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 UNUSED xlat_ctx_t const *xctx,
					 UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t *dst, *group, *vb;

	group = fr_value_box_list_head(in);
	vb = fr_value_box_list_head(&group->vb_group);

	/*
	 *	Don't call calc_unary_op(), because we want the enum names.
	 */
	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum));

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

static xlat_arg_parser_t const xlat_func_expr_rcode_arg[] = {
	{ .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Holds the result of pre-parsing the rcode on startup
 */
typedef struct {
	rlm_rcode_t		rcode;	//!< The preparsed rcode.
} xlat_rcode_inst_t;

/** Convert static expr_rcode arguments into rcodes
 *
 * This saves doing the lookup at runtime, which given how frequently this xlat is used
 * could get quite expensive.
 */
static int xlat_instantiate_expr_rcode(xlat_inst_ctx_t const *xctx)
{
	xlat_rcode_inst_t	*inst = talloc_get_type_abort(xctx->inst, xlat_rcode_inst_t);
	xlat_exp_t		*arg;
	xlat_exp_t		*rcode_arg;
	fr_value_box_t		*rcode;

	/*
	 *	If it's literal data, then we can pre-resolve it to
	 *	a rcode now, and skip that at runtime.
	 */
	arg = xlat_exp_head(xctx->ex->call.args);
	fr_assert(arg->type == XLAT_GROUP);

	/*
	 *	We can only pre-parse if this if the value is
	 *	in a single box...
	 */
	if (fr_dlist_num_elements(&arg->group->dlist) != 1) return 0;
	rcode_arg = xlat_exp_head(arg->group);

	/*
	 *	We can only pre-parse is this is a static value.
	 */
	if (rcode_arg->type != XLAT_BOX) return 0;

	rcode = &rcode_arg->data;

	switch (rcode->type) {
	case FR_TYPE_STRING:
		inst->rcode = fr_table_value_by_str(rcode_table, rcode->vb_strvalue, RLM_MODULE_NOT_SET);
		if (inst->rcode == RLM_MODULE_NOT_SET) {
		unknown:
			ERROR("Unknown rcode '%pV'", rcode);
			return -1;
		}
		break;

	case FR_TYPE_INT8:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
	case FR_TYPE_SIZE:
		if (fr_value_box_cast_in_place(rcode_arg, rcode, FR_TYPE_UINT8, NULL) < 0) {
		invalid:
			ERROR("Invalid value for rcode '%pV'", rcode);
			return -1;
		}
		FALL_THROUGH;

	case FR_TYPE_UINT8:
		if (rcode->vb_uint8 >= RLM_MODULE_NUMCODES) goto invalid;
		inst->rcode = rcode->vb_uint8;
		break;

	default:
		goto unknown;
	}

	/*
	 *	No point in creating useless boxes at runtime,
	 *	nuke the argument now.
	 */
	(void) fr_dlist_remove(&xctx->ex->call.args->dlist, arg);
	talloc_free(arg);

	return 0;
}

static fr_slen_t xlat_expr_print_rcode(fr_sbuff_t *out, xlat_exp_t const *node, void *instance, UNUSED fr_sbuff_escape_rules_t const *e_rules)
{
	size_t			at_in = fr_sbuff_used_total(out);
	xlat_rcode_inst_t	*inst = instance;

	FR_SBUFF_IN_STRCPY_LITERAL_RETURN(out, "%interpreter.rcode('");
	if (xlat_exp_head(node->call.args)) {
		ssize_t slen;

		xlat_exp_foreach(node->call.args, child) {
			slen = xlat_print_node(out, node->call.args, child, NULL, 0);
			if (slen < 0) return slen;
		}
	} else {
		FR_SBUFF_IN_STRCPY_RETURN(out, fr_table_str_by_value(rcode_table, inst->rcode, "<INVALID>"));
	}
	FR_SBUFF_IN_STRCPY_LITERAL_RETURN(out, "')");

	return fr_sbuff_used_total(out) - at_in;
}

/** Match the passed rcode against request->rcode
 *
 * Example:
@verbatim
%interpreter.rcode('handled') == true

# ...or how it's used normally used
if (handled) {
    ...
}
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_expr_rcode(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     	  xlat_ctx_t const *xctx,
				     	  request_t *request, fr_value_box_list_t *args)
{
	xlat_rcode_inst_t const	*inst = talloc_get_type_abort_const(xctx->inst, xlat_rcode_inst_t);
	fr_value_box_t		*arg_rcode;
	rlm_rcode_t		rcode;
	fr_value_box_t		*vb;

	/*
	 *	If we have zero args, it's because the instantiation
	 *	function consumed them. Unless the user read the debug
	 *	output, and tried to see what the rcode is, in case we
	 */
	if (fr_value_box_list_num_elements(args) == 0) {
		if (inst->rcode == RLM_MODULE_NOT_SET) {
			RDEBUG("Request rcode is '%s'",
			       fr_table_str_by_value(rcode_table, request->rcode, "<INVALID>"));
			return XLAT_ACTION_DONE;
		}

		rcode = inst->rcode;
	} else {
		XLAT_ARGS(args, &arg_rcode);
		rcode = fr_table_value_by_str(rcode_table, arg_rcode->vb_strvalue, RLM_MODULE_NOT_SET);
		if (rcode == RLM_MODULE_NOT_SET) {
			REDEBUG("Invalid rcode '%pV'", arg_rcode);
			return XLAT_ACTION_FAIL;
		}
	}

	RDEBUG3("Request rcode is '%s'",
		fr_table_str_by_value(rcode_table, request->rcode, "<INVALID>"));

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum));
	fr_dcursor_append(out, vb);
	vb->vb_bool = (request->rcode == rcode);

	return XLAT_ACTION_DONE;
}

/** Takes no arguments
 */
static xlat_arg_parser_t const xlat_func_rcode_arg[] = {
	XLAT_ARG_PARSER_TERMINATOR,	/* Coverity gets tripped up by only having a single entry here */
	XLAT_ARG_PARSER_TERMINATOR
};

/** Return the current rcode as a string
 *
 * Example:
@verbatim
"%rcode()" == "handled"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_rcode(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     UNUSED xlat_ctx_t const *xctx,
				     request_t *request, UNUSED fr_value_box_list_t *args)
{
	fr_value_box_t	*vb;

	/*
	 *	FIXME - This should really be an enum
	 */
	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL));
	if (fr_value_box_strdup(vb, vb, NULL, fr_table_str_by_value(rcode_table, request->rcode, "<INVALID>"), false) < 0) {
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

typedef struct {
	tmpl_t const		*vpt;		//!< the attribute reference
} xlat_exists_inst_t;

static xlat_arg_parser_t const xlat_func_exists_arg[] = {
	{ .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/*
 *	We just print the node as-is.
 */
static fr_slen_t xlat_expr_print_exists(fr_sbuff_t *out, xlat_exp_t const *node, void *instance, fr_sbuff_escape_rules_t const *e_rules)
{
	size_t	at_in = fr_sbuff_used_total(out);
	xlat_exists_inst_t	*inst = instance;

	if (inst->vpt) {
		FR_SBUFF_IN_STRCPY_RETURN(out, inst->vpt->name);
	} else {
               xlat_print_node(out, node->call.args, xlat_exp_head(node->call.args), e_rules, 0);
	}

	return fr_sbuff_used_total(out) - at_in;
}

/*
 *	Don't expand the argument if it's already an attribute reference.
 */
static int xlat_instantiate_exists(xlat_inst_ctx_t const *xctx)
{
	xlat_exists_inst_t	*inst = talloc_get_type_abort(xctx->inst, xlat_exists_inst_t);
	xlat_exp_t		*arg, *node;

	arg = xlat_exp_head(xctx->ex->call.args);

	fr_assert(arg->type == XLAT_GROUP);
	node = xlat_exp_head(arg->group);

	/*
	 *	@todo - add an escape callback to this xlat
	 *	registration, so that it can take untrusted inputs.
	 */
	if ((node->type != XLAT_TMPL) || !tmpl_contains_attr(node->vpt)) {
		fr_strerror_const("The %exists() function can only be used internally");
		return -1;
	}

	inst->vpt = talloc_steal(inst, node->vpt);

	/*
	 *	Free the input arguments so that they don't get expanded.
	 */
	while ((arg = fr_dlist_pop_head(&xctx->ex->call.args->dlist)) != NULL) {
		talloc_free(arg);
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

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum));

	vp = tmpl_dcursor_init(NULL, NULL, &cc, &cursor, request, vpt);
	dst->vb_bool = (vp != NULL);

	if (do_free) talloc_const_free(vpt);
	tmpl_dcursor_clear(&cc);
	fr_dcursor_append(out, dst);
	return XLAT_ACTION_DONE;
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

	/*
	 *	We return "true" if the attribute exists.  Otherwise we return "false".
	 */
	fr_assert(inst->vpt);

	return xlat_attr_exists(ctx, out, request, inst->vpt, false);
}

#undef XLAT_REGISTER_BINARY_OP
#define XLAT_REGISTER_BINARY_OP(_op, _name) \
do { \
	if (unlikely((xlat = xlat_func_register(NULL, "op_" STRINGIFY(_name), xlat_func_op_ ## _name, FR_TYPE_VOID)) == NULL)) return -1; \
	xlat_func_args_set(xlat, binary_op_xlat_args); \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE | XLAT_FUNC_FLAG_INTERNAL); \
	xlat_func_print_set(xlat, xlat_expr_print_binary); \
	xlat->token = _op; \
} while (0)

#undef XLAT_REGISTER_BINARY_CMP
#define XLAT_REGISTER_BINARY_CMP(_op, _name) \
do { \
	if (unlikely((xlat = xlat_func_register(NULL, "cmp_" STRINGIFY(_name), xlat_func_cmp_ ## _name, FR_TYPE_BOOL)) == NULL)) return -1; \
	xlat_func_args_set(xlat, binary_cmp_xlat_args); \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE | XLAT_FUNC_FLAG_INTERNAL); \
	xlat_func_print_set(xlat, xlat_expr_print_binary); \
	xlat_func_resolve_set(xlat, xlat_expr_resolve_binary); \
	xlat->token = _op; \
} while (0)

#undef XLAT_REGISTER_NARY_OP
#define XLAT_REGISTER_NARY_OP(_op, _name, _func_name) \
do { \
	if (unlikely((xlat = xlat_func_register(NULL, STRINGIFY(_name), xlat_func_ ## _func_name, FR_TYPE_VOID)) == NULL)) return -1; \
	xlat_func_instantiate_set(xlat, xlat_instantiate_ ## _func_name, xlat_ ## _func_name ## _inst_t, NULL, NULL); \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE | XLAT_FUNC_FLAG_INTERNAL); \
	xlat_func_print_set(xlat, xlat_expr_print_nary); \
	xlat_purify_func_set(xlat, xlat_expr_logical_purify); \
	xlat->token = _op; \
} while (0)

#undef XLAT_REGISTER_REGEX_OP
#define XLAT_REGISTER_REGEX_OP(_op, _name) \
do { \
	if (unlikely((xlat = xlat_func_register(NULL, STRINGIFY(_name), xlat_func_ ## _name, FR_TYPE_BOOL)) == NULL)) return -1; \
	xlat_func_args_set(xlat, regex_op_xlat_args); \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE | XLAT_FUNC_FLAG_INTERNAL); \
	xlat_func_instantiate_set(xlat, xlat_instantiate_regex, xlat_regex_inst_t, NULL, NULL); \
	xlat_func_print_set(xlat, xlat_expr_print_regex); \
	xlat->token = _op; \
} while (0)

#define XLAT_REGISTER_BOOL(_xlat, _func, _arg, _ret_type) \
do { \
	if (unlikely((xlat = xlat_func_register(NULL, _xlat, _func, _ret_type)) == NULL)) return -1; \
	xlat_func_args_set(xlat, _arg); \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL); \
} while (0)

#define XLAT_REGISTER_UNARY(_op, _xlat, _func) \
do { \
	if (unlikely((xlat = xlat_func_register(NULL, _xlat, _func, FR_TYPE_VOID)) == NULL)) return -1; \
	xlat_func_args_set(xlat, unary_op_xlat_args); \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE | XLAT_FUNC_FLAG_INTERNAL); \
	xlat_func_print_set(xlat, xlat_expr_print_unary); \
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
	XLAT_REGISTER_BINARY_CMP(T_OP_CMP_EQ_TYPE, eq_type);
	XLAT_REGISTER_BINARY_CMP(T_OP_CMP_NE_TYPE, ne_type);

	XLAT_REGISTER_REGEX_OP(T_OP_REG_EQ, reg_eq);
	XLAT_REGISTER_REGEX_OP(T_OP_REG_NE, reg_ne);

	if (unlikely((xlat = xlat_func_register(NULL, "regex.search", xlat_func_regex_search, FR_TYPE_BOOL)) == NULL)) return -1;
	xlat_func_args_set(xlat, regex_search_xlat_args);
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE);

	/*
	 *	&&, ||
	 *
	 *	@todo - remove tmpl_resolve() from tokenize_field(), and add xlat_resolve_logical_or() / xlat_resolve_logical_and()
	 *	functions which do partial resolution.
	 */
	XLAT_REGISTER_NARY_OP(T_LAND, logical_and, logical);
	XLAT_REGISTER_NARY_OP(T_LOR, logical_or, logical);

	XLAT_REGISTER_BOOL("interpreter.rcode", xlat_func_expr_rcode, xlat_func_expr_rcode_arg, FR_TYPE_BOOL);
	xlat_func_instantiate_set(xlat, xlat_instantiate_expr_rcode, xlat_rcode_inst_t, NULL, NULL);
	xlat_func_print_set(xlat, xlat_expr_print_rcode);

	XLAT_REGISTER_BOOL("expr.rcode", xlat_func_expr_rcode, xlat_func_expr_rcode_arg, FR_TYPE_BOOL);
	xlat->deprecated = true;
	xlat_func_instantiate_set(xlat, xlat_instantiate_expr_rcode, xlat_rcode_inst_t, NULL, NULL);
	xlat_func_print_set(xlat, xlat_expr_print_rcode);

	XLAT_REGISTER_BOOL("exists", xlat_func_exists, xlat_func_exists_arg, FR_TYPE_BOOL);
	xlat_func_instantiate_set(xlat, xlat_instantiate_exists, xlat_exists_inst_t, NULL, NULL);
	xlat_func_print_set(xlat, xlat_expr_print_exists);
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL);

	if (unlikely((xlat = xlat_func_register(NULL, "rcode", xlat_func_rcode, FR_TYPE_STRING)) == NULL)) return -1;
	xlat_func_args_set(xlat, xlat_func_rcode_arg);
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL);

	/*
	 *	-EXPR
	 *	~EXPR
	 *	!EXPR
	 */
	XLAT_REGISTER_UNARY(T_SUB, "unary_minus", xlat_func_unary_minus);
	XLAT_REGISTER_UNARY(T_COMPLEMENT, "unary_complement", xlat_func_unary_complement);
	XLAT_REGISTER_UNARY(T_NOT, "unary_not", xlat_func_unary_not);

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

	[ T_OP_CMP_EQ_TYPE ]	= L("cmp_eq_type"),
	[ T_OP_CMP_NE_TYPE ]	= L("cmp_ne_type"),

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
 *	These operators can take multiple arguments.
 *
 *	@todo - include T_ADD, T_SUB, T_MUL, T_AND, T_OR, T_XOR, here too.
 *
 *	This array should contain a function pointer to the code which either appends the results, or does
 *	peephole optimizations to merge the arguments together.  This merging will reduce run-time effort.
 */
static const bool multivalue_ops[T_TOKEN_LAST] = {
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

	[T_OP_CMP_EQ_TYPE] = P(4,1),
	[T_OP_CMP_NE_TYPE] = P(4,1),

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
		while (isspace((uint8_t) fr_sbuff_char(_x, '\0'))) fr_sbuff_advance(_x, 1); \
	} while (0)

static ssize_t tokenize_expression(xlat_exp_head_t *head, xlat_exp_t **out, fr_sbuff_t *in,
				   fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
				   fr_token_t prev, fr_sbuff_parse_rules_t const *bracket_rules,
				   fr_sbuff_parse_rules_t const *input_rules, bool cond) CC_HINT(nonnull(1,2,3,4,5));

static ssize_t tokenize_field(xlat_exp_head_t *head, xlat_exp_t **out, fr_sbuff_t *in,
			      fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
			      fr_sbuff_parse_rules_t const *bracket_rules, char *out_c, bool cond) CC_HINT(nonnull(1,2,3,4,5));

static fr_slen_t tokenize_unary(xlat_exp_head_t *head, xlat_exp_t **out, fr_sbuff_t *in,
				fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
				fr_sbuff_parse_rules_t const *bracket_rules, char *out_c, bool cond) CC_HINT(nonnull(1,2,3,4,5));

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

	MEM(unary = xlat_exp_alloc(head, XLAT_FUNC, fr_tokens[func->token], strlen(fr_tokens[func->token])));
	xlat_exp_set_func(unary, func, t_rules->attr.dict_def);
	MEM(unary->call.args = xlat_exp_head_alloc(unary));
	unary->call.args->is_argv = true;

	if (tokenize_field(unary->call.args, &node, &our_in, p_rules, t_rules, bracket_rules, out_c, (c == '!')) <= 0) {
		talloc_free(unary);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	if (!node) {
		fr_strerror_const("Empty expressions are invalid");
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
static xlat_exp_t *expr_cast_alloc(TALLOC_CTX *ctx, fr_type_t type, xlat_exp_t *child)
{
	xlat_exp_t *cast, *node;
	char const *str;

	/*
	 *	Create a "cast" node.  The first argument is a UINT8 value-box of the cast type.  The RHS is
	 *	whatever "node" comes next.
	 */
	MEM(cast = xlat_exp_alloc(ctx, XLAT_FUNC, "cast", 4));
	MEM(cast->call.func = xlat_func_find("cast", 4));
	// no need to set dict here
	fr_assert(cast->call.func != NULL);
	cast->flags = cast->call.func->flags;

	/*
	 *	Create argv[0] UINT8, with "Cast-Base" as
	 *	the "da".  This allows the printing routines
	 *	to print the name of the type, and not the
	 *	number.
	 */
	str = fr_type_to_str(type);
	fr_assert(str != NULL);

	MEM(node = xlat_exp_alloc(cast, XLAT_BOX, NULL, 0));
	xlat_exp_set_name(node, str, strlen(str));

	fr_value_box_init(&node->data, FR_TYPE_UINT8, attr_cast_base, false);
	node->data.vb_uint8 = type;

	xlat_func_append_arg(cast, node, false);
	(void) talloc_steal(cast, child);
	xlat_func_append_arg(cast, child, false);

	return cast;
}

static fr_slen_t expr_cast_from_substr(fr_type_t *cast, fr_sbuff_t *in)
{
	fr_sbuff_t		our_in = FR_SBUFF(in);
	ssize_t			slen;

	if (!fr_sbuff_next_if_char(&our_in, '(')) {
	no_cast:
		*cast = FR_TYPE_NULL;
		return 0;
	}

	/*
	 *	Check for an actual data type.
	 */
	fr_sbuff_out_by_longest_prefix(&slen, cast, fr_type_table, &our_in, FR_TYPE_NULL);

	/*
	 *	It's not a known data type, so it's not a cast.
	 */
	if (*cast == FR_TYPE_NULL) {
		goto no_cast;
	}

	/*
	 *	We're not allowed to start expressions with data types:
	 *
	 *		(ipaddr ...
	 *		(ipaddr+...
	 *		(ipaddr(...
	 */
	if (!fr_sbuff_next_if_char(&our_in, ')')) {
		if (!fr_sbuff_is_in_charset(&our_in, sbuff_char_word)) {
			fr_strerror_printf("Unexpected text after data type '%s'", fr_type_to_str(*cast));
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		goto no_cast;
	}

	/*
	 *	We're not allowed to cast to a structural data type: (group)
	 *
	 *	@todo - maybe cast to structural data type could mean "parse it as a string"?  But then where
	 *	do the pairs go..
	 */
	if (!fr_type_is_leaf(*cast)) {
		fr_strerror_printf("Invalid structural data type '%s' in cast", fr_type_to_str(*cast));
		FR_SBUFF_ERROR_RETURN(&our_in);
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
	MEM(node = xlat_exp_alloc(head, XLAT_TMPL, NULL, 0));

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

	node->quote = quote;
	xlat_exp_set_vpt(node, vpt);

	XLAT_VERIFY(node);
	*out = node;

	FR_SBUFF_SET_RETURN(in, &our_in);
}


static ssize_t tokenize_rcode(xlat_exp_head_t *head, xlat_exp_t **out, fr_sbuff_t *in, fr_sbuff_term_t const *terminals)
{
	rlm_rcode_t		rcode;
	ssize_t			slen;
	xlat_t			*func;
	xlat_exp_t		*node, *arg;
	fr_sbuff_t		our_in = FR_SBUFF(in);

	fr_sbuff_out_by_longest_prefix(&slen, &rcode, rcode_table, &our_in, T_BARE_WORD);
	if (slen <= 0) return 0;

	if (!fr_sbuff_is_terminal(&our_in, terminals)) {
		if (!fr_dict_attr_allowed_chars[fr_sbuff_char(&our_in, '\0')]) {
			fr_strerror_const("Unexpected text after return code");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}
		return 0;
	}

	/*
	 *	We do NOT do math on return codes.  But these two characters are allowed for attribute names.
	 *	So we don't parse "Invalid-Packet" as "Invalid - packet".
	 */
	if (fr_sbuff_is_char(&our_in, '-') || fr_sbuff_is_char(&our_in, '/')) {
		return 0;
	}

	/*
	 *	@todo - allow for attributes to have the name "ok-foo" ???
	 */
	func = xlat_func_find("interpreter.rcode", -1);
	fr_assert(func != NULL);

	MEM(node = xlat_exp_alloc(head, XLAT_FUNC, fr_sbuff_start(&our_in), slen));
	node->call.func = func;
	// no need to set dict here
	node->flags = func->flags; /* rcode is impure, but can be calculated statically */

	MEM(arg = xlat_exp_alloc(node, XLAT_BOX, fr_sbuff_start(&our_in), slen));

	/*
	 *	We need a string for unit tests, but this should really be just a number.
	 */
	fr_value_box_init(&arg->data, FR_TYPE_STRING, NULL, false);
	(void) fr_value_box_bstrndup(arg, &arg->data, NULL, fr_sbuff_start(&our_in), slen, false);

	xlat_func_append_arg(node, arg, false);

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
	tmpl_rules_t		our_t_rules;
	tmpl_t			*vpt = NULL;
	fr_token_t		quote;
	fr_type_t		cast_type;
	fr_dict_attr_t const	*enumv;

	XLAT_DEBUG("FIELD <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	/*
	 *	Allow for explicit casts.  Non-leaf types are forbidden.
	 */
	if (expr_cast_from_substr(&cast_type, &our_in) < 0) FR_SBUFF_ERROR_RETURN(&our_in);

	/*
	 *	Do NOT pass the cast down to the next set of parsing routines.  Instead, let the next data be
	 *	parsed as whatever, and then add a cast, or cast in place as necessary.
	 */
	our_t_rules = *t_rules;
	if (cast_type == FR_TYPE_NULL) {
		cast_type = our_t_rules.cast;
		enumv = our_t_rules.enumv;
	} else {
		enumv = NULL;
	}

	our_t_rules.cast = FR_TYPE_NULL;
//	our_t_rules.enumv = NULL;

	/*
	 *	As a special case, we allow
	 *
	 *		&reply = "foo = bar"
	 *
	 *	and then we don't parse the RHS as any enum.
	 */
	if ( our_t_rules.enumv && !fr_type_is_leaf(our_t_rules.enumv->type)) {
		 our_t_rules.enumv = enumv = NULL;
	}

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
		our_t_rules.cast = FR_TYPE_NULL;
		our_t_rules.enumv = NULL;

		fr_sbuff_skip_whitespace(&our_in);
		if (fr_sbuff_is_char(&our_in, ')')) {
			fr_strerror_printf("Empty expressions are invalid");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		/*
		 *	No input rules means "ignore external terminal sequences, as we're expecting a ')' as
		 *	our terminal sequence.
		 */
		if (tokenize_expression(head, &node, &our_in, bracket_rules, &our_t_rules, T_INVALID, bracket_rules, NULL, cond) <= 0) {
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		if (!fr_sbuff_next_if_char(&our_in, ')')) {
			fr_strerror_printf("Failed to find trailing ')'");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		/*
		 *	We've parsed one "thing", so we stop.  The next thing should be an operator, not
		 *	another value.
		 *
		 *	The nested call to tokenize_expression() can return >=0 if there are spaces followed by a
		 *	terminal character.  So "node" may be NULL;
		 */
		if (!node) {
			fr_strerror_const("Empty expressions are invalid");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		*out_c = '\0';
		goto done;
	}

	/*
	 *	Record where the operand begins for better error offsets later
	 */
	fr_sbuff_skip_whitespace(&our_in);
	fr_sbuff_marker(&opand_m, &our_in);

	fr_sbuff_out_by_longest_prefix(&slen, &quote, expr_quote_table, &our_in, T_BARE_WORD);

	switch (quote) {
	case T_BARE_WORD:
		p_rules = bracket_rules;

		/*
		 *	Peek for rcodes.
		 */
		if (cond) {
			slen = tokenize_rcode(head, &node, &our_in, p_rules->terminals);
			if (slen < 0) FR_SBUFF_ERROR_RETURN(&our_in);

			if (slen > 0) {
				fr_assert(node != NULL);
				goto done;
			}
		}
		FALL_THROUGH;

	default:
		slen = xlat_tokenize_word(head, &node, &our_in, quote, p_rules, &our_t_rules);
		if (slen <= 0) FR_SBUFF_ERROR_RETURN(&our_in);

		fr_assert(node != NULL);
		break;
	}

	/*
	 *	Cast value-box.
	 */
	if (node->type == XLAT_BOX) {
		if (cast_type != FR_TYPE_NULL) {
			if (node->data.type != cast_type) {
				if (fr_value_box_cast_in_place(node, &node->data, cast_type, NULL) < 0) goto error;
			}

			cast_type = FR_TYPE_NULL;
		}
	}

	/*
	 *	Something other than a tmpl, we can just return.
	 */
	if (node->type != XLAT_TMPL) {
		xlat_exp_set_name(node, fr_sbuff_current(&opand_m), fr_sbuff_behind(&opand_m));
		goto done;
	}

	vpt = node->vpt;

	/*
	 *	The tmpl has a cast, and it's the same as the explicit cast we were given, we can sometimes
	 *	discard the explicit cast.
	 */
	if (cast_type != FR_TYPE_NULL) {
		if (tmpl_rules_cast(vpt) == cast_type) {
			fr_assert(0);
			cast_type = FR_TYPE_NULL;

		} else if (tmpl_is_attr(vpt)) {
			fr_dict_attr_t const *da;

			fr_assert(!tmpl_is_attr_unresolved(vpt));

			da = tmpl_attr_tail_da(vpt); /* could be a list! */

			/*
			 *	Set the cast for attributes.  Note that tmpl_cast_set() will take care of
			 *	suppressing redundant casts.  But it still allows (uint32)&Service-Type,
			 *	which means "return the raw value", and not "return enum name".
			 */
			if (da) {
				if (tmpl_cast_set(vpt, cast_type) < 0) {
				error:
					fr_sbuff_set(&our_in, &opand_m);
					talloc_free(node);
					FR_SBUFF_ERROR_RETURN(&our_in);
				}

				cast_type = FR_TYPE_NULL;

			} else { /* it's something like &reply. */
				fr_assert(0);
			}

		} else if (tmpl_is_data(vpt)) {
			fr_assert(!tmpl_is_data_unresolved(vpt));

			/*
			 *	Omit our cast type if the data is already of the right type.
			 *
			 *	Otherwise if we have a cast, then convert the data now, and then reset the
			 *	cast_type to nothing.  This work allows for better errors at startup, and
			 *	minimizes run-time work.
			 */
			if (tmpl_value_type(vpt) == cast_type) {
				cast_type = FR_TYPE_NULL;

			} else if (tmpl_cast_in_place(vpt, cast_type, enumv) < 0) {
				fr_sbuff_set(&our_in, &opand_m);
				goto error;

			} else {
				/*
				 *	We've parsed the data as the new data type, so we don't need any more
				 *	casting.
				 */
				cast_type = FR_TYPE_NULL;
			}

		} else if (tmpl_contains_xlat(vpt)) {
			/*
			 *	(string) "foo %{...}" is redundant.  Drop the cast.
			 */
			if ((cast_type == FR_TYPE_STRING) && (vpt->quote != T_BARE_WORD)) {
				tmpl_cast_set(vpt, FR_TYPE_NULL);
				cast_type = FR_TYPE_NULL;

			} else {
				/*
				 *	Push the cast to the tmpl.
				 */
				tmpl_cast_set(vpt, cast_type);
				cast_type = FR_TYPE_NULL;
			}

 		} else if (tmpl_is_attr_unresolved(vpt)) {
			fr_assert(t_rules->attr.allow_unresolved);

		} else if (tmpl_is_data_unresolved(vpt)) {
			fr_assert(0);

			fr_assert(quote == T_BARE_WORD);
			fr_strerror_const("Failed parsing input");
			fr_sbuff_set(&our_in, &opand_m);
			goto error;

		} else {
			/*
			 *	Regex?  Or something else weird?
			 */
			tmpl_debug(stderr, vpt);
			fr_assert(0);
		}
	}

	fr_assert(!tmpl_contains_regex(vpt));

done:
	/*
	 *	If there is a cast, then reparent the node with a cast wrapper.
	 */
	if (cast_type != FR_TYPE_NULL) {
		xlat_exp_t *cast;

		MEM(cast = expr_cast_alloc(head, cast_type, node));
		node = cast;
	}

	*out = node;

	fr_sbuff_skip_whitespace(&our_in);
	FR_SBUFF_SET_RETURN(in, &our_in);
}

/*
 *	A mapping of operators to tokens.
 */
static fr_table_num_ordered_t const expr_assignment_op_table[] = {
	{ L("!="),	T_OP_NE			},
	{ L("!=="),	T_OP_CMP_NE_TYPE	},

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
	{ L("==="),	T_OP_CMP_EQ_TYPE	},

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

	da = tmpl_attr_tail_da(node->vpt);
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
	char c = '\0';

	XLAT_DEBUG("EXPRESSION <-- %pV", fr_box_strvalue_len(fr_sbuff_current(in), fr_sbuff_remaining(in)));

	fr_sbuff_skip_whitespace(&our_in);

	fr_sbuff_marker(&m_lhs, &our_in);

	/*
	 *	Get the LHS of the operation.
	 */
	slen = tokenize_unary(head, &lhs, &our_in, p_rules, t_rules, bracket_rules, &c, cond);
	if (slen <= 0) FR_SBUFF_ERROR_RETURN(&our_in);

	if (slen == 0) {
		fr_assert(lhs == NULL);
		*out = NULL;
		FR_SBUFF_SET_RETURN(in, &our_in);
	}

redo:
	rhs = NULL;

	fr_sbuff_skip_whitespace(&our_in);

	/*
	 *	No more input, we're done.
	 */
	if (fr_sbuff_extend(&our_in) == 0) {
	done:
		/*
		 *	LHS may be NULL if the expression has spaces followed by a terminal character.
		 */
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
	if ((op == T_INVALID) || !binary_ops[op].str) {
		fr_strerror_const("Invalid operator");
		fr_sbuff_set(&our_in, &m_op);
		talloc_free(lhs);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	We can't (yet) do &list1 = &list2 + &list3
	 */
	if (fr_binary_op[op] && t_rules->enumv && fr_type_is_structural(t_rules->enumv->type)) {
		fr_strerror_const("Invalid operator for structural attribute");
		fr_sbuff_set(&our_in, &m_op);
		talloc_free(lhs);
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

	/*
	 *	We now parse the RHS, allowing a (perhaps different) cast on the RHS.
	 */
	XLAT_DEBUG("    recurse RHS <-- %pV", fr_box_strvalue_len(fr_sbuff_current(&our_in), fr_sbuff_remaining(&our_in)));
	if ((op == T_OP_REG_EQ) || (op == T_OP_REG_NE)) {
		fr_type_t type;

		/*
		 *	@todo - LHS shouldn't be anything else.
		 */
		switch (lhs->type) {
		case XLAT_TMPL:
			type = tmpl_cast_get(lhs->vpt);
			if ((type != FR_TYPE_NULL) && (type != FR_TYPE_STRING)) {
				fr_strerror_const("Casts cannot be used with regular expressions");
				fr_sbuff_set(&our_in, &m_lhs);
				FR_SBUFF_ERROR_RETURN(&our_in);
			}

			/*
			 *	Cast the LHS to a string, if it's not already one!
			 */
			if (lhs->vpt->quote == T_BARE_WORD) tmpl_cast_set(lhs->vpt, FR_TYPE_STRING);
			break;

		case XLAT_BOX:
			/*
			 *	192.168.0.1 =~ /foo/
			 *
			 *	Gets the LHS automatically converted to a string.
			 */
			if (lhs->data.type != FR_TYPE_STRING) {
				if (fr_value_box_cast_in_place(lhs, &lhs->data, FR_TYPE_STRING, NULL) < 0) {
					fr_sbuff_set(&our_in, &m_lhs);
					FR_SBUFF_ERROR_RETURN(&our_in);
				}
			}
			break;

		default:
			/*
			 *	@todo - if we hoist the LHS to a function instead of an xlat->tmpl->xlat, then
			 *	we can't cast the LHS to a string.  OR, we have to manually add a lHS cast to
			 *	a string.  Maybe we need to delay the LHS hoisting until such time as we know
			 *	it's safe.
			 *
			 *	Also, hoisting a double-quoted xlat string to a _list_ of xlats is hard,
			 *	because we expect the LHS here to be one node.  So perhaps the hoisting has to
			 *	be from an XLAT_TMPL to an XLAT_GROUP, which is still perhaps a bit of an
			 *	improvement.
			 */
			break;

		}

		slen = tokenize_regex_rhs(head, &rhs, &our_in, t_rules, bracket_rules);
	} else {
		tmpl_rules_t our_t_rules = *t_rules;

		/*
		 *	Pass the enumv down ONLY if the RHS name begins with "::".
		 *
		 *	Otherwise, the terminal rules for expressions includes "-" and "+", both of which are
		 *	allowed in enum names.  If we pass the enumv down to the next function, it will see
		 *	"Access-Accept", and then only parse "Access".  Which is wrong.
		 */
		if ((lhs->type == XLAT_TMPL) && tmpl_is_attr(lhs->vpt) &&
		    fr_sbuff_is_str_literal(&our_in, "::")) {
			our_t_rules.enumv = tmpl_attr_tail_da(lhs->vpt);
		}

		slen = tokenize_expression(head, &rhs, &our_in, p_rules, &our_t_rules, op, bracket_rules, input_rules, cond);
	}
	if (slen <= 0) {
		talloc_free(lhs);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	The nested call to tokenize_expression() can return >=0 if there are spaces followed by a
	 *	terminal character.
	 */
	if (!rhs) goto done;

	func = xlat_func_find(binary_ops[op].str, binary_ops[op].len);
	fr_assert(func != NULL);

	if (multivalue_ops[op]) {
		if ((lhs->type == XLAT_FUNC) && (lhs->call.func->token == op)) {
			xlat_func_append_arg(lhs, rhs, cond);

			lhs->call.args->flags.can_purify |= rhs->flags.can_purify | rhs->flags.pure;
			lhs->flags.can_purify = lhs->call.args->flags.can_purify;
			goto redo;
		}
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
	if (fr_comparison_op[op]) {
		if (!valid_type(lhs)) goto fail_lhs;
		if (!valid_type(rhs)) {
			fr_sbuff_set(&our_in, &m_rhs);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

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
	xlat_exp_set_func(node, func, t_rules->attr.dict_def);

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
	fr_slen_t slen;
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
	if (!t_rules) t_rules = &my_rules;

	slen = tokenize_expression(head, &node, in, terminal_rules, t_rules, T_INVALID, bracket_rules, p_rules, cond);
	talloc_free(bracket_rules);
	talloc_free(terminal_rules);

	if (slen <= 0) {
		talloc_free(head);
		return slen;
	}

	if (!node) {
		*out = head;
		return slen;
	}

	/*
	 *	If the tmpl is not resolved, then it refers to an attribute which doesn't exist.  That's an
	 *	error.
	 */
	if (node->type == XLAT_TMPL) {
		if (tmpl_is_data_unresolved(node->vpt)) {
			fr_strerror_const("Unknown attribute");
			return -1;
		}

		/*
		 *	Convert raw existence checks to existence functions.
		 */
		if (tmpl_contains_attr(node->vpt)) {
			if (cond) MEM(node = xlat_exists_alloc(head, node));
		}
	}

	xlat_exp_insert_tail(head, node);

	*out = head;
	return slen;
}

fr_slen_t xlat_tokenize_expression(TALLOC_CTX *ctx, xlat_exp_head_t **out, fr_sbuff_t *in,
				   fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	fr_slen_t slen;

	slen = xlat_tokenize_expression_internal(ctx, out, in, p_rules, t_rules, false);
	if (slen < 0) return slen;

#ifdef STATIC_ANALYZER
	/*
	 *	Coverity doesn't realise that out will be set by this point
	 *	by a successful call to xlat_tokenize_expression_internal.
	 */
	if (!out) return -1;
#endif
	if (!*out) {
		fr_strerror_const("Empty expressions are invalid");
		return -1;
	}

	if (xlat_finalize(*out, t_rules->xlat.runtime_el) < 0) {
		TALLOC_FREE(*out);
		return -1;
	}

	return slen;
}

fr_slen_t xlat_tokenize_condition(TALLOC_CTX *ctx, xlat_exp_head_t **out, fr_sbuff_t *in,
				  fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	fr_slen_t slen;

	slen = xlat_tokenize_expression_internal(ctx, out, in, p_rules, t_rules, true);
	if (slen < 0) return slen;

#ifdef STATIC_ANALYZER
	if (!out) return -1;
#endif
	if (!*out) {
		fr_strerror_const("Empty conditions are invalid");
		return -1;
	}

	if (xlat_finalize(*out, t_rules->xlat.runtime_el) < 0) {
		TALLOC_FREE(*out);
		return -1;
	}

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
