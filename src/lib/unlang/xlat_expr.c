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
 *	@todo - Regular expressions are not handled.  This isn't a lot of work, but can be a bit finicky.
 *
 *	@todo - short-circuit && / || need to be updated.  This requires various magic in their instantiation
 *	routines, which is not yet done.
 *
 *	@todo - all function arguments should be in groups, so we need to fix that.  Right now, binary
 *	expressions are fixed.  But unary ones are not.  We did it via a hack, but it might be better to do it
 *	a different way in the future.  The problem is that no matter which way we choose, we'll have to
 *	talloc_steal() something.
 *
 *	@todo - all functions take a value-box group for each argument.  So they need fixing, along with the
 *	purify routinges.
 *
 *	@todo - run xlat_purify_expr() after creating the unary node.
 *
 *	And as a later optimization, lets us optimize the expressions at compile time instead of re-evaluating
 *	them at run-time.  Just like the old-style conditions.
 *
 *	@todo - tmpl_aprint doesn't print casts!  Changing that would likely mean changing many, many, tests.
 *	So we'll leave that later.
 *
 *	@todo - add instantiation routines for regex and assignment operations.  This lets us do things
 *	like:
 *		if ((&foo += 4) > 6) ...
 *
 *	@todo - call xlat_resolve() when we're done, in order to convert all of the nodes to real data types.
 *	xlat resolve should also run callbacks for the expressions, which will do type checks on LHS / RHS.
 */

#if 0
/*
 *	@todo - Call this function for && / ||.  The casting rules for expressions / conditions are slightly
 *	different than fr_value_box_cast().  Largely because that function is used to parse configuration
 *	files, and parses "yes / no" and "true / false" strings, even if there's no fr_dict_attr_t passed to
 *	it.
 */
static void cast_to_bool(fr_value_box_t *out, fr_value_box_t const *in)
{
	fr_value_box_init(out, FR_TYPE_BOOL, NULL, false);

	switch (in->type) {
	case FR_TYPE_BOOL:
		out->vb_bool = in->vb_bool;
		break;

	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
		out->vb_bool = (in->vb_length > 0);
		break;

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV6_ADDR:
		out->vb_bool = !fr_ipaddr_is_inaddr_any(&in->vb_ip);
		break;

	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_PREFIX:
		out->vb_bool = !((in->vb_ip.prefix == 0) && fr_ipaddr_is_inaddr_any(&in->vb_ip));
		break;

	default:
		(void) fr_value_box_cast(NULL, out, FR_TYPE_BOOL, NULL, in);
		break;
	}
}
#endif

#define xlat_is_box(_x) (((_x)->type == XLAT_BOX) || (((_x)->type == XLAT_TMPL) && tmpl_is_data((_x)->vpt)))
static fr_value_box_t *xlat_box(xlat_exp_t *node)
{
	if (node->type == XLAT_BOX) return &node->data;

	fr_assert(node->type == XLAT_TMPL);
	fr_assert(tmpl_is_data(node->vpt));

	return tmpl_value(node->vpt);
}

static ssize_t xlat_expr_print_unary(fr_sbuff_t *out, xlat_exp_t const *node, UNUSED void *inst, fr_sbuff_escape_rules_t const *e_rules)
{
	size_t	at_in = fr_sbuff_used_total(out);

	FR_SBUFF_IN_STRCPY_RETURN(out, fr_tokens[node->call.func->token]);
	xlat_print_node(out, node->child, e_rules);

	return fr_sbuff_used_total(out) - at_in;
}

static ssize_t xlat_expr_print_binary(fr_sbuff_t *out, xlat_exp_t const *node, UNUSED void *inst, fr_sbuff_escape_rules_t const *e_rules)
{
	size_t	at_in = fr_sbuff_used_total(out);

	FR_SBUFF_IN_CHAR_RETURN(out, '(');
	xlat_print_node(out, node->child, e_rules); /* prints a space after the first argument */

	/*
	 *	@todo - when things like "+" support more than 2 arguments, print them all out
	 *	here.
	 */
	FR_SBUFF_IN_STRCPY_RETURN(out, fr_tokens[node->call.func->token]);
	FR_SBUFF_IN_CHAR_RETURN(out, ' ');
	xlat_print_node(out, node->child->next, e_rules);

	FR_SBUFF_IN_CHAR_RETURN(out, ')');

	return fr_sbuff_used_total(out) - at_in;
}

/** Basic purify, but only for expressions and comparisons.
 *
 */
static int xlat_purify_expr(xlat_exp_t *node)
{
	int rcode = -1;
	xlat_t const *func;
	xlat_exp_t *child;
	fr_value_box_t *dst = NULL, *box;
	xlat_arg_parser_t const *arg;
	xlat_action_t xa;
	fr_value_box_list_t input, output;
	fr_dcursor_t cursor;

	if (node->type != XLAT_FUNC) return 0;

	if (!node->flags.pure) return 0;

	func = node->call.func;

	if (!func->internal) return 0;

	if (func->token == T_INVALID) return 0;

	/*
	 *	@todo - for &&, ||, check only the LHS operation.  If
	 *	it satisfies the criteria, then reparent the next
	 *	child, free the "node" node, and return the child.
	 */

	/*
	 *	A child isn't a value-box.  We leave it alone.
	 */
	for (child = node->child; child != NULL; child = child->next) {
		if (!xlat_is_box(child)) return 0;
	}

	fr_value_box_list_init(&input);
	fr_value_box_list_init(&output);

	/*
	 *	Loop over the boxes, checking func->args, too.  We
	 *	have to cast the box to the correct data type (or copy
	 *	it), and then add the box to the source list.
	 */
	for (child = node->child, arg = func->args;
	     child != NULL;
	     child = child->next, arg++) {
		MEM(box = fr_value_box_alloc_null(node));

		if ((arg->type != FR_TYPE_VOID) && (arg->type != box->type)) {
			if (fr_value_box_cast(node, box, arg->type, NULL, xlat_box(child)) < 0) goto fail;

		} else if (fr_value_box_copy(node, box, xlat_box(child)) < 0) {
		fail:
			talloc_free(box);
			goto cleanup;
		}

		/*
		 *	cast / copy over-writes the list fields.
		 */
		fr_dlist_insert_tail(&input, box);
	}

	/*
	 *	We then call the function, and change the node type to
	 *	XLAT_BOX, and copy the value there.  If there are any
	 *	issues, we return an error, and the caller assumes
	 *	that the error is accessible via fr_strerror().
	 */
	fr_dcursor_init(&cursor, &output);

	xa = func->func(node, &cursor, NULL, NULL, &input);
	if (xa == XLAT_ACTION_FAIL) {
		goto cleanup;
	}

	while ((child = node->child) != NULL) {
		node->child = child->next;
		talloc_free(child);
	}

	dst = fr_dcursor_head(&cursor);
	fr_assert(dst != NULL);
	fr_assert(fr_dcursor_next(&cursor) == NULL);

	xlat_exp_set_type(node, XLAT_BOX);
	(void) fr_value_box_copy(node, &node->data, dst);

	rcode = 0;

cleanup:
	while ((box = fr_dlist_head(&input)) != NULL) {
		fr_dlist_remove(&input, box);
		talloc_free(box);
	}

	talloc_free(dst);

	return rcode;
}

static xlat_exp_t *xlat_groupify_node(TALLOC_CTX *ctx, xlat_exp_t *node)
{
	xlat_exp_t *group;

	fr_assert(node->type != XLAT_GROUP);

	group = xlat_exp_alloc_null(ctx);
	xlat_exp_set_type(group, XLAT_GROUP);
	group->quote = T_BARE_WORD;

	group->child = talloc_steal(group, node);
	group->flags = node->flags;

	if (node->next) {
		group->next = xlat_groupify_node(ctx, node->next);
		node->next = NULL;
	}

	return group;
}

/*
 *	Any function requires each argument to be in it's own XLAT_GROUP.  But we can't create an XLAT_GROUP
 *	from the start of parsing, as we might need to return an XLAT_FUNC, or another type of xlat.  Instead,
 *	we just work on the bare nodes, and then later groupify them.  For now, it's just easier to do it this way.
 */
static void xlat_groupify_expr(xlat_exp_t *node)
{
	xlat_t const *func;

	if (node->type != XLAT_FUNC) return;

	func = node->call.func;

	if (!func->internal) return;

	if (func->token == T_INVALID) return;

	/*
	 *	It's already been groupified, don't do anything.
	 */
	if (node->child->type == XLAT_GROUP) return;

	node->child = xlat_groupify_node(node, node->child);
}

static xlat_arg_parser_t const binary_op_xlat_args[] = {
	{ .required = true, .type = FR_TYPE_VOID },
	{ .required = true, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t xlat_binary_op(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    UNUSED request_t *request, fr_value_box_list_t *in,
				    fr_token_t op)
{
	int rcode;
	fr_value_box_t	*dst, *a, *b;

	MEM(dst = fr_value_box_alloc_null(ctx));

	/*
	 *	@todo - A and B must be FR_TYPE_GROUP, and the actual values are inside them.
	 *
	 *	This means... what, exactly?  If the types are addition / substraction, etc., then do operate
	 *	on each list member?  If the types are comparison, do we do the same?
	 */
	a = fr_dlist_head(in);
	b = fr_dlist_next(in, a);

#ifdef __clang_analyzer__
	if (!a || !b) return XLAT_ACTION_FAIL;
#else
	fr_assert(a != NULL);
	fr_assert(b != NULL);
#endif

	rcode = fr_value_calc_binary_op(dst, dst, FR_TYPE_NULL, a, op, b);
	if (rcode < 0) {
		talloc_free(dst);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, dst);
	return XLAT_ACTION_DONE;
}

#define XLAT_BINARY_FUNC(_name, _op)  \
static xlat_action_t xlat_func_ ## _name(TALLOC_CTX *ctx, fr_dcursor_t *out, \
				   xlat_ctx_t const *xctx, \
				   request_t *request, fr_value_box_list_t *in)  \
{ \
	return xlat_binary_op(ctx, out, xctx, request, in, _op); \
}

XLAT_BINARY_FUNC(op_add, T_ADD)
XLAT_BINARY_FUNC(op_sub, T_SUB)
XLAT_BINARY_FUNC(op_mul, T_MUL)
XLAT_BINARY_FUNC(op_div, T_DIV)
XLAT_BINARY_FUNC(op_and, T_AND)
XLAT_BINARY_FUNC(op_or,  T_OR)
XLAT_BINARY_FUNC(op_xor,  T_XOR)

XLAT_BINARY_FUNC(cmp_eq,  T_OP_CMP_EQ)
XLAT_BINARY_FUNC(cmp_ne,  T_OP_NE)
XLAT_BINARY_FUNC(cmp_lt,  T_OP_LT)
XLAT_BINARY_FUNC(cmp_le,  T_OP_LE)
XLAT_BINARY_FUNC(cmp_gt,  T_OP_GT)
XLAT_BINARY_FUNC(cmp_ge,  T_OP_GE)

static xlat_arg_parser_t const short_circuit_xlat_args[] = {
	{ .required = true, .type = FR_TYPE_BOOL },
	{ .required = true, .type = FR_TYPE_BOOL },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t xlat_func_logical_and(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx,
					   UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*dst, *a, *b;

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL, false));

	a = fr_dlist_head(in);
	b = fr_dlist_next(in, a);

	/*
	 *	@todo - short-circuit stuff inside of xlat_eval, not here.
	 */
	dst->vb_bool = a->vb_bool && b->vb_bool;

	fr_dcursor_append(out, dst);
	return XLAT_ACTION_DONE;
}


static xlat_action_t xlat_func_logical_or(TALLOC_CTX *ctx, fr_dcursor_t *out,
					  UNUSED xlat_ctx_t const *xctx,
					  UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*dst, *a, *b;

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL, false));

	a = fr_dlist_head(in);
	b = fr_dlist_next(in, a);

	/*
	 *	@todo - short-circuit stuff inside of xlat_eval, not here.
	 */
	dst->vb_bool = a->vb_bool || b->vb_bool;

	fr_dcursor_append(out, dst);
	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const unary_not_xlat_args[] = {
	{ .required = true, .type = FR_TYPE_BOOL },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t xlat_func_unary_not(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 UNUSED xlat_ctx_t const *xctx,
					 UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t *dst, *a;

	a = fr_dlist_head(in);
	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL, a->tainted));
	dst->vb_bool = !a->vb_bool;

	fr_dcursor_append(out, dst);
	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const unary_minus_xlat_args[] = {
	{ .required = true, .concat = true },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t xlat_func_unary_minus(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx,
					   request_t *request, fr_value_box_list_t *in)
{
	int rcode;
	fr_value_box_t	*dst, a, *b;

	MEM(dst = fr_value_box_alloc_null(ctx));

	fr_value_box_init(&a, FR_TYPE_INT64, NULL, false);
	b = fr_dlist_head(in);

	rcode = fr_value_calc_binary_op(dst, dst, FR_TYPE_NULL, &a, T_SUB, b);
	if (rcode < 0) {
		talloc_free(dst);
		RPEDEBUG("Failed calculating result");
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, dst);
	return XLAT_ACTION_DONE;
}

#undef XLAT_REGISTER_BINARY_OP
#define XLAT_REGISTER_BINARY_OP(_op, _name) \
do { \
	if (!(xlat = xlat_register(NULL, "op_" STRINGIFY(_name), xlat_func_op_ ## _name, XLAT_FLAG_PURE))) return -1; \
	xlat_func_args(xlat, binary_op_xlat_args); \
	xlat_internal(xlat); \
	xlat_print_set(xlat, xlat_expr_print_binary); \
	xlat->token = _op; \
} while (0)

#undef XLAT_REGISTER_BINARY_CMP
#define XLAT_REGISTER_BINARY_CMP(_op, _name) \
do { \
	if (!(xlat = xlat_register(NULL, "cmp_" STRINGIFY(_name), xlat_func_cmp_ ## _name, XLAT_FLAG_PURE))) return -1; \
	xlat_func_args(xlat, binary_op_xlat_args); \
	xlat_internal(xlat); \
	xlat_print_set(xlat, xlat_expr_print_binary); \
	xlat->token = _op; \
} while (0)

int xlat_register_expressions(void)
{
	xlat_t *xlat;

	XLAT_REGISTER_BINARY_OP(T_ADD, add);
	XLAT_REGISTER_BINARY_OP(T_SUB, sub);
	XLAT_REGISTER_BINARY_OP(T_MUL, mul);
	XLAT_REGISTER_BINARY_OP(T_DIV, div);
	XLAT_REGISTER_BINARY_OP(T_AND, and);
	XLAT_REGISTER_BINARY_OP(T_OR, or);
	XLAT_REGISTER_BINARY_OP(T_XOR, xor);

	XLAT_REGISTER_BINARY_CMP(T_OP_CMP_EQ, eq);
	XLAT_REGISTER_BINARY_CMP(T_OP_NE, ne);
	XLAT_REGISTER_BINARY_CMP(T_OP_LT, lt);
	XLAT_REGISTER_BINARY_CMP(T_OP_LE, le);
	XLAT_REGISTER_BINARY_CMP(T_OP_GT, gt);
	XLAT_REGISTER_BINARY_CMP(T_OP_GE, ge);

	/*
	 *	&&, ||
	 */
	if (!(xlat = xlat_register(NULL, "logical_and", xlat_func_logical_and, XLAT_FLAG_PURE))) return -1;
	xlat_func_args(xlat, short_circuit_xlat_args);
	xlat_internal(xlat);
	xlat_print_set(xlat, xlat_expr_print_binary); /* @todo - fix this when we fix the instantiation */
	xlat->token = T_LAND;

	if (!(xlat = xlat_register(NULL, "logical_or", xlat_func_logical_or, XLAT_FLAG_PURE))) return -1;
	xlat_func_args(xlat, short_circuit_xlat_args);
	xlat_print_set(xlat, xlat_expr_print_binary); /* @todo - fix this when we fix the instantiation */
	xlat_internal(xlat);
	xlat->token = T_LOR;

	/*
	 *	-EXPR
	 *	!EXPR
	 */
	if (!(xlat = xlat_register(NULL, "unary_minus", xlat_func_unary_minus, XLAT_FLAG_PURE))) return -1;
	xlat_func_args(xlat, unary_minus_xlat_args);
	xlat_internal(xlat);
	xlat_print_set(xlat, xlat_expr_print_unary);
	xlat->token = T_SUB;

	if (!(xlat = xlat_register(NULL, "unary_not", xlat_func_unary_not, XLAT_FLAG_PURE))) return -1;
	xlat_func_args(xlat, unary_not_xlat_args);
	xlat_internal(xlat);
	xlat_print_set(xlat, xlat_expr_print_unary);
	xlat->token = T_NOT;

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
	[ T_AND ]		= L("op_and"),
	[ T_OR ]		= L("op_or"),
	[ T_XOR ]		= L("op_xor"),

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
 *	Allow for BEDMAS ordering.  Gross ordering is first number,
 *	fine ordering is second number.  Unused operators are assigned as zero.
 */
#define P(_x, _y) (((_x) << 4) | (_y))

static const int precedence[T_TOKEN_LAST] = {
	[T_INVALID]	= 0,

	/*
	 *	Assignment operators go here:
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
	// ^ (3,1)
	[T_AND]		= P(3,2),

	[T_OP_CMP_EQ]	= P(4,0),
	[T_OP_NE]	= P(4,0),

	[T_OP_LT]	= P(5,0),
	[T_OP_LE]	= P(5,0),
	[T_OP_GT]	= P(5,0),
	[T_OP_GE]	= P(5,0),

	[T_RSHIFT]	= P(6,0),
	[T_LSHIFT]	= P(6,0),

	[T_ADD]		= P(7,0),
	[T_SUB]		= P(7,1),

	[T_MUL]		= P(8,0),
	[T_DIV]		= P(8,1),

	[T_LBRACE]	= P(9,0),
};

#define fr_sbuff_skip_whitespace(_x) \
	do { \
		while (isspace((int) *fr_sbuff_current(_x))) fr_sbuff_advance(_x, 1); \
	} while (0)

#if 0
static xlat_exp_t *xlat_exp_func_alloc_args(TALLOC_CTX *ctx, char const *name, size_t namelen, int argc)
{
	int i;
	xlat_exp_t *node, *child, **last;

	MEM(node = xlat_exp_alloc(ctx, XLAT_FUNC, name, namelen));

	last = &node->child;
	for (i = 0; i < argc; i++) {
		MEM(child = xlat_exp_alloc_null(node));
		xlat_exp_set_type(child, XLAT_GROUP);
		child->quote = T_BARE_WORD;
		*last = child;
		last = &child->next;
	}

	return node;
}
#endif

static ssize_t tokenize_expression(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *in,
				   fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
				   fr_token_t prev, fr_type_t type, fr_sbuff_parse_rules_t const *bracket_rules,
				   fr_dict_attr_t const *da);


static fr_table_num_sorted_t const expr_quote_table[] = {
	{ L("\""),	T_DOUBLE_QUOTED_STRING	},	/* Don't re-order, backslash throws off ordering */
	{ L("'"),	T_SINGLE_QUOTED_STRING	},
	{ L("/"),	T_SOLIDUS_QUOTED_STRING	},
	{ L("`"),	T_BACK_QUOTED_STRING	}
};
static size_t expr_quote_table_len = NUM_ELEMENTS(expr_quote_table);

#ifdef HAVE_REGEX
static ssize_t tokenize_regex(TALLOC_CTX *ctx, xlat_exp_t **head, UNUSED xlat_flags_t *flags, fr_sbuff_t *in,
			      fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	ssize_t		slen;
	char		quote = '/';
	xlat_exp_t	*node;
	fr_sbuff_t	our_in = FR_SBUFF(in);
	fr_sbuff_marker_t marker;

	fr_sbuff_skip_whitespace(&our_in);

	fr_sbuff_marker(&marker, &our_in);

	/*
	 *	Allow m:foo:
	 */
	if (fr_sbuff_next_if_char(&our_in, 'm')) {
		quote = *fr_sbuff_current(&our_in); /* screw UTF-8!  Who needs emojis? */
		fr_sbuff_advance(&our_in, 1);

		// @todo - update the terminal rules to use this character, too!

	} else {
		if (!fr_sbuff_next_if_char(&our_in, '/')) {
			fr_strerror_const("Regular expression does not start with '/'");
			FR_SBUFF_ERROR_RETURN(&our_in);
		}
	}

	MEM(node = xlat_exp_alloc_null(ctx));
	xlat_exp_set_type(node, XLAT_TMPL);

	slen = tmpl_afrom_substr(node, &node->vpt, &our_in, T_SOLIDUS_QUOTED_STRING,
				 value_parse_rules_quoted[T_SOLIDUS_QUOTED_STRING], t_rules);
	if (slen <= 0) {
	error:
		fr_sbuff_advance(&our_in, slen * -1);
		talloc_free(node);
		return -(fr_sbuff_used_total(&our_in));
	}

	/*
	 *	Check for, and skip, the trailing quote if we had a leading quote.
	 */
	if (!fr_sbuff_next_if_char(&our_in, quote)) {
		fr_strerror_printf("Regular expression does not edit with '%c'", quote);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	fr_assert(node->vpt != NULL);

	slen = tmpl_regex_flags_substr(node->vpt, &our_in, p_rules->terminals);
	if (slen < 0) goto error;

	/*
	 *	We've now got the expressions and
	 *	the flags.  Try to compile the
	 *	regex.
	 */
	if (tmpl_is_regex_uncompiled(node->vpt)) {
		slen = tmpl_regex_compile(node->vpt, true);
		if (slen <= 0) goto error;
	}

	*head = node;
	return fr_sbuff_used(&our_in);
}
#endif


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
static ssize_t tokenize_field(TALLOC_CTX *input_ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *in,
			      fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
			      UNUSED fr_type_t type, fr_sbuff_parse_rules_t const *bracket_rules, fr_dict_attr_t const *da)
{
	ssize_t			slen;
	xlat_exp_t		*node = NULL;
	xlat_exp_t		*unary = NULL;
	xlat_t			*func = NULL;
	TALLOC_CTX		*ctx = input_ctx;
	TALLOC_CTX		*free_ctx = NULL;
	fr_sbuff_t		our_in = FR_SBUFF(in);
	fr_sbuff_marker_t	opand_m;
	tmpl_rules_t		our_t_rules = *t_rules;
	tmpl_t			*vpt;
	fr_token_t		quote;

	/*
	 *	Handle !-~ by adding a unary function to the xlat
	 *	node, with the first argument being the _next_ thing
	 *	we allocate.
	 */
	if (fr_sbuff_next_if_char(&our_in, '!')) { /* unary not */
		func = xlat_func_find("unary_not", 9);
		fr_assert(func != NULL);
	}
	else if (fr_sbuff_next_if_char(&our_in, '-')) { /* unary minus */
		func = xlat_func_find("unary_minus", 11);
		fr_assert(func != NULL);
	}
	else if (fr_sbuff_next_if_char(&our_in, '+')) { /* ignore unary + */
		/* nothing */
	}

	/*
	 *	Maybe we have a unary not / etc.  If so, make sure
	 *	that we return that, and not the child node
	 */
	if (func) {
		MEM(unary = xlat_exp_alloc(ctx, XLAT_FUNC, func->name, strlen(func->name)));
		unary->call.func = func;
		unary->flags = func->flags;
		free_ctx = ctx = unary;
	}

	/*
	 *	Allow for explicit casts
	 *
	 *	For single quoted literal strings, double quoted strings (without expansions),
	 *	and barewords, we try an immediate conversion. For everything else, we'll
	 *	attempt the conversion at runtime.
	 *
	 *	In both cases the cast will be stored in the tmpl rules.
	 *
	 *	We MUST NOT use the other operand as a hint for the cast type as this leads
	 *	to expressions which are parsed correctly when the other operand is a DA and
	 *	can be resolved, but will fail if the DA is unknown during tokenisation.
	 *
	 *	A common example of this, is where unlang code gets moved from virtual servers
	 *	to policies.  The DA is usually known in the virtual server, but due to the
	 *	nature of policies, resolution there is deferred until pass2.
	 *
	 *	Ignore invalid casts.  (uint32) is a cast.  (1 + 2) is an expression.
	 */
	(void) tmpl_cast_from_substr(&our_t_rules, &our_in);
	fr_sbuff_skip_whitespace(&our_in);

	/*
	 *	If we have '(', then recurse for other expressions
	 *
	 *	Tokenize the sub-expression, ensuring that we stop at ')'.
	 *
	 *	Note that if we have a sub-expression, then we don't use the hinting for "type".
	 *	That's because we're parsing a complete expression here (EXPR).  So the intermediate
	 *	nodes in the expression can be almost anything.  And we only cast it to the final
	 *	value when we get the output of the expression.
	 *
	 *	@todo - have a parser context structure, so that we can disallow things like
	 *
	 *		foo == (int) ((ifid) xxxx)
	 *
	 *	The double casting is technically invalid, and will likely cause breakages at run
	 *	time.
	 */
	if (fr_sbuff_next_if_char(&our_in, '(')) {
		slen = tokenize_expression(ctx, &node, flags, &our_in, bracket_rules, t_rules, T_INVALID, FR_TYPE_NULL, bracket_rules, da);
		if (slen <= 0) {
			talloc_free(free_ctx);
			FR_SBUFF_ERROR_RETURN_ADJ(&our_in, slen);
		}

		if (!fr_sbuff_next_if_char(&our_in, ')')) {
			fr_strerror_printf("Failed to find trailing ')'");
			talloc_free(free_ctx);
			FR_SBUFF_ERROR_RETURN_ADJ(&our_in, -slen);
		}

		/*
		 *	We've parsed one "thing", so we stop.  The
		 *	next thing shoud be an operator, not another
		 *	value.
		 */
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
		break;

	case T_BACK_QUOTED_STRING:
	case T_DOUBLE_QUOTED_STRING:
	case T_SINGLE_QUOTED_STRING:
		p_rules = value_parse_rules_quoted[quote];
		break;

	case T_SOLIDUS_QUOTED_STRING:
		fr_strerror_const("Unexpected regular expression");
		fr_sbuff_set(&our_in, &opand_m);	/* Error points to the quoting char at the start of the string */
		goto error;
	}

	/*
	 *	Allocate the xlat node now so the talloc hierarchy is correct
	 */
	MEM(node = xlat_exp_alloc_null(ctx));
	xlat_exp_set_type(node, XLAT_TMPL);

	/*
	 *	tmpl_afrom_substr does pretty much all the work of parsing
	 *	the operand.
	 */
	slen = tmpl_afrom_substr(node, &vpt, &our_in, quote, bracket_rules, &our_t_rules);
	if (!vpt) {
		fr_sbuff_advance(&our_in, slen * -1);

	error:
		talloc_free(free_ctx);
		return fr_sbuff_error(&our_in);
	}
	node->vpt = vpt;

	fr_sbuff_skip_whitespace(&our_in);

	/*
	 *	Try and add any unknown attributes to the dictionary
	 *	immediately.  This means any future references point
	 *	to the same da.
	 */
	if (tmpl_is_attr(vpt) && (tmpl_attr_unknown_add(vpt) < 0)) {
		fr_strerror_printf("Failed defining attribute %s", tmpl_da(vpt)->name);
		fr_sbuff_set(&our_in, &opand_m);
		goto error;
	}

	/*
	 *	Don't call tmpl_resolve() here, it should be called
	 *	in pass2 or later during tokenization if we've managed
	 *	to resolve all the operands in the expression.
	 */

	/*
	 *	The xlat node identifier here is the same as the tmpl
	 *	in all cases...
	 */
	xlat_exp_set_name_buffer_shallow(node, vpt->name);
	fr_sbuff_skip_whitespace(&our_in);

done:
	/*
	 *	Purify things in place, where we can.
	 */
	if (flags->pure) {
		if (xlat_purify_expr(node) < 0) {
			talloc_free(node);
			FR_SBUFF_ERROR_RETURN(&our_in); /* @todo m_lhs ? */
		}
	}

	/*
	 *	@todo - purify the node.
	 */
	if (unary) {
		unary->child = node;
		xlat_flags_merge(&unary->flags, &node->flags);
		node = unary;
	}

	fr_assert(node != NULL);
	*head = node;
	return fr_sbuff_set(in, &our_in);
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
	{ L("^"),	T_XOR			},

	{ L("|"),	T_OR			},
	{ L("||"),	T_LOR			},

	{ L("<"),	T_OP_LT			},
	{ L("<<"),	T_LSHIFT    		},
	{ L("<="),	T_OP_LE			},

	{ L("="),	T_OP_EQ			},
	{ L("=="),	T_OP_CMP_EQ		},

	{ L("=~"),	T_OP_REG_EQ		},
	{ L("!="),	T_OP_REG_NE		},

	{ L(">"),	T_OP_GT			},
	{ L(">="),	T_OP_GE			},
	{ L(">>"),	T_RSHIFT    		},

};
static size_t const expr_assignment_op_table_len = NUM_ELEMENTS(expr_assignment_op_table);

/** Tokenize a mathematical operation.
 *
 *  @todo - convert rlm_expr to the new API.
 *
 *	(EXPR)
 *	!EXPR
 *	A OP B
 */
static ssize_t tokenize_expression(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *in,
				   fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
				   fr_token_t prev, fr_type_t type, fr_sbuff_parse_rules_t const *bracket_rules,
				   fr_dict_attr_t const *da)
{
	xlat_exp_t	*lhs, *rhs = NULL, *node;
	xlat_t		*func = NULL;
	fr_token_t	op;
	ssize_t		slen;
	fr_sbuff_marker_t  marker;
	fr_sbuff_t	our_in = FR_SBUFF(in);

	fr_sbuff_skip_whitespace(&our_in);

	/*
	 *	Get the LHS of the operation.
	 */
	slen = tokenize_field(ctx, &lhs, flags, &our_in, p_rules, t_rules, type, bracket_rules, da);
	if (slen <= 0) return slen;

redo:
	fr_assert(lhs != NULL);

	fr_sbuff_skip_whitespace(&our_in);

	/*
	 *	No more input, we're done.
	 */
	if (fr_sbuff_extend(&our_in) == 0) {
	done:
		*head = lhs;
		return fr_sbuff_set(in, &our_in);
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
	 *	Remember where we were after parsing the LHS.
	 */
	fr_sbuff_marker(&marker, &our_in);

	/*
	 *	Get the operator.
	 */
	fr_sbuff_out_by_longest_prefix(&slen, &op, expr_assignment_op_table, &our_in, T_INVALID);
	if (op == T_INVALID) {
		talloc_free(lhs);
		fr_strerror_printf("Expected operator at '%.4s'", fr_sbuff_current(&our_in));
		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	/*
	 *	Regular expressions are a special case, and have precedence over everything else.  Because it
	 *	makes zero sense to do things like:
	 *
	 *		Foo-Bar =~ (a | b) ????????
	 *
	 *	@todo - make sure that the LHS is something "real", and isn't (for example) a comparison?  Tho
	 *	TBH why not allow that:
	 *
	 *		(1 < 3) =~ /foo/
	 *
	 *	will get the LHS to be evaluated, then printed to a string, and then the string will be used
	 *	for the regex.  If the user is stupid enough to do this, why not allow it?
	 */
	if ((op == T_OP_REG_EQ) || (op == T_OP_REG_NE)) {
#ifdef HAVE_REGEX
		/*
		 *	@todo - if we have
		 *
		 *		&Foo =~ s/foo/bar/...
		 *
		 *	then do substitution, ala %(subst:...), or maybe just create a %(subst:...) node?
		 *
		 *	It's syntactic sugar, but it's *nice* syntactic sugar.
		 */
		slen = tokenize_regex(ctx, &rhs, flags, &our_in, bracket_rules, t_rules);
		if (slen <= 0) {
			FR_SBUFF_ERROR_RETURN_ADJ(&our_in, slen);
		}

		fr_sbuff_advance(&our_in, slen);

		// @todo - get regex func!
		fr_assert(0);

#else
		fr_sbuff_set(&our_in, &marker);
		fr_strerror_printf("Invalid operator '%s' - regular expressions are not supported in this build.", fr_tokens[op]);
		FR_SBUFF_ERROR_RETURN_ADJ(&our_in, -slen);
#endif
	}

	if (!binary_ops[op].str) {
		fr_strerror_printf("Invalid operator '%s'", fr_tokens[op]);
		FR_SBUFF_ERROR_RETURN_ADJ(&our_in, -slen);
	}

	fr_assert(precedence[op] != 0);

	/*
	 *	a * b + c ... = (a * b) + c ...
	 *
	 *	Feed the current expression to the caller, who will
	 *	take care of continuing.
	 */
	if (precedence[op] <= precedence[prev]) {
		fr_sbuff_set(&our_in, &marker);
		goto done;
	}

	if ((op == T_OP_REG_EQ) || (op == T_OP_REG_NE)) {
	}

	/*
	 *	By default we don't parse enums on the RHS, and we're also flexible about what we see on the
	 *	RHS.
	 */
	da = NULL;
	type = FR_TYPE_NULL;

	/*
	 *	For comparisons, if the LHS is typed, try to parse the RHS as the given type.
	 *
	 *	If we're doing other operations, then don't hint at the type for the RHS.
	 */
	switch (lhs->type) {
	case XLAT_TMPL:
		if (tmpl_rules_cast(lhs->vpt) != FR_TYPE_NULL) {
			type = tmpl_rules_cast(lhs->vpt);

		} else if (tmpl_contains_attr(lhs->vpt)) {
			da = tmpl_da(lhs->vpt);
			type = da->type;

		} else if (tmpl_is_data(lhs->vpt)) {
			type = tmpl_value_type(lhs->vpt);
		}
		break;

	case XLAT_BOX:
		/*
		 *	Bools are too restrictive.
		 *
		 *	@todo - really only for comparisons, or... ???
		 */
		if (lhs->data.type != FR_TYPE_BOOL) {
			type = lhs->data.type;
		}
		break;

	default:
		break;
	}

	/*
	 *	And then for network operations, upcast the RHS type to a prefix.  And then when we do the
	 *	upcast, we can no longer parse the RHS using enums from the LHS.
	 *
	 *	@todo - for normalization, if we do network comparisons with /32, then it's really an equality
	 *	comparison, isn't it?
	 */
	switch (op) {
	case T_OP_LT:
	case T_OP_LE:
	case T_OP_GT:
	case T_OP_GE:
		if (type == FR_TYPE_IPV4_ADDR) { /* allow prefix comparisons */
			type = FR_TYPE_IPV4_PREFIX;
			da = NULL;
		}
		if (type == FR_TYPE_IPV6_ADDR) { /* allow prefix comparisons */
			type = FR_TYPE_IPV6_PREFIX;
			da = NULL;
		}
		break;

		/*
		 *	For shifts, the RHS should really be an unsigned integer.  Hopefully a small one.
		 */
	case T_RSHIFT:
	case T_LSHIFT:
		type = FR_TYPE_UINT64;
		break;

		/*
		 *	We're not doing inter-type operations, so we don't care what the type of the next
		 *	thing is.  In addition, the da (if any) on the first doesn't matter when parsing the
		 *	second expression.
		 */
	case T_LAND:
	case T_LOR:
		da = NULL;
		type = FR_TYPE_NULL;
		break;

	default:
		break;
	}
	/*
	 *	We now parse the RHS, allowing a (perhaps different) cast on the RHS.
	 */
	slen = tokenize_expression(ctx, &rhs, flags, &our_in, p_rules, t_rules, op, type, bracket_rules, da);
	if (slen <= 0) {
		talloc_free(lhs);
		FR_SBUFF_ERROR_RETURN_ADJ(&our_in, slen);
	}

#ifdef __clang_analyzer__
	if (!rhs) {
		talloc_free(lhs);
		FR_SBUFF_ERROR_RETURN(&our_in);
	}
#endif

	fr_assert(rhs != NULL);

	func = xlat_func_find(binary_ops[op].str, binary_ops[op].len);
	fr_assert(func != NULL);

	/*
	 *	@todo - purify the node.
	 *
	 *	@todo - also if the have differenting data types on the LHS and RHS, and one of them is an
	 *	XLAT_BOX, then try to upcast the XLAT_BOX to the destination data type before returning.  This
	 *	optimization minimizes the amount of run-time work we have to do.
	 */

	/*
	 *	Create the function node, with the LHS / RHS arguments.
	 */
	MEM(node = xlat_exp_alloc(ctx, XLAT_FUNC, fr_tokens[op], strlen(fr_tokens[op])));
	node->call.func = func;
	node->flags = func->flags;
	node->child = lhs;
	lhs->next = rhs;

	xlat_flags_merge(&node->flags, &lhs->flags);
	xlat_flags_merge(&node->flags, &rhs->flags);

	/*
	 *	Purify things in place, where we can.
	 */
	if (flags->pure) {
		if (xlat_purify_expr(node) < 0) {
			talloc_free(node);
			FR_SBUFF_ERROR_RETURN(&our_in); /* @todo m_lhs ? */
		}
	}

	/*
	 *	Ensure that the various nodes are grouped properly.
	 */
	xlat_groupify_expr(node);

	lhs = node;
	goto redo;
}

static const fr_sbuff_term_t bracket_terms = FR_SBUFF_TERMS(
	L(")"),
	L(""),
);

static const fr_sbuff_term_t operator_terms = FR_SBUFF_TERMS(
	L(" "),
	L("\t"),
	L("\r"),
	L("\n"),
	L("+"),
	L("-"),
	L("/"),
	L("*"),
	L(":"),
	L("="),
	L("%"),
	L("!"),
	L("~"),
	L("&"),
	L("|"),
	L("^"),
	L(">"),
	L("<"),
);

ssize_t xlat_tokenize_expression(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *in,
				 fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules)
{
	ssize_t slen;
	fr_sbuff_parse_rules_t *bracket_rules = NULL;
	fr_sbuff_parse_rules_t *terminal_rules = NULL;
	xlat_flags_t my_flags = { 0 };
	tmpl_rules_t my_rules = { 0 };

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
			MEM(terminal_rules->terminals = fr_sbuff_terminals_amerge(bracket_rules,
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

	if (!flags) flags = &my_flags;

	if (!t_rules) t_rules = &my_rules;

	*head = NULL;

	slen = tokenize_expression(ctx, head, flags, in, terminal_rules, t_rules, T_INVALID, FR_TYPE_NULL,
				   bracket_rules, NULL);
	talloc_free(bracket_rules);
	talloc_free(terminal_rules);

	if (slen <= 0) return slen;

	/*
	 *	Add nodes that need to be bootstrapped to
	 *	the registry.
	 */
	if (xlat_bootstrap(*head) < 0) {
		TALLOC_FREE(*head);
		return 0;
	}

	return slen;
}
