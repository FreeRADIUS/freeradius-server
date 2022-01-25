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
 *	@todo - run xlat_purify_expr() after creating the unary node.
 *
 *	The purify function should also be smart enough to do things like remove redundant casts.
 *
 *	And as a later optimization, lets us optimize the expressions at compile time instead of re-evaluating
 *	them at run-time.  Just like the old-style conditions.
 *
 *	For now, we only do this for our functions, as they don't use the "request" pointer for anything.
 *	Instead, they rely on fr_strerror_printf(), which is fine for parsing.
 *
 *	The purify function should likely also assume that "pure" functions don't use the "request" pointer
 *	for anything, and instead call fr_strerror_printf().  This means that xlat_frame_eval_repeat() calls a
 *	function, it will need to check for func->flags.pure after getting XLAT_FAIL.  And then call RPEDEBUG
 *	itself.
 *
 *	If we really want to go crazy, we should always call pure functions with a NULL pointer for the
 *	"request" handle, but only when the *instance* is also marked "pure".  That's because a function might
 *	be "pure", but might depend on other functions which are not "pure", and therefore need a "request".
 *
 *	We probably also want a "local" purify function, which only calls our functions.  It can only be
 *	called when the LHS/RHS are both value-boxes.  It's a little more specific than the normal
 *	xlat_purify() function, but also ensures that we can give better errors at parse time, instead of at
 *	run time.
 */

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

#define xlat_is_box(_x) (((_x)->type == XLAT_BOX) || (((_x)->type == XLAT_TMPL) && tmpl_is_data((_x)->vpt)))
static fr_value_box_t *xlat_box(xlat_exp_t *node)
{
	if (node->type == XLAT_BOX) return &node->data;

	fr_assert(node->type == XLAT_TMPL);
	fr_assert(tmpl_is_data(node->vpt));

	return tmpl_value(node->vpt);
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

static xlat_arg_parser_t const cast_xlat_args[] = {
	{ .required = true, .type = FR_TYPE_INT32 },
	{ .required = true, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t xlat_func_cast(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*dst, *a, *b;

	a = fr_dlist_head(in);
	fr_assert(a->vb_uint8 > FR_TYPE_NULL);
	fr_assert(a->vb_uint8 < FR_TYPE_MAX);

	MEM(dst = fr_value_box_alloc_null(ctx)); /* value_box_cast will over-write it anyways */

	b = fr_dlist_next(in, a);

	/*
	 *	We only call this "cast" function when the *next* expansion can't be parsed statically at
	 *	compile time.  Therefore the next expansion is itself an xlat (attribute, exec, etc.)  We
	 *	therefore have special rules for casting them to bool.
	 */
	if (a->vb_uint8 == FR_TYPE_BOOL) {
		cast_to_bool(dst, b);

		/*
		 *	Everything else gets cast via the value-box functions, which look for things like "yes" or
		 *	"no" for booleans.
		 */
	} else if (fr_value_box_cast(ctx, dst, a->vb_uint8, NULL, b) < 0) {
			talloc_free(dst);
			return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, dst);
	return XLAT_ACTION_DONE;
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
XLAT_BINARY_FUNC(op_prepend,  T_OP_PREPEND)

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
	xlat->token = _op; \
	xlat->expr_type = XLAT_EXPR_TYPE_BINARY; \
} while (0)

#undef XLAT_REGISTER_BINARY_CMP
#define XLAT_REGISTER_BINARY_CMP(_op, _name) \
do { \
	if (!(xlat = xlat_register(NULL, "cmp_" STRINGIFY(_name), xlat_func_cmp_ ## _name, XLAT_FLAG_PURE))) return -1; \
	xlat_func_args(xlat, binary_op_xlat_args); \
	xlat_internal(xlat); \
	xlat->token = _op; \
	xlat->expr_type = XLAT_EXPR_TYPE_BINARY; \
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
	XLAT_REGISTER_BINARY_OP(T_OP_PREPEND, prepend);

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
	xlat->token = T_LAND;
	xlat->expr_type = XLAT_EXPR_TYPE_BINARY;

	if (!(xlat = xlat_register(NULL, "logical_or", xlat_func_logical_or, XLAT_FLAG_PURE))) return -1;
	xlat_func_args(xlat, short_circuit_xlat_args);
	xlat_internal(xlat);
	xlat->token = T_LOR;
	xlat->expr_type = XLAT_EXPR_TYPE_BINARY;

	/*
	 *	-EXPR
	 *	!EXPR
	 */
	if (!(xlat = xlat_register(NULL, "unary_minus", xlat_func_unary_minus, XLAT_FLAG_PURE))) return -1;
	xlat_func_args(xlat, unary_minus_xlat_args);
	xlat_internal(xlat);
	xlat->token = T_SUB;
	xlat->expr_type = XLAT_EXPR_TYPE_UNARY;

	if (!(xlat = xlat_register(NULL, "unary_not", xlat_func_unary_not, XLAT_FLAG_PURE))) return -1;
	xlat_func_args(xlat, unary_not_xlat_args);
	xlat_internal(xlat);
	xlat->token = T_NOT;
	xlat->expr_type = XLAT_EXPR_TYPE_UNARY;

	/*
	 *	Our casting function.
	 */
	if (!(xlat = xlat_register(NULL, "cast_expression", xlat_func_cast, XLAT_FLAG_PURE))) return -1;
	xlat_func_args(xlat, cast_xlat_args);
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
	[ T_AND ]		= L("op_and"),
	[ T_OR ]		= L("op_or"),

	[ T_LAND ]		= L("logical_and"),
	[ T_LOR ]		= L("logical_or"),

	[ T_OP_CMP_EQ ]		= L("cmp_eq"),
	[ T_OP_NE ]		= L("cmp_ne"),
	[ T_OP_LT ]		= L("cmp_lt"),
	[ T_OP_LE ]		= L("cmp_le"),
	[ T_OP_GT ]		= L("cmp_gt"),
	[ T_OP_GE ]		= L("cmp_ge"),
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


static xlat_exp_t *xlat_exp_cast_alloc(TALLOC_CTX *ctx, fr_type_t type, xlat_exp_t *rhs)
{
	xlat_exp_t *node, *group, *lhs;

	/*
	 *	Create a "cast" node.  The LHS is a UINT8 value-box of the cast type.  The RHS is
	 *	whatever "node" comes next.
	 */
	MEM(node = xlat_exp_func_alloc_args(ctx, "cast", 4, 2));
	node->call.func = xlat_func_find("cast_expression", 15);
	fr_assert(node->call.func != NULL);
	node->flags = node->call.func->flags;

	/*
	 *	Create a LHS child UINT8, with "Cast-Base" as
	 *	the "da".  This allows the printing routines
	 *	to print the name of the type, and not the
	 *	number.
	 */
	group = node->child;

	MEM(lhs = xlat_exp_alloc_null(group));
	xlat_exp_set_type(lhs, XLAT_BOX);
	xlat_exp_set_name_buffer_shallow(lhs,
					 talloc_strdup(lhs,
						       fr_type_to_str(type)));

	fr_value_box_init(&lhs->data, FR_TYPE_UINT8, attr_cast_base, false);
	lhs->data.vb_uint8 = type;

	group->child = lhs;
	xlat_flags_merge(&group->flags, &lhs->flags);
	xlat_flags_merge(&node->flags, &group->flags);

	group = group->next;
	group->child = talloc_steal(group, rhs);
	xlat_flags_merge(&group->flags, &rhs->flags);
	xlat_flags_merge(&node->flags, &group->flags);

	return node;
}

static ssize_t tokenize_expression(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *input,
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
static ssize_t tokenize_field(TALLOC_CTX *input_ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *input,
			      fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
			      fr_type_t type, fr_sbuff_parse_rules_t const *bracket_rules, fr_dict_attr_t const *da)
{
	ssize_t		slen;
	xlat_exp_t	*node = NULL;
	xlat_exp_t	*unary = NULL;
	xlat_t		*func = NULL;
	fr_type_t	cast_type = FR_TYPE_NULL;
	TALLOC_CTX	*ctx = input_ctx;
	TALLOC_CTX	*free_ctx = NULL;
	fr_sbuff_t	in = FR_SBUFF(input);

	/*
	 *	Handle !-~ by adding a unary function to the xlat
	 *	node, with the first argument being the _next_ thing
	 *	we allocate.
	 */
	if (fr_sbuff_next_if_char(&in, '!')) { /* unary not */
		func = xlat_func_find("unary_not", 9);
		fr_assert(func != NULL);
	}
	else if (fr_sbuff_next_if_char(&in, '-')) { /* unary minus */
		func = xlat_func_find("unary_minus", 11);
		fr_assert(func != NULL);
	}
	else if (fr_sbuff_next_if_char(&in, '+')) { /* ignore unary + */
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
	 *	Allow for casts, even if we're given a hint.
	 *
	 *	For immediate value-boxes, the cast is an instruction on how to parse the current input
	 *	string.  For run-time expansions, the cast is an instruction on how to parse the output of the
	 *	run-time expansion.  As such, we need to save it via an xlat_cast() function.
	 *
	 *	But we don't know this until we parse the next thing, and we want all of the talloc parenting
	 *	to be correct.  We can either create a "cast" node, and then delete it when it's not needed.
	 *	Or, create normal nodes, and then re-parent them to a "cast" node.  Either choice is
	 *	imperfect, so we just pick one.
	 *
	 *	(foo) is an expression.  (uint32) is a cast.
	 */
	slen = tmpl_cast_from_substr(&cast_type, &in);
	if (slen > 0) {
		fr_assert(fr_type_is_leaf(cast_type));

		/*
		 *	Cast to the hint gets ignored.
		 */
		if (type == cast_type) {
			cast_type = FR_TYPE_NULL;
		}

		/*
		 *	&Framed-IP-Address == (ipv4addr) foo
		 *
		 *	We can drop the cast.  We already know that the RHS has to match the LHS data type.
		 */
		if (da) {
			if (da->type == cast_type) {
				cast_type = FR_TYPE_NULL;

			} else {
				/*
				 *	We're casting to a type which is different from the input "da".  Which means that we
				 *	can't parse the type using enums from that "da".
				 *
				 *	We MAY be casting the value to the same type as the input "da".  However, we don't
				 *	(yet) know if we can drop the cast, as the RHS could be an attribute, expansion, or a
				 *	value-box.  Let's be safe and leave the cast alone until we know which one it is.
				 */
				da = NULL;
			}
		}
	}

	fr_sbuff_skip_whitespace(&in);

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
	if (fr_sbuff_next_if_char(&in, '(')) {
		slen = tokenize_expression(ctx, &node, flags, &in, bracket_rules, t_rules, T_INVALID, FR_TYPE_NULL, bracket_rules, da);
		if (slen <= 0) {
			talloc_free(free_ctx);
			FR_SBUFF_ERROR_RETURN_ADJ(&in, slen);
		}

		if (!fr_sbuff_next_if_char(&in, ')')) {
			fr_strerror_printf("Failed to find trailing ')'");
			talloc_free(free_ctx);
			FR_SBUFF_ERROR_RETURN_ADJ(&in, -slen);
		}

		goto done;
	}

	/*
	 *	Parse an attribute string.
	 *
	 *	@todo - this case is arguably handled by tmpl_afrom_substr()
	 */
	if (fr_sbuff_is_char(&in, '&')) {
		tmpl_t *vpt = NULL;

		MEM(node = xlat_exp_alloc_null(ctx));
		xlat_exp_set_type(node, XLAT_TMPL);

		slen = tmpl_afrom_attr_substr(node, NULL, &vpt, &in, p_rules, &t_rules->attr);
		if (slen <= 0) {
			talloc_free(node);
			talloc_free(free_ctx);
			FR_SBUFF_ERROR_RETURN_ADJ(&in, slen);
		}

		/*
		 *	If we have a cast, then push it into the tmpl.
		 */
		if (cast_type != FR_TYPE_NULL) {
			(void) tmpl_cast_set(vpt, cast_type);
			cast_type = FR_TYPE_NULL;
		}

		xlat_exp_set_name_buffer_shallow(node, vpt->name);
		node->vpt = vpt;

		goto done;
	}

	/*
	 *	Parse %{...}
	 *
	 *	Use the flags as input to xlat_tokenize_expr(), which control things like "needs_resolving".
	 *
	 *	@todo - optimization - do we want to create a cast node here, instead of later?
	 */
	if (fr_sbuff_adv_past_str_literal(&in, "%{")) {
		if (xlat_tokenize_expansion(ctx, &node, flags, &in, &t_rules->attr) < 0) {
			talloc_free(free_ctx);
			return -1;
		}

		goto done;
	}

	/*
	 *	Parse %(xlat:...)
	 *
	 *	HOWEVER this use-case overlaps a bit with remainder, followed by something:
	 *
	 *		... foo % (bar) ...
	 *
	 *	The simple solution is to just ignore it, and give out crappy errors.  If the user wants a
	 *	literal '%' followed by '(' to NOT be a function call, then the user can put a space between
	 *	them.
	 *
	 *	@todo - optimization - do we want to create a cast node here, instead of later?
	 */
	if (fr_sbuff_adv_past_str_literal(&in, "%(")) {
		if (xlat_tokenize_function_args(ctx, &node, flags, &in, &t_rules->attr) < 0) {
			talloc_free(free_ctx);
			return -1;
		}

		goto done;
	}

	/*
	 *	@todo - we "upcast" IP addresses to prefixes, so that we can do things like check
	 *
	 *		&Framed-IP-Address < 192.168.0.0/16
	 *
	 *	so that the user doesn't always have to specify the data types.
	 *
	 *	However, we *don't* upcast it if the user has given us an explicit cast.  And we probably want
	 *	to remember the original type.  So that for IPs, if there's no '/' in the parsed input, then
	 *	we swap the data type from the "upcast" prefix type to the input IP address type.
	 */

	/*
	 *	Parse the thing as a value-box of the given type.
	 */
	{
		fr_token_t token;
		char *p;
		fr_sbuff_marker_t marker;
		tmpl_rules_t my_rules;

		my_rules = *t_rules;
		my_rules.parent = t_rules;
		my_rules.data.enumv = da;

		/*
		 *	Force parsing as a particular type.
		 */
		if (cast_type != FR_TYPE_NULL) {
			my_rules.data.cast = cast_type;

		} else if (da) {
			my_rules.data.cast = da->type;

		} else {
			/*
			 *	Cast it to the data type we were asked
			 *	to use.
			 */
			my_rules.data.cast = type;
		}

		/*
		 *	Casts are no longer needed.  "const" literals
		 *	are just stored as the value, without a cast.
		 */
		cast_type = FR_TYPE_NULL;

		/*
		 *	Allocate the parent node for the token.
		 */
		MEM(node = xlat_exp_alloc_null(ctx));
		xlat_exp_set_type(node, XLAT_TMPL);

		fr_sbuff_marker(&marker, &in);

		/*
		 *	This thing is a value of some kind.  Try to parse it as that.
		 */
		fr_sbuff_out_by_longest_prefix(&slen, &token, expr_quote_table, &in, T_BARE_WORD);
		if (token == T_BARE_WORD) {
			fr_dict_enum_value_t *enumv;

			if (da) {
				slen = fr_dict_enum_by_name_substr(&enumv, da, &in);
				if (slen < 0) {
					fr_strerror_printf("Failed parsing value - %s", fr_strerror());
					FR_SBUFF_ERROR_RETURN_ADJ(&in, slen);
				}

				if (slen > 0) {
					xlat_exp_set_type(node, XLAT_BOX);
					fr_value_box_copy(node, &node->data, enumv->value);
					node->data.enumv = da;
					xlat_exp_set_name_buffer_shallow(node, talloc_strdup(node, enumv->name));
					goto done;
				}

				/*
				 *	Else try to parse it as just a value.
				 */
			}

			/*
			 *	Note that we *cannot* pass value_parse_rules_quoted[T_BARE_WORD], because that
			 *	doesn't stop at anything.  Instead, we have to pass in our bracket rules,
			 *	which stops at any of the operators / brackets we care about.
			 */
			slen = tmpl_afrom_substr(node, &node->vpt, &in, token,
						 bracket_rules, &my_rules);
			if (slen <= 0) {
				FR_SBUFF_ERROR_RETURN_ADJ(&in, slen);
			}
			fr_assert(node->vpt != NULL);

		} else {
			slen = tmpl_afrom_substr(node, &node->vpt, &in, token,
						 value_parse_rules_quoted[token], &my_rules);
			if (slen <= 0) {
				FR_SBUFF_ERROR_RETURN_ADJ(&in, slen);
			}

			/*
			 *	Check for, and skip, the trailing quote if we had a leading quote.
			 */
			if (!fr_sbuff_is_char(&in, fr_token_quote[token])) {
				fr_strerror_const("Unexpected end of quoted string");
				FR_SBUFF_ERROR_RETURN(&in);
			}

			fr_sbuff_advance(&in, 1);
			fr_assert(node->vpt != NULL);
		}

		/*
		 *	The tmpl code does NOT return tmpl_type_data
		 *	for string data without xlat.  Instead, it
		 *	creates TMPL_TYPE_UNRESOLVED.
		 */
		if (tmpl_resolve(node->vpt, NULL) < 0) {
			fr_sbuff_set(&in, &marker);
			FR_SBUFF_ERROR_RETURN(&in);
		}

		fr_assert(tmpl_value_type(node->vpt) != FR_TYPE_NULL);

		(void) fr_value_box_aprint(node, &p, tmpl_value(node->vpt), fr_value_escape_by_quote[token]);
		xlat_exp_set_name_buffer_shallow(node, p);

		goto done;
	}

done:
	/*
	 *	Add a cast if we still need one.
	 */
	if (cast_type != FR_TYPE_NULL) {
		xlat_exp_t *cast;

		MEM(cast = xlat_exp_cast_alloc(ctx, cast_type, node));
		node = cast;
	}

	fr_sbuff_skip_whitespace(&in);

	/*
	 *	Purify things in place, where we can.
	 */
	if (flags->pure) {
		if (xlat_purify_expr(node) < 0) {
			talloc_free(node);
			FR_SBUFF_ERROR_RETURN(&in); /* @todo m_lhs ? */
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
	return fr_sbuff_set(input, &in);

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

	{ L("|"),	T_OR			},
	{ L("||"),	T_LOR			},

	{ L("<"),	T_OP_LT			},
	{ L("<<"),	T_LSHIFT    		},
	{ L("<="),	T_OP_LE			},

	{ L("="),	T_OP_EQ			},
	{ L("=="),	T_OP_CMP_EQ		},

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
static ssize_t tokenize_expression(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *input,
				   fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
				   fr_token_t prev, fr_type_t type, fr_sbuff_parse_rules_t const *bracket_rules,
				   fr_dict_attr_t const *da)
{
	xlat_exp_t	*lhs, *rhs = NULL, *node;
	xlat_t		*func = NULL;
	fr_token_t	op;
	ssize_t		slen;
	fr_sbuff_marker_t  marker;
	fr_sbuff_t	in = FR_SBUFF(input);

	fr_sbuff_skip_whitespace(&in);

	/*
	 *	Get the LHS of the operation.
	 */
	slen = tokenize_field(ctx, &lhs, flags, &in, p_rules, t_rules, type, bracket_rules, da);
	if (slen <= 0) return slen;

redo:
	fr_assert(lhs != NULL);

	fr_sbuff_skip_whitespace(&in);

	/*
	 *	No more input, we're done.
	 */
	if (fr_sbuff_extend(&in) == 0) {
	done:
		*head = lhs;
		return fr_sbuff_set(input, &in);
	}

	/*
	 *	')' is a terminal, even if we didn't expect it.
	 *	Because if we didn't expect it, then it's an error.
	 *
	 *	If we did expect it, then we return whatever we found,
	 *	and let the caller eat the ')'.
	 */
	if (fr_sbuff_is_char(&in, ')')) {
		if (!bracket_rules) {
			fr_strerror_printf("Unexpected ')'");
			FR_SBUFF_ERROR_RETURN(&in);
		}

		goto done;
	}
	fr_sbuff_skip_whitespace(&in);

	/*
	 *	Remember where we were after parsing the LHS.
	 */
	fr_sbuff_marker(&marker, &in);

	/*
	 *	Get the operator.
	 */
	fr_sbuff_out_by_longest_prefix(&slen, &op, expr_assignment_op_table, &in, T_INVALID);
	if (op == T_INVALID) {
		talloc_free(lhs);
		fr_strerror_printf("Expected operator at '%.4s'", fr_sbuff_current(&in));
		FR_SBUFF_ERROR_RETURN(&in);
	}

	if (!binary_ops[op].str) {
		fr_strerror_printf("Invalid operator '%s'", fr_tokens[op]);
		FR_SBUFF_ERROR_RETURN_ADJ(&in, -slen);
	}

	fr_assert(precedence[op] != 0);

#if 0
	/*
	 *	@todo - handle regexes as a special case.  The LHS ideally should be a simple xlat (i.e. not a
	 *	comparison).  The RHS MUST be a solidus-quoted string.
	 */
	if ((op == T_OP_REG_EQ) || (op == T_OP_REG_NE)) {
		/*
		 *	@todo - if we have
		 *
		 *		&Foo =~ s/foo/bar/...
		 *
		 *	then do substitution, ala %(subst:...), or maybe just create a %(subst:...) node?
		 */
//		slen = tokenize_regex(ctx, &rhs, &in, p_rules, t_rules);
		if (slen <= 0) {
			FR_SBUFF_ERROR_RETURN_ADJ(&in, slen);
		}

		/*
		 *	xlat_func_regex() takes a LHS FR_TYPE_STRING, and RHS FR_TYPE_STRING
		 *
		 *	or RHS FR_TYPE_VOID, which is a pre-compiled regex?
		 */

		goto alloc_func;
	}
#endif

	/*
	 *	a * b + c ... = (a * b) + c ...
	 *
	 *	Feed the current expression to the caller, who will
	 *	take care of continuing.
	 */
	if (precedence[op] <= precedence[prev]) {
		fr_sbuff_set(&in, &marker);
		goto done;
	}

#if 1
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
		}
		break;

	case XLAT_BOX:
		/*
		 *	Bools are too restrictive.
		 */
		if (lhs->data.type != FR_TYPE_BOOL) {
			type = lhs->data.type;
		}
		break;

	default:
		break;
	}

#else
	/*
	 *	If the LHS is typed, try to parse the RHS as the given
	 *	type.  Otherwise, don't parse the RHS using enums.
	 */
	if ((lhs->type == XLAT_TMPL) && (tmpl_is_attr(lhs->vpt) || tmpl_is_list(lhs->vpt))) {
		da = tmpl_da(lhs->vpt);
		type = da->type;
	} else {
		da = NULL;
	}
#endif

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
		if (type == FR_TYPE_IPV4_ADDR) {
			type = FR_TYPE_IPV4_PREFIX;
			da = NULL;
		}
		if (type == FR_TYPE_IPV6_ADDR) {
			type = FR_TYPE_IPV6_PREFIX;
			da = NULL;
		}
		break;

	default:
		break;
	}
	/*
	 *	We now parse the RHS, allowing a (perhaps different) cast on the RHS.
	 */
	slen = tokenize_expression(ctx, &rhs, flags, &in, p_rules, t_rules, op, type, bracket_rules, da);
	if (slen <= 0) {
		talloc_free(lhs);
		FR_SBUFF_ERROR_RETURN_ADJ(&in, slen);
	}

#ifdef __clang_analyzer__
	if (!rhs) {
		talloc_free(lhs);
		FR_SBUFF_ERROR_RETURN(&in);
	}
#endif

	fr_assert(rhs != NULL);

//alloc_func:
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
			FR_SBUFF_ERROR_RETURN(&in); /* @todo m_lhs ? */
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

	slen = tokenize_expression(ctx, head, flags, in, terminal_rules, t_rules, T_INVALID, FR_TYPE_NULL,
				   bracket_rules, NULL);
	talloc_free(bracket_rules);
	talloc_free(terminal_rules);
	return slen;
}
