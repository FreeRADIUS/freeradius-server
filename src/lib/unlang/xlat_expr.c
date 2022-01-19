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
 *	@todo - add special / internal flags to xlat_t which mark it as an expression (unary, binary,
 *	operator, etc.).  These flags should be checked only by xlat_print(), so that we can print the new
 *	expressions in a sane form.
 *
 *	@todo - add a "output" fr_type_t to xlat_t, which is mainly used by the comparison functions.  Right
 *	now it will happily parse things like:
 *
 *		(1 < 2) < 3
 *
 *	though the result of (1 < 2) is a boolean, so the result is always true.  We probably want to have
 *	that as a compile-time error / check.
 *
 *	@todo - Regular expressions are not handled.  This isn't a lot of work, but can be a bit finicky.
 *
 *	@todo - short-circuit && / || need to be updated.  This requires various magic in their instantiation
 *	routines, which is not yet done.
 *
 *	@todo - we should have an xlat_purify() function, but that may require other changes to the code.  See
 *	comments below.  The purify function should also be smart enough to do things like remove redundant
 *	casts.
 *
 *	@todo - for existence checks, we should add a "cast to bool" node, so that the answer is returned
 *	correctly, and the caller doesn't have to do it.
 */

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
		switch (b->type) {
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			fr_value_box_init(dst, FR_TYPE_BOOL, NULL, false);
			dst->vb_bool = (b->vb_length > 0);
			goto done;

		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_IPV6_ADDR:
			fr_value_box_init(dst, FR_TYPE_BOOL, NULL, false);
			dst->vb_bool = fr_ipaddr_is_inaddr_any(&b->vb_ip);
			break;

		case FR_TYPE_IPV4_PREFIX:
		case FR_TYPE_IPV6_PREFIX:
			fr_value_box_init(dst, FR_TYPE_BOOL, NULL, false);
			dst->vb_bool = (b->vb_ip.prefix == 0) && fr_ipaddr_is_inaddr_any(&b->vb_ip);
			break;

		default:
			break;
		}
	}

	/*
	 *	Everything else gets cast via the value-box functions, which look for things like "yes" or
	 *	"no" for booleans.
	 */
	if (fr_value_box_cast(ctx, dst, a->vb_uint8, NULL, b) < 0) {
		talloc_free(dst);
		return XLAT_ACTION_FAIL;
	}

done:
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

static xlat_arg_parser_t const unary_sub_xlat_args[] = {
	{ .required = true, .concat = true },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t xlat_func_unary_sub(TALLOC_CTX *ctx, fr_dcursor_t *out,
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
	if (!(xlat = xlat_register(NULL, "unary_minus", xlat_func_unary_sub, XLAT_FLAG_PURE))) return -1;
	xlat_func_args(xlat, unary_sub_xlat_args);
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

#ifdef UPCAST
static const fr_type_t upcast[FR_TYPE_MAX + 1] = {
	[FR_TYPE_IPV4_ADDR] = FR_TYPE_IPV4_PREFIX,
	[FR_TYPE_IPV6_ADDR] = FR_TYPE_IPV6_PREFIX,
};
#endif

#define fr_sbuff_skip_whitespace(_x) \
	do { \
		while (isspace((int) *fr_sbuff_current(_x))) fr_sbuff_advance(_x, 1); \
	} while (0)


static xlat_exp_t *xlat_expr_cast_alloc(TALLOC_CTX *ctx, fr_type_t type)
{
	xlat_exp_t *cast, *node;

	/*
	 *	Create a "cast" node.  The LHS is a UINT8 value-box of the cast type.  The RHS is
	 *	whatever "node" comes next.
	 */
	MEM(cast = xlat_exp_alloc(ctx, XLAT_FUNC, "cast", 4));
	cast->call.func = xlat_func_find("cast_expression", 15);
	fr_assert(cast->call.func != NULL);
	cast->flags = cast->call.func->flags;

	/*
	 *	Create a LHS child UINT8, with "Cast-Base" as
	 *	the "da".  This allows the printing routines
	 *	to print the name of the type, and not the
	 *	number.
	 */
	MEM(node = xlat_exp_alloc_null(cast));
	xlat_exp_set_type(node, XLAT_BOX);
	xlat_exp_set_name_buffer_shallow(node,
					 talloc_strdup(node,
						       fr_table_str_by_value(fr_value_box_type_table,
									     type, "<INVALID>")));

	fr_value_box_init(&node->data, FR_TYPE_UINT8, attr_cast_base, false);
	node->data.vb_uint8 = type;

	cast->child = node;

	return cast;
}

static ssize_t tokenize_expression(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *input,
				   fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
				   fr_token_t prev, fr_type_t type, fr_sbuff_parse_rules_t const *bracket_rules,
				   fr_dict_attr_t const *da);


/*
 *	Look for prefix operators
 *
 *	+ = ignore
 *	- = unary_sub(next)
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
	xlat_exp_t	*cast = NULL;
	xlat_t		*func = NULL;
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
	 *	Allow for casts, if the caller hasn't already specified that.
	 *
	 *	For immediate value-boxes, the cast is an instruction on how to parse the current input
	 *	string.  For run-time expansions, the cast is an instruction on how to parse the output of the
	 *	run-time expansion.  As such, we need to save it via an xlat_cast() function.
	 *
	 *	But we don't know this until we parse the next thing, and we want all of the talloc parenting
	 *	to be correct.  So we might as well always create a cast, and then reparent things later.
	 */
	if (type == FR_TYPE_VOID) {
		char end = '\0';
		fr_sbuff_marker_t marker;

		fr_sbuff_marker(&marker, &in);
		if (fr_sbuff_is_char(&in, '(')) { /* <cast> is yucky.  (cast) is friendly */
			fr_sbuff_advance(&in, 1);
			end = ')';

		} else if (fr_sbuff_is_char(&in, '<')) {
			fr_sbuff_advance(&in, 1);
			end = '>';

		} else {
			goto check_more;
		}

		fr_sbuff_skip_whitespace(&in);

		fr_sbuff_out_by_longest_prefix(&slen, &type, fr_value_box_type_table, &in, FR_TYPE_VOID);
		if (type == FR_TYPE_VOID) {
			fr_sbuff_set(&in, &marker);
			goto check_more;
		}

		if (!fr_type_is_leaf(type)) {
			fr_strerror_printf("Cannot cast to structural data type");
			fr_sbuff_set(&in, &marker);
			talloc_free(unary);
			FR_SBUFF_ERROR_RETURN(&in);
		}

		fr_sbuff_skip_whitespace(&in);
		if (!fr_sbuff_is_char(&in, end)) {
			fr_strerror_printf("Unexpected text after cast data type");
			talloc_free(unary);
			FR_SBUFF_ERROR_RETURN(&in);
		}

		fr_sbuff_advance(&in, 1);

		MEM(cast = xlat_expr_cast_alloc(ctx, type));

		ctx = cast;
		if (!free_ctx) free_ctx = cast;

		node = NULL;

		/*
		 *	We're casting to a type which is different from the input "da".  Which means that we
		 *	can't parse the type using enums from that "da".
		 *
		 *	We MAY be casting the value to the same type as the input "da".  However, we don't
		 *	(yet) know if we can drop the cast, as the RHS could be an attribute, expansion, or a
		 *	value-box.  Let's be safe and leave the cast alone until we know which one it is.
		 */
		if (da && (da->type != type)) {
			da = NULL;
		}
	}

	/*
	 *	If we have '(', then recurse for other expressions
	 */
check_more:
	fr_sbuff_skip_whitespace(&in);

	if (fr_sbuff_next_if_char(&in, '(')) {
		/*
		 *	Tokenize the sub-expression, ensuring that we stop at ')'.
		 */
		slen = tokenize_expression(ctx, &node, flags, &in, bracket_rules, t_rules, T_INVALID, type, bracket_rules, da);
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
	 */
	if (fr_sbuff_is_char(&in, '&')) {
		tmpl_t *vpt = NULL;

		MEM(node = xlat_exp_alloc_null(ctx));
		xlat_exp_set_type(node, XLAT_ATTRIBUTE);

		slen = tmpl_afrom_attr_substr(node, NULL, &vpt, &in, p_rules, t_rules);
		if (slen <= 0) {
			talloc_free(node);
			talloc_free(free_ctx);
			FR_SBUFF_ERROR_RETURN_ADJ(&in, slen);
		}

		xlat_exp_set_name_buffer_shallow(node, vpt->name);
		node->attr = vpt;

		goto done;
	}

	/*
	 *	Parse %{...}
	 *
	 *	Use the flags as input to xlat_tokenize_expr(), which control things like "needs_resolving".
	 */
	if (fr_sbuff_adv_past_str_literal(&in, "%{")) {
		if (xlat_tokenize_expansion(ctx, &node, flags, &in, t_rules) < 0) {
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
	 */
	if (fr_sbuff_adv_past_str_literal(&in, "%(")) {
		if (xlat_tokenize_function_args(ctx, &node, flags, &in, t_rules) < 0) {
			talloc_free(free_ctx);
			return -1;
		}

		goto done;
	}

	/*
	 *	Else it's nothing we recognize.  Do some quick checks
	 *	to see what it might be.
	 */
	if (type == FR_TYPE_VOID) {
		if (da) {
			type = da->type;

		} else if (fr_sbuff_is_char(&in, '"') || fr_sbuff_is_char(&in, '\'') || fr_sbuff_is_char(&in, '`')) {
			/*
			 *	@todo - also update the escaping rules, depending on kind of string we have.
			 */
			type = FR_TYPE_STRING;
		} else {			
			type = FR_TYPE_INT64;
		}
	}

	/*
	 *	@todo - we "upcast" IP addresses to prefixes, so that we can do things like check
	 *
	 *		&Framed-IP-Address < 192.168/16
	 *
	 *	so that the user doesn't always have to specify the data types.
	 *
	 *	However, we *don't* upcast it if the user has given us an explicit cast.  And we probably want
	 *	to remember the original type.  So that for IPs, if there's no '/' in the parsed input, then
	 *	we swap the data type from the "upcast" prefix type to the input IP address type.
	 */
#ifdef UPCAST
	if (!cast && upcast[type]) type = upcast[type];
#endif

	fr_assert(fr_type_is_leaf(type));

	/*
	 *	Parse the thing as a value-box of the given type.
	 */
	{
		char *p;
		fr_sbuff_marker_t marker;

		fr_sbuff_marker(&marker, &in);

#if 0
		/*
		 *	If there's a cast, then remove it.  We have a cast in "type", so the value-box MUST be
		 *	parsed as that type, or it else parsing fails.  There's no reason to parse something
		 *	as a particular type, and then immediately cast it to that type.
		 */
		if (cast) {
			TALLOC_FREE(cast);
			ctx = unary ? unary : input_ctx;
		}
#endif

		MEM(node = xlat_exp_alloc_null(ctx));
		xlat_exp_set_type(node, XLAT_BOX);

		/*
		 *	'-' and '/' are allowed in dictionary names.
		 *	But they're also tokens allowed here.  So we
		 *	have to jump through some hoops in order to
		 *	parse both.
		 *
		 *	e.g. "Framed-User" should be parsed as that, and not as anything else.
		 */
		if (da) {
			fr_dict_enum_value_t *enumv;

			slen = fr_dict_enum_by_name_substr(&enumv, da, &in);
			if (slen == 0) {
				da = NULL;
				goto parse_other;
			}
			if (slen < 0) {
				goto failed_value;
			}

			fr_value_box_copy(node, &node->data, enumv->value);
			node->data.enumv = da;

		} else {
		parse_other:
			/*
			 *	Note that this allows "192.168/24" if the type-specific parser allows it, even
			 *	if '/' is a terminal character.
			 */
			slen = fr_value_box_from_substr(node, &node->data, type, da, &in, p_rules, false);
			if (slen <= 0) {
			failed_value:
				fr_strerror_printf("Failed parsing value - %s", fr_strerror());
				talloc_free(free_ctx);
				FR_SBUFF_ERROR_RETURN_ADJ(&in, slen);
			}
		}

		MEM(p = talloc_array(node, char, slen + 1));
		p[slen] = '\0';
		memcpy(p, fr_sbuff_current(&marker), slen);
		xlat_exp_set_name_buffer_shallow(node, p);
		goto done;
	}

done:
	/*
	 *	@todo - keep a flag to track if we create the node via a cmp_foo / op_foo function.  And if
	 *	so, check for input flags->pure.  If set, we call xlat_purify() to purify the results.  This
	 *	capability lets us write tests for parsing which use simple numbers, to verify that the parser
	 *	is OK.
	 *
	 *	And as a later optimization, lets us optimize the expressions at compile time instead of
	 *	re-evaluating them at run-time.  Just like the old-style conditions.
	 *
	 *	For now, we only do this for our functions, as they don't use the "request" pointer for
	 *	anything.  Instead, they rely on fr_strerror_printf(), which is fine for parsing.
	 *
	 *	The purify function should likely also assume that "pure" functions don't use the "request"
	 *	pointer for anything, and instead call fr_strerror_printf().  This means that
	 *	xlat_frame_eval_repeat() calls a function, it will need to check for func->flags.pure after
	 *	getting XLAT_FAIL.  And then call RPEDEBUG itself.
	 *
	 *	If we really want to go crazy, we should always call pure functions with a NULL pointer for
	 *	the "request" handle, but only when the *instance* is also marked "pure".  That's because a
	 *	function might be "pure", but might depend on other functions which are not "pure", and
	 *	therefore need a "request".
	 */

	fr_sbuff_skip_whitespace(&in);

	/*
	 *	Wrap the result in a cast.
	 *
	 *	@todo - if the node is an XLAT_ATTR or XLAT_BOX and is already of the correct data type, then reparent
	 *	"node" to the parent of "cast", and free "cast".
	 */
	if (cast) {
		if ((node->type == XLAT_BOX) && (node->data.type == cast->child->data.vb_uint8)) {
			talloc_steal(talloc_parent(cast), node);
			talloc_free(cast);
			goto check_unary;
		}

		fr_assert(cast->child);
		cast->child->next = node;
		xlat_flags_merge(&cast->flags, &node->flags);
		node = cast;
	}

	/*
	 *	@todo - if the node is an XLAT_BOX, and we have flags->pure, then purify the node.
	 */
check_unary:
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
	xlat_exp_t	*lhs, *rhs, *node;
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

		*head = lhs;
		return fr_sbuff_set(input, &in);
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

	/*
	 *	a * b + c ... = (a * b) + c ...
	 *
	 *	Feed the current expression to the caller, who will
	 *	take care of continuing.
	 */
	if (precedence[op] <= precedence[prev]) {
		*head = lhs;
		return fr_sbuff_set(input, &marker);
	}

	/*
	 *	If the LHS is typed, try to parse the RHS as the given
	 *	type.  Otherwise, don't parse the RHS using enums.
	 */
	if (lhs->type == XLAT_ATTRIBUTE) {
		da = tmpl_da(lhs->attr);
	} else {
		da = NULL;
	}

	/*
	 *	We now parse the RHS, allowing a (perhaps different) cast on the RHS.
	 */
	slen = tokenize_expression(ctx, &rhs, flags, &in, p_rules, t_rules, op, FR_TYPE_VOID, bracket_rules, da);
	if (slen <= 0) {
		talloc_free(lhs);
		FR_SBUFF_ERROR_RETURN_ADJ(&in, slen);
	}

alloc_func:
	func = xlat_func_find(binary_ops[op].str, binary_ops[op].len);
	fr_assert(func != NULL);

	/*
	 *	Check if we need to purify the output.
	 *
	 *	@todo - also if the have differenting data types on the LHS and RHS, and one of them is an
	 *	XLAT_BOX, then try to upcast the XLAT_BOX to the destination data type before returning.  This
	 *	optimization minimizes the amount of run-time work we have to do.
	 */
	if (flags->pure && (lhs->type == XLAT_BOX) && (rhs->type == XLAT_BOX)) {
		// create a fr_value_box_list from the two boxes, and call our function, which then gets us a
		// value-box as output.  We then create free RHS, and put the box into LHS
	}

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

	slen = tokenize_expression(ctx, head, flags, in, terminal_rules, t_rules, T_INVALID, FR_TYPE_VOID,
				   bracket_rules, NULL);
	talloc_free(bracket_rules);
	talloc_free(terminal_rules);
	return slen;
}
