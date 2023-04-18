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
 * @file xlat_redundant.c
 * @brief Register xlat functions for calling redundant xlats
 *
 * @copyright 2023 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/unlang/xlat_redundant.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/unlang/xlat_priv.h>
#include <freeradius-devel/util/rand.h>

/*
 *	Internal redundant handler for xlats
 */
typedef enum {
	XLAT_REDUNDANT_INVALID = 0,			//!< Not a valid redundant type.
	XLAT_REDUNDANT,					//!< Use the first xlat function first, then
							///< go through in sequence, using the next
							///< function after each failure.

	XLAT_LOAD_BALANCE,				//!< Pick a random xlat, and if that fails
							///< then the call as a whole fails.

	XLAT_REDUNDANT_LOAD_BALANCE,			//!< Pick a random xlat to start, then fail
							///< between the other xlats in the redundant
							///< group.
} xlat_redundant_type_t;

typedef struct {
	fr_dlist_t			entry;		//!< Entry in the redundant function list.
	xlat_t				*func;		//!< Resolved xlat function.
} xlat_redundant_func_t;

typedef struct {
	xlat_redundant_type_t		type;		//!< Type of redundant xlat expression.
	fr_dlist_head_t			funcs;		//!< List of redundant xlat functions.
	CONF_SECTION			*cs;		//!< That this redundant xlat list was created from.
} xlat_redundant_t;

typedef struct {
	xlat_redundant_t		*xr;		//!< Information about the redundant xlat.
	xlat_exp_head_t			**ex;		//!< Array of xlat expressions created by
							///< tokenizing the arguments to the redundant
							///< xlat, then duplicating them multiple times,
							///< one for each xlat function that may be called.
} xlat_redundant_inst_t;

typedef struct {
	bool				last_success;	//!< Did the last call succeed?

	xlat_exp_head_t			**first;	//!< First function called.
							///< Used for redundant-load-balance.
	xlat_exp_head_t			**current;	//!< Last function called, used for redundant xlats.
} xlat_redundant_rctx_t;

/** Pass back the result from a single redundant child call
 *
 */
static xlat_action_t xlat_redundant_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   xlat_ctx_t const *xctx,
					   request_t *request, UNUSED fr_value_box_list_t *in)
{
	xlat_redundant_inst_t const	*xri = talloc_get_type_abort_const(xctx->inst, xlat_redundant_inst_t);
	xlat_redundant_rctx_t		*rctx = talloc_get_type_abort(xctx->rctx, xlat_redundant_rctx_t);
	xlat_action_t			xa = XLAT_ACTION_DONE;

	if (rctx->last_success) {
	done:
		talloc_free(rctx);
		return xa;
	}

	/*
	 *	We're at the end, loop back to the start
	 */
	if (++rctx->current >= (xri->ex + talloc_array_length(xri->ex))) rctx->current = xri->ex;

	/*
	 *	We're back to the first one we tried, fail...
	 */
	if (rctx->current == rctx->first) {
	error:
		xa = XLAT_ACTION_FAIL;
		goto done;
	}

	if (unlang_xlat_yield(request, xlat_redundant_resume, NULL, 0, rctx) != XLAT_ACTION_YIELD) goto error;

	/*
	 *	Push the next child...
	 */
	if (unlang_xlat_push(ctx, &rctx->last_success, (fr_value_box_list_t *)out->dlist,
			     request, *rctx->current, UNLANG_SUB_FRAME) < 0) goto error;

	return XLAT_ACTION_PUSH_UNLANG;
}

/** Pass back the result from a single redundant child call
 *
 */
static xlat_action_t xlat_load_balance_resume(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					      xlat_ctx_t const *xctx,
					      UNUSED request_t *request, UNUSED fr_value_box_list_t *in)
{
	xlat_redundant_rctx_t	*rctx = talloc_get_type_abort(xctx->rctx, xlat_redundant_rctx_t);
	xlat_action_t 		xa = rctx->last_success ? XLAT_ACTION_DONE : XLAT_ACTION_FAIL;

	talloc_free(rctx);

	return xa;
}

/** xlat "redundant", "load-balance" and "redundant-load-balance" processing
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_redundant(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    xlat_ctx_t const *xctx,
				    request_t *request, UNUSED fr_value_box_list_t *in)
{
	xlat_redundant_inst_t const	*xri = talloc_get_type_abort_const(xctx->inst, xlat_redundant_inst_t);
	xlat_redundant_rctx_t		*rctx;

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), xlat_redundant_rctx_t));

	switch (xri->xr->type) {
	/*
	 *	Run through each of the redundant functions sequentially
	 *	starting at the first.
	 */
	case XLAT_REDUNDANT:
		rctx->current = rctx->first = xri->ex;	/* First element first */
		if (unlang_xlat_yield(request, xlat_redundant_resume, NULL, 0, rctx) != XLAT_ACTION_YIELD) {
		error:
			talloc_free(rctx);
			return XLAT_ACTION_FAIL;
		}
		break;

	/*
	 *	Run a single random redundant function.
	 */
	case XLAT_LOAD_BALANCE:
		rctx->first = &xri->ex[(size_t)fr_rand() & (talloc_array_length(xri->ex) - 1)];	/* Random start */
		if (unlang_xlat_yield(request, xlat_load_balance_resume, NULL, 0, rctx) != XLAT_ACTION_YIELD) goto error;
		break;

	/*
	 *	Run through each of the redundant functions sequentially
	 *	starting at a random element.
	 */
	case XLAT_REDUNDANT_LOAD_BALANCE:
		rctx->first = &xri->ex[(size_t)fr_rand() & (talloc_array_length(xri->ex) - 1)];	/* Random start */
		if (unlang_xlat_yield(request, xlat_redundant_resume, NULL, 0, rctx) != XLAT_ACTION_YIELD) goto error;
		break;

	default:
		fr_assert(0);
	}

	if (unlang_xlat_push(ctx, &rctx->last_success, (fr_value_box_list_t *)out->dlist,
			     request, *rctx->current, UNLANG_SUB_FRAME) < 0) return XLAT_ACTION_FAIL;

	return XLAT_ACTION_PUSH_UNLANG;
}


/** Allocate additional nodes for evaluation
 *
 */
static int xlat_redundant_instantiate(xlat_inst_ctx_t const *xctx)
{
	xlat_redundant_t		*xr = talloc_get_type_abort(xctx->uctx, xlat_redundant_t);
	xlat_redundant_inst_t		*xri = talloc_get_type_abort(xctx->inst, xlat_redundant_inst_t);
	unsigned int			num = 0;
	xlat_redundant_func_t const	*first;

	MEM(xri->ex = talloc_array(xri, xlat_exp_head_t *, fr_dlist_num_elements(&xr->funcs)));
	xri->xr = xr;

	first = talloc_get_type_abort(fr_dlist_head(&xr->funcs), xlat_redundant_func_t);

	/*
	 *	Check the calling style matches the first
	 *	function.
	 *
	 *	We do this here as the redundant xlat
	 *	itself can't have an input type or
	 *	defined arguments;
	 */
	switch (xctx->ex->call.input_type) {
	case XLAT_INPUT_UNPROCESSED:
		break;

	case XLAT_INPUT_MONO:
		if (first->func->input_type == XLAT_INPUT_ARGS) {
			PERROR("Expansion function \"%s\" takes defined arguments and should "
			       "be called using %%(func:args) syntax",
				xctx->ex->call.func->name);
			return -1;

		}
		break;

	case XLAT_INPUT_ARGS:
		if (first->func->input_type == XLAT_INPUT_MONO) {
			PERROR("Expansion function \"%s\" should be called using %%{func:arg} syntax",
			       xctx->ex->call.func->name);
			return -1;
		}
		break;
	}

	/*
	 *	For each function, create the appropriate xlat
	 *	node, and duplicate the child arguments.
	 */
	fr_dlist_foreach(&xr->funcs, xlat_redundant_func_t, xrf) {
		xlat_exp_t *node;
		xlat_exp_head_t *head;

		/*
		 *	We have to do this here as it only
		 *	becomes an error when the user tries
		 *	to use the redundant xlat.
		 */
		if (first->func->input_type != xrf->func->input_type) {
			cf_log_err(xr->cs, "Expansion functions \"%s\" and \"%s\" use different argument styles "
				   "cannot be used in the same redundant section", first->func->name, xrf->func->name);
		error:
			talloc_free(xri->ex);
			return -1;
		}

		/*
		 *	We pass the current arguments in
		 *	so that the instantiation functions
		 *	for the new node can operate
		 *	correctly.
		 */
		MEM(head = xlat_exp_head_alloc(xri->ex));
		MEM(node = xlat_exp_func_alloc(head, xrf->func, xctx->ex->call.args));
		xlat_exp_insert_tail(head, node);

		switch (xrf->func->input_type) {
		case XLAT_INPUT_UNPROCESSED:
			break;

		case XLAT_INPUT_MONO:
			if (xlat_validate_function_mono(node) < 0) {
				PERROR("Invalid arguments for redundant expansion function \"%s\"",
				       xrf->func->name);
				goto error;
			}
			break;

		case XLAT_INPUT_ARGS:
			if (xlat_validate_function_args(node) < 0) {
				PERROR("Invalid arguments for redundant expansion function \"%s\"",
				       xrf->func->name);
				goto error;
			}
			break;
		}

		/*
		 *	Add the xlat function (and any children)
		 *	to the end of the instantiation list so
		 *	they'll get called at some point after
		 *	we return.
		 */
		head->flags = node->flags;
		xlat_bootstrap(head);
		xri->ex[num++] = head;
	}

	/*
	 *	Free the original argument nodes so they're
	 *	not evaluated when the redundant xlat is called.
	 *
	 *	We need to re-evaluate the arguments for each
	 *	redundant function call we perform.
	 *
	 *	The xlat_exp_func_alloc call above associates
	 *	a copy of the original arguments with each
	 *	function that's called.
	 */
	fr_dlist_talloc_free(&xctx->ex->call.args->dlist);

	return 0;
}

static xlat_arg_parser_t const xlat_redundant_args[] = {
	{ .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Registers a redundant xlat
 *
 * These xlats wrap the xlat methods of the modules in a redundant section,
 * emulating the behaviour of a redundant section, but over xlats.
 *
 * @return
 *	- 0 on success.
 *	- -1 on error.
 *	- 1 if the modules in the section do not have an xlat method.
 */
int xlat_register_redundant(CONF_SECTION *cs)
{
	static fr_table_num_sorted_t const xlat_redundant_type_table[] = {
		{ L("load-balance"),		XLAT_LOAD_BALANCE		},
		{ L("redundant"),		XLAT_REDUNDANT			},
		{ L("redundant-load-balance"),	XLAT_REDUNDANT_LOAD_BALANCE	},
	};
	static size_t xlat_redundant_type_table_len = NUM_ELEMENTS(xlat_redundant_type_table);

	char const		*name1, *name2;
	xlat_redundant_type_t	xr_type;
	xlat_redundant_t	*xr;
	xlat_func_flags_t	flags = XLAT_FUNC_FLAG_NONE;
	bool			can_be_pure = false;
	xlat_arg_parser_t const *args = NULL;

	fr_type_t		return_type = FR_TYPE_NULL;
	bool			first = true;

	xlat_t			*xlat;
	CONF_ITEM		*ci = NULL;

	name1 = cf_section_name1(cs);
	xr_type = fr_table_value_by_str(xlat_redundant_type_table, name1, XLAT_REDUNDANT_INVALID);
	switch (xr_type) {
	case XLAT_REDUNDANT_INVALID:
		cf_log_err(cs, "Invalid redundant section verb \"%s\"", name1);
		return -1;

	case XLAT_REDUNDANT:
		can_be_pure = true;	/* Can be pure */
		break;

	case XLAT_LOAD_BALANCE:
		can_be_pure = false;	/* Can never be pure because of random selection */
		break;

	case XLAT_REDUNDANT_LOAD_BALANCE:
		can_be_pure = false;	/* Can never be pure because of random selection */
		break;
	}

	name2 = cf_section_name2(cs);
	if (xlat_func_find(name2, talloc_array_length(name2) - 1)) {
		cf_log_err(cs, "An expansion is already registered for this name");
		return -1;
	}

	MEM(xr = talloc_zero(cs, xlat_redundant_t));
	xr->type = xr_type;
	xr->cs = cs;
	fr_dlist_talloc_init(&xr->funcs, xlat_redundant_func_t, entry);

	/*
	 *	Count the number of children for load-balance, and
	 *	also find out a little bit more about the old xlats.
	 *
	 *	These are just preemptive checks, the majority of
	 *	the work is done when a redundant xlat is
	 *	instantiated.  There we create an xlat node for
	 *	each of the children of the section.
	 */
	while ((ci = cf_item_next(cs, ci))) {
		xlat_redundant_func_t	*xrf;
		char const		*mod_func_name;
		xlat_t			*mod_func;

		if (!cf_item_is_pair(ci)) continue;

		mod_func_name = cf_pair_attr(cf_item_to_pair(ci));

		/*
		 *	This is ok, it just means the module
		 *	doesn't have an xlat method.
		 *
		 *	If there are ordering issues we could
		 *	move this check to the instantiation
		 *	function.
		 */
		mod_func = xlat_func_find(mod_func_name, talloc_array_length(mod_func_name) - 1);
		if (!mod_func) {
			talloc_free(xr);
			return 1;
		}

		if (!args) {
			args = mod_func->args;
		} else {
			fr_assert(args == mod_func->args);
		}

		/*
		 *	Degrade to a void return type if
		 *	we have mixed types in a redundant
		 *	section.
		 */
		if (!first) {
			if (mod_func->return_type != return_type) return_type = FR_TYPE_VOID;
		} else {
			return_type = mod_func->return_type;
			first = false;
		}

		MEM(xrf = talloc_zero(xr, xlat_redundant_func_t));
		xrf->func = mod_func;
		fr_dlist_insert_tail(&xr->funcs, xrf);

		/*
		 *	Figure out pure status.  If any of
		 *	the children are un-pure then the
		 *	whole redundant xlat is un-pure,
		 *	same with async.
		 */
		if (can_be_pure && mod_func->flags.pure) flags |= XLAT_FUNC_FLAG_PURE;
	}

	/*
	 *	At least one module xlat has to exist.
	 */
	if (!fr_dlist_num_elements(&xr->funcs)) {
		talloc_free(xr);
		return 1;
	}

	xlat = xlat_func_register(NULL, name2, xlat_redundant, return_type);
	if (unlikely(xlat == NULL)) {
		ERROR("Registering xlat for %s section failed",
		      fr_table_str_by_value(xlat_redundant_type_table, xr->type, "<INVALID>"));
		talloc_free(xr);
		return -1;
	}
	xlat_func_flags_set(xlat, flags);
	xlat_func_async_instantiate_set(xlat, xlat_redundant_instantiate, xlat_redundant_inst_t, NULL, xr);
	if (args) xlat_func_args_set(xlat, xlat_redundant_args);

	return 0;
}
