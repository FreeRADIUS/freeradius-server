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

#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/module_rlm.h>

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
	xlat_t const			*func;		//!< Resolved xlat function.
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
	unlang_result_t			last_result;	//!< Did the last call succeed?

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

	if (XLAT_RESULT_SUCCESS(&rctx->last_result)) {
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
		fr_strerror_printf("Failed all choices for redundant expansion %s", xctx->ex->fmt);
	error:
		xa = XLAT_ACTION_FAIL;
		goto done;
	}

	if (unlang_xlat_yield(request, xlat_redundant_resume, NULL, 0, rctx) != XLAT_ACTION_YIELD) goto error;

	/*
	 *	Push the next child...
	 */
	if (unlang_xlat_push(ctx, &rctx->last_result, (fr_value_box_list_t *)out->dlist,
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
	xlat_action_t 		xa = XLAT_RESULT_SUCCESS(&rctx->last_result) ? XLAT_ACTION_DONE : XLAT_ACTION_FAIL;

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

	if (unlang_xlat_push(ctx, &rctx->last_result, (fr_value_box_list_t *)out->dlist,
			     request, *rctx->current, UNLANG_SUB_FRAME) < 0) return XLAT_ACTION_FAIL;

	return XLAT_ACTION_PUSH_UNLANG;
}

static void xlat_mark_safe_for(xlat_exp_head_t *head, fr_value_box_safe_for_t safe_for)
{
	xlat_exp_foreach(head, node) {
		if (node->type == XLAT_BOX) {
			fr_value_box_mark_safe_for(&node->data, safe_for);
			continue;
		}

		if (node->type == XLAT_GROUP) {
			xlat_mark_safe_for(node->group, safe_for);
		}
	}
}

/** Allocate an xlat node to call an xlat function
 *
 * @param[in] ctx	to allocate the new node in.
 * @param[in] func	to call.
 * @param[in] args	Arguments to the function.  Will be copied,
 *			and freed when the new xlat node is freed.
 * @param[in] dict	the dictionary
 */
static xlat_exp_t *xlat_exp_func_alloc(TALLOC_CTX *ctx, xlat_t const *func, xlat_exp_head_t const *args, fr_dict_t const *dict)
{
	xlat_exp_t *node;

	MEM(node = xlat_exp_alloc(ctx, XLAT_FUNC, func->name, strlen(func->name)));
	xlat_exp_set_func(node, func, dict);

	node->flags = func->flags;
	node->flags.impure_func = !func->flags.pure;

	if (args) {
		xlat_flags_merge(&node->flags, &args->flags);

		/*
		 *	If the function is pure, AND it's arguments are pure,
		 *	then remember that we need to call a pure function.
		 */
		node->flags.can_purify = (func->flags.pure && args->flags.pure) | args->flags.can_purify;

		MEM(node->call.args = xlat_exp_head_alloc(node));
		node->call.args->is_argv = true;

		if (unlikely(xlat_copy(node, node->call.args, args) < 0)) {
			talloc_free(node);
			return NULL;
		}
	}

	/*
	 *      The original tokenizing is done using the redundant xlat argument parser so the boxes need to
	 *      have their "safe_for" value changed to the new one.
	 */
	if (func->args) {
		xlat_arg_parser_t const	*arg_p;
		xlat_exp_t		*arg;

		fr_assert(args);

		arg = xlat_exp_head(node->call.args);

		for (arg_p = node->call.func->args; arg_p->type != FR_TYPE_NULL; arg_p++) {
			if (!arg) break;

			xlat_mark_safe_for(arg->group, arg_p->safe_for);

			arg = xlat_exp_next(node->call.args, arg);
		}
	}

	return node;
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
	fr_dict_t const			*dict = NULL;

	MEM(xri->ex = talloc_array(xri, xlat_exp_head_t *, fr_dlist_num_elements(&xr->funcs)));
	xri->xr = xr;

	first = talloc_get_type_abort(fr_dlist_head(&xr->funcs), xlat_redundant_func_t);

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
		if ((!first->func->args && xrf->func->args) ||
		    (first->func->args && !xrf->func->args)) {
			cf_log_err(xr->cs, "Expansion functions \"%s\" and \"%s\" use different argument styles "
				   "cannot be used in the same redundant section", first->func->name, xrf->func->name);
		error:
			talloc_free(xri->ex);
			return -1;
		}

		if (!dict) {
			dict = xctx->ex->call.dict;
			fr_assert(dict != NULL);

		} else if (dict != xctx->ex->call.dict) {
			cf_log_err(xr->cs, "Expansion functions \"%s\" and \"%s\" use different dictionaries"
				   "cannot be used in the same redundant section", first->func->name, xrf->func->name);
			goto error;
		}

		/*
		 *	We pass the current arguments in
		 *	so that the instantiation functions
		 *	for the new node can operate
		 *	correctly.
		 */
		MEM(head = xlat_exp_head_alloc(xri->ex));
		MEM(node = xlat_exp_func_alloc(head, xrf->func, xctx->ex->call.args, dict));
		xlat_exp_insert_tail(head, node);

		if (xlat_validate_function_args(node) < 0) {
			PERROR("Invalid arguments for redundant expansion function \"%s\"",
			       xrf->func->name);
			goto error;
		}

		/*
		 *	Add the xlat function (and any children)
		 *	to the end of the instantiation list so
		 *	they'll get called at some point after
		 *	we return.
		 */
		head->flags = node->flags;
		if (xlat_finalize(head, NULL) < 0) {
			PERROR("Failed bootstrapping function \"%s\"",
			       xrf->func->name);
			goto error;
		}
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
	{ .type = FR_TYPE_VOID, .variadic = XLAT_ARG_VARIADIC_EMPTY_KEEP },
	XLAT_ARG_PARSER_TERMINATOR
};

static inline CC_HINT(always_inline)
void xlat_redundant_add_xlat(xlat_redundant_t *xr, xlat_t const *x)
{
	xlat_redundant_func_t *xrf;

	MEM(xrf = talloc_zero(xr, xlat_redundant_func_t));
	xrf->func = x;
	fr_dlist_insert_tail(&xr->funcs, xrf);
}

/** Compare two module_rlm_xlat_t based on whether they have the same name
 *
 * @note If the two xlats both have the same name as the module that registered them,
 *       then they are considered equal.
 */
static int8_t module_xlat_cmp(void const *a, void const *b)
{
	module_rlm_xlat_t const *mrx_a = talloc_get_type_abort_const(a, module_rlm_xlat_t);
	module_rlm_xlat_t const *mrx_b = talloc_get_type_abort_const(b, module_rlm_xlat_t);
	char const *a_p, *b_p;

	/*
	 *	A null result means a self-named module xlat,
	 *	which is always equal to another self-named
	 *	module xlat.
	 */
	a_p = strchr(mrx_a->xlat->name, '.');
	b_p = strchr(mrx_b->xlat->name, '.');
	if (!a_p && !b_p) return 0;

	/*
	 *	Compare the bit after the module name
	 */
	if (!a_p || !b_p) return CMP(a_p, b_p);

	return CMP(strcmp(a_p, b_p), 0);
}

static int8_t module_qualified_xlat_cmp(void const *a, void const *b)
{
	int8_t ret;

	module_rlm_xlat_t const *mrx_a = talloc_get_type_abort_const(a, module_rlm_xlat_t);
	module_rlm_xlat_t const *mrx_b = talloc_get_type_abort_const(b, module_rlm_xlat_t);

	ret = module_xlat_cmp(a, b);
	if (ret != 0) return ret;

	return CMP(mrx_a->mi, mrx_b->mi);
}

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

	char const		*name1;
	xlat_redundant_type_t	xr_type;
	xlat_func_flags_t	default_flags = 0;	/* Prevent warnings about default flags if xr_rype is corrupt */

	fr_type_t		return_type = FR_TYPE_NULL;

	CONF_ITEM		*ci = NULL;
	int			children = 0, i;
	fr_rb_tree_t		*mrx_tree;		/* Temporary tree for ordering xlats */

	name1 = cf_section_name1(cs);
	xr_type = fr_table_value_by_str(xlat_redundant_type_table, name1, XLAT_REDUNDANT_INVALID);
	switch (xr_type) {
	case XLAT_REDUNDANT_INVALID:
		cf_log_err(cs, "Invalid redundant section verb \"%s\"", name1);
		return -1;

	case XLAT_REDUNDANT:
		default_flags = XLAT_FUNC_FLAG_PURE;	/* Can be pure */
		break;

	case XLAT_LOAD_BALANCE:
		default_flags = XLAT_FUNC_FLAG_NONE;	/* Can never be pure because of random selection */
		break;

	case XLAT_REDUNDANT_LOAD_BALANCE:
		default_flags = XLAT_FUNC_FLAG_NONE;	/* Can never be pure because of random selection */
		break;
	}

	/*
	 *	Count the children
	 */
	while ((ci = cf_item_next(cs, ci))) {
		if (!cf_item_is_pair(ci)) continue;

		children++;
	}

	/*
	 *	There must be at least one child.
	 *
	 *	It's useful to allow a redundant section with only one
	 *	child, for debugging.
	 */
	if (children == 0) {
		cf_log_err(cs, "%s %s { ... } section must contain at least one module",
			   cf_section_name1(cs), cf_section_name2(cs));
		return -1;
	}

	/*
	 *	Resolve all the modules in the redundant section,
	 *	and insert all the mrx into a temporary tree to
	 *	order them.
	 *
	 *	Next we'll iterate over all the mrx, creating
	 *	redundant xlats from contiguous runs of mrxs
	 *	pointing to the same xlat.
	 */
	MEM(mrx_tree = fr_rb_talloc_alloc(NULL, module_rlm_xlat_t, module_qualified_xlat_cmp, NULL));
	for (ci = cf_item_next(cs, NULL), i = 0;
	     ci;
	     ci = cf_item_next(cs, ci), i++) {
		module_instance_t		*mi;
		module_rlm_instance_t		*mri;
		char const			*name;

		if (!cf_item_is_pair(ci)) continue;

		name = cf_pair_attr(cf_item_to_pair(ci));

		mi = module_rlm_static_by_name(NULL, name);
		if (!mi) {
			cf_log_err(ci, "Module '%s' not found.  Referenced in %s %s { ... } section",
				   name, cf_section_name1(cs), cf_section_name2(cs));
		error:
			talloc_free(mrx_tree);
			return -1;
		}

		mri = talloc_get_type_abort(mi->uctx, module_rlm_instance_t);
		fr_dlist_foreach(&mri->xlats, module_rlm_xlat_t const, mrx) {
			if (!fr_rb_insert(mrx_tree, mrx)) {
				cf_log_err(cs, "Module '%s' referenced multiple times in %s %s { ... } section",
					   mrx->mi->name, cf_section_name1(cs), cf_section_name2(cs));
				goto error;
			}
		}
	}

	if (fr_rb_num_elements(mrx_tree) == 0) {
		cf_log_debug(cs, "No expansions exported by modules in %s %s { ... } section, "
			     "not registering redundant/load-balance expansion",
			     cf_section_name1(cs), cf_section_name2(cs));
		talloc_free(mrx_tree);
		return 0;
	}

	/*
	 *	Iterate over the xlats registered for the first module,
	 *	verifying that the other module instances have all registered
	 *	the similarly named xlat functions.
	 *
	 *	We ignore any xlat functions that aren't available in all the
	 *	modules.
	 */
	{
		fr_rb_iter_inorder_t		iter;
		fr_sbuff_t			*name;
		fr_sbuff_marker_t		name_start;
		module_instance_t		*mi;
		module_rlm_xlat_t		*mrx, *prev_mrx;
		xlat_redundant_t		*xr;

		FR_SBUFF_TALLOC_THREAD_LOCAL(&name, 128, SIZE_MAX);

		/*
		 *	Prepopulate the name buffer with  <section_name2>.
		 *	as every function wil be registered with this
		 *	prefix.
		 */
		if ((fr_sbuff_in_bstrcpy_buffer(name, cf_section_name2(cs)) <= 0) ||
		     (fr_sbuff_in_char(name, '.') <= 0)) {
			cf_log_perr(cs, "Name too long");
			return -1;
		}

		fr_sbuff_marker(&name_start, name);

		mrx = fr_rb_iter_init_inorder(&iter, mrx_tree);

		/*
		 *	Iterate over the all the xlats, registered by
		 *	all the modules in the section.
		 */
		while (mrx) {
			xlat_t			*xlat;
			xlat_func_flags_t	flags = default_flags;
			char const		*name_p;

			mi = mrx->mi;

			/*
			 *	Where the xlat name is in the format <mod>.<name2>
			 *	then the redundant xlat will be <section_name2>.<xlat_name>.
			 *
			 *	Where the xlat has no '.', it's likely just the module
			 *	name, in which case we just use <section_name2>.
			 */
			name_p = strchr(mrx->xlat->name, '.');
			if (name_p) {
				name_p++;
				fr_sbuff_set(name, &name_start);	/* Reset the aggregation buffer to the '.' */
				if (fr_sbuff_in_bstrncpy(name, name_p, strlen(name_p)) < 0) {
					cf_log_perr(cs, "Name too long");
					goto error;
				}
				name_p = fr_sbuff_start(name);
			} else {
				name_p = cf_section_name2(cs);
			}

			MEM(xr = talloc_zero(NULL, xlat_redundant_t));
			xr->type = xr_type;
			xr->cs = cs;
			fr_dlist_talloc_init(&xr->funcs, xlat_redundant_func_t, entry);

			/*
			 *	Iterate over all the xlats registered by all the modules
			 *	in the section, when we reach the end of a run of common
			 *	xlats, we register the redundant xlat.
			 *
			 *	Note: Just because a xlat function has the same name,
			 *	it does not mean the function signature is compatible.
			 *
			 *	These issues are caught when we instantiate a redundant
			 *	xlat, as the arguments passed to the redunant xlat are
			 *	validated against the argument definitions for each
			 *	individual xlat the redunant xlat would call.
			 */
			do {
				if (!mrx->xlat->flags.pure) flags &= ~XLAT_FUNC_FLAG_PURE;
				xlat_redundant_add_xlat(xr, mrx->xlat);
				prev_mrx = mrx;
			} while ((mrx = fr_rb_iter_next_inorder(&iter)) && (module_xlat_cmp(prev_mrx, mrx) == 0));

			/*
			 *	Warn, but allow, redundant/failover expansions that are
			 *	neither redundant, nor failover.
			 *
			 *	Sometimes useful to comment out modules during testing.
			 */
			if (fr_dlist_num_elements(&xr->funcs) == 1) {
				cf_log_warn(cs, "%s expansion has no alternates, only %s",
					    fr_table_str_by_value(xlat_redundant_type_table, xr->type, "<INVALID>"),
					    ((xlat_redundant_func_t *)fr_dlist_head(&xr->funcs))->func->name);

			}

			/*
			 *	Register the new redundant xlat, and hang it off of
			 *	the first module instance in the section.
			 *
			 *	This isn't great, but at least the xlat should
			 *	get unregistered at about the right time.
			 */
			xlat = xlat_func_register(mi, name_p, xlat_redundant, return_type);
			if (unlikely(xlat == NULL)) {
				cf_log_err(cs, "Registering expansion for %s section failed",
					   fr_table_str_by_value(xlat_redundant_type_table, xr->type, "<INVALID>"));
				talloc_free(xr);
				return -1;
			}
			talloc_steal(xlat, xr);	/* redundant xlat should own its own config */

			cf_log_debug(cs, "Registered %s expansion \"%s\" with %u alternates",
				     fr_table_str_by_value(xlat_redundant_type_table, xr->type, "<INVALID>"),
				     xlat->name, fr_dlist_num_elements(&xr->funcs));

			xlat_func_flags_set(xlat, flags);
			xlat_func_instantiate_set(xlat, xlat_redundant_instantiate, xlat_redundant_inst_t, NULL, xr);
			xlat_func_args_set(xlat, xlat_redundant_args);
		}
	}
	talloc_free(mrx_tree);

	return 0;
}
