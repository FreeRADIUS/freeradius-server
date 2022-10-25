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
 * @file xlat_builtin.c
 * @brief String expansion ("translation").  Baked in expansions.
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

/**
 * @defgroup xlat_functions xlat expansion functions
 */

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/tmpl_dcursor.h>
#include <freeradius-devel/unlang/xlat_priv.h>

#include <freeradius-devel/io/test_point.h>

#include <freeradius-devel/util/base64.h>
#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/sha1.h>

#ifdef HAVE_OPENSSL_EVP_H
#  include <freeradius-devel/tls/openssl_user_macros.h>
#  include <openssl/evp.h>
#endif

#ifdef HAVE_REGEX_PCRE2
#endif


static fr_rb_tree_t *xlat_root = NULL;

static char const hextab[] = "0123456789abcdef";

/** Return a VP from the specified request.
 *
 * @note DEPRECATED, TO NOT USE.
 *
 * @param out where to write the pointer to the resolved VP. Will be NULL if the attribute couldn't
 *	be resolved.
 * @param request current request.
 * @param name attribute name including qualifiers.
 * @return
 *	- -4 if either the attribute or qualifier were invalid.
 *	- The same error codes as #tmpl_find_vp for other error conditions.
 */
int xlat_fmt_get_vp(fr_pair_t **out, request_t *request, char const *name)
{
	int ret;
	tmpl_t *vpt;

	*out = NULL;

	if (tmpl_afrom_attr_str(request, NULL, &vpt, name,
				&(tmpl_rules_t){
					.attr = {
						.dict_def = request->dict,
						.prefix = TMPL_ATTR_REF_PREFIX_AUTO
					}
				}) <= 0) return -4;

	ret = tmpl_find_vp(out, request, vpt);
	talloc_free(vpt);

	return ret;
}


/*
 *	Compare two xlat_t structs, based ONLY on the module name.
 */
static int8_t xlat_cmp(void const *one, void const *two)
{
	xlat_t const *a = one, *b = two;
	size_t a_len, b_len;
	int ret;

	a_len = strlen(a->name);
	b_len = strlen(b->name);

	ret = CMP(a_len, b_len);
	if (ret != 0) return ret;

	ret = memcmp(a->name, b->name, a_len);
	return CMP(ret, 0);
}


/*
 *	find the appropriate registered xlat function.
 */
xlat_t *xlat_func_find(char const *in, ssize_t inlen)
{
	char buffer[256];

	if (!xlat_root) return NULL;

	if (inlen < 0) return fr_rb_find(xlat_root, &(xlat_t){ .name = in });

	if ((size_t) inlen >= sizeof(buffer)) return NULL;

	memcpy(buffer, in, inlen);
	buffer[inlen] = '\0';

	return fr_rb_find(xlat_root, &(xlat_t){ .name = buffer });
}


/** Remove an xlat function from the function tree
 *
 * @param[in] xlat	to free.
 * @return 0
 */
static int _xlat_func_talloc_free(xlat_t *xlat)
{
	if (!xlat_root) return 0;

	fr_rb_delete(xlat_root, xlat);
	if (fr_rb_num_elements(xlat_root) == 0) TALLOC_FREE(xlat_root);

	return 0;
}


/** Callback for the rbtree to clear out any xlats still registered
 *
 */
static void _xlat_func_tree_free(void *xlat)
{
	talloc_free(xlat);
}

/** Register an xlat function for a module
 *
 * @param[in] ctx		Used to automate deregistration of the xlat fnction.
 * @param[in] mctx		Instantiation context from the module.
 *				Will be duplicated and passed to future xlat calls.
 * @param[in] name		of the xlat.
 * @param[in] func		to register.
 * @param[in] flags		various function flags
 * @return
 *	- A handle for the newly registered xlat function on success.
 *	- NULL on failure.
 */
xlat_t *xlat_register_module(TALLOC_CTX *ctx, module_inst_ctx_t const *mctx,
			     char const *name, xlat_func_t func, xlat_flags_t const *flags)
{
	static const xlat_flags_t default_flags;
	xlat_t	*c;
	module_inst_ctx_t *our_mctx = NULL;

	fr_assert(xlat_root);

	if (!*name) {
		ERROR("%s: Invalid xlat name", __FUNCTION__);
		return NULL;
	}

	if (!flags) {
		flags = &default_flags;
	} else {
		fr_assert(!flags->needs_resolving);
	}

	/*
	 *	If it already exists, replace the instance.
	 */
	c = fr_rb_find(xlat_root, &(xlat_t){ .name = name });
	if (c) {
		if (c->internal) {
			ERROR("%s: Cannot re-define internal expansion %s", __FUNCTION__, name);
			return NULL;
		}

		if (c->flags.needs_async != flags->needs_async) {
			ERROR("%s: Cannot change async capability of %s", __FUNCTION__, name);
			return NULL;
		}

		if (c->func != func) {
			ERROR("%s: Cannot change callback function for %s", __FUNCTION__, name);
			return NULL;
		}

		return c;
	}

	/*
	 *	Doesn't exist.  Create it.
	 */
	MEM(c = talloc(ctx, xlat_t));
	if (mctx) {
		MEM(our_mctx = talloc_zero(c, module_inst_ctx_t));	/* Original won't stick around */
		memcpy(our_mctx, mctx, sizeof(*our_mctx));
	}
	*c = (xlat_t){
		.name = talloc_typed_strdup(c, name),
		.func = func,
		.mctx = our_mctx,
		.flags = *flags,
		.input_type = XLAT_INPUT_UNPROCESSED	/* set default - will be overridden if args are registered */
	};
	talloc_set_destructor(c, _xlat_func_talloc_free);
	DEBUG3("%s: %s", __FUNCTION__, c->name);

	if (fr_rb_replace(NULL, xlat_root, c) < 0) {
		ERROR("%s: Failed inserting xlat registration for %s", __FUNCTION__, c->name);
		talloc_free(c);
		return NULL;
	}

	/*
	 *	If the function is async, it can't be pure.  But
	 *	non-pure functions don't need to be async.
	 */
	fr_assert(!flags->needs_async || !flags->pure);
	fr_assert(!flags->needs_resolving);

	return c;
}

/** Register an xlat function
 *
 * @param[in] ctx		Used to automate deregistration of the xlat fnction.
 * @param[in] name		of the xlat.
 * @param[in] func		to register.
 * @param[in] flags		various function flags
 * @return
 *	- A handle for the newly registered xlat function on success.
 *	- NULL on failure.
 */
xlat_t *xlat_register(TALLOC_CTX *ctx, char const *name, xlat_func_t func, xlat_flags_t const *flags)
{
	return xlat_register_module(ctx, NULL, name, func, flags);
}

#if 0
/** Compare two argument entries to see if they're equivalent
 *
 * @note Does not check escape function or uctx pointers.
 *
 * @param[in] a		First argument structure.
 * @param[in] b		Second argument structure.
 * @return
 *	- 1 if a > b
 *	- 0 if a == b
 *	- -1 if a < b
 */
static int xlat_arg_cmp_no_escape(xlat_arg_parser_t const *a, xlat_arg_parser_t const *b)
{
	int8_t ret;

	ret = CMP(a->required, b->required);
	if (ret != 0) return ret;

	ret = CMP(a->concat, b->concat);
	if (ret != 0) return ret;

	ret = CMP(a->single, b->single);
	if (ret != 0) return ret;

	ret = CMP(a->variadic, b->variadic);
	if (ret != 0) return ret;

	ret = CMP(a->always_escape, b->always_escape);
	if (ret != 0) return ret;

	return CMP(a->type, b->type);
}

/** Compare two argument lists to see if they're equivalent
 *
 * @note Does not check escape function or uctx pointers.
 *
 * @param[in] a		First argument structure.
 * @param[in] b		Second argument structure.
 * @return
 *	- 1 if a > b
 *	- 0 if a == b
 *	- -1 if a < b
 */
static int xlat_arg_cmp_list_no_escape(xlat_arg_parser_t const a[], xlat_arg_parser_t const b[])
{
	xlat_arg_parser_t const *arg_a_p;
	xlat_arg_parser_t const *arg_b_p;

	for (arg_a_p = a, arg_b_p = b;
	     (arg_a_p->type != FR_TYPE_NULL) && (arg_b_p->type != FR_TYPE_NULL);
	     arg_a_p++, arg_b_p++) {
		int8_t ret;

		ret = xlat_arg_cmp_no_escape(arg_a_p, arg_b_p);
		if (ret != 0) return ret;
	}

	return CMP(arg_a_p, arg_b_p);	/* Check we ended at the same point */
}
#endif

/** Verify xlat arg specifications are valid
 *
 * @param[in] arg	specification to validate.
 */
static inline int xlat_arg_parser_validate(xlat_arg_parser_t const *arg, bool last)
{
	if (arg->concat) {
		if (!fr_cond_assert_msg((arg->type == FR_TYPE_STRING) || (arg->type == FR_TYPE_OCTETS),
					"concat type must be string or octets")) return -1;

		if (!fr_cond_assert_msg(!arg->single, "concat and single are mutually exclusive")) return -1;
	}

	if (arg->single) {
		if (!fr_cond_assert_msg(!arg->concat, "single and concat are mutually exclusive")) return -1;
	}

	if (arg->variadic) {
		if (!fr_cond_assert_msg(last, "variadic can only be set on the last argument")) return -1;
	}

	if (arg->always_escape) {
		if (!fr_cond_assert_msg(arg->func, "always_escape requires an escape func")) return -1;
	}

	if (arg->uctx) {
		if (!fr_cond_assert_msg(arg->func, "uctx requires an escape func")) return -1;
	}

	switch (arg->type) {
	case FR_TYPE_LEAF:
	case FR_TYPE_VOID:
		break;

	default:
		fr_assert_fail("type must be a leaf box type");
		return -1;
	}

	return 0;
}

/** Register the arguments of an xlat
 *
 * For xlats that take multiple arguments
 *
 * @param[in,out] x		to have it's arguments registered
 * @param[in] args		to be registered
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
int xlat_func_args(xlat_t *x, xlat_arg_parser_t const args[])
{
	xlat_arg_parser_t const *arg_p = args;
	bool			seen_optional = false;

	for (arg_p = args; arg_p->type != FR_TYPE_NULL; arg_p++) {
		if (xlat_arg_parser_validate(arg_p, (arg_p + 1)->type == FR_TYPE_NULL) < 0) return -1;

		if (arg_p->required) {
			if (!fr_cond_assert_msg(!seen_optional,
						"required arguments must be at the "
						"start of the argument list")) return -1;
		} else {
			seen_optional = true;
		}
	}
	x->args = args;
	x->input_type = XLAT_INPUT_ARGS;

	return 0;
}

/** Register the argument of an xlat
 *
 * For xlats that take all their input as a single argument
 *
 * @param[in,out] x		to have it's arguments registered
 * @param[in] arg		to be registered
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
int xlat_func_mono(xlat_t *x, xlat_arg_parser_t const *arg)
{
	if (xlat_arg_parser_validate(arg, true) < 0) return -1;

	x->args = arg;
	x->input_type = XLAT_INPUT_MONO;

	return 0;
}

/** Set global instantiation/detach callbacks
 *
 * All functions registered must be needs_async.
 *
 * @param[in] xlat		to set instantiation callbacks for.
 * @param[in] instantiate	Instantiation function. Called whenever a xlat is
 *				compiled.
 * @param[in] inst_type		Name of the instance structure.
 * @param[in] inst_size		The size of the instance struct.
 *				Pre-allocated for use by the instantiate function.
 *				If 0, no memory will be allocated.
 * @param[in] detach		Called when an xlat_exp_t is freed.
 * @param[in] uctx		Passed to the instantiation function.
 */
void _xlat_async_instantiate_set(xlat_t const *xlat,
				 xlat_instantiate_t instantiate, char const *inst_type, size_t inst_size,
				 xlat_detach_t detach,
				 void *uctx)
{
	xlat_t *c = UNCONST(xlat_t *, xlat);

	c->instantiate = instantiate;
	c->inst_type = inst_type;
	c->inst_size = inst_size;
	c->detach = detach;
	c->uctx = uctx;
}


/** Register an async xlat
 *
 * All functions registered must be needs_async.
 *
 * @param[in] xlat			to set instantiation callbacks for.
 * @param[in] thread_instantiate	Instantiation function. Called for every compiled xlat
 *					every time a thread is started.
 * @param[in] thread_inst_type		Name of the thread instance structure.
 * @param[in] thread_inst_size		The size of the thread instance struct.
 *					Pre-allocated for use by the instantiate function.
 *					If 0, no memory will be allocated.
 * @param[in] thread_detach		Called when the thread is freed.
 * @param[in] uctx			Passed to the thread instantiate function.
 */
void _xlat_async_thread_instantiate_set(xlat_t const *xlat,
					xlat_thread_instantiate_t thread_instantiate,
				        char const *thread_inst_type, size_t thread_inst_size,
				        xlat_thread_detach_t thread_detach,
				        void *uctx)
{
	xlat_t *c = UNCONST(xlat_t *, xlat);

	/*
	 *	Pure functions can't use any thread-local
	 *	variables. They MUST operate only on constant
	 *	instantiation data, and on their (possibly constant)
	 *	inputs.
	 */
	fr_assert(!c->flags.pure);

	c->thread_instantiate = thread_instantiate;
	c->thread_inst_type = thread_inst_type;
	c->thread_inst_size = thread_inst_size;
	c->thread_detach = thread_detach;
	c->thread_uctx = uctx;
}


/** Unregister an xlat function
 *
 * We can only have one function to call per name, so the passing of "func"
 * here is extraneous.
 *
 * @param[in] name xlat to unregister.
 */
void xlat_unregister(char const *name)
{
	xlat_t	*c;

	if (!name || !xlat_root) return;

	c = fr_rb_find(xlat_root, &(xlat_t){ .name = name });
	if (!c) return;

	(void) talloc_get_type_abort(c, xlat_t);

	talloc_free(c);	/* Should also remove from tree */
}


void xlat_unregister_module(dl_module_inst_t const *inst)
{
	xlat_t				*c;
	fr_rb_iter_inorder_t	iter;

	if (!xlat_root) return;	/* All xlats have already been freed */

	for (c = fr_rb_iter_init_inorder(&iter, xlat_root);
	     c;
	     c = fr_rb_iter_next_inorder(&iter)) {
		if (!c->mctx) continue;
		if (c->mctx->inst != inst) continue;

		fr_rb_iter_delete_inorder(&iter);
	}
}


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

	if (unlang_xlat_yield(request, xlat_redundant_resume, NULL, rctx) != XLAT_ACTION_YIELD) goto error;

	/*
	 *	Push the next child...
	 */
	if (unlang_xlat_push(ctx, &rctx->last_success, out->dlist,
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
		if (unlang_xlat_yield(request, xlat_redundant_resume, NULL, rctx) != XLAT_ACTION_YIELD) {
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
		if (unlang_xlat_yield(request, xlat_load_balance_resume, NULL, rctx) != XLAT_ACTION_YIELD) goto error;
		break;

	/*
	 *	Run through each of the redundant functions sequentially
	 *	starting at a random element.
	 */
	case XLAT_REDUNDANT_LOAD_BALANCE:
		rctx->first = &xri->ex[(size_t)fr_rand() & (talloc_array_length(xri->ex) - 1)];	/* Random start */
		if (unlang_xlat_yield(request, xlat_redundant_resume, NULL, rctx) != XLAT_ACTION_YIELD) goto error;
		break;

	default:
		fr_assert(0);
	}

	if (unlang_xlat_push(ctx, &rctx->last_success, out->dlist,
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
	xlat_flags_t		flags = {};
	xlat_arg_parser_t const *args = NULL;

	xlat_t			*xlat;
	CONF_ITEM		*ci = NULL;

	name1 = cf_section_name1(cs);
	xr_type = fr_table_value_by_str(xlat_redundant_type_table, name1, XLAT_REDUNDANT_INVALID);
	switch (xr_type) {
	case XLAT_REDUNDANT_INVALID:
		cf_log_err(cs, "Invalid redundant section verb \"%s\"", name1);
		return -1;

	case XLAT_REDUNDANT:
		flags.pure = true;	/* Can be pure */
		break;

	case XLAT_LOAD_BALANCE:
		flags.pure = false;	/* Can never be pure because of random selection */
		break;

	case XLAT_REDUNDANT_LOAD_BALANCE:
		flags.pure = false;	/* Can never be pure because of random selection */
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
		xlat_t			*mod_func = NULL;
		char const		*mod_func_name;

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

		MEM(xrf = talloc_zero(xr, xlat_redundant_func_t));
		xrf->func = mod_func;
		fr_dlist_insert_tail(&xr->funcs, xrf);

		/*
		 *	Figure out pure status.  If any of
		 *	the children are un-pure then the
		 *	whole redundant xlat is un-pure,
		 *	same with async.
		 */
		xlat_flags_merge(&flags, &mod_func->flags);
	}

	/*
	 *	At least one module xlat has to exist.
	 */
	if (!fr_dlist_num_elements(&xr->funcs)) {
		talloc_free(xr);
		return 1;
	}

	xlat = xlat_register(NULL, name2, xlat_redundant, &flags);
	if (!xlat) {
		ERROR("Registering xlat for %s section failed",
		      fr_table_str_by_value(xlat_redundant_type_table, xr->type, "<INVALID>"));
		talloc_free(xr);
		return -1;
	}
	xlat_async_instantiate_set(xlat, xlat_redundant_instantiate, xlat_redundant_inst_t, NULL, xr);
	if (args) xlat_func_args(xlat, args);

	return 0;
}

/*
 *	Regular xlat functions
 */
static xlat_arg_parser_t const xlat_func_debug_args[] = {
	{ .single = true, .type = FR_TYPE_INT8 },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Dynamically change the debugging level for the current request
 *
 * Example:
@verbatim
"%(debug:3)"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_debug(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     UNUSED xlat_ctx_t const *xctx,
				     request_t *request, fr_value_box_list_t *in)
{
	int level = 0;
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head = fr_dlist_head(in);

	/*
	 *  Expand to previous (or current) level
	 */
	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_INT8, NULL, false));
	vb->vb_int8 = request->log.lvl;
	fr_dcursor_append(out, vb);

	/*
	 *  Assume we just want to get the current value and NOT set it to 0
	 */
	if (!in_head) goto done;

	level = in_head->vb_int8;
	if (level == 0) {
		request->log.lvl = RAD_REQUEST_LVL_NONE;
	} else {
		if (level > L_DBG_LVL_MAX) level = L_DBG_LVL_MAX;
		request->log.lvl = level;
	}

done:
	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const xlat_func_debug_attr_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

void xlat_debug_attr_vp(request_t *request, fr_pair_t *vp, tmpl_t const *vpt)
{
	fr_dict_vendor_t const		*vendor;
	fr_table_num_ordered_t const	*type;
	size_t				i;

	switch (vp->da->type) {
	case FR_TYPE_STRUCTURAL:
		if (vpt) {
			RIDEBUG2("&%s.%s = {",
				 fr_table_str_by_value(pair_list_table, tmpl_list(vpt), "<INVALID>"),
				 vp->da->name);
		} else {
			RIDEBUG2("%s = {", vp->da->name);
		}
		RINDENT();
		xlat_debug_attr_list(request, &vp->vp_group);
		REXDENT();
		RIDEBUG2("}");
		break;

	default:
		if (vpt) {
			RIDEBUG2("&%s.%s = %pV",
				 fr_table_str_by_value(pair_list_table, tmpl_list(vpt), "<INVALID>"),
				 vp->da->name,
				 &vp->data);
		} else {
			RIDEBUG2("%s = %pV", vp->da->name, &vp->data);
		}
	}

	if (!RDEBUG_ENABLED3) return;

	RINDENT();
	RIDEBUG3("da         : %p", vp->da);
	RIDEBUG3("is_raw     : %pV", fr_box_bool(vp->da->flags.is_raw));
	RIDEBUG3("is_unknown : %pV", fr_box_bool(vp->da->flags.is_unknown));

	if (RDEBUG_ENABLED3) {
		RIDEBUG3("parent     : %s (%p)", vp->da->parent->name, vp->da->parent);
	} else {
		RIDEBUG2("parent     : %s", vp->da->parent->name);
	}
	RIDEBUG3("attr       : %u", vp->da->attr);
	vendor = fr_dict_vendor_by_da(vp->da);
	if (vendor) RIDEBUG2("vendor     : %i (%s)", vendor->pen, vendor->name);
	RIDEBUG3("type       : %s", fr_type_to_str(vp->vp_type));

	if (fr_box_is_variable_size(&vp->data)) {
		RIDEBUG3("length     : %zu", vp->vp_length);
	}
	RIDEBUG3("tainted    : %pV", fr_box_bool(vp->data.tainted));

	if (!RDEBUG_ENABLED4) {
		REXDENT();
		return;
	}

	for (i = 0; i < fr_type_table_len; i++) {
		int pad;

		fr_value_box_t *dst = NULL;

		type = &fr_type_table[i];

		if ((fr_type_t) type->value == vp->vp_type) goto next_type;

		switch (type->value) {
		case FR_TYPE_NON_LEAF:	/* Skip everything that's not a value */
			goto next_type;

		default:
			break;
		}

		MEM(dst = fr_value_box_alloc_null(vp));
		/* We expect some to fail */
		if (fr_value_box_cast(dst, dst, type->value, NULL, &vp->data) < 0) {
			goto next_type;
		}

		if ((pad = (11 - type->name.len)) < 0) pad = 0;

		RINDENT();
		RDEBUG4("as %s%*s: %pV", type->name.str, pad, " ", dst);
		REXDENT();

	next_type:
		talloc_free(dst);
	}

	REXDENT();
}

void xlat_debug_attr_list(request_t *request, fr_pair_list_t const *list)
{
	fr_pair_t *vp;

	for (vp = fr_pair_list_next(list, NULL);
	     vp != NULL;
	     vp = fr_pair_list_next(list, vp)) {
		xlat_debug_attr_vp(request, vp, NULL);
	}
}

/** Print out attribute info
 *
 * Prints out all instances of a current attribute, or all attributes in a list.
 *
 * At higher debugging levels, also prints out alternative decodings of the same
 * value. This is helpful to determine types for unknown attributes of long
 * passed vendors, or just crazy/broken NAS.
 *
 * This expands to a zero length string.
 *
 * Example:
@verbatim
"%(debug_attr:&request[*])"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_debug_attr(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					  UNUSED xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *in)
{
	fr_pair_t		*vp;
	fr_dcursor_t		cursor;
	tmpl_dcursor_ctx_t	cc;
	tmpl_t			*vpt;
	fr_value_box_t		*attr = fr_dlist_head(in);
	char const		*fmt;

	if (!RDEBUG_ENABLED2) return XLAT_ACTION_DONE;	/* NOOP if debugging isn't enabled */

	fmt = attr->vb_strvalue;

	if (tmpl_afrom_attr_str(request, NULL, &vpt, fmt,
				&(tmpl_rules_t){
					.attr = {
						.dict_def = request->dict,
						.prefix = TMPL_ATTR_REF_PREFIX_AUTO
					}
				}) <= 0) {
		RPEDEBUG("Invalid input");
		return XLAT_ACTION_FAIL;
	}

	RIDEBUG("Attributes matching \"%s\"", fmt);

	RINDENT();
	for (vp = tmpl_dcursor_init(NULL, NULL, &cc, &cursor, request, vpt);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
		xlat_debug_attr_vp(request, vp, vpt);
	}
	tmpl_dcursor_clear(&cc);
	REXDENT();

	talloc_free(vpt);

	return XLAT_ACTION_DONE;
}

/** Flatten a given group.
 *
 *  This is a temporary function for migration purposes
 *
 * Example:
@verbatim
"%(flatten:&request)"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_flatten(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					  UNUSED xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *in)
{
	fr_pair_t		*vp;
	tmpl_t			*vpt;
	fr_value_box_t		*attr = fr_dlist_head(in);
	char const		*fmt;

	fmt = attr->vb_strvalue;
	if (tmpl_afrom_attr_str(request, NULL, &vpt, fmt,
				&(tmpl_rules_t){
					.attr = {
						.dict_def = request->dict,
						.prefix = TMPL_ATTR_REF_PREFIX_AUTO
					}
				}) <= 0) {
		RPEDEBUG("Invalid input");
		return XLAT_ACTION_FAIL;
	}

	if ((tmpl_find_vp(&vp, request, vpt) < 0) ||
	    (vp->da->type != FR_TYPE_GROUP)) {
		REDEBUG("Can't find '%s', or it's not a group", fmt);
		talloc_free(vpt);
		return XLAT_ACTION_FAIL;
	}

	fr_pair_flatten(vp);

	talloc_free(vpt);

	return XLAT_ACTION_DONE;
}

/** Unflatten a given group.
 *
 *  This is a temporary function for migration purposes
 *
 * Example:
@verbatim
"%(unflatten:&request)"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_unflatten(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					  UNUSED xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *in)
{
	fr_pair_t		*vp;
	tmpl_t			*vpt;
	fr_value_box_t		*attr = fr_dlist_head(in);
	char const		*fmt;

	fmt = attr->vb_strvalue;
	if (tmpl_afrom_attr_str(request, NULL, &vpt, fmt,
				&(tmpl_rules_t){
					.attr = {
						.dict_def = request->dict,
						.prefix = TMPL_ATTR_REF_PREFIX_AUTO
					}
				}) <= 0) {
		RPEDEBUG("Invalid input");
		return XLAT_ACTION_FAIL;
	}

	if ((tmpl_find_vp(&vp, request, vpt) < 0) ||
	    (vp->da->type != FR_TYPE_GROUP)) {
		REDEBUG("Can't find '%s', or it's not a group", fmt);
		talloc_free(vpt);
		return XLAT_ACTION_FAIL;
	}

	fr_pair_unflatten(vp);

	talloc_free(vpt);

	return XLAT_ACTION_DONE;
}

static xlat_action_t xlat_func_untaint(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t *vb;

	fr_value_box_list_untaint(in);
	while ((vb = fr_dlist_pop_head(in)) != NULL) {
		fr_dcursor_append(out, vb);
	}

	return XLAT_ACTION_DONE;
}

static xlat_action_t xlat_func_taint(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				     UNUSED xlat_ctx_t const *xctx,
				     UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t *vb;

	fr_value_box_list_taint(in);
	while ((vb = fr_dlist_pop_head(in)) != NULL) {
		fr_dcursor_append(out, vb);
	}

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_explode_args[] = {
	{ .required = true, .type = FR_TYPE_STRING },
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Split a string into multiple new strings based on a delimiter
 *
@verbatim
%(explode:<string> <delim>)
@endverbatim
 *
 * Example:
@verbatim
update request {
	&Tmp-String-1 := "a,b,c"
}
"%(concat:%(explode:%{Tmp-String-1} ,) |)" == "a|b|c"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_explode(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t		*strings = fr_dlist_head(in);
	fr_value_box_list_t	*list = &strings->vb_group;
	fr_value_box_t		*delim_vb = fr_dlist_next(in, strings);
	ssize_t			delim_len;
	char const		*delim;
	fr_value_box_t		*string, *vb;

	/* coverity[dereference] */
	if (delim_vb->vb_length == 0) {
		REDEBUG("Delimiter must be greater than zero characters");
		return XLAT_ACTION_FAIL;
	}

	delim = delim_vb->vb_strvalue;
	delim_len = delim_vb->vb_length;

	while((string = fr_dlist_pop_head(list))) {
		fr_sbuff_t		sbuff = FR_SBUFF_IN(string->vb_strvalue, string->vb_length);
		fr_sbuff_marker_t	m_start;

		/*
		 *	If the delimiter is not in the string, just move to the output
		 */
		if (!fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, delim, delim_len)) {
			fr_dcursor_append(out, string);
			continue;
		}

		fr_sbuff_set_to_start(&sbuff);
		fr_sbuff_marker(&m_start, &sbuff);

		while (fr_sbuff_remaining(&sbuff)) {
			if (fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, delim, delim_len)) {
				/*
				 *	If there's nothing before the delimiter skip
				 */
				if (fr_sbuff_behind(&m_start) == 0) goto advance;

				MEM(vb = fr_value_box_alloc_null(ctx));
				fr_value_box_bstrndup(ctx, vb, NULL, fr_sbuff_current(&m_start),
						      fr_sbuff_behind(&m_start), string->tainted);
				fr_dcursor_append(out, vb);

			advance:
				fr_sbuff_advance(&sbuff, delim_len);
				fr_sbuff_set(&m_start, &sbuff);
				continue;
			}
			fr_sbuff_set_to_end(&sbuff);
			MEM(vb = fr_value_box_alloc_null(ctx));
			fr_value_box_bstrndup(ctx, vb, NULL, fr_sbuff_current(&m_start),
					      fr_sbuff_behind(&m_start), string->tainted);
			fr_dcursor_append(out, vb);
			break;
		}
		talloc_free(string);
	}

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_integer_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Print data as integer, not as VALUE.
 *
 * Example:
@verbatim
update request {
	&Tmp-IP-Address-0 := "127.0.0.5"
}
"%(integer:%{Tmp-IP-Address-0})" == 2130706437
@endverbatim
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_integer(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*in_vb = fr_dlist_head(in);
	char const *p;

	fr_strerror_clear(); /* Make sure we don't print old errors */

	fr_dlist_remove(in, in_vb);

	switch (in_vb->type) {
	default:
	error:
		RPEDEBUG("Failed converting %pV (%s) to an integer", in_vb,
			 fr_type_to_str(in_vb->type));
		talloc_free(in_vb);
		return XLAT_ACTION_FAIL;

	case FR_TYPE_NUMERIC:
		/*
		 *	Ensure enumeration is NULL so that the integer
		 *	version of a box is returned
		 */
		in_vb->enumv = NULL;

		/*
		 *	FR_TYPE_DATE and FR_TYPE_DELTA need to be cast
		 *	to int64_t so that they're printed in a
		 *	numeric format.
		 */
		if ((in_vb->type == FR_TYPE_DATE) || (in_vb->type == FR_TYPE_TIME_DELTA)) {
			if (fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_INT64, NULL) < 0) goto error;
		}
		break;

	case FR_TYPE_STRING:
		/*
		 *	Strings are always zero terminated.  They may
		 *	also have zeros in the middle, but if that
		 *	happens, the caller will only get the part up
		 *	to the first zero.
		 *
		 *	We check for negative numbers, just to be
		 *	nice.
		 */
		for (p = in_vb->vb_strvalue; *p != '\0'; p++) {
			if (*p == '-') break;
		}

		if (*p == '-') {
			if (fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_INT64, NULL) < 0) goto error;
		} else {
			if (fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_UINT64, NULL) < 0) goto error;
		}
		break;

	case FR_TYPE_OCTETS:
		if (in_vb->vb_length > sizeof(uint64_t)) {
			fr_strerror_printf("Expected octets length <= %zu, got %zu", sizeof(uint64_t), in_vb->vb_length);
			goto error;
		}

		if (in_vb->vb_length > sizeof(uint32_t)) {
			fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_UINT64, NULL);
		} else if (in_vb->vb_length > sizeof(uint16_t)) {
			fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_UINT32, NULL);
		} else if (in_vb->vb_length > sizeof(uint8_t)) {
			fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_UINT16, NULL);
		} else {
			fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_UINT8, NULL);
		}

		break;

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
		if (fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_UINT32, NULL) < 0) goto error;
		break;

	case FR_TYPE_ETHERNET:
		if (fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_UINT64, NULL) < 0) goto error;
		break;

	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
	{
		uint128_t	ipv6int;
		char		buff[40];
		fr_value_box_t	*vb;

		/*
		 *	Needed for correct alignment (as flagged by ubsan)
		 */
		memcpy(&ipv6int, &in_vb->vb_ip.addr.v6.s6_addr, sizeof(ipv6int));

		fr_snprint_uint128(buff, sizeof(buff), ntohlll(ipv6int));

		MEM(vb = fr_value_box_alloc_null(ctx));
		fr_value_box_bstrndup(ctx, vb, NULL, buff, strlen(buff), false);
		fr_dcursor_append(out, vb);
		talloc_free(in_vb);
		return XLAT_ACTION_DONE;
	}
	}

	fr_dcursor_append(out, in_vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_map_arg = {
	.required = true,
	.concat = true,
	.type = FR_TYPE_STRING
};

/** Processes fmt as a map string and applies it to the current request
 *
 * e.g.
@verbatim
%{map:&User-Name := 'foo'}
@endverbatim
 *
 * Allows sets of modifications to be cached and then applied.
 * Useful for processing generic attributes from LDAP.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_map(TALLOC_CTX *ctx, fr_dcursor_t *out,
				   UNUSED xlat_ctx_t const *xctx,
				   request_t *request, fr_value_box_list_t *in)
{
	map_t		*map = NULL;
	int		ret;
	fr_value_box_t	*fmt_vb = fr_dlist_head(in);
	fr_value_box_t	*vb;

	tmpl_rules_t	attr_rules = {
		.attr = {
			.dict_def = request->dict,
			.prefix = TMPL_ATTR_REF_PREFIX_AUTO
		}
	};

	if (map_afrom_attr_str(request, &map, fmt_vb->vb_strvalue, &attr_rules, &attr_rules) < 0) {
		RPEDEBUG("Failed parsing \"%s\" as map", fmt_vb->vb_strvalue);
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_INT8, NULL, false));
	vb->vb_int8 = 0;	/* Default fail value - changed to 1 on success */
	fr_dcursor_append(out, vb);

	switch (map->lhs->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_XLAT:
		break;

	default:
		REDEBUG("Unexpected type %s in left hand side of expression",
			tmpl_type_to_str(map->lhs->type));
		return XLAT_ACTION_FAIL;
	}

	switch (map->rhs->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_DATA:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:
	case TMPL_TYPE_UNRESOLVED:
	case TMPL_TYPE_XLAT:
		break;

	default:
		REDEBUG("Unexpected type %s in right hand side of expression",
			tmpl_type_to_str(map->rhs->type));
		return XLAT_ACTION_FAIL;
	}

	RINDENT();
	ret = map_to_request(request, map, map_to_vp, NULL);
	REXDENT();
	talloc_free(map);
	if (ret < 0) return XLAT_ACTION_FAIL;

	vb->vb_int8 = 1;
	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const xlat_func_next_time_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Calculate number of seconds until the next n hour(s), day(s), week(s), year(s).
 *
 * For example, if it were 16:18 %(nexttime:1h) would expand to 2520.
 *
 * The envisaged usage for this function is to limit sessions so that they don't
 * cross billing periods. The output of the xlat should be combined with %{rand:} to create
 * some jitter, unless the desired effect is every subscriber on the network
 * re-authenticating at the same time.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_next_time(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 UNUSED xlat_ctx_t const *xctx,
					 request_t *request, fr_value_box_list_t *in)
{
	long		num;

	char const	*p;
	char		*q;
	time_t		now;
	struct tm	*local, local_buff;
	fr_value_box_t	*in_head = fr_dlist_head(in);
	fr_value_box_t	*vb;

	/*
	 *	We want to limit based on _now_, not on when they logged in.
	 */
	now = time(NULL);
	local = localtime_r(&now, &local_buff);

	p = in_head->vb_strvalue;

	num = strtoul(p, &q, 10);
	if (!q || *q == '\0') {
		REDEBUG("nexttime: <int> must be followed by period specifier (h|d|w|m|y)");
		return XLAT_ACTION_FAIL;
	}

	if (p == q) {
		num = 1;
	} else {
		p += q - p;
	}

	local->tm_sec = 0;
	local->tm_min = 0;

	switch (*p) {
	case 'h':
		local->tm_hour += num;
		break;

	case 'd':
		local->tm_hour = 0;
		local->tm_mday += num;
		break;

	case 'w':
		local->tm_hour = 0;
		local->tm_mday += (7 - local->tm_wday) + (7 * (num-1));
		break;

	case 'm':
		local->tm_hour = 0;
		local->tm_mday = 1;
		local->tm_mon += num;
		break;

	case 'y':
		local->tm_hour = 0;
		local->tm_mday = 1;
		local->tm_mon = 0;
		local->tm_year += num;
		break;

	default:
		REDEBUG("nexttime: Invalid period specifier '%c', must be h|d|w|m|y", *p);
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_uint64(vb, NULL, (uint64_t)(mktime(local) - now), false);
	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

typedef struct {
	bool		last_success;
	xlat_exp_head_t	*ex;
} xlat_eval_rctx_t;

/** Just serves to push the result up the stack
 *
 */
static xlat_action_t xlat_eval_resume(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
				      xlat_ctx_t const *xctx,
				      UNUSED request_t *request, UNUSED fr_value_box_list_t *in)
{
	xlat_eval_rctx_t	*rctx = talloc_get_type_abort(xctx->rctx, xlat_eval_rctx_t);
	xlat_action_t		xa = rctx->last_success ? XLAT_ACTION_DONE : XLAT_ACTION_FAIL;

	talloc_free(rctx);

	return xa;
}

static xlat_arg_parser_t const xlat_func_eval_arg = {
	.required = true,
	.concat = true,
	.type = FR_TYPE_STRING
};

/** Dynamically evaluate an expansion string
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_eval(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    request_t *request, fr_value_box_list_t *in)
{
	xlat_eval_rctx_t	*rctx;
	fr_value_box_t		*arg = fr_dlist_head(in);

	/*
	 *	These are escaping rules applied to the
	 *	input string. They're mostly here to
	 *	allow \% and \\ to work.
	 *
	 *	Everything else should be passed in as
	 *	unescaped data.
	 */
	static fr_sbuff_unescape_rules_t const escape_rules = {
		.name = "xlat",
		.chr = '\\',
		.subs = {
			['%'] = '%',
			['\\'] = '\\',
		},
		.do_hex = false,
		.do_oct = false
	};

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), xlat_eval_rctx_t));

	/*
	 *	Parse the input as a literal expansion
	 */
	if (xlat_tokenize_ephemeral(rctx,
				    &rctx->ex, unlang_interpret_event_list(request),
				    &FR_SBUFF_IN(arg->vb_strvalue, arg->vb_length),
				    &(fr_sbuff_parse_rules_t){
					    .escapes = &escape_rules
				    },
				    &(tmpl_rules_t){
					    .attr = {
						.allow_unknown = false,
						.allow_unresolved = false,
						.allow_foreign = false,
						.dict_def = request->dict
					},
					.at_runtime = true
				    }) < 0) {
		RPEDEBUG("Failed parsing expansion");
	error:
		talloc_free(rctx);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Call the resolution function so we produce
	 *	good errors about what function was
	 *	unresolved.
	 */
	if (rctx->ex->flags.needs_resolving &&
	    (xlat_resolve(rctx->ex, &(xlat_res_rules_t){ .allow_unresolved = false }) < 0)) {
		RPEDEBUG("Unresolved expansion functions in expansion");
		goto error;

	}

	if (unlang_xlat_yield(request, xlat_eval_resume, NULL, rctx) != XLAT_ACTION_YIELD) goto error;

	if (unlang_xlat_push(ctx, &rctx->last_success, out->dlist,
			     request, rctx->ex, UNLANG_SUB_FRAME) < 0) goto error;

	return XLAT_ACTION_PUSH_UNLANG;
}

/** Dynamically evaluate an expression string
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_expr(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    request_t *request, fr_value_box_list_t *in)
{
	xlat_eval_rctx_t	*rctx;
	fr_value_box_t		*arg = fr_dlist_head(in);

	/*
	 *	These are escaping rules applied to the
	 *	input string. They're mostly here to
	 *	allow \% and \\ to work.
	 *
	 *	Everything else should be passed in as
	 *	unescaped data.
	 */
	static fr_sbuff_unescape_rules_t const escape_rules = {
		.name = "xlat",
		.chr = '\\',
		.subs = {
			['%'] = '%',
			['\\'] = '\\',
		},
		.do_hex = false,
		.do_oct = false
	};

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), xlat_eval_rctx_t));

	/*
	 *	Parse the input as an expression.
	 */
	if (xlat_tokenize_ephemeral_expression(rctx,
				    &rctx->ex, unlang_interpret_event_list(request),
				    &FR_SBUFF_IN(arg->vb_strvalue, arg->vb_length),
				    &(fr_sbuff_parse_rules_t){
				    	.escapes = &escape_rules
				    },
				    &(tmpl_rules_t){
				    	.attr = {
						.allow_unknown = false,
						.allow_unresolved = false,
						.allow_foreign = false,
						.dict_def = request->dict
					},
					.at_runtime = true
				    }) < 0) {
		RPEDEBUG("Failed parsing expansion");
	error:
		talloc_free(rctx);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Call the resolution function so we produce
	 *	good errors about what function was
	 *	unresolved.
	 */
	if (rctx->ex->flags.needs_resolving &&
	    (xlat_resolve(rctx->ex, &(xlat_res_rules_t){ .allow_unresolved = false }) < 0)) {
		RPEDEBUG("Unresolved expansion functions in expansion");
		goto error;

	}

	if (unlang_xlat_yield(request, xlat_eval_resume, NULL, rctx) != XLAT_ACTION_YIELD) goto error;

	if (unlang_xlat_push(ctx, &rctx->last_success, out->dlist,
			     request, rctx->ex, UNLANG_SUB_FRAME) < 0) goto error;

	return XLAT_ACTION_PUSH_UNLANG;
}

static xlat_arg_parser_t const xlat_func_pad_args[] = {
	{ .required = true, .type = FR_TYPE_STRING },
	{ .required = true, .single = true, .type = FR_TYPE_UINT64 },
	{ .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** lpad a string
 *
@verbatim
%(rpad:&Attribute-Name <length> [<fill>])
@endverbatim
 *
 * Example: (User-Name = "foo")
@verbatim
"%(rpad:%{User-Name} 5 x)" == "xxfoo"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_lpad(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t		*values = fr_dlist_head(args);
	fr_value_box_list_t	*list = &values->vb_group;
	fr_value_box_t		*pad = fr_dlist_next(args, values);
	/* coverity[dereference] */
	size_t			pad_len = (size_t)pad->vb_uint64;
	/* coverity[dereference] */
	fr_value_box_t		*fill = fr_dlist_next(args, pad);
	char const		*fill_str = NULL;
	size_t			fill_len = 0;

	fr_value_box_t		*in = NULL;

	/*
	 *	Fill is optional
	 */
	if (fill) {
		fill_str = fill->vb_strvalue;
		fill_len = talloc_array_length(fill_str) - 1;
	}

	if (fill_len == 0) {
		fill_str = " ";
		fill_len = 1;
	}

	while ((in = fr_dlist_pop_head(list))) {
		size_t			len = talloc_array_length(in->vb_strvalue) - 1;
		size_t			remaining;
		char			*buff;
		fr_sbuff_t		sbuff;
		fr_sbuff_marker_t	m_data;

		fr_dcursor_append(out, in);

		if (len >= pad_len) continue;

		if (fr_value_box_bstr_realloc(in, &buff, in, pad_len) < 0) {
			RPEDEBUG("Failed reallocing input data");
			return XLAT_ACTION_FAIL;
		}

		fr_sbuff_init_in(&sbuff, buff, pad_len);
		fr_sbuff_marker(&m_data, &sbuff);

		/*
		 *	...nothing to move if the input
		 *	string is empty.
		 */
		if (len > 0) {
			fr_sbuff_advance(&m_data, pad_len - len);	/* Mark where we want the data to go */
			fr_sbuff_move(&FR_SBUFF(&m_data), &FR_SBUFF(&sbuff), len); /* Shift the data */
		}

		if (fill_len == 1) {
			memset(fr_sbuff_current(&sbuff), *fill_str, fr_sbuff_ahead(&m_data));
			continue;
		}

		/*
		 *	Copy fill as a repeating pattern
		 */
		while ((remaining = fr_sbuff_ahead(&m_data))) {
			size_t to_copy = remaining >= fill_len ? fill_len : remaining;
			memcpy(fr_sbuff_current(&sbuff), fill_str, to_copy);	/* avoid \0 termination */
			fr_sbuff_advance(&sbuff, to_copy);
		}
		fr_sbuff_set_to_end(&sbuff);
		fr_sbuff_terminate(&sbuff);			/* Move doesn't re-terminate */
	}

	return XLAT_ACTION_DONE;
}

/** Right pad a string
 *
@verbatim
%(rpad:&Attribute-Name <length> [<fill>])
@endverbatim
 *
 * Example: (User-Name = "foo")
@verbatim
"%(rpad:%{User-Name} 5 x)" == "fooxx"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_rpad(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t		*values = fr_dlist_head(args);
	fr_value_box_list_t	*list = &values->vb_group;
	fr_value_box_t		*pad = fr_dlist_next(args, values);
	/* coverity[dereference] */
	size_t			pad_len = (size_t)pad->vb_uint64;
	fr_value_box_t		*fill = fr_dlist_next(args, pad);
	char const		*fill_str = NULL;
	size_t			fill_len = 0;

	fr_value_box_t		*in = NULL;

	/*
	 *	Fill is optional
	 */
	if (fill) {
		fill_str = fill->vb_strvalue;
		fill_len = talloc_array_length(fill_str) - 1;
	}

	if (fill_len == 0) {
		fill_str = " ";
		fill_len = 1;
	}

	while ((in = fr_dlist_pop_head(list))) {
		size_t		len = talloc_array_length(in->vb_strvalue) - 1;
		size_t		remaining;
		char		*buff;
		fr_sbuff_t	sbuff;

		fr_dcursor_append(out, in);

		if (len >= pad_len) continue;

		if (fr_value_box_bstr_realloc(in, &buff, in, pad_len) < 0) {
		fail:
			RPEDEBUG("Failed reallocing input data");
			return XLAT_ACTION_FAIL;
		}

		fr_sbuff_init_in(&sbuff, buff, pad_len);
		fr_sbuff_advance(&sbuff, len);

		if (fill_len == 1) {
			memset(fr_sbuff_current(&sbuff), *fill_str, fr_sbuff_remaining(&sbuff));
			continue;
		}

		/*
		 *	Copy fill as a repeating pattern
		 */
		while ((remaining = fr_sbuff_remaining(&sbuff))) {
			if (fr_sbuff_in_bstrncpy(&sbuff, fill_str, remaining >= fill_len ? fill_len : remaining) < 0) {
				goto fail;
			}
		}
	}

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_base64_encode_arg = {
	.required = true,
	.concat = true,
	.type = FR_TYPE_OCTETS
};

/** Encode string or attribute as base64
 *
 * Example:
@verbatim
"%{base64:foo}" == "Zm9v"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_base64_encode(TALLOC_CTX *ctx, fr_dcursor_t *out,
					     UNUSED xlat_ctx_t const *xctx,
					     request_t *request, fr_value_box_list_t *args)
{
	size_t		alen;
	ssize_t		elen;
	char		*buff;
	fr_value_box_t	*vb;
	fr_value_box_t	*in = fr_dlist_head(args);

	alen = FR_BASE64_ENC_LENGTH(in->vb_length);

	MEM(vb = fr_value_box_alloc_null(ctx));
	if (fr_value_box_bstr_alloc(vb, &buff, vb, NULL, alen, false) < 0) {
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	elen = fr_base64_encode(&FR_SBUFF_OUT(buff, talloc_array_length(buff)),
				&FR_DBUFF_TMP(in->vb_octets, in->vb_length), true);
	if (elen < 0) {
		RPEDEBUG("Base64 encoding failed");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}
	fr_assert((size_t)elen <= alen);
	vb->tainted = in->tainted;
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_base64_decode_arg = {
	.required = true,
	.concat = true,
	.type = FR_TYPE_OCTETS
};

/** Decode base64 string
 *
 * Example:
@verbatim
"%{base64decode:Zm9v}" == "foo"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_base64_decode(TALLOC_CTX *ctx, fr_dcursor_t *out,
					     UNUSED xlat_ctx_t const *xctx,
					     request_t *request, fr_value_box_list_t *args)
{
	size_t		alen;
	ssize_t		declen = 0;
	uint8_t		*decbuf;
	fr_value_box_t	*vb;
	fr_value_box_t	*in = fr_dlist_head(args);

	alen = FR_BASE64_DEC_LENGTH(in->vb_length);
	MEM(vb = fr_value_box_alloc_null(ctx));
	if (alen > 0) {
		MEM(fr_value_box_mem_alloc(vb, &decbuf, vb, NULL, alen, in->tainted) == 0);
		declen = fr_base64_decode(&FR_DBUFF_TMP(decbuf, alen),
					  &FR_SBUFF_IN(in->vb_strvalue, in->vb_length), true, true);
		if (declen < 0) {
			RPEDEBUG("Base64 string invalid");
			talloc_free(vb);
			return XLAT_ACTION_FAIL;
		}

		MEM(fr_value_box_mem_realloc(vb, NULL, vb, declen) == 0);
	}

	vb->tainted = in->tainted;
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_bin_arg = {
	.required = true,
	.concat = true,
	.type = FR_TYPE_STRING
};

/** Convert hex string to binary
 *
 * Example:
@verbatim
"%{bin:666f6f626172}" == "foobar"
@endverbatim
 *
 * @see #xlat_func_hex
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_bin(TALLOC_CTX *ctx, fr_dcursor_t *out,
				   UNUSED xlat_ctx_t const *xctx,
				   request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t		*result;
	char const		*p, *end;
	uint8_t			*bin;
	size_t			len, outlen;
	fr_sbuff_parse_error_t	err;
	fr_value_box_t		*hex;

	hex = fr_dlist_head(in);
	len = hex->vb_length;
	if ((len > 1) && (len & 0x01)) {
		REDEBUG("Input data length must be >1 and even, got %zu", len);
		return XLAT_ACTION_FAIL;
	}

	p = hex->vb_strvalue;
	end = p + len;

	/*
	 *	Look for 0x at the start of the string
	 */
	if ((p[0] == '0') && (p[1] == 'x')) {
		p += 2;
		len -=2;
	}

	/*
	 *	Zero length octets string
	 */
	if (p == end) goto finish;

	outlen = len / 2;

	MEM(result = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_mem_alloc(result, &bin, result, NULL, outlen, fr_value_box_list_tainted(in)) == 0);
	fr_base16_decode(&err, &FR_DBUFF_TMP(bin, outlen), &FR_SBUFF_IN(p, end - p), true);
	if (err) {
		REDEBUG2("Invalid hex string");
		talloc_free(result);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, result);

finish:
	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_cast_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_VOID },
	{ .required = true, .variadic = true, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Cast one or more output value-boxes to the given type
 *
 * First argument of is type to cast to.
 *
 * Example:
@verbatim
%(cast:string %{request[*]}) results in all of the input boxes being cast to string/
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_cast(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*name = fr_dlist_head(in);
	fr_value_box_t	*arg;
	fr_type_t	type;

	/*
	 *	Get the type, which can be in one of a few formats.
	 */
	if (fr_type_is_numeric(name->type)) {
		if (fr_value_box_cast_in_place(name, name, FR_TYPE_UINT8, NULL) < 0) {
			RPEDEBUG("Failed parsing '%pV' as a numerical data type", name);
			return XLAT_ACTION_FAIL;
		}
		type = name->vb_uint8;

	} else {
		if (name->type != FR_TYPE_STRING) {
			if (fr_value_box_cast_in_place(name, name, FR_TYPE_STRING, NULL) < 0) {
				RPEDEBUG("Failed parsing '%pV' as a string data type", name);
				return XLAT_ACTION_FAIL;
			}
		}

		type = fr_table_value_by_str(fr_type_table, name->vb_strvalue, FR_TYPE_NULL);
		if (type == FR_TYPE_NULL) {
			RDEBUG("Unknown data type '%s'", name->vb_strvalue);
			return XLAT_ACTION_FAIL;
		}
	}

	/*
	 *	Cast to string means *print* to string.
	 */
	if (type == FR_TYPE_STRING) {
		fr_sbuff_t *agg;
		fr_value_box_t *dst;

		(void) fr_dlist_pop_head(in);
		talloc_free(name);

		FR_SBUFF_TALLOC_THREAD_LOCAL(&agg, 256, 8192);

		MEM(dst = fr_value_box_alloc_null(ctx));
		if (fr_value_box_list_concat_as_string(NULL, agg, in, NULL, 0, &fr_value_escape_double,
						       FR_VALUE_BOX_LIST_FREE_BOX, true, true) < 0) {
			RPEDEBUG("Failed concatenating string");
			return XLAT_ACTION_FAIL;
		}

		fr_value_box_bstrndup(dst, dst, NULL, fr_sbuff_start(agg), fr_sbuff_used(agg), false);
		fr_dcursor_append(out, dst);

		return XLAT_ACTION_DONE;
	}

	/*
	 *	Copy inputs to outputs, casting them along the way.
	 */
	arg = name;
	while ((arg = fr_dlist_next(in, arg)) != NULL) {
		fr_value_box_t	*vb, *p;

		fr_assert(arg->type == FR_TYPE_GROUP);

		vb = fr_dlist_head(&arg->vb_group);
		while (vb) {
			p = fr_dlist_remove(&arg->vb_group, vb);

			if (fr_value_box_cast_in_place(vb, vb, type, NULL) < 0) {
				RPEDEBUG("Failed casting %pV to data type '%s'", vb, fr_type_to_str(type));
				return XLAT_ACTION_FAIL;
			}
			fr_dcursor_append(out, vb);
			vb = fr_dlist_next(&arg->vb_group, p);
		}
	}

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_concat_args[] = {
	{ .required = true, .type = FR_TYPE_VOID },
	{ .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Concatenate string representation of values of given attributes using separator
 *
 * First argument of is the list of attributes to concatenate, followed
 * by an optional separator
 *
 * Example:
@verbatim
"%(concat:%{request[*]} ,)" == "<attr1value>,<attr2value>,<attr3value>,..."
"%(concat:%{Tmp-String-0[*]} '. ')" == "<str1value>. <str2value>. <str3value>. ..."
"%(concat:%(join:%{User-Name} %{Calling-Station-Id}) ', ')" == "bob, aa:bb:cc:dd:ee:ff"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_concat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      UNUSED xlat_ctx_t const *xctx,
				      request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*result;
	fr_value_box_t	*list = fr_dlist_head(in);
	fr_value_box_t	*separator = fr_dlist_next(in, list);
	char		*buff;
	char const	*sep;

	sep = (separator) ? separator->vb_strvalue : "";

	result = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false);
	if (!result) {
	error:
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	buff = fr_value_box_list_aprint(result, &list->vb_group, sep, NULL);
	if (!buff) goto error;

	fr_value_box_bstrdup_buffer_shallow(NULL, result, NULL, buff, fr_value_box_list_tainted(in));

	fr_dcursor_append(out, result);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_hex_arg = {
	.required = true,
	.concat = true,
	.type = FR_TYPE_OCTETS
};

/** Print data as hex, not as VALUE.
 *
 * Example:
@verbatim
"%{hex:foobar}" == "666f6f626172"
@endverbatim
 *
 * @see #xlat_func_bin
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_hex(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				   UNUSED xlat_ctx_t const *xctx,
				   UNUSED request_t *request, fr_value_box_list_t *in)
{
	char		*new_buff;
	fr_value_box_t	*bin = fr_dlist_pop_head(in);	/* First argument */

	/*
	 *	Use existing box, but with new buffer
	 */
	MEM(new_buff = talloc_zero_array(bin, char, (bin->vb_length * 2) + 1));
	if (bin->vb_length) {
		fr_base16_encode(&FR_SBUFF_OUT(new_buff, (bin->vb_length * 2) + 1),
					       &FR_DBUFF_TMP(bin->vb_octets, bin->vb_length));
		fr_value_box_clear_value(bin);
		fr_value_box_strdup_shallow(bin, NULL, new_buff, bin->tainted);
	/*
	 *	Zero length binary > zero length hex string
	 */
	} else {
		fr_value_box_clear_value(bin);
		fr_value_box_strdup(bin, bin, NULL, "", bin->tainted);
	}
	fr_dcursor_append(out, bin);

	return XLAT_ACTION_DONE;
}

typedef enum {
	HMAC_MD5,
	HMAC_SHA1
} hmac_type;

static xlat_action_t xlat_hmac(TALLOC_CTX *ctx, fr_dcursor_t *out,
				fr_value_box_list_t *in, uint8_t *digest, int digest_len, hmac_type type)
{
	fr_value_box_t	*vb, *data, *key;

	data = fr_dlist_head(in);
	key = fr_dlist_next(in, data);

	if (type == HMAC_MD5) {
		/* coverity[dereference] */
		fr_hmac_md5(digest, data->vb_octets, data->vb_length, key->vb_octets, key->vb_length);
	} else if (type == HMAC_SHA1) {
		/* coverity[dereference] */
		fr_hmac_sha1(digest, data->vb_octets, data->vb_length, key->vb_octets, key->vb_length);
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, digest_len, false);

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_hmac_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Generate the HMAC-MD5 of a string or attribute
 *
 * Example:
@verbatim
"%(hmacmd5:%{string:foo} %{string:bar})" == "0x31b6db9e5eb4addb42f1a6ca07367adc"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_hmac_md5(TALLOC_CTX *ctx, fr_dcursor_t *out,
					UNUSED xlat_ctx_t const *xctx,
					UNUSED request_t *request, fr_value_box_list_t *in)
{
	uint8_t		digest[MD5_DIGEST_LENGTH];
	return xlat_hmac(ctx, out, in, digest, MD5_DIGEST_LENGTH, HMAC_MD5);
}


/** Generate the HMAC-SHA1 of a string or attribute
 *
 * Example:
@verbatim
"%(hmacsha1:%{string:foo} %{string:bar})" == "0x85d155c55ed286a300bd1cf124de08d87e914f3a"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_hmac_sha1(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 UNUSED xlat_ctx_t const *xctx,
					 UNUSED request_t *request, fr_value_box_list_t *in)
{
	uint8_t		digest[SHA1_DIGEST_LENGTH];
	return xlat_hmac(ctx, out, in, digest, SHA1_DIGEST_LENGTH, HMAC_SHA1);
}

static xlat_arg_parser_t const xlat_func_join_args[] = {
	{ .required = true, .variadic = true, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Join a series of arguments to form a single list
 *
 */
static xlat_action_t xlat_func_join(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*arg = NULL, *vb, *p;

	while ((arg = fr_dlist_next(in, arg))) {
		fr_assert(arg->type == FR_TYPE_GROUP);
		vb = fr_dlist_head(&arg->vb_group);
		while (vb) {
			p = fr_dlist_remove(&arg->vb_group, vb);
			fr_dcursor_append(out, vb);
			vb = fr_dlist_next(&arg->vb_group, p);
		}
	}
	return XLAT_ACTION_DONE;
}

static void ungroup(fr_dcursor_t *out, fr_value_box_list_t *in)
{
	fr_value_box_t *vb;

	while ((vb = fr_dlist_pop_head(in)) != NULL) {
		if (vb->type != FR_TYPE_GROUP) {
			fr_dcursor_append(out, vb);
			continue;
		}
		talloc_free(vb);
	}
}

/** Ungroups all of its arguments into one flat list.
 *
 */
static xlat_action_t xlat_func_ungroup(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*arg = NULL;

	while ((arg = fr_dlist_next(in, arg)) != NULL) {
		fr_assert(arg->type == FR_TYPE_GROUP);

		ungroup(out, &arg->vb_group);
	}
	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_length_args[] = {
	{ .single = true, .variadic = true, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Return the on-the-wire size of the boxes in bytes
 *
 * Example:
@verbatim
"%(length:foobar)" == 6
"%(length:%{bin:0102030005060708})" == 8
@endverbatim
 *
 * @see #xlat_func_strlen
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_length(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      UNUSED xlat_ctx_t const *xctx,
				      UNUSED request_t *request, fr_value_box_list_t *in)

{
	fr_value_box_t	*vb = NULL;

	while ((vb = fr_dlist_next(in, vb))) {
		fr_value_box_t *my;

		MEM(my = fr_value_box_alloc(ctx, FR_TYPE_SIZE, NULL, false));
		my->vb_size = fr_value_box_network_length(vb);
		fr_dcursor_append(out, my);
	}

	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const xlat_func_md4_arg = {
	.concat = true,
	.type = FR_TYPE_OCTETS
};

/** Calculate the MD4 hash of a string or attribute.
 *
 * Example:
@verbatim
"%{md4:foo}" == "0ac6700c491d70fb8650940b1ca1e4b2"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_md4(TALLOC_CTX *ctx, fr_dcursor_t *out,
				   UNUSED xlat_ctx_t const *xctx,
				   UNUSED request_t *request, fr_value_box_list_t *in)
{
	uint8_t		digest[MD5_DIGEST_LENGTH];
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head = fr_dlist_head(in);

	if (in_head) {
		fr_md4_calc(digest, in_head->vb_octets, in_head->vb_length);
	} else {
		/* Digest of empty string */
		fr_md4_calc(digest, NULL, 0);
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, sizeof(digest), false);

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_md5_arg = {
	.concat = true,
	.type = FR_TYPE_OCTETS
};

/** Calculate the MD5 hash of a string or attribute.
 *
 * Example:
@verbatim
"%{md5:foo}" == "acbd18db4cc2f85cedef654fccc4a4d8"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_md5(TALLOC_CTX *ctx, fr_dcursor_t *out,
				   UNUSED xlat_ctx_t const *xctx,
				   UNUSED request_t *request, fr_value_box_list_t *in)
{
	uint8_t		digest[MD5_DIGEST_LENGTH];
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head = fr_dlist_head(in);

	if (in_head) {
		fr_md5_calc(digest, in_head->vb_octets, in_head->vb_length);
	} else {
		/* Digest of empty string */
		fr_md5_calc(digest, NULL, 0);
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, sizeof(digest), false);

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Prints the name of the current module processing the request
 *
 * For example will expand to "echo" (not "exec") in
@verbatim
exec echo {
  ...
  program = "/bin/echo %{module:}"
  ...
}
@endverbatim
 *
 * Example:
@verbatim
"%{module:}" == "" (outside a module)
"%{module:}" == "ldap" (in the ldap module)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_module(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      UNUSED xlat_ctx_t const *xctx,
				      request_t *request, UNUSED fr_value_box_list_t *in)
{
	fr_value_box_t	*vb = NULL;

	/*
	 *	Don't do anything if we're outside of a module
	 */
	if (!request->module || !*request->module) return XLAT_ACTION_DONE;

	MEM(vb = fr_value_box_alloc_null(ctx));
	if (fr_value_box_strdup(vb, vb, NULL, request->module, false) < 0) {
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_pack_arg = {
	.required = true,
	.concat = true,
	.type = FR_TYPE_OCTETS
};

/** Pack multiple things together
 *
 * Example:
@verbatim
"%{pack:%{Attr-Foo}%{Attr-bar}" == packed hex values of the attributes
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_pack(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*vb;

	/*
	 *	Input boxes are already cast to FR_TYPE_OCTETS and concatenated
	 *	by the input argument parser - so simply move to the output
	 */
	vb = fr_dlist_pop_head(in);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const xlat_func_pairs_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Encode attributes as a series of string attribute/value pairs
 *
 * This is intended to serialize one or more attributes as a comma
 * delimited string.
 *
 * Example:
@verbatim
"%(pairs:request[*])" == "User-Name = 'foo'User-Password = 'bar'"
"%{concat:, %(pairs:request[*])}" == "User-Name = 'foo', User-Password = 'bar'"
@endverbatim
 *
 * @see #xlat_func_concat
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_pairs(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     UNUSED xlat_ctx_t const *xctx,
				     request_t *request, fr_value_box_list_t *in)
{
	tmpl_t			*vpt = NULL;
	fr_dcursor_t		cursor;
	tmpl_dcursor_ctx_t	cc;
	fr_value_box_t		*vb;
	fr_value_box_t		*in_head = fr_dlist_head(in);

	fr_pair_t *vp;

	if (tmpl_afrom_attr_str(ctx, NULL, &vpt, in_head->vb_strvalue,
				&(tmpl_rules_t){
					.attr = {
						.dict_def = request->dict,
						.prefix = TMPL_ATTR_REF_PREFIX_AUTO
					}
				}) <= 0) {
		RPEDEBUG("Invalid input");
		return XLAT_ACTION_FAIL;
	}

	for (vp = tmpl_dcursor_init(NULL, NULL, &cc, &cursor, request, vpt);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
		char *buff;

		MEM(vb = fr_value_box_alloc_null(ctx));
		if (unlikely(fr_pair_aprint(vb, &buff, NULL, vp) < 0)) {
			RPEDEBUG("Failed printing pair");
			talloc_free(vb);
			tmpl_dcursor_clear(&cc);
			return XLAT_ACTION_FAIL;
		}

		fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, buff, false);
		fr_dcursor_append(out, vb);
	}
	tmpl_dcursor_clear(&cc);
	talloc_free(vpt);

	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const xlat_func_rand_arg = {
	.required = true,
	.single = true,
	.type = FR_TYPE_UINT32
};

/** Generate a random integer value
 *
 * For "N = %{rand:MAX}", 0 <= N < MAX
 *
 * Example:
@verbatim
"%{rand:100}" == 42
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_rand(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    UNUSED request_t *request, fr_value_box_list_t *in)
{
	int64_t		result;
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head = fr_dlist_head(in);

	result = in_head->vb_uint32;

	/* Make sure it isn't too big */
	if (result > (1 << 30)) result = (1 << 30);

	result *= fr_rand();	/* 0..2^32-1 */
	result >>= 32;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL, false));
	vb->vb_uint64 = result;

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const xlat_func_randstr_arg = {
	.required = true,
	.concat = true,
	.type = FR_TYPE_STRING
};

/** Generate a string of random chars
 *
 * Build strings of random chars, useful for generating tokens and passcodes
 * Format similar to String::Random.
 *
 * Format characters may include the following, and may be
 * preceeded by a repetition count:
 * - "c"	lowercase letters
 * - "C" 	uppercase letters
 * - "n" 	numbers
 * - "a" 	alphanumeric
 * - "!" 	punctuation
 * - "." 	alphanumeric + punctuation
 * - "s" 	alphanumeric + "./"
 * - "o" 	characters suitable for OTP (easily confused removed)
 * - "b" 	binary data
 *
 * Example:
@verbatim
"%{randstr:CCCC!!cccnnn}" == "IPFL>{saf874"
"%{randstr:42o}" == "yHdupUwVbdHprKCJRYfGbaWzVwJwUXG9zPabdGAhM9"
"%{hex:%{randstr:bbbb}}" == "a9ce04f3"
"%{hex:%{randstr:8b}}" == "fe165529f9f66839"
@endverbatim
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_randstr(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *in)
{
	/*
	 *	Lookup tables for randstr char classes
	 */
	static char	randstr_punc[] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
	static char	randstr_salt[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmopqrstuvwxyz/.";

	/*
	 *	Characters humans rarely confuse. Reduces char set considerably
	 *	should only be used for things such as one time passwords.
	 */
	static char	randstr_otp[] = "469ACGHJKLMNPQRUVWXYabdfhijkprstuvwxyz";

	char const	*p, *start, *end;
	char		*endptr;
	char		*buff_p;
	unsigned int	result;
	unsigned int	reps;
	size_t		outlen = 0;
	fr_value_box_t*	vb;
	fr_value_box_t	*in_head = fr_dlist_head(in);

	/** Max repetitions of a single character class
	 *
	 */
#define REPETITION_MAX 1024

	start = p = in_head->vb_strvalue;
	end = p + in_head->vb_length;

	/*
	 *	Calculate size of output
	 */
	while (p < end) {
		/*
		 *	Repetition modifiers.
		 *
		 *	We limit it to REPETITION_MAX, because we don't want
		 *	utter stupidity.
		 */
		if (isdigit((int) *p)) {
			reps = strtol(p, &endptr, 10);
			if (reps > REPETITION_MAX) reps = REPETITION_MAX;
			outlen += reps;
			p = endptr;
		} else {
			outlen++;
		}
		p++;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_bstr_alloc(vb, &buff_p, vb, NULL, outlen, false) == 0);

	/* Reset p to start position */
	p = start;

	while (p < end) {
		size_t i;

		if (isdigit((int) *p)) {
			reps = strtol(p, &endptr, 10);
			if (reps > REPETITION_MAX) {
				reps = REPETITION_MAX;
				RMARKER(L_WARN, L_DBG_LVL_2, start, start - p,
					"Forcing repetition to %u", (unsigned int)REPETITION_MAX);
			}
			p = endptr;
		} else {
			reps = 1;
		}

		for (i = 0; i < reps; i++) {
			result = fr_rand();
			switch (*p) {
			/*
			 *  Lowercase letters
			 */
			case 'c':
				*buff_p++ = 'a' + (result % 26);
				break;

			/*
			 *  Uppercase letters
			 */
			case 'C':
				*buff_p++ = 'A' + (result % 26);
				break;

			/*
			 *  Numbers
			 */
			case 'n':
				*buff_p++ = '0' + (result % 10);
				break;

			/*
			 *  Alpha numeric
			 */
			case 'a':
				*buff_p++ = randstr_salt[result % (sizeof(randstr_salt) - 3)];
				break;

			/*
			 *  Punctuation
			 */
			case '!':
				*buff_p++ = randstr_punc[result % (sizeof(randstr_punc) - 1)];
				break;

			/*
			 *  Alpha numeric + punctuation
			 */
			case '.':
				*buff_p++ = '!' + (result % 95);
				break;

			/*
			 *  Alpha numeric + salt chars './'
			 */
			case 's':
				*buff_p++ = randstr_salt[result % (sizeof(randstr_salt) - 1)];
				break;

			/*
			 *  Chars suitable for One Time Password tokens.
			 *  Alpha numeric with easily confused char pairs removed.
			 */
			case 'o':
				*buff_p++ = randstr_otp[result % (sizeof(randstr_otp) - 1)];
				break;

			/*
			 *	Binary data - Copy between 1-4 bytes at a time
			 */
			case 'b':
			{
				size_t copy = (reps - i) > sizeof(result) ? sizeof(result) : reps - i;

				memcpy(buff_p, (uint8_t *)&result, copy);
				buff_p += copy;
				i += (copy - 1);	/* Loop +1 */
			}
				break;

			default:
				REDEBUG("Invalid character class '%c'", *p);
				talloc_free(vb);

				return XLAT_ACTION_FAIL;
			}
		}

		p++;
	}

	*buff_p++ = '\0';

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


#if defined(HAVE_REGEX_PCRE) || defined(HAVE_REGEX_PCRE2)
/** Get named subcapture value from previous regex
 *
 * Example:
@verbatim
if ("foo" =~ /^(?<name>.*)/) {
        noop
}
"%{regex:name}" == "foo"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_regex(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     UNUSED xlat_ctx_t const *xctx,
				     request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*in_head  = fr_dlist_head(in);
	/*
	 *	Return the complete capture if no other capture is specified
	 */
	if (!in_head) {
		fr_value_box_t	*vb;
		char		*p;

		MEM(vb = fr_value_box_alloc_null(ctx));
		if (regex_request_to_sub(vb, &p, request, 0) < 0) {
			REDEBUG2("No previous regex capture");
			talloc_free(vb);
			return XLAT_ACTION_FAIL;
		}

		fr_assert(p);
		fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, p, false);
		fr_dcursor_append(out, vb);

		return XLAT_ACTION_DONE;
	}

	switch (in_head->type) {
	/*
	 *	If the input is an integer value then get an
	 *	arbitrary subcapture index.
	 */
	case FR_TYPE_NUMERIC:
	{
		fr_value_box_t	idx;
		fr_value_box_t	*vb;
		char		*p;

		if (fr_dlist_next(in, in_head)) {
			REDEBUG("Only one subcapture argument allowed");
			return XLAT_ACTION_FAIL;
		}

		if (fr_value_box_cast(NULL, &idx, FR_TYPE_UINT32, NULL, in_head) < 0) {
			RPEDEBUG("Bad subcapture index");
			return XLAT_ACTION_FAIL;
		}

		MEM(vb = fr_value_box_alloc_null(ctx));
		if (regex_request_to_sub(vb, &p, request, idx.vb_uint32) < 0) {
			REDEBUG2("No previous numbered regex capture group");
			talloc_free(vb);
			return XLAT_ACTION_FAIL;
		}
		fr_assert(p);
		fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, p, false);
		fr_dcursor_append(out, vb);

		return XLAT_ACTION_DONE;
	}

	default:
	{
		fr_value_box_t	*vb;
		char		*p;

		/*
		 *	Concatenate all input
		 */
		if (fr_value_box_list_concat_in_place(ctx,
						      in_head, in, FR_TYPE_STRING,
						      FR_VALUE_BOX_LIST_FREE, true,
						      SIZE_MAX) < 0) {
			RPEDEBUG("Failed concatenating input");
			return XLAT_ACTION_FAIL;
		}

		MEM(vb = fr_value_box_alloc_null(ctx));
		if (regex_request_to_sub_named(vb, &p, request, in_head->vb_strvalue) < 0) {
			REDEBUG2("No previous named regex capture group");
			talloc_free(vb);
			return XLAT_ACTION_FAIL;
		}

		fr_assert(p);
		fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, p, false);
		fr_dcursor_append(out, vb);

		return XLAT_ACTION_DONE;
	}
	}
}
#endif

static xlat_arg_parser_t const xlat_func_sha_arg = {
	.concat = true,
	.type = FR_TYPE_OCTETS
};

/** Calculate the SHA1 hash of a string or attribute.
 *
 * Example:
@verbatim
"%{sha1:foo}" == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_sha1(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    UNUSED request_t *request, fr_value_box_list_t *in)
{
	uint8_t		digest[SHA1_DIGEST_LENGTH];
	fr_sha1_ctx	sha1_ctx;
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head = fr_dlist_head(in);

	fr_sha1_init(&sha1_ctx);
	if (in_head) {
		fr_sha1_update(&sha1_ctx, in_head->vb_octets, in_head->vb_length);
	} else {
		/* sha1 of empty string */
		fr_sha1_update(&sha1_ctx, NULL, 0);
	}
	fr_sha1_final(digest, &sha1_ctx);

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, sizeof(digest), false);

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Calculate any digest supported by OpenSSL EVP_MD
 *
 * Example:
@verbatim
"%{sha2_256:foo}" == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
@endverbatim
 *
 * @ingroup xlat_functions
 */
#ifdef HAVE_OPENSSL_EVP_H
static xlat_action_t xlat_evp_md(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 UNUSED xlat_ctx_t const *xctx,
				 UNUSED request_t *request, fr_value_box_list_t *in, EVP_MD const *md)
{
	uint8_t		digest[EVP_MAX_MD_SIZE];
	unsigned int	digestlen;
	EVP_MD_CTX	*md_ctx;
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head = fr_dlist_head(in);

	md_ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(md_ctx, md, NULL);
	if (in_head) {
		EVP_DigestUpdate(md_ctx, in_head->vb_octets, in_head->vb_length);
	} else {
		EVP_DigestUpdate(md_ctx, NULL, 0);
	}
	EVP_DigestFinal_ex(md_ctx, digest, &digestlen);
	EVP_MD_CTX_destroy(md_ctx);

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, digestlen, false);

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

#  define EVP_MD_XLAT(_md, _md_func) \
static xlat_action_t xlat_func_##_md(TALLOC_CTX *ctx, fr_dcursor_t *out,\
				     xlat_ctx_t const *xctx, \
				     request_t *request,\
				     fr_value_box_list_t *in)\
{\
	return xlat_evp_md(ctx, out, xctx, request, in, EVP_##_md_func());\
}

EVP_MD_XLAT(sha2_224, sha224)
EVP_MD_XLAT(sha2_256, sha256)
EVP_MD_XLAT(sha2_384, sha384)
EVP_MD_XLAT(sha2_512, sha512)

EVP_MD_XLAT(blake2s_256, blake2s256)
EVP_MD_XLAT(blake2b_512, blake2b512)

#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
EVP_MD_XLAT(sha3_224, sha3_224)
EVP_MD_XLAT(sha3_256, sha3_256)
EVP_MD_XLAT(sha3_384, sha3_384)
EVP_MD_XLAT(sha3_512, sha3_512)
#  endif
#endif


static xlat_arg_parser_t const xlat_func_string_arg = {
	.required = true,
	.concat = true,
	.type = FR_TYPE_STRING
};

/** Print data as string, if possible.
 *
 * Concat and cast one or more input boxes to a single output box string.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_string(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				      UNUSED xlat_ctx_t const *xctx,
				      UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*in_head = fr_dlist_pop_head(in);

	/*
	 *	Casting and concat is done by arg processing
	 *	so just move the value box to the output
	 */
	fr_dcursor_append(out, in_head);

	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const xlat_func_strlen_arg = {
	.concat = true,
	.type = FR_TYPE_STRING
};

/** Print length of given string
 *
 * Example:
@verbatim
"%{strlen:foo}" == 3
@endverbatim
 *
 * @see #xlat_func_length
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_strlen(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      UNUSED xlat_ctx_t const *xctx,
				      UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head = fr_dlist_head(in);

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_SIZE, NULL, false));

	if (!in_head) {
		vb->vb_size = 0;
	} else {
		vb->vb_size = strlen(in_head->vb_strvalue);
	}

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


#ifdef HAVE_REGEX_PCRE2
/** Perform regex substitution TODO CHECK
 *
 * Called when %(subst:) pattern begins with "/"
 *
@verbatim
%(subst:<subject> /<regex>/[flags] <replace>)
@endverbatim
 *
 * Example: (User-Name = "foo")
@verbatim
"%(subst:%{User-Name} /oo.*$/ un)" == "fun"
@endverbatim
 *
 * @see #xlat_func_subst
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_subst_regex(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 UNUSED xlat_ctx_t const *xctx, request_t *request,
					 fr_value_box_list_t *in)
{
	char const		*p, *q, *end;
	char const		*regex;
	char			*buff;
	size_t			regex_len;
	ssize_t			slen;
	regex_t			*pattern;
	fr_regex_flags_t	flags;
	fr_value_box_t		*vb;
	fr_value_box_t		*subject_vb = fr_dlist_head(in);
	fr_value_box_t		*regex_vb = fr_dlist_next(in, subject_vb);
	fr_value_box_t		*rep_vb = fr_dlist_next(in, regex_vb);

	/* coverity[dereference] */
	p = regex_vb->vb_strvalue;
	end = p + regex_vb->vb_length;

	if (p == end) {
		REDEBUG("Regex must not be empty");
		return XLAT_ACTION_FAIL;
	}

	p++;	/* Advance past '/' */
	regex = p;

	q = memchr(p, '/', end - p);
	if (!q) {
		REDEBUG("No terminating '/' found for regex");
		return XLAT_ACTION_FAIL;
	}
	regex_len = q - p;

	p = q + 1;

	/*
	 *	Parse '[flags]'
	 */
	memset(&flags, 0, sizeof(flags));

	slen = regex_flags_parse(NULL, &flags, &FR_SBUFF_IN(p, end), NULL, true);
	if (slen < 0) {
		RPEDEBUG("Failed parsing regex flags");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Process the substitution
	 */
	if (regex_compile(NULL, &pattern, regex, regex_len, &flags, false, true) <= 0) {
		RPEDEBUG("Failed compiling regex");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	if (regex_substitute(vb, &buff, 0, pattern, &flags,
			     subject_vb->vb_strvalue, subject_vb->vb_length,
			     rep_vb->vb_strvalue, rep_vb->vb_length, NULL) < 0) {
		RPEDEBUG("Failed performing substitution");
		talloc_free(vb);
		talloc_free(pattern);
		return XLAT_ACTION_FAIL;
	}
	fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, buff, subject_vb->tainted);

	fr_dcursor_append(out, vb);

	talloc_free(pattern);

	return XLAT_ACTION_DONE;
}
#endif


static xlat_arg_parser_t const xlat_func_subst_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Perform regex substitution
 *
@verbatim
%(sub:<subject> <pattern> <replace>)
@endverbatim
 *
 * Example: (User-Name = "foobar")
@verbatim
"%(sub:%{User-Name} oo un)" == "funbar"
@endverbatim
 *
 * @see xlat_func_subst_regex
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_subst(TALLOC_CTX *ctx, fr_dcursor_t *out,
#ifdef HAVE_REGEX_PCRE2
				   xlat_ctx_t const *xctx,
#else
				   UNUSED xlat_ctx_t const *xctx,
#endif
				   request_t *request, fr_value_box_list_t *in)
{
	char const		*p, *q, *end;
	char			*vb_str;

	char const		*pattern, *rep;
	size_t			pattern_len, rep_len;

	fr_value_box_t		*rep_vb, *vb;
	fr_value_box_t		*subject_vb = fr_dlist_head(in);
	fr_value_box_t		*pattern_vb = fr_dlist_next(in, subject_vb);

	/* coverity[dereference] */
	pattern = pattern_vb->vb_strvalue;

	if (*pattern == '/') {
#ifdef HAVE_REGEX_PCRE2
		return xlat_func_subst_regex(ctx, out, xctx, request, in);
#else
		REDEBUG("regex based substitutions require libpcre2.  "
			"Check ${features.regex-pcre2} to determine support");
		return XLAT_ACTION_FAIL;
#endif
	}

	/*
	 *	Check for empty pattern
	 */
	pattern_len = pattern_vb->vb_length;
	if (pattern_len == 0) {
		REDEBUG("Empty pattern");
		return XLAT_ACTION_FAIL;
	}

	rep_vb = fr_dlist_next(in, pattern_vb);
	rep = rep_vb->vb_strvalue;
	rep_len = rep_vb->vb_length;

	p = subject_vb->vb_strvalue;
	end = p + subject_vb->vb_length;

	MEM(vb = fr_value_box_alloc_null(ctx));
	vb_str = talloc_bstrndup(vb, "", 0);

	while (p < end) {
		q = memmem(p, end - p, pattern, pattern_len);
		if (!q) {
			MEM(vb_str = talloc_bstr_append(vb, vb_str, p, end - p));
			break;
		}

		if (q > p) MEM(vb_str = talloc_bstr_append(vb, vb_str, p, q - p));
		if (rep_len) MEM(vb_str = talloc_bstr_append(vb, vb_str, rep, rep_len));
		p = q + pattern_len;
	}

	if (fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, vb_str, subject_vb->tainted) < 0) {
		RPEDEBUG("Failed creating output box");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_assert(vb && (vb->type != FR_TYPE_NULL));
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Change case of a string
 *
 * If upper is true, change to uppercase, otherwise, change to lowercase
 */
static xlat_action_t xlat_change_case(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED request_t *request, fr_value_box_list_t *in, bool upper)
{
	char		*p;
	char const	*end;
	fr_value_box_t	*vb = fr_dlist_pop_head(in);

	p = UNCONST(char *, vb->vb_strvalue);
	end = p + vb->vb_length;

	while (p < end) {
		*(p) = upper ? toupper ((int) *(p)) : tolower((int) *(p));
		p++;
	}

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_change_case_arg = {
	.required = true,
	.concat = true,
	.type = FR_TYPE_STRING
};


/** Convert a string to lowercase
 *
 * Example:
@verbatim
"%{tolower:Bar}" == "bar"
@endverbatim
 *
 * Probably only works for ASCII
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_tolower(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *in)
{
	return xlat_change_case(ctx, out, request, in, false);
}


/** Convert a string to uppercase
 *
 * Example:
@verbatim
"%{toupper:Foo}" == "FOO"
@endverbatim
 *
 * Probably only works for ASCII
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_toupper(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *in)
{
	return xlat_change_case(ctx, out, request, in, true);
}


static xlat_arg_parser_t const xlat_func_urlquote_arg = {
	.required = true,
	.concat = true,
	.type = FR_TYPE_STRING
};

/** URLencode special characters
 *
 * Example:
@verbatim
"%{urlquote:http://example.org/}" == "http%3A%47%47example.org%47"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_urlquote(TALLOC_CTX *ctx, fr_dcursor_t *out,
					UNUSED xlat_ctx_t const *xctx,
					UNUSED request_t *request, fr_value_box_list_t *in)
{
	char const	*p, *end;
	char		*buff_p;
	size_t		outlen = 0;
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head = fr_dlist_head(in);

	p = in_head->vb_strvalue;
	end = p + in_head->vb_length;

	/*
	 * Calculate size of output
	 */
	while (p < end) {
		if (isalnum(*p) ||
		    *p == '-' ||
		    *p == '_' ||
		    *p == '.' ||
		    *p == '~') {
			outlen++;
		} else {
			outlen += 3;
		}
		p++;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_bstr_alloc(vb, &buff_p, vb, NULL, outlen, false) == 0);

	/* Reset p to start position */
	p = in_head->vb_strvalue;

	while (p < end) {
		if (isalnum(*p)) {
			*buff_p++ = *p++;
			continue;
		}

		switch (*p) {
		case '-':
		case '_':
		case '.':
		case '~':
			*buff_p++ = *p++;
			break;

		default:
			/* MUST be upper case hex to be compliant */
			snprintf(buff_p, 4, "%%%02X", (uint8_t) *p++); /* %XX */

			buff_p += 3;
		}
	}

	*buff_p = '\0';

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const xlat_func_urlunquote_arg = {
	.required = true,
	.concat = true,
	.type = FR_TYPE_STRING
};

/** URLdecode special characters
 *
 * @note Remember to escape % with %% in strings, else xlat will try to parse it.
 *
 * Example:
@verbatim
"%{urlunquote:http%%3A%%47%%47example.org%%47}" == "http://example.org/"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_urlunquote(TALLOC_CTX *ctx, fr_dcursor_t *out,
					  UNUSED xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *in)
{
	char const	*p, *end;
	char		*buff_p;
	char		*c1, *c2;
	size_t		outlen = 0;
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head = fr_dlist_head(in);

	p = in_head->vb_strvalue;
	end = p + in_head->vb_length;

	/*
	 * Calculate size of output
	 */
	while (p < end) {
		if (*p == '%') {
			p += 3;
		} else {
			p++;
		}
		outlen++;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_bstr_alloc(vb, &buff_p, vb, NULL, outlen, false) == 0);

	/* Reset p to start position */
	p = in_head->vb_strvalue;

	while (p < end) {
		if (*p != '%') {
			*buff_p++ = *p++;
			continue;
		}
		/* Is a % char */

		/* Don't need \0 check, as it won't be in the hextab */
		if (!(c1 = memchr(hextab, tolower(*++p), 16)) ||
		    !(c2 = memchr(hextab, tolower(*++p), 16))) {
			REMARKER(in_head->vb_strvalue, p - in_head->vb_strvalue, "Non-hex char in %% sequence");
			talloc_free(vb);

			return XLAT_ACTION_FAIL;
		}
		p++;
		*buff_p++ = ((c1 - hextab) << 4) + (c2 - hextab);
	}

	*buff_p = '\0';
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const protocol_decode_xlat_args[] = {
	{ .single = true, .variadic = true, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Decode any protocol attribute / options
 *
 * Creates protocol-specific attributes based on the given binary option data
 *
 * Example:
@verbatim
%(decode.dhcpv4:%{Tmp-Octets-0})
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t protocol_decode_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					  xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *in)
{
	int					decoded;
	fr_value_box_t				*vb;
	void					*decode_ctx = NULL;
	fr_test_point_pair_decode_t const	*tp_decode = *(void * const *)xctx->inst;

	if (tp_decode->test_ctx) {
		if (tp_decode->test_ctx(&decode_ctx, ctx) < 0) {
			return XLAT_ACTION_FAIL;
		}
	}

	decoded = xlat_decode_value_box_list(request->request_ctx, &request->request_pairs,
					     request, decode_ctx, tp_decode->func, in);
	if (decoded <= 0) {
		talloc_free(decode_ctx);
		RPERROR("Protocol decoding failed");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Create a value box to hold the decoded count, and add
	 *	it to the output list.
	 */
	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL, false));
	vb->vb_uint32 = decoded;
	fr_dcursor_append(out, vb);

	talloc_free(decode_ctx);
	return XLAT_ACTION_DONE;
}

static int protocol_xlat_instantiate(xlat_inst_ctx_t const *mctx)
{
	*(void **) mctx->inst = mctx->uctx;
	return 0;
}

static xlat_arg_parser_t const protocol_encode_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Encode protocol attributes / options
 *
 * Returns octet string created from the provided pairs
 *
 * Example:
@verbatim
%(encode.dhcpv4:&request[*])
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t protocol_encode_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					  xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *in)
{
	tmpl_t		*vpt;
	fr_pair_t	*vp;
	fr_dcursor_t	cursor;
	tmpl_dcursor_ctx_t	cc;
	bool		tainted = false;
	fr_value_box_t	*encoded;

	uint8_t		binbuf[2048];
	uint8_t		*p = binbuf, *end = p + sizeof(binbuf);
	ssize_t		len = 0;
	fr_value_box_t	*in_head = fr_dlist_head(in);

	void		*encode_ctx = NULL;
	fr_test_point_pair_encode_t const *tp_encode;

	memcpy(&tp_encode, xctx->inst, sizeof(tp_encode)); /* const issues */

	if (tmpl_afrom_attr_str(ctx, NULL, &vpt, in_head->vb_strvalue,
				&(tmpl_rules_t){
					.attr = {
						.dict_def = request->dict,
						.prefix = TMPL_ATTR_REF_PREFIX_AUTO
					}
				}) <= 0) {
		RPEDEBUG("Failed parsing attribute reference");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Create the encoding context.
	 */
	if (tp_encode->test_ctx) {
		if (tp_encode->test_ctx(&encode_ctx, vpt) < 0) {
			talloc_free(vpt);
			return XLAT_ACTION_FAIL;
		}
	}

	/*
	 *	Loop over the attributes, encoding them.
	 */
	for (vp = tmpl_dcursor_init(NULL, NULL, &cc, &cursor, request, vpt);
	     vp != NULL;
	     vp = fr_dcursor_next(&cursor)) {
		if (vp->da->flags.internal) continue;

		/*
		 *	Don't check the dictionaries.  By definition,
		 *	vp->da->dict==request->dict, OR else we're
		 *	using the internal encoder and encoding a real
		 *	protocol.
		 *
		 *	However, we likely still want a
		 *	dictionary-specific "is encodable" function,
		 *	as AKA/SIM and DHCPv6 encode "bool"s only if
		 *	their value is true.
		 */

		len = tp_encode->func(&FR_DBUFF_TMP(p, end), &cursor, encode_ctx);
		if (len < 0) {
			RPEDEBUG("Protocol encoding failed");
			tmpl_dcursor_clear(&cc);
			talloc_free(vpt);
			return XLAT_ACTION_FAIL;
		}

		tainted |= vp->vp_tainted;
		p += len;
	}

	tmpl_dcursor_clear(&cc);
	talloc_free(vpt);

	/*
	 *	Pass the options string back to the caller.
	 */
	MEM(encoded = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(encoded, encoded, NULL, binbuf, (size_t)len, tainted);
	fr_dcursor_append(out, encoded);

	return XLAT_ACTION_DONE;
}

static int xlat_protocol_register(fr_dict_t const *dict)
{
	fr_test_point_pair_decode_t *tp_decode;
	fr_test_point_pair_encode_t *tp_encode;
	xlat_t *xlat;
	dl_t *dl = fr_dict_dl(dict);
	char *p, buffer[256+32], name[256];

	/*
	 *	No library for this protocol, skip it.
	 *
	 *	Protocol TEST has no libfreeradius-test, so that's OK.
	 */
	if (!dl) return 0;

	strlcpy(name, fr_dict_root(dict)->name, sizeof(name));
	for (p = name; *p != '\0'; p++) {
		*p = tolower((int) *p);
	}

	/*
	 *	See if there's a decode function for it.
	 */
	snprintf(buffer, sizeof(buffer), "%s_tp_decode_pair", name);
	tp_decode = dlsym(dl->handle, buffer);
	if (tp_decode) {
		snprintf(buffer, sizeof(buffer), "decode.%s", name);

		xlat = xlat_register(NULL, buffer, protocol_decode_xlat, NULL);
		if (!xlat) return -1;
		xlat_func_args(xlat, protocol_decode_xlat_args);
		/* coverity[suspicious_sizeof] */
		xlat_async_instantiate_set(xlat, protocol_xlat_instantiate, fr_test_point_pair_decode_t *, NULL, tp_decode);
		xlat_internal(xlat);
	}

	/*
	 *	See if there's an encode function for it.
	 */
	snprintf(buffer, sizeof(buffer), "%s_tp_encode_pair", name);
	tp_encode = dlsym(dl->handle, buffer);
	if (tp_encode) {
		snprintf(buffer, sizeof(buffer), "encode.%s", name);

		xlat = xlat_register(NULL, buffer, protocol_encode_xlat, NULL);
		if (!xlat) return -1;
		xlat_func_args(xlat, protocol_encode_xlat_args);
		/* coverity[suspicious_sizeof] */
		xlat_async_instantiate_set(xlat, protocol_xlat_instantiate, fr_test_point_pair_encode_t *, NULL, tp_encode);
		xlat_internal(xlat);
	}

	return 0;
}

static int xlat_protocol_init(void)
{
	fr_dict_t *dict;
	fr_dict_global_ctx_iter_t iter;

	for (dict = fr_dict_global_ctx_iter_init(&iter);
	     dict != NULL;
	     dict = fr_dict_global_ctx_iter_next(&iter)) {
		if (xlat_protocol_register(dict) < 0) return -1;
	}

	/*
	 *	And the internal protocol, too.
	 */
	if (xlat_protocol_register(fr_dict_internal()) < 0) return -1;

	return 0;
}


/** Global initialisation for xlat
 *
 * @note Free memory with #xlat_free
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_init(void)
{
	xlat_t *xlat;

	if (xlat_root) return 0;

	/*
	 *	Lookup attributes used by virtual xlat expansions.
	 */
	if (xlat_eval_init() < 0) return -1;

	/*
	 *	Registers async xlat operations in the `unlang` interpreter.
	 */
	unlang_xlat_init();

	/*
	 *	Create the function tree
	 */
	xlat_root = fr_rb_inline_talloc_alloc(NULL, xlat_t, node, xlat_cmp, _xlat_func_tree_free);
	if (!xlat_root) {
		ERROR("%s: Failed to create tree", __FUNCTION__);
		return -1;
	}

	/*
	 *	Define encode/decode xlats for the various protocols.
	 */
	if (xlat_protocol_init() < 0) return -1;

	/*
	 *	These are all "pure" functions.
	 */
#define XLAT_REGISTER_ARGS(_xlat, _func, _args) \
do { \
	if (!(xlat = xlat_register(NULL, _xlat, _func, XLAT_FLAG_PURE))) return -1; \
	xlat_func_args(xlat, _args); \
	xlat_internal(xlat); \
} while (0)

	XLAT_REGISTER_ARGS("cast", xlat_func_cast, xlat_func_cast_args);
	XLAT_REGISTER_ARGS("concat", xlat_func_concat, xlat_func_concat_args);
	XLAT_REGISTER_ARGS("explode", xlat_func_explode, xlat_func_explode_args);
	XLAT_REGISTER_ARGS("hmacmd5", xlat_func_hmac_md5, xlat_hmac_args);
	XLAT_REGISTER_ARGS("hmacsha1", xlat_func_hmac_sha1, xlat_hmac_args);
	XLAT_REGISTER_ARGS("integer", xlat_func_integer, xlat_func_integer_args);
	XLAT_REGISTER_ARGS("join", xlat_func_join, xlat_func_join_args);
	XLAT_REGISTER_ARGS("ungroup", xlat_func_ungroup, xlat_func_join_args);
	XLAT_REGISTER_ARGS("length", xlat_func_length, xlat_func_length_args);
	XLAT_REGISTER_ARGS("lpad", xlat_func_lpad, xlat_func_pad_args);
	XLAT_REGISTER_ARGS("rpad", xlat_func_rpad, xlat_func_pad_args);

	/*
	 *	The inputs to these functions are variable.
	 */
#undef XLAT_REGISTER_ARGS
#define XLAT_REGISTER_ARGS(_xlat, _func, _args) \
do { \
	if (!(xlat = xlat_register(NULL, _xlat, _func, NULL))) return -1; \
	xlat_func_args(xlat, _args); \
	xlat_internal(xlat); \
} while (0)

	XLAT_REGISTER_ARGS("debug", xlat_func_debug, xlat_func_debug_args);
	XLAT_REGISTER_ARGS("debug_attr", xlat_func_debug_attr, xlat_func_debug_attr_args);
	XLAT_REGISTER_ARGS("nexttime", xlat_func_next_time, xlat_func_next_time_args);
	XLAT_REGISTER_ARGS("pairs", xlat_func_pairs, xlat_func_pairs_args);
	XLAT_REGISTER_ARGS("subst", xlat_func_subst, xlat_func_subst_args);
	XLAT_REGISTER_ARGS("trigger", trigger_xlat, trigger_xlat_args);

	/*
	 *	Temporary functions for migration.
	 */
	XLAT_REGISTER_ARGS("flatten", xlat_func_flatten, xlat_func_debug_attr_args); /* takes an attribute reference */
	XLAT_REGISTER_ARGS("unflatten", xlat_func_unflatten, xlat_func_debug_attr_args); /* takes an attribute reference */

	xlat = xlat_register(NULL, "untaint", xlat_func_untaint, NULL);
	xlat_internal(xlat);
	xlat = xlat_register(NULL, "taint", xlat_func_taint, NULL);
	xlat_internal(xlat);

	/*
	 *	All of these functions are pure.
	 */
#define XLAT_REGISTER_MONO(_xlat, _func, _arg) \
do { \
	if (!(xlat = xlat_register(NULL, _xlat, _func, XLAT_FLAG_PURE))) return -1; \
	xlat_func_mono(xlat, &_arg); \
	xlat_internal(xlat); \
} while (0)

	XLAT_REGISTER_MONO("base64", xlat_func_base64_encode, xlat_func_base64_encode_arg);
	XLAT_REGISTER_MONO("base64decode", xlat_func_base64_decode, xlat_func_base64_decode_arg);
	XLAT_REGISTER_MONO("bin", xlat_func_bin, xlat_func_bin_arg);
	XLAT_REGISTER_MONO("hex", xlat_func_hex, xlat_func_hex_arg);
	XLAT_REGISTER_MONO("map", xlat_func_map, xlat_func_map_arg);
	XLAT_REGISTER_MONO("md4", xlat_func_md4, xlat_func_md4_arg);
	XLAT_REGISTER_MONO("md5", xlat_func_md5, xlat_func_md5_arg);
	XLAT_REGISTER_MONO("pack", xlat_func_pack, xlat_func_pack_arg);
#if defined(HAVE_REGEX_PCRE) || defined(HAVE_REGEX_PCRE2)
	xlat = xlat_register(NULL, "regex", xlat_func_regex, NULL);
	xlat_internal(xlat);
#endif
	XLAT_REGISTER_MONO("sha1", xlat_func_sha1, xlat_func_sha_arg);

#ifdef HAVE_OPENSSL_EVP_H
	XLAT_REGISTER_MONO("sha2_224", xlat_func_sha2_224, xlat_func_sha_arg);
	XLAT_REGISTER_MONO("sha2_256", xlat_func_sha2_256, xlat_func_sha_arg);
	XLAT_REGISTER_MONO("sha2_384", xlat_func_sha2_384, xlat_func_sha_arg);
	XLAT_REGISTER_MONO("sha2_512", xlat_func_sha2_512, xlat_func_sha_arg);

	XLAT_REGISTER_MONO("blake2s_256", xlat_func_blake2s_256, xlat_func_sha_arg);
	XLAT_REGISTER_MONO("blake2b_512", xlat_func_blake2b_512, xlat_func_sha_arg);

#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
	XLAT_REGISTER_MONO("sha3_224", xlat_func_sha3_224, xlat_func_sha_arg);
	XLAT_REGISTER_MONO("sha3_256", xlat_func_sha3_256, xlat_func_sha_arg);
	XLAT_REGISTER_MONO("sha3_384", xlat_func_sha3_384, xlat_func_sha_arg);
	XLAT_REGISTER_MONO("sha3_512", xlat_func_sha3_512, xlat_func_sha_arg);
#  endif
#endif

	XLAT_REGISTER_MONO("string", xlat_func_string, xlat_func_string_arg);
	XLAT_REGISTER_MONO("strlen", xlat_func_strlen, xlat_func_strlen_arg);
	XLAT_REGISTER_MONO("tolower", xlat_func_tolower, xlat_change_case_arg);
	XLAT_REGISTER_MONO("toupper", xlat_func_toupper, xlat_change_case_arg);
	XLAT_REGISTER_MONO("urlquote", xlat_func_urlquote, xlat_func_urlquote_arg);
	XLAT_REGISTER_MONO("urlunquote", xlat_func_urlunquote, xlat_func_urlunquote_arg);
	XLAT_REGISTER_MONO("eval", xlat_func_eval, xlat_func_eval_arg);
	XLAT_REGISTER_MONO("expr", xlat_func_expr, xlat_func_eval_arg);

#undef XLAT_REGISTER_MONO
#define XLAT_REGISTER_MONO(_xlat, _func, _arg) \
do { \
	if (!(xlat = xlat_register(NULL, _xlat, _func, NULL))) return -1; \
	xlat_func_mono(xlat, &_arg); \
	xlat_internal(xlat); \
} while (0)

	XLAT_REGISTER_MONO("rand", xlat_func_rand, xlat_func_rand_arg);
	XLAT_REGISTER_MONO("randstr", xlat_func_randstr, xlat_func_randstr_arg);

	xlat = xlat_register(NULL, "module", xlat_func_module, NULL);
	xlat_internal(xlat);

	return xlat_register_expressions();
}


/** De-register all xlat functions we created
 *
 */
void xlat_free(void)
{
	fr_rb_tree_t *xr = xlat_root;		/* Make sure the tree can't be freed multiple times */

	if (!xr) return;

	xlat_root = NULL;
	talloc_free(xr);

	xlat_eval_free();
}
