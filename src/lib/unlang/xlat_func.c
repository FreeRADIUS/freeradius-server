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
 * @file xlat_func.c
 * @brief Registration API for xlat functions
 *
 * @copyright 2023 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/unlang/xlat_priv.h>
#include <freeradius-devel/unlang/xlat.h>
#include <freeradius-devel/unlang/xlat_func.h>

static fr_rb_tree_t *xlat_root = NULL;

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

/** Register an xlat function for a module
 *
 * @param[in] ctx		Used to automate deregistration of the xlat fnction.
 * @param[in] mctx		Instantiation context from the module.
 *				Will be duplicated and passed to future xlat calls.
 * @param[in] name		of the xlat.
 * @param[in] func		to register.
 * @param[in] return_type	what type of output the xlat function will produce.
 * @return
 *	- A handle for the newly registered xlat function on success.
 *	- NULL on failure.
 */
xlat_t *xlat_func_register_module(TALLOC_CTX *ctx, module_inst_ctx_t const *mctx,
			     char const *name, xlat_func_t func, fr_type_t return_type)
{
	xlat_t	*c;
	module_inst_ctx_t *our_mctx = NULL;

	fr_assert(xlat_root);

	if (!*name) {
		ERROR("%s: Invalid xlat name", __FUNCTION__);
		return NULL;
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
		.return_type = return_type,
		.mctx = our_mctx,
		.input_type = XLAT_INPUT_UNPROCESSED	/* set default - will be overridden if args are registered */
	};
	talloc_set_destructor(c, _xlat_func_talloc_free);
	DEBUG3("%s: %s", __FUNCTION__, c->name);

	if (fr_rb_replace(NULL, xlat_root, c) < 0) {
		ERROR("%s: Failed inserting xlat registration for %s", __FUNCTION__, c->name);
		talloc_free(c);
		return NULL;
	}

	return c;
}

/** Register an xlat function
 *
 * @param[in] ctx		Used to automate deregistration of the xlat fnction.
 * @param[in] name		of the xlat.
 * @param[in] func		to register.
 * @param[in] return_type	what type of output the xlat function will produce.
 * @return
 *	- A handle for the newly registered xlat function on success.
 *	- NULL on failure.
 */
xlat_t *xlat_func_register(TALLOC_CTX *ctx, char const *name, xlat_func_t func, fr_type_t return_type)
{
	return xlat_func_register_module(ctx, NULL, name, func, return_type);
}

/** Verify xlat arg specifications are valid
 *
 * @param[in] x		we're setting arguments for.
 * @param[in] arg	specification to validate.
 * @param[in] last	Is this the last argument in the list.
 */
static inline int xlat_arg_parser_validate(xlat_t *x, xlat_arg_parser_t const *arg, bool last)
{
	if (arg->concat) {
		if (!fr_cond_assert_msg((arg->type == FR_TYPE_STRING) || (arg->type == FR_TYPE_OCTETS),
					"%s - concat type must be string or octets", x->name)) return -1;

		if (!fr_cond_assert_msg(!arg->single, "%s - concat and single are mutually exclusive", x->name)) return -1;
	}

	if (arg->single) {
		if (!fr_cond_assert_msg(!arg->concat, "%s - single and concat are mutually exclusive", x->name)) return -1;
	}

	if (arg->variadic) {
		if (!fr_cond_assert_msg(last, "%s - variadic can only be set on the last argument", x->name)) return -1;
		if (!fr_cond_assert_msg(!arg->required, "%s - required can't be set on a variadic argument. "
					"Set required in the preceeding entry", x->name)) return -1;
	}

	if (arg->always_escape) {
		if (!fr_cond_assert_msg(arg->func, "%s - always_escape requires an escape func", x->name)) return -1;
	}

	if (arg->uctx) {
		if (!fr_cond_assert_msg(arg->func, "%s - uctx requires an escape func", x->name)) return -1;
	}

	switch (arg->type) {
	case FR_TYPE_LEAF:
	case FR_TYPE_VOID:
		break;

	default:
		fr_assert_fail("%s - type must be a leaf box type", x->name);
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
int xlat_func_args_set(xlat_t *x, xlat_arg_parser_t const args[])
{
	xlat_arg_parser_t const *arg_p = args;
	bool			seen_optional = false;

	for (arg_p = args; arg_p->type != FR_TYPE_NULL; arg_p++) {
		if (xlat_arg_parser_validate(x, arg_p, (arg_p + 1)->type == FR_TYPE_NULL) < 0) return -1;

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
 * @param[in] args		to be registered
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
int xlat_func_mono_set(xlat_t *x, xlat_arg_parser_t const args[])
{
	if (xlat_func_args_set(x, args) < 0) return -1;
	x->input_type = XLAT_INPUT_MONO;

	return 0;
}

/** Register call environment of an xlat
 *
 * @param[in,out] x		to have it's module method env registered.
 * @param[in] env		to be registered.
 */
void xlat_func_call_env_set(xlat_t *x, call_method_env_t const *env)
{
	x->call_env = env;
}

/** Specify flags that alter the xlat's behaviour
 *
 * @param[in] x			xlat to set flags for.
 * @param[in] flags		to set.
 */
void xlat_func_flags_set(xlat_t *x, xlat_func_flags_t flags)
{
	x->flags.pure = flags & XLAT_FUNC_FLAG_PURE;
	x->internal = flags & XLAT_FUNC_FLAG_INTERNAL;
}

/** Set a print routine for an xlat function.
 *
 * @param[in] xlat to set
 * @param[in] func for printing
 */
void xlat_func_print_set(xlat_t *xlat, xlat_print_t func)
{
	xlat->print = func;
}

/** Set a resolve routine for an xlat function.
 *
 * @param[in] xlat to set
 * @param[in] func to resolve xlat.
 */
void xlat_func_resolve_set(xlat_t *xlat, xlat_resolve_t func)
{
	xlat->resolve = func;
}

/** Set a resolve routine for an xlat function.
 *
 * @param[in] xlat to set
 * @param[in] func to purify xlat
 */
void xlat_purify_func_set(xlat_t *xlat, xlat_purify_t func)
{
	xlat->purify = func;
}

/** Set global instantiation/detach callbacks
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
void _xlat_func_async_instantiate_set(xlat_t const *xlat,
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
 * All functions registered must be !pure
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
void _xlat_func_async_thread_instantiate_set(xlat_t const *xlat,
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
void xlat_func_unregister(char const *name)
{
	xlat_t	*c;

	if (!name || !xlat_root) return;

	c = fr_rb_find(xlat_root, &(xlat_t){ .name = name });
	if (!c) return;

	(void) talloc_get_type_abort(c, xlat_t);

	talloc_free(c);	/* Should also remove from tree */
}

void xlat_func_unregister_module(dl_module_inst_t const *inst)
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

int xlat_func_init(void)
{
	if (xlat_root) return 0;

	/*
	 *	Create the function tree
	 */
	xlat_root = fr_rb_inline_talloc_alloc(NULL, xlat_t, node, xlat_cmp, _xlat_func_tree_free);
	if (!xlat_root) {
		ERROR("%s: Failed to create tree", __FUNCTION__);
		return -1;
	}

	return 0;
}

void xlat_func_free(void)
{
	fr_rb_tree_t *xr = xlat_root;		/* Make sure the tree can't be freed multiple times */

	if (!xr) return;

	xlat_root = NULL;
	talloc_free(xr);
}
