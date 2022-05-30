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
 * @file xlat_inst.c
 * @brief Create instance data for xlat function calls.
 *
 * @copyright 2018-2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2018 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/unlang/xlat_priv.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/heap.h>

/** Holds instance data created by xlat_instantiate
 */
static fr_heap_t *xlat_inst_tree;

/** Holds thread specific instance data created by xlat_instantiate
 */
static _Thread_local fr_heap_t *xlat_thread_inst_tree;

/** Compare two xlat instances based on node pointer
 *
 * @param[in] one      	First xlat expansion instance.
 * @param[in] two	Second xlat expansion instance.
 * @return CMP(one, two)
 */
static int8_t _xlat_inst_cmp(void const *one, void const *two)
{
	xlat_inst_t const *a = one, *b = two;

	return CMP(a->node->call.id, b->node->call.id);
}

/** Compare two thread instances based on node pointer
 *
 * @param[in] one	First thread specific xlat expansion instance.
 * @param[in] two	Second thread specific xlat expansion instance.
 * @return CMP(one, two)
 */
static int8_t _xlat_thread_inst_cmp(void const *one, void const *two)
{
	xlat_thread_inst_t const *a = one, *b = two;

	return CMP(a->node->call.id, b->node->call.id);
}

/** Destructor for xlat_thread_inst_t
 *
 * Calls thread_detach method if provided by xlat expansion
 *
 * @note This cannot be converted to a talloc destructor,
 *	as we need to call thread_detach *before* any of the children
 *	of the talloc ctx are freed.
 */
static int _xlat_thread_inst_detach(xlat_thread_inst_t *xt)
{
	xlat_call_t const *call = &xt->node->call;

	fr_assert(xt->node->type == XLAT_FUNC);

	DEBUG4("Cleaning up xlat thread instance (%p/%p)", xt, xt->data);

	fr_assert(call->func->thread_detach);

	(void) call->func->thread_detach(XLAT_THREAD_INST_CTX(call->inst->data,
							      xt->data, xt->node, xt->mctx,
							      xt->el,
							      call->func->thread_uctx));

	return 0;
}

/** Create thread instances where needed
 *
 * @param[in] ctx	to allocate thread instance data in.
 * @param[in] el	event list to register I/O handlers against.
 * @param[in] xi	to allocate thread-instance data for.
 * @return
 *	- 0 on success.  The node/thread specific data will be inserted
 *	  into xlat_thread_inst_tree.
 *	- -1 on failure.
 */
static xlat_thread_inst_t *xlat_thread_inst_alloc(TALLOC_CTX *ctx, fr_event_list_t *el, xlat_inst_t *xi)
{
	size_t 			extra_headers = 0;
	size_t 			extra_mem = 0;
	xlat_call_t const	*call = &((xlat_inst_t const *)talloc_get_type_abort_const(xi, xlat_inst_t))->node->call;
	xlat_thread_inst_t	*xt = NULL;

	/*
	 *	Allocate extra room for the thread instance data
	 */
	if (call->func->thread_inst_size) {
		extra_headers++;
		extra_mem += call->func->thread_inst_size;
	}

	/*
	 *	Allocate extra room for the mctx
	 */
	if (call->func->mctx) {
		extra_headers++;
		extra_mem += sizeof(*call->func->mctx);
	}

	if (extra_headers || extra_mem) {
		MEM(xt = talloc_zero_pooled_object(ctx, xlat_thread_inst_t, extra_headers, extra_mem));
	} else {
		MEM(xt = talloc_zero(ctx, xlat_thread_inst_t));
	}

	xt->node = xi->node;
	xt->el = el;

	fr_assert(xi->node->type == XLAT_FUNC);

	if (call->func->thread_detach) talloc_set_destructor(xt, _xlat_thread_inst_detach);

	if (call->func->thread_inst_size) {
		MEM(xt->data = talloc_zero_array(xt, uint8_t, call->func->thread_inst_size));

		if (call->func->thread_inst_type) {
			talloc_set_name_const(xt->data, call->func->thread_inst_type);
		} else {
			talloc_set_name(xt->data, "xlat_%s_thread_t", call->func->name);
		}
	}

	/*
	 *	Create a module call ctx.
	 *
	 *	We do this now because we're operating in the
	 *	context of a thread and can get the thread
	 *	specific data for the module.
	 */
	if (call->func->mctx) {
		module_ctx_t *mctx;

		mctx = module_ctx_from_inst(xt, call->func->mctx);
		mctx->thread = module_rlm_thread_by_data(mctx->inst->data)->data;

		xt->mctx = mctx;
	}

	DEBUG4("Alloced xlat thread instance (%p/%p)", xt, xt->data);

	return xt;
}

/** Destructor for xlat_inst_t
 *
 * Calls detach method if provided by xlat expansion
 *
 * @note This cannot be converted to a talloc destructor,
 *	as we need to call thread_detach *before* any of the children
 *	of the talloc ctx are freed.
 */
static int _xlat_inst_detach(xlat_inst_t *xi)
{
	xlat_call_t const *call;

	fr_assert(xlat_inst_tree);		/* xlat_inst_init must have been called */

	(void) talloc_get_type_abort_const(xi->node, xlat_exp_t);
	fr_assert(xi->node->type == XLAT_FUNC);

	call = &xi->node->call;

	/*
	 *	Remove permanent data from the instance tree
	 *	and auto-free the tree when the last xlat is
	 *      freed.
	 */
	if (!call->ephemeral) {
		if (fr_heap_entry_inserted(xi->idx)) fr_heap_extract(&xlat_inst_tree, xi);
		if (fr_heap_num_elements(xlat_inst_tree) == 0) TALLOC_FREE(xlat_inst_tree);
	}

	DEBUG4("Cleaning up xlat instance (%p/%p)", xi, xi->data);

	if (call->func->detach) (void) call->func->detach(XLAT_INST_CTX(xi->data,
									xi->node,
									call->func->mctx,
									call->func->uctx));
	return 0;
}

/** Allocate instance data for an xlat expansion
 *
 * @param[in] node	to allocate instance data for.
 */
static xlat_inst_t *xlat_inst_alloc(xlat_exp_t *node)
{
	xlat_call_t const	*call = &node->call;
	xlat_inst_t		*xi = NULL;

	(void)talloc_get_type_abort(node, xlat_exp_t);

	fr_assert(xlat_inst_tree);		/* xlat_inst_init must have been called */
	fr_assert(node->type == XLAT_FUNC);
	fr_assert(!call->inst);

	if (call->func->inst_size) {
		MEM(xi = talloc_zero_pooled_object(node, xlat_inst_t, 1, call->func->inst_size));
	} else {
		MEM(xi = talloc_zero(node, xlat_inst_t));
	}
	xi->node = node;

	/*
	 *	Instance data is freed when the
	 *	node is freed.
	 */
	if (call->func->detach || !call->ephemeral) {
		talloc_set_destructor(xi, _xlat_inst_detach);
	}

	if (call->func->inst_size) {
		MEM(xi->data = talloc_zero_array(xi, uint8_t, call->func->inst_size));
		if (call->func->inst_type) {
			talloc_set_name_const(xi->data, call->func->inst_type);
		} else {
			talloc_set_name(xi->data, "xlat_%s_t", call->func->name);
		}
	}

	return xi;
}

/** Callback for creating "ephemeral" instance data for a #xlat_exp_t
 *
 * @note Epehemeral xlats must not be shared between requests.
 *
 * @param[in] node	to create "ephemeral" instance data for.
 * @param[in] uctx	UNUSED.
 * @return
 *	- 0 if instantiation functions were successful.
 *	- -1 if either instantiation function failed.
 */
static int _xlat_instantiate_ephemeral_walker(xlat_exp_t *node, void *uctx)
{
	fr_event_list_t		*el;
	xlat_call_t		*call;
	xlat_inst_t		*xi;
	xlat_thread_inst_t	*xt;

	/*
	 *	tmpl_tokenize() instantiates ephemeral xlats.  So for
	 *	now, just ignore ones which are already instantiated.
	 */
	if (node->type == XLAT_GROUP) {
		return node->group->instantiated; /* prune on 1, continue on 0 */
	}

	if (node->type != XLAT_FUNC) return 0; /* skip it */

	el = talloc_get_type_abort(uctx, fr_event_list_t);
	call = &node->call;

	fr_assert(!call->inst && !call->thread_inst);

	/*
	 *	Mark this up as an ephemeral node, so the destructors
	 *	don't search for it in the xlat_inst_tree.
	 */
	call->ephemeral = true;

	xi = call->inst = xlat_inst_alloc(node);
	if (!xi) return -1;

	/*
	 *	Instantiate immediately unlike permanent XLATs
	 *	Where it's a separate phase.
	 */
	if (call->func->instantiate &&
	    (call->func->instantiate(XLAT_INST_CTX(xi->data,
		    				   xi->node,
						   call->func->mctx,
						   call->func->uctx)) < 0)) {
	error:
		TALLOC_FREE(call->inst);
		return -1;
	}

	/*
	 *	Create a thread instance too.
	 */
	xt = node->call.thread_inst = xlat_thread_inst_alloc(node, el, call->inst);
	if (!xt) goto error;

	if (call->func->thread_instantiate &&
	    (call->func->thread_instantiate(XLAT_THREAD_INST_CTX(xi->data,
	    					 		 xt->data,
	    					 		 xi->node,
	    					 		 xt->mctx,
	    					 		 el,
	    					 		 call->func->thread_uctx)) < 0)) goto error;

	return 0;
}

/** Create instance data for "ephemeral" xlats
 *
 * @note This must only be used for xlats created at runtime.
 *
 * @param[in] head of xlat tree to create instance data for.
 * @param[in] el event list used to run any instantiate data
 */
int xlat_instantiate_ephemeral(xlat_exp_head_t *head, fr_event_list_t *el)
{
	int ret;

	/*
	 *	The caller MAY resolve it, or may not.  If the caller
	 *	hasn't resolved it, then we can't allow any unresolved
	 *	functions or attributes.
	 */
	if (head->flags.needs_resolving) {
		if (xlat_resolve(head, &(xlat_res_rules_t){ .allow_unresolved = false }) < 0) return -1;
	}

	if (head->instantiated) return 0;

	ret = xlat_eval_walk(head, _xlat_instantiate_ephemeral_walker, XLAT_INVALID, el);
	if (ret < 0) return ret;

	head->instantiated = true;

	return 0;
}

/** Retrieve xlat/thread specific instance data
 *
 * @param[in] node to find thread specific data for.
 * @return
 *	- Thread specific data on success.
 *	- NULL if the xlat has no thread instance data.
 */
xlat_thread_inst_t *xlat_thread_instance_find(xlat_exp_t const *node)
{
	xlat_call_t const *call = &node->call;
	xlat_thread_inst_t *xt;

	fr_assert(xlat_thread_inst_tree);
	fr_assert(node->type == XLAT_FUNC);
	fr_assert(fr_heap_num_elements(xlat_thread_inst_tree) == fr_heap_num_elements(xlat_inst_tree));

	if (call->ephemeral) return call->thread_inst;

	/*
	 *	This works because the comparator for
	 *      the thread heap returns the same result
	 *	as the one for the global instance data
	 *	heap, and both heaps contain the same
	 *	number of elements.
	 */
	xt = fr_heap_peek_at(xlat_thread_inst_tree, call->inst->idx);
	fr_assert(xt && (xt->idx == call->inst->idx));

	return xt;
}

/** Create thread specific instance tree and create thread instances
 *
 * This should be called directly after the modules_thread_instantiate() function.
 *
 * Memory will be freed automatically when the thread exits.
 *
 * @param[in] ctx	to bind instance tree lifetime to.  Must not be
 *			shared between multiple threads.
 * @param[in] el	Event list to pass to all thread instantiation functions.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_thread_instantiate(TALLOC_CTX *ctx, fr_event_list_t *el)
{
	fr_assert(xlat_inst_tree);

	if (unlikely(!xlat_thread_inst_tree)) {
		MEM(xlat_thread_inst_tree = fr_heap_talloc_alloc(ctx,
								 _xlat_thread_inst_cmp,
								 xlat_thread_inst_t,
								 idx,
								 fr_heap_num_elements(xlat_inst_tree)));
	}

	fr_heap_foreach(xlat_inst_tree, xlat_inst_t, xi) {
		int			ret;
	     	xlat_call_t const	*call = &xi->node->call;
	     	xlat_thread_inst_t	*xt = xlat_thread_inst_alloc(xlat_thread_inst_tree, el, xi);
		if (unlikely(!xt)) return -1;

		DEBUG3("Instantiating xlat \"%s\" node %p, instance %p, new thread instance %p",
		       call->func->name, xt->node, xi->data, xt);

		ret = fr_heap_insert(&xlat_thread_inst_tree, xt);
		if (!fr_cond_assert(ret == 0)) {
		error:
			TALLOC_FREE(xlat_thread_inst_tree);	/* Reset the tree on error */
			return -1;
		}

		if (!call->func->thread_instantiate) continue;

		ret = call->func->thread_instantiate(XLAT_THREAD_INST_CTX(xi->data,
									  xt->data,
									  xi->node,
									  xt->mctx,
									  el,
									  call->func->thread_uctx));
		if (unlikely(ret < 0)) goto error;
	}}

	return 0;
}

/** Destroy any thread specific xlat instances
 *
 */
void xlat_thread_detach(void)
{
	if (!xlat_thread_inst_tree) return;

	TALLOC_FREE(xlat_thread_inst_tree);
}

/** Initialise the xlat instance data code
 *
 */
static int xlat_instantiate_init(void)
{
	if (unlikely(xlat_inst_tree != NULL)) return 0;

	xlat_inst_tree = fr_heap_talloc_alloc(NULL, _xlat_inst_cmp, xlat_inst_t, idx, 0);
	if (!xlat_inst_tree) return -1;

	return 0;
}

/** Call instantiation functions for "permanent" xlats
 *
 * Should be called after all the permanent xlats have been tokenised/bootstrapped.
 */
int xlat_instantiate(void)
{
	if (unlikely(!xlat_inst_tree)) xlat_instantiate_init();

	/*
	 *	Loop over all the bootstrapped
	 *      xlats, instantiating them.
	 */
	fr_heap_foreach(xlat_inst_tree, xlat_inst_t, xi) {
	     	xlat_call_t const	*call = &xi->node->call;

		/*
		 *	We can't instantiate functions which
		 *	still have children that need resolving
		 *      as this may break redundant xlats
		 *	if we end up needing to duplicate the
		 *	argument nodes.
		 */
		fr_assert(!xi->node->flags.needs_resolving);

		if (!call->func->instantiate) continue;

		if (call->func->instantiate(XLAT_INST_CTX(xi->data,
		    					  xi->node,
		    					  call->func->mctx,
		    					  call->func->uctx)) < 0) return -1;
	}}

	return 0;
}

/** Callback for creating "permanent" instance data for a #xlat_exp_t
 *
 * This function records the #xlat_exp_t requiring instantiation but does
 * not call the instantiation function.  This is to allow for a clear separation
 * between the module instantiation phase and the xlat instantiation phase.
 *
 * @param[in] node	to create "permanent" instance data for.
 * @return
 *	- 0 if instantiation functions were successful.
 *	- -1 if either instantiation function failed.
 */
int xlat_bootstrap_func(xlat_exp_t *node)
{
	static uint64_t call_id;
	xlat_call_t *call = &node->call;
	bool ret;

	fr_assert(node->type == XLAT_FUNC);
	fr_assert(!call->id && !call->inst && !call->thread_inst);	/* Node cannot already have instance data */
	if (!fr_cond_assert(!call->ephemeral)) return -1;		/* Can't bootstrap ephemeral calls */

	call->inst = xlat_inst_alloc(node);
	if (unlikely(!call->inst)) return -1;

	DEBUG3("Instantiating xlat \"%s\" node %p, new instance %p", call->func->name, node, call->inst);

	/*
	 *	Assign a unique ID to each xlat function call.
	 *
	 *	This is so they're ordered in the heap by
	 *	the order in which they were "bootstrapped".
	 *
	 *	This allows additional functions to be added
	 *	in the instantiation functions of other xlats
	 *	which is useful for the redundant xlats.
	 */
	node->call.id = call_id++;

	ret = fr_heap_insert(&xlat_inst_tree, call->inst);
	if (!fr_cond_assert(ret == 0)) {
		TALLOC_FREE(call->inst);
		return -1;
	}

	return 0;
}

static int _xlat_bootstrap_walker(xlat_exp_t *node, UNUSED void *uctx)
{
	/*
	 *	tmpl_tokenize() instantiates ephemeral xlats.  So for
	 *	now, just ignore ones which are already instantiated.
	 */
	if (node->type == XLAT_GROUP) {
		return node->group->instantiated; /* prune on 1, continue on 0 */
	}

	if (node->type != XLAT_FUNC) return 0; /* skip it */


	return xlat_bootstrap_func(node);
}

/** Create instance data for "permanent" xlats
 *
 * @note This must only be used for xlats created during startup.
 *	 IF THIS IS CALLED FOR XLATS TOKENIZED AT RUNTIME YOU WILL LEAK LARGE AMOUNTS OF MEMORY.
 *	 USE xlat_instantiate_request() INSTEAD.
 *
 * @param[in] head of xlat tree to create instance data for.
 */
int xlat_bootstrap(xlat_exp_head_t *head)
{
	int ret;

	/*
	 *	If thread instantiate has been called, it's too late to
	 *	bootstrap new xlats.
	 */
	fr_assert(!xlat_thread_inst_tree);

	/*
	 *	Initialise the instance tree if this is the first xlat
	 *	being instantiated.
	 */
	if (unlikely(!xlat_inst_tree)) xlat_instantiate_init();

	if (head->instantiated) return 0;

	/*
	 *	Walk an expression registering all the function calls
	 *	so that we can instantiate them later.
	 */
	ret = xlat_eval_walk(head, _xlat_bootstrap_walker, XLAT_INVALID, NULL);
	if (ret < 0) return ret;

	head->instantiated = true;
	return 0;
}

/** Walk over all registered instance data and free them explicitly
 *
 * This must be called before any modules or xlats are deregistered/unloaded and before
 * the mainconfig is freed, as the xlat_t need to still exist in order to call
 * the detach functions within them.
 */
void xlat_instances_free(void)
{
	xlat_inst_t *xi;

	/*
	 *	When we get to zero instances the heap
	 *	is freed, so we need to check there's
	 *	still a heap to pass to fr_heap_pop.
	 */
	while (xlat_inst_tree && (xi = fr_heap_pop(&xlat_inst_tree))) talloc_free(xi);
}

/** Remove a node from the list of xlat instance data
 *
 */
int xlat_inst_remove(xlat_exp_t *node)
{
	int ret;

	fr_assert(node->type == XLAT_FUNC);
	fr_assert(!node->call.func->detach);
	fr_assert(!node->call.func->thread_detach);

	if (node->call.inst) {
		ret = fr_heap_extract(&xlat_inst_tree, node->call.inst);
		if (ret < 0) return ret;

		talloc_set_destructor(node->call.inst, NULL);
		TALLOC_FREE(node->call.inst);
	}

	if (node->call.thread_inst) {
		if (!node->call.ephemeral) {
			ret = fr_heap_extract(&xlat_thread_inst_tree, node->call.thread_inst);
			if (ret < 0) return ret;
		}

		talloc_set_destructor(node->call.thread_inst, NULL);
		TALLOC_FREE(node->call.inst);
	}


	node->type = XLAT_INVALID;
	return 0;
}
