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
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/unlang/xlat_priv.h>
#include <freeradius-devel/io/schedule.h>

#include <ctype.h>

/** Holds instance data created by xlat_instantiate
 */
static fr_rb_tree_t *xlat_inst_tree;

/** Holds thread specific instance data created by xlat_instantiate
 */
static _Thread_local fr_rb_tree_t *xlat_thread_inst_tree;

/** Compare two xlat instances based on node pointer
 *
 * @param[in] one      	First xlat expansion instance.
 * @param[in] two	Second xlat expansion instance.
 * @return CMP(one, two)
 */
static int8_t _xlat_inst_cmp(void const *one, void const *two)
{
	xlat_inst_t const *a = one, *b = two;

	return CMP(a->node, b->node);
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

	return CMP(a->node, b->node);
}

/** Destructor for xlat_thread_inst_t
 *
 * Calls thread_detach method if provided by xlat expansion
 *
 * @note This cannot be converted to a talloc destructor,
 *	as we need to call thread_detach *before* any of the children
 *	of the talloc ctx are freed.
 */
static int _xlat_thread_inst_detach(xlat_thread_inst_t *thread_inst)
{
	fr_assert(thread_inst->node->type == XLAT_FUNC);

	if (thread_inst->node->call.func->thread_detach) {
		(void) thread_inst->node->call.func->thread_detach(thread_inst->data, thread_inst->node->call.func->thread_uctx);
	}

	return 0;
}

/** Destructor for xlat_thread_inst_tree elements
 *
 */
static void _xlat_thread_inst_free(void *to_free)
{
	xlat_thread_inst_t *thread_inst = talloc_get_type_abort(to_free, xlat_thread_inst_t);

	DEBUG4("Worker cleaning up xlat thread instance (%p/%p)", thread_inst, thread_inst->data);

	talloc_free(thread_inst);
}

/** Create thread instances where needed
 *
 * @param[in] ctx	to allocate thread instance data in.
 * @param[in] inst	to allocate thread-instance data for.
 * @return
 *	- 0 on success.  The node/thread specific data will be inserted
 *	  into xlat_thread_inst_tree.
 *	- -1 on failure.
 */
static xlat_thread_inst_t *xlat_thread_inst_alloc(TALLOC_CTX *ctx, xlat_inst_t *inst)
{
	xlat_thread_inst_t	*thread_inst = NULL;

	(void)talloc_get_type_abort(inst, xlat_inst_t);

	if (inst->node->call.func->thread_inst_size) {
		MEM(thread_inst = talloc_zero_pooled_object(ctx, xlat_thread_inst_t,
							    1, inst->node->call.func->thread_inst_size));
	} else {
		MEM(thread_inst = talloc_zero(ctx, xlat_thread_inst_t));
	}

	thread_inst->node = inst->node;

	fr_assert(inst->node->type == XLAT_FUNC);
	fr_assert(!inst->node->call.thread_inst);		/* May be missing inst, but this is OK */

	talloc_set_destructor(thread_inst, _xlat_thread_inst_detach);
	if (inst->node->call.func->thread_inst_size) {
		MEM(thread_inst->data = talloc_zero_array(thread_inst, uint8_t, inst->node->call.func->thread_inst_size));

		/*
		 *	This is expensive, only do it if we might
		 *	might be using it.
		 */
#ifndef TALLOC_GET_TYPE_ABORT_NOOP
		talloc_set_name_const(thread_inst->data, inst->node->call.func->thread_inst_type);
#endif
	}

	DEBUG4("Worker alloced xlat thread instance (%p/%p)", thread_inst, thread_inst->data);

	return thread_inst;
}

/** Destructor for xlat_inst_t
 *
 * Calls detach method if provided by xlat expansion
 *
 * @note This cannot be converted to a talloc destructor,
 *	as we need to call thread_detach *before* any of the children
 *	of the talloc ctx are freed.
 */
static int _xlat_inst_detach(xlat_inst_t *inst)
{
	(void)talloc_get_type_abort_const(inst->node, xlat_exp_t);
	fr_assert(inst->node->type == XLAT_FUNC);

	/*
	 *	Remove permanent data from the instance tree.
	 */
	if (!inst->node->call.ephemeral) {
		fr_rb_delete(xlat_inst_tree, inst);
		if (fr_rb_num_elements(xlat_inst_tree) == 0) TALLOC_FREE(xlat_inst_tree);
	}

	if (inst->node->call.func->detach) (void) inst->node->call.func->detach(inst->data, inst->node->call.func->uctx);

	return 0;
}

/** Destructor for xlat_inst_tree elements
 *
 */
static void _xlat_inst_free(void *to_free)
{
	xlat_inst_t *inst = talloc_get_type_abort(to_free, xlat_inst_t);
	talloc_free(inst);
}

/** Allocate instance data for an xlat expansion
 *
 * @param[in] node	to allocate instance data for.
 */
static xlat_inst_t *xlat_inst_alloc(xlat_exp_t *node)
{
	xlat_inst_t		*inst = NULL;

	(void)talloc_get_type_abort(node, xlat_exp_t);

	fr_assert(xlat_inst_tree);		/* xlat_inst_init must have been called */
	fr_assert(node->type == XLAT_FUNC);
	fr_assert(!node->call.inst);

	if (node->call.func->inst_size) {
		MEM(inst = talloc_zero_pooled_object(node, xlat_inst_t, 1, node->call.func->inst_size));
	} else {
		MEM(inst = talloc_zero(node, xlat_inst_t));
	}

	inst->node = node;

	/*
	 *	Instance data is freed when the
	 *	node is freed.
	 */
	talloc_set_destructor(inst, _xlat_inst_detach);
	if (node->call.func->inst_size) {
		MEM(inst->data = talloc_zero_array(inst, uint8_t, node->call.func->inst_size));

		/*
		 *	This is expensive, only do it if we might
		 *	might be using it.
		 */
#ifndef TALLOC_GET_TYPE_ABORT_NOOP
		talloc_set_name_const(inst->data, node->call.func->inst_type);
#endif
	}

	return inst;
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
static int _xlat_instantiate_ephemeral_walker(xlat_exp_t *node, UNUSED void *uctx)
{
	fr_assert(!node->call.inst && !node->call.thread_inst);

	node->call.inst = xlat_inst_alloc(node);
	if (!node->call.inst) return -1;

	/*
	 *	Instantiate immediately unlike permanent XLATs
	 *	Where it's a separate phase.
	 */
	if (node->call.func->instantiate &&
	    (node->call.func->instantiate(node->call.inst->data, node, node->call.func->uctx) < 0)) {
	error:
		TALLOC_FREE(node->call.inst);
		return -1;
	}

	/*
	 *	Create a thread instance too.
	 */
	node->call.thread_inst = xlat_thread_inst_alloc(node, node->call.inst);
	if (!node->call.thread_inst) goto error;

	if (node->call.func->thread_instantiate &&
	    node->call.func->thread_instantiate(node->call.inst, node->call.thread_inst->data,
	    				   node, node->call.func->thread_uctx) < 0) goto error;

	/*
	 *	Mark this up as an ephemeral node, so the destructors
	 *	don't search for it in the xlat_inst_tree.
	 */
	node->call.ephemeral = true;

	return 0;
}

/** Create instance data for "ephemeral" xlats
 *
 * @note This must only be used for xlats created at runtime.
 *
 * @param[in] root of xlat tree to create instance data for.
 */
int xlat_instantiate_ephemeral(xlat_exp_t *root)
{
	return xlat_eval_walk(root, _xlat_instantiate_ephemeral_walker, XLAT_FUNC, NULL);
}

/** Walker callback for xlat_inst_tree
 *
 */
static int _xlat_thread_instantiate(void *data, void *uctx)
{
	xlat_thread_inst_t	*thread_inst;
	xlat_inst_t		*inst = talloc_get_type_abort(data, xlat_inst_t);

	thread_inst = xlat_thread_inst_alloc(uctx, data);
	if (!thread_inst) return -1;

	DEBUG3("Instantiating xlat \"%s\" node %p, instance %p, new thread instance %p",
	       inst->node->call.func->name, inst->node, inst, thread_inst);

	if (inst->node->call.func->thread_instantiate) {
		int ret;

		ret = inst->node->call.func->thread_instantiate(inst->data, thread_inst->data,
							   inst->node, inst->node->call.func->thread_uctx);
		if (ret < 0) {
			talloc_free(thread_inst);
			return -1;
		}
	}

	fr_rb_insert(xlat_thread_inst_tree, thread_inst);

	return 0;
}

/** Retrieve xlat/thread specific instance data
 *
 * @param[in] node to find thread specific data for.
 * @return
 *	- Thread specific data on success.
 *	- NULL if the xlat has no thread instance data (should not happen).
 */
xlat_thread_inst_t *xlat_thread_instance_find(xlat_exp_t const *node)
{
	xlat_thread_inst_t	*found;

	fr_assert(xlat_thread_inst_tree);
	fr_assert(node->type == XLAT_FUNC);

	if (node->call.ephemeral) return node->call.thread_inst;

	found = fr_rb_find(xlat_thread_inst_tree, &(xlat_thread_inst_t){ .node = node });
	fr_assert(found);

	return found;
}

/** Create thread specific instance tree and create thread instances
 *
 * This should be called directly after the modules_thread_instantiate() function.
 *
 * Memory will be freed automatically when the thread exits.
 *
 * @param[in] ctx	to bind instance tree lifetime to.  Must not be
 *			shared between multiple threads.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_thread_instantiate(TALLOC_CTX *ctx)
{
	fr_rb_iter_preorder_t	iter;
	void				*data;

	if (!xlat_inst_tree) return 0;

	if (!xlat_thread_inst_tree) {
		MEM(xlat_thread_inst_tree = fr_rb_talloc_alloc(ctx, xlat_thread_inst_t, inst_node,
								_xlat_thread_inst_cmp, _xlat_thread_inst_free, 0));
	}

	/*
	 *	Walk the inst tree, creating thread specific instances.
	 */
	for (data = fr_rb_iter_init_preorder(&iter, xlat_inst_tree);
	     data;
	     data = fr_rb_iter_next_preorder(&iter)) {
		if (_xlat_thread_instantiate(data, xlat_thread_inst_tree) < 0) {
			TALLOC_FREE(xlat_thread_inst_tree);
			fr_rb_iter_done(&iter);
			return -1;
		}
	}

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

/** Initialise the xlat inst code
 *
 */
static int xlat_instantiate_init(void)
{
	if (xlat_inst_tree) return 0;

	xlat_inst_tree = fr_rb_talloc_alloc(NULL, xlat_inst_t, inst_node,
					     _xlat_inst_cmp, _xlat_inst_free, RB_FLAG_NONE);
	if (!xlat_inst_tree) return -1;

	return 0;
}

/** Call instantiation functions for "permanent" xlats
 *
 * Should be called after module instantiation is complete.
 */
int xlat_instantiate(void)
{
	fr_rb_iter_preorder_t	iter;
	void				*data;

	if (!xlat_inst_tree) xlat_instantiate_init();

	for (data = fr_rb_iter_init_preorder(&iter, xlat_inst_tree);
	     data;
	     data = fr_rb_iter_next_preorder(&iter)) {
		xlat_inst_t *inst = talloc_get_type_abort(data, xlat_inst_t);

		if (inst->node->call.func->instantiate &&
		    (inst->node->call.func->instantiate(inst->data, inst->node, inst->node->call.func->uctx) < 0)) {
			fr_rb_iter_done(&iter);
			return -1;
		}
	}

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
	bool ret;

	fr_assert(node->type == XLAT_FUNC);
	fr_assert(!node->call.inst && !node->call.thread_inst);

	node->call.inst = xlat_inst_alloc(node);
	if (!node->call.inst) return -1;

	DEBUG3("Instantiating xlat \"%s\" node %p, new instance %p", node->call.func->name, node, node->call.inst);

	ret = fr_rb_insert(xlat_inst_tree, node->call.inst);
	if (!fr_cond_assert(ret)) {
		TALLOC_FREE(node->call.inst);
		return -1;
	}

	return 0;
}

static int _xlat_bootstrap_walker(xlat_exp_t *node, UNUSED void *uctx)
{
	return xlat_bootstrap_func(node);
}

/** Create instance data for "permanent" xlats
 *
 * @note This must only be used for xlats created during startup.
 *	 IF THIS IS CALLED FOR XLATS TOKENIZED AT RUNTIME YOU WILL LEAK LARGE AMOUNTS OF MEMORY.
 *	 USE xlat_instantiate_request() INSTEAD.
 *
 * @param[in] root of xlat tree to create instance data for.
 */
int xlat_bootstrap(xlat_exp_t *root)
{
	/*
	 *	If thread instantiate has been called, it's too late to
	 *	bootstrap new xlats.
	 */
	fr_assert(!xlat_thread_inst_tree);

	if (!xlat_inst_tree) xlat_instantiate_init();

	return xlat_eval_walk(root, _xlat_bootstrap_walker, XLAT_FUNC, NULL);
}

/** Walk over all registered instance data and free them explicitly
 *
 * This must be called before any modules or xlats are deregistered/unloaded and before
 * the mainconfig is freed, as the xlat_t need to still exist in order to call
 * the detach functions within them.
 */
void xlat_instances_free(void)
{
	TALLOC_FREE(xlat_inst_tree);
}
