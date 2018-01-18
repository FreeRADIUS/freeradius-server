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
 * @copyright 2018  The FreeRADIUS server project
 * @copyright 2018  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>

#include "xlat_priv.h"

/** Holds instance data created by xlat_instantiate
 */
static rbtree_t *xlat_inst_tree;

/** Holds thread specific instance data created by xlat_instantiate
 */
fr_thread_local_setup(rbtree_t *, xlat_thread_inst_tree)

/** Destructor for xlat_inst_t
 *
 * Calls detach method if provided by xlat expansion
 *
 * @note This cannot be converted to a talloc destructor,
 *	as we need to call thread_detach *before* any of the children
 *	of the talloc ctx are freed.
 */
static int _xlat_inst_free(xlat_inst_t *inst)
{
	rad_assert(inst->node->type == XLAT_FUNC);

	/*
	 *	Remove permanent data from the instance tree.
	 */
	if (!inst->node->ephemeral) rbtree_deletebydata(xlat_inst_tree, inst);

	if (inst->node->xlat->detach) (void) inst->node->xlat->detach(inst->data, inst->node->xlat->uctx);

	return 0;
}

/** Compare two xlat instances based on node pointer
 *
 * @param[in] a		First xlat expansion instance.
 * @param[in] b		Second xlat expansion instance.
 * @return
 *	- +1 if a > b.
 *	- -1 if a < b.
 *	- 0 if a == b.
 */
static int _xlat_inst_cmp(void const *a, void const *b)
{
	xlat_thread_inst_t const *my_a = a, *my_b = b;

	return (my_a->node > my_b->node) - (my_a->node < my_b->node);
}

/** Compare two thread instances based on node pointer
 *
 * @param[in] a		First thread specific xlat expansion instance.
 * @param[in] b		Second thread specific xlat expansion instance.
 * @return
 *	- +1 if a > b.
 *	- -1 if a < b.
 *	- 0 if a == b.
 */
static int _xlat_thread_inst_cmp(void const *a, void const *b)
{
	xlat_thread_inst_t const *my_a = a, *my_b = b;

	return (my_a->node > my_b->node) - (my_a->node < my_b->node);
}

/** Destructor for xlat_thread_inst_t
 *
 * Calls thread_detach method if provided by xlat expansion
 *
 * @note This cannot be converted to a talloc destructor,
 *	as we need to call thread_detach *before* any of the children
 *	of the talloc ctx are freed.
 */
static void _xlat_thread_inst_free(void *to_free)
{
	xlat_thread_inst_t *thread_inst = talloc_get_type_abort(to_free, xlat_thread_inst_t);

	rad_assert(thread_inst->node->type == XLAT_FUNC);

	if (thread_inst->node->xlat->thread_detach) {
		(void) thread_inst->node->xlat->thread_detach(thread_inst->data, thread_inst->node->xlat->uctx);
	}

	talloc_free(thread_inst);
}

/** Frees the thread local instance free and any thread local instance data
 *
 * @param[in] to_free	Thread specific module instance tree to free.
 */
static void _xlat_thread_inst_tree_free(void *to_free)
{
	rbtree_t *thread_inst_tree = talloc_get_type_abort(to_free , rbtree_t);

	talloc_free(thread_inst_tree);
}

/** Create thread instances where needed
 *
 * @param[in] node	to perform thread instantiation for.
 * @return
 *	- 0 on success.  The node/thread specific data will be inserted
 *	  into xlat_thread_inst_tree.
 *	- -1 on failure.
 */
static xlat_thread_inst_t *xlat_thread_inst_alloc(xlat_exp_t *node)
{
	xlat_thread_inst_t	*thread_inst = NULL;
	int			ret;

	(void)talloc_get_type_abort(node, xlat_exp_t);

	MEM(thread_inst = talloc_zero(NULL, xlat_thread_inst_t));
	thread_inst->node = node;

	rad_assert(node->type == XLAT_FUNC);
	rad_assert(!node->thread_inst);		/* May be missing inst, but this is OK */

	if (node->xlat->thread_inst_size) {
		MEM(thread_inst->data = talloc_zero_array(thread_inst, uint8_t, node->xlat->thread_inst_size));

		/*
		 *	This is expensive, only do it if we might
		 *	might be using it.
		 */
#ifndef TALLOC_GET_TYPE_ABORT_NOOP
		talloc_set_name(thread_inst, "%s_thread_inst_t", node->xlat->name);
#endif
	}

	if (node->xlat->thread_instantiate) {
		ret = node->xlat->thread_instantiate(node->inst, thread_inst->data, node, node->xlat->uctx);
		if (ret < 0) {
			talloc_free(thread_inst);
			return NULL;
		}
	}

	return thread_inst;
}

/** Walker callback for xlat_inst_tree
 *
 */
static int _xlat_thread_instantiate(UNUSED void *ctx, void *data)
{
	xlat_thread_inst_t	*thread_inst;

	thread_inst = xlat_thread_inst_alloc(data);
	if (!thread_inst) return -1;

	rbtree_insert(xlat_thread_inst_tree, thread_inst);

	return 0;
}

/** Create thread specific instance tree and create thread instances
 *
 * This should be called directly after the module_thread_instantiate function.
 *
 * Memory will be freed automatically when the thread exits.
 */
int xlat_thread_instantiate(void)
{
	int ret;

	if (!xlat_thread_inst_tree) {
		MEM(xlat_thread_inst_tree = rbtree_create(NULL, _xlat_thread_inst_cmp, _xlat_thread_inst_free, 0));
		fr_thread_local_set_destructor(xlat_thread_inst_tree,
					       _xlat_thread_inst_tree_free, xlat_thread_inst_tree);
	}

	/*
	 *	Walk the inst tree, creating thread
	 *	specific instances.
	 */
	ret = rbtree_walk(xlat_inst_tree, RBTREE_PRE_ORDER, _xlat_thread_instantiate, NULL);
	if (ret < 0) {
		TALLOC_FREE(xlat_thread_inst_tree);	/* Destroy the thread_inst_tree if instantiation fails */
		return -1;
	}

	return 0;
}

/** Allocate instance data for an xlat expansion
 *
 * @param[in] node	to allocate instance data for.
 */
static xlat_inst_t *xlat_inst_alloc(xlat_exp_t *node)
{
	xlat_inst_t		*inst = NULL;

	rad_assert(xlat_inst_tree);		/* xlat_inst_init must have been called */
	rad_assert(node->type == XLAT_FUNC);
	rad_assert(!node->inst);

	/*
	 *	Instance data is freed when the
	 *	node is freed.
	 */
	MEM(inst = talloc_zero(node, xlat_inst_t));
	talloc_set_destructor(inst, _xlat_inst_free);

	if (node->xlat->inst_size) {
		MEM(inst->data = talloc_zero_array(inst, uint8_t, node->xlat->inst_size));

		/*
		 *	This is expensive, only do it if we might
		 *	might be using it.
		 */
#ifndef TALLOC_GET_TYPE_ABORT_NOOP
		talloc_set_name(inst, "%s_inst_t", node->xlat->name);
#endif
	}

	if (node->xlat->instantiate) {
		int ret;

		ret = node->xlat->instantiate(inst->data, node, node->xlat->uctx);
		if (ret < 0) {
			talloc_free(inst);
			return NULL;
		}
	}

	return inst;
}

/** Callback for creating "ephemeral" instance data for a #xlat_exp_t
 *
 * @param[in] node	to create "ephemeral" instance data for.
 * @param[in] uctx	UNUSED.
 * @return
 *	- 0 if instantiation functions were successful.
 *	- -1 if either instantiation function failed.
 */
static int _xlat_instantiate_request_walker(xlat_exp_t *node, UNUSED void *uctx)
{
	rad_assert(!node->inst && !node->thread_inst);

	node->inst = xlat_inst_alloc(node);
	if (!node->inst) return -1;

	node->thread_inst = xlat_thread_inst_alloc(node);
	if (!node->thread_inst) {
		TALLOC_FREE(node->inst);
		return -1;
	}

	return 0;
}

/** Create instance data for "ephemeral" xlats
 *
 * @node This must only be used for xlats created at runtime.
 *
 * @param[in] root of xlat tree to create instance data for.
 */
int xlat_instatiate_request(xlat_exp_t *root)
{
	return xlat_eval_walk(root, _xlat_instantiate_request_walker, XLAT_FUNC, NULL);
}

/** Callback for creating "permanent" instance data for a #xlat_exp_t
 *
 * @param[in] node	to create "permanent" instance data for.
 * @param[in] uctx	UNUSED.
 * @return
 *	- 0 if instantiation functions were successful.
 *	- -1 if either instantiation function failed.
 */
static int _xlat_instantiate_walker(xlat_exp_t *node, UNUSED void *uctx)
{
	xlat_thread_inst_t *thread_inst;
	bool ret;

	rad_assert(!node->inst && !node->thread_inst);

	node->inst = xlat_inst_alloc(node);
	if (!node->inst) return -1;

	thread_inst = xlat_thread_inst_alloc(node);
	if (!thread_inst) {
		TALLOC_FREE(node->inst);
		return -1;
	}

	ret = rbtree_insert(xlat_inst_tree, node->inst);
	if (!fr_cond_assert(ret)) {
	insert_error:
		TALLOC_FREE(node->inst);
		talloc_free(thread_inst);
		return -1;
	}

	ret = rbtree_insert(xlat_thread_inst_tree, thread_inst);
	if (!ret) goto insert_error;

	return 0;
}

/** Create instance data for "permanent" xlats
 *
 * @note This must only be used for xlats created during startup.
 *	 IF THIS IS CALLED FOR XLATS TOKENIZED AT RUNTIME YOU WILL LEAK LARGE AMOUNTS OF MEMORY.
 *	 USE #xlat_instantiate_request INSTEAD.
 *
 * @param[in] root of xlat tree to create instance data for.
 */
int xlat_instantiate(xlat_exp_t *root)
{
	return xlat_eval_walk(root, _xlat_instantiate_walker, XLAT_FUNC, NULL);
}

/** Initialise the xlat inst code
 *
 * Call xlat_inst_free when done.
 */
int xlat_inst_init(void)
{
	if (xlat_inst_tree) return 0;

	xlat_inst_tree = rbtree_create(NULL, _xlat_inst_cmp, NULL, RBTREE_FLAG_NONE);
	if (!xlat_inst_tree) return -1;

	return 0;
}

/** Free the main xlat instance tree
 *
 * @note Will not free thread/expansion specific data.  This will be freed as threads
 *	 exit.
 */
void xlat_inst_free(void)
{
	/*
	 *	All xlat_exp_t should have been freed
	 *	before xlat_inst_free is called.
	 */
	rad_assert(rbtree_num_elements(xlat_inst_tree) == 0);
	talloc_free(xlat_inst_tree);
}
