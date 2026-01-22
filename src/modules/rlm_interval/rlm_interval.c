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
 * @file rlm_interval.c
 * @brief Interval limiting module providing an xlat function.
 *
 * @copyright 2026 The FreeRADIUS server project
 * @copyright 2026 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/main_loop.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/slab.h>
#include <freeradius-devel/util/timer.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/strerror.h>

#include <pthread.h>

typedef enum {
	INTERVAL_SCOPE_GLOBAL = 0,
	INTERVAL_SCOPE_THREAD
} rlm_interval_scope_t;

static fr_table_num_sorted_t const interval_scope_table[] = {
	{ L("global"),	INTERVAL_SCOPE_GLOBAL },
	{ L("thread"),	INTERVAL_SCOPE_THREAD }
};
static size_t interval_scope_table_len = NUM_ELEMENTS(interval_scope_table);

/** RBTree entry for keyed lookups
 */
typedef struct {
	fr_rb_node_t		node;		//!< RBTree node.
	fr_value_box_t		key;		//!< Key stored in value box.
	fr_timer_t		*ev;		//!< Expiry timer.
	void			*owner;		//!< Back-pointer to mutable_t or thread_t.
} rlm_interval_entry_t;

FR_SLAB_TYPES(interval, rlm_interval_entry_t)
FR_SLAB_FUNCS(interval, rlm_interval_entry_t)

/** Mutable data for global scope (allocated outside mprotected instance data)
 */
typedef struct {
	fr_rb_tree_t		*tree;		//!< RBTree for keyed lookups.
	pthread_mutex_t		mutex;		//!< Mutex for thread safety.
} rlm_interval_mutable_t;

/** Module instance data
 */
typedef struct {
	rlm_interval_scope_t	scope;		//!< Global or thread-local scope.
	fr_slab_config_t	reuse;		//!< Slab allocator configuration.
	rlm_interval_mutable_t	*mutable;	//!< Mutable data for global scope.
} rlm_interval_t;

/** Module thread instance data
 */
typedef struct {
	fr_rb_tree_t		*tree;		//!< RBTree for keyed lookups (thread scope only).
	fr_timer_list_t		*tl;		//!< Timer list for entry expiry.
	interval_slab_list_t	*slab;		//!< Slab allocator for entries.
} rlm_interval_thread_t;

/** Xlat instance data - stores the xlat expression pointer for keyless lookups
 */
typedef struct {
	xlat_exp_t const	*ex;		//!< Cached for keyless lookups.
} rlm_interval_xlat_inst_t;

/** Xlat thread instance data - stores last_used for keyless thread-scope lookups
 */
typedef struct {
	fr_time_t		last_used;	//!< Last used time for this call site.
} rlm_interval_xlat_thread_inst_t;

static conf_parser_t reuse_config[] = {
	FR_SLAB_CONFIG_CONF_PARSER
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("scope", rlm_interval_t, scope),
	  .func = cf_table_parse_int,
	  .uctx = &(cf_table_parse_ctx_t){ .table = interval_scope_table, .len = &interval_scope_table_len },
	  .dflt = "global" },
	{ FR_CONF_OFFSET_SUBSECTION("reuse", 0, rlm_interval_t, reuse, reuse_config) },
	CONF_PARSER_TERMINATOR
};

static xlat_arg_parser_t const interval_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_TIME_DELTA },
	{ .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

static int8_t interval_entry_cmp(void const *one, void const *two)
{
	rlm_interval_entry_t const *a = one;
	rlm_interval_entry_t const *b = two;
	int8_t ret;

	ret = CMP(a->key.type, b->key.type);
	if (ret != 0) return ret;

	return fr_value_box_cmp(&a->key, &b->key);
}

/** Timer callback to expire entries (thread scope)
 */
static void interval_expire_thread(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	rlm_interval_entry_t	*entry = uctx;
	rlm_interval_thread_t	*thread = talloc_get_type_abort(entry->owner, rlm_interval_thread_t);

	(void)fr_rb_delete_by_inline_node(thread->tree, &entry->node);
	interval_slab_release(entry);
}

/** Timer callback to expire entries (global scope)
 */
static void interval_expire_global(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	rlm_interval_entry_t	*entry = uctx;
	rlm_interval_mutable_t	*mutable = talloc_get_type_abort(entry->owner, rlm_interval_mutable_t);

	pthread_mutex_lock(&mutable->mutex);
	(void)fr_rb_delete_by_inline_node(mutable->tree, &entry->node);
	pthread_mutex_unlock(&mutable->mutex);

	interval_slab_release(entry);
}

/** Check interval limit
 *
 * @note Don't be tempted to move mutex handling in here.  Yes you could probably reduce
 *       the size of the critical region, but you're going to break something and miss
 *	 interaction effects.  Just don't do it.
 *
 * @param[in] tree	RBTree for lookups.
 * @param[in] thread	Thread instance (for timer list and slab).
 * @param[in] owner	Back-pointer to store in new entries (for expiry callback).
 * @param[in] expire	Expiry callback function.
 * @param[in] find	Entry with key to search for.
 * @param[in] interval	Interval limit interval.
 * @return
 *	- 1 if allowed.
 *	- 0 if interval limited.
 *	- -1 on error.
 */
static int interval_check(fr_rb_tree_t *tree, rlm_interval_thread_t *thread,
			  void *owner, fr_timer_cb_t expire,
			  rlm_interval_entry_t *find, fr_time_delta_t interval)
{
	rlm_interval_entry_t *entry;

	entry = fr_rb_find(tree, find);
	if (!entry) {
		entry = interval_slab_reserve(thread->slab);
		if (!entry) return -1;

		fr_value_box_copy_shallow(entry, &entry->key, &find->key);

		entry->owner = owner;

		if (unlikely(fr_rb_insert(tree, entry) == false)) {
			fr_strerror_const("Insertion failed - duplicate key?");
		error:
			interval_slab_release(entry);
			return -1;
		}

		if (unlikely(fr_timer_in(entry, thread->tl, &entry->ev, interval, true, expire, entry) < 0)) goto error;
		return 1;
	}

	/*
	 *	Entry exists - check if interval limited.
	 *	Timer loop doesn't run immediately, so check the scheduled
	 *	fire time rather than just whether it's armed.
	 */
	if (fr_timer_armed(entry->ev) && fr_time_gt(fr_timer_when(entry->ev), fr_time())) return 0;

	/*
	 *	Timer expired (or wasn't set), reset it
	 */
	if (unlikely(fr_timer_in(entry, thread->tl, &entry->ev, interval, true, expire, entry) < 0)) {
		fr_rb_delete(tree, entry);
		return -1;
	}

	return 1;
}

/** Global scope xlat - always uses mutex-protected tree
 */
static xlat_action_t interval_xlat_global(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   xlat_ctx_t const *xctx,
					   request_t *request, fr_value_box_list_t *in)
{
	rlm_interval_t const		*inst = talloc_get_type_abort_const(xctx->mctx->mi->data, rlm_interval_t);
	rlm_interval_thread_t		*thread = talloc_get_type_abort(xctx->mctx->thread, rlm_interval_thread_t);
	rlm_interval_xlat_inst_t const	*xlat_inst = xctx->inst;

	fr_value_box_t			*interval, *key, *result;
	rlm_interval_entry_t		find = {};
	int				ret;

	XLAT_ARGS(in, &interval, &key);

	/*
	 *	Set up the find key - either string key or xlat expression pointer
	 */
	if (!key) {
		fr_value_box_set_void_shallow(&find.key, xlat_inst->ex);
	} else {
		fr_value_box_copy_shallow(NULL, &find.key, key);
	}

	pthread_mutex_lock(&inst->mutable->mutex);
	ret = interval_check(inst->mutable->tree, thread, inst->mutable, interval_expire_global,
			     &find, interval->vb_time_delta);
	pthread_mutex_unlock(&inst->mutable->mutex);

	MEM(result = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	switch (ret) {
	case 1:
		RDEBUG3("Interval passed");
		result->vb_bool = true;
		break;

	case 0:
		RDEBUG3("Within interval");
		result->vb_bool = false;
		break;

	default:
		fr_assert_msg(false, "interval_check failed in global scope xlat: %s", fr_strerror());
		result->vb_bool = true;		/* Allow on error */
		break;
	}

	fr_dcursor_append(out, result);
	return XLAT_ACTION_DONE;
}

/** Thread scope xlat - uses thread-local tree or module thread instance
 */
static xlat_action_t interval_xlat_thread(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   xlat_ctx_t const *xctx,
					   request_t *request, fr_value_box_list_t *in)
{
	rlm_interval_thread_t			*thread = talloc_get_type_abort(xctx->mctx->thread, rlm_interval_thread_t);
	rlm_interval_xlat_thread_inst_t	*xlat_thread = xctx->thread;

	fr_value_box_t				*interval, *key, *result;
	int					ret;

	XLAT_ARGS(in, &interval, &key);

	if (!key) {
		/*
		 *	Keyless: use xlat thread instance directly - no tree lookup needed
		 */
		fr_time_t now = fr_time();

		if (fr_time_gt(fr_time_add(xlat_thread->last_used, interval->vb_time_delta), now)) {
			ret = 0;
		} else {
			xlat_thread->last_used = now;
			ret = 1;
		}
	} else {
		/*
		 *	Keyed: use thread-local tree
		 */
		rlm_interval_entry_t find = {};

		fr_value_box_copy_shallow(NULL, &find.key, key);

		ret = interval_check(thread->tree, thread, thread, interval_expire_thread,
				     &find, interval->vb_time_delta);
	}

	MEM(result = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));

	switch (ret) {
	case 1:
		RDEBUG3("Interval passed");
		result->vb_bool = true;
		break;

	case 0:
		RDEBUG3("Within interval");
		result->vb_bool = false;
		break;

	default:
		fr_assert_msg(false, "interval_check failed in thread scope xlat: %s", fr_strerror());
		result->vb_bool = true;		/* Allow on error */
		break;
	}

	fr_dcursor_append(out, result);
	return XLAT_ACTION_DONE;
}

static int interval_xlat_instantiate(xlat_inst_ctx_t const *xctx)
{
	rlm_interval_xlat_inst_t *xlat_inst = xctx->inst;

	xlat_inst->ex = xctx->ex;
	return 0;
}

static int interval_xlat_thread_instantiate(xlat_thread_inst_ctx_t const *xctx)
{
	rlm_interval_xlat_thread_inst_t *xlat_thread = xctx->thread;

	/*
	 *	Initialize to "never used" so first check always allows.
	 *	fr_time() is relative to server start, not Unix epoch.
	 */
	xlat_thread->last_used = fr_time_min();
	return 0;
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_interval_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_interval_t);
	rlm_interval_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_interval_thread_t);

	/*
	 *	Always need a thread-local timer list and slab, even for global scope,
	 *	because timer lists and talloc aren't thread-safe.
	 *
	 *	Use lst (heap) not ordered (dlist) because timers aren't
	 *	inserted in chronological order.
	 */
	t->tl = fr_timer_list_lst_alloc(t, mctx->el->tl);
	if (!t->tl) {
		ERROR("Failed to create thread-local timer list");
		return -1;
	}

	t->slab = interval_slab_list_alloc(t, mctx->el, &inst->reuse,
					    NULL, NULL, NULL,
					    true, false);
	if (!t->slab) {
		ERROR("Failed to create thread-local slab allocator");
		return -1;
	}

	if (inst->scope == INTERVAL_SCOPE_THREAD) {
		t->tree = fr_rb_inline_talloc_alloc(t, rlm_interval_entry_t, node,
						    interval_entry_cmp, NULL);
		if (!t->tree) {
			ERROR("Failed to create thread-local rbtree");
			return -1;
		}
	}

	return 0;
}

static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_interval_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_interval_t);

	if (inst->mutable) {
		pthread_mutex_destroy(&inst->mutable->mutex);
		talloc_free(inst->mutable);
	}

	return 0;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_interval_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_interval_t);

	if (inst->scope == INTERVAL_SCOPE_GLOBAL) {
		MEM(inst->mutable = talloc_zero(NULL, rlm_interval_mutable_t));

		inst->mutable->tree = fr_rb_inline_talloc_alloc(inst->mutable, rlm_interval_entry_t, node,
								interval_entry_cmp, NULL);
		if (!inst->mutable->tree) {
			ERROR("Failed to create rbtree");
			talloc_free(inst->mutable);
			return -1;
		}

		MEM(pthread_mutex_init(&inst->mutable->mutex, NULL) == 0);
	}

	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_interval_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_interval_t);
	xlat_t		*xlat;

	/*
	 *	Register scope-specific xlat function
	 */
	switch (inst->scope) {
	case INTERVAL_SCOPE_GLOBAL:
		xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, NULL, interval_xlat_global, FR_TYPE_BOOL);
		if (!xlat) {
		registration_error:
			ERROR("Failed to register xlat function");
			return -1;
		}
		break;

	case INTERVAL_SCOPE_THREAD:
		xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, NULL, interval_xlat_thread, FR_TYPE_BOOL);
		if (!xlat) goto registration_error;
		if (xlat) {
			xlat_func_thread_instantiate_set(xlat, interval_xlat_thread_instantiate,
							 rlm_interval_xlat_thread_inst_t, NULL, NULL);
		}
		break;
	}

	xlat_func_args_set(xlat, interval_xlat_args);
	xlat_func_instantiate_set(xlat, interval_xlat_instantiate, rlm_interval_xlat_inst_t, NULL, NULL);

	return 0;
}

extern module_rlm_t rlm_interval;
module_rlm_t rlm_interval = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "interval",
		.inst_size		= sizeof(rlm_interval_t),
		.thread_inst_size	= sizeof(rlm_interval_thread_t),
		.config			= module_config,
		.bootstrap		= mod_bootstrap,
		.instantiate		= mod_instantiate,
		.detach			= mod_detach,
		.thread_instantiate	= mod_thread_instantiate,
	}
};
