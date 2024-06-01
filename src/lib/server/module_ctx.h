#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/server/module_ctx.h
 * @brief Temporary argument structures for module calls.
 *
 * These get used in various places where we may not want to include
 * the full module.h.
 *
 * @copyright 2021 Arran Cudbard-bell <a.cudbardb@freeradius.org>
 */
RCSIDH(module_ctx_h, "$Id$")

#include <freeradius-devel/util/event.h>

#ifdef __cplusplus
extern "C" {
#endif
typedef struct module_instance_s module_instance_t;

/** Temporary structure to hold arguments for module calls
 *
 */
typedef struct {
	module_instance_t const		*mi;		//!< Instance of the module being instantiated.
	void				*thread;	//!< Thread specific instance data.
	void				*env_data;	//!< Per call environment data.
	void				*rctx;		//!< Resume ctx that a module previously set.
} module_ctx_t;

/** Temporary structure to hold arguments for instantiation calls
 */
typedef struct {
	module_instance_t		*mi;		//!< Instance of the module being instantiated.
} module_inst_ctx_t;

/** Temporary structure to hold arguments for detach calls
 */
typedef struct {
	module_instance_t		*mi;		//!< Module instance to detach.
} module_detach_ctx_t;

/** Temporary structure to hold arguments for thread_instantiation calls
 *
 */
typedef struct {
	module_instance_t const		*mi;		//!< Instance of the module being instantiated.
							///< Must come first to allow cast between
							///< module_inst_ctx.
	void				*thread;	//!< Thread instance data.
	fr_event_list_t			*el;		//!< Event list to register any IO handlers
							///< and timers against.
} module_thread_inst_ctx_t;

DIAG_OFF(unused-function)
/** Allocate a module calling ctx on the heap based on an instance ctx
 *
 */
static module_ctx_t *module_ctx_from_inst(TALLOC_CTX *ctx, module_inst_ctx_t const *mctx)
{
	module_ctx_t *nmctx;

	nmctx = talloc_zero(ctx, module_ctx_t);
	if (unlikely(!nmctx)) return NULL;
	nmctx->mi = mctx->mi;

	return nmctx;
}

/** Allocate a module calling ctx on the heap based on an instance ctx
 *
 */
static module_ctx_t *module_ctx_from_thread_inst(TALLOC_CTX *ctx, module_thread_inst_ctx_t const *mctx)
{
	module_ctx_t *nmctx;

	nmctx = talloc_zero(ctx, module_ctx_t);
	if (unlikely(!nmctx)) return NULL;
	nmctx->mi = mctx->mi;
	nmctx->thread = mctx->thread;

	return nmctx;
}

/** Duplicate a stack based module_ctx_t on the heap
 *
 */
static module_ctx_t *module_ctx_dup(TALLOC_CTX *ctx, module_ctx_t const *mctx)
{
	module_ctx_t *nmctx;

	nmctx = talloc_zero(ctx, module_ctx_t);
	if (unlikely(!nmctx)) return NULL;
	memcpy(nmctx, mctx, sizeof(*nmctx));

	return nmctx;
}
DIAG_ON(unused-function)

/** Wrapper to create a module_ctx_t as a compound literal
 *
 * This is used so that the compiler will flag any uses of (module_ctx_t)
 * which don't set the required fields.  Additional arguments should be added
 * to this macro whenever the module_ctx_t fields are altered.
 *
 * @param[in] _mi	of the module being called.
 * @param[in] _thread 	instance of the module being called.
 * @param[in] _env_data	Call environment data.
 * @param[in] _rctx	Resume ctx (if any).
 */
#define MODULE_CTX(_mi, _thread, _env_data, _rctx) &(module_ctx_t){ .mi = _mi, .thread = _thread, .env_data = _env_data, .rctx = _rctx }

/** Wrapper to create a module_ctx_t as a compound literal from a module_inst_ctx_t
 *
 * This is used so that the compiler will flag any uses of (module_ctx_t)
 * which don't set the required fields.  Additional arguments should be added
 * to this macro whenever the module_ctx_t fields are altered.
 *
 * @param[in] _mctx	to copy fields from.
 */
#define MODULE_CTX_FROM_INST(_mctx) &(module_ctx_t){ .mi = (_mctx)->mi }

/** Wrapper to create a module_ctx_t as a compound literal from a module_inst_ctx_t
 *
 * This is used so that the compiler will flag any uses of (module_ctx_t)
 * which don't set the required fields.  Additional arguments should be added
 * to this macro whenever the module_ctx_t fields are altered.
 *
 * @param[in] _mctx	to copy fields from.
 */
#define MODULE_CTX_FROM_THREAD_INST(_mctx) &(module_ctx_t){ .mi = (_mctx)->mi, .thread = (_mctx)->thread, .env_data = (_mctx)->env_data }

/** Wrapper to create a module_inst_ctx_t as a compound literal
 *
 * This is used so that the compiler will flag any uses of (module_inst_ctx_t)
 * which don't set the required fields.  Additional arguments should be added
 * to this macro whenever the module_inst_ctx_t fields are altered.
 *
 * @param[in] _mi	of the module being called..
 */
#define MODULE_INST_CTX(_mi) &(module_inst_ctx_t){ .mi = _mi }

/** Wrapper to create a module_detach_ctx_t as a compound literal
 *
 * @param[in] _mi	of the module being called..
 */
#define MODULE_DETACH_CTX(_mi) &(module_detach_ctx_t){ .mi = _mi }

/** Wrapper to create a module_thread_inst_ctx_t as a compound literal
 *
 * This is used so that the compiler will flag any uses of (module_thread_inst_ctx_t)
 * which don't set the required fields.  Additional arguments should be added
 * to this macro whenever the module_thread_inst_ctx_t fields are altered.
 *
 * @param[in] _mi	of the module being called.
 * @param[in] _thread 	instance of the module being called.
 * @param[in] _el	Thread specific event list.
 */
#define MODULE_THREAD_INST_CTX(_mi, _thread, _el) &(module_thread_inst_ctx_t){ .mi = _mi, .thread = _thread, .el = _el }

/** Wrapper to create a module_inst_ctx_t as a comound listeral from a module_thread_ctx_t
 *
 * Extract the module_instance_t from a module_thread_inst_ctx_t.
 *
 * @param[in] _mctx	to extract module_thread_inst_ctx_t from.
 */
#define MODULE_THREAD_INST_CTX_FROM_INST_CTX(_mctx) &(module_ctx_t){ .mi = (_mctx)->mi }

#ifdef __cplusplus
}
#endif
