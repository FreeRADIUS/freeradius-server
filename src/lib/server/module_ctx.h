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
 * @file lib/server/module_call_ctx.h
 * @brief Temporary argument structures for module calls.
 *
 * These get used in various places where we may not want to include
 * the full module.h.
 *
 * @copyright 2021 Arran Cudbard-bell <a.cudbardb@freeradius.org>
 */
RCSIDH(module_ctx_h, "$Id$")

#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/util/event.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Temporary structure to hold arguments for module calls
 *
 */
typedef struct {
	dl_module_inst_t const		*inst;		//!< Dynamic loader API handle for the module.
	void				*thread;	//!< Thread specific instance data.
	void				*rctx;		//!< Resume ctx that a module previously set.
} module_ctx_t;

/** Temporary structure to hold arguments for instantiation calls
 *
 */
typedef struct {
	dl_module_inst_t const		*inst;		//!< Dynamic loader API handle for the module.
} module_inst_ctx_t;

/** Temporary structure to hold arguments for thread_instantiation calls
 *
 */
typedef struct {
	dl_module_inst_t const		*inst;		//!< Dynamic loader API handle for the module.
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
	nmctx->inst = mctx->inst;

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
	nmctx->inst = mctx->inst;
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
 * @param[in] _dl_inst	of the module being called.
 * @param[in] _thread 	instance of the module being called.
 * @param[in] _rctx	Resume ctx (if any).
 */
#define MODULE_CTX(_dl_inst, _thread, _rctx) &(module_ctx_t){ .inst = _dl_inst, .thread = _thread, .rctx = _rctx }

/** Wrapper to create a module_ctx_t as a compound literal from a module_inst_ctx_t
 *
 * This is used so that the compiler will flag any uses of (module_ctx_t)
 * which don't set the required fields.  Additional arguments should be added
 * to this macro whenever the module_ctx_t fields are altered.
 *
 * @param[in] _mctx	to copy fields from.
 */
#define MODULE_CTX_FROM_INST(_mctx) &(module_ctx_t){ .inst = (_mctx)->inst }

/** Wrapper to create a module_ctx_t as a compound literal from a module_inst_ctx_t
 *
 * This is used so that the compiler will flag any uses of (module_ctx_t)
 * which don't set the required fields.  Additional arguments should be added
 * to this macro whenever the module_ctx_t fields are altered.
 *
 * @param[in] _mctx	to copy fields from.
 */
#define MODULE_CTX_FROM_THREAD_INST(_mctx) &(module_ctx_t){ .inst = (_mctx)->inst, .thread = (_mctx)->thread }

/** Wrapper to create a module_inst_ctx_t as a compound literal
 *
 * This is used so that the compiler will flag any uses of (module_inst_ctx_t)
 * which don't set the required fields.  Additional arguments should be added
 * to this macro whenever the module_inst_ctx_t fields are altered.
 *
 * @param[in] _dl_inst	of the module being called..
 */
#define MODULE_INST_CTX(_dl_inst) &(module_inst_ctx_t){ .inst = _dl_inst }

/** Wrapper to create a module_thread_inst_ctx_t as a compound literal
 *
 * This is used so that the compiler will flag any uses of (module_thread_inst_ctx_t)
 * which don't set the required fields.  Additional arguments should be added
 * to this macro whenever the module_thread_inst_ctx_t fields are altered.
 *
 * @param[in] _dl_inst	of the module being called.
 * @param[in] _thread 	instance of the module being called.
 * @param[in] _el	Thread specific event list.
 */
#define MODULE_THREAD_INST_CTX(_dl_inst, _thread, _el) &(module_thread_inst_ctx_t){ .inst = _dl_inst, .thread = _thread, .el = _el }

/** Wrapper to create a module_inst_ctx_t as a comound listeral from a module_thread_ctx_t
 *
 * Extract the dl_module_inst_t from a module_thread_inst_ctx_t.
 *
 * @param[in] _mctx	to extract module_thread_inst_ctx_t from.
 */
#define MODULE_THREAD_INST_CTX_FROM_INST_CTX(_mctx) &(module_ctx_t){ .inst = (_mctx)->inst }

#ifdef __cplusplus
}
#endif
