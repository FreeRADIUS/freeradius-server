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
 * @file lib/unlang/xlat_ctx.h
 * @brief xlat ephemeral argument passing structures
 *
 * @copyright 2021 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(xlat_ctx_h, "$Id$")

#include <freeradius-devel/server/module_ctx.h>

#ifdef __cplusplus
extern "C" {
#endif

/* So we don't need to include xlat.h */
typedef struct xlat_exp_s xlat_exp_t;
typedef struct xlat_exp_head_s xlat_exp_head_t;

/** An xlat calling ctx
 *
 * This provides optional arguments to xlat functions.
 */
typedef struct {
	void const			*inst;			//!< xlat instance data.
	void				*thread;		//!< xlat threadinstance data.
	module_ctx_t const		*mctx;			//!< Synthesised module calling ctx.
	void				*rctx;			//!< Resume context.
} xlat_ctx_t;

/** An xlat instantiation ctx
 *
 * This provides optional arguments to xlat functions.
 */
typedef struct {
	void				*inst;			//!< xlat instance data to populate.
	xlat_exp_t 			*ex;			//!< Tokenized expression to use in expansion.
	module_inst_ctx_t const		*mctx;			//!< Synthesised module calling ctx.
	void				*uctx;			//!< Passed to the registration function.
} xlat_inst_ctx_t;

/** An xlat thread instantiation ctx
 *
 * This provides optional arguments to xlat functions.
 */
typedef struct {
	void const			*inst;			//!< xlat instance data.
	void				*thread;		//!< xlat thread instance data to populate.
	xlat_exp_t const 		*ex;			//!< Tokenized expression to use in expansion.
	module_ctx_t const		*mctx;			//!< Synthesised module calling ctx.
	fr_event_list_t			*el;			//!< To register any I/O handlers or timers against.
	void				*uctx;			//!< Passed to the registration function.
} xlat_thread_inst_ctx_t;

/** Wrapper to create a xlat_ctx_t as a compound literal
 *
 * This is used so that the compiler will flag any uses of (xlat_ctx_t)
 * which don't set the required fields.  Additional arguments should be added
 * to this macro whenever the xlat_ctx_t fields are altered.
 *
 * @param[in] _inst	Instance data of the module being called.
 * @param[in] _thread 	Instance data of the thread being called.
 * @param[in] _mctx	Module ctx.
 * @param[in] _rctx	resume ctx data.
 */
#define XLAT_CTX(_inst, _thread, _mctx, _rctx) &(xlat_ctx_t){ .inst = _inst, .thread = _thread, .mctx = _mctx, .rctx = _rctx }

/** Wrapper to create a xlat_inst_ctx_t as a compound literal
 *
 * This is used so that the compiler will flag any uses of (xlat_inst_ctx_t)
 * which don't set the required fields.  Additional arguments should be added
 * to this macro whenever the xlat_inst_ctx_t fields are altered.
 *
 * @param[in] _inst	Instance data of the module being called.
 * @param[in] _ex 	xlat expression to be evaluated by the instantiation function.
 * @param[in] _mctx	The module_inst_ctx_t from the parent module (if any).
 * @param[in] _uctx	passed when the instantiation function was registered.
 */
#define XLAT_INST_CTX(_inst, _ex, _mctx, _uctx) &(xlat_inst_ctx_t){ .inst = _inst, .ex = _ex, .mctx = _mctx, .uctx = _uctx }

/** Wrapper to create a xlat_thread_inst_ctx_t as a compound literal
 *
 * This is used so that the compiler will flag any uses of (xlat_thread_inst_ctx_t)
 * which don't set the required fields.  Additional arguments should be added
 * to this macro whenever the xlat_thread_inst_ctx_t fields are altered.
 *
 * @param[in] _inst	Instance data of the module being called.
 * @param[in] _thread	Instance data of the thread being called.
 * @param[in] _ex 	xlat expression to be evaluated by the instantiation function.
 * @param[in] _mctx	The module_inst_ctx_t from the parent module (if any).
 * @param[in] _el	To register any I/O handlers or timers against.
 * @param[in] _uctx	passed when the instantiation function was registered.
 */
#define XLAT_THREAD_INST_CTX(_inst, _thread, _ex, _mctx, _el, _uctx) &(xlat_thread_inst_ctx_t){ .inst = _inst, .ex = _ex, .mctx = _mctx, .el = _el, .uctx = _uctx }

#ifdef __cplusplus
}
#endif
