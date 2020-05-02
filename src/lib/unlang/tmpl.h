#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/**
 * $Id$
 *
 * @file unlang/tmpl.h
 *
 * @brief Functions to allow tmpls to push resumption frames onto the stack
 *	  and inform the interpreter about the conditions they need to be
 *	  resumed under (usually an I/O event or timer event).
 *
 * @copyright 2016-2019 The FreeRADIUS server project
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/unlang/tmpl.h>

/** A callback when the request gets a fr_state_signal_t.
 *
 * A module may call unlang_yeild(), but still need to do something on FR_SIGNAL_DUP.  If so, it's
 * set here.
 *
 * @note The callback is automatically removed on unlang_interpret_resumable().
 *
 * @param[in] rctx		Resume ctx for the callback.
 * @param[in] request		The current request.
 * @param[in] action		which is signalling the request.
 */
typedef void (*fr_unlang_tmpl_signal_t)(REQUEST *request, void *rctx, fr_state_signal_t action);

/** A callback for when the request is resumed.
 *
 * The resumed request cannot call the normal "authorize", etc. method.  It needs a separate callback.
 *
 * @param[in] request		the current request.
 * @param[in] rctx		a local context for the callback.
 * @return a normal rlm_rcode_t.
 */
typedef rlm_rcode_t (*fr_unlang_tmpl_resume_t)(REQUEST *request, void *rctx);

void		unlang_tmpl_push(TALLOC_CTX *ctx, fr_value_box_t **out, REQUEST *request, vp_tmpl_t const *tmpl, VALUE_PAIR *vps, int *status);

#ifdef __cplusplus
}
#endif
