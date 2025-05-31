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
 * @file unlang/map.h
 *
 * @copyright 2025 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/signal.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/unlang/interpret.h>

/** A callback when the request gets a fr_signal_t.
 *
 * @note The callback is automatically removed on unlang_interpret_mark_runnable().
 *
 * @param[in] mpctx		calling context for the map function.
 * @param[in] request		The current request.
 * @param[in] action		which is signalling the request.
 */
typedef void (*unlang_map_signal_t)(map_ctx_t const *mpctx, request_t *request, fr_signal_t action);

unlang_action_t unlang_map_yield(request_t *request,
				 map_proc_func_t resume, unlang_map_signal_t signal, fr_signal_t sigmask, void *rctx);
#ifdef __cplusplus
}
#endif
