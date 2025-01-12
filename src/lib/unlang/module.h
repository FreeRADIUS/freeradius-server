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
 * @file unlang/module.h
 *
 * @brief Functions to allow modules to push resumption frames onto the stack
 *	  and inform the interpreter about the conditions they need to be
 *	  resumed under (usually an I/O event or timer event).
 *
 * @copyright 2016-2019 The FreeRADIUS server project
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/unlang/subrequest.h>
#include <freeradius-devel/unlang/tmpl.h>

/** A callback when a retry happens
 *
 * Used when a module needs wait for an event.
 * Typically the callback is set, and then the module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_interpret_mark_runnable(), i.e. if an event
 *	on a registered FD occurs before the timeout event fires.
 *
 * @param[in] mctx		calling context for the module.
 *				Contains global, thread-specific, and call-specific data for a module.
 * @param[in] request		the request.
 * @param[in] retry		retry status.  "now" is in retry->updated
 */
typedef	void (*unlang_module_retry_t)(module_ctx_t const *mctx, request_t *request, fr_retry_t const *retry);

/** A callback when the FD is ready for reading
 *
 * Used when a module needs to read from an FD.  Typically the callback is set, and then the
 * module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_interpret_mark_runnable(), so
 *
 * @param[in] mctx		calling context for the module.
 *				Contains global, thread-specific, and call-specific data for a module.
 * @param[in] request		the current request.
 * @param[in] fd		the file descriptor.
 */
typedef void (*unlang_module_fd_event_t)(module_ctx_t const *mctx, request_t *request, int fd);

/** A callback when the request gets a fr_signal_t.
 *
 * A module may call unlang_yeild(), but still need to do something on FR_SIGNAL_DUP.  If so, it's
 * set here.
 *
 * @note The callback is automatically removed on unlang_interpret_mark_runnable().
 *
 * @param[in] mctx		calling context for the module.
 *				Contains global, thread-specific, and call-specific data for a module.
 * @param[in] request		The current request.
 * @param[in] action		which is signalling the request.
 */
typedef void (*unlang_module_signal_t)(module_ctx_t const *mctx, request_t *request, fr_signal_t action);

int		unlang_module_push(rlm_rcode_t *p_result, request_t *request,
				   module_instance_t *module_instance, module_method_t method, bool top_frame)
				   CC_HINT(warn_unused_result) CC_HINT(nonnull(2,3,4));

int		unlang_module_set_resume(request_t *request, module_method_t resume);

unlang_action_t	unlang_module_yield_to_section(rlm_rcode_t *p_result,
					       request_t *request, CONF_SECTION *subcs,
					       rlm_rcode_t default_rcode,
					       module_method_t resume,
					       unlang_module_signal_t signal, fr_signal_t sigmask, void *rctx);

unlang_action_t	unlang_module_yield_to_xlat(TALLOC_CTX *ctx, bool *p_success, fr_value_box_list_t *out,
					    request_t *request, xlat_exp_head_t const *xlat,
					    module_method_t resume,
					    unlang_module_signal_t signal, fr_signal_t sigmask, void *rctx);

unlang_action_t	unlang_module_yield_to_tmpl(TALLOC_CTX *ctx, fr_value_box_list_t *out,
					    request_t *request, tmpl_t const *vpt,
					    unlang_tmpl_args_t *args,
					    module_method_t resume,
					    unlang_module_signal_t signal, fr_signal_t sigmask, void *rctx);

void		unlang_module_retry_now(module_ctx_t const *mctx, request_t *request) CC_HINT(nonnull);

unlang_action_t	unlang_module_yield_to_retry(request_t *request, module_method_t resume, unlang_module_retry_t retry_cb,
					     unlang_module_signal_t signal, fr_signal_t sigmask, void *rctx,
					     fr_retry_config_t const *retry_cfg);

unlang_action_t	unlang_module_yield(request_t *request,
				    module_method_t resume,
				    unlang_module_signal_t signal, fr_signal_t sigmask, void *rctx);

#ifdef __cplusplus
}
#endif
