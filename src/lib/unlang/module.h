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
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/unlang/subrequest.h>

/** A callback when the the timeout occurs
 *
 * Used when a module needs wait for an event.
 * Typically the callback is set, and then the module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_interpret_mark_resumable(), i.e. if an event
 *	on a registered FD occurs before the timeout event fires.
 *
 * @param[in] mctx		calling context for the module.
 *				Contains global, thread-specific, and call-specific data for a module.
 * @param[in] rctx		a local context for the callback.
 * @param[in] request		the request.
 * @param[in] fired		the time the timeout event actually fired.
 */
typedef	void (*unlang_module_timeout_t)(module_ctx_t const *mctx, request_t *request, void *rctx, fr_time_t fired);

/** A callback when the FD is ready for reading
 *
 * Used when a module needs to read from an FD.  Typically the callback is set, and then the
 * module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_interpret_mark_resumable(), so
 *
 * @param[in] mctx		calling context for the module.
 *				Contains global, thread-specific, and call-specific data for a module.
 * @param[in] request		the current request.
 * @param[in] rctx		a local context for the callback.
 * @param[in] fd		the file descriptor.
 */
typedef void (*unlang_module_fd_event_t)(module_ctx_t const *mctx, request_t *request, void *rctx, int fd);

/** A callback for when the request is resumed.
 *
 * The resumed request cannot call the normal "authorize", etc. method.  It needs a separate callback.
 *
 * @param[out] p_result		result of the operation.
 * @param[in] mctx		calling context for the module.
 *				Contains global, thread-specific, and call-specific data for a module.
 * @param[in] request		the current request.
 * @param[in] rctx		a local context for the callback.
 * @return an instruction for the interpreter.
 */
typedef unlang_action_t (*unlang_module_resume_t)(rlm_rcode_t *p_result, module_ctx_t const *mctx,
						  request_t *request, void *rctx);

/** A callback when the request gets a fr_state_signal_t.
 *
 * A module may call unlang_yeild(), but still need to do something on FR_SIGNAL_DUP.  If so, it's
 * set here.
 *
 * @note The callback is automatically removed on unlang_interpret_mark_resumable().
 *
 * @param[in] mctx		calling context for the module.
 *				Contains global, thread-specific, and call-specific data for a module.
 * @param[in] rctx		Resume ctx for the callback.
 * @param[in] request		The current request.
 * @param[in] action		which is signalling the request.
 */
typedef void (*unlang_module_signal_t)(module_ctx_t const *mctx, request_t *request,
				       void *rctx, fr_state_signal_t action);

int		unlang_module_timeout_add(request_t *request, unlang_module_timeout_t callback,
					  void const *ctx, fr_time_t when);

int		unlang_module_timeout_delete(request_t *request, void const *ctx);

int 		unlang_module_fd_add(request_t *request,
				     unlang_module_fd_event_t read,
				     unlang_module_fd_event_t write,
				     unlang_module_fd_event_t error,
				     void const *rctx, int fd);

int		unlang_module_fd_delete(request_t *request, void const *rctx, int fd);

int		unlang_module_push(rlm_rcode_t *out, request_t *request,
				   module_instance_t *module_instance, module_method_t method, bool top_frame)
				   CC_HINT(warn_unused_result);

request_t	*unlang_module_subrequest_alloc(request_t *parent, fr_dict_t const *namespace);

unlang_action_t	unlang_module_yield_to_subrequest(rlm_rcode_t *out, request_t *child,
						  unlang_module_resume_t resume,
						  unlang_module_signal_t signal,
						  unlang_subrequest_session_t const *session,
						  void *rctx);

unlang_action_t	unlang_module_yield_to_section(rlm_rcode_t *p_result,
					       request_t *request, CONF_SECTION *subcs,
					       rlm_rcode_t default_rcode,
					       unlang_module_resume_t resume,
					       unlang_module_signal_t signal, void *rctx);

unlang_action_t	unlang_module_yield_to_xlat(TALLOC_CTX *ctx, fr_value_box_t **out,
					    request_t *request, xlat_exp_t const *xlat,
					    unlang_module_resume_t resume,
					    unlang_module_signal_t signal, void *rctx);

unlang_action_t	unlang_module_yield_to_tmpl(TALLOC_CTX *ctx, fr_value_box_t **out, int *status,
					    request_t *request, tmpl_t const *exp,
					    fr_pair_list_t *vps,
					    unlang_module_resume_t resume,
					    unlang_module_signal_t signal, void *rctx);

unlang_action_t	unlang_module_yield(request_t *request,
				    unlang_module_resume_t resume,
				    unlang_module_signal_t signal, void *rctx);

#ifdef __cplusplus
}
#endif
