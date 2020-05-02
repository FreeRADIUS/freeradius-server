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
 * @note The callback is automatically removed on unlang_interpret_resumable(), i.e. if an event
 *	on a registered FD occurs before the timeout event fires.
 *
 * @param[in] instance		the module instance.
 * @param[in] thread		data specific to this module instance.
 * @param[in] rctx		a local context for the callback.
 * @param[in] request		the request.
 * @param[in] fired		the time the timeout event actually fired.
 */
typedef	void (*fr_unlang_module_timeout_t)(void *instance, void *thread, REQUEST *request, void *rctx,
					   fr_time_t fired);

/** A callback when the FD is ready for reading
 *
 * Used when a module needs to read from an FD.  Typically the callback is set, and then the
 * module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_interpret_resumable(), so
 *
 * @param[in] instance		the module instance.
 * @param[in] thread		data specific to this module instance.
 * @param[in] request		the current request.
 * @param[in] rctx		a local context for the callback.
 * @param[in] fd		the file descriptor.
 */
typedef void (*fr_unlang_module_fd_event_t)(void *instance, void *thread, REQUEST *request, void *rctx, int fd);

/** A callback for when the request is resumed.
 *
 * The resumed request cannot call the normal "authorize", etc. method.  It needs a separate callback.
 *
 * @param[in] instance		The module instance.
 * @param[in] thread		data specific to this module instance.
 * @param[in] request		the current request.
 * @param[in] rctx		a local context for the callback.
 * @return a normal rlm_rcode_t.
 */
typedef rlm_rcode_t (*fr_unlang_module_resume_t)(void *instance, void *thread, REQUEST *request, void *rctx);

/** A callback when the request gets a fr_state_signal_t.
 *
 * A module may call unlang_yeild(), but still need to do something on FR_SIGNAL_DUP.  If so, it's
 * set here.
 *
 * @note The callback is automatically removed on unlang_interpret_resumable().
 *
 * @param[in] instance		The module instance.
 * @param[in] thread		data specific to this module instance.
 * @param[in] rctx		Resume ctx for the callback.
 * @param[in] request		The current request.
 * @param[in] action		which is signalling the request.
 */
typedef void (*fr_unlang_module_signal_t)(void *instance, void *thread, REQUEST *request,
					  void *rctx, fr_state_signal_t action);

int		unlang_module_timeout_add(REQUEST *request, fr_unlang_module_timeout_t callback,
					  void const *ctx, fr_time_t when);

int		unlang_module_timeout_delete(REQUEST *request, void const *ctx);

int 		unlang_module_fd_add(REQUEST *request,
				     fr_unlang_module_fd_event_t read,
				     fr_unlang_module_fd_event_t write,
				     fr_unlang_module_fd_event_t error,
				     void const *rctx, int fd);


int		unlang_module_fd_delete(REQUEST *request, void const *rctx, int fd);

void		unlang_module_push(rlm_rcode_t *out, REQUEST *request,
				   module_instance_t *module_instance, module_method_t method, bool top_frame);

REQUEST		*unlang_module_subrequest_alloc(REQUEST *parent, fr_dict_t const *namespace);

rlm_rcode_t	unlang_module_yield_to_subrequest(rlm_rcode_t *out, REQUEST *child,
						  fr_unlang_module_resume_t resume,
						  fr_unlang_module_signal_t signal,
						  unlang_subrequest_session_t const *session,
						  void *rctx);

rlm_rcode_t	unlang_module_yield_to_section(REQUEST *request, CONF_SECTION *subcs,
					       rlm_rcode_t default_rcode,
					       fr_unlang_module_resume_t resume,
					       fr_unlang_module_signal_t signal, void *rctx);

rlm_rcode_t	unlang_module_yield_to_xlat(TALLOC_CTX *ctx, fr_value_box_t **out,
					    REQUEST *request, xlat_exp_t const *xlat,
					    fr_unlang_module_resume_t resume,
					    fr_unlang_module_signal_t signal, void *rctx);

rlm_rcode_t unlang_module_yield_to_tmpl(TALLOC_CTX *ctx, fr_value_box_t **out, int *status,
					REQUEST *request, vp_tmpl_t const *exp,
					VALUE_PAIR *vps,
					fr_unlang_module_resume_t resume,
					fr_unlang_module_signal_t signal, void *rctx);

rlm_rcode_t	unlang_module_yield(REQUEST *request,
				    fr_unlang_module_resume_t resume,
				    fr_unlang_module_signal_t signal, void *rctx);

TALLOC_CTX	*unlang_module_frame_talloc_ctx(REQUEST *request);

#ifdef __cplusplus
}
#endif
