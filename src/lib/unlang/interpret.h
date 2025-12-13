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
 * @file unlang/interpret.h
 * @brief Declarations for the unlang interpreter.
 *
 * @copyright 2019 The FreeRADIUS server project
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/unlang/mod_action.h>
#include <freeradius-devel/unlang/action.h>

#define UNLANG_TOP_FRAME (true)
#define UNLANG_SUB_FRAME (false)

#define UNLANG_STACK_MAX (64)		//!< The maximum depth of the stack.
#define UNLANG_FRAME_PRE_ALLOC (128)	//!< How much memory we pre-alloc for each frame.

#define UNLANG_REQUEST_RUNNING (true)
#define UNLANG_REQUEST_RESUME (false)

/** Interpreter handle
 *
 */
typedef struct unlang_interpret_s unlang_interpret_t;

/** Signal the owner of the interpreter that this request should be initialised and executed
 *
 * This is called once per request, when it's about to start executing.
 */
typedef void (*unlang_request_init_t)(request_t *request, void *uctx);

/** Signal the owner of the interpreter that this request completed processing
 *
 * This is called once per request, when the interpret is about to stop processing it.
 */
typedef void (*unlang_request_done_t)(request_t *request, rlm_rcode_t rcode, void *uctx);

/** Stop a request from running
 *
 * This is called whenever a request has been signalled to stop
 */
typedef void (*unlang_request_stop_t)(request_t *request, void *uctx);

/** Signal the owner of the interpreter that a request has yielded
 *
 * This is called whenever a request has given control back to the interpreter.
 */
typedef void (*unlang_request_yield_t)(request_t *request, void *uctx);

/** Signal the owner of the interpreter that a request is ready to be resumed
 *
 * This is called any time a yielded request has resumed.
 */
typedef void (*unlang_request_resume_t)(request_t *request, void *uctx);

/** Signal the owner of the interpreter that a request is now runnable
 *
 * This is called any time a yielded request has been marked runnable.
 */
typedef void (*unlang_request_runnable_t)(request_t *request, void *uctx);

/** Signal the owner of the interpreter that a request is now runnable
 *
 * This is called any time a yielded request has been marked runnable.
 */
typedef bool (*unlang_request_scheduled_t)(request_t const *request, void *uctx);

/** Re-priotise the request in the runnable queue
 *
 * The new priority will be available in request->async->priority.
 */
typedef void (*unlang_request_prioritise_t)(request_t *request, void *uctx);

/** External functions provided by the owner of the interpret
 *
 * These functions allow the event loop to signal the caller when a given
 * request is ready to run for the first time, and when it should be resumed
 * and passed back to #unlang_interpret to continue execution.
 *
 * This is the cleanest way to separate the interpret and the code that's
 * managing requests.
 *
 * Test harnesses (for example) need to perform far less initialisation and
 * request management than FeeRADIUS worker threads.
 */
typedef struct {
	/*
	 *	There's no init_external as this is done
	 *	before the external request is handed off
	 *	to the interpreter.
	 */
	unlang_request_init_t		init_internal;	//!< Function called to initialise an internal request.

	unlang_request_done_t		done_external;	//!< Function called when a external request completes.
	unlang_request_done_t		done_internal;	//!< Function called when an internal request completes.
	unlang_request_done_t		done_detached;	//!< Function called when a detached request completes.

	unlang_request_init_t		detach;		//!< Function called when a request is detached.
	unlang_request_yield_t		yield;		//!< Function called when a request yields.
	unlang_request_resume_t		resume;		//!< Function called when a request is resumed.
	unlang_request_runnable_t	mark_runnable;	//!< Function called when a request needs to be
							///< added back to the runnable queue.
	unlang_request_scheduled_t	scheduled;	//!< Function to check if a request is already
							///< scheduled.
	unlang_request_prioritise_t	prioritise;	//!< Function to re-priotise a request in the
							///< runnable queue.
} unlang_request_func_t;

typedef struct {
	rlm_rcode_t 			rcode;			//!< The current rcode, from executing the instruction
								///< or merging the result from a frame.
	unlang_mod_action_t		priority;		//!< The priority or action for that rcode.
} unlang_result_t;

#define UNLANG_RESULT_NOT_SET ((unlang_result_t) { .rcode =  RLM_MODULE_NOT_SET, .priority = MOD_ACTION_NOT_SET })
#define UNLANG_RESULT_RCODE(_x) ((unlang_result_t) { .rcode = (_x), .priority = MOD_ACTION_NOT_SET })

/** Configuration structure to make it easier to pass configuration options to initialise the frame with
 */
typedef struct {
	bool				top_frame;		//!< Is this the top frame?
	unlang_result_t			default_result;		//!< The default result for the frame.
								///< This needs to be specified separately
								///< from p_result, because we may be passing
								///< in NULL for p_result.
} unlang_frame_conf_t;

#define FRAME_CONF(_default_rcode, _top_frame)		\
	&(unlang_frame_conf_t){				\
		.top_frame = (_top_frame),		\
		.default_result = UNLANG_RESULT_RCODE(_default_rcode),	\
	}

int			unlang_interpret_push_section(unlang_result_t *p_result, request_t *request,
						      CONF_SECTION *cs, unlang_frame_conf_t const *conf)
						      CC_HINT(warn_unused_result);

int			unlang_interpret_push_instruction(unlang_result_t *p_result, request_t *request,
							  void *instruction, unlang_frame_conf_t const *conf)
						  	  CC_HINT(warn_unused_result);

unlang_interpret_t	*unlang_interpret_init(TALLOC_CTX *ctx,
					       fr_event_list_t *el, unlang_request_func_t *func, void *uctx);

void			unlang_interpet_frame_discard(request_t *request);

void			unlang_interpret_set(request_t *request, unlang_interpret_t *intp);

unlang_interpret_t	*unlang_interpret_get(request_t *request);

fr_event_list_t		*unlang_interpret_event_list(request_t *request);

void			unlang_interpret_set_thread_default(unlang_interpret_t *intp);

unlang_interpret_t	*unlang_interpret_get_thread_default(void);

int			unlang_interpret_set_timeout(request_t *request, fr_time_delta_t timeout) CC_HINT(nonnull);

rlm_rcode_t		unlang_interpret(request_t *request, bool running) CC_HINT(hot);

rlm_rcode_t		unlang_interpret_synchronous(fr_event_list_t *el, request_t *request);

void			*unlang_interpret_stack_alloc(TALLOC_CTX *ctx);

bool			unlang_request_is_scheduled(request_t const *request);

bool			unlang_request_is_cancelled(request_t const *request);

bool			unlang_request_is_done(request_t const *request);

void			unlang_interpret_request_done(request_t *request);

void			unlang_interpret_request_cancel_retry(request_t *request);

void			unlang_interpret_request_prioritise(request_t *request, uint32_t priority);

void			unlang_interpret_mark_runnable(request_t *request);

bool			unlang_interpret_is_resumable(request_t *request);

void			unlang_interpret_signal(request_t *request, fr_signal_t action);

int			unlang_interpret_stack_depth(request_t *request);

rlm_rcode_t		unlang_interpret_rcode(request_t *request);

unlang_mod_action_t	unlang_interpret_priority(request_t *request);

unlang_result_t		*unlang_interpret_result(request_t *request);

TALLOC_CTX		*unlang_interpret_frame_talloc_ctx(request_t *request);

int			unlang_interpret_init_global(TALLOC_CTX *ctx);
#ifdef __cplusplus
}
#endif
