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

#include <freeradius-devel/server/request.h>
#include <freeradius-devel/unlang/action.h>

#define UNLANG_TOP_FRAME (true)
#define UNLANG_SUB_FRAME (false)

#define UNLANG_STACK_MAX (64)		//!< The maximum depth of the stack.
#define UNLANG_FRAME_PRE_ALLOC (128)	//!< How much memory we pre-alloc for each frame.

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
 * This is called whenever a request has given control back to the interpeter.
 */
typedef void (*unlang_request_yield_t)(request_t *request, void *uctx);

/** Signal the owner of the interpeter that a request is ready to be resumed
 *
 * This is called any time a yielded request has resumed.
 */
typedef void (*unlang_request_resume_t)(request_t *request, void *uctx);

/** Signal the owner of the interpeter that a request is now runnable
 *
 * This is called any time a yielded request has been marked runnable.
 */
typedef void (*unlang_request_runnable_t)(request_t *request, void *uctx);

/** Signal the owner of the interpeter that a request is now runnable
 *
 * This is called any time a yielded request has been marked runnable.
 */
typedef bool (*unlang_request_scheduled_t)(request_t const *request, void *uctx);

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
	unlang_request_stop_t		stop;		//!< function called when a request is signalled to stop.
	unlang_request_yield_t		yield;		//!< Function called when a request yields.
	unlang_request_resume_t		resume;		//!< Function called when a request is resumed.
	unlang_request_runnable_t	mark_runnable;	//!< Function called when a request needs to be
							///< added back to the runnable queue.
	unlang_request_scheduled_t	scheduled;	//!< Function to check if a request is already
							///< scheduled.
} unlang_request_func_t;

int			unlang_interpret_push_section(request_t *request, CONF_SECTION *cs,
					      	      rlm_rcode_t default_action, bool top_frame)
						      CC_HINT(warn_unused_result);

int			unlang_interpret_push_instruction(request_t *request, void *instruction,
						  	  rlm_rcode_t default_rcode, bool top_frame)
						  	  CC_HINT(warn_unused_result);

unlang_interpret_t	*unlang_interpret_init(TALLOC_CTX *ctx,
					       fr_event_list_t *el, unlang_request_func_t *func, void *uctx);

void			unlang_interpet_frame_discard(request_t *request);

void			unlang_interpret_set(request_t *request, unlang_interpret_t *intp);

unlang_interpret_t	*unlang_interpret_get(request_t *request);

void			unlang_interpret_set_thread_default(unlang_interpret_t *intp);

unlang_interpret_t	*unlang_interpret_get_thread_default(void);

rlm_rcode_t		unlang_interpret(request_t *request) CC_HINT(hot);

rlm_rcode_t		unlang_interpret_synchronous(request_t *request);

void			*unlang_interpret_stack_alloc(TALLOC_CTX *ctx);

bool			unlang_request_is_scheduled(request_t const *request);

void			unlang_interpret_request_done(request_t *request);

void			unlang_interpret_mark_runnable(request_t *request);

bool			unlang_interpret_is_resumable(request_t *request);

void			unlang_interpret_signal(request_t *request, fr_state_signal_t action);

int			unlang_interpret_stack_depth(request_t *request);

rlm_rcode_t		unlang_interpret_stack_result(request_t *request);

void			unlang_interpret_stack_result_set(request_t *request, rlm_rcode_t code);

TALLOC_CTX		*unlang_interpret_frame_talloc_ctx(request_t *request);

void			unlang_interpret_init_global(void);
#ifdef __cplusplus
}
#endif
