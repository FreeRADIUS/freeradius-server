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
 * @file unlang/unlang_priv.h
 * @brief Private interpreter structures and functions
 *
 * @author Alan DeKok (aland@freeradius.org)
 *
 * @copyright 2016-2019 The FreeRADIUS server project
 */
#include <freeradius-devel/server/cf_util.h> /* Need CONF_* definitions */
#include <freeradius-devel/server/cond_eval.h>
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/io/listen.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UNLANG_STACK_MAX (64)

/* Actions may be a positive integer (the highest one returned in the group
 * will be returned), or the keyword "return", represented here by
 * MOD_ACTION_RETURN, to cause an immediate return.
 * There's also the keyword "reject", represented here by MOD_ACTION_REJECT
 * to cause an immediate reject. */
#define MOD_ACTION_RETURN  (-1)
#define MOD_ACTION_REJECT  (-2)
#define MOD_PRIORITY_MAX   (64)

/** Types of unlang_t nodes
 *
 * Here are our basic types: unlang_t, unlang_group_t, and unlang_module_t. For an
 * explanation of what they are all about, see doc/unlang/configurable_failover.adoc
 */
typedef enum {
	UNLANG_TYPE_NULL = 0,			//!< unlang type not set.
	UNLANG_TYPE_MODULE = 1,			//!< Module method.
	UNLANG_TYPE_FUNCTION,			//!< Internal call to a function or submodule.
	UNLANG_TYPE_GROUP,			//!< Grouping section.
	UNLANG_TYPE_LOAD_BALANCE,		//!< Load balance section.
	UNLANG_TYPE_REDUNDANT_LOAD_BALANCE,	//!< Redundant load balance section.
	UNLANG_TYPE_PARALLEL,			//!< execute statements in parallel
#ifdef WITH_UNLANG
	UNLANG_TYPE_IF,				//!< Condition.
	UNLANG_TYPE_ELSE,			//!< !Condition.
	UNLANG_TYPE_ELSIF,			//!< !Condition && Condition.
	UNLANG_TYPE_FILTER,			//!< Filter block.
	UNLANG_TYPE_UPDATE,			//!< Update block.
	UNLANG_TYPE_SWITCH,			//!< Switch section.
	UNLANG_TYPE_CASE,			//!< Case section (within a #UNLANG_TYPE_SWITCH).
	UNLANG_TYPE_FOREACH,			//!< Foreach section.
	UNLANG_TYPE_BREAK,			//!< Break statement (within a #UNLANG_TYPE_FOREACH).
	UNLANG_TYPE_RETURN,			//!< Return statement.
	UNLANG_TYPE_MAP,			//!< Mapping section (like #UNLANG_TYPE_UPDATE, but uses
						//!< values from a #map_proc_t call).
	UNLANG_TYPE_SUBREQUEST,			//!< create a child subrequest
	UNLANG_TYPE_DETACH,			//!< detach a child
	UNLANG_TYPE_CALL,			//!< call another virtual server
#endif
	UNLANG_TYPE_POLICY,			//!< Policy section.
	UNLANG_TYPE_XLAT_INLINE,		//!< xlat statement, inline in "unlang"
	UNLANG_TYPE_XLAT,			//!< Represents one level of an xlat expansion.
	UNLANG_TYPE_RESUME,			//!< where to resume processing
	UNLANG_TYPE_MAX
} unlang_type_t;

/** Allows the frame evaluator to signal the interpreter
 *
 */
typedef enum {
	UNLANG_FRAME_ACTION_POP = 1,		//!< Pop the current frame, and check the next one further
						///< up in the stack for what to do next.
	UNLANG_FRAME_ACTION_NEXT,		//!< Process the next instruction at this level.
	UNLANG_FRAME_ACTION_YIELD		//!< Temporarily return control back to the caller on the C
						///< stack.
} unlang_frame_action_t;

typedef enum {
	UNLANG_GROUP_TYPE_SIMPLE = 0,		//!< Execute each of the children sequentially, until we execute
						//!< all of the children, or one returns #UNLANG_ACTION_BREAK.
	UNLANG_GROUP_TYPE_REDUNDANT,		//!< Execute each of the children until one returns a 'good'
						//!< result i.e. ok, updated, noop, then break out of the group.
	UNLANG_GROUP_TYPE_MAX			//!< Number of group types.
} unlang_group_type_t;

#define UNLANG_NEXT_STOP	(false)
#define UNLANG_NEXT_SIBLING	(true)

#define UNLANG_DETACHABLE (true)
#define UNLANG_NORMAL_CHILD (false)

typedef struct unlang_s unlang_t;

/** A node in a graph of #unlang_op_t (s) that we execute
 *
 * The interpreter acts like a turing machine, with #unlang_t nodes forming the tape
 * and the #unlang_action_t the instructions.
 *
 * This is the parent 'class' for multiple #unlang_t node specialisations.
 * The #unlang_t struct is listed first in the specialisation so that we can cast between
 * parent/child classes without knowledge of the layout of the structures.
 *
 * The specialisations of the nodes describe additional details of the operation to be performed.
 */
struct unlang_s {
	unlang_t		*parent;	//!< Previous node.
	unlang_t		*next;		//!< Next node (executed on #UNLANG_ACTION_EXECUTE_NEXT et al).
	char const		*name;		//!< Unknown...
	char const 		*debug_name;	//!< Printed in log messages when the node is executed.
	unlang_type_t		type;		//!< The specialisation of this node.
	CONF_ITEM const		*closed;       	//!< whether or not we can add any children, and where it was closed
	int			actions[RLM_MODULE_NUMCODES];	//!< Priorities for the various return codes.
};

/** Generic representation of a grouping
 *
 * Can represent IF statements, maps, update sections etc...
 */
typedef struct {
	unlang_t		self;
	unlang_group_type_t	group_type;
	unlang_t		*children;	//!< Children beneath this group.  The body of an if
						//!< section for example.
	unlang_t		*tail;		//!< of the children list.
	CONF_SECTION		*cs;
	int			num_children;

	/*
	 *	Hackity-hack.  We should probably just have a common
	 *	group header, and then have type-specific structures.
	 */
	union {
		struct {
			vp_tmpl_t		*vpt;		//!< #UNLANG_TYPE_SWITCH, #UNLANG_TYPE_MAP

			union {
				struct {
					vp_map_t		*map;		//!< #UNLANG_TYPE_FILTER, #UNLANG_TYPE_UPDATE, #UNLANG_TYPE_MAP,
					map_proc_inst_t		*proc_inst;	//!< Instantiation data for #UNLANG_TYPE_MAP.
				};
				struct {
					CONF_SECTION		*server_cs;	//!< #UNLANG_TYPE_CALL
				};
				struct {
					fr_dict_t const		*dict;		//!< #UNLANG_TYPE_SUBREQUEST
					fr_dict_attr_t const	*attr_packet_type;
					fr_dict_enum_t const	*type_enum;
				};
			};
		};
		fr_cond_t		*cond;		//!< #UNLANG_TYPE_IF, #UNLANG_TYPE_ELSIF.

		struct {				//!< #UNLANG_TYPE_PARALLEL
			bool			clone;
			bool			detach;
		};
	};
} unlang_group_t;

/** Pushed onto the interpreter stack by a yielding module, xlat, or keyword to indicate a resumption point
 *
 * Unlike normal coroutines in other languages, we represent resumption points as states in a state
 * machine made up of function pointers.
 *
 * When a module, xlat or keyword yields, it specifies the function to call when whatever
 * condition is required for resumption is satisfied, it also specifies the ctx for that function,
 * which represents the internal state of the module at the time of yielding.
 *
 * Because we occasionally want to cancel requests that are waiting on a resumption condition
 * a signal function may also be specified.  This is provided so that whatever yielded can cancel
 * any pending I/O operations, and cleanup any memory that was temporarily allocated.
 *
 * If you want normal coroutine behaviour... rctx is arbitrary and could include a state enum,
 * in which case the function pointer could be the same as the function that yielded, and something
 * like Duff's device could be used to jump back to the yield point.
 *
 * Yield/resume are left as flexible as possible.  Writing async code this way is difficult enough
 * without being straightjacketed.
 */
typedef struct {
	unlang_t		self;

	unlang_t		*parent;			//!< The original instruction.

	void    		*resume;			//!< Function the yielding code indicated should
								//!< be called when the request could be resumed.

	void			*signal;			//!< Function the yielding code indicated should
								///< be called if the request is destroyed in
								///< the middle of an async operation.

	void			*rctx;   			//!< Context data for the resume and signal functions.
								///< Usually represents the internal state at the
								///< time of yielding.
} unlang_resume_t;

/** A naked xlat
 *
 * @note These are vestigial and may be removed in future.
 */
typedef struct {
	unlang_t		self;
	int			exec;
	char			*xlat_name;
	xlat_exp_t		*exp;				//!< First xlat node to execute.
} unlang_xlat_inline_t;

/** State of a redundant operation
 *
 */
typedef struct {
	unlang_t 		*child;
	unlang_t		*found;
} unlang_frame_state_redundant_t;

/** Our interpreter stack, as distinct from the C stack
 *
 * We don't call the modules recursively.  Instead we iterate over a list of #unlang_t and
 * and manage the call stack ourselves.
 *
 * After looking at various green thread implementations, it was decided that using the existing
 * unlang interpreter stack was the best way to perform async I/O.
 *
 * Each request as an unlang interpreter stack associated with it, which represents its progress
 * through the server.  Because the interpreter stack is distinct from the C stack, we can have
 * a single system thread with many thousands of pending requests.
 */
typedef struct {
	unlang_t		*instruction;			//!< The unlang node we're evaluating.
	unlang_t		*next;				//!< The next unlang node we will evaluate

	/** Stack frame specialisations
	 *
	 * These store extra (mutable) state data, for the immutable (#unlang_t)
	 * instruction.  Instructions can't be used to store data because they
	 * might be shared between multiple threads.
	 *
	 * Which stack_entry specialisation to use is determined by the
	 * instruction->type.
	 */
	void			*state;

	rlm_rcode_t		result;				//!< The result from executing the instruction.
	int			priority;			//!< Result priority.  When we pop this stack frame
								///< this priority will be compared with the one of the
								///< frame lower in the stack to determine if the
								///< result stored in the lower stack frame should
								///< be replaced.
	bool			repeat : 1;			//!< Call the action callback again on our way
								//!< back up the stack.
	bool			top_frame : 1;			//!< are we the top frame of the stack?
								///< If true, causes the interpreter to stop
								///< interpreting and return, control then passes
								///< to whatever called the interpreter.
	bool			break_point : 1;       		//!< 'break' stops here
	bool			return_point : 1;      		//!< 'return' stops here
} unlang_stack_frame_t;

/** An unlang stack associated with a request
 *
 */
typedef struct {
	rlm_rcode_t		result;				//!< The current stack rcode.
	int			depth;				//!< Current depth we're executing at.
	unlang_type_t		unwind;				//!< Unwind to this frame if it exists.
								///< This is used for break and return.
	unlang_stack_frame_t	frame[UNLANG_STACK_MAX];	//!< The stack...
} unlang_stack_t;

/** Different operations the interpreter can execute
 */
extern unlang_op_t unlang_ops[];

#define MOD_NUM_TYPES (UNLANG_TYPE_XLAT + 1)

extern char const *const comp2str[];

/** @name Conversion functions for converting #unlang_t to its specialisations
 *
 * Simple conversions: #unlang_module_t and #unlang_group_t are subclasses of #unlang_t,
 * so we often want to go back and forth between them.
 *
 * @{
 */
static inline unlang_group_t *unlang_generic_to_group(unlang_t *p)
{
	rad_assert((p->type > UNLANG_TYPE_MODULE) && (p->type <= UNLANG_TYPE_POLICY));

	return (unlang_group_t *)p;
}

static inline unlang_t *unlang_group_to_generic(unlang_group_t *p)
{
	return (unlang_t *)p;
}

static inline unlang_xlat_inline_t *unlang_generic_to_xlat_inline(unlang_t *p)
{
	rad_assert(p->type == UNLANG_TYPE_XLAT_INLINE);
	return talloc_get_type_abort(p, unlang_xlat_inline_t);
}

static inline unlang_t *unlang_xlat_inline_to_generic(unlang_xlat_inline_t *p)
{
	return (unlang_t *)p;
}

static inline unlang_resume_t *unlang_generic_to_resume(unlang_t *p)
{
	rad_assert(p->type == UNLANG_TYPE_RESUME);
	return talloc_get_type_abort(p, unlang_resume_t);
}

static inline unlang_t *unlang_resume_to_generic(unlang_resume_t *p)
{
	return (unlang_t *)p;
}
/* @} **/

/** @name Internal interpreter functions needed by ops
 *
 * @{
 */
uint64_t	unlang_interpret_active_callers(unlang_t *instruction);

unlang_resume_t *unlang_interpret_resume_alloc(REQUEST *request, void *callback, void *signal, void *rctx);

void		unlang_interpret_push(REQUEST *request, unlang_t *instruction,
				      rlm_rcode_t default_rcode, bool do_next_sibling, bool top_frame);
rlm_rcode_t	unlang_interpret_run(REQUEST *request);

int		unlang_op_init(void);

void		unlang_op_free(void);
/* @} **/

/** @name io shims
 *
 * Functions to simulate a 'proto' module when we're running 'fake'
 * requests. i.e. those created by parallel and subrequest.
 *
 * @{
 */
fr_io_final_t	unlang_io_process_interpret(UNUSED void const *instance, REQUEST *request);

REQUEST		*unlang_io_subrequest_alloc(REQUEST *parent, fr_dict_t const *namespace, bool detachable);

/* @} **/

/** @name op init functions
 *
 * Functions to trigger registration of the various unlang ops.
 *
 * @{
 */
void		unlang_call_init(void);

void		unlang_condition_init(void);

void		unlang_foreach_init(void);

void		unlang_function_init(void);

void		unlang_group_init(void);

void		unlang_load_balance_init(void);

void		unlang_map_init(void);

void		unlang_module_init(void);

void		unlang_return_init(void);

void		unlang_parallel_init(void);

int		unlang_subrequest_op_init(void);

void		unlang_subrequest_op_free(void);

void		unlang_switch_init(void);
 /* @} **/

#ifdef __cplusplus
}
#endif
