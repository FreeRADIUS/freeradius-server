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
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/io/listen.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Actions may be a positive integer (the highest one returned in the group
 * will be returned), or the keyword "return", represented here by
 * MOD_ACTION_RETURN, to cause an immediate return.
 * There's also the keyword "reject", represented here by MOD_ACTION_REJECT
 * to cause an immediate reject. */
#define MOD_ACTION_RETURN  (-1)
#define MOD_ACTION_REJECT  (-2)
#define MOD_ACTION_RETRY   (-3)
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
	UNLANG_TYPE_REDUNDANT,			//!< exactly like group, but with different default return codes
	UNLANG_TYPE_LOAD_BALANCE,		//!< Load balance section.
	UNLANG_TYPE_REDUNDANT_LOAD_BALANCE,	//!< Redundant load balance section.
	UNLANG_TYPE_PARALLEL,			//!< execute statements in parallel
	UNLANG_TYPE_IF,				//!< Condition.
	UNLANG_TYPE_ELSE,			//!< !Condition.
	UNLANG_TYPE_ELSIF,			//!< !Condition && Condition.
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
	UNLANG_TYPE_CALLER,			//!< conditionally check parent dictionary type
	UNLANG_TYPE_TIMEOUT,			//!< time-based timeouts.
	UNLANG_TYPE_LIMIT,			//!< limit number of requests in a section
	UNLANG_TYPE_POLICY,			//!< Policy section.
	UNLANG_TYPE_XLAT,			//!< Represents one level of an xlat expansion.
	UNLANG_TYPE_TMPL,			//!< asynchronously expand a tmpl_t
	UNLANG_TYPE_EDIT,			//!< edit VPs in place.  After 20 years!
	UNLANG_TYPE_MAX
} unlang_type_t;

/** Allows the frame evaluator to signal the interpreter
 *
 */
typedef enum {
	UNLANG_FRAME_ACTION_POP = 1,		//!< Pop the current frame, and check the next one further
						///< up in the stack for what to do next.
	UNLANG_FRAME_ACTION_RETRY,		//!< retry the current frame
	UNLANG_FRAME_ACTION_NEXT,		//!< Process the next instruction at this level.
	UNLANG_FRAME_ACTION_YIELD		//!< Temporarily return control back to the caller on the C
						///< stack.
} unlang_frame_action_t;

#define UNLANG_NEXT_STOP	(false)
#define UNLANG_NEXT_SIBLING	(true)

#define UNLANG_DETACHABLE	(true)
#define UNLANG_NORMAL_CHILD	(false)

typedef struct unlang_s unlang_t;
typedef struct unlang_stack_frame_s unlang_stack_frame_t;

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
	bool			closed;		//!< whether or not this section is closed to new statements
	CONF_ITEM		*ci;		//!< used to generate this item
	unsigned int		number;		//!< unique node number
	unlang_actions_t	actions;	//!< Priorities, etc. for the various return codes.
};

/** Describes how to allocate an #unlang_group_t with additional memory keyword specific data
 *
 */
typedef struct {
	unlang_type_t		type;		//!< Keyword.
	size_t			len;		//!< Total length of the unlang_group_t + specialisation struct.
	unsigned		pool_headers;	//!< How much additional space to allocate for chunk headers.
	size_t			pool_len;	//!< How much additional space to allocate for extensions.
	char const		*type_name;	//!< Talloc type name.
} unlang_ext_t;

typedef struct {
	fr_dict_t		*dict;		//!< our dictionary
	fr_dict_attr_t const	*root;		//!< the root of our dictionary
	int			max_attr;	//!< 1..N local attributes have been defined
} unlang_variable_t;

/** Generic representation of a grouping
 *
 * Can represent IF statements, maps, update sections etc...
 */
typedef struct {
	unlang_t		self;
	unlang_t		*children;	//!< Children beneath this group.  The body of an if
						//!< section for example.
	unlang_t		**tail;		//!< pointer to the tail which gets updated
	CONF_SECTION		*cs;
	int			num_children;

	unlang_variable_t	*variables;	//!< rarely used, so we don't usually need it
} unlang_group_t;

/** A naked xlat
 *
 * @note These are vestigial and may be removed in future.
 */
typedef struct {
	unlang_t		self;
	tmpl_t const		*tmpl;
} unlang_tmpl_t;

/** Function to call when interpreting a frame
 *
 * @param[in,out] p_result	Pointer to the current rcode, may be modified by the function.
 * @param[in] request		The current request.
 * @param[in] frame		being executed.
 *
 * @return an action for the interpreter to perform.
 */
typedef unlang_action_t (*unlang_process_t)(rlm_rcode_t *p_result, request_t *request,
					    unlang_stack_frame_t *frame);

/** Function to call if the request was signalled
 *
 * This is the instruction specific cancellation function.
 * This function will usually either call a more specialised cancellation function
 * set when something like a module yielded, or just cleanup the state of the original
 * #unlang_process_t.
 *
 * @param[in] request		The current request.
 * @param[in] frame		being signalled.
 * @param[in] action		We're being signalled with.
 */
typedef void (*unlang_signal_t)(request_t *request,
				unlang_stack_frame_t *frame, fr_signal_t action);

/** Custom callback for dumping information about frame state
 *
 * @param[in] request		The current request.
 * @param[in] frame		to provide additional information for.
 */
typedef void (*unlang_dump_t)(request_t *request, unlang_stack_frame_t *frame);

typedef int (*unlang_thread_instantiate_t)(unlang_t const *instruction, void *thread_inst);

/** An unlang operation
 *
 * These are like the opcodes in other interpreters.  Each operation, when executed
 * will return an #unlang_action_t, which determines what the interpreter does next.
 */
typedef struct {
	char const		*name;				//!< Name of the operation.

	unlang_process_t	interpret;     			//!< Function to interpret the keyword

	unlang_signal_t		signal;				//!< Function to signal stop / dup / whatever

	unlang_dump_t		dump;				//!< Dump additional information about the frame state.

	unlang_thread_instantiate_t thread_instantiate;		//!< per-thread instantiation function
	size_t			thread_inst_size;
	char const		*thread_inst_type;


	bool			debug_braces;			//!< Whether the operation needs to print braces
								///< in debug mode.

	size_t			frame_state_size;       	//!< size of instance data in the stack frame

	char const		*frame_state_type;		//!< talloc name of the frame instance data

	size_t			frame_state_pool_objects;	//!< How many sub-allocations we expect.

	size_t			frame_state_pool_size;		//!< The total size of the pool to alloc.
} unlang_op_t;

typedef struct {
	unlang_t const		*instruction;			//!< instruction which we're executing
	void			*thread_inst;			//!< thread-specific instance data
#ifdef WITH_PERF
	uint64_t		use_count;			//!< how many packets it has processed
	uint64_t		running;			//!< currently running this instruction
	uint64_t		yielded;			//!< currently yielded
	fr_time_tracking_t	tracking;			//!< tracking cpu time
#endif
} unlang_thread_t;

void	*unlang_thread_instance(unlang_t const *instruction);

#ifdef WITH_PERF
void		unlang_frame_perf_init(unlang_stack_frame_t *frame);
void		unlang_frame_perf_yield(unlang_stack_frame_t *frame);
void		unlang_frame_perf_resume(unlang_stack_frame_t *frame);
void		unlang_frame_perf_cleanup(unlang_stack_frame_t *frame);
#else
#define		unlang_frame_perf_init(_x)
#define		unlang_frame_perf_yield(_x)
#define		unlang_frame_perf_resume(_x)
#define		unlang_frame_perf_cleanup(_x)
#endif

void	unlang_frame_signal(request_t *request, fr_signal_t action, int limit);

typedef struct {
	request_t		*request;
	int			depth;				//!< of this retry structure
	fr_retry_state_t	state;
	fr_time_t		timeout;
	uint32_t       		count;
	fr_event_timer_t const	*ev;
} unlang_retry_t;

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
struct unlang_stack_frame_s {
	unlang_t const		*instruction;			//!< The unlang node we're evaluating.
	unlang_t const		*next;				//!< The next unlang node we will evaluate

	unlang_process_t	process;			//!< function to call for interpreting this stack frame
	unlang_signal_t		signal;				//!< function to call when signalling this stack frame

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

	unlang_retry_t		*retry;				//!< if the frame is being retried.

	rlm_rcode_t 		result;				//!< The result from executing the instruction.
	int			priority;			//!< Result priority.  When we pop this stack frame
								///< this priority will be compared with the one of the
								///< frame lower in the stack to determine if the
								///< result stored in the lower stack frame should
	uint8_t			uflags;				//!< Unwind markers
#ifdef WITH_PERF
	fr_time_tracking_t	tracking;			//!< track this instance of this instruction
#endif
};

/** An unlang stack associated with a request
 *
 */
typedef struct {
	unlang_interpret_t	*intp;				//!< Interpreter that the request is currently
								///< associated with.
	int			priority;			//!< Current priority.
	rlm_rcode_t		result;				//!< The current stack rcode.
	int			depth;				//!< Current depth we're executing at.
	uint8_t			unwind;				//!< Unwind to this frame if it exists.
								///< This is used for break and return.
	unlang_stack_frame_t	frame[UNLANG_STACK_MAX];	//!< The stack...
} unlang_stack_t;

/** Different operations the interpreter can execute
 */
extern unlang_op_t unlang_ops[];

#define MOD_NUM_TYPES (UNLANG_TYPE_XLAT + 1)

extern fr_table_num_sorted_t const mod_rcode_table[];
extern size_t mod_rcode_table_len;

#define UNWIND_FLAG_NONE		0x00			//!< No flags.
#define UNWIND_FLAG_REPEAT		0x01			//!< Repeat the frame on the way up the stack.
#define UNWIND_FLAG_TOP_FRAME		0x02			//!< are we the top frame of the stack?
								///< If true, causes the interpreter to stop
								///< interpreting and return, control then passes
								///< to whatever called the interpreter.
#define UNWIND_FLAG_BREAK_POINT		0x04			//!< 'break' stops here.
#define UNWIND_FLAG_RETURN_POINT	0x08      		//!< 'return' stops here.
#define UNWIND_FLAG_NO_CLEAR		0x10			//!< Keep unwinding, don't clear the unwind flag.
#define UNWIND_FLAG_YIELDED		0x20			//!< frame has yielded

static inline void repeatable_set(unlang_stack_frame_t *frame)		{ frame->uflags |= UNWIND_FLAG_REPEAT; }
static inline void top_frame_set(unlang_stack_frame_t *frame) 		{ frame->uflags |= UNWIND_FLAG_TOP_FRAME; }
static inline void break_point_set(unlang_stack_frame_t *frame)		{ frame->uflags |= UNWIND_FLAG_BREAK_POINT; }
static inline void return_point_set(unlang_stack_frame_t *frame)	{ frame->uflags |= UNWIND_FLAG_RETURN_POINT; }
static inline void yielded_set(unlang_stack_frame_t *frame)		{ frame->uflags |= UNWIND_FLAG_YIELDED; }

static inline void repeatable_clear(unlang_stack_frame_t *frame)	{ frame->uflags &= ~UNWIND_FLAG_REPEAT; }
static inline void top_frame_clear(unlang_stack_frame_t *frame)		{ frame->uflags &= ~UNWIND_FLAG_TOP_FRAME; }
static inline void break_point_clear(unlang_stack_frame_t *frame)	{ frame->uflags &= ~UNWIND_FLAG_BREAK_POINT; }
static inline void return_point_clear(unlang_stack_frame_t *frame) 	{ frame->uflags &= ~UNWIND_FLAG_RETURN_POINT; }
static inline void yielded_clear(unlang_stack_frame_t *frame) 		{ frame->uflags &= ~UNWIND_FLAG_YIELDED; }

static inline bool is_repeatable(unlang_stack_frame_t const *frame)	{ return frame->uflags & UNWIND_FLAG_REPEAT; }
static inline bool is_top_frame(unlang_stack_frame_t const *frame)	{ return frame->uflags & UNWIND_FLAG_TOP_FRAME; }
static inline bool is_break_point(unlang_stack_frame_t const *frame)	{ return frame->uflags & UNWIND_FLAG_BREAK_POINT; }
static inline bool is_return_point(unlang_stack_frame_t const *frame) 	{ return frame->uflags & UNWIND_FLAG_RETURN_POINT; }
static inline bool is_yielded(unlang_stack_frame_t const *frame) 	{ return frame->uflags & UNWIND_FLAG_YIELDED; }

static inline unlang_action_t unwind_to_break(unlang_stack_t *stack)
{
	stack->unwind = UNWIND_FLAG_BREAK_POINT | UNWIND_FLAG_TOP_FRAME;
	return UNLANG_ACTION_UNWIND;
}
static inline unlang_action_t unwind_to_return(unlang_stack_t *stack)
{
	stack->unwind = UNWIND_FLAG_RETURN_POINT | UNWIND_FLAG_TOP_FRAME;
	return UNLANG_ACTION_UNWIND;
}
static inline unlang_action_t unwind_all(unlang_stack_t *stack)
{
	stack->unwind = UNWIND_FLAG_TOP_FRAME | UNWIND_FLAG_NO_CLEAR;
	return UNLANG_ACTION_UNWIND;
}

static inline bool is_stack_unwinding_to_top_frame(unlang_stack_t *stack)	{ return stack->unwind & UNWIND_FLAG_TOP_FRAME; }
static inline bool is_stack_unwinding_to_break(unlang_stack_t *stack)		{ return stack->unwind & UNWIND_FLAG_BREAK_POINT; }
static inline bool is_stack_unwinding_to_return(unlang_stack_t *stack)		{ return stack->unwind & UNWIND_FLAG_RETURN_POINT; }
static inline void stack_unwind_top_frame_clear(unlang_stack_t *stack)		{ stack->unwind &= ~UNWIND_FLAG_TOP_FRAME; }
static inline void stack_unwind_break_clear(unlang_stack_t *stack)		{ stack->unwind &= ~UNWIND_FLAG_BREAK_POINT; }
static inline void stack_unwind_return_clear(unlang_stack_t *stack)		{ stack->unwind &= ~UNWIND_FLAG_RETURN_POINT; }

static inline unlang_stack_frame_t *frame_current(request_t *request)
{
	unlang_stack_t *stack = request->stack;

	return &stack->frame[stack->depth];
}

static inline int stack_depth_current(request_t *request)
{
	unlang_stack_t *stack = request->stack;

	return stack->depth;
}

static inline void frame_state_init(unlang_stack_t *stack, unlang_stack_frame_t *frame)
{
	unlang_t const	*instruction = frame->instruction;
	unlang_op_t	*op;
	char const	*name;

	unlang_frame_perf_init(frame);

	op = &unlang_ops[instruction->type];
	name = op->frame_state_type ? op->frame_state_type : __location__;

	frame->process = op->interpret;
	frame->signal = op->signal;

#ifdef HAVE_TALLOC_ZERO_POOLED_OBJECT
	/*
	 *	Pooled object
	 */
	if (op->frame_state_pool_size && op->frame_state_size) {
		MEM(frame->state = _talloc_zero_pooled_object(stack,
							      op->frame_state_size, name,
							      op->frame_state_pool_objects,
							      op->frame_state_pool_size));
	} else
#endif
	/*
	 *	Pool
	 */
	if (op->frame_state_pool_size && !op->frame_state_size) {
		MEM(frame->state = talloc_pool(stack,
					       op->frame_state_pool_size +
					       ((20 + 68 + 15) * op->frame_state_pool_objects))); /* from samba talloc.c */
		talloc_set_name_const(frame->state, name);
	/*
	 *	Object
	 */
	} else if (op->frame_state_size) {
		MEM(frame->state = _talloc_zero(stack, op->frame_state_size, name));
	}

	/*
	 *	Don't change frame->retry, it may be left over from a previous retry.
	 */
}

/** Cleanup any lingering frame state
 *
 */
static inline void frame_cleanup(unlang_stack_frame_t *frame)
{
	unlang_frame_perf_cleanup(frame);

	/*
	 *	Don't clear top_frame flag, bad things happen...
	 */
	frame->uflags &= UNWIND_FLAG_TOP_FRAME;
	if (frame->state) {
		talloc_free_children(frame->state); /* *(ev->parent) = NULL in event.c */
		TALLOC_FREE(frame->state);
	}
}

/** Advance to the next sibling instruction
 *
 */
static inline void frame_next(unlang_stack_t *stack, unlang_stack_frame_t *frame)
{
	frame_cleanup(frame);
	frame->instruction = frame->next;

	if (!frame->instruction) return;

	frame->next = frame->instruction->next;

	frame_state_init(stack, frame);
}

/** Pop a stack frame, removing any associated dynamically allocated state
 *
 * @param[in] request	The current request.
 * @param[in] stack	frame to pop.
 */
static inline void frame_pop(request_t *request, unlang_stack_t *stack)
{
	unlang_stack_frame_t *frame;

	fr_assert(stack->depth > 1);

	frame = &stack->frame[stack->depth];

	/*
	 *	We clean up the retries when we pop the frame, not
	 *	when we do a frame_cleanup().  That's because
	 *	frame_cleanup() is called from the signal handler, and
	 *	we need to keep frame->retry around to ensure that we
	 *	know how to _stop_ the retries after they've hit a timeout.
	 */
	TALLOC_FREE(frame->retry);

	frame_cleanup(frame);

	frame = &stack->frame[--stack->depth];

	/*
	 *	Signal the frame to get it back into a consistent state
	 *	as we won't be calling the resume function.
	 */
	if (stack->unwind && is_repeatable(frame) &&
	    ((is_stack_unwinding_to_break(stack) && !is_break_point(frame)) ||
	     (is_stack_unwinding_to_return(stack) && !is_return_point(frame)))) {
		if (frame->signal) frame->signal(request, frame, FR_SIGNAL_CANCEL);
		repeatable_clear(frame);
	}
}

/** Mark the current stack frame up for repeat, and set a new process function
 *
 */
static inline void frame_repeat(unlang_stack_frame_t *frame, unlang_process_t process)
{
	repeatable_set(frame);
	frame->process = process;
}

/** @name Conversion functions for converting #unlang_t to its specialisations
 *
 * Simple conversions: #unlang_module_t and #unlang_group_t are subclasses of #unlang_t,
 * so we often want to go back and forth between them.
 *
 * @{
 */
static inline unlang_group_t *unlang_generic_to_group(unlang_t const *p)
{
	fr_assert((p->type > UNLANG_TYPE_MODULE) && (p->type <= UNLANG_TYPE_POLICY));

	return UNCONST(unlang_group_t *, p);
}

static inline unlang_t *unlang_group_to_generic(unlang_group_t const *p)
{
	return UNCONST(unlang_t *, p);
}

static inline unlang_tmpl_t *unlang_generic_to_tmpl(unlang_t const *p)
{
	fr_assert(p->type == UNLANG_TYPE_TMPL);
	return UNCONST(unlang_tmpl_t *, talloc_get_type_abort_const(p, unlang_tmpl_t));
}

static inline unlang_t *unlang_tmpl_to_generic(unlang_tmpl_t const *p)
{
	return UNCONST(unlang_t *, p);
}
/** @} */

/** @name Internal interpreter functions needed by ops
 *
 * @{
 */
int		unlang_interpret_push(request_t *request, unlang_t const *instruction,
				      rlm_rcode_t default_rcode, bool do_next_sibling, bool top_frame)
				      CC_HINT(warn_unused_result);

int		unlang_interpret_push_children(rlm_rcode_t *p_result, request_t *request,
					       rlm_rcode_t default_rcode, bool do_next_sibling)
					       CC_HINT(warn_unused_result);

int		unlang_op_init(void);

void		unlang_op_free(void);

/** @} */

/** @name io shims
 *
 * Functions to simulate a 'proto' module when we're running 'fake'
 * requests. i.e. those created by parallel and subrequest.
 *
 * @{
 */
request_t		*unlang_io_subrequest_alloc(request_t *parent, fr_dict_t const *namespace, bool detachable);

/** @} */

/** @name op init functions
 *
 * Functions to trigger registration of the various unlang ops.
 *
 * @{
 */
void		unlang_register(int type, unlang_op_t *op);

void		unlang_call_init(void);

void		unlang_caller_init(void);

void		unlang_condition_init(void);

void		unlang_foreach_init(TALLOC_CTX *ctx);

void		unlang_function_init(void);

void		unlang_group_init(void);

void		unlang_load_balance_init(void);

void		unlang_map_init(void);

void		unlang_module_init(void);

void		unlang_return_init(void);

void		unlang_parallel_init(void);

int		unlang_subrequest_op_init(void);

void		unlang_subrequest_op_free(void);

void		unlang_detach_init(void);

void		unlang_switch_init(void);

void		unlang_tmpl_init(void);

void		unlang_edit_init(void);

void		unlang_timeout_init(void);

void		unlang_limit_init(void);

 /** @} */

#ifdef __cplusplus
}
#endif
