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
#include <freeradius-devel/server/time_tracking.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/io/listen.h>

#ifdef __cplusplus
extern "C" {
#endif

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
	UNLANG_TYPE_BREAK,			//!< Break statement (within a #UNLANG_TYPE_FOREACH or #UNLANG_TYPE_CASE).
	UNLANG_TYPE_CONTINUE,			//!< Break statement (within a #UNLANG_TYPE_FOREACH).
	UNLANG_TYPE_RETURN,			//!< Return statement.
	UNLANG_TYPE_MAP,			//!< Mapping section (like #UNLANG_TYPE_UPDATE, but uses
						//!< values from a #map_proc_t call).
	UNLANG_TYPE_SUBREQUEST,			//!< create a child subrequest
	UNLANG_TYPE_CHILD_REQUEST,		//!< a frame at the top of a child's request stack used to signal the
						///< parent when the child is complete.
	UNLANG_TYPE_DETACH,			//!< detach a child
	UNLANG_TYPE_CALL,			//!< call another virtual server
	UNLANG_TYPE_CALLER,			//!< conditionally check parent dictionary type
	UNLANG_TYPE_TIMEOUT,			//!< time-based timeouts.
	UNLANG_TYPE_LIMIT,			//!< limit number of requests in a section
	UNLANG_TYPE_TRANSACTION,       		//!< transactions for editing lists
	UNLANG_TYPE_TRY,       			//!< try / catch blocks
	UNLANG_TYPE_CATCH,       		//!< catch a previous try
	UNLANG_TYPE_FINALLY,			//!< run at the end of a virtual server.
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

DIAG_OFF(attributes)
typedef enum CC_HINT(flag_enum) {
	UNLANG_FRAME_FLAG_NONE			= 0x00,			//!< No flags.
	UNLANG_FRAME_FLAG_REPEAT		= 0x01,			//!< Repeat the frame on the way up the stack.
	UNLANG_FRAME_FLAG_TOP_FRAME		= 0x02,			//!< are we the top frame of the stack?
									///< If true, causes the interpreter to stop
									///< interpreting and return, control then passes
									///< to whatever called the interpreter.
	UNLANG_FRAME_FLAG_YIELDED		= 0x04,			//!< frame has yielded
	UNLANG_FRAME_FLAG_UNWIND		= 0x08,			//!< This frame should be unwound without evaluation.
} unlang_frame_flag_t;
DIAG_ON(attributes)

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
	unlang_mod_actions_t	actions;	//!< Priorities, etc. for the various return codes.
};

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
typedef unlang_action_t (*unlang_process_t)(unlang_result_t *p_result, request_t *request,
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

typedef struct {
	virtual_server_t const		*vs;			//!< Virtual server we're compiling in the context of.
								///< This shouldn't change during the compilation of
								///< a single unlang section.
	char const			*section_name1;
	char const			*section_name2;
	unlang_mod_actions_t		actions;
	tmpl_rules_t const		*rules;
} unlang_compile_ctx_t;

typedef unlang_t *(*unlang_compile_t)(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci);

#define UNLANG_IGNORE ((unlang_t *) -1)

unlang_t *unlang_compile_empty(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_SECTION *cs, unlang_type_t type);

unlang_t *unlang_compile_section(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_SECTION *cs, unlang_type_t type);

unlang_t *unlang_compile_children(unlang_group_t *g, unlang_compile_ctx_t *unlang_ctx);

unlang_group_t *unlang_group_allocate(unlang_t *parent, CONF_SECTION *cs, unlang_type_t type);

int unlang_define_local_variable(CONF_ITEM *ci, unlang_variable_t *var, tmpl_rules_t *t_rules, fr_type_t type, char const *name,
				 fr_dict_attr_t const *ref);

bool unlang_compile_limit_subsection(CONF_SECTION *cs, char const *name);

/*
 *	@todo - These functions should be made private once all of they keywords have been moved to foo(args) syntax.
 */
bool pass2_fixup_tmpl(UNUSED TALLOC_CTX *ctx, tmpl_t **vpt_p, CONF_ITEM const *ci, fr_dict_t const *dict);
bool pass2_fixup_map(map_t *map, tmpl_rules_t const *rules, fr_dict_attr_t const *parent);
bool pass2_fixup_update(unlang_group_t *g, tmpl_rules_t const *rules);
bool pass2_fixup_map_rhs(unlang_group_t *g, tmpl_rules_t const *rules);

/*
 *	When we switch to a new unlang ctx, we use the new component
 *	name and number, but we use the CURRENT actions.
 */
static inline CC_HINT(always_inline)
void unlang_compile_ctx_copy(unlang_compile_ctx_t *dst, unlang_compile_ctx_t const *src)
{
	int i;

	*dst = *src;

	/*
	 *	Ensure that none of the actions are RETRY.
	 */
	for (i = 0; i < RLM_MODULE_NUMCODES; i++) {
		if (dst->actions.actions[i] == MOD_ACTION_RETRY) dst->actions.actions[i] = MOD_PRIORITY_MIN;
	}
	memset(&dst->actions.retry, 0, sizeof(dst->actions.retry)); \
}


#ifndef NDEBUG
static inline CC_HINT(always_inline) int unlang_attr_rules_verify(tmpl_attr_rules_t const *rules)
{
	if (!fr_cond_assert_msg(rules->dict_def, "No protocol dictionary set")) return -1;
	if (!fr_cond_assert_msg(rules->dict_def != fr_dict_internal(), "rules->attr.dict_def must not be the internal dictionary")) return -1;
	if (!fr_cond_assert_msg(!rules->allow_foreign, "rules->attr.allow_foreign must be false")) return -1;

	return 0;
}

static inline CC_HINT(always_inline) int unlang_rules_verify(tmpl_rules_t const *rules)
{
	if (!fr_cond_assert_msg(!rules->at_runtime, "rules->at_runtime must be false")) return -1;
	return unlang_attr_rules_verify(&rules->attr);
}

#define RULES_VERIFY(_rules) do { if (unlang_rules_verify(_rules) < 0) return NULL; } while (0)
#else
#define RULES_VERIFY(_rules)
#endif

DIAG_OFF(attributes)
typedef enum CC_HINT(flag_enum) {
	UNLANG_OP_FLAG_NONE			= 0x00,			//!< No flags.
	UNLANG_OP_FLAG_DEBUG_BRACES		= 0x01,			//!< Print debug braces.
	UNLANG_OP_FLAG_RCODE_SET		= 0x02,			//!< Set request->rcode to the result of this operation.
	UNLANG_OP_FLAG_NO_FORCE_UNWIND		= 0x04,			//!< Must not be cancelled.
									///< @Note Slightly confusingly, a cancellation signal
									///< can still be delivered to a frame that is not
									///< cancellable, but the frame won't be automatically
									///< unwound.  This lets the frame know that cancellation
									///< is desired, but can be ignored.
	UNLANG_OP_FLAG_BREAK_POINT		= 0x08,			//!< Break point.
	UNLANG_OP_FLAG_RETURN_POINT		= 0x10,			//!< Return point.
	UNLANG_OP_FLAG_CONTINUE_POINT		= 0x20,			//!< Continue point.

	UNLANG_OP_FLAG_SINGLE_WORD		= 0x1000,		//!< the operation is parsed and compiled as a single word
	UNLANG_OP_FLAG_INTERNAL			= 0x2000,		//!< it's not a real keyword

} unlang_op_flag_t;
DIAG_ON(attributes)

/** An unlang operation
 *
 * These are like the opcodes in other interpreters.  Each operation, when executed
 * will return an #unlang_action_t, which determines what the interpreter does next.
 */
typedef struct {
	char const		*name;				//!< Name of the keyword
	unlang_type_t		type;				//!< enum value for the keyword

	unlang_compile_t	compile;			//!< compile the keyword

	unlang_process_t	interpret;     			//!< Function to interpret the keyword

	unlang_signal_t		signal;				//!< Function to signal stop / dup / whatever

	unlang_dump_t		dump;				//!< Dump additional information about the frame state.

	size_t			unlang_size;			//!< Total length of the unlang_t + specialisation struct.
	char const		*unlang_name;			//!< Talloc type name for the unlang_t

	unsigned		pool_headers;			//!< How much additional space to allocate for chunk headers.
	size_t			pool_len;			//!< How much additional space to allocate for chunks


	unlang_thread_instantiate_t thread_instantiate;		//!< per-thread instantiation function
	size_t			thread_inst_size;
	char const		*thread_inst_type;

	unlang_op_flag_t	flag;				//!< Interpreter flags for this operation.

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

void	unlang_stack_signal(request_t *request, fr_signal_t action, int limit);

typedef struct {
	request_t		*request;
	int			depth;				//!< of this retry structure
	fr_retry_state_t	state;
	uint32_t       		count;
	fr_timer_t		*ev;
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

	unlang_result_t		section_result;			//!< The aggregate result of executing all siblings
								///< in this section.  This will be merged with the
								///< higher stack frame's rcode when the frame is popped.
								///< If the rcode is set to RLM_MODULE_NOT_SET when
								///< the frame is popped, then the rcode of the frame
								///< does not modify the rcode of the frame above it.

	unlang_result_t		scratch_result;			//!< The result of executing the current instruction.
								///< This will be set to RLM_MODULE_NOT_SET, and
								///< MOD_ACTION_NOT_SET when a new instruction is set
								///< for the frame.  If result_p does not point to this
								///< field, the rcode and priority returned will be
								///< left as NOT_SET and will be ignored.
								///< This values here will persist between yields.

	unlang_result_t		*result_p;			//!< Where to write the result of executing the current
								///< instruction.  Will either point to `scratch_result`,
								///< OR if the parent does not want its rcode to be updated
								///< by a child it pushed for evaluation, it will point to
								///< memory in the parent's frame state, so that the parent
								///< can manually process the rcode.

	unlang_retry_t		*retry;				//!< if the frame is being retried.


	rindent_t		indent;				//!< Indent level of the request when the frame was
								///< created.  This is used to restore the indent
								///< level when the stack is being forcefully unwound.

	unlang_frame_flag_t	flag;				//!< Flags that mark up the frame for various things
								///< such as being the point where break, return or
								///< continue stop, or for forced unwinding.

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

	int			depth;				//!< Current depth we're executing at.
	uint8_t			unwind;				//!< Unwind to this frame if it exists.
								///< This is used for break and return.
	unlang_stack_frame_t	frame[UNLANG_STACK_MAX];	//!< The stack...
} unlang_stack_t;

/** Different operations the interpreter can execute
 */
extern unlang_op_t unlang_ops[];
extern fr_hash_table_t *unlang_op_table;

#define MOD_NUM_TYPES (UNLANG_TYPE_XLAT + 1)

extern fr_table_num_sorted_t const mod_rcode_table[];
extern size_t mod_rcode_table_len;
extern fr_table_num_sorted_t const mod_action_table[];
extern size_t mod_action_table_len;

static inline void repeatable_set(unlang_stack_frame_t *frame)			{ frame->flag |= UNLANG_FRAME_FLAG_REPEAT; }
static inline void top_frame_set(unlang_stack_frame_t *frame) 			{ frame->flag |= UNLANG_FRAME_FLAG_TOP_FRAME; }
static inline void yielded_set(unlang_stack_frame_t *frame)			{ frame->flag |= UNLANG_FRAME_FLAG_YIELDED; }
static inline void unwind_set(unlang_stack_frame_t *frame)			{ frame->flag |= UNLANG_FRAME_FLAG_UNWIND; }

static inline void repeatable_clear(unlang_stack_frame_t *frame)		{ frame->flag &= ~UNLANG_FRAME_FLAG_REPEAT; }
static inline void top_frame_clear(unlang_stack_frame_t *frame)			{ frame->flag &= ~UNLANG_FRAME_FLAG_TOP_FRAME; }
static inline void yielded_clear(unlang_stack_frame_t *frame) 			{ frame->flag &= ~UNLANG_FRAME_FLAG_YIELDED; }
static inline void unwind_clear(unlang_stack_frame_t *frame)			{ frame->flag &= ~UNLANG_FRAME_FLAG_UNWIND; }

static inline bool is_repeatable(unlang_stack_frame_t const *frame)		{ return frame->flag & UNLANG_FRAME_FLAG_REPEAT; }
static inline bool is_top_frame(unlang_stack_frame_t const *frame)		{ return frame->flag & UNLANG_FRAME_FLAG_TOP_FRAME; }
static inline bool is_yielded(unlang_stack_frame_t const *frame) 		{ return frame->flag & UNLANG_FRAME_FLAG_YIELDED; }
static inline bool is_unwinding(unlang_stack_frame_t const *frame) 		{ return frame->flag & UNLANG_FRAME_FLAG_UNWIND; }
static inline bool is_private_result(unlang_stack_frame_t const *frame)		{ return !(frame->result_p == &frame->section_result); }

static inline bool _instruction_has_debug_braces(unlang_t const *instruction)	{ return unlang_ops[instruction->type].flag & UNLANG_OP_FLAG_DEBUG_BRACES; }
static inline bool _frame_has_debug_braces(unlang_stack_frame_t const *frame)	{ return unlang_ops[frame->instruction->type].flag & UNLANG_OP_FLAG_DEBUG_BRACES; }
#define has_debug_braces(_thing) \
		   _Generic((_thing), \
			unlang_t *: _instruction_has_debug_braces((unlang_t const *)(_thing)), \
			unlang_t const *: _instruction_has_debug_braces((unlang_t const *)(_thing)), \
			unlang_stack_frame_t *: _frame_has_debug_braces((unlang_stack_frame_t const *)(_thing)), \
			unlang_stack_frame_t const *: _frame_has_debug_braces((unlang_stack_frame_t const *)(_thing)) \
		   )
static inline bool is_rcode_set(unlang_stack_frame_t const *frame)		{ return unlang_ops[frame->instruction->type].flag & UNLANG_OP_FLAG_RCODE_SET; }
static inline bool is_cancellable(unlang_stack_frame_t const *frame)		{ return !(unlang_ops[frame->instruction->type].flag & UNLANG_OP_FLAG_NO_FORCE_UNWIND); }
static inline bool is_break_point(unlang_stack_frame_t const *frame)		{ return unlang_ops[frame->instruction->type].flag & UNLANG_OP_FLAG_BREAK_POINT; }
static inline bool is_return_point(unlang_stack_frame_t const *frame) 		{ return unlang_ops[frame->instruction->type].flag & UNLANG_OP_FLAG_RETURN_POINT; }
static inline bool is_continue_point(unlang_stack_frame_t const *frame) 	{ return unlang_ops[frame->instruction->type].flag & UNLANG_OP_FLAG_CONTINUE_POINT; }

/** @name Debug functions
 *
 * @{
 */
void stack_dump(request_t *request);
void stack_dump_with_actions(request_t *request);
/** @} */

/** Find the first frame with a given flag
 *
 * @return
 *	- 0 if no frame has the flag.
 *	- The index of the first frame with the flag.
 */
static inline unsigned int unlang_frame_by_flag(unlang_stack_t *stack, unlang_frame_flag_t flag)
{
	unsigned int	i;

	for (i = stack->depth; i > 0; i--) {
		unlang_stack_frame_t *frame = &stack->frame[i];

		if (frame->flag & flag) return i;
	}
	return 0;
}

/** Find the first frame with a given flag
 *
 * @return
 *	- 0 if no frame has the flag.
 *	- The index of the first frame with the flag.
 */
static inline unsigned int unlang_frame_by_op_flag(unlang_stack_t *stack, unlang_op_flag_t flag)
{
	unsigned int	i;

	for (i = stack->depth; i > 0; i--) {
		unlang_stack_frame_t *frame = &stack->frame[i];

		if (unlang_ops[frame->instruction->type].flag & flag) return i;
	}
	return 0;
}

/** Mark up frames as cancelled so they're immediately popped by the interpreter
 *
 * @note We used to do this asynchronously, but now we may need to execute timeout sections
 *       which means it's not enough to pop and cleanup the stack, we need continue executing
 *	the request.
 *
 * @param[in] stack	The current stack.
 * @param[in] to_depth	mark all frames below this depth as cancelled.
 */
static inline unlang_action_t unwind_to_depth(unlang_stack_t *stack, unsigned int to_depth)
{
	unlang_stack_frame_t	*frame;
	unsigned int i, depth = stack->depth;	/* must be signed to avoid underflow */

	if (!fr_cond_assert(to_depth >= 1)) return UNLANG_ACTION_FAIL;

	for (i = depth; i >= to_depth; i--) {
		frame = &stack->frame[i];
		if (!is_cancellable(frame)) continue;
		unwind_set(frame);
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Mark the entire stack as cancelled
 *
 * This cancels all frames up to the next "break" frame.
 *
 * @param[out] depth_p		Depth of the break || return || continue point.
 * @param[in] stack		The current stack.
 * @param[in] flag		Flag to search for.  One of:
 *				- UNLANG_OP_FLAG_BREAK_POINT
 *				- UNLANG_OP_FLAG_RETURN_POINT
 *				- UNLANG_OP_FLAG_CONTINUE_POINT
 * @return UNLANG_ACTION_CALCULATE_RESULT
 */
static inline unlang_action_t unwind_to_op_flag(unsigned int *depth_p, unlang_stack_t *stack, unlang_op_flag_t flag)
{
	unsigned int depth;

	depth = unlang_frame_by_op_flag(stack, flag);
	if (depth == 0) {
		if (depth_p) *depth_p = stack->depth + 1;	/* Don't cancel any frames! */
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	unwind_to_depth(stack, depth + 1);	/* cancel UP TO the break point */

	if (depth_p) *depth_p = depth;

	return UNLANG_ACTION_CALCULATE_RESULT;
}

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

/** Initialise memory and instruction for a frame when a new instruction is to be evaluated
 *
 * @note We don't change result_p here, we only reset the scratch values.  This is because
 *	 Whatever pushed the frame onto the stack generally wants the aggregate result of
 *	 the complete section, not just the first instruction.
 *
 * @param[in] stack	the current request stack.
 * @param[in] frame	frame to initialise
 */
static inline void frame_state_init(unlang_stack_t *stack, unlang_stack_frame_t *frame)
{
	unlang_t const	*instruction = frame->instruction;
	unlang_op_t	*op;
	char const	*name;

	unlang_frame_perf_init(frame);

	op = &unlang_ops[instruction->type];
	name = op->frame_state_type ? op->frame_state_type : __location__;

	/*
	 *	Reset for each instruction
	 */
	frame->scratch_result.rcode = RLM_MODULE_NOT_SET;
	frame->scratch_result.priority = MOD_ACTION_NOT_SET;

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
	frame->flag &= UNLANG_FRAME_FLAG_TOP_FRAME;
	TALLOC_FREE(frame->retry);
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

	if (!frame->instruction) return;	/* No siblings, need to pop instead */

	frame->next = frame->instruction->next;

	/*
	 *	We _may_ want to take a new result_p value in future but
	 *	for now default to the scratch result.  Generally the thing
	 *	advancing the frame is within this library, and doesn't
	 *	need custom behaviour for rcodes.
	 */
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

	fr_assert(stack->depth >= 1);

	frame = &stack->frame[stack->depth];

	/*
	 *	Signal the frame to get it back into a consistent state
	 *	as we won't be calling the resume function.
	 *
	 *	If the frame was cancelled, the signal function will
	 *	have already been called.
	 */
	if (!is_unwinding(frame) && is_repeatable(frame)) {
		if (frame->signal) frame->signal(request, frame, FR_SIGNAL_CANCEL);
		repeatable_clear(frame);
	}

	/*
	 *	We clean up the retries when we pop the frame, not
	 *	when we do a frame_cleanup().  That's because
	 *	frame_cleanup() is called from the signal handler, and
	 *	we need to keep frame->retry around to ensure that we
	 *	know how to _stop_ the retries after they've hit a timeout.
	 */
	TALLOC_FREE(frame->retry);

	/*
	 *	Ensure log indent is at the same level as it was when
	 *	the frame was pushed.  This is important when we're
	 *	unwinding the stack and forcefully cancelling calls.
	 */
	request->log.indent = frame->indent;

	frame_cleanup(frame);

	stack->depth--;
}

/** Mark the current stack frame up for repeat, and set a new process function
 *
 */
static inline void frame_repeat(unlang_stack_frame_t *frame, unlang_process_t process)
{
	repeatable_set(frame);
	frame->process = process;
}

static inline unlang_action_t frame_set_next(unlang_stack_frame_t *frame, unlang_t *unlang)
{
	/*
	 *	We're skipping the remaining siblings, stop the
	 *	interpreter from continuing and have it pop
	 *	this frame, running cleanups normally.
	 *
	 *	We don't explicitly cleanup here, otherwise we
	 *	end up doing it twice and bad things happen.
	 */
	if (!unlang) {
		frame->next = NULL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Clean up this frame now, so that stats, etc. will be
	 *	processed using the correct frame.
	 */
	frame_cleanup(frame);

	/*
	 *	frame_next() will call cleanup *before* resetting the frame->instruction.
	 *	but since the instruction is NULL, no duplicate cleanups will happen.
	 *
	 *	frame_next() will then set frame->instruction = frame->next, and everything will be OK.
	 */
	frame->instruction = NULL;
	frame->next = unlang;
	return UNLANG_ACTION_EXECUTE_NEXT;
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
int		unlang_interpret_push(unlang_result_t *p_result, request_t *request, unlang_t const *instruction,
				      unlang_frame_conf_t const *conf, bool do_next_sibling)
				      CC_HINT(warn_unused_result);

unlang_action_t unlang_interpret_push_children(unlang_result_t *p_result, request_t *request,
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
void		unlang_register(unlang_op_t *op) CC_HINT(nonnull);

void		unlang_call_init(void);

void		unlang_caller_init(void);

void		unlang_condition_init(void);

void		unlang_finally_init(void);

void		unlang_foreach_init(void);

void		unlang_function_init(void);

void		unlang_group_init(void);

void		unlang_load_balance_init(void);

void		unlang_map_init(void);

void		unlang_module_init(void);

void		unlang_return_init(void);

void		unlang_parallel_init(void);

int		unlang_subrequest_op_init(void);

void		unlang_detach_init(void);

void		unlang_switch_init(void);

void		unlang_tmpl_init(void);

void		unlang_edit_init(void);

void		unlang_timeout_init(void);

void		unlang_transaction_init(void);

void		unlang_limit_init(void);

void		unlang_try_init(void);

void		unlang_catch_init(void);

 /** @} */

#ifdef __cplusplus
}
#endif
