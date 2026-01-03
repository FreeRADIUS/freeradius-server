#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/unlang/xlat.h
 * @brief xlat expansion parsing and evaluation API.
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(xlat_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/retry.h>

/*
 *	Forward declarations
 */
typedef enum {
	XLAT_ACTION_PUSH_CHILD = 1,		//!< A deeper level of nesting needs to be evaluated.
	XLAT_ACTION_PUSH_UNLANG,		//!< An xlat function pushed an unlang frame onto the unlang stack.
						///< This frame needs to be evaluated, and then we need to call
						///< the xlat's resume function.
	XLAT_ACTION_YIELD,			//!< An xlat function pushed a resume frame onto the stack.
	XLAT_ACTION_DONE,			//!< We're done evaluating this level of nesting.
	XLAT_ACTION_FAIL			//!< An xlat function failed.
} xlat_action_t;

typedef struct xlat_inst_s xlat_inst_t;
typedef struct xlat_thread_inst_s xlat_thread_inst_t;

#include <freeradius-devel/server/request.h>

typedef ssize_t (*xlat_escape_legacy_t)(request_t *request, char *out, size_t outlen, char const *in, void *arg);

#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/signal.h>
#include <freeradius-devel/server/tmpl.h>

#include <freeradius-devel/util/heap.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/value.h>

#include <freeradius-devel/unlang/call_env.h>
#include <freeradius-devel/unlang/xlat_ctx.h>
#include <freeradius-devel/unlang/interpret.h>

/** Instance data for an xlat expansion node
 *
 */
struct xlat_inst_s {
	fr_heap_index_t		idx;		//!< Entry in heap of xlat instances.
						///< Identical instances are used for
						///< global instance data and thread-specific
						///< instance data.

	xlat_exp_t		*node;		//!< Node this data relates to.
	void			*data;		//!< xlat node specific instance data.
	call_env_t const 	*call_env;	//!< Per call environment.
};

/** Thread specific instance data for xlat expansion node
 *
 */
struct xlat_thread_inst_s {
	fr_heap_index_t		idx;		//!< Entry in heap of xlat thread instances.
						///< Identical instances are used for
						///< global instance data and thread-specific
						///< instance data.

	fr_event_list_t		*el;		//!< Event list associated with this thread.

	xlat_exp_t const	*node;		//!< Node this data relates to.
 	void			*data;		//!< Thread specific instance data.

	module_ctx_t const	*mctx;		//!< A synthesised module calling ctx containing
						///< module global and thread instance data.

	uint64_t		total_calls;	//! total number of times we've been called
	uint64_t		active_callers; //! number of active callers.  i.e. number of current yields
};

typedef struct xlat_s xlat_t;

/** Flags that control resolution and evaluation
 *
 */
typedef struct {
	unsigned int   		needs_resolving : 1;	//!< Needs pass2 resolution.
	unsigned int		pure : 1;		//!< has no external side effects, true for BOX, LITERAL, and some functions
	unsigned int		impure_func : 1;	//!< xlat contains an impure function
	unsigned int		can_purify : 1;		//!< if the xlat has a pure function with pure arguments.

	unsigned int		constant : 1;		//!< xlat is just tmpl_attr_tail_data, or XLAT_BOX
	unsigned int		xlat : 1;		//!< it's an xlat wrapper
} xlat_flags_t;

#define XLAT_FLAGS_INIT ((xlat_flags_t) { .pure = true, .can_purify = true, .constant = true, })

extern fr_table_num_sorted_t const xlat_action_table[];
extern size_t xlat_action_table_len;

/** A function used to escape an argument passed to an xlat
 *
 * @param[in] request		being processed.  Used mostly for debugging.
 * @param[in,out] vb		to escape
 * @param[in] uctx		a "context" for the escaping
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*xlat_escape_func_t)(request_t *request, fr_value_box_t *vb, void *uctx);

typedef enum {
	XLAT_ARG_VARIADIC_DISABLED	= 0,
	XLAT_ARG_VARIADIC_EMPTY_SQUASH	= 1,	//!< Empty argument groups are removed.
	XLAT_ARG_VARIADIC_EMPTY_KEEP	= 2, 	//!< Empty argument groups are left alone,
						///< and either passed through as empty groups
						///< or null boxes.
} xlat_arg_parser_variadic_t;

/** Definition for a single argument consumend by an xlat function
 *
 */
typedef struct {
	unsigned int			required : 1;	//!< Argument must be present, and non-empty.
	unsigned int			concat : 1;    	//!< Concat boxes together.
	unsigned int			single : 1;    	//!< Argument must only contain a single box
	unsigned int			allow_wildcard : 1; //!< For parsing the cursor
	unsigned int			will_escape : 1;   //!< the function will do escaping and concatenation.
	unsigned int			always_escape : 1;  //!< Pass all arguments to escape function not just
							    ///< tainted ones.
	xlat_arg_parser_variadic_t	variadic;	//!< All additional boxes should be processed
							///< using this definition.
	fr_type_t			type;		//!< Type to cast argument to.
	xlat_escape_func_t		func;		//!< Function to handle tainted values.
	fr_value_box_safe_for_t		safe_for;	//!< Escaped value to set for boxes processed by
							///< this escape function.
	void				*uctx;		//!< Argument to pass to escape callback.
} xlat_arg_parser_t;

#define XLAT_ARG_PARSER_CURSOR { .required = true, .single = true, .allow_wildcard = true, .type = FR_TYPE_PAIR_CURSOR, .safe_for = FR_VALUE_BOX_SAFE_FOR_ANY }

typedef struct {
	tmpl_res_rules_t const	*tr_rules;	//!< tmpl resolution rules.
	bool			allow_unresolved; //!< If false, all resolution steps must be completed
						///< this round, otherwise an error will be produced.
} xlat_res_rules_t;

#define XLAT_ARG_PARSER_TERMINATOR { .required = false, .concat = false, .single = false, .variadic = false, \
					.type = FR_TYPE_NULL, .func = NULL, .uctx = NULL }

/** A callback when the the timeout occurs
 *
 * Used when a xlat needs wait for an event.
 * Typically the callback is set, and then the xlat returns unlang_xlat_yield().
 *
 * @note The callback is automatically removed on unlang_interpret_mark_runnable(), i.e. if an event
 *	on a registered FD occurs before the timeout event fires.
 *
 * @param[in] xctx		xlat calling ctx.  Contains all instance data.
 * @param[in] request		the request.
 * @param[in] fired		the time the timeout event actually fired.
 */
typedef	void (*fr_unlang_xlat_timeout_t)(xlat_ctx_t const *xctx, request_t *request, fr_time_t fired);

/** A callback when the the timeout occurs
 *
 * Used when a xlat needs wait for an event.
 * Typically the callback is set, and then the xlat returns unlang_xlat_yield().
 *
 * @note The callback is automatically removed on unlang_interpret_mark_runnable(), i.e. if an event
 *	on a registered FD occurs before the timeout event fires.
 *
 * @param[in] xctx		xlat calling ctx.  Contains all instance data.
 * @param[in] request		the request.
 * @param[in] retry		retry status.  "now" is in retry->updated
 */
typedef	void (*fr_unlang_xlat_retry_t)(xlat_ctx_t const *xctx, request_t *request, fr_retry_t const *retry);

/** A callback when the FD is ready for reading
 *
 * Used when a xlat needs to read from an FD.  Typically the callback is set, and then the
 * xlat returns unlang_xlat_yield().
 *
 * @note The callback is automatically removed on unlang_interpret_mark_runnable(), so
 *
 * @param[in] xctx		xlat calling ctx.  Contains all instance data.
 * @param[in] request		the current request.
 * @param[in] fd		the file descriptor.
 */
typedef void (*fr_unlang_xlat_fd_event_t)(xlat_ctx_t const *xctx, request_t *request, int fd);

/** xlat callback function
 *
 * Ingests a list of value boxes as arguments.
 *
 * @param[in] ctx		to allocate any fr_value_box_t in.
 * @param[out] out		Where to append #fr_value_box_t containing the output of
 *				this function.
 * @param[in] xctx		xlat calling ctx.  Contains all instance data and the resume
 *				ctx if this function is being resumed.
 * @param[in] request		The current request.
 * @param[in] in		Input arguments.
 * @return
 *	- XLAT_ACTION_YIELD	xlat function is waiting on an I/O event and
 *				has pushed a resumption function onto the stack.
 *	- XLAT_ACTION_DONE	xlat function completed. This does not necessarily
 *				mean it turned a result.
 *	- XLAT_ACTION_FAIL	the xlat function failed.
 */
typedef xlat_action_t (*xlat_func_t)(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     xlat_ctx_t const *xctx, request_t *request, fr_value_box_list_t *in);

/** A callback when the request gets a fr_signal_t.
 *
 * @note The callback is automatically removed on unlang_interpret_mark_runnable().
 *
 * @param[in] request		The current request.
 * @param[in] xctx		xlat calling ctx.  Contains all instance data.
 * @param[in] action		which is signalling the request.
 */
typedef void (*xlat_func_signal_t)(xlat_ctx_t const *xctx, request_t *request, fr_signal_t action);

/** Allocate new instance data for an xlat instance
 *
 * @param[in] xctx	instantiate/detach calling ctx.

 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*xlat_instantiate_t)(xlat_inst_ctx_t const *xctx);

/** Allocate new thread instance data for an xlat instance
 *
 * @param[in] xctx	thread instantiate/detach ctx.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*xlat_thread_instantiate_t)(xlat_thread_inst_ctx_t const *xctx);

/** xlat detach callback
 *
 * Is called whenever an xlat_node_t is freed.
 *
 * Detach should close all handles associated with the xlat instance, and
 * free any memory allocated during instantiate.
 *
 * @param[in] xctx	instantiate/detach calling ctx.
 * @return
 *	- 0 on success.
 *	- -1 if detach failed.
 */
typedef int (*xlat_detach_t)(xlat_inst_ctx_t const *xctx);

/** xlat thread detach callback
 *
 * Is called whenever an xlat_node_t is freed (if ephemeral),
 * or when a thread exits.
 *
 * Detach should close all handles associated with the xlat instance, and
 * free any memory allocated during instantiate.
 *
 * @param[in] xctx	thread instantiate/detach calling ctx.
 * @return
 *	- 0 on success.
 *	- -1 if detach failed.
 */
typedef int (*xlat_thread_detach_t)(xlat_thread_inst_ctx_t const *xctx);

/** Set the next argument to the next item in the input list or NULL
 *
 * @param[in] _list	we're extracting arguments from.
 * @param[in] _prev	argument.
 * @param[in] _curr	argument we're populating.
 */
#define XLAT_ARGS_NEXT(_list, _prev, _curr) *(_curr) = likely(*(_prev) != NULL) ? fr_value_box_list_next(_list, *(_prev)) : NULL

#define XLAT_ARGS_1(_list, _a) \
	*(_a) = fr_value_box_list_head(_list)

#define XLAT_ARGS_2(_list, _a, _b) \
	do { \
		*(_a) = fr_value_box_list_head(_list); \
		XLAT_ARGS_NEXT(_list, _a, _b); \
	} while (0)

#define XLAT_ARGS_3(_list, _a, _b, _c) \
	do { \
		*(_a) = fr_value_box_list_head(_list); \
		XLAT_ARGS_NEXT(_list, _a, _b); \
		XLAT_ARGS_NEXT(_list, _b, _c); \
	} while (0)

#define XLAT_ARGS_4(_list, _a, _b, _c, _d) \
	do { \
		*(_a) = fr_value_box_list_head(_list); \
		XLAT_ARGS_NEXT(_list, _a, _b); \
		XLAT_ARGS_NEXT(_list, _b, _c); \
		XLAT_ARGS_NEXT(_list, _c, _d); \
	} while (0)

#define XLAT_ARGS_5(_list, _a, _b, _c, _d, _e) \
	do { \
		*(_a) = fr_value_box_list_head(_list); \
		XLAT_ARGS_NEXT(_list, _a, _b); \
		XLAT_ARGS_NEXT(_list, _b, _c); \
		XLAT_ARGS_NEXT(_list, _c, _d); \
		XLAT_ARGS_NEXT(_list, _d, _e); \
	} while (0)

#define XLAT_ARGS_6(_list, _a, _b, _c, _d, _e, _f) \
	do { \
		*(_a) = fr_value_box_list_head(_list); \
		XLAT_ARGS_NEXT(_list, _a, _b); \
		XLAT_ARGS_NEXT(_list, _b, _c); \
		XLAT_ARGS_NEXT(_list, _c, _d); \
		XLAT_ARGS_NEXT(_list, _d, _e); \
		XLAT_ARGS_NEXT(_list, _e, _f); \
	} while (0)

#define XLAT_ARGS_7(_list, _a, _b, _c, _d, _e, _f, _g) \
	do { \
		*(_a) = fr_value_box_list_head(_list); \
		XLAT_ARGS_NEXT(_list, _a, _b); \
		XLAT_ARGS_NEXT(_list, _b, _c); \
		XLAT_ARGS_NEXT(_list, _c, _d); \
		XLAT_ARGS_NEXT(_list, _d, _e); \
		XLAT_ARGS_NEXT(_list, _e, _f); \
		XLAT_ARGS_NEXT(_list, _f, _g); \
	} while (0)

#define XLAT_ARGS_8(_list, _a, _b, _c, _d, _e, _f, _g, _h) \
	do { \
		*(_a) = fr_value_box_list_head(_list); \
		XLAT_ARGS_NEXT(_list, _a, _b); \
		XLAT_ARGS_NEXT(_list, _b, _c); \
		XLAT_ARGS_NEXT(_list, _c, _d); \
		XLAT_ARGS_NEXT(_list, _d, _e); \
		XLAT_ARGS_NEXT(_list, _e, _f); \
		XLAT_ARGS_NEXT(_list, _f, _g); \
		XLAT_ARGS_NEXT(_list, _g, _h); \
	} while (0)

/** Trampoline macro for selecting which ``XLAT_ARGS_<num>`` macro to expand
 *
 *
 * @param[in] XLAT_ARGS_N	the name of the macro to expand.
 *				Created by concatenating ``XLAT_ARGS_ + <number of variadic arguments>``.
 * @param[in] _list		The input list of value boxes.
 * @param[in] ...		The variadic arguments themselves.
 */
#define _XLAT_ARGS_X(XLAT_ARGS_N, _list, ...) XLAT_ARGS_N(_list, __VA_ARGS__)

/** Populate local variables with value boxes from the input list
 *
 * @param[in] _list		input list to pull arguments from.
 * @param[in] ...		1-8 output boxes pointers `fr_value_box_t **`
 *				e.g. `XLAT_ARGS(in, &arg0, &arg1, &argN)``.
 */
#define XLAT_ARGS(_list, ...) _XLAT_ARGS_X(JOIN(XLAT_ARGS_, VA_NARG(__VA_ARGS__)), _list, __VA_ARGS__)

ssize_t		xlat_eval(char *out, size_t outlen, request_t *request, char const *fmt, xlat_escape_legacy_t escape,
			  void const *escape_ctx)
			  CC_HINT(nonnull (1 ,3 ,4));

ssize_t		xlat_eval_compiled(char *out, size_t outlen, request_t *request, xlat_exp_head_t const *head,
				   xlat_escape_legacy_t escape, void const *escape_ctx)
				   CC_HINT(nonnull (1 ,3 ,4));

ssize_t		xlat_aeval(TALLOC_CTX *ctx, char **out, request_t *request,
			   char const *fmt, xlat_escape_legacy_t escape, void const *escape_ctx)
			   CC_HINT(nonnull(2, 3, 4));

ssize_t		xlat_aeval_compiled(TALLOC_CTX *ctx, char **out, request_t *request,
				    xlat_exp_head_t const *head, xlat_escape_legacy_t escape, void const *escape_ctx)
				    CC_HINT(nonnull (2, 3, 4));

int		xlat_flatten_to_argv(TALLOC_CTX *ctx, xlat_exp_head_t ***argv, xlat_exp_head_t *head);

fr_slen_t	xlat_tokenize_expression(TALLOC_CTX *ctx, xlat_exp_head_t **head, fr_sbuff_t *in,
					 fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules) CC_HINT(nonnull(1,2,3));

fr_slen_t	xlat_tokenize_condition(TALLOC_CTX *ctx, xlat_exp_head_t **head, fr_sbuff_t *in,
					fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules) CC_HINT(nonnull(1,2,3));

fr_slen_t 	xlat_tokenize_argv(TALLOC_CTX *ctx, xlat_exp_head_t **head, fr_sbuff_t *in,
				   xlat_arg_parser_t const *xlat_args, fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules,
				   bool spaces) CC_HINT(nonnull(1,2,3,6));

fr_slen_t	xlat_tokenize(TALLOC_CTX *ctx, xlat_exp_head_t **head, fr_sbuff_t *in,
			      fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules);

fr_slen_t	xlat_print(fr_sbuff_t *in, xlat_exp_head_t const *node, fr_sbuff_escape_rules_t const *e_rules);

static inline fr_slen_t xlat_aprint(TALLOC_CTX *ctx, char **out, xlat_exp_head_t const *head,
				    fr_sbuff_escape_rules_t const *e_rules)
		SBUFF_OUT_TALLOC_FUNC_NO_LEN_DEF(xlat_print, head, e_rules)

bool		xlat_is_truthy(xlat_exp_head_t const *head, bool *out);

int		xlat_validate_function_args(xlat_exp_t *node);

void		xlat_debug(xlat_exp_t const *node);

void		xlat_debug_head(xlat_exp_head_t const *head);

bool		xlat_is_literal(xlat_exp_head_t const *head);

bool		xlat_needs_resolving(xlat_exp_head_t const *head);

bool		xlat_to_string(TALLOC_CTX *ctx, char **str, xlat_exp_head_t **head);

int		xlat_resolve(xlat_exp_head_t *head, xlat_res_rules_t const *xr_rules);

void		xlat_debug_attr_list(request_t *request, fr_pair_list_t const *list);
void		xlat_debug_attr_vp(request_t *request, fr_pair_t *vp, tmpl_t const *vpt);

xlat_action_t	xlat_transparent(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				 UNUSED xlat_ctx_t const *xctx,
				 request_t *request, fr_value_box_list_t *args);

/*
 *	xlat_tokenize.c
 */
tmpl_t		*xlat_to_tmpl_attr(TALLOC_CTX *ctx, xlat_exp_head_t *xlat);

bool		xlat_impure_func(xlat_exp_head_t const *head) CC_HINT(nonnull);

fr_type_t	xlat_data_type(xlat_exp_head_t const *head);

/*
 *	xlat_alloc.c
 */
int		_xlat_copy(NDEBUG_LOCATION_ARGS TALLOC_CTX *ctx, xlat_exp_head_t *out, xlat_exp_head_t const *in);
#define		xlat_copy(_ctx, _out, _in) _xlat_copy(NDEBUG_LOCATION_EXP _ctx, _out, _in)
#ifdef WITH_VERIFY_PTR
void		xlat_exp_verify(xlat_exp_t const *node);
void		xlat_exp_head_verify(xlat_exp_head_t const *head);

#  define XLAT_VERIFY(_node) xlat_exp_verify(_node)
#  define XLAT_HEAD_VERIFY(_head) xlat_exp_head_verify(_head)
#else
#  define XLAT_VERIFY(_node)
#  define XLAT_HEAD_VERIFY(_head)
#endif

/*
 *	xlat_inst.c
 */
xlat_thread_inst_t *xlat_thread_instance_find(xlat_exp_t const *node);

int		xlat_thread_instantiate(TALLOC_CTX *ctx, fr_event_list_t *el);

int		xlat_instantiate(void);

void		xlat_thread_detach(void);

int		xlat_instance_unregister_func(xlat_exp_t *node);

int		xlat_instance_register_func(xlat_exp_t *node);

int		xlat_finalize(xlat_exp_head_t *head, fr_event_list_t *runtime_el); /* xlat_instance_register() or xlat_instantiate_ephemeral() */

void		xlat_instances_free(void);

/*
 *	xlat_purify.c
 */
typedef struct unlang_interpret_s unlang_interpret_t;
int		xlat_purify(xlat_exp_head_t *head, unlang_interpret_t *intp);

int		xlat_purify_op(TALLOC_CTX *ctx, xlat_exp_t **out, xlat_exp_t *lhs, fr_token_t op, xlat_exp_t *rhs);

/*
 *	xlat.c
 */
int		unlang_xlat_timeout_add(request_t *request, fr_unlang_xlat_timeout_t callback,
					void const *rctx, fr_time_t when);

#define XLAT_RESULT_SUCCESS(_p_result) ((_p_result)->rcode == RLM_MODULE_OK)

int		unlang_xlat_push(TALLOC_CTX *ctx, unlang_result_t *p_result, fr_value_box_list_t *out,
				 request_t *request, xlat_exp_head_t const *head, bool top_frame)
				 CC_HINT(warn_unused_result);

int		unlang_xlat_eval(TALLOC_CTX *ctx, fr_value_box_list_t *out,
				 request_t *request, xlat_exp_head_t const *head)
				 CC_HINT(warn_unused_result);

int		unlang_xlat_eval_type(TALLOC_CTX *ctx, fr_value_box_t *out, fr_type_t type, fr_dict_attr_t const *enumv,
				      request_t *request, xlat_exp_head_t const *head)
				      CC_HINT(warn_unused_result);

xlat_action_t	unlang_xlat_yield(request_t *request,
				  xlat_func_t callback, xlat_func_signal_t signal, fr_signal_t sigmask,
				  void *rctx);

xlat_action_t	unlang_xlat_yield_to_retry(request_t *request, xlat_func_t resume, fr_unlang_xlat_retry_t retry,
					   xlat_func_signal_t signal, fr_signal_t sigmask, void *rctx,
					   fr_retry_config_t const *retry_cfg);

/*
 *	xlat_builtin.c
 */
int		xlat_protocols_register(void);
int		xlat_global_init(void);

#ifdef __cplusplus
}
#endif
