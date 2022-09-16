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

typedef enum {
	XLAT_INPUT_UNPROCESSED,			//!< No input argument processing
	XLAT_INPUT_MONO,			//!< Ingests a single argument
	XLAT_INPUT_ARGS				//!< Ingests a number of arguments
} xlat_input_type_t;

typedef struct xlat_inst xlat_inst_t;
typedef struct xlat_thread_inst xlat_thread_inst_t;

#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/signal.h>

#include <freeradius-devel/util/heap.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/value.h>

#include <freeradius-devel/unlang/xlat_ctx.h>

/** Instance data for an xlat expansion node
 *
 */
struct xlat_inst {
	fr_heap_index_t		idx;		//!< Entry in heap of xlat instances.
						///< Identical instances are used for
						///< global instance data and thread-specific
						///< instance data.

	xlat_exp_t		*node;		//!< Node this data relates to.
	void			*data;		//!< xlat node specific instance data.
};

/** Thread specific instance data for xlat expansion node
 *
 */
struct xlat_thread_inst {
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
	bool			needs_resolving;//!< Needs pass2 resolution.
	bool			needs_async;	//!< Node and all child nodes are guaranteed to not
						///< require asynchronous expansion.
	bool			pure;		//!< has no external side effects, true for BOX, LITERAL, and some functions
	bool			can_purify;	//!< if the xlat has a pure function with pure arguments.

	bool			constant;	//!< xlat is just tmpl_data, or XLAT_BOX
} xlat_flags_t;

/*
 *	Simplify many use-cases
 *
 *	We can't set "needs_resolving" here, and async functions can't be pure.
 */
#define XLAT_FLAG_NEEDS_ASYNC &(xlat_flags_t) { .needs_async = true, }
#define XLAT_FLAG_PURE &(xlat_flags_t) { .pure = true, }

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

/** Definition for a single argument consumend by an xlat function
 *
 */
typedef struct {
	bool			required;	//!< Argument must be present.
	bool			concat;		//!< Concat boxes together.
	bool			single;		//!< Argument must only contain a single box
	bool			variadic;	//!< All additional boxes should be processed
						///< using this definition.
	bool			always_escape;	//!< Pass all arguments to escape function not just
						///< tainted ones.
	fr_type_t		type;		//!< Type to cast argument to.
	xlat_escape_func_t	func;		//!< Function to handle tainted values.
	void			*uctx;		//!< Argument to pass to escape callback.
} xlat_arg_parser_t;

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

/** A callback when the request gets a fr_state_signal_t.
 *
 * @note The callback is automatically removed on unlang_interpret_mark_runnable().
 *
 * @param[in] request		The current request.
 * @param[in] xctx		xlat calling ctx.  Contains all instance data.
 * @param[in] action		which is signalling the request.
 */
typedef void (*xlat_func_signal_t)(xlat_ctx_t const *xctx, request_t *request, fr_state_signal_t action);

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

typedef size_t (*xlat_escape_legacy_t)(request_t *request, char *out, size_t outlen, char const *in, void *arg);

int		xlat_fmt_get_vp(fr_pair_t **out, request_t *request, char const *name);

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

int		xlat_aeval_compiled_argv(TALLOC_CTX *ctx, char ***argv, request_t *request,
					 xlat_exp_head_t const *head, xlat_escape_legacy_t escape, void const *escape_ctx);

int		xlat_flatten_compiled_argv(TALLOC_CTX *ctx, xlat_exp_head_t ***argv, xlat_exp_head_t *head);

bool		xlat_async_required(xlat_exp_head_t const *xlat);


fr_slen_t	xlat_tokenize_expression(TALLOC_CTX *ctx, xlat_exp_head_t **head, fr_sbuff_t *in,
					 fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules);

fr_slen_t	xlat_tokenize_condition(TALLOC_CTX *ctx, xlat_exp_head_t **head, fr_sbuff_t *in,
					fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules);

fr_slen_t	xlat_tokenize_ephemeral_expression(TALLOC_CTX *ctx, xlat_exp_head_t **head,
						   fr_event_list_t *el,
						   fr_sbuff_t *in,
						   fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules);

fr_slen_t	xlat_tokenize_ephemeral(TALLOC_CTX *ctx, xlat_exp_head_t **head,
					fr_event_list_t *el, fr_sbuff_t *in,
					fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules);

fr_slen_t 	xlat_tokenize_argv(TALLOC_CTX *ctx, xlat_exp_head_t **head, fr_sbuff_t *in,
				   fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules);

fr_slen_t	xlat_tokenize(TALLOC_CTX *ctx, xlat_exp_head_t **head, fr_sbuff_t *in,
			      fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules);

fr_slen_t	xlat_print(fr_sbuff_t *in, xlat_exp_head_t const *node, fr_sbuff_escape_rules_t const *e_rules);

static inline fr_slen_t xlat_aprint(TALLOC_CTX *ctx, char **out, xlat_exp_head_t const *head,
				    fr_sbuff_escape_rules_t const *e_rules)
		SBUFF_OUT_TALLOC_FUNC_NO_LEN_DEF(xlat_print, head, e_rules)

int		xlat_validate_function_mono(xlat_exp_t *node);

int		xlat_validate_function_args(xlat_exp_t *node);

void		xlat_debug(xlat_exp_head_t const *head);

bool		xlat_is_literal(xlat_exp_head_t const *head);

bool		xlat_needs_resolving(xlat_exp_head_t const *head);

bool		xlat_to_string(TALLOC_CTX *ctx, char **str, xlat_exp_head_t **head);

int		xlat_resolve(xlat_exp_head_t *head, xlat_res_rules_t const *xr_rules);

xlat_t		*xlat_register_module(TALLOC_CTX *ctx, module_inst_ctx_t const *mctx,
				      char const *name, xlat_func_t func, xlat_flags_t const *flags);
xlat_t		*xlat_register(TALLOC_CTX *ctx, char const *name, xlat_func_t func, xlat_flags_t const *flags) CC_HINT(nonnull(2));

int		xlat_func_args(xlat_t *xlat, xlat_arg_parser_t const args[]) CC_HINT(nonnull);

int		xlat_func_mono(xlat_t *xlat, xlat_arg_parser_t const *arg) CC_HINT(nonnull);

bool		xlat_is_truthy(xlat_exp_head_t const *head, bool *out);

/** Set a callback for global instantiation of xlat functions
 *
 * @param[in] _xlat		function to set the callback for (as returned by xlat_register).
 * @param[in] _instantiate	A instantiation callback.
 * @param[in] _inst_struct	The instance struct to pre-allocate.
 * @param[in] _detach		A destructor callback.
 * @param[in] _uctx		to pass to _instantiate and _detach callbacks.
 */
#define	xlat_async_instantiate_set(_xlat, _instantiate, _inst_struct, _detach, _uctx) \
	_xlat_async_instantiate_set(_xlat, _instantiate, #_inst_struct, sizeof(_inst_struct), _detach, _uctx)
void _xlat_async_instantiate_set(xlat_t const *xlat,
				        xlat_instantiate_t instantiate, char const *inst_type, size_t inst_size,
				        xlat_detach_t detach,
				        void *uctx);

/** Set a callback for thread-specific instantiation of xlat functions
 *
 * @param[in] _xlat		function to set the callback for (as returned by xlat_register).
 * @param[in] _instantiate	A instantiation callback.
 * @param[in] _inst_struct	The instance struct to pre-allocate.
 * @param[in] _detach		A destructor callback.
 * @param[in] _uctx		to pass to _instantiate and _detach callbacks.
 */
#define	xlat_async_thread_instantiate_set(_xlat, _instantiate, _inst_struct, _detach, _uctx) \
	_xlat_async_thread_instantiate_set(_xlat, _instantiate, #_inst_struct, sizeof(_inst_struct), _detach, _uctx)
void _xlat_async_thread_instantiate_set(xlat_t const *xlat,
					xlat_thread_instantiate_t thread_instantiate,
				        char const *thread_inst_type, size_t thread_inst_size,
				        xlat_thread_detach_t thread_detach,
					void *uctx);

void		xlat_unregister(char const *name);
void		xlat_unregister_module(dl_module_inst_t const *inst);
int		xlat_register_redundant(CONF_SECTION *cs);
int		xlat_init(void);
void		xlat_free(void);

void		xlat_debug_attr_list(request_t *request, fr_pair_list_t const *list);
void		xlat_debug_attr_vp(request_t *request, fr_pair_t *vp, tmpl_t const *vpt);
/*
 *	xlat_tokenize.c
 */
xlat_exp_t	*xlat_exp_func_alloc(TALLOC_CTX *ctx, xlat_t *func, xlat_exp_head_t const *args);

tmpl_t		*xlat_to_tmpl_attr(TALLOC_CTX *ctx, xlat_exp_head_t *xlat);

int		xlat_from_tmpl_attr(TALLOC_CTX *ctx, xlat_exp_head_t **head, tmpl_t **vpt_p);

int		xlat_copy(TALLOC_CTX *ctx, xlat_exp_head_t **out, xlat_exp_head_t const *in);

/*
 *	xlat_inst.c
 */
int		xlat_instantiate_ephemeral(xlat_exp_head_t *head, fr_event_list_t *el) CC_HINT(nonnull(1));

xlat_thread_inst_t *xlat_thread_instance_find(xlat_exp_t const *node);

int		xlat_thread_instantiate(TALLOC_CTX *ctx, fr_event_list_t *el);

int		xlat_instantiate(void);

void		xlat_thread_detach(void);

int		xlat_bootstrap_func(xlat_exp_t *node);

int		xlat_bootstrap(xlat_exp_head_t *root);

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

int		unlang_xlat_push(TALLOC_CTX *ctx, bool *p_success, fr_value_box_list_t *out,
				 request_t *request, xlat_exp_head_t const *head, bool top_frame)
				 CC_HINT(warn_unused_result);

xlat_action_t	unlang_xlat_yield(request_t *request,
				  xlat_func_t callback, xlat_func_signal_t signal,
				  void *rctx);
#ifdef __cplusplus
}
#endif
