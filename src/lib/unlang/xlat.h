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
	XLAT_ACTION_YIELD,			//!< An xlat function pushed a resume frame onto the stack.
	XLAT_ACTION_DONE,			//!< We're done evaluating this level of nesting.
	XLAT_ACTION_FAIL			//!< An xlat function failed.
} xlat_action_t;

typedef struct xlat_inst xlat_inst_t;
typedef struct xlat_thread_inst xlat_thread_inst_t;
typedef struct xlat_exp xlat_exp_t;

#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/signal.h>

#include <freeradius-devel/util/cursor.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/sbuff.h>

/** Instance data for an xlat expansion node
 *
 */
struct xlat_inst {
	xlat_exp_t const	*node;		//!< Node this data relates to.
	void			*data;		//!< xlat node specific instance data.
};

/** Thread specific instance data for xlat expansion node
 *
 */
struct xlat_thread_inst {
	xlat_exp_t const	*node;		//!< Node this data relates to.
 	void			*data;		//!< Thread specific instance data.

	uint64_t		total_calls;	//! total number of times we've been called
	uint64_t		active_callers; //! number of active callers.  i.e. number of current yields
};

typedef struct xlat_s xlat_t;

/** Flags that control resolution and evaluation
 *
 */
typedef struct {
	bool			needs_resolving;	//!< Needs pass2 resolution.
	bool			needs_async;	//!< Node and all child nodes are guaranteed to not
						///< require asynchronous expansion.
} xlat_flags_t;

extern fr_table_num_sorted_t const xlat_action_table[];
extern size_t xlat_action_table_len;

/** A callback when the the timeout occurs
 *
 * Used when a xlat needs wait for an event.
 * Typically the callback is set, and then the xlat returns unlang_xlat_yield().
 *
 * @note The callback is automatically removed on unlang_interpret_resumable(), i.e. if an event
 *	on a registered FD occurs before the timeout event fires.
 *
 * @param[in] request		the request.
 * @param[in] xlat_inst		the xlat instance.
 * @param[in] xlat_thread_inst	data specific to this xlat instance.
 * @param[in] rctx		Resume ctx provided when the xlat last yielded.
 * @param[in] fired		the time the timeout event actually fired.
 */
typedef	void (*fr_unlang_xlat_timeout_t)(request_t *request, void *xlat_inst,
					 void *xlat_thread_inst, void *rctx, fr_time_t fired);

/** A callback when the FD is ready for reading
 *
 * Used when a xlat needs to read from an FD.  Typically the callback is set, and then the
 * xlat returns unlang_xlat_yield().
 *
 * @note The callback is automatically removed on unlang_interpret_resumable(), so
 *
 * @param[in] request		the current request.
 * @param[in] xlat_inst		the xlat instance.
 * @param[in] xlat_thread_inst	data specific to this xlat instance.
 * @param[in] rctx		Resume ctx provided when the xlat last yielded.
 * @param[in] fd		the file descriptor.
 */
typedef void (*fr_unlang_xlat_fd_event_t)(request_t *request, void *xlat_inst,
					  void *xlat_thread_inst, void *rctx, int fd);

/** xlat callback function
 *
 * Ingests a list of value boxes as arguments.
 *
 * @param[in] ctx		to allocate any fr_value_box_t in.
 * @param[out] out		Where to append #fr_value_box_t containing the output of
 *				this function.
 * @param[in] request		The current request.
 * @param[in] xlat_inst		Global xlat instance.
 * @param[in] xlat_thread_inst	Thread specific xlat instance.
 * @param[in] in		Input arguments.
 * @return
 *	- XLAT_ACTION_YIELD	xlat function is waiting on an I/O event and
 *				has pushed a resumption function onto the stack.
 *	- XLAT_ACTION_DONE	xlat function completed. This does not necessarily
 *				mean it turned a result.
 *	- XLAT_ACTION_FAIL	the xlat function failed.
 */
typedef xlat_action_t (*xlat_func_t)(TALLOC_CTX *ctx, fr_cursor_t *out,
				     request_t *request, void const *xlat_inst, void *xlat_thread_inst,
				     fr_value_box_t **in);

/** xlat callback resumption function
 *
 * Ingests a list of value boxes as arguments, with arguments delimited by spaces.
 *
 * @param[in] ctx		to allocate any fr_value_box_t in.
 * @param[out] out		Where to append #fr_value_box_t containing the output of
 *				this function.
 * @param[in] request		The current request.
 * @param[in] xlat_inst		Global xlat instance.
 * @param[in] xlat_thread_inst	Thread specific xlat instance.
 * @param[in] in		Input arguments.
 * @param[in] rctx		Resume ctx provided when the xlat last yielded.
 * @return
 *	- XLAT_ACTION_YIELD	xlat function is waiting on an I/O event and
 *				has pushed a resumption function onto the stack.
 *	- XLAT_ACTION_DONE	xlat function completed. This does not necessarily
 *				mean it turned a result.
 *	- XLAT_ACTION_FAIL	the xlat function failed.
 */
typedef xlat_action_t (*xlat_func_resume_t)(TALLOC_CTX *ctx, fr_cursor_t *out,
					    request_t *request, void const *xlat_inst, void *xlat_thread_inst,
					    fr_value_box_t **in, void *rctx);

/** A callback when the request gets a fr_state_signal_t.
 *
 * @note The callback is automatically removed on unlang_interpret_resumable().
 *
 * @param[in] request		The current request.
 * @param[in] xlat_inst		the xlat instance.
 * @param[in] xlat_thread_inst	data specific to this xlat instance.
 * @param[in] rctx		Resume ctx provided when the xlat last yielded.
 * @param[in] action		which is signalling the request.
 */
typedef void (*xlat_func_signal_t)(request_t *request, void *xlat_inst, void *xlat_thread_inst,
				   void *rctx, fr_state_signal_t action);

/** Allocate new instance data for an xlat instance
 *
 * @param[out] xlat_inst 	Structure to populate. Allocated by #map_proc_instantiate.
 * @param[in] exp		Tokenized expression to use in expansion.
 * @param[in] uctx		passed to the registration function.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*xlat_instantiate_t)(void *xlat_inst, xlat_exp_t const *exp, void *uctx);

/** Allocate new thread instance data for an xlat instance
 *
 * @param[in] xlat_inst		Previously instantiated xlat instance.
 * @param[out] xlat_thread_inst	Thread specific structure to populate.
 *				Allocated by #map_proc_instantiate.
 * @param[in] exp		Tokenized expression to use in expansion.
 * @param[in] uctx		passed to the registration function.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*xlat_thread_instantiate_t)(void *xlat_inst, void *xlat_thread_inst,
					 xlat_exp_t const *exp, void *uctx);

/** xlat detach callback
 *
 * Is called whenever an xlat_node_t is freed.
 *
 * Detach should close all handles associated with the xlat instance, and
 * free any memory allocated during instantiate.
 *
 * @param[in] xlat_inst		to free.
 * @param[in] uctx		passed to the xlat registration function.
 * @return
 *	- 0 on success.
 *	- -1 if detach failed.
 */
typedef int (*xlat_detach_t)(void *xlat_inst, void *uctx);

/** xlat thread detach callback
 *
 * Is called whenever an xlat_node_t is freed (if ephemeral),
 * or when a thread exits.
 *
 * Detach should close all handles associated with the xlat instance, and
 * free any memory allocated during instantiate.
 *
 * @param[in] xlat_thread_inst	to free.
 * @param[in] uctx		passed to the xlat registration function.
 * @return
 *	- 0 on success.
 *	- -1 if detach failed.
 */
typedef int (*xlat_thread_detach_t)(void *xlat_thread_inst, void *uctx);

/** legacy xlat callback function
 *
 * Should write the result of expanding the fmt string to the output buffer.
 *
 * If a outlen > 0 was provided to #xlat_register_legacy, out will point to a talloced
 * buffer of that size, which the result should be written to.
 *
 * If outlen is 0, then the function should allocate its own buffer, in the
 * context of the request.
 *
 * @param[in] ctx		to allocate any dynamic buffers in.
 * @param[in,out] out		Where to write either a pointer to a new buffer,
 *				or data to an existing buffer.
 * @param[in] outlen		Length of pre-allocated buffer, or 0 if function should
 *				allocate its own buffer.
 * @param[in] mod_inst		Instance data provided by the xlat that registered the xlat.
 * @param[in] xlat_inst		Instance data created by the xlat instantiation function.
 * @param[in] request		The current request.
 * @param[in] fmt		string to expand.
 */
typedef ssize_t (*xlat_func_legacy_t)(TALLOC_CTX *ctx, char **out, size_t outlen,
				      void const *mod_inst, void const *xlat_inst,
				      request_t *request, char const *fmt);

typedef size_t (*xlat_escape_legacy_t)(request_t *request, char *out, size_t outlen, char const *in, void *arg);



int		xlat_fmt_get_vp(fr_pair_t **out, request_t *request, char const *name);
int		xlat_fmt_copy_vp(TALLOC_CTX *ctx, fr_pair_t **out, request_t *request, char const *name);

int		xlat_fmt_to_cursor(TALLOC_CTX *ctx, fr_cursor_t **out,
				   bool *tainted, request_t *requst, char const *fmt);

ssize_t		xlat_eval(char *out, size_t outlen, request_t *request, char const *fmt, xlat_escape_legacy_t escape,
			  void const *escape_ctx)
			  CC_HINT(nonnull (1 ,3 ,4));

ssize_t		xlat_eval_compiled(char *out, size_t outlen, request_t *request, xlat_exp_t const *xlat,
				   xlat_escape_legacy_t escape, void const *escape_ctx)
				   CC_HINT(nonnull (1 ,3 ,4));

ssize_t		xlat_aeval(TALLOC_CTX *ctx, char **out, request_t *request,
			   char const *fmt, xlat_escape_legacy_t escape, void const *escape_ctx)
			   CC_HINT(nonnull (2, 3, 4));

ssize_t		xlat_aeval_compiled(TALLOC_CTX *ctx, char **out, request_t *request,
				    xlat_exp_t const *xlat, xlat_escape_legacy_t escape, void const *escape_ctx)
				    CC_HINT(nonnull (2, 3, 4));

int		xlat_aeval_compiled_argv(TALLOC_CTX *ctx, char ***argv, request_t *request,
					 xlat_exp_t const *xlat, xlat_escape_legacy_t escape, void const *escape_ctx);

int		xlat_flatten_compiled_argv(TALLOC_CTX *ctx, xlat_exp_t const ***argv, xlat_exp_t const *xlat);

int		xlat_eval_pair(request_t *request, fr_pair_t *vp);

bool		xlat_async_required(xlat_exp_t const *xlat);

ssize_t		xlat_tokenize_ephemeral(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags,
					fr_sbuff_t *in,
					fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules);

ssize_t 	xlat_tokenize_argv(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *in,
				   fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules);

ssize_t		xlat_tokenize(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, fr_sbuff_t *in,
			      fr_sbuff_parse_rules_t const *p_rules, tmpl_rules_t const *t_rules);

ssize_t		xlat_print(fr_sbuff_t *in, xlat_exp_t const *node, fr_sbuff_escape_rules_t const *e_rules);

static inline size_t xlat_aprint(TALLOC_CTX *ctx, char **out, xlat_exp_t const *node,
				 fr_sbuff_escape_rules_t const *e_rules)
{
		SBUFF_OUT_TALLOC_FUNC_NO_LEN_DEF(xlat_print, node, e_rules);
}

void		xlat_debug(xlat_exp_t const *node);

bool		xlat_is_literal(xlat_exp_t const *head);

bool		xlat_to_literal(TALLOC_CTX *ctx, char **str, xlat_exp_t **head);

int		xlat_resolve(xlat_exp_t **head, xlat_flags_t *flags, bool allow_unresolved);


#define XLAT_DEFAULT_BUF_LEN	2048

int		xlat_register_legacy(void *mod_inst, char const *name,
				     xlat_func_legacy_t func, xlat_escape_legacy_t escape,
				     xlat_instantiate_t instantiate, size_t inst_size,
				     size_t buf_len);

xlat_t const	*xlat_register(TALLOC_CTX *ctx, char const *name, xlat_func_t func, bool needs_async);

int		xlat_internal(char const *name);

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
void		xlat_unregister_module(void *instance);
int		xlat_register_legacy_redundant(CONF_SECTION *cs);
int		xlat_init(void);
void		xlat_free(void);

/*
 *	xlat_tokenize.c
 */
void 		xlat_exp_free(xlat_exp_t **head);

tmpl_t		*xlat_to_tmpl_attr(TALLOC_CTX *ctx, xlat_exp_t *xlat);

int		xlat_from_tmpl_attr(TALLOC_CTX *ctx, xlat_exp_t **head, xlat_flags_t *flags, tmpl_t **vpt_p);

/*
 *	xlat_inst.c
 */
int		xlat_instantiate_ephemeral(xlat_exp_t *root);

xlat_thread_inst_t *xlat_thread_instance_find(xlat_exp_t const *node);

int		xlat_thread_instantiate(TALLOC_CTX *ctx);

int		xlat_instantiate(void);

void		xlat_thread_detach(void);

int		xlat_bootstrap_func(xlat_exp_t *node);

int		xlat_bootstrap(xlat_exp_t *root);

void		xlat_instances_free(void);

/*
 *	xlat.c
 */
int		unlang_xlat_event_timeout_add(request_t *request, fr_unlang_xlat_timeout_t callback,
					      void const *ctx, fr_time_t when);

int		unlang_xlat_push(TALLOC_CTX *ctx, fr_value_box_t **out,
				 request_t *request, xlat_exp_t const *exp, bool top_frame)
				 CC_HINT(warn_unused_result);

xlat_action_t	unlang_xlat_yield(request_t *request,
				  xlat_func_resume_t callback, xlat_func_signal_t signal,
				  void *rctx);
#ifdef __cplusplus
}
#endif
