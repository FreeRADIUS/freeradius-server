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
 * @file lib/server/xlat.h
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
	XLAT_ACTION_PUSH_CHILD_GROUP,		//!< same as above, and the child is a group
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

extern fr_table_num_sorted_t const xlat_action_table[];
extern size_t xlat_action_table_len;

typedef size_t (*xlat_escape_t)(REQUEST *request, char *out, size_t outlen, char const *in, void *arg);

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
typedef	void (*fr_unlang_xlat_timeout_t)(REQUEST *request, void *xlat_inst,
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
typedef void (*fr_unlang_xlat_fd_event_t)(REQUEST *request, void *xlat_inst,
					  void *xlat_thread_inst, void *rctx, int fd);

/** xlat callback function
 *
 * Should write the result of expanding the fmt string to the output buffer.
 *
 * If a outlen > 0 was provided to #xlat_register, out will point to a talloced
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
typedef ssize_t (*xlat_func_sync_t)(TALLOC_CTX *ctx, char **out, size_t outlen,
				    void const *mod_inst, void const *xlat_inst,
				    REQUEST *request, char const *fmt);

/** Async xlat callback function
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
 * @return
 *	- XLAT_ACTION_YIELD	xlat function is waiting on an I/O event and
 *				has pushed a resumption function onto the stack.
 *	- XLAT_ACTION_DONE	xlat function completed. This does not necessarily
 *				mean it turned a result.
 *	- XLAT_ACTION_FAIL	the xlat function failed.
 */
typedef xlat_action_t (*xlat_func_async_t)(TALLOC_CTX *ctx, fr_cursor_t *out,
					   REQUEST *request, void const *xlat_inst, void *xlat_thread_inst,
					   fr_value_box_t **in);

/** Async xlat callback function
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
					    REQUEST *request, void const *xlat_inst, void *xlat_thread_inst,
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
typedef void (*xlat_func_signal_t)(REQUEST *request, void *xlat_inst, void *xlat_thread_inst,
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

int		xlat_fmt_get_vp(VALUE_PAIR **out, REQUEST *request, char const *name);
int		xlat_fmt_copy_vp(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, char const *name);

int		xlat_fmt_to_cursor(TALLOC_CTX *ctx, fr_cursor_t **out,
				   bool *tainted, REQUEST *requst, char const *fmt);

ssize_t		xlat_eval(char *out, size_t outlen, REQUEST *request, char const *fmt, xlat_escape_t escape,
			  void const *escape_ctx)
			  CC_HINT(nonnull (1 ,3 ,4));

ssize_t		xlat_eval_compiled(char *out, size_t outlen, REQUEST *request, xlat_exp_t const *xlat,
				   xlat_escape_t escape, void const *escape_ctx)
				   CC_HINT(nonnull (1 ,3 ,4));

ssize_t		xlat_aeval(TALLOC_CTX *ctx, char **out, REQUEST *request,
			   char const *fmt, xlat_escape_t escape, void const *escape_ctx)
			   CC_HINT(nonnull (2, 3, 4));

ssize_t		xlat_aeval_compiled(TALLOC_CTX *ctx, char **out, REQUEST *request,
				    xlat_exp_t const *xlat, xlat_escape_t escape, void const *escape_ctx)
				    CC_HINT(nonnull (2, 3, 4));

int		xlat_aeval_compiled_argv(TALLOC_CTX *ctx, char ***argv, REQUEST *request,
					 xlat_exp_t const *xlat, xlat_escape_t escape, void const *escape_ctx);

int		xlat_flatten_compiled_argv(TALLOC_CTX *ctx, xlat_exp_t const ***argv, xlat_exp_t const *xlat);

int		xlat_eval_pair(REQUEST *request, VALUE_PAIR *vp);

ssize_t		xlat_tokenize_ephemeral(TALLOC_CTX *ctx, xlat_exp_t **head, REQUEST *request,
					char const *fmt, vp_tmpl_rules_t const *rules);

ssize_t		xlat_tokenize(TALLOC_CTX *ctx, xlat_exp_t **head, char const *in, ssize_t inlen, vp_tmpl_rules_t const *rules);

ssize_t		xlat_tokenize_argv(TALLOC_CTX *ctx, xlat_exp_t **head, char const *in, size_t inlen,
				   vp_tmpl_rules_t const *rules);

size_t		xlat_snprint(char *buffer, size_t bufsize, xlat_exp_t const *node);

#define XLAT_DEFAULT_BUF_LEN	2048

int		xlat_register(void *mod_inst, char const *name,
			      xlat_func_sync_t func, xlat_escape_t escape,
			      xlat_instantiate_t instantiate, size_t inst_size,
			      size_t buf_len, bool async_safe);

xlat_t const	*xlat_async_register(TALLOC_CTX *ctx, char const *name, xlat_func_async_t func);

int		xlat_internal(char const *name);

#define	xlat_async_instantiate_set(_xlat, _instantiate, _inst_struct, _detach, _uctx) \
	_xlat_async_instantiate_set(_xlat, _instantiate, #_inst_struct, sizeof(_inst_struct), _detach, _uctx)
void _xlat_async_instantiate_set(xlat_t const *xlat,
				        xlat_instantiate_t instantiate, char const *inst_type, size_t inst_size,
				        xlat_detach_t detach,
				        void *uctx);

#define	xlat_async_thread_instantiate_set(_xlat, _instantiate, _inst_struct, _detach, _uctx) \
	_xlat_async_thread_instantiate_set(_xlat, _instantiate, #_inst_struct, sizeof(_inst_struct), _detach, _uctx)
void _xlat_async_thread_instantiate_set(xlat_t const *xlat,
					xlat_thread_instantiate_t thread_instantiate,
				        char const *thread_inst_type, size_t thread_inst_size,
				        xlat_thread_detach_t thread_detach,
					void *uctx);

void		xlat_unregister(char const *name);
void		xlat_unregister_module(void *instance);
int		xlat_register_redundant(CONF_SECTION *cs);
int		xlat_init(void);
void		xlat_free(void);

/*
 *	xlat_tokenize.c
 */
vp_tmpl_t	*xlat_to_tmpl_attr(TALLOC_CTX *ctx, xlat_exp_t *xlat);

xlat_exp_t	*xlat_from_tmpl_attr(TALLOC_CTX *ctx, vp_tmpl_t *vpt);

/*
 *	xlat_inst.c
 */
int		xlat_instantiate_ephemeral(xlat_exp_t *root);

xlat_thread_inst_t *xlat_thread_instance_find(xlat_exp_t const *node);

int		xlat_thread_instantiate(TALLOC_CTX *ctx);

int		xlat_instantiate(void);

void		xlat_thread_detach(void);

int		xlat_bootstrap(xlat_exp_t *root);

void		xlat_instances_free(void);

/*
 *	unlang/xlat.c
 */
int		unlang_xlat_event_timeout_add(REQUEST *request, fr_unlang_xlat_timeout_t callback,
					      void const *ctx, fr_time_t when);

int		unlang_xlat_event_timeout_delete(REQUEST *request, void *ctx);

void		unlang_xlat_push(TALLOC_CTX *ctx, fr_value_box_t **out,
				 REQUEST *request, xlat_exp_t const *exp, bool top_frame);

xlat_action_t	unlang_xlat_yield(REQUEST *request,
				  xlat_func_resume_t callback, xlat_func_signal_t signal,
				  void *rctx);
#ifdef __cplusplus
}
#endif
