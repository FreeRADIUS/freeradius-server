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
#ifndef _FR_XLAT_H
#define _FR_XLAT_H
/**
 * $Id$
 *
 * @file include/xlat.h
 * @brief xlat expansion parsing and evaluation API.
 *
 * @copyright 2015  The FreeRADIUS server project
 */
RCSIDH(xlat_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/cf_util.h>

typedef struct xlat_exp xlat_exp_t;

typedef enum {
	XLAT_ACTION_PUSH_CHILD = 1,	//!< A deeper level of nesting needs to be evaluated.
	XLAT_ACTION_YIELD,		//!< An xlat function pushed a resume frame onto the stack.
	XLAT_ACTION_DONE,		//!< We're done evaluating this level of nesting.
	XLAT_ACTION_FAIL		//!< An xlat function failed.
} xlat_action_t;

extern FR_NAME_NUMBER const xlat_action_table[];

typedef size_t (*xlat_escape_t)(REQUEST *request, char *out, size_t outlen, char const *in, void *arg);

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
 * @param[in] ctx to allocate any dynamic buffers in.
 * @param[in,out] out Where to write either a pointer to a new buffer, or data to an existing buffer.
 * @param[in] outlen Length of pre-allocated buffer, or 0 if function should allocate its own buffer.
 * @param[in] mod_inst Instance data provided by the module that registered the xlat.
 * @param[in] xlat_inst Instance data created by the xlat instantiation function.
 * @param[in] request The current request.
 * @param[in] fmt string to expand.
 */
typedef ssize_t (*xlat_func_sync_t)(TALLOC_CTX *ctx, char **out, size_t outlen,
			       void const *mod_inst, void const *xlat_inst,
			       REQUEST *request, char const *fmt);

/** Async xlat callback function
 *
 * Ingests a list of value boxes as arguments, with arguments delimited by spaces.
 *
 * @param[in] ctx		to allocate any fr_value_box_t in.
 * @param[out] out		Where to append #fr_value_box_t containing the output of this function.
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
					   fr_cursor_t const *in);

/** Async xlat callback function
 *
 * Ingests a list of value boxes as arguments, with arguments delimited by spaces.
 *
 * @param[in] ctx		to allocate any fr_value_box_t in.
 * @param[out] out		Where to append #fr_value_box_t containing the output of this function.
 * @param[in] request		The current request.
 * @param[in] xlat_inst		Global xlat instance.
 * @param[in] xlat_thread_inst	Thread specific xlat instance.
 * @param[in] in		Input arguments.
 * @param[in] rctx		passed to resume function.
 * @return
 *	- XLAT_ACTION_YIELD	xlat function is waiting on an I/O event and
 *				has pushed a resumption function onto the stack.
 *	- XLAT_ACTION_DONE	xlat function completed. This does not necessarily
 *				mean it turned a result.
 *	- XLAT_ACTION_FAIL	the xlat function failed.
 */
typedef xlat_action_t (*xlat_resume_callback_t)(TALLOC_CTX *ctx, fr_cursor_t *out,
						REQUEST *request, void const *xlat_inst, void *xlat_thread_inst,
						fr_cursor_t *in, void *rctx);

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

/** Allocate new tread instance data for an xlat instance
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

xlat_action_t	xlat_frame_eval_repeat(TALLOC_CTX *ctx, fr_cursor_t *out,
				       xlat_exp_t const **child, bool *alternate,
				       REQUEST *request, xlat_exp_t const **in,
				       fr_cursor_t *result);

xlat_action_t	xlat_frame_eval(TALLOC_CTX *ctx, fr_cursor_t *out, xlat_exp_t const **child,
				REQUEST *request, xlat_exp_t const **in);

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

ssize_t		xlat_tokenize(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head, char const **error);

size_t		xlat_snprint(char *buffer, size_t bufsize, xlat_exp_t const *node);

#define XLAT_DEFAULT_BUF_LEN	2048

int		xlat_register(void *mod_inst, char const *name,
			      xlat_func_sync_t func, xlat_escape_t escape,
			      xlat_instantiate_t instantiate, size_t inst_size,
			      size_t buf_len, bool async_safe);

int		xlat_async_register(TALLOC_CTX *ctx,
				    char const *name, xlat_func_async_t func,
				    xlat_instantiate_t instantiate, size_t inst_size,
				    xlat_thread_instantiate_t thread_instantiate, size_t thread_inst_size,
				    void *uctx);

void		xlat_unregister(char const *name);
void		xlat_unregister_module(void *instance);
int		xlat_register_redundant(CONF_SECTION *cs);
int		xlat_init(void);
void		xlat_free(void);

#ifdef __cplusplus
}
#endif
#endif	/* _FR_XLAT_H */
