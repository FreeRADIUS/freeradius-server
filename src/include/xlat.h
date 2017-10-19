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
typedef ssize_t (*xlat_func_t)(TALLOC_CTX *ctx, char **out, size_t outlen,
			       void const *mod_inst, void const *xlat_inst,
			       REQUEST *request, char const *fmt);

/** Allocate new instance data for an xlat instance
 *
 * @param[out] xlat_inst Structure to populate. Allocated by #map_proc_instantiate.
 * @param[in] mod_inst Module instance that registered the #xlat_func_t.
 * @param[in] fmt string to base instantiation around.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*xlat_instantiate_t)(void *xlat_inst, void *mod_inst, char const *fmt);

ssize_t xlat_eval(char *out, size_t outlen, REQUEST *request, char const *fmt, xlat_escape_t escape,
		    void const *escape_ctx)
	CC_HINT(nonnull (1 ,3 ,4));

ssize_t xlat_eval_compiled(char *out, size_t outlen, REQUEST *request, xlat_exp_t const *xlat,
			   xlat_escape_t escape, void const *escape_ctx)
	CC_HINT(nonnull (1 ,3 ,4));

ssize_t xlat_aeval(TALLOC_CTX *ctx, char **out, REQUEST *request,
		     char const *fmt, xlat_escape_t escape, void const *escape_ctx)
	CC_HINT(nonnull (2, 3, 4));

ssize_t xlat_aeval_compiled(TALLOC_CTX *ctx, char **out, REQUEST *request,
			    xlat_exp_t const *xlat, xlat_escape_t escape, void const *escape_ctx)
	CC_HINT(nonnull (2, 3, 4));

ssize_t xlat_tokenize(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head, char const **error);

size_t xlat_snprint(char *buffer, size_t bufsize, xlat_exp_t const *node);

#define XLAT_DEFAULT_BUF_LEN	2048

int		xlat_register(void *mod_inst, char const *name,
			      xlat_func_t func, xlat_escape_t escape,
			      xlat_instantiate_t instantiate, size_t inst_size,
			      size_t buf_len, bool async_safe);

void		xlat_unregister(void *mod_inst, char const *name, xlat_func_t func);
void		xlat_unregister_module(void *instance);
int		xlat_register_redundant(CONF_SECTION *cs);
void		xlat_free(void);

#ifdef __cplusplus
}
#endif
#endif	/* _FR_XLAT_H */
