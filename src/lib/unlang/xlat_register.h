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
 * @file lib/unlang/xlat_register.h
 * @brief Registration API for xlat functions.
 *
 * @copyright 2023 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(xlat_register_h, "$Id$")

#include <freeradius-devel/unlang/xlat.h>

xlat_t		*xlat_register_module(TALLOC_CTX *ctx, module_inst_ctx_t const *mctx,
				      char const *name, xlat_func_t func, fr_type_t return_type);
xlat_t		*xlat_register(TALLOC_CTX *ctx, char const *name, xlat_func_t func, fr_type_t return_type) CC_HINT(nonnull(2));

int		xlat_func_args_set(xlat_t *xlat, xlat_arg_parser_t const args[]) CC_HINT(nonnull);

int		xlat_func_mono_set(xlat_t *xlat, xlat_arg_parser_t const *arg) CC_HINT(nonnull);

void		xlat_func_flags_set(xlat_t *x, xlat_flags_t const *flags) CC_HINT(nonnull);

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
/** @hidecallgraph */

int		xlat_register_init(void);
void		xlat_register_free(void);
