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
 * @file lib/unlang/xlat_func.h
 * @brief Registration API for xlat functions.
 *
 * @copyright 2023 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(xlat_register_h, "$Id$")

#include <freeradius-devel/unlang/xlat.h>

/*
 * GCC doesn't support flag_enum (yet)
 *
 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=81665
 */
DIAG_OFF(attributes)
typedef enum CC_HINT(flag_enum) {
	XLAT_FUNC_FLAG_NONE = 0x00,
	XLAT_FUNC_FLAG_PURE = 0x01,
	XLAT_FUNC_FLAG_INTERNAL = 0x02
} xlat_func_flags_t;
DIAG_ON(attributes)

/** Custom function to print xlat debug
 */
typedef	fr_slen_t (*xlat_print_t)(fr_sbuff_t *in, xlat_exp_t const *self, void *inst, fr_sbuff_escape_rules_t const *e_rules);

/** Custom function to perform resolution of arguments
 */
typedef	int (*xlat_resolve_t)(xlat_exp_t *xlat, void *inst, xlat_res_rules_t const *xr_rules);

/** Custom function purify the result of an xlat function
 */
typedef int (*xlat_purify_t)(xlat_exp_t *xlat, void *inst, request_t *request);

int8_t		xlat_func_cmp(void const *one, void const *two);

xlat_t		*xlat_func_find_module(module_inst_ctx_t const *mctx, char const *name);

xlat_t		*xlat_func_register(TALLOC_CTX *ctx, char const *name, xlat_func_t func, fr_type_t return_type) CC_HINT(nonnull(2));

void		xlat_mctx_set(xlat_t *x, module_inst_ctx_t const *mctx);

int		xlat_func_args_set(xlat_t *xlat, xlat_arg_parser_t const args[]) CC_HINT(nonnull);

void		xlat_func_call_env_set(xlat_t *x, call_env_method_t const *env) CC_HINT(nonnull);

void		xlat_func_flags_set(xlat_t *x, xlat_func_flags_t flags) CC_HINT(nonnull);

void		xlat_func_print_set(xlat_t *xlat, xlat_print_t func);

void		xlat_func_resolve_set(xlat_t *xlat, xlat_resolve_t func);

void		xlat_purify_func_set(xlat_t *xlat, xlat_purify_t func);

/** Set the escaped values for output boxes
 *
 * Any boxes output by the xlat function will have their values marked as safe for something.
 *
 * @param[in] _xlat		function to set the escaped value for (as returned by xlat_register).
 * @param[in] _escaped		escaped value to write to output boxes.
 */
#define		xlat_func_safe_for_set(_xlat, _escaped) _xlat_func_safe_for_set(_xlat, (uintptr_t) (_escaped))
void		_xlat_func_safe_for_set(xlat_t *xlat, uintptr_t escaped);

/** Set a callback for global instantiation of xlat functions
 *
 * @param[in] _xlat		function to set the callback for (as returned by xlat_register).
 * @param[in] _instantiate	A instantiation callback.
 * @param[in] _inst_struct	The instance struct to pre-allocate.
 * @param[in] _detach		A destructor callback.
 * @param[in] _uctx		to pass to _instantiate and _detach callbacks.
 */
#define	xlat_func_instantiate_set(_xlat, _instantiate, _inst_struct, _detach, _uctx) \
	_xlat_func_instantiate_set(_xlat, _instantiate, #_inst_struct, sizeof(_inst_struct), _detach, _uctx)
void _xlat_func_instantiate_set(xlat_t const *xlat,
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
#define	xlat_func_thread_instantiate_set(_xlat, _instantiate, _inst_struct, _detach, _uctx) \
	_xlat_func_thread_instantiate_set(_xlat, _instantiate, #_inst_struct, sizeof(_inst_struct), _detach, _uctx)
void _xlat_func_thread_instantiate_set(xlat_t const *xlat,
				       xlat_thread_instantiate_t thread_instantiate,
				       char const *thread_inst_type, size_t thread_inst_size,
				       xlat_thread_detach_t thread_detach,
				       void *uctx);

void		xlat_func_unregister(char const *name);
void		xlat_func_unregister_module(module_instance_t const *inst);
/** @hidecallgraph */

int		xlat_func_init(void);
void		xlat_func_free(void);
