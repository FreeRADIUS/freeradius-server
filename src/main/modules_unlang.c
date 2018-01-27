/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file modules_unlang.c
 * @brief Defines functions for calling modules asynchronously
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/parser.h>
#include <freeradius-devel/unlang.h>
#include <freeradius-devel/xlat.h>
#include "unlang_priv.h"

/** Push a pre-compiled xlat and resumption state onto the stack for evaluation
 *
 * In order to use the async unlang processor the calling module needs to establish
 * a resumption point, as the call to an xlat function may require yielding control
 * back to the interpreter.
 *
 * To simplify the calling conventions, this function is provided to first push a
 * resumption stack frame for the module, and then push an xlat stack frame.
 *
 * After pushing those frames the function updates the stack pointer to jump over
 * the resumption frame and execute the xlat interpreter.
 *
 * When the xlat interpreter finishes, and pops the xlat frame, the unlang interpreter
 * will then call the module resumption frame, allowing the module to continue exectuion.
 *
 * @param[in] ctx		To allocate value boxes and values in.
 * @param[out] out		Where to write the result of the expansion.
 * @param[in] request		The current request.
 * @param[in] exp		to evaluate.
 * @param[in] callback		to call on unlang_resumable().
 * @param[in] signal		to call on unlang_action().
 * @param[in] uctx		to pass to the callbacks.
 * @return
 *	- RLM_MODULE_YIELD if the xlat would perform blocking I/O
 *	- A return code representing the result of the xla
 */
rlm_rcode_t module_unlang_push_xlat(TALLOC_CTX *ctx, fr_value_box_t **out,
				    REQUEST *request, xlat_exp_t const *exp,
				    fr_unlang_module_resume_t callback,
				    fr_unlang_module_signal_t signal, void *uctx)
{
	/*
	 *	Push the resumption point
	 */
	(void) unlang_module_yield(request, callback, signal, uctx);

	/*
	 *	Push the xlat function
	 */
	xlat_unlang_push(ctx, out, request, exp, true);

	/*
	 *	Execute the xlat frame we just pushed onto the stack.
	 */
	return unlang_run(request);
}
