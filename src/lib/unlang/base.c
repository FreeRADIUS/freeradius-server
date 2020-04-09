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
 * @file unlang/base.c
 * @brief Base, utility functions for the unlang library.
 *
 * @copyright 2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/unlang/base.h>

#include "unlang_priv.h"

/** Return whether a section has unlang data associated with it
 *
 * @param[in] cs	to check.
 * @return
 *	- true if it has data.
 *	- false if it doesn't have data.
 */
bool unlang_section(CONF_SECTION *cs)
{
	return (cf_data_find(cs, unlang_group_t, NULL) != NULL);
}

/** Register an operation with the interpreter
 *
 * The main purpose of this registration API is to avoid intermixing the xlat,
 * condition, map APIs with the interpreter, i.e. the callbacks needed for that
 * functionality can be in their own source files, and we don't need to include
 * supporting types and function declarations in the interpreter.
 *
 * Later, this could potentially be used to register custom operations for modules.
 *
 * The reason why there's a function instead of accessing the unlang_op array
 * directly, is because 'type' really needs to go away, as needing to add ops to
 * the unlang_type_t enum breaks the pluggable module model. If there's no
 * explicit/consistent type values we need to enumerate the operations ourselves.
 *
 * @param[in] type		Operation identifier.  Used to map compiled unlang code
 *				to operations.
 * @param[in] op		unlang_op to register.
 */
void unlang_register(int type, unlang_op_t *op)
{
	rad_assert(type < UNLANG_TYPE_MAX);	/* Unlang max isn't a valid type */

	memcpy(&unlang_ops[type], op, sizeof(unlang_ops[type]));
}

/** Initialize the unlang compiler / interpreter.
 *
 *  For now, just register the magic xlat function.
 */
int unlang_init(void)
{
	/*
	 *	Explicitly initialise the xlat tree, and perform dictionary lookups.
	 */
	if (xlat_init() < 0) return -1;

	unlang_interpret_init();
	/* Register operations for the default keywords */
	unlang_condition_init();
	unlang_foreach_init();
	unlang_function_init();
	unlang_group_init();
	unlang_load_balance_init();
	unlang_map_init();
	unlang_module_init();
	unlang_parallel_init();
	unlang_return_init();
	if (unlang_subrequest_op_init() < 0) return -1;
	unlang_switch_init();
	unlang_call_init();
	unlang_tmpl_init();

	return 0;
}

void unlang_free(void)
{
	unlang_foreach_free();
	unlang_subrequest_op_free();
}
