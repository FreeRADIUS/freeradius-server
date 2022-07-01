#pragma once
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
 * @file src/lib/server/module_method.h
 * @brief Defines standard module methods specified by virtual servers and modules.
 *
 * @copyright 2022 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(module_method_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

/** Specifies a module method identifier
 *
 * These are used in module definitions and by virtual servers to find mutually
 * acceptable module methods to call between a virtual server section and the
 * module that's calling it.
 *
 * For example, a `send Access-Accept` compilation structure may also have a
 * `ippool alloc` method associated with it, to instruct any ippool modules to
 * allocate an IP address.
 */
typedef struct {
	fr_dict_t const		**proto;	//!< If none-null, restrict matches to this protocol.
						///< i.e. if both the virtual server module_method_name
                                                ///< and the module method have non-null proto pointers
                                                ///< then *proto must be equal for the method name to
                                                ///< match.

	char const		*name1;		//!< module method name1 which is allowed in this section
	char const		*name2;		//!< module method name2 which is allowed in this section
} module_method_name_t;

extern module_method_name_t module_method_ippool_allocate;

extern module_method_name_t module_method_ippool_extend;

extern module_method_name_t module_method_ippool_mark;

extern module_method_name_t module_method_ippool_release;

#ifdef __cplusplus
}
#endif
