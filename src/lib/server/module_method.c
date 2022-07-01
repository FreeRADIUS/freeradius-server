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
 * @file src/lib/server/module_method.c
 * @briefCentral module_method_name_t definitions
 *
 * This file contains common module_method_t structures which may be
 * referenced within a #virtual_server_compile_t and a #module_t.
 *
 * This is partly for documentation, partly for boilerplate reducation
 * and partly to minimise stupid typos and other screwups which'd lead
 * to matches failing.
 *
 * Referencing the same #module_method_t in both the virtual server
 * and the module allows for a potential fast path where we just compare
 * the pointer values.
 *
 * @copyright 2022 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
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

module_method_name_t module_method_ippool_allocate = {
	.name1 = "ippool",
	.name2 = "allocate"
};

module_method_name_t module_method_ippool_extend = {
	.name1 = "ippool",
	.name2 = "extend"
};

module_method_name_t module_method_ippool_mark = {
	.name1 = "ippool",
	.name2 = "mark"
};

module_method_name_t module_method_ippool_release = {
	.name1 = "ippool",
	.name2 = "release"
};
