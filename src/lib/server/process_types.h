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
 * @file src/lib/server/process_types.h
 * @brief Common types for process modules
 *
 * @copyright 2021 The FreeRADIUS server project
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 * @copyright 2025 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/server/pair.h>

/** Common public symbol definition for all process modules
 */
typedef struct {
	module_t			common;		//!< Common fields for all loadable modules.

	module_method_t			process;	//!< Process packets
	virtual_server_compile_t const	*compile_list;	//!< list of processing sections
	fr_dict_t const			**dict;		//!< pointer to local fr_dict_t *
	fr_dict_attr_t const		**packet_type;	//!< Request packet types to look for finally sections for.
} fr_process_module_t;

#ifdef __cplusplus
}
#endif
