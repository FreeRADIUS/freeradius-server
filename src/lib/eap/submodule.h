#pragma once
/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file lib/eap/submodule.h
 * @brief Submodule interface
 *
 * @copyright 2019 The FreeRADIUS server project
 */
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/module.h>

#define MAX_PROVIDED_METHODS	10

/** Interface exported by EAP submodules
 *
 */
typedef struct {
	DL_MODULE_COMMON;				//!< Common fields to all loadable modules.
	FR_MODULE_COMMON;				//!< Common fields for all instantiated modules.
	FR_MODULE_THREADED_COMMON;			//!< Common fields for threaded modules.

	eap_type_t		provides[MAX_PROVIDED_METHODS];	//!< Allow the module to register itself for more
								///< than one EAP-Method.

	module_method_t		session_init;		//!< Callback for creating a new #eap_session_t.
	module_method_t		entry_point;		//!< Callback for processing the next #eap_round_t of an
							//!< #eap_session_t.

	fr_dict_t		**namespace;		//!< Namespace children should be allocated in.
} rlm_eap_submodule_t;

/** Private structure to hold handles and interfaces for an EAP method
 *
 */
typedef struct {
	module_instance_t		*submodule_inst;		//!< Submodule's instance data
	rlm_eap_submodule_t const	*submodule;			//!< Submodule's exported interface.
} rlm_eap_method_t;
