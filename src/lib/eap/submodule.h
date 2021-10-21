#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
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

#define MAX_PROVIDED_METHODS	5

/** Allow a module to vouch explicitly for an identity
 *
 * This is mainly used for EAP-SIM/EAP-AKA/EAP-AKA' where the preferred
 * eap method is specified by the first byte of the identity.
 *
 * @param[in] inst		Submodule instance.
 * @param[in] id		To check. Do NOT assume the identity is binary safe,
 *				it is common for some identities to be prefixed with
 *				a \0 byte.
 * @param[in] id_len		Length of the identity.
 * @return
 *	- FR_EAP_METHOD_INVALID if we don't recognise the identity.
 *	- Another FR_EAP_METHOD_* to run as the initial EAP method.
 */
typedef eap_type_t (*eap_type_identity_t)(void *inst, char const *id, size_t id_len);

/** Interface exported by EAP submodules
 *
 */
typedef struct {
	DL_MODULE_COMMON;				//!< Common fields to all loadable modules.
	FR_MODULE_COMMON;				//!< Common fields for all instantiated modules.
	FR_MODULE_THREADED_COMMON;			//!< Common fields for threaded modules.

	eap_type_t			provides[MAX_PROVIDED_METHODS];	//!< Allow the module to register itself for more
									///< than one EAP-Method.

	eap_type_identity_t		type_identity;		//!< Do we recognise this identity?

	module_method_t			session_init;		//!< Callback for creating a new #eap_session_t.

	fr_dict_t const			**namespace;		//!< Namespace children should be allocated in.

	bool				clone_parent_lists;	//!< HACK until all eap methods run their own sections.
} rlm_eap_submodule_t;

/** Private structure to hold handles and interfaces for an EAP method
 *
 */
typedef struct {
	module_instance_t		*submodule_inst;		//!< Submodule's instance data
	rlm_eap_submodule_t const	*submodule;			//!< Submodule's exported interface.
} rlm_eap_method_t;
