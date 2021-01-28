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
 * @file rlm_eap.h
 * @brief Implements the EAP framework.
 *
 * @copyright 2000-2003,2006 The FreeRADIUS server project
 * @copyright 2001 hereUare Communications, Inc. (raghud@hereuare.com)
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(rlm_eap_h, "$Id$")

#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/eap/base.h>
#include <freeradius-devel/eap/types.h>

/** Instance data for rlm_eap
 *
 */
typedef struct {
	CONF_SECTION			**submodule_cs;			//!< Configuration sections for the submodules
									///< we're going to load.
	rlm_eap_method_t 		methods[FR_EAP_METHOD_MAX];	//!< Array of loaded (or not), submodules.

	char const			*default_method_name;		//!< Default method to attempt to start.
	eap_type_t			default_method;			//!< Resolved default_method_name.

	bool				ignore_unknown_types;		//!< Ignore unknown types (for later proxying).
	bool				cisco_accounting_username_bug;

	char const			*name;				//!< Name of this instance.
	fr_dict_enum_t			*auth_type;

	fr_randctx			rand_pool;			//!< Pool of random data.
} rlm_eap_t;

/*
 *	EAP Method selection
 */
int      	eap_method_instantiate(rlm_eap_method_t **out, rlm_eap_t *inst, eap_type_t num, CONF_SECTION *cs);
