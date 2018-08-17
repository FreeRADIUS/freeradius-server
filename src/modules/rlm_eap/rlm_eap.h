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
 * @copyright 2000-2003,2006  The FreeRADIUS server project
 * @copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * @copyright 2003  Alan DeKok <aland@freeradius.org>
 */
RCSIDH(rlm_eap_h, "$Id$")

#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/state.h>
#include "eap.h"
#include "eap_types.h"

/** Private structure to hold handles and interfaces for an EAP method
 *
 */
typedef struct rlm_eap_method {
	dl_instance_t			*submodule_inst;		//!< Submodule's instance data
	rlm_eap_submodule_t const	*submodule;			//!< Submodule's exported interface.
} rlm_eap_method_t;

/** Instance data for rlm_eap
 *
 */
typedef struct rlm_eap {
	dl_instance_t			**submodule_instances;		//!< All the submodules we loaded.
	rlm_eap_method_t 		methods[FR_EAP_MAX_TYPES];	//!< Array of loaded (or not), submodules.

	char const			*default_method_name;		//!< Default method to attempt to start.
	eap_type_t			default_method;			//!< Resolved default_method_name.

	bool				ignore_unknown_types;		//!< Ignore unknown types (for later proxying).
	bool				cisco_accounting_username_bug;

	char const			*name;				//!< Name of this instance.
	fr_dict_enum_t			*auth_type;

	fr_randctx			rand_pool;			//!< Pool of random data.
} rlm_eap_t;

/*
 *	Dictionary attributes used by the EAP module
 */
extern fr_dict_attr_t const *attr_eap_type;

extern fr_dict_attr_t const *attr_eap_message;
extern fr_dict_attr_t const *attr_message_authenticator;
extern fr_dict_attr_t const *attr_state;
extern fr_dict_attr_t const *attr_user_name;

/*
 *	EAP Method selection
 */
int      	eap_method_instantiate(rlm_eap_method_t **out, rlm_eap_t *inst, eap_type_t num, CONF_SECTION *cs);

/*
 *	EAP Method composition
 */
int  		eap_start(rlm_eap_t const *inst, REQUEST *request) CC_HINT(nonnull);
rlm_rcode_t	eap_continue(eap_session_t *eap_session) CC_HINT(nonnull);
rlm_rcode_t	eap_fail(eap_session_t *eap_session) CC_HINT(nonnull);
rlm_rcode_t 	eap_success(eap_session_t *eap_session) CC_HINT(nonnull);
rlm_rcode_t 	eap_compose(eap_session_t *eap_session) CC_HINT(nonnull);

/*
 *	Session management
 */
void		eap_session_destroy(eap_session_t **eap_session);
void		eap_session_freeze(eap_session_t **eap_session);
eap_session_t	*eap_session_thaw(REQUEST *request);
eap_session_t 	*eap_session_continue(eap_packet_raw_t **eap_packet, rlm_eap_t const *inst,
				      REQUEST *request) CC_HINT(nonnull);

/*
 *	Memory management
 */
eap_round_t	*eap_round_alloc(eap_session_t *eap_session) CC_HINT(nonnull);
eap_session_t	*eap_session_alloc(rlm_eap_t const *inst, REQUEST *request) CC_HINT(nonnull);
