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
 * @file lib/eap/session.h
 * @brief EAP session management.
 *
 * @copyright 2019 The FreeRADIUS server project
 */
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/request_data.h>
#include <freeradius-devel/server/module.h>

#include "compose.h"
#include "types.h"

#define REQUEST_DATA_EAP_SESSION	 (1)
#define REQUEST_DATA_EAP_SESSION_PROXIED (2)

typedef struct eap_session_s eap_session_t;

/** Tracks the progress of a single session of any EAP method
 *
 */
struct eap_session_s {
	eap_session_t	*prev, *next;			//!< Next/previous eap session in this doubly linked list.

	eap_session_t	*child;				//!< Session for tunneled EAP method.

	REQUEST		*subrequest;			//!< Current subrequest being executed.
	rlm_rcode_t	submodule_rcode;		//!< Result of last submodule call.

	void const	*inst;				//!< Instance of the eap module this session was created by.
	eap_type_t	type;				//!< EAP method number.

	REQUEST		*request;			//!< Current request.  Only used by OpenSSL callbacks to
							///< access the current request.  Must be NULL if eap_session
							///< is not being processed by rlm_eap.

	char		*identity;			//!< NAI (User-Name) from EAP-Identity

	eap_round_t 	*prev_round;			//!< Previous response/request pair. #this_round should contain
							///< the response to the request in #prev_round.
	eap_round_t 	*this_round;			//!< The EAP response we're processing, and the EAP request
							///< we're building.

	void 		*opaque;			//!< Opaque data used by EAP methods.

	module_method_t	process;			//!< Callback that should be used to process the next round.
							///< Usually set to the process function of an EAP submodule.
	int		rounds;				//!< How many roundtrips have occurred this session.

	fr_time_t	updated;			//!< The last time we received a packet for this EAP session.

	bool		tls;				//!< Whether EAP method uses TLS.
	bool		finished;			//!< Whether we consider this session complete.
};

void		eap_session_destroy(eap_session_t **eap_session);

void		eap_session_freeze(eap_session_t **eap_session);

eap_session_t	*eap_session_thaw(REQUEST *request);

eap_session_t 	*eap_session_continue(void const *instance, eap_packet_raw_t **eap_packet, REQUEST *request) CC_HINT(nonnull);

static inline eap_session_t *eap_session_get(REQUEST *request)
{
	return request_data_reference(request, NULL, REQUEST_DATA_EAP_SESSION);
}
