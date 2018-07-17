#pragma once
/*
 * eap.h    Header file containing the interfaces for all EAP types.
 *
 * Version:     $Id$
 *
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
 *
 * @copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * @copyright 2003  Alan DeKok <aland@freeradius.org>
 * @copyright 2006  The FreeRADIUS server project
 */
RCSIDH(eap_h, "$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/server/rad_assert.h>

#include "lib/base/eap_base.h"
#include "eap_types.h"

/* TLS configuration name */
#define TLS_CONFIG_SECTION "tls-config"

#define MAX_PROVIDED_METHODS	10

/** Contains a pair of request and response packets
 *
 * Helps with formulating/correlating requests to responses we've received.
 */
typedef struct eap_round {
	eap_packet_t	*response;			//!< Packet we received from the peer.
	eap_packet_t	*request;			//!< Packet we will send to the peer.
	bool		set_request_id;			//!< Whether the EAP-Method already set the next request ID.
} eap_round_t;

/*
 *	Function to process EAP packets.
 */
typedef rlm_rcode_t (*eap_process_t)(void *instance, eap_session_t *eap_session);

#define EAP_STATE_LEN (AUTH_VECTOR_LEN)
/** Tracks the progress of a single session of any EAP method
 *
 */
struct _eap_session {
	eap_session_t	*prev, *next;			//!< Next/previous eap session in this doubly linked list.

	eap_session_t	*child;				//!< Session for tunneled EAP method.

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

	eap_process_t	process;			//!< Callback that should be used to process the next round.
							///< Usually set to the process functino of an EAP submodule.
	int		rounds;				//!< How many roundtrips have occurred this session.

	time_t		updated;			//!< The last time we received a packet for this EAP session.

	bool		tls;				//!< Whether EAP method uses TLS.
	bool		finished;			//!< Whether we consider this session complete.
};

/** Interface exported by EAP submodules
 *
 */
typedef struct rlm_eap_submodule {
	RAD_MODULE_COMMON;					//!< Common fields to all loadable modules.

	eap_type_t		provides[MAX_PROVIDED_METHODS];	//!< Allow the module to register itself for more
								///< than one EAP-Method.

	module_instantiate_t	bootstrap;			//!< Register any attributes required for the module

	module_instantiate_t	instantiate;			//!< Create a new submodule instance.
	eap_process_t		session_init;			//!< Callback for creating a new #eap_session_t.
	eap_process_t		entry_point;			//!< Callback for processing the next #eap_round_t of an
								//!< #eap_session_t.
} rlm_eap_submodule_t;

#define REQUEST_DATA_EAP_SESSION	 (1)
#define REQUEST_DATA_EAP_SESSION_PROXIED (2)

#define REQUEST_DATA_EAP_TUNNEL_CALLBACK FR_EAP_MESSAGE
#define REQUEST_DATA_EAP_MSCHAP_TUNNEL_CALLBACK ((FR_EAP_MESSAGE << 16) | FR_EAP_MSCHAPV2)
#define RAD_REQUEST_OPTION_PROXY_EAP	(1 << 16)

/*
 *	This is for tunneled callbacks
 */
typedef int (*eap_tunnel_callback_t)(eap_session_t *eap_session, void *tls_session);

typedef struct eap_tunnel_data_t {
	void			*tls_session;
	eap_tunnel_callback_t	callback;
} eap_tunnel_data_t;
