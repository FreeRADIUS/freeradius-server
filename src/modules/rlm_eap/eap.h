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
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 * Copyright 2006  The FreeRADIUS server project
 */
#ifndef _EAP_H
#define _EAP_H

RCSIDH(eap_h, "$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include "eap_types.h"

/* TLS configuration name */
#define TLS_CONFIG_SECTION "tls-config"

/** Contains a pair of request and response packets
 *
 * Helps with formulating/correlating requests to responses we've received.
 */
typedef struct eap_round {
	eap_packet_t	*response;			//!< Packet we received from the peer.
	eap_packet_t	*request;			//!< Packet we will send to the peer.
	bool		set_request_id;
} eap_round_t;

typedef struct _eap_session eap_session_t;

/*
 *	Function to process EAP packets.
 */
typedef int (*eap_process_t)(void *instance, eap_session_t *eap_session);

#define EAP_STATE_LEN (AUTH_VECTOR_LEN)
/** Tracks the progress of a single session of any EAP method
 *
 */
struct _eap_session {
	eap_session_t	*prev, *next;			//!< Next/previous eap session in this doubly linked list.

	eap_session_t	*child;				//!< Session for tunnelled EAP method.

	void		*inst;				//!< Instance of the eap module this session was created by.
	uint8_t		state[EAP_STATE_LEN];		//!< State attribute value the last reply we sent.
	fr_ipaddr_t	src_ipaddr;			//!< of client which sent us the RADIUS request for this
							//!< session.

	eap_type_t	type;				//!< EAP method number.

	REQUEST		*request;			//!< Request that contains the response we're processing.

	char		*identity;			//!< NAI (User-Name) from EAP-Identity

	eap_round_t 	*prev_round;			//!< Previous response/request pair. #this_round should contain
							//!< the response to the request in #prev_round.
	eap_round_t 	*this_round;			//!< The EAP response we're processing, and the EAP request
							//!< we're building.

	void 		*opaque;			//!< Opaque data used by EAP methods.

	eap_process_t	process;			//!< Callback that should be used to process the next round.
							//!< Usually set to the process functino of an EAP submodule.
	int		rounds;				//!< How many roundtrips have occurred this session.

	bool		tls;				//!< Whether EAP method uses TLS.
	bool		finished;			//!< Whether we consider this session complete.
};

/** Interface to call EAP sub mdoules
 *
 */
typedef struct rlm_eap_module {
	char const *name;				//!< The name of the sub-module
							//!< (without rlm_ prefix).
	int (*instantiate)(CONF_SECTION *conf, void **instance); //!< Create a new submodule instance.
	eap_process_t	session_init;			//!< Callback for creating a new #eap_session_t.
	eap_process_t	process;			//!< Callback for processing the next #eap_round_t of an
							//!< #eap_session_t.

	int (*detach)(void *instance);			//!< Destroy an EAP submodule instance.
} rlm_eap_module_t;

#define REQUEST_DATA_EAP_SESSION	 (1)
#define REQUEST_DATA_EAP_TUNNEL_CALLBACK PW_EAP_MESSAGE
#define REQUEST_DATA_EAP_MSCHAP_TUNNEL_CALLBACK ((PW_EAP_MESSAGE << 16) | PW_EAP_MSCHAPV2)
#define RAD_REQUEST_OPTION_PROXY_EAP	(1 << 16)

/*
 *	This is for tunneled callbacks
 */
typedef int (*eap_tunnel_callback_t)(eap_session_t *eap_session, void *tls_session);

typedef struct eap_tunnel_data_t {
	void			*tls_session;
	eap_tunnel_callback_t	callback;
} eap_tunnel_data_t;

rlm_rcode_t	eap_virtual_server(REQUEST *request, REQUEST *fake,
				   eap_session_t *eap_session, char const *virtual_server);

#endif /*_EAP_H*/
