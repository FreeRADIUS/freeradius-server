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
	eap_packet_t	*response;		//!< Packet we received from the peer.
	eap_packet_t	*request;		//!< Packet we will send to the peer.
	bool		set_request_id;
} eap_round_t;

typedef struct _eap_session eap_session_t;

/*
 *	Function to process EAP packets.
 */
typedef int (*eap_process_t)(void *instance, eap_session_t *eap_session);

/*
 * eap_session_t is the interface for any EAP-Type.
 * Each eap_session contains information for one specific EAP-Type.
 * This way we don't need to change any interfaces in future.
 * It is also a list of EAP-request eap_sessions waiting for EAP-response
 * eap_id = copy of the eap packet we sent to the
 *
 * next = pointer to next
 * state = state attribute from the reply we sent
 * state_len = length of data in the state attribute.
 * src_ipaddr = client which sent us the RADIUS request containing
 *	      this EAP conversation.
 * eap_id = copy of EAP id we sent to the client.
 * timestamp  = timestamp when this eap_session was last used.
 * identity = Identity, as obtained, from EAP-Identity response.
 * request = RADIUS request data structure
 * prev_eap_round = Previous EAP request, for which eap_round contains the response.
 * eap_round   = Current EAP response.
 * opaque   = EAP-Type holds some data that corresponds to the current
 *		EAP-request/response
 * free_opaque = To release memory held by opaque,
 * 		when this eap_session is timedout & needs to be deleted.
 * 		It is the responsibility of the specific EAP-TYPE
 * 		to avoid any memory leaks in opaque
 *		Hence this pointer should be provided by the EAP-Type
 *		if opaque is not NULL
 * status   = finished/onhold/..
 */
#define EAP_STATE_LEN (AUTH_VECTOR_LEN)
struct _eap_session {
	eap_session_t	*prev, *next;
	uint8_t		state[EAP_STATE_LEN];
	fr_ipaddr_t	src_ipaddr;

	uint8_t		eap_id;		//!< EAP Identifier used to match
					//!< requests and responses.
	eap_type_t	type;		//!< EAP type number.

	time_t		timestamp;

	REQUEST		*request;

	char		*identity;	//!< User name from EAP-Identity

	eap_round_t 	*prev_round;
	eap_round_t 	*this_round;

	void 		*opaque;
	void 		(*free_opaque)(void *opaque);
	void		*inst_holder;

	int		status;

	eap_process_t	process;

	int		trips;

	bool		tls;
	bool		finished;
	VALUE_PAIR	*cert_vps;
};

/*
 * Interface to call EAP sub mdoules
 */
typedef struct rlm_eap_module {
	char const *name;						//!< The name of the sub-module
									//!< (without rlm_ prefix).
	int (*instantiate)(CONF_SECTION *conf, void **instance);	//!< Create a new submodule instance.
	eap_process_t	session_init;					//!< Initialise a new EAP session.
	eap_process_t	process;					//!< Continue an EAP session.

	int (*detach)(void *instance);					//!< Destroy a submodule instance.
} rlm_eap_module_t;

#define REQUEST_DATA_EAP_HANDLER	 (1)
#define REQUEST_DATA_EAP_TUNNEL_CALLBACK PW_EAP_MESSAGE
#define REQUEST_DATA_EAP_MSCHAP_TUNNEL_CALLBACK ((PW_EAP_MESSAGE << 16) | PW_EAP_MSCHAPV2)
#define RAD_REQUEST_OPTION_PROXY_EAP	(1 << 16)

/*
 *	This is for tunneled callbacks
 */
typedef int (*eap_tunnel_callback_t)(eap_session_t *eap_session, void *tls_session);

typedef struct eap_tunnel_data_t {
  void			*tls_session;
  eap_tunnel_callback_t callback;
} eap_tunnel_data_t;

#endif /*_EAP_H*/
