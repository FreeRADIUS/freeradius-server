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
 * @file lib/eap/compose.h
 * @brief EAP packet composition.
 *
 * @copyright 2019 The FreeRADIUS server project
 */

#include <stdbool.h>

#include "types.h"

/** Structure to hold EAP data
 *
 * length = code + id + length + type + type.data
 *	=  1   +  1 +   2    +  1   +  X
 */
typedef struct {
	eap_code_t	code;
	uint8_t		id;
	size_t		length;
	eap_type_data_t	type;

	uint8_t		*packet;
} eap_packet_t;

/** Contains a pair of request and response packets
 *
 * Helps with formulating/correlating requests to responses we've received.
 */
typedef struct {
	eap_packet_t	*response;			//!< Packet we received from the peer.
	eap_packet_t	*request;			//!< Packet we will send to the peer.
	bool		set_request_id;			//!< Whether the EAP-Method already set the next request ID.
} eap_round_t;

#include "session.h"
#include "submodule.h"

#define RAD_REQUEST_OPTION_PROXY_EAP	(1 << 16)

int  		eap_start(REQUEST *request, rlm_eap_method_t const methods[], bool ignore_unknown_types) CC_HINT(nonnull);
rlm_rcode_t	eap_continue(eap_session_t *eap_session) CC_HINT(nonnull);
rlm_rcode_t	eap_fail(eap_session_t *eap_session) CC_HINT(nonnull);
rlm_rcode_t 	eap_success(eap_session_t *eap_session) CC_HINT(nonnull);
rlm_rcode_t 	eap_compose(eap_session_t *eap_session) CC_HINT(nonnull);
eap_round_t	*eap_round_build(eap_session_t *eap_session, eap_packet_raw_t **eap_packet_p);

