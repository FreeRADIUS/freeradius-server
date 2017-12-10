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
 * @file rlm_eap_aka/eap_aka.h
 * @brief Declarations for EAP-AKA
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 *
 * @copyright 2016 The FreeRADIUS server project
 * @copyright 2016 Network RADIUS SARL <sales@networkradius.com>
 */
RCSIDH(rlm_eap_aka_eap_aka_h, "$Id$")

#include "sim_proto.h"

/** Server states
 *
 * In server_start, we send a EAP-AKA Start message.
 */
typedef enum {
	EAP_AKA_SERVER_START = 0,				//!< Initial state.
	EAP_AKA_SERVER_IDENTITY,				//!< Attempting to discover permanent
								///< identity of the supplicant.
	EAP_AKA_SERVER_CHALLENGE,				//!< We've challenged the supplicant.
	EAP_AKA_SERVER_SUCCESS_NOTIFICATION,			//!< Send success notification.
	EAP_AKA_SERVER_SUCCESS,					//!< Authentication completed successfully.
	EAP_AKA_SERVER_GENERAL_FAILURE_NOTIFICATION,		//!< Send failure notification.
	EAP_AKA_SERVER_MAX_STATES
} eap_aka_server_state_t;

typedef struct {
	fr_sim_id_req_type_t		id_req;			//!< The type of identity we're requesting
								///< or previously requested.
	eap_aka_server_state_t		state;			//!< Current session state.
	fr_sim_keys_t			keys;			//!< Various EAP-AKA keys.

	fr_sim_checkcode_t		*checkcode_state;	//!< Digest of all identity packets we've seen.
	uint8_t				checkcode[32];		//!< Checkcode we calculated.
	size_t				checkcode_len;		//!< 0, 20 or 32 bytes.

	int  				aka_id;			//!< Packet ID. (replay protection).
} eap_aka_session_t;

typedef struct {
	char const			*virtual_server;	//!< Virtual server for HLR integration.
	bool				request_identity;	//!< Whether we always request the identity of
								///< the subscriber.
} rlm_eap_aka_t;
