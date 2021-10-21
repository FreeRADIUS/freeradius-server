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
 * @file rlm_eap_sim/eap_sim.h
 * @brief Declarations for EAP-SIM
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 The FreeRADIUS server project
 */
RCSIDH(rlm_eap_sim_eap_sim_h, "$Id$")

#include <freeradius-devel/sim/base.h>

/** Server states
 *
 * In server_start, we send a EAP-SIM Start message.
 */
typedef enum {
	EAP_SIM_SERVER_START = 0,
	EAP_SIM_SERVER_CHALLENGE,
	EAP_SIM_SERVER_REAUTHENTICATE,
	EAP_SIM_SERVER_SUCCESS_NOTIFICATION,
	EAP_SIM_SERVER_SUCCESS,
	EAP_SIM_SERVER_FAILURE_NOTIFICATION,
	EAP_SIM_SERVER_FAILURE,
	EAP_SIM_SERVER_MAX_STATES
} eap_sim_server_state_t;

typedef struct {
	eap_sim_server_state_t		state;			//!< Current session state.

	bool				allow_encrypted;	//!< Whether we can send encrypted attributes.
	bool				challenge_success;	//!< Whether we received the correct
								///< challenge response.

	fr_sim_keys_t			keys;			//!< Various EAP-AKA keys.
	fr_sim_id_req_type_t		id_req;			//!< The type of identity we're requesting
								///< or previously requested.

	bool				send_result_ind;	//!< Say that we would like to use protected result
								///< indications (SIM-Notification-Success).

	int  				sim_id;			//!< Packet ID. (replay protection)
} eap_sim_session_t;


typedef struct {
	char const			*virtual_server;	//!< Virtual server for HLR integration.
	bool				protected_success;	//!< Send protected success messages.
} rlm_eap_sim_t;
