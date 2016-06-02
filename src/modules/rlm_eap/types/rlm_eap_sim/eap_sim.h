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
 * @file rlm_eap_sim/eap_sim.h
 * @brief Declarations for EAP-SIM
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 *
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2016 The FreeRADIUS server project
 */
RCSIDH(rlm_eap_sim_eap_sim_h, "$Id$")

#include "../../libeap/eap_sim.h"

/** Where to get EAP-SIM vectors from
 *
 */
typedef enum {
	EAP_SIM_VECTOR_SRC_AUTO,		//!< Discover where to get Triplets from automatically.
	EAP_SIM_VECTOR_SRC_GSM,			//!< Source of triplets is EAP-SIM-* attributes.
	EAP_SIM_VECTOR_SRC_UMTS,		//!< Source of triplets is derived from EAP-AKA-* quintuplets.
	EAP_SIM_VECTOR_SRC_KI			//!< Should generate triplets locally using a Ki.
} eap_sim_vector_src_t;

/** Server states
 *
 * In server_start, we send a EAP-SIM Start message.
 */
typedef enum eap_sim_server_states {
	EAP_SIM_SERVER_START		= 0,
	EAP_SIM_SERVER_CHALLENGE	= 1,
	EAP_SIM_SERVER_SUCCESS		= 10,
	EAP_SIM_SERVER_MAX_STATES
} eap_sim_server_state_t;

typedef struct eap_sim_session {
	eap_sim_server_state_t	state;		//!< Current session state.
	eap_sim_keys_t		keys;		//!< Various EAP-SIM keys.
	int  			sim_id;		//!< Packet ID. (replay protection)
} eap_sim_session_t;

/*
 *	sim_vector.c
 */
int sim_vector_from_attrs(eap_session_t *eap_session, VALUE_PAIR *vps,
			  int idx, eap_sim_session_t *ess, eap_sim_vector_src_t *src);
