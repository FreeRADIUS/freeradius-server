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
 * @file src/lib/sim/eap_sim_common.h
 * @brief Declarations for EAP-SIM
 *
 * @note These are required by rlm_eap_sim
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2016 The FreeRADIUS server project
 */
#include <freeradius-devel/protocol/eap/sim/dictionary.h>

#define EAP_SIM_VERSION			1
#define EAP_SIM_NONCE_MT_SIZE		16	//!< Length of challenge from SIM client.

#define EAP_SIM_AUTH_SIZE		16
#define EAP_AKA_AUTH_SIZE		16
#define EAP_AKA_PRIME_AUTH_SIZE		32

typedef enum {
	EAP_SIM_START			= 10,	//!< Start packet used for version negotiation.
	EAP_SIM_CHALLENGE		= 11,	//!< Challenge packet for distributing NONCE and RAND values.
	EAP_SIM_NOTIFICATION		= 12,	//!< Notification packet.
	EAP_SIM_REAUTH			= 13,	//!< Fast Re-Authentication.
	EAP_SIM_CLIENT_ERROR		= 14,	//!< Client error.
	EAP_SIM_MAX_SUBTYPE		= 15
} eap_sim_subtype_t;

/** Client states
 *
 * The states an EAP-SIM client may be in.
 */
typedef enum {
	EAP_SIM_CLIENT_INIT		= 0,	//!< Client is in initialization phase.
	EAP_SIM_CLIENT_START		= 1,	//!< Client is in version negotiation phase.
	EAP_SIM_CLIENT_MAX_STATES
} eap_sim_client_states_t;
