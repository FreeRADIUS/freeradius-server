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
 * @file src/lib/sim/eap_aka_common.h
 * @brief Declarations for EAP-AKA
 *
 * @note These are needed for the quintuplet -> triplet conversion in EAP-SIM.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2016 The FreeRADIUS server project
 */
#include <freeradius-devel/protocol/eap/aka/dictionary.h>

#define EAP_AKA_AUTS_SIZE		14	//!< Server sequence number.  SIM checks this
						//!< is within the correct range.

typedef enum eap_aka_subtype {
	EAP_AKA_CHALLENGE 		= 1,	//!< Challenge packet for distributing NONCE and RAND values.
	EAP_AKA_AUTHENTICATION_REJECT	= 2,
	EAP_AKA_SYNCHRONIZATION_FAILURE	= 4,
	EAP_AKA_IDENTITY 		= 5,	//!< Fast Re-Authentication and pseudonyms.
	EAP_AKA_NOTIFICATION		= 12,	//!< Notification packet.
	EAP_AKA_REAUTHENTICATION	= 13,
	EAP_AKA_CLIENT_ERROR		= 14,
	EAP_AKA_MAX_SUBTYPE		= 15
} eap_aka_subtype_t;
