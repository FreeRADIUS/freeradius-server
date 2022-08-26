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
 * @file lib/ldap/sync.h
 *
 * @brief Common definitions required by both network and worker for LDAP sync
 *
 * @copyright 2022 Network RADIUS SARL (legal@networkradius.com)
 */

#include <freeradius-devel/protocol/ldap/freeradius.internal.h>

/** Types of the internal packets for processing LDAP sync messages
 */
typedef enum {
	FR_LDAP_SYNC_CODE_UNDEFINED		= 0,	//!< Packet code has not been set.
	FR_LDAP_SYNC_CODE_PRESENT		= FR_PACKET_TYPE_VALUE_PRESENT,
							//!< LDAP server indicates a particular object is
							//!< present and unchanged.
	FR_LDAP_SYNC_CODE_ADD			= FR_PACKET_TYPE_VALUE_ADD,
							//!< Object has been added to the LDAP directory.
	FR_LDAP_SYNC_CODE_MODIFY		= FR_PACKET_TYPE_VALUE_MODIFY,
							//!< Object has been modified.
	FR_LDAP_SYNC_CODE_DELETE		= FR_PACKET_TYPE_VALUE_DELETE,
							//!< Object has been deleted.
	FR_LDAP_SYNC_CODE_ENTRY_RESPONSE	= FR_PACKET_TYPE_VALUE_RESPONSE,
							//!< Response packet to present / add / modify / delete.
	FR_LDAP_SYNC_CODE_COOKIE_LOAD		= FR_PACKET_TYPE_VALUE_COOKIE_LOAD,
							//!< Before the sync starts, request any previously stored cookie.
	FR_LDAP_SYNC_CODE_COOKIE_LOAD_RESPONSE	= FR_PACKET_TYPE_VALUE_COOKIE_LOAD_RESPONSE,
							//!< Response with the returned cookie.
	FR_LDAP_SYNC_CODE_COOKIE_STORE		= FR_PACKET_TYPE_VALUE_COOKIE_STORE,
							//!< The server has sent a new cookie.
	FR_LDAP_SYNC_CODE_COOKIE_STORE_RESPONSE	= FR_PACKET_TYPE_VALUE_COOKIE_STORE_RESPONSE,
							//!< Response to storing the new cookie.
	FR_LDAP_SYNC_CODE_MAX 			= FR_PACKET_TYPE_VALUE_COOKIE_STORE_RESPONSE + 1,
	FR_LDAP_SYNC_CODE_DO_NOT_RESPOND	= 256	//!< Special rcode to indicate we will not respond.
} fr_ldap_sync_packet_code_t;

#define FR_LDAP_SYNC_PACKET_CODE_VALID(_code) (((_code) > 0) && ((_code) < FR_LDAP_SYNC_CODE_MAX))
