#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifdef WITH_TLS
/**
 * $Id$
 *
 * @file lib/tls/ticket_stateless.h
 * @brief Types for stateless TLS session tickets
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(ticket_stateless_h, "$Id$")

#include "openssl_user_macros.h"

#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The current state of calling `encode session` or `decode session`
 *
 * A stateless session ticket encodes the contents of the `session-state` list.
 *
 * The `encode session` policy allows the admin to change the list
 * before the ticket is created.
 *
 * The `decode session` policy allows the admin to check the list
 * after a ticket has been received.
 */
typedef enum {
	FR_TLS_TICKET_STATELESS_INIT = 0,				//!< Nothing requested.
	FR_TLS_TICKET_STATELESS_ENCODE_REQUESTED,			//!< `encode session` needs to run.
	FR_TLS_TICKET_STATELESS_DECODE_REQUESTED,			//!< `decode session` needs to run.
	FR_TLS_TICKET_STATELESS_SUCCESS,				//!< The section ran and returned success.
	FR_TLS_TICKET_STATELESS_FAILED				//!< The section ran and did not.
} fr_tls_ticket_stateless_state_t;

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
