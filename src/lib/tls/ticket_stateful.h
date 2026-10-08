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
 * @file lib/tls/ticket_stateful.h
 * @brief Types for stateful TLS session resumption, the session cache
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(ticket_stateful_h, "$Id$")

#include "openssl_user_macros.h"

#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/** State of one cache operation
 *
 * All policy operations are run the same way.  OpenSSL asks us for
 * something via a callback, and the callback remembers to do it.
 * OpenSSL then returns to us, where then see that there's a policy to
 * be run, and run it.
 *
 * We can't run the interpreter from an OpenSSL callback, so we have
 * to do it via this "back and forth" bounce.
 *
 * Not every operation reaches every state.  A clear has nothing to report
 * back, so it only ever moves between INIT and REQUESTED.
 */
typedef enum {
	FR_TLS_TICKET_STATEFUL_INIT = 0,			//!< Nothing has been asked for.
	FR_TLS_TICKET_STATEFUL_REQUESTED,			//!< OpenSSL has asked for the operation, and the
						///< section which does the work has not run yet.
	FR_TLS_TICKET_STATEFUL_SUCCESS,			//!< The operation completed.  For a load that means
						///< the session came back from the data store, and for
						///< a store it means the session was persisted.
	FR_TLS_TICKET_STATEFUL_FAILED,			//!< The operation did not complete.
} fr_tls_ticket_stateful_state_t;

/** This structure holds the current cache state for the session
 *
 */
typedef struct {
	struct {
		fr_tls_ticket_stateful_state_t		state;		//!< Tracks store state.
		fr_value_box_t			id;		//!< ID of the session being stored
		SSL_SESSION			*sess;		//!< Session to store.
	} store;

	struct {
		fr_tls_ticket_stateful_state_t		state;		//!< Tracks load requests from OpenSSL.
		fr_value_box_t			id;		//!< Session ID that the peer asked to resume
		SSL_SESSION			*sess;		//!< Deserialized session.
	} load;

	struct {
		fr_tls_ticket_stateful_state_t		state;		//!< Tracks delete requests from OpenSSL.
		fr_value_box_t			id;		//!< Session ID to clear
	} clear;

	fr_value_box_t const *session_id;      		//!< if set, points to tls_session->session_id
							///< sent by the peer in ClientHello.
							///< The various IDs above are _usually_ the same, but
							///< are not _always_ the same.

	bool		loaded;				//!< Whether `load session` ever returned a session.
							///< The load state above is reset as the handshake
							///< moves on, so it cannot answer this later.  A
							///< failed session is only worth clearing when a
							///< session was loaded, because `store session` is
							///< not run on failure, and `load session` does not
							///< remove what it read.
} fr_tls_ticket_stateful_t;

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
