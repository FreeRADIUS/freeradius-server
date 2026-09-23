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
 * @file lib/tls/connection.h
 * @brief Run one TLS connection from the first policy section to the last.
 *
 * A TLS session is the handshake.  A TLS connection is the handshake, the
 * policy which runs before and after the handshake, and the cache operations
 * the handshake queues.  fr_tls_session_t holds the handshake.
 * fr_tls_connection_t holds the connection, and drives fr_tls_session_t.
 *
 * @copyright 2026 The FreeRADIUS server project
 */
RCSIDH(tls_connection_h, "$Id$")

#include "openssl_user_macros.h"

#include <freeradius-devel/unlang/action.h>

#include "conf.h"
#include "session.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Which part of a connection is running
 *
 * A connection is more than a handshake.  Policy runs before the handshake
 * and after the handshake.  fr_tls_connection_push() pushes one connection
 * frame, and the policy sections and the handshake rounds all run under the
 * connection frame.  Each state arms the next state as the repeat function of
 * the connection frame, so the repeat function records which part runs next.
 *
 * The `state` field of fr_tls_connection_t records the same part for
 * fr_tls_connection_process().  fr_tls_connection_process() runs outside of
 * the connection frame, and so cannot read a repeat function.
 * fr_tls_connection_process() acts only while `state` is
 * TLS_CONNECTION_HANDSHAKE, and sets `state` to TLS_CONNECTION_COMPLETE to
 * record that the handshake has ended.
 */
typedef enum {
	TLS_CONNECTION_NEW_SESSION = 0,			//!< Run `new session { ... }`.
	TLS_CONNECTION_LOAD_SESSION,			//!< Ask the virtual server for a session to resume.
	TLS_CONNECTION_HANDSHAKE,			//!< Run handshake rounds until the handshake ends.
	TLS_CONNECTION_COMPLETE				//!< Run the cache operations the handshake queued.
} fr_tls_connection_state_t;

/** Everything the TLS connection state machine needs
 *
 * The state machine is the set of functions in src/lib/tls/connection.c.
 * Every field the state machine reads or writes lives in fr_tls_connection_t,
 * and the state machine reads no other structure, so the caller may keep
 * fr_tls_connection_t in whatever structure the caller chooses.
 *
 * The state machine performs two actions which are outside of TLS state
 * management:
 *
 * - telling the calling application that the TLS connection has finished,
 *   whether the connection succeeded or failed
 * - writing the data OpenSSL produced out to the peer
 *
 * Both actions belong to the application which owns the connection, so the
 * state machine calls the `finished` and `write` callbacks rather than
 * performing either action itself.
 */
typedef struct fr_tls_connection_s fr_tls_connection_t;

struct fr_tls_connection_s {
	fr_tls_conf_t		*tls_conf;		//!< Parsed "tls" section.
	fr_tls_session_t	*tls_session;		//!< State of the handshake.
	request_t		*request;		//!< Request the handshake runs under.

	fr_tls_connection_state_t state;       		//!< Which part of the connection is running.
	bool			client;			//!< Act as the client and connect to a server,
							///< rather than accept a connection.
	bool			idle;			//!< The connection frame has yielded, and waits
							///< for a record.
	bool			pending;		//!< A record is waiting for OpenSSL.
	bool			failed;			//!< A state or the handshake failed, so the cache
							///< denies the session.

	void			*uctx;			//!< Context for the callback functions below.

	void			(*finished)(void *uctx, fr_tls_connection_t *conn);
							//!< Stop running the connection.  Read the
							///< result from `conn->failed`, and anything
							///< else needed from `conn->tls_conf` or
							///< `conn->tls_session`.
	int			(*write)(void *uctx, fr_tls_connection_t *conn);
							//!< Write what OpenSSL produced out to the
							///< peer.  Returns < 0 on failure.
};

int		fr_tls_connection_push(fr_tls_connection_t *conn);

void		fr_tls_connection_wake(fr_tls_connection_t *conn);

void		fr_tls_connection_process(fr_tls_connection_t *conn);

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
