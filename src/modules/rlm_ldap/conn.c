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
 * @file rlm_ldap.c
 * @brief Connection wrappers
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2017 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#define LOG_PREFIX "%s - "
#define LOG_PREFIX_ARGS handle_config->name

#include <freeradius-devel/util/debug.h>

#include "rlm_ldap.h"

/** Gets an LDAP socket from the connection pool
 *
 * Retrieve a socket from the connection pool, or NULL on error (of if no sockets are available).
 *
 * @param inst rlm_ldap configuration.
 * @param request Current request (may be NULL).
 */
fr_ldap_connection_t *mod_conn_get(rlm_ldap_t const *inst, REQUEST *request)
{
	fr_ldap_connection_t *conn;

	conn = fr_pool_connection_get(inst->pool, request);

	fr_assert(!conn || conn->config);

#ifdef LDAP_CONTROL_X_SESSION_TRACKING
	/*
	 *	Add optional session tracking controls,
	 *	that contain values of some attributes
	 *	in the request.
	 */
	if ((conn != NULL) && (request != NULL) && inst->session_tracking) {
		if (fr_ldap_control_add_session_tracking(conn, request) < 0) {
			fr_pool_connection_release(inst->pool, request, conn);
			return NULL;
		}
	}
#endif
	return conn;
}

/** Releases an LDAP socket back to the connection pool
 *
 * If the socket was rebound chasing a referral onto another server then we destroy it.
 * If the socket was rebound to another user on the same server, we let the next caller rebind it.
 *
 * @param inst rlm_ldap configuration.
 * @param request The current request.
 * @param conn to release.
 */
void ldap_mod_conn_release(rlm_ldap_t const *inst, REQUEST *request, fr_ldap_connection_t *conn)
{
	/*
	 *	Could have already been free'd due to a previous error.
	 */
	if (!conn) return;

	/*
	 *	Clear any client/server controls associated with the connection.
	 */
	fr_ldap_control_clear(conn);

	/*
	 *	We chased a referral to another server.
	 *
	 *	This connection is no longer part of the pool which is
	 *	connected to and bound to the configured server.
	 *	Close it.
	 *
	 *	Note that we do NOT close it if it was bound to another user.
	 *	Instead, we let the next caller do the rebind.
	 */
	if (conn->referred) {
		fr_pool_connection_close(inst->pool, request, conn);
		return;
	}

	fr_pool_connection_release(inst->pool, request, conn);
	return;
}

/** Create and return a new connection
 *
 * Create a new ldap connection and allocate memory for a new rlm_handle_t
 */
void *ldap_mod_conn_create(TALLOC_CTX *ctx, void *instance, fr_time_delta_t timeout)
{
	fr_ldap_rcode_t		status;
	fr_ldap_connection_t	*conn;
	fr_ldap_config_t const	*handle_config = instance;	/* Not talloced */

	conn = fr_ldap_connection_alloc(ctx);
	if (!conn) return NULL;

	if (fr_ldap_connection_configure(conn, handle_config) < 0) {
		talloc_free(conn);
		return NULL;
	}

	fr_ldap_connection_timeout_set(conn, timeout);
	if (handle_config->start_tls) {
		if (ldap_start_tls_s(conn->handle, NULL, NULL) != LDAP_SUCCESS) {
			int ldap_errno;

			ldap_get_option(conn->handle, LDAP_OPT_ERROR_NUMBER, &ldap_errno);

			ERROR("Could not start TLS: %s", ldap_err2string(ldap_errno));

		error:
			talloc_free(conn);

			return NULL;
		}
	}

	status = fr_ldap_bind(NULL,
			      &conn,
			      conn->config->admin_identity, conn->config->admin_password,
			      &(conn->config->admin_sasl),
			      timeout,
			      NULL, NULL);
	if (status != LDAP_PROC_SUCCESS) goto error;
	fr_ldap_connection_timeout_reset(conn);

	/*
	 *	Only error out on memory allocation errors
	 */
	if (fr_ldap_directory_alloc(conn, &conn->directory, &conn) < 0) goto error;

	return conn;
}
