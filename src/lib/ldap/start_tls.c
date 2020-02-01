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
 * @file lib/ldap/start_tls.c
 * @brief Start TLS asynchronously
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/ldap/base.h>
#include <freeradius-devel/server/rad_assert.h>

/** Holds arguments for the start_tls operation
 *
 */
typedef struct {
	fr_ldap_connection_t	*c;			//!< The current connection.
	LDAPControl		**serverctrls;		//!< Controls to pass to the server.
	LDAPControl		**clientctrls;		//!< Controls to pass to the client (library).

	int			msgid;
} fr_ldap_start_tls_ctx_t;

/** Error reading from or writing to the file descriptor
 *
 * @param[in] el	the event occurred in.
 * @param[in] fd	the event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] fd_errno	The error that ocurred.
 * @param[in] uctx	Connection config and handle.
 */
static void _ldap_start_tls_io_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags,
				     UNUSED int fd_errno, void *uctx)
{
	fr_ldap_start_tls_ctx_t	*tls_ctx = talloc_get_type_abort(uctx, fr_ldap_start_tls_ctx_t);
	fr_ldap_connection_t	*c = tls_ctx->c;

	talloc_free(tls_ctx);
	fr_ldap_state_error(c);			/* Restart the connection state machine */
}

/** Event handler for the response to the StartTLS extended operation
 *
 * Call flow is:
 *
 * - ldap_install_tls
 *   - calls ldap_pvt_tls_inplace to check is the Sockbuf for defconn has TLS installed
 *     - If it does (it shouldn't), returns LDAP_LOCAL_ERROR (and we fail).
 *   - calls ldap_int_tls_start.
 *     - calls_tls_init (to initialise ssl library - only done once per implementation).
 *     - if net timeout is >= 0, then set the FD to nonblocking mode.
 *     - calls ldap_int_tls_connect
 *       - either gets existing session or
 *         - installs sockbuff shims to do tls encode/decode.
 *         - calls connect callback
 *       - calls ->ti_session_connect (ssl library callback)
 *         - calls tlso_session_connect (openssl shim)
 *           - calls SSL_connect - SSL_connect can be called multiple times
 *             to continue session negotiation.
 *             returns 0 on success, -1 on error.
 *       - on -1, calls update_flags, which calls tlso_session_upflags
 *         - calls SSL_get_error, which returns SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE,
 *           SSL_ERROR_WANT_CONNECT, or another error.  If error code is one of the above
 *           returns 1, else returns 0.
 *           Sets sb->sb_trans_needs_read or sb->sb_trans_needs_write.
 *       - if update_flags returns 1 ldap_int_tls_connect returns 1.
 *     - calls ldap_int_poll to check for errors.
 *   - returns LDAP_TIMEOUT if no data is available and we hit the timeout.
 *
 * So unfortunately ldap_install_tls is blocking... We need to send patches to OpenLDAP
 * in order to fix that.
 *
 * @param[in] el	the event occurred in.
 * @param[in] fd	the event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] uctx	Connection config and handle.
 */
static void _ldap_start_tls_io_read(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	fr_ldap_start_tls_ctx_t	*tls_ctx = talloc_get_type_abort(uctx, fr_ldap_start_tls_ctx_t);
	fr_ldap_connection_t	*c = tls_ctx->c;
	int			ret;
	fr_ldap_rcode_t		status;

	/*
	 *	We're I/O driven, if there's no data someone lied to us
	 */
	status = fr_ldap_result(NULL, NULL, c, tls_ctx->msgid, LDAP_MSG_ALL, NULL, 0);
	talloc_free(tls_ctx);				/* Free explicitly so we don't accumulate contexts */

	switch (status) {
	case LDAP_PROC_SUCCESS:
		/*
		 *	If tls_handshake_timeout is NULL ldap_install_tls
		 *	will block forever.
		 */
		fr_ldap_connection_timeout_set(c, c->config->tls_handshake_timeout);

		/*
		 *	This call will block for a maximum of tls_handshake_timeout.
		 *	Patches to libldap are required to fix this.
		 */
		ret = ldap_install_tls(c->handle);
		fr_ldap_connection_timeout_reset(c);
		if (ret != LDAP_SUCCESS) {
			ERROR("ldap_install_tls failed: %s", ldap_err2string(ret));
			fr_ldap_state_error(c);		/* Restart the connection state machine */
		}

		fr_ldap_state_next(c);			/* onto the next operation */
		break;

	default:
		PERROR("StartTLS failed");
		fr_ldap_state_error(c);			/* Restart the connection state machine */
		break;
	}
}

/** Send an extended operation to the LDAP server, requesting a transition to TLS
 *
 * Behind the scenes ldap_start_tls calls:
 *
 *	ldap_extended_operation(ld, LDAP_EXOP_START_TLS, NULL, serverctrls, clientctrls, msgidp);
 *
 * @param[in] el	the event occurred in.
 * @param[in] fd	the event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] uctx	Connection config and handle.
 */
static void _ldap_start_tls_io_write(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_ldap_start_tls_ctx_t	*tls_ctx = talloc_get_type_abort(uctx, fr_ldap_start_tls_ctx_t);
	fr_ldap_connection_t	*c = tls_ctx->c;

	int			ret;

	LDAPControl		*our_serverctrls[LDAP_MAX_CONTROLS];
	LDAPControl		*our_clientctrls[LDAP_MAX_CONTROLS];

	fr_ldap_control_merge(our_serverctrls, our_clientctrls,
			      NUM_ELEMENTS(our_serverctrls),
			      NUM_ELEMENTS(our_clientctrls),
			      c, tls_ctx->serverctrls, tls_ctx->clientctrls);

	/*
	 *	Set timeout to be 0.0, which is the magic
	 *	non-blocking value.
	 */
	(void) ldap_set_option(c->handle, LDAP_OPT_NETWORK_TIMEOUT, &fr_time_delta_to_timeval(0));
	ret = ldap_start_tls(c->handle, our_serverctrls, our_clientctrls, &tls_ctx->msgid);
	/*
	 *	If the handle was not connected, this operation
	 *	can return either LDAP_X_CONNECTING or LDAP_SUCCESS
	 *	depending on how fast the connection came up
	 *	and whether it was connectionless.
	 */
	switch (ret) {
	case LDAP_X_CONNECTING:					/* Connection in progress - retry later */
		ret = ldap_get_option(c->handle, LDAP_OPT_DESC, &fd);
		if (!fr_cond_assert(ret == LDAP_OPT_SUCCESS)) {
		error:
			talloc_free(tls_ctx);
			fr_ldap_connection_timeout_reset(c);
			fr_ldap_state_error(c);			/* Restart the connection state machine */
			return;
		}

		ret = fr_event_fd_insert(tls_ctx, el, fd,
					 NULL,
					 _ldap_start_tls_io_write,	/* We'll be called again when the conn is open */
					 _ldap_start_tls_io_error,
					 tls_ctx);
		if (!fr_cond_assert(ret == 0)) goto error;
		break;

	case LDAP_SUCCESS:
		ret = fr_event_fd_insert(tls_ctx, el, fd,
					 _ldap_start_tls_io_read,
					 NULL,
					 _ldap_start_tls_io_error,
					 tls_ctx);
		if (!fr_cond_assert(ret == 0)) goto error;
		break;

	default:
		ERROR("ldap_start_tls failed: %s", ldap_err2string(ret));
		goto error;
	}

	fr_ldap_connection_timeout_reset(c);
}


/** Install I/O handlers for Start TLS negotiation
 *
 * @param[in] c			connection to StartTLS on.
 * @param[in] serverctrls	Extra controls to pass to the server.
 * @param[in] clientctrls	Extra controls to pass to libldap.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_ldap_start_tls_async(fr_ldap_connection_t *c, LDAPControl **serverctrls, LDAPControl **clientctrls)
{
	int				fd = -1;
	fr_ldap_start_tls_ctx_t		*tls_ctx;
	fr_event_list_t			*el;

	DEBUG2("Starting TLS negotiation");

	MEM(tls_ctx = talloc_zero(c, fr_ldap_start_tls_ctx_t));
	tls_ctx->c = c;
	tls_ctx->serverctrls = serverctrls;
	tls_ctx->clientctrls = clientctrls;

	el = c->conn->el;

	if (ldap_get_option(c->handle, LDAP_OPT_DESC, &fd) == LDAP_SUCCESS) {
		int ret;

		ret = fr_event_fd_insert(tls_ctx, el, fd,
					 NULL,
					 _ldap_start_tls_io_write,
					 _ldap_start_tls_io_error,
					 tls_ctx);
		if (!fr_cond_assert(ret == 0)) {
			talloc_free(tls_ctx);
			return -1;
		}
	} else {
		_ldap_start_tls_io_write(el, -1, 0, tls_ctx);
	}

	return 0;
}
