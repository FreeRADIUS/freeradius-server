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
 * @file lib/ldap/start_tls.c
 * @brief Start TLS asynchronously
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/ldap/base.h>
#include <freeradius-devel/util/debug.h>

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
 * @param[in] fd_errno	The error that occurred.
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

/*
 *	TLS handshake call flow.  Entries marked [< 2.6.9] or [>= 2.6.9] only
 *	apply to those versions of libldap.  2.6.9 is where ITS#8047 made the
 *	handshake resumable.
 *
 *	- ldap_install_tls
 *	  - calls ldap_tls_inplace to check if the Sockbuf for defconn has TLS installed
 *	    - If it does, returns LDAP_LOCAL_ERROR (and we fail).
 *	    - [>= 2.6.9] Not if defconn's status is LDAP_CONNST_TLS_INPROGRESS, which is
 *	      what lets a second call resume a handshake.
 *	  - calls ldap_int_tls_start.
 *	    - calls tls_init (to initialise ssl library - only done once per implementation).
 *	    - if net timeout is >= 0, and LDAP_OPT_CONNECT_ASYNC is off, then set the FD to
 *	      nonblocking mode.  With LDAP_OPT_CONNECT_ASYNC on it's already nonblocking.
 *	    - calls ldap_int_tls_connect
 *	      - either gets existing session or
 *	        - installs sockbuff shims to do tls encode/decode.
 *	        - calls connect callback
 *	        - [>= 2.6.9] sets defconn's status to LDAP_CONNST_TLS_INPROGRESS.
 *	      - calls ->ti_session_connect (ssl library callback)
 *	        - calls tlso_session_connect (openssl shim)
 *	          - calls SSL_connect - SSL_connect can be called multiple times
 *	            to continue session negotiation.
 *	            returns 0 on success, -1 on error.
 *	      - on -1, calls update_flags, which calls tlso_session_upflags
 *	        - calls SSL_get_error, which returns SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE,
 *	          SSL_ERROR_WANT_CONNECT, or another error.  If error code is one of the above
 *	          returns 1, else returns 0.
 *	          Sets sb->sb_trans_needs_read or sb->sb_trans_needs_write.
 *	      - if update_flags returns 1 ldap_int_tls_connect returns 1.
 *	      - [>= 2.6.9] sets defconn's status to LDAP_CONNST_CONNECTED on success or error.
 *	    - while ldap_int_tls_connect returns 1:
 *	      - [< 2.6.9] with LDAP_OPT_CONNECT_ASYNC on, calls ldap_int_poll, waiting for
 *	        what remains of the net timeout.  The deadline and fd are only set up if the
 *	        net timeout is >= 0, and a net timeout of 0 fails on the first wait.
 *	      - [< 2.6.9] with LDAP_OPT_CONNECT_ASYNC off, calls ldap_int_tls_connect again
 *	        without waiting.
 *	      - [>= 2.6.9] with LDAP_OPT_CONNECT_ASYNC on, returns LDAP_X_CONNECTING.  Calling
 *	        ldap_install_tls again continues the handshake.
 *	      - [>= 2.6.9] with LDAP_OPT_CONNECT_ASYNC off, calls ldap_int_poll, waiting for
 *	        what remains of the net timeout.
 *	    - [>= 2.6.9] with LDAP_OPT_CONNECT_ASYNC off, and a net timeout >= 0, sets the FD
 *	      back to blocking mode.
 *	  - returns LDAP_TIMEOUT if we hit the timeout.
 *
 *	Our handles always have LDAP_OPT_CONNECT_ASYNC on, and a net timeout of 0.  So
 *	from 2.6.9 we drive the handshake from the event loop.  Before 2.6.9 the only
 *	way to complete the handshake is to put the socket into blocking mode, so
 *	SSL_connect never asks to wait.
 */
#if LDAP_VENDOR_VERSION >= 20609
static void _ldap_start_tls_io_handshake(fr_event_list_t *el, int fd, int flags, void *uctx);

/** Run the TLS handshake as far as it can go without waiting
 *
 * If the handshake needs to wait, install an I/O handler for whichever
 * of read or write the TLS library is waiting on, and continue when
 * that handler is called.
 *
 * @param[in] el	to install I/O handlers in.
 * @param[in] tls_ctx	of the StartTLS operation.  Freed when the handshake
 *			completes or fails.
 */
static void ldap_start_tls_handshake(fr_event_list_t *el, fr_ldap_start_tls_ctx_t *tls_ctx)
{
	fr_ldap_connection_t	*c = tls_ctx->c;
	Sockbuf			*sb = NULL;
	int			fd = -1;
	int			ret;
	bool			need_read, need_write;

	ret = ldap_install_tls(c->handle);
	switch (ret) {
	case LDAP_SUCCESS:
		talloc_free(tls_ctx);
		fr_ldap_state_next(c);			/* onto the next operation */
		return;

	case LDAP_X_CONNECTING:
		if ((ldap_get_option(c->handle, LDAP_OPT_SOCKBUF, &sb) != LDAP_OPT_SUCCESS) ||
		    (ldap_get_option(c->handle, LDAP_OPT_DESC, &fd) != LDAP_OPT_SUCCESS) || (fd < 0)) {
			ERROR("Failed getting the socket to continue the TLS handshake");
			goto error;
		}

		need_read = ber_sockbuf_ctrl(sb, LBER_SB_OPT_NEEDS_READ, NULL);
		need_write = ber_sockbuf_ctrl(sb, LBER_SB_OPT_NEEDS_WRITE, NULL);
		if (!fr_cond_assert_msg(need_read || need_write,
					"TLS handshake waiting on neither read nor write")) goto error;

		if (fr_event_fd_insert(tls_ctx, NULL, el, fd,
				       need_read ? _ldap_start_tls_io_handshake : NULL,
				       need_write ? _ldap_start_tls_io_handshake : NULL,
				       _ldap_start_tls_io_error,
				       tls_ctx) < 0) {
			PERROR("Failed inserting TLS handshake I/O handler");
			goto error;
		}
		return;

	default:
		ERROR("ldap_install_tls failed: %s", ldap_err2string(ret));
	error:
		talloc_free(tls_ctx);
		fr_ldap_state_error(c);			/* Restart the connection state machine */
		return;
	}
}

/** Continue the TLS handshake once the socket is ready
 *
 * @param[in] el	the event occurred in.
 * @param[in] fd	the event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] uctx	the StartTLS operation.
 */
static void _ldap_start_tls_io_handshake(fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	ldap_start_tls_handshake(el, talloc_get_type_abort(uctx, fr_ldap_start_tls_ctx_t));
}
#else
/** Run the TLS handshake to completion
 *
 * libldap before 2.6.9 can't resume a TLS handshake, so the socket is put
 * back into blocking mode, and this call blocks the thread until the
 * handshake completes or fails.  Build against libldap 2.6.9 or later to
 * avoid this.
 *
 * @param[in] el	unused.
 * @param[in] tls_ctx	of the StartTLS operation.  Always freed.
 */
static void ldap_start_tls_handshake(UNUSED fr_event_list_t *el, fr_ldap_start_tls_ctx_t *tls_ctx)
{
	fr_ldap_connection_t	*c = tls_ctx->c;
	Sockbuf			*sb = NULL;
	int			ret;

	talloc_free(tls_ctx);

	if (ldap_get_option(c->handle, LDAP_OPT_SOCKBUF, &sb) != LDAP_OPT_SUCCESS) {
		ERROR("Failed getting the socket for the TLS handshake");
	error:
		fr_ldap_state_error(c);			/* Restart the connection state machine */
		return;
	}

	ber_sockbuf_ctrl(sb, LBER_SB_OPT_SET_NONBLOCK, (void *)0);
	ret = ldap_install_tls(c->handle);
	ber_sockbuf_ctrl(sb, LBER_SB_OPT_SET_NONBLOCK, (void *)1);

	if (ret != LDAP_SUCCESS) {
		ERROR("ldap_install_tls failed: %s", ldap_err2string(ret));
		goto error;
	}

	fr_ldap_state_next(c);				/* onto the next operation */
}
#endif

/** Event handler for the response to the StartTLS extended operation
 *
 * Once the server has agreed to StartTLS, run the TLS handshake.
 *
 * @param[in] el	the event occurred in.
 * @param[in] fd	the event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] uctx	Connection config and handle.
 */
static void _ldap_start_tls_io_read(fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	fr_ldap_start_tls_ctx_t	*tls_ctx = talloc_get_type_abort(uctx, fr_ldap_start_tls_ctx_t);
	fr_ldap_connection_t	*c = tls_ctx->c;
	fr_ldap_rcode_t		status;

	/*
	 *	We're I/O driven, if there's no data someone lied to us
	 */
	status = fr_ldap_result(NULL, NULL, c, tls_ctx->msgid, LDAP_MSG_ALL, NULL, fr_time_delta_wrap(0));
	switch (status) {
	case LDAP_PROC_PENDING:
		return;

	case LDAP_PROC_SUCCESS:
		ldap_start_tls_handshake(el, tls_ctx);
		break;

	default:
		talloc_free(tls_ctx);
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
			fr_ldap_state_error(c);			/* Restart the connection state machine */
			return;
		}

		ret = fr_event_fd_insert(tls_ctx, NULL, el, fd,
					 NULL,
					 _ldap_start_tls_io_write,	/* We'll be called again when the conn is open */
					 _ldap_start_tls_io_error,
					 tls_ctx);
		if (!fr_cond_assert(ret == 0)) goto error;
		break;

	case LDAP_SUCCESS:
		if (fd < 0) {
			ret = ldap_get_option(c->handle, LDAP_OPT_DESC, &fd);
			if ((ret != LDAP_OPT_SUCCESS) || (fd < 0)) goto error;
		}
		c->fd = fd;

		/*
		 *	libldap, up to at least 2.7.2, switches the socket to blocking mode
		 *	while sending the first request after an async connect.
		 */
		if (fr_nonblock(fd) < 0) {
			PERROR("Failed setting LDAP connection non-blocking");
			goto error;
		}

		ret = fr_event_fd_insert(tls_ctx, NULL, el, fd,
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

	/*
	 *	ldap_get_option can return LDAP_SUCCESS even if the fd is not yet available
	 *	- hence the test for fd >= 0
	 */
	if ((ldap_get_option(c->handle, LDAP_OPT_DESC, &fd) == LDAP_SUCCESS) && (fd >= 0)) {
		int ret;

		ret = fr_event_fd_insert(tls_ctx, NULL, el, fd,
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
