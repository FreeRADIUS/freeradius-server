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
 * @file lib/ldap/bind.c
 * @brief Asynchronous SASL bind functions for LDAP.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/ldap/base.h>
#include <freeradius-devel/server/rad_assert.h>
#include <sasl/sasl.h>

/** Holds arguments for the bind operation
 *
 */
typedef struct {
	fr_ldap_connection_t	*c;			//!< to bind.
	char const		*mechs;			//!< SASL mechanisms to run
	char const		*identity;		//!< of the user.
	char const		*password;		//!< of the user, may be NULL if no password is specified.
	char const		*proxy;			//!< Proxy identity, may be NULL in which case identity is used.
	char const		*realm;			//!< SASL realm (may be NULL).
	LDAPControl		**serverctrls;		//!< Controls to pass to the server.
	LDAPControl		**clientctrls;		//!< Controls to pass to the client (library).

	int			msgid;			//!< Last msgid.
	LDAPMessage		*result;		//!< Previous result.
	char const		*rmech;			//!< Mech we're continuing with.
} fr_ldap_sasl_ctx_t;

static void _ldap_sasl_bind_io_write(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx);

/** Error reading from or writing to the file descriptor
 *
 * @param[in] el	the event occurred in.
 * @param[in] fd	the event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] fd_errno	The error that ocurred.
 * @param[in] uctx	Connection config and handle.
 */
static void _ldap_sasl_bind_io_error(UNUSED fr_event_list_t *el, UNUSED int fd,
				     UNUSED int flags, UNUSED int fd_errno, void *uctx)
{
	fr_ldap_sasl_ctx_t	*sasl_ctx = talloc_get_type_abort(uctx, fr_ldap_sasl_ctx_t);
	fr_ldap_connection_t	*c = sasl_ctx->c;

	talloc_free(sasl_ctx);
	fr_ldap_state_error(c);			/* Restart the connection state machine */
}

/** Callback for fr_ldap_sasl_interactive_bind
 *
 * @param[in] handle		used for the SASL bind.
 * @param[in] flags		data as provided to  fr_ldap_sasl_interactive_bind.
 * @param[in] uctx		Our context data, containing the identity, password, realm and various other things.
 * @param[in] sasl_callbacks	Array of challenges to provide responses for.
 * @return SASL_OK.
 */
static int _sasl_interact(UNUSED LDAP *handle, UNUSED unsigned flags, void *uctx, void *sasl_callbacks)
{
	fr_ldap_sasl_ctx_t		*sasl_ctx = talloc_get_type_abort(uctx, fr_ldap_sasl_ctx_t);;
	sasl_interact_t			*cb = sasl_callbacks;
	sasl_interact_t			*cb_p;

	for (cb_p = cb; cb_p->id != SASL_CB_LIST_END; cb_p++) {
		DEBUG3("SASL challenge : %s", cb_p->challenge);
		DEBUG3("SASL prompt    : %s", cb_p->prompt);

		switch (cb_p->id) {
		case SASL_CB_AUTHNAME:
			cb_p->result = sasl_ctx->identity;
			break;

		case SASL_CB_PASS:
			cb_p->result = sasl_ctx->password;
			break;

		case SASL_CB_USER:
			cb_p->result = sasl_ctx->proxy ? sasl_ctx->proxy : sasl_ctx->identity;
			break;

		case SASL_CB_GETREALM:
			cb_p->result = sasl_ctx->realm;
			break;

		default:
			break;
		}
		DEBUG3("SASL result    : %s", cb_p->result ? (char const *)cb_p->result : "");
	}
	return SASL_OK;
}

/** Parse a sasl bind response from a server
 *
 * @param[in] el	the event occurred in.
 * @param[in] fd	the event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] uctx	bind_ctx containing credentials, and connection config/handle.
 */
static void _ldap_sasl_bind_io_read(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_ldap_sasl_ctx_t	*sasl_ctx = talloc_get_type_abort(uctx, fr_ldap_sasl_ctx_t);
	fr_ldap_connection_t	*c = sasl_ctx->c;
	fr_ldap_rcode_t		status;

	/*
	 *	If LDAP parse result indicates there was an error
	 *	then we're done.
	 */
	status = fr_ldap_result(&sasl_ctx->result, NULL, c, sasl_ctx->msgid, LDAP_MSG_ALL, sasl_ctx->identity, 0);
	switch (status) {
	case LDAP_PROC_SUCCESS:
	case LDAP_PROC_CONTINUE:
	{
		struct berval			*srv_cred;
		int				ret;

		/*
		 *	Free the old result (if there is one)
		 */
		if (sasl_ctx->result) {
			ldap_msgfree(sasl_ctx->result);
			sasl_ctx->result = NULL;
		}

		ret = ldap_parse_sasl_bind_result(c->handle, sasl_ctx->result, &srv_cred, 0);
		if (ret != LDAP_SUCCESS) {
			ERROR("SASL decode failed (bind failed): %s", ldap_err2string(ret));
		error:
			talloc_free(sasl_ctx);
			fr_ldap_state_error(c);		/* Restart the connection state machine */
			return;
		}

		DEBUG3("SASL response  : %pV", fr_box_strvalue_len(srv_cred->bv_val, srv_cred->bv_len));
		ldap_memfree(srv_cred);

		/*
		 *	If we need to continue, wait until the
		 *	socket is writable, and then call
		 *	ldap_sasl_interactive_bind again.
		 */
		DEBUG3("Continuing SASL mech %s...", sasl_ctx->rmech);

		ret = fr_event_fd_insert(sasl_ctx, el, fd,
					 NULL,
					 _ldap_sasl_bind_io_write,	/* Need to write more SASL stuff */
					 _ldap_sasl_bind_io_error,
					 sasl_ctx);
		if (!fr_cond_assert(ret == 0)) goto error;
	}
		return;

	default:
		PERROR("SASL bind failed");
		goto error;
	}
}

/** Progress an interactive SASL bind
 *
 * @param[in] el	the event occurred in.
 * @param[in] fd	the event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] uctx	Connection config and handle.
 */
static void _ldap_sasl_bind_io_write(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_ldap_sasl_ctx_t		*sasl_ctx = talloc_get_type_abort(uctx, fr_ldap_sasl_ctx_t);
	fr_ldap_connection_t		*c = sasl_ctx->c;

	int				ret = 0;

	LDAPControl			*our_serverctrls[LDAP_MAX_CONTROLS];
	LDAPControl			*our_clientctrls[LDAP_MAX_CONTROLS];

	fr_ldap_control_merge(our_serverctrls, our_clientctrls,
			      NUM_ELEMENTS(our_serverctrls),
			      NUM_ELEMENTS(our_clientctrls),
			      c, sasl_ctx->serverctrls, sasl_ctx->clientctrls);

	DEBUG2("Starting SASL mech(s): %s", sasl_ctx->mechs);

	/*
	 *	Set timeout to be 0.0, which is the magic
	 *	non-blocking value.
	 */
	(void) ldap_set_option(c->handle, LDAP_OPT_NETWORK_TIMEOUT, &fr_time_delta_to_timeval(0));
	ret = ldap_sasl_interactive_bind(c->handle, NULL, sasl_ctx->mechs,
					 our_serverctrls, our_clientctrls,
					 LDAP_SASL_AUTOMATIC,
					 _sasl_interact, sasl_ctx, sasl_ctx->result,
					 &sasl_ctx->rmech, &sasl_ctx->msgid);
	fr_ldap_connection_timeout_reset(c);
	switch (ret) {
	/*
	 *	If the handle was not connected, this operation
	 *	can return either LDAP_X_CONNECTING or
	 *	LDAP_SASL_BIND_IN_PROGRESS
	 *	depending on how fast the connection came up
	 *	and whether it was connectionless.
	 */
	case LDAP_X_CONNECTING:
		ret = ldap_get_option(c->handle, LDAP_OPT_DESC, &fd);
		if (!fr_cond_assert(ret == LDAP_OPT_SUCCESS)) {
		error:
			talloc_free(sasl_ctx);
			fr_ldap_connection_timeout_reset(c);
			fr_ldap_state_error(c);				/* Restart the connection state machine */
			return;
		}

		ret = fr_event_fd_insert(sasl_ctx, el, fd,
					 NULL,
					 _ldap_sasl_bind_io_write,	/* We'll be called again when the conn is open */
					 _ldap_sasl_bind_io_error,
					 sasl_ctx);
		if (!fr_cond_assert(ret == 0)) goto error;
		break;

	/*
	 *	Want to read more SASL stuff...
	 */
	case LDAP_SASL_BIND_IN_PROGRESS:
		ret = fr_event_fd_insert(sasl_ctx, el, fd,
					 _ldap_sasl_bind_io_read,
					 NULL,
					 _ldap_sasl_bind_io_error,
					 sasl_ctx);
		if (!fr_cond_assert(ret == 0)) goto error;
		break;

	/*
	 *	We're done, woohoo!
	 */
	case LDAP_SUCCESS:
		talloc_free(sasl_ctx);
		fr_ldap_state_next(c);
		break;

	default:
		ERROR("ldap sasl bind failed: %s", ldap_err2string(ret));
		goto error;
	}
}

/** Ensure any outstanding messages are freed
 *
 * @param[in] sasl_ctx	to free.
 * @return 0;
 */
static int _sasl_ctx_free(fr_ldap_sasl_ctx_t *sasl_ctx)
{
	if (sasl_ctx->result) ldap_msgfree(sasl_ctx->result);

	return 0;
}

/** Install I/O handlers for the bind operation
 *
 * @param[in] c			connection to StartTLS on.
 * @param[in] mechs		Space delimited list of sasl mechs to try.
 * @param[in] identity		SASL identity to bind with.
 * @param[in] password		Password credential to pass to SASL.
 * @param[in] proxy		identity. May be NULL.
 * @param[in] realm		SASL realm.
 * @param[in] serverctrls	Extra controls to pass to the server.
 * @param[in] clientctrls	Extra controls to pass to libldap.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_ldap_sasl_bind_async(fr_ldap_connection_t *c,
			    char const *mechs,
			    char const *identity,
			    char const *password,
			    char const *proxy,
			    char const *realm,
			    LDAPControl **serverctrls, LDAPControl **clientctrls)
{
	int			fd = -1;
	fr_ldap_sasl_ctx_t	*sasl_ctx;
	fr_event_list_t		*el;

	DEBUG2("Starting SASL bind operation");

	MEM(sasl_ctx = talloc_zero(c, fr_ldap_sasl_ctx_t));
	talloc_set_destructor(sasl_ctx, _sasl_ctx_free);

	sasl_ctx->c = c;
	sasl_ctx->mechs = mechs;
	sasl_ctx->identity = identity;
	sasl_ctx->password = password;
	sasl_ctx->proxy = proxy;
	sasl_ctx->realm = realm;
	sasl_ctx->serverctrls = serverctrls;
	sasl_ctx->clientctrls = clientctrls;

	el = c->conn->el;

	if (ldap_get_option(c->handle, LDAP_OPT_DESC, &fd) == LDAP_SUCCESS) {
		int ret;

		ret = fr_event_fd_insert(sasl_ctx, el, fd,
					 NULL,
					 _ldap_sasl_bind_io_write,
					 _ldap_sasl_bind_io_error,
					 sasl_ctx);
		if (!fr_cond_assert(ret == 0)) {
			talloc_free(sasl_ctx);
			return -1;
		}
	} else {
		_ldap_sasl_bind_io_write(el, -1, 0, sasl_ctx);
	}

	return 0;
}

