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
 * @brief Asynchronous bind functions for LDAP.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/ldap/base.h>
#include <freeradius-devel/util/debug.h>

/** Error reading from or writing to the file descriptor
 *
 * @param[in] el	the event occurred in.
 * @param[in] fd	the event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] fd_errno	The error that ocurred.
 * @param[in] uctx	Connection config and handle.
 */
static void _ldap_bind_io_error(UNUSED fr_event_list_t *el, UNUSED int fd,
				UNUSED int flags, UNUSED int fd_errno, void *uctx)
{
	fr_ldap_bind_ctx_t	*bind_ctx = talloc_get_type_abort(uctx, fr_ldap_bind_ctx_t);
	fr_ldap_connection_t	*c = bind_ctx->c;

	talloc_free(bind_ctx);
	fr_ldap_state_error(c);			/* Restart the connection state machine */
}

/** Parse a bind response from a server
 *
 * @param[in] el	the event occurred in.
 * @param[in] fd	the event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] uctx	bind_ctx containing credentials, and connection config/handle.
 */
static void _ldap_bind_io_read(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	fr_ldap_bind_ctx_t	*bind_ctx = talloc_get_type_abort(uctx, fr_ldap_bind_ctx_t);
	fr_ldap_connection_t	*c = bind_ctx->c;

	fr_ldap_rcode_t		status;

	/*
	 *	We're I/O driven, if there's no data someone lied to us
	 */
	status = fr_ldap_result(NULL, NULL, c, bind_ctx->msgid, LDAP_MSG_ALL, bind_ctx->bind_dn, fr_time_delta_wrap(0));
	switch (status) {
	case LDAP_PROC_SUCCESS:
		DEBUG2("Bind as \"%s\" to \"%s\" successful",
		       *bind_ctx->bind_dn ? bind_ctx->bind_dn : "(anonymous)", c->config->server);
		fr_ldap_state_next(c);		/* onto the next operation */
		break;

	case LDAP_PROC_NOT_PERMITTED:
		PERROR("Bind as \"%s\" to \"%s\" not permitted",
		       *bind_ctx->bind_dn ? bind_ctx->bind_dn : "(anonymous)", c->config->server);
		fr_ldap_state_error(c);		/* Restart the connection state machine */
		return;

	default:
		PERROR("Bind as \"%s\" to \"%s\" failed",
		       *bind_ctx->bind_dn ? bind_ctx->bind_dn : "(anonymous)", c->config->server);
		fr_ldap_state_error(c);		/* Restart the connection state machine */
		return;
	}
	talloc_free(bind_ctx);			/* Also removes fd events */
}

/** Send a bind request to a server
 *
 * @param[in] el	the event occurred in.
 * @param[in] fd	the event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] uctx	bind_ctx containing credentials, and connection config/handle.
 */
static void _ldap_bind_io_write(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_ldap_bind_ctx_t	*bind_ctx = talloc_get_type_abort(uctx, fr_ldap_bind_ctx_t);
	fr_ldap_connection_t	*c = bind_ctx->c;

	LDAPControl		*our_serverctrls[LDAP_MAX_CONTROLS];
	LDAPControl		*our_clientctrls[LDAP_MAX_CONTROLS];

	int			ret;
	struct berval		cred;

	fr_ldap_control_merge(our_serverctrls, our_clientctrls,
			      NUM_ELEMENTS(our_serverctrls),
			      NUM_ELEMENTS(our_clientctrls),
			      c, bind_ctx->serverctrls, bind_ctx->clientctrls);

	if (bind_ctx->password) {
		memcpy(&cred.bv_val, &bind_ctx->password, sizeof(cred.bv_val));
		cred.bv_len = talloc_array_length(bind_ctx->password) - 1;
	} else {
		cred.bv_val = NULL;
		cred.bv_len = 0;
	}

	/*
	 *	Yes, confusingly named.  This is the simple version
	 *	of the SASL bind function that should always be
	 *	available.
	 */
	ret = ldap_sasl_bind(c->handle, bind_ctx->bind_dn, LDAP_SASL_SIMPLE, &cred,
			     our_serverctrls, our_clientctrls, &bind_ctx->msgid);
	switch (ret) {
	/*
	 *	If the handle was not connected, this operation
	 *	can return either LDAP_X_CONNECTING or LDAP_SUCCESS
	 *	depending on how fast the connection came up
	 *	and whether it was connectionless.
	 */
	case LDAP_X_CONNECTING:					/* Connection in progress - retry later */
		ret = ldap_get_option(c->handle, LDAP_OPT_DESC, &fd);
		if (!fr_cond_assert(ret == LDAP_OPT_SUCCESS)) {
		error:
			talloc_free(bind_ctx);
			fr_ldap_connection_timeout_reset(c);
			fr_ldap_state_error(c);			/* Restart the connection state machine */
			return;
		}

		ret = fr_event_fd_insert(bind_ctx, el, fd,
					 NULL,
					 _ldap_bind_io_write,	/* We'll be called again when the conn is open */
					 _ldap_bind_io_error,
					 bind_ctx);
		if (!fr_cond_assert(ret == 0)) goto error;
		break;

	case LDAP_SUCCESS:
		if (fd < 0 ) {
			ret = ldap_get_option(c->handle, LDAP_OPT_DESC, &fd);
			if ((ret != LDAP_OPT_SUCCESS) || (fd < 0)) goto error;
		}
		c->fd = fd;
		ret = fr_event_fd_insert(bind_ctx, el, fd,
					 _ldap_bind_io_read,
					 NULL,
					 _ldap_bind_io_error,
					 bind_ctx);
		if (!fr_cond_assert(ret == 0)) goto error;
		break;

	default:
		ERROR("Bind failed: %s", ldap_err2string(ret));
		goto error;
	}

	fr_ldap_connection_timeout_reset(c);
}

/** Install I/O handlers for the bind operation
 *
 * @param[in] c			connection to StartTLS on.
 * @param[in] bind_dn		Identity to bind with.
 * @param[in] password		Password to bind with.
 * @param[in] serverctrls	Extra controls to pass to the server.
 * @param[in] clientctrls	Extra controls to pass to libldap.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_ldap_bind_async(fr_ldap_connection_t *c,
		       char const *bind_dn, char const *password,
		       LDAPControl **serverctrls, LDAPControl **clientctrls)
{
	int			fd = -1;
	fr_ldap_bind_ctx_t	*bind_ctx;
	fr_event_list_t		*el;

	DEBUG2("Starting bind operation");

	MEM(bind_ctx = talloc_zero(c, fr_ldap_bind_ctx_t));
	bind_ctx->c = c;

	/*
	 *	Bind as anonymous user
	 */
	bind_ctx->bind_dn = bind_dn ? bind_dn : "";
	bind_ctx->password = password;
	bind_ctx->serverctrls = serverctrls;
	bind_ctx->clientctrls = clientctrls;

	el = c->conn->el;

	/*
	 *	ldap_get_option can return a LDAP_SUCCESS even if the fd is not yet available
	 *	- hence the test for fd >= 0
	 */
	if ((ldap_get_option(c->handle, LDAP_OPT_DESC, &fd) == LDAP_SUCCESS) && (fd >= 0)) {
		int ret;

		ret = fr_event_fd_insert(bind_ctx, el, fd,
					 NULL,
					 _ldap_bind_io_write,
					 _ldap_bind_io_error,
					 bind_ctx);
		if (!fr_cond_assert(ret == 0)) {
			talloc_free(bind_ctx);
			return -1;
		}
	} else {
	/*
	 *	Connections initialised with ldap_init() do not have a fd until
	 *	the first request (usually bind) occurs - so this code path
	 *	starts the bind process to open the connection.
	 */
		_ldap_bind_io_write(el, -1, 0, bind_ctx);
	}

	return 0;
}

/** Yield interpreter after queueing LDAP bind
 *
 */
static unlang_action_t ldap_async_auth_bind_start(UNUSED rlm_rcode_t *p_result, UNUSED int *priority,
						  UNUSED request_t *request, UNUSED void *uctx)
{
	return UNLANG_ACTION_YIELD;
}

/** Handle the return code from parsed LDAP results to set the module rcode
 *
 */
static unlang_action_t ldap_async_auth_bind_results(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx)
{
	fr_ldap_bind_auth_ctx_t	*bind_auth_ctx = talloc_get_type_abort(uctx, fr_ldap_bind_auth_ctx_t);
	fr_ldap_bind_ctx_t	*bind_ctx = bind_auth_ctx->bind_ctx;
	rlm_rcode_t		rcode = RLM_MODULE_OK;

	switch (bind_auth_ctx->ret) {
	case LDAP_PROC_SUCCESS:
		RDEBUG2("Bind as user \"%s\" was successful", bind_ctx->bind_dn);
		break;

	case LDAP_PROC_NOT_PERMITTED:
		RDEBUG2("Bind as user \"%s\" not permitted", bind_ctx->bind_dn);
		rcode = RLM_MODULE_DISALLOW;
		break;

	case LDAP_PROC_REJECT:
		RDEBUG2("Bind as user \"%s\" rejected", bind_ctx->bind_dn);
		rcode = RLM_MODULE_REJECT;
		break;

	case LDAP_PROC_BAD_DN:
		rcode = RLM_MODULE_INVALID;
		break;

	case LDAP_PROC_NO_RESULT:
		rcode = RLM_MODULE_NOTFOUND;
		break;

	default:
		rcode = RLM_MODULE_FAIL;
		break;
	}

	/*
	 *	Bind auth ctx is freed by trunk request free.
	 */
	fr_trunk_request_signal_complete(bind_auth_ctx->treq);

	RETURN_MODULE_RCODE(rcode);
}

/** Signal an outstanding LDAP bind request to cancel
 *
 */
static void ldap_async_auth_bind_cancel(request_t *request, UNUSED fr_signal_t action, void *uctx)
{
	fr_ldap_bind_auth_ctx_t	*bind_auth_ctx = talloc_get_type_abort(uctx, fr_ldap_bind_auth_ctx_t);

	RWARN("Cancelling bind auth");
	if (bind_auth_ctx->msgid > 0) fr_rb_remove(bind_auth_ctx->thread->binds, bind_auth_ctx);
	fr_trunk_request_signal_cancel(bind_auth_ctx->treq);
}

/** Initiate an async LDAP bind for authentication
 *
 * @param[in] request		this bind relates to.
 * @param[in] thread		whose connection the bind should be performed on.
 * @param[in] bind_dn		Identity to bind with.
 * @param[in] password		Password to bind with.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_ldap_bind_auth_async(request_t *request, fr_ldap_thread_t *thread, char const *bind_dn, char const *password)
{
	fr_ldap_bind_auth_ctx_t	*bind_auth_ctx;
	fr_trunk_request_t	*treq;
	fr_ldap_thread_trunk_t	*ttrunk = fr_thread_ldap_bind_trunk_get(thread);
	fr_trunk_enqueue_t	ret;

	if (!ttrunk) {
		ERROR("Failed to get trunk connection for LDAP bind");
		return -1;
	}

	treq = fr_trunk_request_alloc(ttrunk->trunk, request);
	if (!treq) {
		ERROR ("Failed to allocate trunk request for LDAP bind");
		return -1;
	}

	MEM(bind_auth_ctx = talloc(treq, fr_ldap_bind_auth_ctx_t));
	*bind_auth_ctx = (fr_ldap_bind_auth_ctx_t) {
		.treq = treq,
		.request = request,
		.thread = thread,
		.ret = LDAP_PROC_NO_RESULT
	};

	MEM(bind_auth_ctx->bind_ctx = talloc(bind_auth_ctx, fr_ldap_bind_ctx_t));
	*bind_auth_ctx->bind_ctx = (fr_ldap_bind_ctx_t) {
		.bind_dn = bind_dn,
		.password = password
	};

	ret = fr_trunk_request_enqueue(&bind_auth_ctx->treq, ttrunk->trunk, request, bind_auth_ctx, NULL);

	switch (ret) {
	case FR_TRUNK_ENQUEUE_OK:
	case FR_TRUNK_ENQUEUE_IN_BACKLOG:
		break;

	default:
		ERROR("Failed to enqueue bind request");
		fr_trunk_request_free(&treq);
		return -1;
	}

	return unlang_function_push(request,
				    ldap_async_auth_bind_start,
				    ldap_async_auth_bind_results,
				    ldap_async_auth_bind_cancel,
				    ~FR_SIGNAL_CANCEL, UNLANG_SUB_FRAME,
				    bind_auth_ctx) == UNLANG_ACTION_PUSHED_CHILD ? 0 : -1;
}
