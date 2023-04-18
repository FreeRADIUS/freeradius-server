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
#include <freeradius-devel/util/debug.h>
#include <sasl/sasl.h>

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
	fr_ldap_sasl_ctx_t		*sasl_ctx = talloc_get_type_abort(uctx, fr_ldap_sasl_ctx_t);
	sasl_interact_t			*cb = sasl_callbacks;
	sasl_interact_t			*cb_p;

	for (cb_p = cb; cb_p->id != SASL_CB_LIST_END; cb_p++) {
		DEBUG3("SASL challenge : %s", cb_p->challenge);
		DEBUG3("SASL prompt    : %s", cb_p->prompt);

		switch (cb_p->id) {
		case SASL_CB_AUTHNAME:
			/*
			 *	For mechs like -Y EXTERNAL we don't have
			 *	any information to provide to SASL.
			 */
			if (!sasl_ctx->identity) {
			null_result:
				cb_p->result = NULL;
				cb_p->len = 0;
				break;
			}
			cb_p->result = sasl_ctx->identity;
			cb_p->len = strlen(sasl_ctx->identity);
			break;

		case SASL_CB_PASS:
			if (!sasl_ctx->password) goto null_result;

			cb_p->result = sasl_ctx->password;
			cb_p->len = strlen(sasl_ctx->password);
			break;

		case SASL_CB_USER:
			if (!sasl_ctx->proxy && !sasl_ctx->identity) goto null_result;

			cb_p->result = sasl_ctx->proxy ? sasl_ctx->proxy : sasl_ctx->identity;
			cb_p->len = sasl_ctx->proxy ? strlen(sasl_ctx->proxy) : strlen(sasl_ctx->identity);
			break;

		case SASL_CB_GETREALM:
			if (!sasl_ctx->realm) goto null_result;

			cb_p->result = sasl_ctx->realm;
			cb_p->len = strlen(sasl_ctx->realm);
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
	 *	Free the old result (if there is one)
	 */
	if (sasl_ctx->result) {
		ldap_msgfree(sasl_ctx->result);
		sasl_ctx->result = NULL;
	}

	/*
	 *	If LDAP parse result indicates there was an error
	 *	then we're done.
	 */
	status = fr_ldap_result(&sasl_ctx->result, NULL, c, sasl_ctx->msgid, LDAP_MSG_ALL,
				sasl_ctx->identity, fr_time_delta_wrap(0));
	switch (status) {
	case LDAP_PROC_SUCCESS:
	case LDAP_PROC_CONTINUE:
	{
		struct berval			*srv_cred;
		int				ret;

		ret = ldap_parse_sasl_bind_result(c->handle, sasl_ctx->result, &srv_cred, 0);
		if (ret != LDAP_SUCCESS) {
			ERROR("SASL decode failed (bind failed): %s", ldap_err2string(ret));
		error:
			talloc_free(sasl_ctx);
			fr_ldap_state_error(c);		/* Restart the connection state machine */
			return;
		}

		/*
		 *	Observed as NULL when doing EXTERNAL
		 *	authentication.
		 */
		if (srv_cred) {
			DEBUG3("SASL response  : %pV",
			       fr_box_strvalue_len(srv_cred->bv_val, srv_cred->bv_len));
			ber_bvfree(srv_cred);
		}

		/*
		 *	If we need to continue, wait until the
		 *	socket is writable, and then call
		 *	ldap_sasl_interactive_bind again.
		 *
		 *	sasl_ctx->rmech may be NULL if there's
		 *	nothing else to do.
		 */
		if (sasl_ctx->rmech) DEBUG3("Continuing SASL mech %s...", sasl_ctx->rmech);

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

	DEBUG2("%s SASL mech(s): %s", (sasl_ctx->result == NULL ? "Starting" : "Continuing"), sasl_ctx->mechs);

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
		if (fd < 0) {
			ret = ldap_get_option(c->handle, LDAP_OPT_DESC, &fd);
			if ((ret != LDAP_OPT_SUCCESS) || (fd < 0)) goto error;
		}
		c->fd = fd;
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
		DEBUG2("SASL bind as \"%s\" to \"%s\" successful",
		       sasl_ctx->identity ? sasl_ctx->identity : "(anonymous)", c->config->server);
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

	/*
	 *	ldap_get_option can return LDAP_SUCCESS even if the fd is not yet available
	 *	- hence the test for fd >= 0
	 */
	if ((ldap_get_option(c->handle, LDAP_OPT_DESC, &fd) == LDAP_SUCCESS) && (fd >= 0)){
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

/** Send a SASL LDAP auth bind
 *
 * Shares the same callback as SASL admin binds
 *
 * @param[in] sasl_ctx	containing SASL parameters / state for the bind.
 * @param[out] msgid	where to write the LDAP message ID.
 * @param[in] ldap_conn	on which the message should be sent.
 */
int fr_ldap_sasl_bind_auth_send(fr_ldap_sasl_ctx_t *sasl_ctx, int *msgid,
				 fr_ldap_connection_t *ldap_conn)
{
	return ldap_sasl_interactive_bind(ldap_conn->handle, NULL, sasl_ctx->mechs,
					  NULL, NULL, LDAP_SASL_AUTOMATIC,
					  _sasl_interact, sasl_ctx, sasl_ctx->result,
					  &sasl_ctx->rmech, msgid);
}

/** Yield interpreter after enqueueing sasl auth bind
 *
 */
static unlang_action_t ldap_async_sasl_bind_auth_start(UNUSED rlm_rcode_t *p_result, UNUSED int *priority,
						       UNUSED request_t *request, UNUSED void *uctx)
{
	return UNLANG_ACTION_YIELD;
}

/** Signal an outstanding SASL LDAP bind to cancel
 *
 * @param[in] request	being processed. Unused.
 * @param[in] action	Signal to handle.
 * @param[in] uctx	bind auth ctx.
 */
static void ldap_async_sasl_bind_auth_cancel(request_t *request, UNUSED fr_signal_t action, void *uctx)
{
	fr_ldap_bind_auth_ctx_t *bind_auth_ctx = talloc_get_type_abort(uctx, fr_ldap_bind_auth_ctx_t);

	RWARN("Cancelling SASL bind auth");
	if (bind_auth_ctx->msgid > 0) fr_rb_remove(bind_auth_ctx->thread->binds, bind_auth_ctx);
	fr_trunk_request_signal_cancel(bind_auth_ctx->treq);
}

/** Handle the return code from parsed LDAP results to set the module rcode
 *
 * @param[out] p_result	Where to write return code.
 * @param[in] priority	Unused.
 * @param[in] request	being processed.
 * @param[in] uctx	bind auth ctx.
 * @return	unlang action.
 */
static unlang_action_t ldap_async_sasl_bind_auth_results(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx)
{
	fr_ldap_bind_auth_ctx_t	*bind_auth_ctx = talloc_get_type_abort(uctx, fr_ldap_bind_auth_ctx_t);
	fr_ldap_sasl_ctx_t	*sasl_ctx = bind_auth_ctx->sasl_ctx;
	fr_ldap_rcode_t		ret = bind_auth_ctx->ret;
	fr_ldap_connection_t	*ldap_conn = NULL;

	switch (bind_auth_ctx->ret) {
	case LDAP_PROC_SUCCESS:
		RDEBUG2("Bind as user \"%s\" was successful", sasl_ctx->identity);
		break;

	case LDAP_PROC_NOT_PERMITTED:
		RDEBUG2("Bind as user \"%s\" not permitted", sasl_ctx->identity);
		break;

	case LDAP_PROC_REJECT:
		RDEBUG2("Bind as user \"%s\" rejected", sasl_ctx->identity);
		break;

	case LDAP_PROC_CONTINUE:
		if (fr_trunk_request_requeue(bind_auth_ctx->treq) != FR_TRUNK_ENQUEUE_OK) {
			ret = LDAP_PROC_ERROR;
			break;
		}

		/*
		 *	Once the next SASL exchange has completed repeat this function to
		 *	process the results
		 */
		if (unlang_function_repeat_set(request, ldap_async_sasl_bind_auth_results) < 0) {
			/*
			 *	Not strictly an LDAP error but if this happens we will want to reset
			 *	the connection to get a known state.
			 */
			ret = LDAP_PROC_ERROR;
			break;
		}
		return UNLANG_ACTION_YIELD;

	default:
		break;
	}

	if (bind_auth_ctx->treq->tconn) ldap_conn = talloc_get_type_abort(bind_auth_ctx->treq->tconn->conn->h,
									  fr_ldap_connection_t);

	/*
	 *	Will free bind_auth_ctx
	 */
	fr_trunk_request_signal_complete(bind_auth_ctx->treq);

	switch (ret) {
	case LDAP_PROC_SUCCESS:
		RETURN_MODULE_OK;

	case LDAP_PROC_NOT_PERMITTED:
		RETURN_MODULE_DISALLOW;

	case LDAP_PROC_REJECT:
		RETURN_MODULE_REJECT;

	case LDAP_PROC_BAD_DN:
		RETURN_MODULE_INVALID;

	case LDAP_PROC_NO_RESULT:
		RETURN_MODULE_NOTFOUND;

	default:
		if (ldap_conn) {
			RPERROR("LDAP connection returned an error - restarting the connection");
			fr_ldap_state_error(ldap_conn);
		}
		RETURN_MODULE_FAIL;
	}
}

/** Initiate an async SASL LDAP bind for authentication
 *
 * @param[in] request		this bind relates to.
 * @param[in] thread		whose connection the bind should be performed on.
 * @param[in] mechs		SASL mechanisms to use.
 * @param[in] dn		DN to bind as.
 * @param[in] identity		Identity to bind with.
 * @param[in] password		Password to bind with.
 * @param[in] proxy		Identity to proxy.
 * @param[in] realm		SASL realm if applicable.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
*/
int fr_ldap_sasl_bind_auth_async(request_t *request, fr_ldap_thread_t *thread, char const *mechs, char const *dn,
				 char const *identity, char const *password, char const *proxy, char const *realm)
{
	fr_ldap_bind_auth_ctx_t *bind_auth_ctx;
	fr_trunk_request_t	*treq;
	fr_ldap_thread_trunk_t	*ttrunk = fr_thread_ldap_bind_trunk_get(thread);
	fr_trunk_enqueue_t	ret;

	if (!ttrunk) {
		ERROR("Failed to get trunk connection for LDAP bind");
		return -1;
	}

	treq = fr_trunk_request_alloc(ttrunk->trunk, request);
	if (!treq) {
		ERROR("Failed to allocate trunk request for LDAP bind");
		return -1;
	}

	MEM(bind_auth_ctx = talloc_zero(treq, fr_ldap_bind_auth_ctx_t));
	*bind_auth_ctx = (fr_ldap_bind_auth_ctx_t) {
		.treq = treq,
		.request = request,
		.thread = thread,
		.ret = LDAP_PROC_NO_RESULT,
		.type = LDAP_BIND_SASL
	};

	MEM(bind_auth_ctx->sasl_ctx = talloc(bind_auth_ctx, fr_ldap_sasl_ctx_t));
	talloc_set_destructor(bind_auth_ctx->sasl_ctx, _sasl_ctx_free);
	*bind_auth_ctx->sasl_ctx = (fr_ldap_sasl_ctx_t) {
		.mechs = mechs,
		.dn = dn,
		.identity = identity,
		.password = password,
		.proxy = proxy,
		.realm = realm,
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
				    ldap_async_sasl_bind_auth_start,
				    ldap_async_sasl_bind_auth_results,
				    ldap_async_sasl_bind_auth_cancel,
				    ~FR_SIGNAL_CANCEL, UNLANG_SUB_FRAME,
				    bind_auth_ctx) == UNLANG_ACTION_PUSHED_CHILD ? 0 : -1;
}
