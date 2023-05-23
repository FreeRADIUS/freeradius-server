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
 * @file lib/ldap/connection.c
 * @brief Asynchronous connection management functions for LDAP.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/ldap/base.h>
#include <freeradius-devel/util/debug.h>

/*
 *	Lookup of libldap result message types to meaningful strings
 */
static char const *ldap_msg_types[UINT8_MAX] = {
	[LDAP_RES_BIND]			= "bind response",
	[LDAP_RES_SEARCH_ENTRY]		= "search entry",
	[LDAP_RES_SEARCH_REFERENCE]	= "search reference",
	[LDAP_RES_SEARCH_RESULT]	= "search result",
	[LDAP_RES_MODIFY]		= "modify response",
	[LDAP_RES_ADD]			= "add response",
	[LDAP_RES_DELETE]		= "delete response",
	[LDAP_RES_MODDN]		= "modify dn response",
	[LDAP_RES_COMPARE]		= "compare response",
	[LDAP_RES_EXTENDED]		= "extended response",
	[LDAP_RES_INTERMEDIATE]		= "intermediate response"
};


/** Allocate and configure a new connection
 *
 * Configures both our ldap handle, and libldap's handle.
 *
 * This can be used by async code and async code as no attempt is made to connect
 * to the LDAP server.  An attempt will only be made if ldap_start_tls* or ldap_bind*
 * functions are called.
 *
 * If called on an #fr_ldap_connection_t which has already been initialised, will
 * clear any memory allocated to the connection, unbind the ldap handle, and reinitialise
 * everything.
 *
 * @param[in] c		to configure.
 * @param[in] config	to apply.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
int fr_ldap_connection_configure(fr_ldap_connection_t *c, fr_ldap_config_t const *config)
{
	LDAP	*handle = NULL;
	int	ldap_errno, ldap_version, keepalive, probes, is_server;

	fr_assert(config->server);

	ldap_errno = ldap_initialize(&handle, config->server);
	if (ldap_errno != LDAP_SUCCESS) {
		ERROR("ldap_initialize failed: %s", ldap_err2string(ldap_errno));
	error:
		return -1;
	}

	DEBUG3("New connection %p libldap handle %p", c, handle);

	c->config = config;
	c->handle = handle;

	/*
	 *	We now have a connection structure, but no actual connection.
	 *
	 *	Set a bunch of LDAP options, using common code.
	 */
#define do_ldap_option(_option, _name, _value) \
	if (ldap_set_option(c->handle, _option, _value) != LDAP_OPT_SUCCESS) { \
		ldap_get_option(c->handle, LDAP_OPT_ERROR_NUMBER, &ldap_errno); \
		ERROR("Failed setting connection option %s: %s", _name, \
		      (ldap_errno != LDAP_SUCCESS) ? ldap_err2string(ldap_errno) : "Unknown error"); \
		goto error;\
	}

DIAG_OFF(unused-macros)
#define maybe_ldap_option(_option, _name, _value) \
	if (_value) do_ldap_option(_option, _name, _value)
DIAG_ON(unused-macros)

	/*
	 *	Leave "dereference" unset to use the OpenLDAP default.
	 */
	if (config->dereference_str) do_ldap_option(LDAP_OPT_DEREF, "dereference", &(config->dereference));

	/*
	 *	We handle our own referral chasing as there is no way to
	 *	get the fd for a referred query.
	 */
	do_ldap_option(LDAP_OPT_REFERRALS, "chase_referrals", LDAP_OPT_OFF);

	/*
	 *	A value of zero results in an handle configuration failure.
	 *
	 *	When most people specify zero they mean infinite.
	 *
	 *	libldap requires tv_sec to be -1 to mean that.
	 */
	do_ldap_option(LDAP_OPT_NETWORK_TIMEOUT, "net_timeout",
		       (fr_time_delta_ispos(config->net_timeout) ?
				&fr_time_delta_to_timeval(config->net_timeout) :
				&(struct timeval) { .tv_sec = -1, .tv_usec = 0 }));

	do_ldap_option(LDAP_OPT_TIMELIMIT, "srv_timelimit", &fr_time_delta_to_timeval(config->srv_timelimit));

	ldap_version = LDAP_VERSION3;
	do_ldap_option(LDAP_OPT_PROTOCOL_VERSION, "ldap_version", &ldap_version);

	keepalive = fr_time_delta_to_sec(config->keepalive_idle);
	do_ldap_option(LDAP_OPT_X_KEEPALIVE_IDLE, "keepalive_idle", &keepalive);

	probes = config->keepalive_probes;
	do_ldap_option(LDAP_OPT_X_KEEPALIVE_PROBES, "keepalive_probes", &probes);

	keepalive = fr_time_delta_to_sec(config->keepalive_interval);
	do_ldap_option(LDAP_OPT_X_KEEPALIVE_INTERVAL, "keepalive_interval", &keepalive);

	/*
	 *	Set all of the TLS options
	 */
	if (config->tls_mode) do_ldap_option(LDAP_OPT_X_TLS, "tls_mode", &(config->tls_mode));

	maybe_ldap_option(LDAP_OPT_X_TLS_CACERTFILE, "ca_file", config->tls_ca_file);
	maybe_ldap_option(LDAP_OPT_X_TLS_CACERTDIR, "ca_path", config->tls_ca_path);

	/*
	 *	Set certificate options
	 */
	maybe_ldap_option(LDAP_OPT_X_TLS_CERTFILE, "certificate_file", config->tls_certificate_file);
	maybe_ldap_option(LDAP_OPT_X_TLS_KEYFILE, "private_key_file", config->tls_private_key_file);

	if (config->tls_require_cert_str) {
		do_ldap_option(LDAP_OPT_X_TLS_REQUIRE_CERT, "require_cert", &config->tls_require_cert);
	}

	if (config->tls_min_version_str) {
		do_ldap_option(LDAP_OPT_X_TLS_PROTOCOL_MIN, "tls_min_version", &config->tls_min_version);
	}

	/*
	 *	Counter intuitively the TLS context appears to need to be initialised
	 *	after all the TLS options are set on the handle.
	 */

	/* Always use the new TLS configuration context */
	is_server = 0;
	do_ldap_option(LDAP_OPT_X_TLS_NEWCTX, "new TLS context", &is_server);

	if (config->sasl_secprops) do_ldap_option(LDAP_OPT_X_SASL_SECPROPS, "sasl_secprops", config->sasl_secprops);

	if (config->start_tls) {
		if (config->port == 636) {
			WARN("Told to Start TLS on LDAPS port this will probably fail, please correct the "
			     "configuration");
		}
	}

	return 0;
}

/** Free the handle, closing the connection to ldap
 *
 * @param[in] el	UNUSED.
 * @param[in] h		to close.
 * @param[in] uctx	Connection config and handle.
 */
static void _ldap_connection_close(fr_event_list_t *el, void *h, UNUSED void *uctx)
{
	fr_ldap_connection_t *c = talloc_get_type_abort(h, fr_ldap_connection_t);

	/*
	 *	Explicitly remove the file descriptor event
	 *
	 *	Even if the fr_ldap_connection_t has outstanding
	 *	queries, we still don't want its fd in the event loop.
	 */
	if (c->fd >= 0) {
		fr_event_fd_delete(el, c->fd, FR_EVENT_FILTER_IO);
		c->fd = -1;
	}

	talloc_free(h);
}

/** Close and delete a connection
 *
 * Unbinds the LDAP connection, informing the server and freeing any memory, then releases the memory used by the
 * connection handle.
 *
 * @param[in] c		to destroy.
 * @return always indicates success.
 */
static int _ldap_connection_free(fr_ldap_connection_t *c)
{
	/*
	 *	If there are any pending queries, don't free
	 */
	if (((c->queries) && (fr_rb_num_elements(c->queries) > 0)) || (fr_dlist_num_elements(&c->refs) > 0)) return -1;

	talloc_free_children(c);	/* Force inverted free order */

	if (c->handle) {
		LDAPControl	*our_serverctrls[LDAP_MAX_CONTROLS];
		LDAPControl	*our_clientctrls[LDAP_MAX_CONTROLS];

		fr_ldap_control_merge(our_serverctrls, our_clientctrls,
				      NUM_ELEMENTS(our_serverctrls),
				      NUM_ELEMENTS(our_clientctrls),
				      c, NULL, NULL);

		DEBUG3("Closing connection %p libldap handle %p", c->handle, c);
		ldap_unbind_ext(c->handle, our_serverctrls, our_clientctrls);	/* Same code as ldap_unbind_ext_s */
	}

	fr_ldap_control_clear(c);

	return 0;
}

/** Allocate our ldap connection handle layer
 *
 * This is using handles outside of the connection state machine.
 *
 * @param[in] ctx to allocate connection handle in.
 * @return
 *	- A new unbound/unconfigured connection handle on success.
 *	  Call f#r_ldap_connection_configure next.
 *	- NULL on OOM.
 */
fr_ldap_connection_t *fr_ldap_connection_alloc(TALLOC_CTX *ctx)
{
	fr_ldap_connection_t *c;

	/*
	 *	Allocate memory for the handle.
	 */
	c = talloc_zero(ctx, fr_ldap_connection_t);
	if (!c) return NULL;

	talloc_set_destructor(c, _ldap_connection_free);

	/*
	 *	Ensure the fd is invalid to start with, preventing
	 *	attempts to remove fd events if the server is shut down
	 *	before the LDAP conneciton is established
	 */
	c->fd = -1;

	return c;
}

/** Watcher for LDAP connections being closed
 *
 * If there are any outstanding queries on the connection then
 * re-parent the connection to the NULL ctx so that it remains
 * until all the queries have been dealt with.
 */
static void _ldap_connection_close_watch(fr_connection_t *conn, UNUSED fr_connection_state_t prev,
					 UNUSED fr_connection_state_t state, void *uctx)
{
	fr_ldap_connection_t	*ldap_conn = talloc_get_type_abort(uctx, fr_ldap_connection_t);

	if ((fr_rb_num_elements(ldap_conn->queries) == 0) && (fr_dlist_num_elements(&ldap_conn->refs) == 0)) return;

	talloc_reparent(conn, NULL, ldap_conn);
	ldap_conn->conn = NULL;
}

/** (Re-)Initialises the libldap side of the connection handle
 *
 *  The first ldap state transition is either:
 *
 *     init -> start tls
 *  or
 *     init -> bind
 *
 *  Either way libldap will try an open the connection so when fr_ldap_state_next
 *  returns we should have the file descriptor to pass back.
 *
 *  The complete order of operations is:
 *
 *  - Initialise the libldap handle with fr_ldap_connection_configure (calls ldap_init)
 *  - Initiate the connection with fr_ldap_state_next, which either binds or calls start_tls.
 *  - Either operation calls ldap_send_server_request.
 *    - Which calls ldap_new_connection.
 *    - Which calls ldap_int_open_connection.
 *    - Which calls ldap_connect_to_(host|path) and adds socket buffers, and possibly
 *      calls ldap_int_tls_start (for ldaps://).
 *    - When ldap_new_connection returns, because LDAP_OPT_CONNECT_ASYNC
 *      is set to LDAP_OPT_ON, lc->lconn_status is set to LDAP_CONNST_CONNECTING.
 *    - ldap_send_server_request checks for lconn_stats == LDAP_CONNST_CONNECTING,
 *      and calls ldap_int_poll, which checks the fd for error conditions
 *      and immediately returns due to the network timeout value.
 *    - If the socket is not yet connected:
 *      - As network timeout on the LDAP handle is 0, ld->ld_errno is set to
 *        LDAP_X_CONNECTING. ldap_send_server_request returns -1.
 *      - bind or start_tls errors with LDAP_X_CONNECTING without sending the request.
 *      - We install a write I/O handler, and wait to be called again, then we retry the
 *        operation.
 *    - else
 *      - the bind or start_tls operation succeeds, our ldap state machine advances,
 *        the connection callback is called and our socket state machine transitions to
 *        connected.
 *  - Continue running the state machine
 *
 * @param[out] h	Underlying file descriptor from libldap handle.
 * @param[in] conn	Being initialised.
 * @param[in] uctx	Our LDAP connection handle (a #fr_ldap_connection_t).
 * @return
 *	- FR_CONNECTION_STATE_CONNECTING on success.
 *	- FR_CONNECTION_STATE_FAILED on failure.
 */
static fr_connection_state_t _ldap_connection_init(void **h, fr_connection_t *conn, void *uctx)
{
	fr_ldap_config_t const	*config = uctx;
	fr_ldap_connection_t	*c;
	fr_ldap_state_t		state;

	c = fr_ldap_connection_alloc(conn);
	c->conn = conn;

	fr_connection_add_watch_pre(conn, FR_CONNECTION_STATE_CLOSED, _ldap_connection_close_watch, true, c);

	/*
	 *	Configure/allocate the libldap handle
	 */
	if (fr_ldap_connection_configure(c, config) < 0) {
	error:
		talloc_free(c);
		return FR_CONNECTION_STATE_FAILED;
	}

	/* Don't block */
	if (ldap_set_option(c->handle, LDAP_OPT_CONNECT_ASYNC, LDAP_OPT_ON) != LDAP_OPT_SUCCESS) goto error;
	fr_ldap_connection_timeout_set(c, fr_time_delta_wrap(0));	/* Forces LDAP_X_CONNECTING */

	state = fr_ldap_state_next(c);
	if (state == FR_LDAP_STATE_ERROR) goto error;

	/*
	 *	Initialise tree for outstanding queries handled by this connection
	 */
	MEM(c->queries = fr_rb_inline_talloc_alloc(c, fr_ldap_query_t, node, fr_ldap_query_cmp, NULL));
	fr_dlist_init(&c->refs, fr_ldap_query_t, entry);

	*h = c;	/* Set the handle */

	return FR_CONNECTION_STATE_CONNECTING;
}

/** Alloc a self re-establishing connection to an LDAP server
 *
 * @param[in] ctx		to allocate any memory in, and to bind the lifetime of the connection to.
 * @param[in] el		to insert I/O and timer callbacks into.
 * @param[in] config		to use to bind the connection to an LDAP server.
 * @param[in] log_prefix	to prepend to connection state messages.
 */
fr_connection_t	*fr_ldap_connection_state_alloc(TALLOC_CTX *ctx, fr_event_list_t *el,
					        fr_ldap_config_t const *config, char const *log_prefix)
{
	fr_connection_t *conn;

	conn = fr_connection_alloc(ctx, el,
				   &(fr_connection_funcs_t){
				   	.init = _ldap_connection_init,
				   	.close = _ldap_connection_close
				   },
				   &(fr_connection_conf_t){
				   	.connection_timeout = config->net_timeout,
				   	.reconnection_delay = config->reconnection_delay
				   },
				   log_prefix, config);
	if (!conn) {
		PERROR("Failed allocating state handler for new LDAP connection");
		return NULL;
	}

	return conn;
}

int fr_ldap_connection_timeout_set(fr_ldap_connection_t const *c, fr_time_delta_t timeout)
{
	int ldap_errno;

	/*
	 *	A value of zero results in an handle configuration failure.
	 *
	 *	When most people specify zero they mean infinite.
	 *
	 *	libldap requires tv_sec to be -1 to mean that.
	 */
	do_ldap_option(LDAP_OPT_NETWORK_TIMEOUT, "net_timeout",
		       (fr_time_delta_ispos(timeout) ?
		       		&fr_time_delta_to_timeval(timeout) :
		       		&(struct timeval) { .tv_sec = -1, .tv_usec = 0 }));

	return 0;

error:
	return -1;
}

int fr_ldap_connection_timeout_reset(fr_ldap_connection_t const *c)
{
	int ldap_errno;

	/*
	 *	A value of zero results in an handle configuration failure.
	 *
	 *	When most people specify zero they mean infinite.
	 *
	 *	libldap requires tv_sec to be -1 to mean that.
	 */
	do_ldap_option(LDAP_OPT_NETWORK_TIMEOUT, "net_timeout",
		       (fr_time_delta_ispos(c->config->net_timeout) ?
		       		&fr_time_delta_to_timeval(c->config->net_timeout) :
				&(struct timeval) { .tv_sec = -1, .tv_usec = 0 }));

	return 0;

error:
	return -1;
}

/** Callback for closing idle LDAP trunk
 *
 */
static void _ldap_trunk_idle_timeout(fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_ldap_thread_trunk_t	*ttrunk = talloc_get_type_abort(uctx, fr_ldap_thread_trunk_t);

	if (ttrunk->trunk->req_alloc == 0) {
		DEBUG2("Removing idle LDAP trunk to \"%s\"", ttrunk->uri);
		talloc_free(ttrunk->trunk);
		talloc_free(ttrunk);
	} else {
		/*
		 *	There are still pending queries - insert a new event
		 */
		(void) fr_event_timer_in(ttrunk, el, &ttrunk->ev, ttrunk->t->config->idle_timeout,
					 _ldap_trunk_idle_timeout, ttrunk);
	}
}

/** Callback when an LDAP trunk request is cancelled
 *
 * Ensure the request is removed from the list of outstanding requests
 */
static void ldap_request_cancel(UNUSED fr_connection_t *conn, void *preq, UNUSED fr_trunk_cancel_reason_t reason,
			        UNUSED void *uctx) {
	fr_ldap_query_t	*query = talloc_get_type_abort(preq, fr_ldap_query_t);

	if (query->ldap_conn) {
		fr_rb_remove(query->ldap_conn->queries, query);
		query->ldap_conn = NULL;
	}
}

/** Callback to cancel LDAP queries
 *
 * Inform the remote LDAP server that we no longer want responses to specific queries.
 *
 * @param[in] el	For timer mangement.
 * @param[in] tconn	The trunk connection handle
 * @param[in] conn	The specific connection queries will be cancelled on
 * @param[in] uctx	Context provided to fr_trunk_alloc
 */
static void ldap_request_cancel_mux(UNUSED fr_event_list_t *el, fr_trunk_connection_t *tconn,
				    fr_connection_t *conn, UNUSED void *uctx)
{
	fr_trunk_request_t	*treq;
	fr_ldap_connection_t	*ldap_conn = talloc_get_type_abort(conn->h, fr_ldap_connection_t);
	fr_ldap_query_t		*query;

	while ((fr_trunk_connection_pop_cancellation(&treq, tconn)) == 0) {
		query = talloc_get_type_abort(treq->preq, fr_ldap_query_t);
		ldap_abandon_ext(ldap_conn->handle, query->msgid, NULL, NULL);

		fr_trunk_request_signal_cancel_complete(treq);
	}
}


/** I/O read function
 *
 * Underlying FD is now readable - call the trunk to read any pending requests.
 *
 * @param[in] el	The event list signalling.
 * @param[in] fd	that's now readable.
 * @param[in] flags	describing the read event.
 * @param[in] uctx	The trunk connection handle.
 */
static void ldap_conn_readable(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);

	fr_trunk_connection_signal_readable(tconn);
}


/** I/O write function
 *
 * Underlying FD is now writable - call the trunk to write any pending requests.
 *
 * @param[in] el	The event list signalling.
 * @param[in] fd	that's now writable.
 * @param[in] flags	describing the write event.
 * @param[in] uctx	The trunk connection handle
 */
static void ldap_conn_writable(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);

	fr_trunk_connection_signal_writable(tconn);
}


/** I/O error function
 *
 * The event loop signalled that a fatal error occurec on this connection.
 *
 * @param[in] el	The event list signalling.
 * @param[in] fd	that errored.
 * @param[in] flags	EL flags.
 * @param[in] fd_errno	The nature of the error.
 * @param[in] uctx	The trunk connection handle
 */
static void ldap_conn_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, int fd_errno, void *uctx)
{
	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);

	ERROR("%s - Connection failed: %s", tconn->conn->name, fr_syserror(fd_errno));

	fr_connection_signal_reconnect(tconn->conn, FR_CONNECTION_FAILED);
}

/** Setup callbacks requested by LDAP trunk connections
 *
 * @param[in] tconn	Trunk handle.
 * @param[in] conn	Individual connection callbacks are to be installed for.
 * @param[in] el	The event list to install events in.
 * @param[in] notify_on	The types of event the trunk wants to be notified on.
 * @param[in] uctx	Context provided to fr_trunk_alloc.
 */
static void ldap_trunk_connection_notify(fr_trunk_connection_t *tconn, fr_connection_t *conn,
					 fr_event_list_t *el,
					 fr_trunk_connection_event_t notify_on, UNUSED void *uctx)
{
	fr_ldap_connection_t	*ldap_conn = talloc_get_type_abort(conn->h, fr_ldap_connection_t);
	fr_event_fd_cb_t	read_fn = NULL;
	fr_event_fd_cb_t	write_fn = NULL;

	switch (notify_on) {
	case FR_TRUNK_CONN_EVENT_NONE:
		fr_event_fd_delete(el, ldap_conn->fd, FR_EVENT_FILTER_IO);
		return;

	case FR_TRUNK_CONN_EVENT_READ:
		read_fn = ldap_conn_readable;
		break;

	case FR_TRUNK_CONN_EVENT_WRITE:
		write_fn = ldap_conn_writable;
		break;

	case FR_TRUNK_CONN_EVENT_BOTH:
		read_fn = ldap_conn_readable;
		write_fn = ldap_conn_writable;
		break;
	}

	if (fr_event_fd_insert(ldap_conn, el, ldap_conn->fd,
			       read_fn,
			       write_fn,
			       ldap_conn_error,
			       tconn) < 0) {
		PERROR("Failed inserting FD event");
		fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
	}
}

/** Allocate an LDAP trunk connection
 *
 * @param[in] tconn		Trunk handle.
 * @param[in] el		Event list which will be used for I/O and timer events.
 * @param[in] conn_conf		Configuration of the connnection.
 * @param[in] log_prefix	What to prefix log messages with.
 * @param[in] uctx		User context passed to fr_trunk_alloc.
 */
static fr_connection_t *ldap_trunk_connection_alloc(fr_trunk_connection_t *tconn, fr_event_list_t *el,
						    UNUSED fr_connection_conf_t const *conn_conf,
						    char const *log_prefix, void *uctx)
{
	fr_ldap_thread_trunk_t	*thread_trunk = talloc_get_type_abort(uctx, fr_ldap_thread_trunk_t);

	return fr_ldap_connection_state_alloc(tconn, el, &thread_trunk->config, log_prefix);
}

#define POPULATE_LDAP_CONTROLS(_dest, _src) do { \
	int i; \
	for (i = 0; (i < LDAP_MAX_CONTROLS) && (_src[i].control); i++) { \
		_dest[i] = _src[i].control; \
	} \
	_dest[i] = NULL; \
} while (0)

/** Take LDAP pending queries from the queue and send them.
 *
 * @param[in] el	Event list for timers.
 * @param[in] tconn	Trunk handle.
 * @param[in] conn	on which to send the queries
 * @param[in] uctx	User context passed to fr_trunk_alloc
 */
static void ldap_trunk_request_mux(UNUSED fr_event_list_t *el, fr_trunk_connection_t *tconn,
				   fr_connection_t *conn, UNUSED void *uctx)
{
	fr_ldap_connection_t	*ldap_conn = talloc_get_type_abort(conn->h, fr_ldap_connection_t);
	fr_trunk_request_t	*treq;

	LDAPURLDesc		*referral_url = NULL;

	fr_ldap_query_t		*query = NULL;
	fr_ldap_rcode_t		status = LDAP_PROC_ERROR;

	while (fr_trunk_connection_pop_request(&treq, tconn) == 0) {
		LDAPControl	*our_serverctrls[LDAP_MAX_CONTROLS + 1];
		LDAPControl	*our_clientctrls[LDAP_MAX_CONTROLS + 1];

		if (!treq) break;

		query = talloc_get_type_abort(treq->preq, fr_ldap_query_t);

		switch (query->type) {
		case LDAP_REQUEST_SEARCH:
			/*
			 *	This query is a LDAP search
			 */
			if (query->referral) referral_url = query->referral->referral_url;

			POPULATE_LDAP_CONTROLS(our_serverctrls, query->serverctrls);
			POPULATE_LDAP_CONTROLS(our_clientctrls, query->clientctrls);

			/*
			 *	If we are chasing a referral, referral_url will be populated and may
			 *	have a base dn or scope to override the original query
			 */
			status = fr_ldap_search_async(&query->msgid, query->treq->request, &ldap_conn,
						      (referral_url && referral_url->lud_dn) ?
						      	referral_url->lud_dn : query->dn,
						      (referral_url && referral_url->lud_scope) ?
					      		referral_url->lud_scope : query->search.scope,
					      	      query->search.filter, query->search.attrs,
						      our_serverctrls, our_clientctrls);
			break;

		case LDAP_REQUEST_MODIFY:
			/*
			 *	This query is an LDAP modification
			 */
			POPULATE_LDAP_CONTROLS(our_serverctrls, query->serverctrls);
			POPULATE_LDAP_CONTROLS(our_clientctrls, query->clientctrls);

			status = fr_ldap_modify_async(&query->msgid, query->treq->request,
						      &ldap_conn, query->dn, query->mods,
						      our_serverctrls, our_clientctrls);
			break;

		case LDAP_REQUEST_EXTENDED:
			/*
			 *	This query is an LDAP extended operation.
			 */
			status = fr_ldap_extended_async(&query->msgid, query->treq->request, &ldap_conn,
							query->extended.reqoid, query->extended.reqdata);
			break;

		default:
			ERROR("Invalid LDAP query for trunk connection");
		error:
			fr_trunk_request_signal_fail(query->treq);
			continue;

		}

		if (status != LDAP_PROC_SUCCESS) goto error;

		/*
		 *	If the query has previously been associated with a different
		 *	connection, remove that reference.  Typically when following references.
		 */
		if (query->ldap_conn) fr_dlist_remove(&query->ldap_conn->refs, query);

		/*
		 *	Record which connection was used for this query
		 *	- results processing often needs access to an LDAP handle
		 */
		query->ldap_conn = ldap_conn;

		/*
		 *	Add the query to the tree of pending queries for this trunk
		 */
		fr_rb_insert(query->ldap_conn->queries, query);

		fr_trunk_request_signal_sent(treq);
	}

}

/** Read LDAP responses
 *
 * Responses from the LDAP server will cause the fd to become readable and trigger this
 * callback.  Most LDAP search responses have multiple messages in their response - we
 * only gather those which are complete before either following a referral or passing
 * the head of the resulting chain of messages back.
 *
 * @param[in] el	To insert timers into.
 * @param[in] tconn	Trunk connection associated with these results.
 * @param[in] conn	Connection handle for these results.
 * @param[in] uctx	Thread specific trunk structure - contains tree of pending queries.
 */
static void ldap_trunk_request_demux(fr_event_list_t *el, fr_trunk_connection_t *tconn, fr_connection_t *conn, void *uctx)
{
	fr_ldap_connection_t	*ldap_conn = talloc_get_type_abort(conn->h, fr_ldap_connection_t);
	fr_ldap_thread_trunk_t	*ttrunk = talloc_get_type_abort(uctx, fr_ldap_thread_trunk_t);

	int 			ret = 0, msgtype;
	struct timeval		poll = { 0, 10 };
	LDAPMessage		*result = NULL;
	fr_ldap_rcode_t		rcode;
	fr_ldap_query_t		find = { .msgid = -1 }, *query = NULL;
	request_t		*request;
	bool			really_no_result = false;
	fr_trunk_request_t	*treq;

	/*
	 *  Reset the idle timeout event
	 */
	(void) fr_event_timer_in(ttrunk, el, &ttrunk->ev,
				 ttrunk->t->config->idle_timeout, _ldap_trunk_idle_timeout, ttrunk);

	do {
		/*
		 *	Look for any results for which we have the complete result message
		 *	ldap_result will return a pointer to a chain of messages.
		 *
		 *	The first time ldap_result is called when there's pending network
		 *	data, it may read the data, but not return any results.
		 *
		 *	In order to fix the spurious debugging messages and overhead,
		 *	if this is the first iteration through the loop and ldap_result
		 *	returns no result (0), we call it again.
		 */
		ret = ldap_result(ldap_conn->handle, LDAP_RES_ANY, LDAP_MSG_ALL, &poll, &result);
		switch (ret) {
		case 0:
			if (really_no_result) return;
			really_no_result = true;
			continue;

		case -1:
			rcode = fr_ldap_error_check(NULL, ldap_conn, NULL, NULL);
			if (rcode == LDAP_PROC_BAD_CONN) {
				ERROR("Bad LDAP connection");
				fr_connection_signal_reconnect(tconn->conn, FR_CONNECTION_FAILED);
			}
			return;

		default:
			/*
			 *	We only retry ldap_result the first time through the loop.
			 */
			really_no_result = true;
			break;
		}

		find.msgid = ldap_msgid(result);
		query = fr_rb_find(ldap_conn->queries, &find);

		if (!query) {
			WARN("Ignoring msgid %i - doesn't match any outstanding queries (it may have been cancelled)",
			      find.msgid);
			ldap_msgfree(result);
			continue;
		}

		/*
		 *	Remove the query from the tree of outstanding queries
		 */
		fr_rb_remove(ldap_conn->queries, query);

		/*
		 *	Add the query to the list of queries referencing this connection.
		 *	Prevents the connection from being freed until the query has finished using it.
		 */
		fr_dlist_insert_tail(&ldap_conn->refs, query);

		/*
		 *	This really shouldn't happen - as we only retrieve complete sets of results -
		 *	but as the query data structure will last until its results are fully handled
		 *	better to have this safety check here.
		 */
		if (query->ret != LDAP_RESULT_PENDING) {
			WARN("Received results for msgid %i which has already been handled - ignoring", find.msgid);
			ldap_msgfree(result);
			continue;
		}

		msgtype = ldap_msgtype(result);

		/*
		 *	Request to reference in debug output
		 */
		request = query->treq->request;

		ROPTIONAL(RDEBUG2, DEBUG2, "Got %s response for message %d",
			  ldap_msg_types[msgtype], query->msgid);
		rcode = fr_ldap_error_check(NULL, ldap_conn, result, query->dn);

		switch (rcode) {
		case LDAP_PROC_SUCCESS:
			switch (query->type) {
			case LDAP_REQUEST_SEARCH:
				query->ret = (ldap_count_entries(ldap_conn->handle, result) == 0) ?
						LDAP_RESULT_NO_RESULT : LDAP_RESULT_SUCCESS;
				break;

			default:
				query->ret = LDAP_RESULT_SUCCESS;
				break;
			}
			break;

		case LDAP_PROC_REFERRAL:
			if (!ttrunk->t->config->chase_referrals) {
				ROPTIONAL(REDEBUG, ERROR,
					  "LDAP referral received but 'chase_referrals' is set to 'no'");
				query->ret = LDAP_RESULT_EXCESS_REFERRALS;
				break;
			}

			if (query->referral_depth >= ttrunk->t->config->referral_depth) {
				ROPTIONAL(REDEBUG, ERROR, "Maximum LDAP referral depth (%d) exceeded",
					  ttrunk->t->config->referral_depth);
				query->ret = LDAP_RESULT_EXCESS_REFERRALS;
				break;
			}

			/*
			 *	If we've come here as the result of an existing referral
			 *	clear the previous list of URLs before getting the next list.
			 */
			if (query->referral_urls) ldap_memvfree((void **)query->referral_urls);

			ldap_get_option(ldap_conn->handle, LDAP_OPT_REFERRAL_URLS, &query->referral_urls);
			if (!(query->referral_urls) || (!(query->referral_urls[0]))) {
				ROPTIONAL(REDEBUG, ERROR, "LDAP referral missing referral URL");
				query->ret = LDAP_RESULT_MISSING_REFERRAL;
				break;
			}

			query->referral_depth ++;

			if (fr_ldap_referral_follow(ttrunk->t, request, query) == 0) {
			next_follow:
				ldap_msgfree(result);
				continue;
			}

			ROPTIONAL(REDEBUG, ERROR, "Unable to follow any LDAP referral URLs");
			query->ret = LDAP_RESULT_REFERRAL_FAIL;
			break;

		case LDAP_PROC_BAD_DN:
			ROPTIONAL(RDEBUG2, DEBUG2, "DN %s does not exist", query->dn);
			query->ret = LDAP_RESULT_BAD_DN;
			break;

		default:
			ROPTIONAL(RPERROR, PERROR, "LDAP server returned an error");

			if (query->referral_depth > 0) {
				/*
				 *	We're processing a referral - see if there are any more to try
				 */
				fr_dlist_talloc_free_item(&query->referrals, query->referral);
				query->referral = NULL;

				if ((fr_dlist_num_elements(&query->referrals) > 0) &&
				    (fr_ldap_referral_next(ttrunk->t, request, query) == 0)) goto next_follow;
			}

			query->ret = LDAP_RESULT_REFERRAL_FAIL;
			break;
		}

		/*
		 *	Remove the timeout event
		 */
		if (query->ev) fr_event_timer_delete(&query->ev);

		query->result = result;

		/*
		 *	If we have a specific parser to handle the result, call it
		 */
		if (query->parser && (rcode == LDAP_PROC_SUCCESS)) query->parser(ldap_conn->handle, query,
										 result, query->treq->rctx);

		/*
		 *	Set the request as runnable
		 */
		if (request) unlang_interpret_mark_runnable(request);

		/*
		 *	If referral following failed, there is no active trunk request.
		 */
		if (!query->treq) continue;

		/*
		 *	If the query is parented off the treq then it will be freed when
		 *	the request is completed.  If it is parented by something else then it will not.
		 */
		treq = query->treq;
		query->treq = NULL;
		fr_trunk_request_signal_complete(treq);
	} while (1);
}

static int _thread_ldap_trunk_free(fr_ldap_thread_trunk_t *ttrunk)
{
	if (ttrunk->t && fr_rb_node_inline_in_tree(&ttrunk->node)) fr_rb_remove(ttrunk->t->trunks, ttrunk);

	return 0;
}

/** Find a thread specific LDAP connection for a specific URI / bind DN
 *
 * If no existing connection exists for that combination then create a new one
 *
 * @param[in] thread		to which the connection belongs
 * @param[in] uri		of the host to find / create a connection to
 * @param[in] bind_dn		to make the connection as
 * @param[in] bind_password	for making connection
 * @param[in] request		currently being processed (only for debug messages)
 * @param[in] config		LDAP config of the module requesting the connection.
 * @return
 *	- an existing or new connection matching the URI and bind DN
 *	- NULL on failure
 */
fr_ldap_thread_trunk_t *fr_thread_ldap_trunk_get(fr_ldap_thread_t *thread, char const *uri,
						 char const *bind_dn, char const *bind_password,
						 request_t *request, fr_ldap_config_t const *config)
{
	fr_ldap_thread_trunk_t	*found, find = {.uri = uri, .bind_dn = bind_dn};

	ROPTIONAL(RDEBUG2, DEBUG2, "Looking for LDAP connection to \"%s\" bound as \"%s\"", uri,
		 bind_dn ? bind_dn : "(anonymous)");
	found = fr_rb_find(thread->trunks, &find);

	if (found) return found;

	/*
	 *	No existing connection matching the requirement - create a new one
	 */
	ROPTIONAL(RDEBUG2, DEBUG2, "No existing connection found - creating new one");
	found = talloc_zero(thread, fr_ldap_thread_trunk_t);
	talloc_set_destructor(found, _thread_ldap_trunk_free);

	/*
	 *	Buld config for this connection - start with module settings and
	 *	override server and bind details
	 */
	memcpy(&found->config, config, sizeof(fr_ldap_config_t));
	found->config.server = talloc_strdup(found, uri);
	found->config.admin_identity = talloc_strdup(found, bind_dn);
	found->config.admin_password = talloc_strdup(found, bind_password);

	found->uri = found->config.server;
	found->bind_dn = found->config.admin_identity;

	found->trunk = fr_trunk_alloc(found, thread->el,
				      &(fr_trunk_io_funcs_t){
					      .connection_alloc = ldap_trunk_connection_alloc,
					      .connection_notify = ldap_trunk_connection_notify,
					      .request_mux = ldap_trunk_request_mux,
					      .request_demux = ldap_trunk_request_demux,
					      .request_cancel = ldap_request_cancel,
					      .request_cancel_mux = ldap_request_cancel_mux
					},
				      thread->trunk_conf,
				      "rlm_ldap", found, false);

	if (!found->trunk) {
	error:
		ROPTIONAL(REDEBUG, ERROR, "Unable to create LDAP connection");
		talloc_free(found);
		return NULL;
	}

	found->t = thread;

	/*
	 *  Insert event to close trunk if it becomes idle
	 */
	if (!fr_cond_assert_msg(fr_event_timer_in(found, thread->el, &found->ev, thread->config->idle_timeout,
						  _ldap_trunk_idle_timeout, found) == 0, "cannot insert trunk idle event")) goto error;

	/*
	 *	Attempt to discover what type directory we are talking to
	 */
	if (fr_ldap_trunk_directory_alloc_async(found, found) < 0) goto error;

	fr_rb_insert(thread->trunks, found);

	return found;
}

/** Lookup the state of a thread specific LDAP connection trunk for a specific URI / bind DN
 *
 * @param[in] thread		to which the connection belongs
 * @param[in] uri		of the host to find / create a connection to
 * @param[in] bind_dn		to make the connection as
 * @return
 *	- State of a trunk matching the URI and bind DN
 *	- FR_TRUNK_STATE_MAX if no matching trunk
 */
fr_trunk_state_t fr_thread_ldap_trunk_state(fr_ldap_thread_t *thread, char const *uri, char const *bind_dn)
{
	fr_ldap_thread_trunk_t	*found, find = {.uri = uri, .bind_dn = bind_dn};

	found = fr_rb_find(thread->trunks, &find);

	return (found) ? found->trunk->state : FR_TRUNK_STATE_MAX;
}

/** Free LDAP bind auth ctx when trunk request is "freed" with fr_trunk_request_free()
 *
 */
static void ldap_trunk_bind_auth_free(UNUSED request_t *request, void *preq_to_free, UNUSED void *uctx)
{
	fr_ldap_bind_auth_ctx_t *bind = talloc_get_type_abort(preq_to_free, fr_ldap_bind_auth_ctx_t);

	talloc_free(bind);
}

/** Take pending LDAP bind auths from the queue and send them.
 *
 * @param[in] el	Event list for timers.
 * @param[in] tconn	Trunk handle.
 * @param[in] conn	on which to send the queries
 * @param[in] uctx	User context passed to fr_trunk_alloc
 */
static void ldap_trunk_bind_auth_mux(UNUSED fr_event_list_t *el, fr_trunk_connection_t *tconn,
				   fr_connection_t *conn, void *uctx)
{
	fr_ldap_connection_t	*ldap_conn = talloc_get_type_abort(conn->h, fr_ldap_connection_t);
	fr_ldap_thread_trunk_t	*ttrunk = talloc_get_type_abort(uctx, fr_ldap_thread_trunk_t);
	fr_ldap_thread_t	*thread = ttrunk->t;
	fr_trunk_request_t	*treq;

	fr_ldap_bind_auth_ctx_t	*bind = NULL;
	int			ret = 0;
	struct berval		cred;
	request_t		*request;

	if (fr_trunk_connection_pop_request(&treq, tconn) != 0) return;

	/* Pacify clang scan */
	if (!treq) return;

	bind = talloc_get_type_abort(treq->preq, fr_ldap_bind_auth_ctx_t);
	request = bind->request;

	switch (bind->type) {
	case LDAP_BIND_SIMPLE:
	{
		fr_ldap_bind_ctx_t	*bind_ctx = bind->bind_ctx;

		RDEBUG2("Starting bind auth operation as %s", bind_ctx->bind_dn);

		if (bind_ctx->password) {
			memcpy(&cred.bv_val, &bind_ctx->password, sizeof(cred.bv_val));
			cred.bv_len = talloc_array_length(bind_ctx->password) - 1;
		} else {
			cred.bv_val = NULL;
			cred.bv_len = 0;
		}

		ret = ldap_sasl_bind(ldap_conn->handle, bind_ctx->bind_dn, LDAP_SASL_SIMPLE,
			     	     &cred, NULL, NULL, &bind->msgid);

		switch (ret) {
		case LDAP_SUCCESS:
			fr_rb_insert(thread->binds, bind);
			RDEBUG3("Bind auth sent as LDAP msgid %d", bind->msgid);
			break;

		default:
			bind->ret = LDAP_PROC_ERROR;
			unlang_interpret_mark_runnable(treq->request);
			RERROR("Failed to send bind auth");
			break;
		}
	}
		break;

#ifdef WITH_SASL
	case LDAP_BIND_SASL:
	{
		fr_ldap_sasl_ctx_t	*sasl_ctx = bind->sasl_ctx;

		RDEBUG2("%s SASL bind auth operation as %s", sasl_ctx->rmech ? "Continuing" : "Starting",
			sasl_ctx->identity);

		ret = fr_ldap_sasl_bind_auth_send(sasl_ctx, &bind->msgid, ldap_conn);

		switch (ret) {
		case LDAP_SASL_BIND_IN_PROGRESS:
			/*
			 *	Add the bind to the list of pending binds.
			 */
			fr_rb_insert(thread->binds, bind);
			RDEBUG3("SASL bind auth sent as LDAP msgid %d", bind->msgid);
			break;

		case LDAP_SUCCESS:
			bind->ret = LDAP_PROC_SUCCESS;
			unlang_interpret_mark_runnable(treq->request);
			break;

		default:
			bind->ret = LDAP_PROC_ERROR;
			unlang_interpret_mark_runnable(treq->request);
			RERROR("Failed to send SASL bind auth");
			break;
		}
	}
#endif
		break;
	}
	/*
	 *	The request is marked as sent, to remove from the pending list.
	 *	This is regardless of whether the sending was successful or not as
	 *	the different states are handled by the resume function which then
	 *	marks the request as complete triggering the tidy up.
	 */
	fr_trunk_request_signal_sent(treq);
}

/** Read LDAP bind auth responses
 *
 * @param[in] el	To insert timers into.
 * @param[in] tconn	Trunk connection associated with these results.
 * @param[in] conn	Connection handle for these results.
 * @param[in] uctx	Thread specific trunk structure - contains tree of pending queries.
 */
static void ldap_trunk_bind_auth_demux(UNUSED fr_event_list_t *el, UNUSED fr_trunk_connection_t *tconn,
				       fr_connection_t *conn, void *uctx)
{
	fr_ldap_connection_t	*ldap_conn = talloc_get_type_abort(conn->h, fr_ldap_connection_t);
	fr_ldap_thread_trunk_t	*ttrunk = talloc_get_type_abort(uctx, fr_ldap_thread_trunk_t);
	fr_ldap_thread_t	*thread = ttrunk->t;
	fr_ldap_bind_auth_ctx_t	find = { .msgid = -1 }, *bind = NULL;

	int 			ret = 0;
	LDAPMessage		*result = NULL;
	request_t		*request;
	bool			really_no_result = false;

	do {
		/*
		 *	The first time ldap_result is called when there's pending network
		 *	data, it may read the data, but actually return a timeout.
		 *
		 *	In order to fix the spurious debugging messages and overhead,
		 *	if this is the first iteration through the loop and fr_ldap_result
		 *	returns a timeout, we call it again.
		 */
		ret = fr_ldap_result(&result, NULL, ldap_conn, LDAP_RES_ANY, LDAP_MSG_ALL, NULL, fr_time_delta_wrap(10));
		if (ret == LDAP_PROC_TIMEOUT) {
			if (really_no_result) return;
			really_no_result = true;
			continue;
		}

		if (!result) return;

		really_no_result = true;
		find.msgid = ldap_msgid(result);
		bind = fr_rb_find(thread->binds, &find);

		if (!bind) {
			WARN("Ignoring bind result msgid %i - doesn't match any outstanding binds", find.msgid);
			ldap_msgfree(result);
			result = NULL;
			continue;
		}
	} while (!bind);

	/*
	 *	There will only ever be one bind in flight at a time on a given
	 *	connection - so having got a result, no need to loop.
	 */

	fr_rb_remove(thread->binds, bind);
	request = bind->request;
	bind->ret = ret;

	switch (ret) {
	/*
	 *	Accept or reject will be SUCCESS, NOT_PERMITTED or REJECT
	 */
	case LDAP_PROC_NOT_PERMITTED:
	case LDAP_PROC_REJECT:
	case LDAP_PROC_BAD_DN:
	case LDAP_PROC_NO_RESULT:
		break;

	case LDAP_PROC_SUCCESS:
		if (bind->type == LDAP_BIND_SIMPLE) break;

		/*
		 *	With SASL binds, we will be here after ldap_sasl_interactive_bind
		 *	returned LDAP_SASL_BIND_IN_PROGRESS.  That always requires a further
		 *	call of ldap_sasl_interactive_bind to get the final result.
		 */
		bind->ret = LDAP_PROC_CONTINUE;
		FALL_THROUGH;

	case LDAP_PROC_CONTINUE:
	{
		fr_ldap_sasl_ctx_t	*sasl_ctx = bind->sasl_ctx;
		struct berval		*srv_cred;

		/*
		 *	Free any previous result and track the new one.
		 */
		if (sasl_ctx->result) ldap_msgfree(sasl_ctx->result);
		sasl_ctx->result = result;
		result = NULL;

		ret = ldap_parse_sasl_bind_result(ldap_conn->handle, sasl_ctx->result, &srv_cred, 0);
		if (ret != LDAP_SUCCESS) {
			RERROR("SASL decode failed (bind failed): %s", ldap_err2string(ret));
			break;
		}

		if (srv_cred) {
			RDEBUG3("SASL response  : %pV",
				fr_box_strvalue_len(srv_cred->bv_val, srv_cred->bv_len));
			ber_bvfree(srv_cred);
		}

		if (sasl_ctx->rmech) RDEBUG3("Continuing SASL mech %s...", sasl_ctx->rmech);
	}
		break;

	default:
		break;
	}

	ldap_msgfree(result);
	unlang_interpret_mark_runnable(request);
}

/** Callback to cancel LDAP bind auth
 *
 * Inform the remote LDAP server that we no longer want responses to specific bind.
 *
 * @param[in] el	For timer management.
 * @param[in] tconn	The trunk connection handle
 * @param[in] conn	The specific connection binds will be cancelled on
 * @param[in] uctx	Context provided to fr_trunk_alloc
 */
static void ldap_bind_auth_cancel_mux(UNUSED fr_event_list_t *el, fr_trunk_connection_t *tconn,
				    fr_connection_t *conn, UNUSED void *uctx)
{
	fr_trunk_request_t	*treq;
	fr_ldap_connection_t	*ldap_conn = talloc_get_type_abort(conn->h, fr_ldap_connection_t);
	fr_ldap_bind_auth_ctx_t	*bind;

	while ((fr_trunk_connection_pop_cancellation(&treq, tconn)) == 0) {
		bind = talloc_get_type_abort(treq->preq, fr_ldap_bind_auth_ctx_t);
#ifdef WITH_SASL
		if (bind->type == LDAP_BIND_SASL) {
			/*
			 *	With SASL binds, abandoning the bind part way through
			 *	seems to leave the connection in an unpredictable state
			 *	so safer to restart.
			 */
			fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
		} else {
#endif
			ldap_abandon_ext(ldap_conn->handle, bind->msgid, NULL, NULL);
#ifdef WITH_SASL
		}
#endif
		fr_trunk_request_signal_cancel_complete(treq);
	}
}

/** Find the thread specific trunk to use for LDAP bind auths
 *
 * If there is no current trunk then a new one is created.
 *
 * @param[in] thread	to which the connection belongs
 * @return
 *	- an existing or new trunk.
 *	- NULL on failure
 */
fr_ldap_thread_trunk_t *fr_thread_ldap_bind_trunk_get(fr_ldap_thread_t *thread)
{
	fr_ldap_thread_trunk_t	*ttrunk;

	if (thread->bind_trunk) return (thread->bind_trunk);

	MEM(ttrunk = talloc_zero(thread, fr_ldap_thread_trunk_t));
	memcpy(&ttrunk->config, thread->config, sizeof(fr_ldap_config_t));

	ttrunk->uri = ttrunk->config.server;
	ttrunk->bind_dn = ttrunk->config.admin_identity;

	ttrunk->trunk = fr_trunk_alloc(ttrunk, thread->el,
				       &(fr_trunk_io_funcs_t){
					      .connection_alloc = ldap_trunk_connection_alloc,
					      .connection_notify = ldap_trunk_connection_notify,
					      .request_mux = ldap_trunk_bind_auth_mux,
					      .request_demux = ldap_trunk_bind_auth_demux,
					      .request_cancel_mux = ldap_bind_auth_cancel_mux,
					      .request_free = ldap_trunk_bind_auth_free
					},
				       thread->bind_trunk_conf,
				       "rlm_ldap bind auth", ttrunk, false);

	if (!ttrunk->trunk) {
		ERROR("Unable to create LDAP connection");
		talloc_free(ttrunk);
		return NULL;
	}

	ttrunk->t = thread;
	thread->bind_trunk = ttrunk;

	return ttrunk;
}
