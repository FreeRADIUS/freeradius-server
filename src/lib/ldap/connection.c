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
#include <freeradius-devel/server/rad_assert.h>

#if LDAP_SET_REBIND_PROC_ARGS == 3
/** Callback for OpenLDAP to rebind and chase referrals
 *
 * Called by OpenLDAP when it receives a referral and has to rebind.
 *
 * @param handle to rebind.
 * @param url to bind to.
 * @param request that triggered the rebind.
 * @param msgid that triggered the rebind.
 * @param ctx fr_ldap configuration.
 */
static int fr_ldap_rebind(LDAP *handle, LDAP_CONST char *url,
			  UNUSED ber_tag_t request, UNUSED ber_int_t msgid, void *ctx)
{
	fr_ldap_rcode_t			status;
	fr_ldap_connection_t			*conn = talloc_get_type_abort(ctx, fr_ldap_connection_t);
	fr_ldap_config_t const	*handle_config = conn->config;

	char const			*admin_identity = NULL;
	char const			*admin_password = NULL;

	int				ldap_errno;

	conn->referred = true;
	conn->rebound = true;	/* not really, but oh well... */
	rad_assert(handle == conn->handle);

	DEBUG("Rebinding to URL %s", url);

#  ifdef HAVE_LDAP_URL_PARSE
	/*
	 *	Use bindname and x-bindpw extensions to get the bind credentials
	 *	SASL mech is inherited from the module that defined the connection
	 *	pool.
	 */
	if (handle_config->use_referral_credentials) {
		LDAPURLDesc	*ldap_url;
		int		ret;
		char		**ext;

		ret = ldap_url_parse(url, &ldap_url);
		if (ret != LDAP_SUCCESS) {
			ERROR("Failed parsing LDAP URL \"%s\": %s", url, ldap_err2string(ret));
			return -1;
		}

		/*
		 *	If there are no extensions, OpenLDAP doesn't
		 *	bother allocating an array.
		 */
		for (ext = ldap_url->lud_exts; ext && *ext; ext++) {
			char const *p;
			bool critical = false;

			p = *ext;

			if (*p == '!') {
				critical = true;
				p++;
			}

			/*
			 *	LDAP Parse URL unescapes the extensions for us
			 */
			switch (fr_table_value_by_substr(fr_ldap_supported_extensions, p, -1, LDAP_EXT_UNSUPPORTED)) {
			case LDAP_EXT_BINDNAME:
				p = strchr(p, '=');
				if (!p) {
				bad_ext:
					ERROR("Failed parsing extension \"%s\": "
					      "No attribute/value delimiter '='", *ext);
					ldap_free_urldesc(ldap_url);
					return LDAP_OTHER;
				}
				admin_identity = p + 1;
				break;

			case LDAP_EXT_BINDPW:
				p = strchr(p, '=');
				if (!p) goto bad_ext;
				admin_password = p + 1;
				break;

			default:
				if (critical) {
					ERROR("Failed parsing critical extension \"%s\": "
					      "Not supported by FreeRADIUS", *ext);
					ldap_free_urldesc(ldap_url);
					return LDAP_OTHER;
				}
				DEBUG2("Skipping unsupported extension \"%s\"", *ext);
				continue;
			}
		}
		ldap_free_urldesc(ldap_url);
	} else
#  endif
	{
		admin_identity = handle_config->admin_identity;
		admin_password = handle_config->admin_password;
	}

	status = fr_ldap_bind(NULL, &conn, admin_identity, admin_password,
			      &conn->config->admin_sasl, 0, NULL, NULL);
	if (status != LDAP_PROC_SUCCESS) {
		ldap_get_option(handle, LDAP_OPT_ERROR_NUMBER, &ldap_errno);

		return ldap_errno;
	}

	return LDAP_SUCCESS;
}
#endif

/** Close and delete a connection
 *
 * Unbinds the LDAP connection, informing the server and freeing any memory, then releases the memory used by the
 * connection handle.
 *
 * @param[in] c		to destroy.
 * @return always indicates success.
 */
static int fr_ldap_connection_reset(fr_ldap_connection_t *c)
{
	talloc_free_children(c);	/* Force inverted free order */

	fr_ldap_control_clear(c);

	if (!c->handle) return 0;	/* Don't need to do anything else if we don't yet have a handle */

#ifdef HAVE_LDAP_UNBIND_EXT_S
	LDAPControl	*our_serverctrls[LDAP_MAX_CONTROLS];
	LDAPControl	*our_clientctrls[LDAP_MAX_CONTROLS];

	fr_ldap_control_merge(our_serverctrls, our_clientctrls,
			      sizeof(our_serverctrls) / sizeof(*our_serverctrls),
			      sizeof(our_clientctrls) / sizeof(*our_clientctrls),
			      c, NULL, NULL);

	DEBUG3("Closing libldap handle %p", c->handle);
	ldap_unbind_ext(c->handle, our_serverctrls, our_clientctrls);	/* Same code as ldap_unbind_ext_s */
#else
	DEBUG3("Closing libldap handle %p", c->handle);
	ldap_unbind(c->handle);						/* Same code as ldap_unbind_s */
#endif
	c->handle = NULL;

	return 0;
}

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
	LDAP				*handle = NULL;
	int				ldap_errno, ldap_version;

	rad_assert(config->server);

	/*
	 *	Puts the handle back into a pristine state
	 *	without leaking memory, but leaves the original
	 *	fr_ldap_connection_t intact.
	 */
	if (c->handle) fr_ldap_connection_reset(c);

#ifdef HAVE_LDAP_INITIALIZE
	ldap_errno = ldap_initialize(&handle, config->server);
	if (ldap_errno != LDAP_SUCCESS) {
		ERROR("ldap_initialize failed: %s", ldap_err2string(ldap_errno));
	error:
		return -1;
	}
#else
	handle = ldap_init(config->server, config->port);
	if (!handle) {
		ERROR("ldap_init failed");
	error:
		return -1;
	}
#endif

	DEBUG3("New libldap handle %p", handle);

	c->config = config;
	c->handle = handle;
	c->rebound = false;
	c->referred = false;

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

#define maybe_ldap_option(_option, _name, _value) \
	if (_value) do_ldap_option(_option, _name, _value)

	/*
	 *	Leave "dereference" unset to use the OpenLDAP default.
	 */
	if (config->dereference_str) do_ldap_option(LDAP_OPT_DEREF, "dereference", &(config->dereference));

	/*
	 *	Leave "chase_referrals" unset to use the OpenLDAP default.
	 */
	if (!config->chase_referrals_unset) {
		if (config->chase_referrals) {
			do_ldap_option(LDAP_OPT_REFERRALS, "chase_referrals", LDAP_OPT_ON);

			if (config->rebind == true) {
#if LDAP_SET_REBIND_PROC_ARGS == 3
				ldap_set_rebind_proc(c->handle, fr_ldap_rebind, c);
#endif
			}
		} else {
			do_ldap_option(LDAP_OPT_REFERRALS, "chase_referrals", LDAP_OPT_OFF);
		}
	}

#ifdef LDAP_OPT_NETWORK_TIMEOUT
	/*
	 *	A value of zero results in an handle configuration failure.
	 *
	 *	When most people specify zero they mean infinite.
	 *
	 *	libldap requires tv_sec to be -1 to mean that.
	 */
	do_ldap_option(LDAP_OPT_NETWORK_TIMEOUT, "net_timeout",
		       (config->net_timeout ? &fr_time_delta_to_timeval(config->net_timeout) :
					      &(struct timeval) { .tv_sec = -1, .tv_usec = 0 }));
#endif

	do_ldap_option(LDAP_OPT_TIMELIMIT, "srv_timelimit", &fr_time_delta_to_timeval(config->srv_timelimit));

	ldap_version = LDAP_VERSION3;
	do_ldap_option(LDAP_OPT_PROTOCOL_VERSION, "ldap_version", &ldap_version);

#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	do_ldap_option(LDAP_OPT_X_KEEPALIVE_IDLE, "keepalive_idle",
		       &fr_time_delta_to_timeval(config->keepalive_idle));
#endif

#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	do_ldap_option(LDAP_OPT_X_KEEPALIVE_PROBES, "keepalive_probes",
		       &fr_time_delta_to_timeval(config->keepalive_probes));
#endif

#ifdef LDAP_OPT_X_KEEPALIVE_INTERVAL
	do_ldap_option(LDAP_OPT_X_KEEPALIVE_INTERVAL, "keepalive_interval",
		       &fr_time_delta_to_timeval(config->keepalive_interval));
#endif

#ifdef HAVE_LDAP_START_TLS_S
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

#  ifdef LDAP_OPT_X_TLS_NEVER
	if (config->tls_require_cert_str) {
		do_ldap_option(LDAP_OPT_X_TLS_REQUIRE_CERT, "require_cert", &config->tls_require_cert);
	}
#  endif

	/*
	 *	Counter intuitively the TLS context appears to need to be initialised
	 *	after all the TLS options are set on the handle.
	 */
#  ifdef LDAP_OPT_X_TLS_NEWCTX
	{
		/* Always use the new TLS configuration context */
		int is_server = 0;
		do_ldap_option(LDAP_OPT_X_TLS_NEWCTX, "new TLS context", &is_server);
	}
#  endif

	if (config->sasl_secprops) do_ldap_option(LDAP_OPT_X_SASL_SECPROPS, "sasl_secprops", config->sasl_secprops);

	if (config->start_tls) {
		if (config->port == 636) {
			WARN("Told to Start TLS on LDAPS port this will probably fail, please correct the "
			     "configuration");
		}
	}
#endif /* HAVE_LDAP_START_TLS_S */

	return 0;
}

/** Close libldap's file descriptor
 *
 * @param[in] fd	to close.
 * @param[in] uctx	Connection config and handle.
 */
static void _ldap_connection_close(UNUSED int fd, void *uctx)
{
	fr_ldap_connection_t	*c = talloc_get_type_abort(uctx, fr_ldap_connection_t);

	INFO("Closing connection");

	fr_ldap_connection_reset(c);
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
 * @param[out] fd_out	Underlying file descriptor from libldap handle.
 * @param[in] uctx	Our LDAP connection handle (a #fr_ldap_connection_t).
 * @return
 *	- FR_CONNECTION_STATE_CONNECTING on success.
 *	- FR_CONNECTION_STATE_FAILED on failure.
 */
static fr_connection_state_t _ldap_connection_init(int *fd_out, void *uctx)
{
	fr_ldap_connection_t	*c = talloc_get_type_abort(uctx, fr_ldap_connection_t);
	fr_ldap_state_t		state;

	*fd_out = -1;	/* We set a real value later */

	/*
	 *	Configure/allocate the libldap handle
	 */
	if (fr_ldap_connection_configure(c, c->config) < 0) return FR_CONNECTION_STATE_FAILED;

	/* Don't block */
	if (ldap_set_option(c->handle, LDAP_OPT_CONNECT_ASYNC, LDAP_OPT_ON) != LDAP_OPT_SUCCESS) {
		return FR_CONNECTION_STATE_FAILED;
	}
	fr_ldap_connection_timeout_set(c, 0);					/* Forces LDAP_X_CONNECTING */

	state = fr_ldap_state_next(c);
	if (state == FR_LDAP_STATE_ERROR) return FR_CONNECTION_STATE_FAILED;

	return FR_CONNECTION_STATE_CONNECTING;
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

	talloc_set_destructor(c, fr_ldap_connection_reset);

	return c;
}

/** Alloc a self re-establishing connection to an LDAP server
 *
 * @param[in] ctx		to allocate any memory in, and to bind the lifetime of the connection to.
 * @param[in] el		to insert I/O and timer callbacks into.
 * @param[in] config		to use to bind the connection to an LDAP server.
 * @param[in] log_prefix	to prepend to connection state messages.
 */
fr_ldap_connection_t *fr_ldap_connection_state_alloc(TALLOC_CTX *ctx, fr_event_list_t *el,
						     fr_ldap_config_t const *config, char *log_prefix)
{
	fr_ldap_connection_t	*c;

	MEM(c = fr_ldap_connection_alloc(ctx));
	c->config = config;
	c->conn = fr_connection_alloc(c, el,
				      config->net_timeout, config->reconnection_delay,
				      _ldap_connection_init,
				      NULL,
				      _ldap_connection_close,
				      log_prefix, c);
	if (!c->conn) return NULL;

	return c;
}

int fr_ldap_connection_timeout_set(fr_ldap_connection_t const *c, fr_time_delta_t timeout)
{
#ifdef LDAP_OPT_NETWORK_TIMEOUT
	int ldap_errno;

	/*
	 *	A value of zero results in an handle configuration failure.
	 *
	 *	When most people specify zero they mean infinite.
	 *
	 *	libldap requires tv_sec to be -1 to mean that.
	 */
	do_ldap_option(LDAP_OPT_NETWORK_TIMEOUT, "net_timeout",
		       (timeout ? &fr_time_delta_to_timeval(timeout) :
				  &(struct timeval) { .tv_sec = -1, .tv_usec = 0 }));
#endif

	return 0;

error:
	return -1;
}

int fr_ldap_connection_timeout_reset(fr_ldap_connection_t const *c)
{

#ifdef LDAP_OPT_NETWORK_TIMEOUT
	int ldap_errno;

	/*
	 *	A value of zero results in an handle configuration failure.
	 *
	 *	When most people specify zero they mean infinite.
	 *
	 *	libldap requires tv_sec to be -1 to mean that.
	 */
	do_ldap_option(LDAP_OPT_NETWORK_TIMEOUT, "net_timeout",
		       (c->config->net_timeout ? &fr_time_delta_to_timeval(c->config->net_timeout) :
						 &(struct timeval) { .tv_sec = -1, .tv_usec = 0 }));
#endif

	return 0;

error:
	return -1;
}
