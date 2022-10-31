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
 * @file lib/ldap/base.c
 * @brief LDAP module library functions.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013-2015 Network RADIUS SARL (legal@networkradius.com)
 * @copyright 2013-2015 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/util/debug.h>

#define LOG_PREFIX handle_config->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/ldap/base.h>
#include <freeradius-devel/unlang/function.h>

LDAP *ldap_global_handle;			//!< Hack for OpenLDAP libldap global initialisation.

static _Thread_local LDAP *ldap_thread_local_handle;	//!< Hack for functions which require an ldap handle
						///< but don't actually use it for anything.

/** Used to set the global log prefix for functions which don't operate on connections
 *
 */
static fr_ldap_config_t ldap_global_handle_config = {
	.name = "global"
};

fr_table_num_sorted_t const fr_ldap_connection_states[] = {
	{ L("bind"),		FR_LDAP_STATE_BIND	},
	{ L("error"),		FR_LDAP_STATE_ERROR	},
	{ L("init"),		FR_LDAP_STATE_INIT	},
	{ L("run"),		FR_LDAP_STATE_RUN	},
	{ L("start-tls"),	FR_LDAP_STATE_START_TLS	}
};
size_t fr_ldap_connection_states_len = NUM_ELEMENTS(fr_ldap_connection_states);

fr_table_num_sorted_t const fr_ldap_supported_extensions[] = {
	{ L("bindname"),	LDAP_EXT_BINDNAME	},
	{ L("x-bindpw"),	LDAP_EXT_BINDPW		}
};
size_t fr_ldap_supported_extensions_len = NUM_ELEMENTS(fr_ldap_supported_extensions);

/*
 *	Scopes
 */
fr_table_num_sorted_t const fr_ldap_scope[] = {
	{ L("base"),		LDAP_SCOPE_BASE },
	{ L("children"),	LDAP_SCOPE_CHILDREN },
	{ L("one"),		LDAP_SCOPE_ONE	},
	{ L("sub"),		LDAP_SCOPE_SUB	}
};
size_t fr_ldap_scope_len = NUM_ELEMENTS(fr_ldap_scope);

fr_table_num_sorted_t const fr_ldap_tls_require_cert[] = {
	{ L("allow"),		LDAP_OPT_X_TLS_ALLOW	},
	{ L("demand"),		LDAP_OPT_X_TLS_DEMAND	},
	{ L("hard"),		LDAP_OPT_X_TLS_HARD	},
	{ L("never"),		LDAP_OPT_X_TLS_NEVER	},
	{ L("try"),		LDAP_OPT_X_TLS_TRY	}
};
size_t fr_ldap_tls_require_cert_len = NUM_ELEMENTS(fr_ldap_tls_require_cert);

fr_table_num_sorted_t const fr_ldap_dereference[] = {
	{ L("always"),		LDAP_DEREF_ALWAYS	},
	{ L("finding"),		LDAP_DEREF_FINDING	},
	{ L("never"),		LDAP_DEREF_NEVER	},
	{ L("searching"),	LDAP_DEREF_SEARCHING	}
};
size_t fr_ldap_dereference_len = NUM_ELEMENTS(fr_ldap_dereference);

static fr_libldap_global_config_t libldap_global_config = {
	.ldap_debug = 0x00,
	.tls_random_file = ""
};

static CONF_PARSER const ldap_global_config[] = {
	{ FR_CONF_OFFSET("random_file", FR_TYPE_FILE_EXISTS, fr_libldap_global_config_t, tls_random_file) },
	{ FR_CONF_OFFSET("ldap_debug", FR_TYPE_UINT32, fr_libldap_global_config_t, ldap_debug), .dflt = "0x0000" },
	CONF_PARSER_TERMINATOR
};

/** Initialise libldap library and set global options
 *
 * Used as a callback from global library initialisation.
 */
static int libldap_init(void)
{
	if (fr_ldap_init() < 0) return -1;

	fr_ldap_global_config(libldap_global_config.ldap_debug, libldap_global_config.tls_random_file);

	return 0;
}

/** Free any global libldap resources
 *
 */
static void libldap_free(void)
{
	/*
	 *	Keeping the dummy ld around for the lifetime
	 *	of the module should always work,
	 *	irrespective of what changes happen in libldap.
	 */
	ldap_unbind_ext_s(ldap_global_handle, NULL, NULL);
}

/*
 *	Public symbol modules can reference to auto instantiate libldap
 */
global_lib_autoinst_t fr_libldap_global_config = {
	 .name = "ldap",
	 .config = (const CONF_PARSER *)ldap_global_config,
	 .inst = &libldap_global_config,
	 .init = libldap_init,
	 .free = libldap_free
};

typedef struct {
	fr_ldap_query_t	*query;
	LDAPMessage	**result;
} sync_ldap_query_t;

/** Prints information to the debug log on the current timeout settings
 *
 * There are so many different timers in LDAP it's often hard to debug
 * issues with them, hence the need for this function.
 */
void fr_ldap_timeout_debug(request_t *request, fr_ldap_connection_t const *conn,
			   fr_time_delta_t timeout, char const *prefix)
{
	struct timeval 			*net = NULL, *client = NULL;
	int				server = 0;
	fr_ldap_config_t const	*handle_config = conn->config;

	if (request) RINDENT();

	if (ldap_get_option(conn->handle, LDAP_OPT_NETWORK_TIMEOUT, &net) != LDAP_OPT_SUCCESS) {
		ROPTIONAL(REDEBUG, ERROR, "Failed getting LDAP_OPT_NETWORK_TIMEOUT");
	}

	if (ldap_get_option(conn->handle, LDAP_OPT_TIMEOUT, &client) != LDAP_OPT_SUCCESS) {
		ROPTIONAL(REDEBUG, ERROR, "Failed getting LDAP_OPT_TIMEOUT");
	}

	if (ldap_get_option(conn->handle, LDAP_OPT_TIMELIMIT, &server) != LDAP_OPT_SUCCESS) {
		ROPTIONAL(REDEBUG, ERROR, "Failed getting LDAP_OPT_TIMELIMIT");
	}

	ROPTIONAL(RDEBUG4, DEBUG4, "%s: Timeout settings", prefix);

	if (fr_time_delta_ispos(timeout)) {
		ROPTIONAL(RDEBUG4, DEBUG4, "Client side result timeout (ovr): %pVs",
			  fr_box_time_delta(timeout));
	} else {
		ROPTIONAL(RDEBUG4, DEBUG4, "Client side result timeout (ovr): unset");
	}

	if (client && (client->tv_sec != -1)) {
		ROPTIONAL(RDEBUG4, DEBUG4, "Client side result timeout (dfl): %pVs",
			  fr_box_time_delta(fr_time_delta_from_timeval(client)));

	} else {
		ROPTIONAL(RDEBUG4, DEBUG4, "Client side result timeout (dfl): unset");
	}

	if (net && (net->tv_sec != -1)) {
		ROPTIONAL(RDEBUG4, DEBUG4, "Client side network I/O timeout : %pVs",
			  fr_box_time_delta(fr_time_delta_from_timeval(net)));
	} else {
		ROPTIONAL(RDEBUG4, DEBUG4, "Client side network I/O timeout : unset");

	}

	ROPTIONAL(RDEBUG4, DEBUG4, "Server side result timeout      : %i", server);
	if (request) REXDENT();

	free(net);
	free(client);
}

/** Return the error string associated with a handle
 *
 * @param conn to retrieve error from.
 * @return error string.
 */
char const *fr_ldap_error_str(fr_ldap_connection_t const *conn)
{
	int lib_errno;
	ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE, &lib_errno);
	if (lib_errno == LDAP_SUCCESS) {
		return "unknown";
	}

	return ldap_err2string(lib_errno);
}

/** Perform basic parsing of multiple types of messages, checking for error conditions
 *
 * @note Error messages should be retrieved with fr_strerror() and fr_strerror_pop()
 *
 * @param[out] ctrls	Server ctrls returned to the client.  May be NULL if not required.
 *			Must be freed with ldap_free_ctrls.
 * @param[in] conn	the message was received on.
 * @param[in] msg	we're parsing.
 * @param[in] dn	if processing the result from a search request.
 * @return One of the LDAP_PROC_* (#fr_ldap_rcode_t) values.
 */
fr_ldap_rcode_t fr_ldap_error_check(LDAPControl ***ctrls, fr_ldap_connection_t const *conn, LDAPMessage *msg, char const *dn)
{
	fr_ldap_rcode_t status = LDAP_PROC_SUCCESS;

	int msg_type;
	int lib_errno = LDAP_SUCCESS;	/* errno returned by the library */
	int srv_errno = LDAP_SUCCESS;	/* errno in the result message */

	char *part_dn = NULL;		/* Partial DN match */
	char *srv_err = NULL;		/* Server's extended error message */

	ssize_t len;

	if (ctrls) *ctrls = NULL;

	if (!msg) {
		ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE, &lib_errno);
		if (lib_errno != LDAP_SUCCESS) goto process_error;

		fr_strerror_const("No result available");
		return LDAP_PROC_NO_RESULT;
	}

	msg_type = ldap_msgtype(msg);
	switch (msg_type) {
	/*
	 *	Parse the result and check for errors sent by the server
	 */
	case LDAP_RES_SEARCH_RESULT:	/* The result of a search */
	case LDAP_RES_BIND:		/* The result of a bind operation */
	case LDAP_RES_EXTENDED:
		lib_errno = ldap_parse_result(conn->handle, msg,
					      &srv_errno, &part_dn, &srv_err,
					      NULL, ctrls, 0);
		break;

	/*
	 *	These are messages containing objects so unless they're
	 *	malformed they can't contain errors.
	 */
	case LDAP_RES_SEARCH_ENTRY:
		if (ctrls) lib_errno = ldap_get_entry_controls(conn->handle, msg, ctrls);
		break;

	/*
	 *	Retrieve the controls if the message is a reference message
	 */
	case LDAP_RES_SEARCH_REFERENCE:
		if (ctrls) lib_errno = ldap_parse_reference(conn->handle, msg, NULL, ctrls, 0);
		break;

	/*
	 *	An intermediate message updating us on the result of an operation
	 */
	case LDAP_RES_INTERMEDIATE:
		lib_errno = ldap_parse_intermediate(conn->handle, msg, NULL, NULL, ctrls, 0);
		break;

	/*
	 *	Can't extract any more useful information.
	 */
	default:
		return LDAP_PROC_SUCCESS;
	}

	/*
	 *	Stupid messy API
	 */
	if (lib_errno != LDAP_SUCCESS) {
		fr_assert(!ctrls || !*ctrls);
		ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE, &lib_errno);
	}

process_error:
	if ((lib_errno == LDAP_SUCCESS) && (srv_errno != LDAP_SUCCESS)) {
		lib_errno = srv_errno;
	} else if ((lib_errno != LDAP_SUCCESS) && (srv_errno == LDAP_SUCCESS)) {
		srv_errno = lib_errno;
	}

	switch (lib_errno) {
	case LDAP_SUCCESS:
		fr_strerror_const("Success");
		break;

	case LDAP_REFERRAL:
		fr_strerror_const("Referral");
		status = LDAP_PROC_REFERRAL;
		break;

	case LDAP_SASL_BIND_IN_PROGRESS:
		fr_strerror_const("Continuing");
		status = LDAP_PROC_CONTINUE;
		break;

	case LDAP_NO_SUCH_OBJECT:
		fr_strerror_const("The specified DN wasn't found");
		status = LDAP_PROC_BAD_DN;

		/*
		 *	Build our own internal diagnostic string
		 */
		if (dn && part_dn) {
			char *spaces;
			char *text;

			len = fr_ldap_common_dn(dn, part_dn);
			if (len < 0) break;

			fr_canonicalize_error(NULL, &spaces, &text, -len, dn);
			fr_strerror_printf_push("%s", text);
			fr_strerror_printf_push("%s^ %s", spaces, "match stopped here");

			talloc_free(spaces);
			talloc_free(text);
		}
		goto error_string;

	case LDAP_INSUFFICIENT_ACCESS:
		fr_strerror_const("Insufficient access. Check the identity and password configuration directives");
		status = LDAP_PROC_NOT_PERMITTED;
		break;

	case LDAP_UNWILLING_TO_PERFORM:
		fr_strerror_const("Server was unwilling to perform");
		status = LDAP_PROC_NOT_PERMITTED;
		break;

	case LDAP_FILTER_ERROR:
		fr_strerror_const("Bad search filter");
		status = LDAP_PROC_ERROR;
		break;

	case LDAP_TIMEOUT:
		fr_strerror_const("Timed out while waiting for server to respond");
		status = LDAP_PROC_TIMEOUT;
		break;

	case LDAP_TIMELIMIT_EXCEEDED:
		fr_strerror_const("Time limit exceeded");
		status = LDAP_PROC_TIMEOUT;
		break;

	case LDAP_SYNC_REFRESH_REQUIRED:
		fr_strerror_const("Refresh required");
		status = LDAP_PROC_REFRESH_REQUIRED;
		break;

	case LDAP_BUSY:
	case LDAP_UNAVAILABLE:
	case LDAP_SERVER_DOWN:
		status = LDAP_PROC_BAD_CONN;
		goto error_string;

	case LDAP_INVALID_CREDENTIALS:
	case LDAP_CONSTRAINT_VIOLATION:
		status = LDAP_PROC_REJECT;
		goto error_string;

	case LDAP_OPERATIONS_ERROR:
		fr_strerror_printf("Please set 'chase_referrals=yes' and 'rebind=yes'. "
				   "See the ldap module configuration for details");
		FALL_THROUGH;

	default:
		status = LDAP_PROC_ERROR;

	error_string:
		if (lib_errno == srv_errno) {
			fr_strerror_printf("lib error: %s (%u)", ldap_err2string(lib_errno), lib_errno);
		} else {
			fr_strerror_printf("lib error: %s (%u), srv error: %s (%u)",
					   ldap_err2string(lib_errno), lib_errno,
					   ldap_err2string(srv_errno), srv_errno);
		}

		if (srv_err) fr_strerror_printf_push("Server said: %s", srv_err);

		break;
	}

	/*
	 *	Cleanup memory
	 */
	if (srv_err) ldap_memfree(srv_err);
	if (part_dn) ldap_memfree(part_dn);

	return status;
}

/** Parse response from LDAP server dealing with any errors
 *
 * Should be called after an LDAP operation. Will check result of operation and if
 * it was successful, then attempt to retrieve and parse the result.  Will also produce
 * extended error output including any messages the server sent, and information about
 * partial DN matches.
 *
 * @note Error messages should be retrieved with fr_strerror() and fr_strerror_pop()
 *
 * @param[out] result	Where to write result, if NULL result will be freed.  If not NULL caller
 *			must free with ldap_msgfree().
 * @param[out] ctrls	Server ctrls returned to the client.  May be NULL if not required.
 *			Must be freed with ldap_free_ctrls.
 * @param[in] conn	Current connection.
 * @param[in] msgid	returned from last operation.
 *			Special values are:
 *			- LDAP_RES_ANY - Retrieve any received messages useful for multiplexing.
 * 			- LDAP_RES_UNSOLICITED - Any unsolicited message.
 * @param[in] all	How many messages to retrieve:
 *			- LDAP_MSG_ONE - Retrieve the first message matching msgid (waiting if one is not available).
 *			- LDAP_MSG_ALL - Retrieve all received messages matching msgid (waiting if none are available).
 *			- LDAP_MSG_RECEIVED - Retrieve all received messages.
 * @param[in] dn	Last search or bind DN.  May be NULL.
 * @param[in] timeout	Override the default result timeout.
 *
 * @return One of the LDAP_PROC_* (#fr_ldap_rcode_t) values.
 */
fr_ldap_rcode_t fr_ldap_result(LDAPMessage **result, LDAPControl ***ctrls,
			       fr_ldap_connection_t const *conn, int msgid, int all,
			       char const *dn,
			       fr_time_delta_t timeout)
{
	fr_ldap_rcode_t	status = LDAP_PROC_SUCCESS;
	int		lib_errno;
	fr_time_delta_t	our_timeout = timeout;

	LDAPMessage	*tmp_msg = NULL, *msg;	/* Temporary message pointer storage if we weren't provided with one */
	LDAPMessage	**result_p = result;

	if (result) *result = NULL;
	if (ctrls) *ctrls = NULL;

	/*
	 *	We always need the result, but our caller may not
	 */
	if (!result) result_p = &tmp_msg;

	/*
	 *	Check if there was an error sending the request
	 */
	ldap_get_option(conn->handle, LDAP_OPT_RESULT_CODE, &lib_errno);
	if (lib_errno != LDAP_SUCCESS) return fr_ldap_error_check(NULL, conn, NULL, dn);

	if (!fr_time_delta_ispos(timeout)) our_timeout = conn->config->res_timeout;

	/*
	 *	Now retrieve the result and check for errors
	 *	ldap_result returns -1 on failure, and 0 on timeout
	 */
	lib_errno = ldap_result(conn->handle, msgid, all, &fr_time_delta_to_timeval(our_timeout), result_p);
	switch (lib_errno) {
	case 0:
		lib_errno = LDAP_TIMEOUT;
		fr_strerror_const("timeout waiting for result");
		return LDAP_PROC_TIMEOUT;

	case -1:
		return fr_ldap_error_check(NULL, conn, NULL, dn);

	default:
		break;
	}

	for (msg = ldap_first_message(conn->handle, *result_p);
	     msg;
	     msg = ldap_next_message(conn->handle, msg)) {
		status = fr_ldap_error_check(ctrls, conn, msg, dn);
		if (status != LDAP_PROC_SUCCESS) break;
	}

	if (*result_p && (!result)) {
		ldap_msgfree(*result_p);
		*result_p = NULL;
	}

	return status;
}

/** Search for something in the LDAP directory
 *
 * Binds as the administrative user and performs a search, dealing with any errors.
 *
 * @param[out] msgid		to match response to request.
 * @param[in] request		Current request.
 * @param[in,out] pconn		to use. May change as this function calls functions which auto re-connect.
 * @param[in] dn		to use as base for the search.
 * @param[in] scope		to use (LDAP_SCOPE_BASE, LDAP_SCOPE_ONE, LDAP_SCOPE_SUB).
 * @param[in] filter		to use, should be pre-escaped.
 * @param[in] attrs		to retrieve.
 * @param[in] serverctrls	Search controls to pass to the server.  May be NULL.
 * @param[in] clientctrls	Search controls for ldap_search.  May be NULL.
 * @return One of the LDAP_PROC_* (#fr_ldap_rcode_t) values.
 */
fr_ldap_rcode_t fr_ldap_search_async(int *msgid, request_t *request,
				     fr_ldap_connection_t **pconn,
				     char const *dn, int scope, char const *filter, char const * const *attrs,
				     LDAPControl **serverctrls, LDAPControl **clientctrls)
{
	fr_ldap_config_t const	*handle_config = (*pconn)->config;

	struct timeval			tv;		// Holds timeout values.

	LDAPControl			*our_serverctrls[LDAP_MAX_CONTROLS];
	LDAPControl			*our_clientctrls[LDAP_MAX_CONTROLS];

	char **search_attrs;

	fr_ldap_control_merge(our_serverctrls, our_clientctrls,
			      NUM_ELEMENTS(our_serverctrls),
			      NUM_ELEMENTS(our_clientctrls),
			      *pconn, serverctrls, clientctrls);

	fr_assert(*pconn && (*pconn)->handle);

	if (DEBUG_ENABLED4 || (request && RDEBUG_ENABLED4)) {
		fr_ldap_timeout_debug(request, *pconn, fr_time_delta_wrap(0), __FUNCTION__);
	}

	/*
	 *	OpenLDAP library doesn't declare attrs array as const, but
	 *	it really should be *sigh*.
	 */
	memcpy(&search_attrs, &attrs, sizeof(attrs));

	if (filter) {
		ROPTIONAL(RDEBUG2, DEBUG2, "Performing search in \"%s\" with filter \"%s\", scope \"%s\"", dn, filter,
			  fr_table_str_by_value(fr_ldap_scope, scope, "<INVALID>"));
	} else {
		ROPTIONAL(RDEBUG2, DEBUG2, "Performing unfiltered search in \"%s\", scope \"%s\"", dn,
			  fr_table_str_by_value(fr_ldap_scope, scope, "<INVALID>"));
	}
	/*
	 *	If LDAP search produced an error it should also be logged
	 *	to the ld. result should pick it up without us
	 *	having to pass it explicitly.
	 */
	memset(&tv, 0, sizeof(tv));

	if (ldap_search_ext((*pconn)->handle, dn, scope, filter, search_attrs,
			    0, our_serverctrls, our_clientctrls, NULL, 0, msgid) != LDAP_SUCCESS) {
		int ldap_errno;

		ldap_get_option((*pconn)->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		ERROR("Failed performing search: %s", ldap_err2string(ldap_errno));

		return LDAP_PROC_ERROR;
	}

	return LDAP_PROC_SUCCESS;
}

/** Handle the return code from parsed LDAP results to set the module rcode
 *
 */
static unlang_action_t ldap_trunk_query_results(rlm_rcode_t *p_result, UNUSED int *priority,
						UNUSED request_t *request, void *uctx)
{
	fr_ldap_query_t		*query = talloc_get_type_abort(uctx, fr_ldap_query_t);

	switch (query->ret) {
	case LDAP_RESULT_PENDING:
		/* The query we want hasn't returned yet */
		return UNLANG_ACTION_YIELD;

	case LDAP_RESULT_SUCCESS:
		RETURN_MODULE_OK;

	case LDAP_RESULT_BAD_DN:
	case LDAP_RESULT_NO_RESULT:
		RETURN_MODULE_NOTFOUND;

	default:
		RETURN_MODULE_FAIL;
	}
}

/** Signal an LDAP query running on a trunk connection to cancel
 *
 */
static void ldap_trunk_query_cancel(UNUSED request_t *request, fr_state_signal_t action, void *uctx)
{
	fr_ldap_query_t	*query = talloc_get_type_abort(uctx, fr_ldap_query_t);

	if (action != FR_SIGNAL_CANCEL) return;
	/*
	 *	Query may have completed, but the request
	 *	not yet have been resumed.
	 */
	if (!query->treq) return;

	fr_trunk_request_signal_cancel(query->treq);

	/*
	 *	Once we've called cancel, the treq is no
	 *	longer ours to manipulate, it belongs to
	 *	the trunk code.
	 */
	query->treq = NULL;

}

#define SET_LDAP_CTRLS(_dest, _src) \
do { \
	int i; \
	if (!_src) break; \
	for (i = 0; i < LDAP_MAX_CONTROLS; i++) { \
		if (!(_src[i])) break; \
		_dest[i].control = _src[i]; \
	} \
} while (0)


/** Hack to make code work with synchronous interpreter
 *
 */
static unlang_action_t ldap_trunk_query_start(UNUSED rlm_rcode_t *p_result, UNUSED int *priority,
					      UNUSED request_t *request, UNUSED void *uctx)
{
	return UNLANG_ACTION_YIELD;
}

/** Hack to add timeouts
 *
 * Here we send a cancellation signal to the trunk if the request hits the timeout limit.
 */
static void _ldap_search_sync_timeout(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	ldap_trunk_query_cancel(NULL, FR_SIGNAL_CANCEL, uctx);
}

/** Run an async or sync search LDAP query on a trunk connection
 *
 * @param[out] p_result		from synchronous evaluation.
 * @param[in] ctx		to allocate the query in.
 * @param[out] out		that has been allocated.
 * @param[in] request		this query relates to.
 * @param[in] ttrunk		to submit the query to.
 * @param[in] base_dn		for the search.
 * @param[in] scope		of the search.
 * @param[in] filter		for the search.
 * @param[in] attrs		to be returned.
 * @param[in] serverctrls	specific to this query.
 * @param[in] clientctrls	specific to this query.
 * @param[in] is_async		If true, will return UNLANG_ACTION_YIELD
 *				and push a search onto the unlang stack
 *				for the current request.
 *				If false, will perform a synchronous search
 *				and provide the result in p_result.
 * @return
 *	- UNLANG_ACTION_FAIL on error.
 *	- UNLANG_ACTION_YIELD on success.
 *	- UNLANG_ACTION_CALCULATE_RESULT if the query was run synchronously.
 */
unlang_action_t fr_ldap_trunk_search(rlm_rcode_t *p_result,
				     TALLOC_CTX *ctx,
				     fr_ldap_query_t **out, request_t *request, fr_ldap_thread_trunk_t *ttrunk,
				     char const *base_dn, int scope, char const *filter, char const * const *attrs,
				     LDAPControl **serverctrls, LDAPControl **clientctrls,
				     bool is_async)
{
	unlang_action_t action;
	fr_ldap_query_t *query;

	query = fr_ldap_search_alloc(ctx, base_dn, scope, filter, attrs, serverctrls, clientctrls);

	switch (fr_trunk_request_enqueue(&query->treq, ttrunk->trunk, request, query, NULL)) {
	case FR_TRUNK_ENQUEUE_OK:
	case FR_TRUNK_ENQUEUE_IN_BACKLOG:
		break;

	default:
	error:
		*p_result = RLM_MODULE_FAIL;
		*out = NULL;
		talloc_free(query);
		return UNLANG_ACTION_FAIL;
	}

	action = unlang_function_push(request, is_async ? NULL : ldap_trunk_query_start, ldap_trunk_query_results,
				      ldap_trunk_query_cancel, is_async ? UNLANG_SUB_FRAME : UNLANG_TOP_FRAME, query);

	if (action == UNLANG_ACTION_FAIL) goto error;

	*out = query;

	/*
	 *	Hack until everything is async
	 */
	if (!is_async) {
		fr_event_timer_t const *ev = NULL;

		fr_time_delta_t timeout = ttrunk->config.res_timeout;

		/*
		 *	Add an event that'll send a cancellation request
		 *	to the request.
		 */
		if (fr_time_delta_ispos(timeout)) {
			if (fr_event_timer_in(ctx, unlang_interpret_event_list(request), &ev, timeout,
					      _ldap_search_sync_timeout, query) < 0) goto error;
		}

		*p_result = unlang_interpret_synchronous(unlang_interpret_event_list(request), request);

		talloc_const_free(ev);	/* If the timer fired this should be NULL */

		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	return UNLANG_ACTION_YIELD;
}

/** Run an async or sync modification LDAP query on a trunk connection
 *
 * @param[out] p_result		from synchronous evaluation.
 * @param[in] ctx		to allocate the query in.
 * @param[out] out		that has been allocated.
 * @param[in] request		this query relates to.
 * @param[in] ttrunk		to submit the query to.
 * @param[in] dn		of the object being modified.
 * @param[in] mods		to be performed.
 * @param[in] serverctrls	specific to this query.
 * @param[in] clientctrls	specific to this query.
 * @param[in] is_async		If true, will return UNLANG_ACTION_YIELD
 *				and push a modify onto the unlang stack
 *				for the current request.
 *				If false, will perform a synchronous search
 *				and provide the result in p_result.
 * @return
 *	- UNLANG_ACTION_FAIL on error.
 *	- UNLANG_ACTION_YIELD on success.
 *	- UNLANG_ACTION_CALCULATE_RESULT if the query was run synchronously.
 */
unlang_action_t fr_ldap_trunk_modify(rlm_rcode_t *p_result,
				     TALLOC_CTX *ctx,
				     fr_ldap_query_t **out, request_t *request, fr_ldap_thread_trunk_t *ttrunk,
				     char const *dn, LDAPMod *mods[],
				     LDAPControl **serverctrls, LDAPControl **clientctrls,
				     bool is_async)
{
	unlang_action_t action;
	fr_ldap_query_t *query;

	query = fr_ldap_modify_alloc(ctx, dn, mods, serverctrls, clientctrls);

	switch (fr_trunk_request_enqueue(&query->treq, ttrunk->trunk, request, query, NULL)) {
	case FR_TRUNK_ENQUEUE_OK:
	case FR_TRUNK_ENQUEUE_IN_BACKLOG:
		break;

	default:
	error:
		*out = NULL;
		*p_result = RLM_MODULE_FAIL;
		talloc_free(query);
		return UNLANG_ACTION_FAIL;
	}

	action = unlang_function_push(request, is_async ? NULL : ldap_trunk_query_start, ldap_trunk_query_results,
				      ldap_trunk_query_cancel, is_async ? UNLANG_SUB_FRAME : UNLANG_TOP_FRAME, query);

	if (action == UNLANG_ACTION_FAIL) goto error;

	*out = query;

	/*
	 *	Hack until everything is async
	 */
	if (!is_async) {
		*p_result = unlang_interpret_synchronous(unlang_interpret_event_list(request), request);
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	return UNLANG_ACTION_YIELD;
}

/** Modify something in the LDAP directory
 *
 * Binds as the administrative user and attempts to modify an LDAP object.
 *
 * @param[in] request		Current request.
 * @param[in,out] pconn		to use. May change as this function calls functions which auto re-connect.
 * @param[in] dn		of the object to modify.
 * @param[in] mods		to make, see 'man ldap_modify' for more information.
 * @param[in] serverctrls	Search controls to pass to the server.  May be NULL.
 * @param[in] clientctrls	Search controls for ldap_modify.  May be NULL.
 * @return One of the LDAP_PROC_* (#fr_ldap_rcode_t) values.
 */
fr_ldap_rcode_t fr_ldap_modify_async(int *msgid, request_t *request, fr_ldap_connection_t **pconn,
				     char const *dn, LDAPMod *mods[],
				     LDAPControl **serverctrls, LDAPControl **clientctrls)
{
	LDAPControl	*our_serverctrls[LDAP_MAX_CONTROLS];
	LDAPControl	*our_clientctrls[LDAP_MAX_CONTROLS];

	fr_ldap_control_merge(our_serverctrls, our_clientctrls,
			      NUM_ELEMENTS(our_serverctrls),
			      NUM_ELEMENTS(our_clientctrls),
			      *pconn, serverctrls, clientctrls);

	fr_assert(*pconn && (*pconn)->handle);

	if (RDEBUG_ENABLED4) fr_ldap_timeout_debug(request, *pconn, fr_time_delta_wrap(0), __FUNCTION__);

	RDEBUG2("Modifying object with DN \"%s\"", dn);
	if(ldap_modify_ext((*pconn)->handle, dn, mods, our_serverctrls, our_clientctrls, msgid) != LDAP_SUCCESS) {
		int ldap_errno;

		ldap_get_option((*pconn)->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		ROPTIONAL(RPEDEBUG, RPERROR, "Failed modifying object %s", ldap_err2string(ldap_errno));

		return LDAP_PROC_ERROR;
	}

	return LDAP_PROC_SUCCESS;
}

/** Free any libldap structures when an fr_ldap_query_t is freed
 *
 * It is also possible that the connection used for this query is now closed,
 * in that instance we free it here.
 */
static int _ldap_query_free(fr_ldap_query_t *query)
{
	int 	i;

	/*
	 *	Remove the query from the tree of outstanding queries
	 */
	if (query->ldap_conn) fr_rb_remove(query->ldap_conn->queries, query);

	/*
	 *	Free any results which were retrieved
	 */
	if (query->result) ldap_msgfree(query->result);

	/*
	 *	Free any server and client controls that need freeing
	 */
	for (i = 0; i < LDAP_MAX_CONTROLS; i++) {
		if (!query->serverctrls[i].control) break;
		if (query->serverctrls[i].freeit) ldap_control_free(query->serverctrls[i].control);
	}

	for (i = 0; i < LDAP_MAX_CONTROLS; i++) {
		if (!query->clientctrls[i].control) break;
		if (query->clientctrls[i].freeit) ldap_control_free(query->clientctrls[i].control);
	}

	/*
	 *	If a URL was parsed, free it.
	 */
	if (query->ldap_url) ldap_free_urldesc(query->ldap_url);

	/*
	 *	If any referrals were followed, the parsed referral URLS should be freed
	 */
	if (query->referral_urls) ldap_memvfree((void **)query->referral_urls);

	fr_dlist_talloc_free(&query->referrals);

	/*
	 *	If the connection this query was using has no pending queries and
	 * 	is no-longer associated with a fr_connection_t then free it
	 */
	if ((query->ldap_conn) && (query->ldap_conn->conn == NULL) &&
	    (fr_rb_num_elements(query->ldap_conn->queries) == 0)) {
		talloc_free(query->ldap_conn);
	}

	return 0;
}

/** Allocate an fr_ldap_query_t, setting the talloc destructor
 *
 */
static inline CC_HINT(always_inline)
fr_ldap_query_t *ldap_query_alloc(TALLOC_CTX *ctx, fr_ldap_request_type_t type)
{
	fr_ldap_query_t	*query;

	MEM(query = talloc_zero(ctx, fr_ldap_query_t));
	talloc_set_destructor(query, _ldap_query_free);

	query->ret = LDAP_RESULT_PENDING;
	query->type = type;

	return query;
}

/** Allocate a new search object
 *
 * @param[in] ctx	to allocate query in.
 */
fr_ldap_query_t *fr_ldap_search_alloc(TALLOC_CTX *ctx,
				      char const *base_dn, int scope, char const *filter, char const * const * attrs,
				      LDAPControl **serverctrls, LDAPControl **clientctrls)
{
	fr_ldap_query_t *query;

	query = ldap_query_alloc(ctx, LDAP_REQUEST_SEARCH);
	query->dn = base_dn;
	query->search.scope = scope;
	query->search.filter = filter;
	query->search.attrs = UNCONST(char const **, attrs);
	SET_LDAP_CTRLS(query->serverctrls, serverctrls);
	SET_LDAP_CTRLS(query->clientctrls, clientctrls);

	return query;
}

fr_ldap_query_t *fr_ldap_modify_alloc(TALLOC_CTX *ctx, char const *dn,
				      LDAPMod *mods[], LDAPControl **serverctrls, LDAPControl **clientctrls)
{
	fr_ldap_query_t *query;

	query = ldap_query_alloc(ctx, LDAP_REQUEST_MODIFY);
	query->dn = dn;
	query->mods = mods;
	SET_LDAP_CTRLS(query->serverctrls, serverctrls);
	SET_LDAP_CTRLS(query->clientctrls, clientctrls);

	return query;
}

static int _ldap_handle_thread_local_free(void *handle)
{
	if (ldap_unbind_ext_s(handle, NULL, NULL) < 0) return -1;
	return 0;
}

/** Get a thread local dummy LDAP handle
 *
 * Many functions in the OpenLDAP API don't actually use the handle
 * for anything other than writing out error codes.
 *
 * This is true for most of the LDAP extensions API functions.
 *
 * This gives us a reusable handle that was can pass to those
 * functions when we don't already have one available.
 */
LDAP *fr_ldap_handle_thread_local(void)
{
	if (!ldap_thread_local_handle) {
		LDAP *handle;

		ldap_initialize(&handle, "");

		fr_atexit_thread_local(ldap_thread_local_handle, _ldap_handle_thread_local_free, handle);
	}

	return ldap_thread_local_handle;
}

/** Change settings global to libldap
 *
 * May only be called once.  Subsequent calls will be ignored.
 *
 * @param[in] debug_level	to enable in libldap.
 * @param[in] tls_random_file	Where OpenSSL gets its randomness.
 */
int fr_ldap_global_config(int debug_level, char const *tls_random_file)
{
	static bool		done_config;
	fr_ldap_config_t	*handle_config = &ldap_global_handle_config;

	if (done_config) return 0;

#define do_ldap_global_option(_option, _name, _value) \
	if (ldap_set_option(NULL, _option, _value) != LDAP_OPT_SUCCESS) { \
		int _ldap_errno; \
		ldap_get_option(NULL, LDAP_OPT_RESULT_CODE, &_ldap_errno); \
		ERROR("Failed setting global option %s: %s", _name, \
			 (_ldap_errno != LDAP_SUCCESS) ? ldap_err2string(_ldap_errno) : "Unknown error"); \
		return -1;\
	}

#define maybe_ldap_global_option(_option, _name, _value) \
	if (_value) do_ldap_global_option(_option, _name, _value)

	if (debug_level) do_ldap_global_option(LDAP_OPT_DEBUG_LEVEL, "ldap_debug", &debug_level);

	/*
	 *	OpenLDAP will error out if we attempt to set
	 *	this on a handle. Presumably it's global in
	 *	OpenSSL too.
	 */
	maybe_ldap_global_option(LDAP_OPT_X_TLS_RANDOM_FILE, "random_file", tls_random_file);

	done_config = true;

	return 0;
}

/** Initialise libldap and check library versions
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_ldap_init(void)
{
	int			ldap_errno;
	static LDAPAPIInfo	info = { .ldapai_info_version = LDAP_API_INFO_VERSION };	/* static to quiet valgrind about this being uninitialised */
	fr_ldap_config_t	*handle_config = &ldap_global_handle_config;

	/*
	 *	Only needs to be done once, prevents races in environment
	 *	initialisation within libldap.
	 *
	 *	See: https://github.com/arr2036/ldapperf/issues/2
	 */
	ldap_initialize(&ldap_global_handle, "");

	if (!ldap_global_handle) {
		ERROR("Failed initialising global LDAP handle");
		return -1;
	}

	ldap_errno = ldap_get_option(NULL, LDAP_OPT_API_INFO, &info);
	if (ldap_errno == LDAP_OPT_SUCCESS) {
		/*
		 *	Don't generate warnings if the compile type vendor name
		 *	is found within the link time vendor name.
		 *
		 *	This allows the server to be built against OpenLDAP but
		 *	run with Symas OpenLDAP.
		 */
		if (strcasestr(info.ldapai_vendor_name, LDAP_VENDOR_NAME) == NULL) {
			WARN("ldap - libldap vendor changed since the server was built");
			WARN("ldap - linked: %s, built: %s", info.ldapai_vendor_name, LDAP_VENDOR_NAME);
		}

		if (info.ldapai_vendor_version < LDAP_VENDOR_VERSION) {
			WARN("ldap - libldap older than the version the server was built against");
			WARN("ldap - linked: %i, built: %i",
			     info.ldapai_vendor_version, LDAP_VENDOR_VERSION);
		}

		INFO("ldap - libldap vendor: %s, version: %i", info.ldapai_vendor_name,
		     info.ldapai_vendor_version);

		if (info.ldapai_extensions) {
			char **p;

			for (p = info.ldapai_extensions; *p != NULL; p++) {
				INFO("ldap - extension: %s", *p);
				ldap_memfree(*p);
			}

			ldap_memfree(info.ldapai_extensions);
		}

		ldap_memfree(info.ldapai_vendor_name);

	} else {
		DEBUG("ldap - Falling back to build time libldap version info.  Query for LDAP_OPT_API_INFO "
		      "returned: %i", ldap_errno);
		INFO("ldap - libldap vendor: %s, version: %i.%i.%i", LDAP_VENDOR_NAME,
		     LDAP_VENDOR_VERSION_MAJOR, LDAP_VENDOR_VERSION_MINOR, LDAP_VENDOR_VERSION_PATCH);
	}

	return 0;
}
