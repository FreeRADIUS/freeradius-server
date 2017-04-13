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
 * @file lib/ldap/libfreeradius-ldap.c
 * @brief LDAP module library functions.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013-2015 Network RADIUS SARL <info@networkradius.com>
 * @copyright 2013-2015 The FreeRADIUS Server Project.
 */

#include <freeradius-devel/rad_assert.h>

#define LOG_PREFIX "%s - "
#define LOG_PREFIX_ARGS handle_config->name

#include <freeradius-devel/radiusd.h>
#include "libfreeradius-ldap.h"

LDAP *ldap_global_handle;			//!< Hack for OpenLDAP libldap global initialisation.
static int instance_count = 0;

/** Used to set the global log prefix for functions which don't operate on connections
 *
 */
static ldap_handle_config_t ldap_global_handle_config = {
	.name = "global"
};

/*
 *	Some functions may be called with a NULL request structure, this
 *	simplifies switching certain messages from the request log to
 *	the main log.
 */
#define LDAP_EXTRA_DEBUG() do { if (extra) { if (request) REDEBUG("%s", extra); else ERROR("%s", extra); }} while (0)

FR_NAME_NUMBER const fr_ldap_supported_extensions[] = {
	{ "bindname",	LDAP_DEREF_NEVER	},
	{ "x-bindpw",	LDAP_DEREF_SEARCHING	},

	{  NULL , -1 }
};

/*
 *	Scopes
 */
FR_NAME_NUMBER const fr_ldap_scope[] = {
	{ "sub",	LDAP_SCOPE_SUB	},
	{ "one",	LDAP_SCOPE_ONE	},
	{ "base",	LDAP_SCOPE_BASE },
#ifdef LDAP_SCOPE_CHILDREN
	{ "children",	LDAP_SCOPE_CHILDREN },
#endif
	{  NULL , -1 }
};

#ifdef LDAP_OPT_X_TLS_NEVER
FR_NAME_NUMBER const fr_ldap_tls_require_cert[] = {
	{ "never",	LDAP_OPT_X_TLS_NEVER	},
	{ "demand",	LDAP_OPT_X_TLS_DEMAND	},
	{ "allow",	LDAP_OPT_X_TLS_ALLOW	},
	{ "try",	LDAP_OPT_X_TLS_TRY	},
	{ "hard",	LDAP_OPT_X_TLS_HARD	},	/* oh yes, just like that */

	{  NULL , -1 }
};
#endif

FR_NAME_NUMBER const fr_ldap_dereference[] = {
	{ "never",	LDAP_DEREF_NEVER	},
	{ "searching",	LDAP_DEREF_SEARCHING	},
	{ "finding",	LDAP_DEREF_FINDING	},
	{ "always",	LDAP_DEREF_ALWAYS	},

	{  NULL , -1 }
};

/** Prints information to the debug log on the current timeout settings
 *
 * There are so many different timers in LDAP it's often hard to debug
 * issues with them, hence the need for this function.
 */
void fr_ldap_timeout_debug(REQUEST *request, ldap_handle_t const *conn,
			   struct timeval const *timeout, char const *prefix)
{
	struct timeval 			*net = NULL, *client = NULL;
	int				server = 0;
	ldap_handle_config_t const	*handle_config = conn->config;


#ifdef LDAP_OPT_NETWORK_TIMEOUT
	if (ldap_get_option(conn->handle, LDAP_OPT_NETWORK_TIMEOUT, &net) != LDAP_OPT_SUCCESS) {
		ROPTIONAL(REDEBUG, ERROR, "Failed getting LDAP_OPT_NETWORK_TIMEOUT");
	}
#endif

#ifdef LDAP_OPT_TIMEOUT
	if (ldap_get_option(conn->handle, LDAP_OPT_TIMEOUT, &client) != LDAP_OPT_SUCCESS) {
		ROPTIONAL(REDEBUG, ERROR, "Failed getting LDAP_OPT_TIMEOUT");
	}
#endif

	if (ldap_get_option(conn->handle, LDAP_OPT_TIMELIMIT, &server) != LDAP_OPT_SUCCESS) {
		ROPTIONAL(REDEBUG, ERROR, "Failed getting LDAP_OPT_TIMELIMIT");
	}

	ROPTIONAL(RDEBUG4, DEBUG4, "%s: Timeout settings", prefix);

	if (timeout) {
		ROPTIONAL(RDEBUG4, DEBUG4, "Client side result timeout (ovr): %ld.%06ld",
			  (long)timeout->tv_sec, (long)timeout->tv_usec);
	} else {
		ROPTIONAL(RDEBUG4, DEBUG4, "Client side result timeout (ovr): unset");
	}

#ifdef LDAP_OPT_TIMEOUT
	if (client && (client->tv_sec != -1)) {
		ROPTIONAL(RDEBUG4, DEBUG4, "Client side result timeout (dfl): %ld.%06ld",
			  (long)client->tv_sec, (long)client->tv_usec);

	} else {
		ROPTIONAL(RDEBUG4, DEBUG4, "Client side result timeout (dfl): unset");
	}
#endif

#ifdef LDAP_OPT_NETWORK_TIMEOUT
	if (net && (net->tv_sec != -1)) {
		ROPTIONAL(RDEBUG4, DEBUG4, "Client side network I/O timeout : %ld.%06ld",
			  (long)net->tv_sec, (long)net->tv_usec);
	} else {
		ROPTIONAL(RDEBUG4, DEBUG4, "Client side network I/O timeout : unset");

	}
#endif
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
char const *fr_ldap_error_str(ldap_handle_t const *conn)
{
	int lib_errno;
	ldap_get_option(conn->handle, LDAP_OPT_ERROR_NUMBER, &lib_errno);
	if (lib_errno == LDAP_SUCCESS) {
		return "unknown";
	}

	return ldap_err2string(lib_errno);
}

/** Parse response from LDAP server dealing with any errors
 *
 * Should be called after an LDAP operation. Will check result of operation
 * and if it was successful, then attempt to retrieve and parse the result.
 *
 * Will also produce extended error output including any messages the server
 * sent, and information about partial DN matches.
 *
 * @param[in] conn	Current connection.
 * @param[in] msgid	returned from last operation. May be LDAP_RES_NONE if no result
 *			processing is required or LDAP_RES_ANY if any outstanding
 *			will do.
 * @param[in] all	Retrieve all outstanding messages (if 1).
 * @param[in] dn	Last search or bind DN.  May be NULL.
 * @param[in] timeout	Override the default result timeout.
 * @param[out] result	Where to write result, if NULL result will be freed.
 * @param[out] error	Where to write the error string, may be NULL, must
 *			not be freed.
 * @param[out] extra	Where to write additional error string to, may be NULL
 *			(faster) or must be freed (with talloc_free).
 * @return One of the LDAP_PROC_* (#ldap_rcode_t) values.
 */
ldap_rcode_t fr_ldap_result(ldap_handle_t const *conn,
			    int msgid,
			    int all,
			    char const *dn,
			    struct timeval const *timeout,
			    LDAPMessage **result,
			    char const **error, char **extra)
{
	ldap_rcode_t status = LDAP_PROC_SUCCESS;

	int lib_errno = LDAP_SUCCESS;	// errno returned by the library.
	int srv_errno = LDAP_SUCCESS;	// errno in the result message.

	char *part_dn = NULL;		// Partial DN match.
	char *our_err = NULL;		// Our extended error message.
	char *srv_err = NULL;		// Server's extended error message.
	char *p, *a;

	bool freeit = false;		// Whether the message should be freed after being processed.
	int len;

	struct timeval tv;		// Holds timeout values.

	LDAPMessage *tmp_msg = NULL;	// Temporary message pointer storage if we weren't provided with one.

	char const *tmp_err;		// Temporary error pointer storage if we weren't provided with one.

	if (!error) error = &tmp_err;
	*error = NULL;

	if (extra) *extra = NULL;
	if (result) *result = NULL;

	/*
	 *	We always need the result, but our caller may not
	 */
	if (!result) {
		result = &tmp_msg;
		freeit = true;
	}

	/*
	 *	Check if there was an error sending the request
	 */
	ldap_get_option(conn->handle, LDAP_OPT_ERROR_NUMBER, &lib_errno);
	if (lib_errno != LDAP_SUCCESS) goto process_error;
	if (msgid == LDAP_RES_NONE) return LDAP_SUCCESS;	/* No msgid and no error, return now */

	if (!timeout) {
		tv = conn->config->res_timeout;
	} else {
		tv = *timeout;
	}

	/*
	 *	Now retrieve the result and check for errors
	 *	ldap_result returns -1 on failure, and 0 on timeout
	 */
	lib_errno = ldap_result(conn->handle, msgid, all, &tv, result);
	if (lib_errno == 0) {
		lib_errno = LDAP_TIMEOUT;

		goto process_error;
	}

	if (lib_errno == -1) {
		ldap_get_option(conn->handle, LDAP_OPT_ERROR_NUMBER, &lib_errno);

		goto process_error;
	}

	/*
	 *	Parse the result and check for errors sent by the server
	 */
	lib_errno = ldap_parse_result(conn->handle, *result,
				      &srv_errno,
				      extra ? &part_dn : NULL,
				      extra ? &srv_err : NULL,
				      NULL, NULL, freeit);
	if (freeit) *result = NULL;

	if (lib_errno != LDAP_SUCCESS) {
		ldap_get_option(conn->handle, LDAP_OPT_ERROR_NUMBER, &lib_errno);
		goto process_error;
	}

process_error:
	if ((lib_errno == LDAP_SUCCESS) && (srv_errno != LDAP_SUCCESS)) {
		lib_errno = srv_errno;
	} else if ((lib_errno != LDAP_SUCCESS) && (srv_errno == LDAP_SUCCESS)) {
		srv_errno = lib_errno;
	}

	switch (lib_errno) {
	case LDAP_SUCCESS:
		*error = "Success";
		break;

	case LDAP_SASL_BIND_IN_PROGRESS:
		*error = "Continuing";
		status = LDAP_PROC_CONTINUE;
		break;

	case LDAP_NO_SUCH_OBJECT:
		*error = "The specified DN wasn't found";
		status = LDAP_PROC_BAD_DN;

		if (!extra) break;

		/*
		 *	Build our own internal diagnostic string
		 */
		if (dn) {
			len = fr_ldap_common_dn(dn, part_dn);
			if (len < 0) break;

			our_err = talloc_typed_asprintf(conn, "Match stopped here: [%.*s]%s",
							len, dn, part_dn ? part_dn : "");
		}
		goto error_string;

	case LDAP_INSUFFICIENT_ACCESS:
		*error = "Insufficient access. Check the identity and password configuration directives";
		status = LDAP_PROC_NOT_PERMITTED;
		break;

	case LDAP_UNWILLING_TO_PERFORM:
		*error = "Server was unwilling to perform";
		status = LDAP_PROC_NOT_PERMITTED;
		break;

	case LDAP_FILTER_ERROR:
		*error = "Bad search filter";
		status = LDAP_PROC_ERROR;
		break;

	case LDAP_TIMEOUT:
		*error = "Timed out while waiting for server to respond";
		status = LDAP_PROC_TIMEOUT;
		break;

	case LDAP_TIMELIMIT_EXCEEDED:
		*error = "Time limit exceeded";
		status = LDAP_PROC_TIMEOUT;
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
		*error = "Please set 'chase_referrals=yes' and 'rebind=yes'. See the ldap module configuration "
			 "for details";

		/* FALL-THROUGH */
	default:
		status = LDAP_PROC_ERROR;

	error_string:
		if (!*error) *error = ldap_err2string(lib_errno);

		if (!extra || ((lib_errno == srv_errno) && !our_err && !srv_err)) break;

		/*
		 *	Output the error codes from the library and server
		 */
		p = talloc_zero_array(conn, char, 1);
		if (!p) break;

		if (lib_errno != srv_errno) {
			a = talloc_asprintf_append(p, "LDAP lib error: %s (%u), srv error: %s (%u). ",
						   ldap_err2string(lib_errno), lib_errno,
						   ldap_err2string(srv_errno), srv_errno);
			if (!a) {
				talloc_free(p);
				break;
			}

			p = a;
		}

		if (our_err) {
			a = talloc_asprintf_append_buffer(p, "%s. ", our_err);
			if (!a) {
				talloc_free(p);
				break;
			}

			p = a;
		}

		if (srv_err) {
			a = talloc_asprintf_append_buffer(p, "Server said: %s. ", srv_err);
			if (!a) {
				talloc_free(p);
				break;
			}

			p = a;
		}

		*extra = p;

		break;
	}

	/*
	 *	Cleanup memory
	 */
	if (srv_err) ldap_memfree(srv_err);
	if (part_dn) ldap_memfree(part_dn);

	talloc_free(our_err);

	if ((status < 0) && *result) {
		ldap_msgfree(*result);
		*result = NULL;
	}

	return status;
}

/** Bind to the LDAP directory as a user
 *
 * Performs a simple bind to the LDAP directory, and handles any errors that occur.
 *
 * @param[in] request		Current request, this may be NULL, in which case all
 *				debug logging is done with radlog.
 * @param[in,out] pconn		to use. May change as this function calls functions
 *				which auto re-connect.
 * @param[in] dn		of the user, may be NULL to bind anonymously.
 * @param[in] password		of the user, may be NULL if no password is specified.
 * @param[in] sasl		mechanism to use for bind, and additional parameters.
 * @param[in] timeout		Maximum time bind is allowed to take.
 * @param[in] serverctrls	Only used for SASL binds.  May be NULL.
 * @param[in] clientctrls	Search controls for sasl_bind.
 *				Only used for SASL binds. May be NULL.
 * @return One of the LDAP_PROC_* (#ldap_rcode_t) values.
 */
ldap_rcode_t fr_ldap_bind(REQUEST *request,
			  ldap_handle_t **pconn,
			  char const *dn, char const *password,
#ifdef WITH_SASL
			  ldap_sasl const *sasl,
#else
			  NDEBUG_UNUSED ldap_sasl const *sasl,
#endif
			  struct timeval const *timeout,
			  LDAPControl **serverctrls, LDAPControl **clientctrls)
{
	ldap_rcode_t			status = LDAP_PROC_ERROR;
	ldap_handle_config_t const	*handle_config = (*pconn)->config;

	int				msgid = -1;

	char const			*error = NULL;
	char 				*extra = NULL;

	rad_assert(*pconn && (*pconn)->handle);

#ifndef WITH_SASL
	rad_assert(!sasl || !sasl->mech);
#endif

	if (DEBUG_ENABLED4 || (request && RDEBUG_ENABLED4)) {
		fr_ldap_timeout_debug(request, *pconn, timeout, __FUNCTION__);
	}

	/*
	 *	Bind as anonymous user
	 */
	if (!dn) dn = "";

#ifdef WITH_SASL
	if (sasl && sasl->mech) {
		status = fr_ldap_sasl_interactive(request, *pconn, dn, password, sasl,
						  serverctrls, clientctrls, timeout, &error, &extra);
	} else
#endif
	{
		int ret;
		struct berval cred;

		if (password) {
			memcpy(&cred.bv_val, &password, sizeof(cred.bv_val));
			cred.bv_len = talloc_array_length(password) - 1;
		} else {
			cred.bv_val = NULL;
			cred.bv_len = 0;
		}

		/*
		 *	Yes, confusingly named.  This is the simple version
		 *	of the SASL bind function that should always be
		 *	available.
		 */
		ret = ldap_sasl_bind((*pconn)->handle, dn, LDAP_SASL_SIMPLE, &cred,
				     serverctrls, clientctrls, &msgid);

		/* We got a valid message ID */
		if ((ret == 0) && (msgid >= 0)) ROPTIONAL(RDEBUG2, DEBUG2, "Waiting for bind result...");

		status = fr_ldap_result(*pconn, msgid, 0, dn, NULL, NULL, &error, &extra);
	}

	switch (status) {
	case LDAP_PROC_SUCCESS:
		ROPTIONAL(RDEBUG, DEBUG, "Bind successful");
		break;

	case LDAP_PROC_NOT_PERMITTED:
		ROPTIONAL(REDEBUG, ERROR, "Bind as \"%s\" to \"%s\" not permitted: %s", *dn ? dn : "(anonymous)",
			  handle_config->server, error);
		LDAP_EXTRA_DEBUG();
		break;

	default:
		ROPTIONAL(REDEBUG, ERROR, "Bind as \"%s\" to \"%s\" failed: %s", *dn ? dn : "(anonymous)",
			  handle_config->server, error);
		LDAP_EXTRA_DEBUG();

		break;
	}

	talloc_free(extra);

	return status; /* caller closes the connection */
}

/** Search for something in the LDAP directory
 *
 * Binds as the administrative user and performs a search, dealing with any errors.
 *
 * @param[out] result		Where to store the result. Must be freed with ldap_msgfree
 *				if LDAP_PROC_SUCCESS is returned.
 *				May be NULL in which case result will be automatically freed after use.
 * @param[in] request		Current request.
 * @param[in,out] pconn		to use. May change as this function calls functions which auto re-connect.
 * @param[in] dn		to use as base for the search.
 * @param[in] scope		to use (LDAP_SCOPE_BASE, LDAP_SCOPE_ONE, LDAP_SCOPE_SUB).
 * @param[in] filter		to use, should be pre-escaped.
 * @param[in] attrs		to retrieve.
 * @param[in] serverctrls	Search controls to pass to the server.  May be NULL.
 * @param[in] clientctrls	Search controls for ldap_search.  May be NULL.
 * @return One of the LDAP_PROC_* (#ldap_rcode_t) values.
 */
ldap_rcode_t fr_ldap_search(LDAPMessage **result, REQUEST *request,
			    ldap_handle_t **pconn,
			    char const *dn, int scope, char const *filter, char const * const *attrs,
			    LDAPControl **serverctrls, LDAPControl **clientctrls)
{
	ldap_rcode_t			status = LDAP_PROC_ERROR;
	LDAPMessage			*our_result = NULL;

	ldap_handle_config_t const	*handle_config = (*pconn)->config;

	int				msgid;		// Message id returned by
							// ldap_search_ext.

	int				count = 0;	// Number of results we got.

	struct timeval			tv;		// Holds timeout values.

	char const 			*error = NULL;
	char				*extra = NULL;

	LDAPControl			*our_serverctrls[LDAP_MAX_CONTROLS];
	LDAPControl			*our_clientctrls[LDAP_MAX_CONTROLS];

	fr_ldap_control_merge(our_serverctrls, our_clientctrls,
			      sizeof(our_serverctrls) / sizeof(*our_serverctrls),
			      sizeof(our_clientctrls) / sizeof(*our_clientctrls),
			      *pconn, serverctrls, clientctrls);

	rad_assert(*pconn && (*pconn)->handle);

	if (DEBUG_ENABLED4 || (request && RDEBUG_ENABLED4)) {
		fr_ldap_timeout_debug(request, *pconn, NULL, __FUNCTION__);
	}

	/*
	 *	OpenLDAP library doesn't declare attrs array as const, but
	 *	it really should be *sigh*.
	 */
	char **search_attrs;
	memcpy(&search_attrs, &attrs, sizeof(attrs));

	/*
	 *	Do all searches as the admin user.
	 */
	if ((*pconn)->rebound) {
		status = fr_ldap_bind(request, pconn,
				      (*pconn)->config->admin_identity, (*pconn)->config->admin_password,
				      &(*pconn)->config->admin_sasl, NULL,
				      NULL, NULL);
		if (status != LDAP_PROC_SUCCESS) return LDAP_PROC_ERROR;

		rad_assert(*pconn);

		(*pconn)->rebound = false;
	}

	if (filter) {
		ROPTIONAL(RDEBUG, DEBUG, "Performing search in \"%s\" with filter \"%s\", scope \"%s\"", dn, filter,
			  fr_int2str(fr_ldap_scope, scope, "<INVALID>"));
	} else {
		ROPTIONAL(RDEBUG, DEBUG, "Performing unfiltered search in \"%s\", scope \"%s\"", dn,
			  fr_int2str(fr_ldap_scope, scope, "<INVALID>"));
	}
	/*
	 *	If LDAP search produced an error it should also be logged
	 *	to the ld. result should pick it up without us
	 *	having to pass it explicitly.
	 */
	memset(&tv, 0, sizeof(tv));

	(void) ldap_search_ext((*pconn)->handle, dn, scope, filter, search_attrs,
			       0, our_serverctrls, our_clientctrls, NULL, 0, &msgid);

	ROPTIONAL(RDEBUG, DEBUG, "Waiting for search result...");
	status = fr_ldap_result(*pconn, msgid, 0, dn, NULL, &our_result, &error, &extra);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	/*
	 *	Invalid DN isn't a failure when searching.
	 *	The DN may be xlat expanded so may point directly
	 *	to an LDAP object. If that can't be located, it's
	 *	the same as notfound.
	 */
	case LDAP_PROC_BAD_DN:
		ROPTIONAL(RDEBUG, DEBUG, "%s", error);
		if (extra) ROPTIONAL(RDEBUG, DEBUG, "%s", extra);
		break;

	case LDAP_PROC_BAD_CONN:
		status = LDAP_PROC_ERROR;
		goto finish;

		/* FALL-THROUGH */
	default:
		ROPTIONAL(REDEBUG, ERROR, "Failed performing search: %s", error);
		if (extra) ROPTIONAL(REDEBUG, ERROR, "%s", extra);

		goto finish;
	}

	count = ldap_count_entries((*pconn)->handle, our_result);
	if (count < 0) {
		ROPTIONAL(REDEBUG, ERROR, "Error counting results: %s", fr_ldap_error_str(*pconn));
		status = LDAP_PROC_ERROR;

		ldap_msgfree(our_result);
		our_result = NULL;
	} else if (count == 0) {
		ROPTIONAL(RDEBUG, DEBUG, "Search returned no results");
		status = LDAP_PROC_NO_RESULT;

		ldap_msgfree(our_result);
		our_result = NULL;
	}

finish:
	talloc_free(extra);

	/*
	 *	We always need to get the result to count entries, but the caller
	 *	may not of requested one. If that's the case, free it, else write
	 *	it to where our caller said.
	 */
	if (!result) {
		if (our_result) ldap_msgfree(our_result);
	} else {
		*result = our_result;
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
 * @return One of the LDAP_PROC_* (#ldap_rcode_t) values.
 */
ldap_rcode_t fr_ldap_search_async(int *msgid, REQUEST *request,
				  ldap_handle_t **pconn,
				  char const *dn, int scope, char const *filter, char const * const *attrs,
				  LDAPControl **serverctrls, LDAPControl **clientctrls)
{
	ldap_rcode_t			status = LDAP_PROC_ERROR;

	ldap_handle_config_t const	*handle_config = (*pconn)->config;

	struct timeval			tv;		// Holds timeout values.

	LDAPControl			*our_serverctrls[LDAP_MAX_CONTROLS];
	LDAPControl			*our_clientctrls[LDAP_MAX_CONTROLS];

	fr_ldap_control_merge(our_serverctrls, our_clientctrls,
			      sizeof(our_serverctrls) / sizeof(*our_serverctrls),
			      sizeof(our_clientctrls) / sizeof(*our_clientctrls),
			      *pconn, serverctrls, clientctrls);

	rad_assert(*pconn && (*pconn)->handle);

	if (DEBUG_ENABLED4 || (request && RDEBUG_ENABLED4)) fr_ldap_timeout_debug(request, *pconn, NULL, __FUNCTION__);

	/*
	 *	OpenLDAP library doesn't declare attrs array as const, but
	 *	it really should be *sigh*.
	 */
	char **search_attrs;
	memcpy(&search_attrs, &attrs, sizeof(attrs));

	/*
	 *	Do all searches as the admin user.
	 */
	if ((*pconn)->rebound) {
		status = fr_ldap_bind(request, pconn,
				      (*pconn)->config->admin_identity, (*pconn)->config->admin_password,
				      &(*pconn)->config->admin_sasl, NULL,
				      NULL, NULL);
		if (status != LDAP_PROC_SUCCESS) return LDAP_PROC_ERROR;

		rad_assert(*pconn);

		(*pconn)->rebound = false;
	}

	if (filter) {
		ROPTIONAL(RDEBUG, DEBUG, "Performing search in \"%s\" with filter \"%s\", scope \"%s\"", dn, filter,
			  fr_int2str(fr_ldap_scope, scope, "<INVALID>"));
	} else {
		ROPTIONAL(RDEBUG, DEBUG, "Performing unfiltered search in \"%s\", scope \"%s\"", dn,
			  fr_int2str(fr_ldap_scope, scope, "<INVALID>"));
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

		ldap_get_option((*pconn)->handle, LDAP_OPT_ERROR_NUMBER, &ldap_errno);
		ERROR("Failed performing search: %s", ldap_err2string(ldap_errno));

		return LDAP_PROC_ERROR;
	}

	return LDAP_PROC_SUCCESS;
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
 * @return One of the LDAP_PROC_* (#ldap_rcode_t) values.
 */
ldap_rcode_t fr_ldap_modify(REQUEST *request, ldap_handle_t **pconn,
			    char const *dn, LDAPMod *mods[],
			    LDAPControl **serverctrls, LDAPControl **clientctrls)
{
	ldap_rcode_t	status = LDAP_PROC_ERROR;

	int		msgid;		// Message id returned by ldap_search_ext.

	char const 	*error = NULL;
	char		*extra = NULL;

	LDAPControl	*our_serverctrls[LDAP_MAX_CONTROLS];
	LDAPControl	*our_clientctrls[LDAP_MAX_CONTROLS];

	fr_ldap_control_merge(our_serverctrls, our_clientctrls,
			      sizeof(our_serverctrls) / sizeof(*our_serverctrls),
			      sizeof(our_clientctrls) / sizeof(*our_clientctrls),
			      *pconn, serverctrls, clientctrls);

	rad_assert(*pconn && (*pconn)->handle);

	if (RDEBUG_ENABLED4) fr_ldap_timeout_debug(request, *pconn, NULL, __FUNCTION__);

	/*
	 *	Perform all modifications as the admin user.
	 */
	if ((*pconn)->rebound) {
		status = fr_ldap_bind(request, pconn,
				      (*pconn)->config->admin_identity, (*pconn)->config->admin_password,
				      &(*pconn)->config->admin_sasl,
				      NULL, NULL, NULL);
		if (status != LDAP_PROC_SUCCESS) {
			return LDAP_PROC_ERROR;
		}

		rad_assert(*pconn);

		(*pconn)->rebound = false;
	}

	RDEBUG2("Modifying object with DN \"%s\"", dn);
	(void) ldap_modify_ext((*pconn)->handle, dn, mods, our_serverctrls, our_clientctrls, &msgid);

	RDEBUG2("Waiting for modify result...");
	status = fr_ldap_result(*pconn, msgid, 0, dn, NULL, NULL, &error, &extra);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	case LDAP_PROC_BAD_CONN:
		break;

		/* FALL-THROUGH */
	default:
		REDEBUG("Failed modifying object: %s", error);
		REDEBUG("%s", extra);

		goto finish;
	}

finish:
	talloc_free(extra);

	return status;
}

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
	ldap_rcode_t			status;
	ldap_handle_t			*conn = talloc_get_type_abort(ctx, ldap_handle_t);
	ldap_handle_config_t const	*handle_config = conn->config;

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
			switch (fr_substr2int(fr_ldap_supported_extensions, p, LDAP_EXT_UNSUPPORTED, -1)) {
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
			      &conn->config->admin_sasl, NULL, NULL, NULL);
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
 * @param conn to destroy.
 * @return always indicates success.
 */
static int _mod_conn_free(ldap_handle_t *conn)
{
	ldap_handle_config_t const	*handle_config = conn->config;

	rad_assert(conn->handle);

	fr_ldap_control_clear(conn);

#ifdef HAVE_LDAP_UNBIND_EXT_S
	LDAPControl	*our_serverctrls[LDAP_MAX_CONTROLS];
	LDAPControl	*our_clientctrls[LDAP_MAX_CONTROLS];

	fr_ldap_control_merge(our_serverctrls, our_clientctrls,
			      sizeof(our_serverctrls) / sizeof(*our_serverctrls),
			      sizeof(our_clientctrls) / sizeof(*our_clientctrls),
			      conn, NULL, NULL);

	DEBUG3("Closing libldap handle %p", conn->handle);
	ldap_unbind_ext_s(conn->handle, our_serverctrls, our_clientctrls);
#else
	DEBUG3("Closing libldap handle %p", conn->handle);
	ldap_unbind_s(conn->handle);
#endif
	conn->handle = NULL;

	return 0;
}

/** Allocate and configure a new connection
 *
 * Allocates and configures both our ldap handle, and libldap's handle.
 *
 * @param[in] ctx		to allocate handle in.
 * @param[in] handle_config	Connection configuration.
 * @return
 *	- A new handle on success.
 *	- NULL on error.
 */
ldap_handle_t *fr_ldap_conn_alloc(TALLOC_CTX *ctx, ldap_handle_config_t const *handle_config)
{
	ldap_handle_t			*conn;
	LDAP				*handle = NULL;

	int				ldap_errno, ldap_version;

	rad_assert(handle_config->server);

#ifdef HAVE_LDAP_INITIALIZE
	ldap_errno = ldap_initialize(&handle, handle_config->server);
	if (ldap_errno != LDAP_SUCCESS) {
		ERROR("ldap_initialize failed: %s", ldap_err2string(ldap_errno));
		return NULL;
	}
#else
	handle = ldap_init(handle_config->server, handle_config->port);
	if (!handle) {
		ERROR("ldap_init failed");
		return NULL;
	}
#endif

	DEBUG3("New libldap handle %p", handle);

	/*
	 *	Allocate memory for the handle.
	 */
	conn = talloc_zero(ctx, ldap_handle_t);
	if (!conn) return NULL;

	conn->config = handle_config;
	conn->handle = handle;
	conn->rebound = false;
	conn->referred = false;

	talloc_set_destructor(conn, _mod_conn_free);

	/*
	 *	We now have a connection structure, but no actual connection.
	 *
	 *	Set a bunch of LDAP options, using common code.
	 */
#define do_ldap_option(_option, _name, _value) \
	if (ldap_set_option(conn->handle, _option, _value) != LDAP_OPT_SUCCESS) { \
		ldap_get_option(conn->handle, LDAP_OPT_ERROR_NUMBER, &ldap_errno); \
		ERROR("Failed setting connection option %s: %s", _name, \
		      (ldap_errno != LDAP_SUCCESS) ? ldap_err2string(ldap_errno) : "Unknown error"); \
		goto error;\
	}

#define maybe_ldap_option(_option, _name, _value) \
	if (_value) do_ldap_option(_option, _name, _value)

	/*
	 *	Leave "dereference" unset to use the OpenLDAP default.
	 */
	if (handle_config->dereference_str) {
		do_ldap_option(LDAP_OPT_DEREF, "dereference", &(handle_config->dereference));
	}

	/*
	 *	Leave "chase_referrals" unset to use the OpenLDAP default.
	 */
	if (!handle_config->chase_referrals_unset) {
		if (handle_config->chase_referrals) {
			do_ldap_option(LDAP_OPT_REFERRALS, "chase_referrals", LDAP_OPT_ON);

			if (handle_config->rebind == true) {
#if LDAP_SET_REBIND_PROC_ARGS == 3
				ldap_set_rebind_proc(conn->handle, fr_ldap_rebind, conn);
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
	{
		struct timeval ldap_timeout = handle_config->net_timeout;

		if ((ldap_timeout.tv_usec == 0) && (ldap_timeout.tv_sec == 0)) ldap_timeout.tv_sec = -1;

		do_ldap_option(LDAP_OPT_NETWORK_TIMEOUT, "net_timeout", &ldap_timeout);
	}
#endif

	do_ldap_option(LDAP_OPT_TIMELIMIT, "srv_timelimit", &(handle_config->srv_timelimit));

	ldap_version = LDAP_VERSION3;
	do_ldap_option(LDAP_OPT_PROTOCOL_VERSION, "ldap_version", &ldap_version);

#ifdef LDAP_OPT_X_KEEPALIVE_IDLE
	do_ldap_option(LDAP_OPT_X_KEEPALIVE_IDLE, "keepalive_idle", &(handle_config->keepalive_idle));
#endif

#ifdef LDAP_OPT_X_KEEPALIVE_PROBES
	do_ldap_option(LDAP_OPT_X_KEEPALIVE_PROBES, "keepalive_probes", &(handle_config->keepalive_probes));
#endif

#ifdef LDAP_OPT_X_KEEPALIVE_INTERVAL
	do_ldap_option(LDAP_OPT_X_KEEPALIVE_INTERVAL, "keepalive_interval", &(handle_config->keepalive_interval));
#endif

#ifdef HAVE_LDAP_START_TLS_S
	/*
	 *	Set all of the TLS options
	 */
	if (handle_config->tls_mode) do_ldap_option(LDAP_OPT_X_TLS, "tls_mode", &(handle_config->tls_mode));

	maybe_ldap_option(LDAP_OPT_X_TLS_CACERTFILE, "ca_file", handle_config->tls_ca_file);
	maybe_ldap_option(LDAP_OPT_X_TLS_CACERTDIR, "ca_path", handle_config->tls_ca_path);

	/*
	 *	Set certificate options
	 */
	maybe_ldap_option(LDAP_OPT_X_TLS_CERTFILE, "certificate_file", handle_config->tls_certificate_file);
	maybe_ldap_option(LDAP_OPT_X_TLS_KEYFILE, "private_key_file", handle_config->tls_private_key_file);

#  ifdef LDAP_OPT_X_TLS_NEVER
	if (handle_config->tls_require_cert_str) {
		do_ldap_option(LDAP_OPT_X_TLS_REQUIRE_CERT, "require_cert", &handle_config->tls_require_cert);
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

	if (handle_config->start_tls) {
		if (handle_config->port == 636) {
			WARN("Told to Start TLS on LDAPS port this will probably fail, please correct the "
			     "configuration");
		}
	}
#endif /* HAVE_LDAP_START_TLS_S */

	conn->config = handle_config;

	return conn;

error:
	talloc_free(conn);

	return NULL;
}

int fr_ldap_conn_timeout_set(ldap_handle_t const *conn, struct timeval const *timeout)
{
	int				ldap_errno;
	ldap_handle_config_t const	*handle_config = conn->config;

#ifdef LDAP_OPT_NETWORK_TIMEOUT
	/*
	 *	A value of zero results in an handle configuration failure.
	 *
	 *	When most people specify zero they mean infinite.
	 *
	 *	libldap requires tv_sec to be -1 to mean that.
	 */
	{
		struct timeval ldap_timeout = *timeout;

		if ((ldap_timeout.tv_usec == 0) && (ldap_timeout.tv_sec == 0)) ldap_timeout.tv_sec = -1;

		do_ldap_option(LDAP_OPT_NETWORK_TIMEOUT, "net_timeout", &ldap_timeout);
	}
#endif

	return 0;

error:
	return -1;
}

int fr_ldap_conn_timeout_reset(ldap_handle_t const *conn)
{
	int				ldap_errno;
	ldap_handle_config_t const	*handle_config = conn->config;

#ifdef LDAP_OPT_NETWORK_TIMEOUT
	/*
	 *	A value of zero results in an handle configuration failure.
	 *
	 *	When most people specify zero they mean infinite.
	 *
	 *	libldap requires tv_sec to be -1 to mean that.
	 */
	{
		struct timeval ldap_timeout = handle_config->net_timeout;

		if ((ldap_timeout.tv_usec == 0) && (ldap_timeout.tv_sec == 0)) ldap_timeout.tv_sec = -1;

		do_ldap_option(LDAP_OPT_NETWORK_TIMEOUT, "net_timeout", &ldap_timeout);
	}
#endif

	return 0;

error:
	return -1;
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
	ldap_handle_config_t	*handle_config = &ldap_global_handle_config;

	if (done_config) return 0;

#define do_ldap_global_option(_option, _name, _value) \
	if (ldap_set_option(NULL, _option, _value) != LDAP_OPT_SUCCESS) { \
		int _ldap_errno; \
		ldap_get_option(NULL, LDAP_OPT_ERROR_NUMBER, &_ldap_errno); \
		ERROR("Failed setting global option %s: %s", _name, \
			 (_ldap_errno != LDAP_SUCCESS) ? ldap_err2string(_ldap_errno) : "Unknown error"); \
		return -1;\
	}

#define maybe_ldap_global_option(_option, _name, _value) \
	if (_value) do_ldap_global_option(_option, _name, _value)

#ifdef LDAP_OPT_DEBUG_LEVEL
	if (debug_level) do_ldap_global_option(LDAP_OPT_DEBUG_LEVEL, "ldap_debug", &debug_level);
#else
	if (debug_level) WARN("ldap_debug not honoured as LDAP_OPT_DEBUG_LEVEL is not available");
#endif

#ifdef LDAP_OPT_X_TLS_RANDOM_FILE
	/*
	 *	OpenLDAP will error out if we attempt to set
	 *	this on a handle. Presumably it's global in
	 *	OpenSSL too.
	 */
	maybe_ldap_global_option(LDAP_OPT_X_TLS_RANDOM_FILE, "random_file", tls_random_file);
#endif

	done_config = true;

	return 0;
}

/** Initialise libldap and check library versions
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_ldap_global_init(void)
{
	int			ldap_errno;
	static LDAPAPIInfo	info = { .ldapai_info_version = LDAP_API_INFO_VERSION };	/* static to quiet valgrind about this being uninitialised */
	ldap_handle_config_t	*handle_config = &ldap_global_handle_config;

	if (instance_count > 0) {
		instance_count++;

		return 0;
	}

	/*
	 *	Only needs to be done once, prevents races in environment
	 *	initialisation within libldap.
	 *
	 *	See: https://github.com/arr2036/ldapperf/issues/2
	 */
#ifdef HAVE_LDAP_INITIALIZE
	ldap_initialize(&ldap_global_handle, "");
#else
	ldap_global_handle = ldap_init("", 0);
#endif
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

		ldap_memfree(info.ldapai_vendor_name);
		ldap_memfree(info.ldapai_extensions);
	} else {
		DEBUG("ldap - Falling back to build time libldap version info.  Query for LDAP_OPT_API_INFO "
		      "returned: %i", ldap_errno);
		INFO("ldap - libldap vendor: %s, version: %i.%i.%i", LDAP_VENDOR_NAME,
		     LDAP_VENDOR_VERSION_MAJOR, LDAP_VENDOR_VERSION_MINOR, LDAP_VENDOR_VERSION_PATCH);
	}

	instance_count++;

	return 0;
}

/** Free any global libldap resources
 *
 */
void fr_ldap_global_free(void)
{
	if (--instance_count > 0) return;

	/*
	 *	Keeping the dummy ld around for the lifetime
	 *	of the module should always work,
	 *	irrespective of what changes happen in libldap.
	 */
#ifdef HAVE_LDAP_UNBIND_EXT_S
	ldap_unbind_ext_s(ldap_global_handle, NULL, NULL);
#else
	ldap_unbind_s(ldap_global_handle);
#endif
}
