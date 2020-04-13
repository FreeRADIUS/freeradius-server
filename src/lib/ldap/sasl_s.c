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
 * @file lib/ldap/sasl.c
 * @brief Functions to perform SASL binds against an LDAP directory.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#define LOG_PREFIX "%s - "
#define LOG_PREFIX_ARGS handle_config->name

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/ldap/base.h>

#include <sasl/sasl.h>

/** Data passed to the _sasl interact callback.
 *
 */
typedef struct {
	REQUEST			*request;	//!< The current request.

	char const		*identity;	//!< User's DN or identity.
	char const		*password;	//!< Bind password.

	fr_ldap_sasl_t const	*extra;		//!< Extra fields (realm and proxy id).

	fr_ldap_connection_t	*conn;		//!< Connection in use.
} fr_ldap_sasl_ctx_t;

/** Callback for  fr_ldap_sasl_interactive_bind
 *
 * @param handle used for the SASL bind.
 * @param flags data as provided to  fr_ldap_sasl_interactive_bind.
 * @param ctx Our context data, containing the identity, password, realm and various other things.
 * @param sasl_callbacks Array of challenges to provide responses for.
 * @return SASL_OK.
 */
static int _sasl_interact(UNUSED LDAP *handle, UNUSED unsigned flags, void *ctx, void *sasl_callbacks)
{
	fr_ldap_sasl_ctx_t		*this = ctx;
	REQUEST				*request = this->request;
	fr_ldap_config_t const	*handle_config = this->conn->config;
	sasl_interact_t			*cb = sasl_callbacks;
	sasl_interact_t			*cb_p;

	for (cb_p = cb; cb_p->id != SASL_CB_LIST_END; cb_p++) {
		ROPTIONAL(RDEBUG3, DEBUG3, "SASL challenge : %s", cb_p->challenge);
		ROPTIONAL(RDEBUG3, DEBUG3, "SASL prompt    : %s", cb_p->prompt);

		switch (cb_p->id) {
		case SASL_CB_AUTHNAME:
			cb_p->result = this->identity;
			break;

		case SASL_CB_PASS:
			cb_p->result = this->password;
			break;

		case SASL_CB_USER:
			cb_p->result = this->extra->proxy ? this->extra->proxy : this->identity;
			break;

		case SASL_CB_GETREALM:
			if (this->extra->realm) cb_p->result = this->extra->realm;
			break;

		default:
			break;
		}
		ROPTIONAL(RDEBUG3, DEBUG3, "SASL result    : %s", cb_p->result ? (char const *)cb_p->result : "");
	}
	return SASL_OK;
}

/** Initiate an LDAP interactive bind
 *
 * @param[in] request		Current request, this may be NULL.
 * @param[in] conn		to use. May change as this function calls functions
 *				which auto re-connect.
 * @param[in] identity		of the user.
 * @param[in] password		of the user.
 * @param[in] sasl		mechanism to use for bind, and additional parameters.
 * @param[in] serverctrls	Search controls to pass to the server.  May be NULL.
 * @param[in] clientctrls	Search controls for  fr_ldap_sasl_interactive.  May be NULL.
 * @param[in] timeout		Maximum time bind is allowed to take.
 * @return One of the LDAP_PROC_* (#fr_ldap_rcode_t) values.
 */
fr_ldap_rcode_t  fr_ldap_sasl_interactive(REQUEST *request,
					  fr_ldap_connection_t *conn, char const *identity,
					  char const *password, fr_ldap_sasl_t const *sasl,
					  LDAPControl **serverctrls, LDAPControl **clientctrls,
					  fr_time_delta_t timeout)
{
	fr_ldap_rcode_t			status;
	int				ret = 0;
	int				msgid;
	char const			*mech;
	LDAPMessage			*result = NULL;
	fr_ldap_sasl_ctx_t		sasl_ctx;		/* SASL defaults */

	fr_ldap_config_t const		*handle_config = conn->config;

	LDAPControl			*our_serverctrls[LDAP_MAX_CONTROLS];
	LDAPControl			*our_clientctrls[LDAP_MAX_CONTROLS];

	fr_ldap_control_merge(our_serverctrls, our_clientctrls,
			      NUM_ELEMENTS(our_serverctrls),
			      NUM_ELEMENTS(our_clientctrls),
			      conn, serverctrls, clientctrls);

	sasl_ctx.request = request;
	sasl_ctx.identity = identity;
	sasl_ctx.password = password;
	sasl_ctx.extra = sasl;
	sasl_ctx.conn = conn;

	ROPTIONAL(RDEBUG2, DEBUG2, "Starting SASL mech(s): %s", sasl->mech);
	for (;;) {
		ret = ldap_sasl_interactive_bind(conn->handle, NULL, sasl->mech,
						 our_serverctrls, our_clientctrls,
						 LDAP_SASL_AUTOMATIC,
						 _sasl_interact, &sasl_ctx, result,
						 &mech, &msgid);

		/*
		 *	If  fr_ldap_sasl_interactive_bind indicates it didn't want
		 *	to continue, then we're done.
		 *
		 *	Calling ldap_result here, results in a timeout in some
		 *	cases, so we need to figure out whether the bind was
		 *	successful without the help of ldap_result.
		 */
		if (ret != LDAP_SASL_BIND_IN_PROGRESS) {
			status = fr_ldap_error_check(NULL, conn, NULL, identity);
			break;		/* Old result gets freed on after exit */
		}

		ldap_msgfree(result);	/* We always need to free the old message */

		/*
		 *	If LDAP parse result indicates there was an error
		 *	then we're done.
		 */
		status = fr_ldap_result(&result, NULL, conn, msgid, 0, identity, timeout);
		switch (status) {
		case LDAP_PROC_SUCCESS:		/*  fr_ldap_sasl_interactive_bind should have indicated success */
		case LDAP_PROC_CONTINUE:
			break;

		default:
			goto done;
		}

		/*
		 *	...otherwise, the bind is still in progress.
		 */
		ROPTIONAL(RDEBUG3, DEBUG3, "Continuing SASL mech %s...", mech);

		/*
		 *	Write the servers response to the debug log
		 */
		if (((request && RDEBUG_ENABLED3) || DEBUG_ENABLED3) && result) {
			struct berval *srv_cred;

			if (ldap_parse_sasl_bind_result(conn->handle, result, &srv_cred, 0) == 0) {
				ROPTIONAL(RDEBUG3, DEBUG3, "SASL response  : %pV",
					  fr_box_strvalue_len(srv_cred->bv_val, srv_cred->bv_len));
				ldap_memfree(srv_cred);
			}
		}
	}
done:
	ldap_msgfree(result);

	if (status != LDAP_PROC_SUCCESS) ROPTIONAL(RPEDEBUG, PERROR, "SASL bind failed");

	return status;
}
