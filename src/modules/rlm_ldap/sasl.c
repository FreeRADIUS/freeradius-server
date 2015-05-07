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

#include "ldap.h"

#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND
/**
 * $Id$
 * @file sasl.c
 * @brief Functions to perform SASL binds against an LDAP directory.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015 The FreeRADIUS Server Project.
 */
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <sasl/sasl.h>

typedef struct rlm_ldap_sasl_ctx {
	rlm_ldap_t	const	*inst;		//!< LDAP instance
	REQUEST			*request;	//!< The current request.

	char const		*identity;	//!< User's DN or identity.
	char const		*password;	//!< Bind password.

	ldap_sasl		*extra;		//!< Extra fields (realm and proxy id).
} rlm_ldap_sasl_ctx_t;

static int _sasl_interact(UNUSED LDAP *handle, UNUSED unsigned flags, void *ctx, void *sasl_callbacks)
{
	rlm_ldap_sasl_ctx_t *this = ctx;
	REQUEST *request = this->request;
	rlm_ldap_t const *inst = this->inst;
	sasl_interact_t *cb = sasl_callbacks;
	sasl_interact_t *cb_p;

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

ldap_rcode_t rlm_ldap_sasl_interactive(rlm_ldap_t const *inst, REQUEST *request,
				       ldap_handle_t *conn, char const *identity,
				       char const *password, ldap_sasl *sasl,
				       char const **error, char **extra)
{
	ldap_rcode_t		status;
	int			ret = 0;
	int			msgid;
	char const		*mech;
	LDAPMessage		*result = NULL;
	rlm_ldap_sasl_ctx_t	sasl_ctx;		/* SASL defaults */

	memset(&sasl_ctx, 0, sizeof(sasl_ctx));

	sasl_ctx.inst = inst;
	sasl_ctx.request = request;
	sasl_ctx.identity = identity;
	sasl_ctx.password = password;

	ROPTIONAL(RDEBUG2, DEBUG2, "Starting SASL mech(s): %s", sasl->mech);
	do {
		ret = ldap_sasl_interactive_bind(conn->handle, NULL, sasl->mech,
						 NULL, NULL, LDAP_SASL_AUTOMATIC,
						 _sasl_interact, &sasl_ctx, result,
						 &mech, &msgid);
		ldap_msgfree(result);	/* We always need to free the old message */
		if (ret >= 0) ROPTIONAL(RDEBUG3, DEBUG3, "Continuing SASL mech %s...", mech);

		status = rlm_ldap_result(inst, conn, msgid, identity, &result, error, extra);
		/*
		 *	Write the servers response to the debug log
		 */
		if (((request && RDEBUG_ENABLED3) || DEBUG_ENABLED3) && result) {
			struct berval *srv_cred;

			if (ldap_parse_sasl_bind_result(conn->handle, result, &srv_cred, 0) == 0) {
				char *escaped;

				escaped = fr_aprints(request, srv_cred->bv_val, srv_cred->bv_len, '\0');
				ROPTIONAL(RDEBUG3, DEBUG3, "SASL response  : %s", escaped);

				talloc_free(escaped);
				ldap_memfree(srv_cred);
			}
		}
	} while (status == LDAP_PROC_CONTINUE);
	ldap_msgfree(result);

	return status;
}
#endif /* HAVE_LDAP_SASL_INTERACTIVE_BIND */
