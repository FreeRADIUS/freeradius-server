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
 * @file groups.c
 * @brief LDAP module group functions.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2013 Network RADIUS SARL (legal@networkradius.com)
 * @copyright 2013-2015 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/util/debug.h>
#include <ctype.h>

#define LOG_PREFIX "rlm_ldap (%s) - "
#define LOG_PREFIX_ARGS inst->name

#include "rlm_ldap.h"

/** Retrieve the DN of a user object
 *
 * Retrieves the DN of a user and adds it to the control list as LDAP-UserDN. Will also retrieve any
 * attributes passed and return the result in *result.
 *
 * This potentially allows for all authorization and authentication checks to be performed in one
 * ldap search operation, which is a big bonus given the number of crappy, slow *cough*AD*cough*
 * LDAP directory servers out there.
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] request Current request.
 * @param[in,out] pconn to use. May change as this function calls functions which auto re-connect.
 * @param[in] attrs Additional attributes to retrieve, may be NULL.
 * @param[in] force Query even if the User-DN already exists.
 * @param[out] result Where to write the result, may be NULL in which case result is discarded.
 * @param[out] rcode The status of the operation, one of the RLM_MODULE_* codes.
 * @return The user's DN or NULL on error.
 */
char const *rlm_ldap_find_user(rlm_ldap_t const *inst, REQUEST *request, fr_ldap_connection_t **pconn,
			       char const *attrs[], bool force, LDAPMessage **result, rlm_rcode_t *rcode)
{
	static char const *tmp_attrs[] = { NULL };

	fr_ldap_rcode_t	status;
	VALUE_PAIR	*vp = NULL;
	LDAPMessage	*tmp_msg = NULL, *entry = NULL;
	int		ldap_errno;
	int		cnt;
	char		*dn = NULL;
	char const	*filter = NULL;
	char	    	filter_buff[LDAP_MAX_FILTER_STR_LEN];
	char const	*base_dn;
	char	    	base_dn_buff[LDAP_MAX_DN_STR_LEN];
	LDAPControl	*serverctrls[] = { inst->userobj_sort_ctrl, NULL };

	bool freeit = false;					//!< Whether the message should
								//!< be freed after being processed.

	*rcode = RLM_MODULE_FAIL;

	if (!result) {
		result = &tmp_msg;
		freeit = true;
	}
	*result = NULL;

	if (!attrs) {
		memset(&attrs, 0, sizeof(tmp_attrs));
	}

	/*
	 *	If the caller isn't looking for the result we can just return the current userdn value.
	 */
	if (!force) {
		vp = fr_pair_find_by_da(request->control, attr_ldap_userdn, TAG_ANY);
		if (vp) {
			RDEBUG2("Using user DN from request \"%pV\"", &vp->data);
			*rcode = RLM_MODULE_OK;
			return vp->vp_strvalue;
		}
	}

	/*
	 *	Perform all searches as the admin user.
	 */
	if ((*pconn)->rebound) {
		status = fr_ldap_bind(request, pconn, (*pconn)->config->admin_identity,
				      (*pconn)->config->admin_password, &(*pconn)->config->admin_sasl,
				      0, NULL, NULL);
		if (status != LDAP_PROC_SUCCESS) {
			*rcode = RLM_MODULE_FAIL;
			return NULL;
		}

		fr_assert(*pconn);

		(*pconn)->rebound = false;
	}

	if (inst->userobj_filter) {
		if (tmpl_expand(&filter, filter_buff, sizeof(filter_buff), request, inst->userobj_filter,
				fr_ldap_escape_func, NULL) < 0) {
			REDEBUG("Unable to create filter");
			*rcode = RLM_MODULE_INVALID;

			return NULL;
		}
	}

	if (tmpl_expand(&base_dn, base_dn_buff, sizeof(base_dn_buff), request,
			inst->userobj_base_dn, fr_ldap_escape_func, NULL) < 0) {
		REDEBUG("Unable to create base_dn");
		*rcode = RLM_MODULE_INVALID;

		return NULL;
	}

	status = fr_ldap_search(result, request, pconn, base_dn,
				inst->userobj_scope, filter, attrs, serverctrls, NULL);
	switch (status) {
	case LDAP_PROC_SUCCESS:
		break;

	case LDAP_PROC_BAD_DN:
	case LDAP_PROC_NO_RESULT:
		*rcode = RLM_MODULE_NOTFOUND;
		return NULL;

	default:
		*rcode = RLM_MODULE_FAIL;
		return NULL;
	}

	fr_assert(*pconn);

	/*
	 *	Forbid the use of unsorted search results that
	 *	contain multiple entries, as it's a potential
	 *	security issue, and likely non deterministic.
	 */
	if (!inst->userobj_sort_ctrl) {
		cnt = ldap_count_entries((*pconn)->handle, *result);
		if (cnt > 1) {
			REDEBUG("Ambiguous search result, returned %i unsorted entries (should return 1 or 0).  "
				"Enable sorting, or specify a more restrictive base_dn, filter or scope", cnt);
			REDEBUG("The following entries were returned:");
			RINDENT();
			for (entry = ldap_first_entry((*pconn)->handle, *result);
			     entry;
			     entry = ldap_next_entry((*pconn)->handle, entry)) {
				dn = ldap_get_dn((*pconn)->handle, entry);
				REDEBUG("%s", dn);
				ldap_memfree(dn);
			}
			REXDENT();
			*rcode = RLM_MODULE_INVALID;
			goto finish;
		}
	}

	entry = ldap_first_entry((*pconn)->handle, *result);
	if (!entry) {
		ldap_get_option((*pconn)->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s",
			ldap_err2string(ldap_errno));

		goto finish;
	}

	dn = ldap_get_dn((*pconn)->handle, entry);
	if (!dn) {
		ldap_get_option((*pconn)->handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Retrieving object DN from entry failed: %s", ldap_err2string(ldap_errno));

		goto finish;
	}
	fr_ldap_util_normalise_dn(dn, dn);

	RDEBUG2("User object found at DN \"%s\"", dn);

	MEM(pair_update_control(&vp, attr_ldap_userdn) >= 0);
	fr_pair_value_strdup(vp, dn);
	*rcode = RLM_MODULE_OK;

	ldap_memfree(dn);

finish:
	if ((freeit || (*rcode != RLM_MODULE_OK)) && *result) {
		ldap_msgfree(*result);
		*result = NULL;
	}

	return vp ? vp->vp_strvalue : NULL;
}

/** Check for presence of access attribute in result
 *
 * @param[in] inst rlm_ldap configuration.
 * @param[in] request Current request.
 * @param[in] conn used to retrieve access attributes.
 * @param[in] entry retrieved by rlm_ldap_find_user or fr_ldap_search.
 * @return
 *	- #RLM_MODULE_DISALLOW if the user was denied access.
 *	- #RLM_MODULE_OK otherwise.
 */
rlm_rcode_t rlm_ldap_check_access(rlm_ldap_t const *inst, REQUEST *request,
				  fr_ldap_connection_t const *conn, LDAPMessage *entry)
{
	rlm_rcode_t rcode = RLM_MODULE_OK;
	struct berval **values = NULL;

	values = ldap_get_values_len(conn->handle, entry, inst->userobj_access_attr);
	if (values) {
		if (inst->access_positive) {
			if ((values[0]->bv_len >= 5) && (strncasecmp(values[0]->bv_val, "false", 5) == 0)) {
				REDEBUG("\"%s\" attribute exists but is set to 'false' - user locked out",
				        inst->userobj_access_attr);
				rcode = RLM_MODULE_DISALLOW;
			}
			/* RLM_MODULE_OK set above... */
		} else if ((values[0]->bv_len < 5) || (strncasecmp(values[0]->bv_val, "false", 5) != 0)) {
			REDEBUG("\"%s\" attribute exists - user locked out", inst->userobj_access_attr);
			rcode = RLM_MODULE_DISALLOW;
		}
		ldap_value_free_len(values);
	} else if (inst->access_positive) {
		REDEBUG("No \"%s\" attribute - user locked out", inst->userobj_access_attr);
		rcode = RLM_MODULE_DISALLOW;
	}

	return rcode;
}

/** Verify we got a password from the search
 *
 * Checks to see if after the LDAP to RADIUS mapping has been completed that a reference password.
 *
 * @param inst rlm_ldap configuration.
 * @param request Current request.
 * @param conn the connection handle
 */
void rlm_ldap_check_reply(rlm_ldap_t const *inst, REQUEST *request, fr_ldap_connection_t const *conn)
{
       /*
	*	More warning messages for people who can't be bothered to read the documentation.
	*
	*	Expect_password is set when we process the mapping, and is only true if there was a mapping between
	*	an LDAP attribute and a password reference attribute in the control list.
	*/
	if (!inst->expect_password || !RDEBUG_ENABLED2) return;

	if (!fr_pair_find_by_da(request->control, attr_cleartext_password, TAG_ANY) &&
	    !fr_pair_find_by_da(request->control, attr_nt_password, TAG_ANY) &&
	    !fr_pair_find_by_da(request->control, attr_user_password, TAG_ANY) &&
	    !fr_pair_find_by_da(request->control, attr_password_with_header, TAG_ANY) &&
	    !fr_pair_find_by_da(request->control, attr_crypt_password, TAG_ANY)) {
		switch (conn->directory->type) {
		case FR_LDAP_DIRECTORY_ACTIVE_DIRECTORY:
			RWDEBUG2("!!! Found map between LDAP attribute and a FreeRADIUS password attribute");
			RWDEBUG2("!!! Active Directory does not allow passwords to be read via LDAP");
			RWDEBUG2("!!! Remove the password map and either:");
			RWDEBUG2("!!!  - Configure authentication via ntlm_auth (mschapv2 only)");
			RWDEBUG2("!!!  - Configure authentication via wbclient (mschapv2 only)");
			RWDEBUG2("!!!    that password attribute");
			RWDEBUG2("!!!  - Bind as the user by listing %s in the authenticate section, and",
				 inst->name);
			RWDEBUG2("!!!	setting attribute &control:Auth-Type := '%s' in the authorize section",
				 inst->name);
			RWDEBUG2("!!!    (pap only)");

			break;

		case FR_LDAP_DIRECTORY_EDIRECTORY:
			RWDEBUG2("!!! Found map between LDAP attribute and a FreeRADIUS password attribute");
			RWDEBUG2("!!! eDirectory does not allow passwords to be retrieved via LDAP search");
			RWDEBUG2("!!! Remove the password map and either:");
			RWDEBUG2("!!!  - Set 'edir = yes' and enable the universal password feature on your");
			RWDEBUG2("!!!    eDir server (recommended)");
			RWDEBUG2("!!!    that password attribute");
			RWDEBUG2("!!!  - Bind as the user by listing %s in the authenticate section, and",
				 inst->name);
			RWDEBUG2("!!!	setting attribute &control:Auth-Type := '%s' in the authorize section",
				 inst->name);
			RWDEBUG("!!!    (pap only)");
			break;

		default:
			if (!conn->config->admin_identity) {
				RWDEBUG2("!!! Found map between LDAP attribute and a FreeRADIUS password attribute");
				RWDEBUG2("!!! but no password attribute found in search result");
				RWDEBUG2("!!! Either:");
				RWDEBUG2("!!!  - Ensure the user object contains a password attribute, and that");
				RWDEBUG2("!!!    \"%s\" has permission to read that password attribute (recommended)",
					 conn->config->admin_identity);
				RWDEBUG2("!!!  - Bind as the user by listing %s in the authenticate section, and",
					 inst->name);
				RWDEBUG2("!!!	setting attribute &control:Auth-Type := '%s' in the authorize section",
					 inst->name);
				RWDEBUG2("!!!    (pap only)");
			} else {
				RWDEBUG2("!!! No \"known good\" password added");
				RWDEBUG2("!!! but no password attribute found in search result");
				RWDEBUG2("!!! Either:");
				RWDEBUG2("!!!  - Ensure the user object contains a password attribute, and that");
				RWDEBUG2("!!!    'identity' is set to the DN of an account that has permission to read");
				RWDEBUG2("!!!    that password attribute");
				RWDEBUG2("!!!  - Bind as the user by listing %s in the authenticate section, and",
					 inst->name);
				RWDEBUG2("!!!	setting attribute &control:Auth-Type := '%s' in the authorize section",
					 inst->name);
				RWDEBUG2("!!!    (pap only)");
			}
			break;
		}
	}
}
