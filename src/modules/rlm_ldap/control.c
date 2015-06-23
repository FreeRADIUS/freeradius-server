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
 * @file control.c
 * @brief Functions for managing server/client side sort controls.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include "ldap.h"

/** Merge connection and call specific client and server controls
 *
 * LDAP_OPT_CLIENT_CONTROLS and LDAP_OPT_SERVER_CONTROLS are useless
 * because they're overriden in their entirety if any call specific
 * controls are specified.
 *
 * @param[out] serverctrls_out Where to write serverctrls.
 * @param[out] clientctrls_out Where to write clientctrls.
 * @param[in] conn to get controls from.
 * @param[in] serverctrls_in from arguments.
 * @param[in] clientctrls_in from_arguments.
 */
 void rlm_ldap_control_merge(LDAPControl *serverctrls_out[LDAP_MAX_CONTROLS],
				   LDAPControl *clientctrls_out[LDAP_MAX_CONTROLS],
				   ldap_handle_t *conn,
				   LDAPControl *serverctrls_in[],
				   LDAPControl *clientctrls_in[])
{
	int i, num_serverctrls = 0, num_clientctrls = 0;

	if (serverctrls_in) {
		for (i = 0; serverctrls_in[i] && (num_serverctrls < LDAP_MAX_CONTROLS); i++) {
			serverctrls_out[num_serverctrls++] = serverctrls_in[i];
		}
	}

	if (clientctrls_in) {
		for (i = 0; clientctrls_in[i] && (num_clientctrls < LDAP_MAX_CONTROLS); i++) {
			clientctrls_out[num_clientctrls++] = clientctrls_in[i];
		}
	}

	for (i = 0; (i < conn->serverctrls_cnt) && (num_serverctrls < LDAP_MAX_CONTROLS); i++) {
		serverctrls_out[num_serverctrls++] = conn->serverctrls[i].control;
	}

	for (i = 0; (i < conn->clientctrls_cnt) && (num_clientctrls < LDAP_MAX_CONTROLS); i++) {
		clientctrls_out[num_clientctrls++] = conn->clientctrls[i].control;
	}

	serverctrls_out[num_serverctrls] = NULL;
	clientctrls_out[num_clientctrls] = NULL;
}

/** Add a serverctrl to a connection handle
 *
 * All internal LDAP functions will pass this serverctrl to the server.
 *
 * @param conn to add control to.
 * @param ctrl to add.
 * @param freeit Whether the control should be freed when the handle is released or closed.
 * @return
 *	- 0 on success.
 *	- -1 on failure (exceeded maximum controls).
 */
 int rlm_ldap_control_add_server(ldap_handle_t *conn, LDAPControl *ctrl, bool freeit)
{
	if ((size_t)conn->serverctrls_cnt >= ((sizeof(conn->serverctrls) / sizeof(conn->serverctrls[0])) - 1)) {
		return -1;
	}

	conn->serverctrls[conn->serverctrls_cnt].control = ctrl;
	conn->serverctrls[conn->serverctrls_cnt++].freeit = freeit;

	return 0;
}

/** Add a clientctrl to a connection handle
 *
 * All internal LDAP functions will pass this clientctrl to libldap.
 *
 * @param conn to add control to.
 * @param ctrl to add.
 * @param freeit Whether the control should be freed when the handle is released or closed.
 * @return
 *	- 0 on success.
 *	- -1 on failure (exceeded maximum controls).
 */
 int rlm_ldap_control_add_client(ldap_handle_t *conn, LDAPControl *ctrl, bool freeit)
{
	if ((size_t)conn->clientctrls_cnt >= ((sizeof(conn->clientctrls) / sizeof(conn->clientctrls[0])) - 1)) return -1;

	conn->clientctrls[conn->clientctrls_cnt].control = ctrl;
	conn->clientctrls[conn->clientctrls_cnt++].freeit = freeit;

	return 0;
}

/** Clear and free any controls associated with a connection
 *
 * @param conn to clear controls from.
 */
 void rlm_ldap_control_clear(ldap_handle_t *conn)
{
	int i;

	for (i = 0; i < conn->serverctrls_cnt; i++) {
		if (conn->serverctrls[i].freeit) ldap_control_free(conn->serverctrls[i].control);
		conn->clientctrls[i].freeit = false;
		conn->serverctrls[i].control = NULL;
	}
	conn->serverctrls_cnt = 0;

	for (i = 0; i < conn->clientctrls_cnt; i++) {
		if (conn->clientctrls[i].freeit) ldap_control_free(conn->clientctrls[i].control);
		conn->clientctrls[i].freeit = false;
		conn->clientctrls[i].control = NULL;
	}
	conn->clientctrls_cnt = 0;
}

#ifdef LDAP_CONTROL_X_SESSION_TRACKING
/** Add session controls to a connection as per draft-wahl-ldap-session
 *
 * @note the RFC states that the username identifier, must be the authenticated
 *	user id, not the purported one. As order of operations is configurable,
 *	we're going to leave that up to the server admin to satisfy that
 *	requirement
 *
 * For once the RFC is pretty helpful about what should be inserted into the
 * various values, and maps out RADIUS attributes to formatOIDs, so none of
 * this is configurable.
 *
 * @param conn to add controls to.
 * @param request to draw attributes from.
 */
int rlm_ldap_control_add_session_tracking(ldap_handle_t *conn, REQUEST *request)
{
	/*
	 *	The OpenLDAP guys didn't declare the formatOID parameter to
	 *	ldap_create_session_tracking_control as const *sigh*.
	 */
	static char 		username_oid[] = LDAP_CONTROL_X_SESSION_TRACKING_USERNAME;
	static char 		acctsessionid_oid[] = LDAP_CONTROL_X_SESSION_TRACKING_RADIUS_ACCT_SESSION_ID;
	static char 		acctmultisessionid_oid[] = LDAP_CONTROL_X_SESSION_TRACKING_RADIUS_ACCT_MULTI_SESSION_ID;

	int			ret;

	char			ipaddress[INET6_ADDRSTRLEN];
	char			*username = NULL;
	char			*acctsessionid = NULL;
	char			*acctmultisessionid = NULL;
	char			*hostname;

	LDAPControl		*username_control = NULL;
	LDAPControl		*acctsessionid_control = NULL;
	LDAPControl		*acctmultisessionid_control = NULL;
	struct berval		tracking_id;

	vp_cursor_t		cursor;
	VALUE_PAIR const	*vp;

	memcpy(&hostname, &progname, sizeof(hostname));

	for (vp = fr_cursor_init(&cursor, &request->packet->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (vp->da->vendor == 0) switch (vp->da->attr) {
		case PW_NAS_IP_ADDRESS:
		case PW_NAS_IPV6_ADDRESS:
			vp_prints_value(ipaddress, sizeof(ipaddress), vp, '\0');
			break;

		case PW_USER_NAME:
			memcpy(&username, &vp->vp_strvalue, sizeof(username));
			break;

		case PW_ACCT_SESSION_ID:
			memcpy(&acctsessionid, &vp->vp_strvalue, sizeof(acctsessionid));
			break;

		case PW_ACCT_MULTI_SESSION_ID:
			memcpy(&acctmultisessionid, &vp->vp_strvalue, sizeof(acctmultisessionid));
			break;
		}
	}

	if (username) {
		tracking_id.bv_val = username;
		tracking_id.bv_len = talloc_array_length(username) - 1;

		ret = ldap_create_session_tracking_control(conn->handle, ipaddress,
							   hostname,
							   username_oid,
							   &tracking_id,
							   &username_control);
		if (ret != LDAP_SUCCESS) {
			REDEBUG("Failed creating username session tracking control: %s", ldap_err2string(ret));
		error:
			if (username_control) ldap_control_free(username_control);
			if (acctsessionid_control) ldap_control_free(acctsessionid_control);
			if (acctmultisessionid_control) ldap_control_free(acctmultisessionid_control);
			return -1;
		}
	}

	if (acctsessionid) {
		tracking_id.bv_val = acctsessionid;
		tracking_id.bv_len = talloc_array_length(acctsessionid) - 1;

		ret = ldap_create_session_tracking_control(conn->handle, ipaddress,
							   hostname,
							   acctsessionid_oid,
							   &tracking_id,
							   &acctsessionid_control);
		if (ret != LDAP_SUCCESS) {
			REDEBUG("Failed creating acctsessionid session tracking control: %s", ldap_err2string(ret));
			goto error;
		}
	}

	if (acctmultisessionid) {
		tracking_id.bv_val = acctmultisessionid;
		tracking_id.bv_len = talloc_array_length(acctmultisessionid) - 1;

		ret = ldap_create_session_tracking_control(conn->handle, ipaddress,
							   hostname,
							   acctmultisessionid_oid,
							   &tracking_id,
							   &acctmultisessionid_control);
		if (ret != LDAP_SUCCESS) {
			REDEBUG("Failed creating acctmultisessionid session tracking control: %s",
				ldap_err2string(ret));
			goto error;
		}
	}

	if ((conn->serverctrls_cnt + 3) >= LDAP_MAX_CONTROLS) {
		REDEBUG("Insufficient space to add session tracking controls");
		return -1;
	}

	if (username_control &&
	    (rlm_ldap_control_add_server(conn, username_control, true) < 0)) return -1;
	if (acctsessionid_control &&
	    (rlm_ldap_control_add_server(conn, acctsessionid_control, true) < 0)) return -1;
	if (acctmultisessionid_control &&
	    (rlm_ldap_control_add_server(conn, acctmultisessionid_control, true) < 0)) return -1;

	return 0;
}
#endif


