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
 * @file lib/ldap/edir.c
 * @brief LDAP extension for reading eDirectory universal password.
 *
 * To contact Novell about this file by physical or electronic mail, you may
 * find current contact information at www.novell.com.
 *
 * @copyright 2012 Olivier Beytrison (olivier@heliosnet.org)
 * @copyright 2012 Alan DeKok (aland@freeradius.org)
 * @copyright 2002-2004 Novell, Inc.
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/ldap/base.h>

/* NMAS error codes */
#define NMAS_E_BASE	(-1600)

#define NMAS_E_FRAG_FAILURE		(NMAS_E_BASE-31)	/* -1631 0xFFFFF9A1 */
#define NMAS_E_SYSTEM_RESOURCES		(NMAS_E_BASE-34)	/* -1634 0xFFFFF99E */
#define NMAS_E_INSUFFICIENT_MEMORY	(NMAS_E_BASE-35)	/* -1635 0xFFFFF99D */
#define NMAS_E_NOT_SUPPORTED		(NMAS_E_BASE-36)	/* -1636 0xFFFFF99C */
#define NMAS_E_INVALID_PARAMETER	(NMAS_E_BASE-43)	/* -1643 0xFFFFF995 */
#define NMAS_E_INVALID_VERSION		(NMAS_E_BASE-52)	/* -1652 0xFFFFF98C */
#define NMAS_E_ACCESS_NOT_ALLOWED	(NMAS_E_BASE-59)	/* -1659 0xFFFFF985 */
#define NMAS_E_INVALID_SPM_REQUEST	(NMAS_E_BASE-97)	/* -1697 0xFFFFF95F */

/* OID of LDAP extension calls to read Universal Password */
#define NMASLDAP_GET_PASSWORD_REQUEST     "2.16.840.1.113719.1.39.42.100.13"
#define NMASLDAP_GET_PASSWORD_RESPONSE    "2.16.840.1.113719.1.39.42.100.14"

#define NMAS_LDAP_EXT_VERSION 1

typedef struct {
	fr_ldap_query_t		*query;
	fr_ldap_thread_trunk_t	*ttrunk;
	char const		*reqoid;
	struct berval		*dn;
	fr_dict_attr_t const	*password_da;
} ldap_edir_ctx_t;

/** Takes the object DN and BER encodes the data into the BER value which is used as part of the request
 *
 @verbatim
	RequestBer contents:
		clientVersion		INTEGER
		targetObjectDN		OCTET STRING
 @endverbatim
 *
 * @param[out] request_bv where to write the request BER value (must be freed with ber_bvfree).
 * @param[in] dn to query for.
 * @return
 *	- 0 on success.
 *	- < 0 on error.
 */
static int ber_encode_request_data(char const *dn, struct berval **request_bv)
{
	int err = 0;
	int rc = 0;
	BerElement *request_ber = NULL;

	if (!dn || !*dn) {
		err = NMAS_E_INVALID_PARAMETER;
		goto finish;
	}

	/* Allocate a BerElement for the request parameters.*/
	if ((request_ber = ber_alloc()) == NULL) {
		err = NMAS_E_FRAG_FAILURE;
		goto finish;
	}

	rc = ber_printf(request_ber, "{io}", NMAS_LDAP_EXT_VERSION, dn, strlen(dn) + 1);
	if (rc < 0) {
		err = NMAS_E_FRAG_FAILURE;
		goto finish;
	}

	/*
	 *	Convert the BER we just built to a berval that we'll
	 *	send with the extended request.
	 */
	if (ber_flatten(request_ber, request_bv) < 0) {
		err = NMAS_E_FRAG_FAILURE;
		goto finish;
	}

finish:
	if (request_ber) ber_free(request_ber, 1);

	return err;
}

/** Converts the reply into server version and a return code
 *
 * This function takes the reply BER Value and decodes the NMAS server version and return code and if a non
 * null retData buffer was supplied, tries to decode the the return data and length.
 *
 @verbatim
	ResponseBer contents:
		server_version		INTEGER
		error       		INTEGER
		data			OCTET STRING
 @endverbatim
 *
 * @param[in] reply_bv reply data from extended request.
 * @param[out] server_version that responded.
 * @param[out] out data.
 * @param[out] outlen Length of data written to out.
 * @return
 *	- 0 on success.
 *	- < 0 on error.
 */
static int ber_decode_login_data(struct berval *reply_bv, int *server_version, void *out, size_t *outlen)
{
	int rc = 0;
	int err = 0;
	BerElement *reply_ber = NULL;

	fr_assert(out != NULL);
	fr_assert(outlen != NULL);

	if ((reply_ber = ber_init(reply_bv)) == NULL) {
		err = NMAS_E_SYSTEM_RESOURCES;
		goto finish;
	}

	rc = ber_scanf(reply_ber, "{iis}", server_version, &err, out, outlen);
	if (rc == -1) {
		err = NMAS_E_FRAG_FAILURE;
		goto finish;
	}

finish:
	if (reply_ber) ber_free(reply_ber, 1);

	return err;
}

/** Submit LDAP extended operation to retrieve Universal Password
 *
 * @param p_result	Result of current operation.
 * @param priority	Unused.
 * @param request	Current request.
 * @param uctx		eDir lookup context.
 * @return One of the RLM_MODULE_* values.
 */
static unlang_action_t ldap_edir_get_password_start(UNUSED rlm_rcode_t *p_result, UNUSED int *priority, request_t *request,
						    void *uctx)
{
	ldap_edir_ctx_t	*edir_ctx = talloc_get_type_abort(uctx, ldap_edir_ctx_t);
	return fr_ldap_trunk_extended(edir_ctx, &edir_ctx->query, request, edir_ctx->ttrunk,
				      edir_ctx->reqoid, edir_ctx->dn, NULL, NULL);
}

/** Handle results of retrieving Universal Password
 *
 * @param p_result	Result of current operation.
 * @param priority	Unused.
 * @param request	Current request.
 * @param uctx		eDir lookup context.
 * @return One of the RLM_MODULE_* values.
 */
static unlang_action_t ldap_edir_get_password_resume(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request,
						     void *uctx)
{
	ldap_edir_ctx_t *edir_ctx = talloc_get_type_abort(uctx, ldap_edir_ctx_t);
	fr_ldap_query_t	*query = edir_ctx->query;
	rlm_rcode_t	rcode = RLM_MODULE_OK;
	fr_pair_t	*vp;
	char		*reply_oid = NULL;
	struct berval	*reply_bv = NULL;
	size_t		bufsize;
	char		buffer[256];
	int		err = 0;
	int		server_version;

	switch (query->ret){
	case LDAP_SUCCESS:
		break;

	default:
		REDEBUG("Failed retrieving Universal Password");
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	err = ldap_parse_extended_result(query->ldap_conn->handle, query->result, &reply_oid, &reply_bv, false);

	switch (err) {
	case LDAP_SUCCESS:
		break;
	}

	/* Make sure there is a return OID */
	if (!reply_oid) {
		err = NMAS_E_NOT_SUPPORTED;
		goto finish;
	}

	/* Is this what we were expecting to get back. */
	if (strcmp(reply_oid, NMASLDAP_GET_PASSWORD_RESPONSE) != 0) {
		err = NMAS_E_NOT_SUPPORTED;
		goto finish;
	}

	/* Do we have a good returned berval? */
	if (!reply_bv) {
		/*
		 *	No; returned berval means we experienced a rather
		 *	drastic error.  Return operations error.
		 */
		err = NMAS_E_SYSTEM_RESOURCES;
		goto finish;
	}

	bufsize = sizeof(buffer);
	err = ber_decode_login_data(reply_bv, &server_version, buffer, &bufsize);
	if (err) goto finish;

	if (server_version != NMAS_LDAP_EXT_VERSION) {
		err = NMAS_E_INVALID_VERSION;
		goto finish;
	}

	/*
	 *	Add Password.Cleartext attribute to the request
	 */
	MEM(pair_update_control(&vp, edir_ctx->password_da) >= 0);
	fr_pair_value_bstrndup(vp, buffer, bufsize, true);

	if (RDEBUG_ENABLED3) {
		RDEBUG3("Added eDirectory password.  control.%pP", vp);
	} else {
		RDEBUG2("Added eDirectory password");
	}

finish:
	/*
	 *	Free any libldap allocated resources.
	 */
	if (reply_bv) ber_bvfree(reply_bv);
	if (reply_oid) ldap_memfree(reply_oid);

	if (err) {
		REDEBUG("Failed to retrieve eDirectory password: (%i) %s", err, fr_ldap_edir_errstr(err));
		rcode = RLM_MODULE_FAIL;
	}

	RETURN_MODULE_RCODE(rcode);
}

/** Cancel an in progress Universal Password lookup
 *
 */
static void ldap_edir_get_password_cancel(UNUSED request_t *request, UNUSED fr_signal_t action, void *uctx)
{
	ldap_edir_ctx_t	*edir_ctx = talloc_get_type_abort(uctx, ldap_edir_ctx_t);

	if (!edir_ctx->query || !edir_ctx->query->treq) return;

	trunk_request_signal_cancel(edir_ctx->query->treq);
}

/** Initiate retrieval of the universal password from Novell eDirectory
 *
 * @param[in] request		Current request.
 * @param[in] dn		of the user whose password is to be retrieved.
 * @param[in] ttrunk		on which to send the LDAP request.
 * @param[in] password_da	DA to use when creating password attribute.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD on success.
 *	- UNLANG_ACTION_FAIL on failure.
 */
unlang_action_t fr_ldap_edir_get_password(request_t *request, char const *dn, fr_ldap_thread_trunk_t *ttrunk,
					  fr_dict_attr_t const *password_da)
{
	ldap_edir_ctx_t	*edir_ctx;
	int		err = 0;

	if (!dn || !*dn) {
		REDEBUG("Missing DN");
		return UNLANG_ACTION_FAIL;
	}

	MEM(edir_ctx = talloc(unlang_interpret_frame_talloc_ctx(request), ldap_edir_ctx_t));

	*edir_ctx = (ldap_edir_ctx_t) {
		.reqoid = NMASLDAP_GET_PASSWORD_REQUEST,
		.ttrunk = ttrunk,
		.password_da = password_da
	};

	err = ber_encode_request_data(dn, &edir_ctx->dn);
	if (err) {
		REDEBUG("Failed to encode user DN: %s", fr_ldap_edir_errstr(err));
		talloc_free(edir_ctx);
		return UNLANG_ACTION_FAIL;
	}

	return unlang_function_push(request, ldap_edir_get_password_start, ldap_edir_get_password_resume,
				    ldap_edir_get_password_cancel, ~FR_SIGNAL_CANCEL,
				    UNLANG_SUB_FRAME, edir_ctx);
}

char const *fr_ldap_edir_errstr(int code)
{
	switch (code) {
	case NMAS_E_FRAG_FAILURE:
		return "BER manipulation failed";

	case NMAS_E_SYSTEM_RESOURCES:
	case NMAS_E_INSUFFICIENT_MEMORY:
		return "Insufficient memory or system resources";

	case NMAS_E_NOT_SUPPORTED:
		return "Server response indicated Universal Password is not supported (missing password response OID)";

	case NMAS_E_INVALID_PARAMETER:
		return "Bad arguments passed to eDir functions";

	case NMAS_E_INVALID_VERSION:
		return "LDAP EXT version does not match expected version" STRINGIFY(NMAS_LDAP_EXT_VERSION);

	case NMAS_E_ACCESS_NOT_ALLOWED:
		return "Bound user does not have sufficient rights to read the Universal Password of users";

	case NMAS_E_INVALID_SPM_REQUEST:
		return "Universal password is not enabled for the container of this user object";

	default:
		return ldap_err2string(code);
	}
}
