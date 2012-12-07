#ifdef WITH_EDIR
/*
 * Copyright (C) 2002-2004 Novell, Inc.
 * Copyright (C) 2012 Olivier Beytrison <olivier@heliosnet.org>
 * Copyright (C) 2012 Alan DeKok <aland@freeradius.org>
 *
 * edir.c  LDAP extension for reading eDirectory universal password
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, contact Novell, Inc.
 *
 * To contact Novell about this file by physical or electronic mail, you may
 * find current contact  information at www.novell.com.
 *
 * Copyright 2006 The FreeRADIUS Server Project.
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/rad_assert.h>

#include <ldap.h>
#include <lber.h>

/* NMAS error codes */
#define NMAS_E_BASE                 (-1600)

#define NMAS_SUCCESS                0

#define NMAS_E_FRAG_FAILURE	    (NMAS_E_BASE-31)     /* -1631 0xFFFFF9A1 */
#define NMAS_E_BUFFER_OVERFLOW      (NMAS_E_BASE-33)     /* -1633 0xFFFFF99F */
#define NMAS_E_SYSTEM_RESOURCES     (NMAS_E_BASE-34)     /* -1634 0xFFFFF99E */
#define NMAS_E_INSUFFICIENT_MEMORY  (NMAS_E_BASE-35)     /* -1635 0xFFFFF99D */
#define NMAS_E_NOT_SUPPORTED        (NMAS_E_BASE-36)     /* -1636 0xFFFFF99C */
#define NMAS_E_INVALID_PARAMETER    (NMAS_E_BASE-43)     /* -1643 0xFFFFF995 */
#define NMAS_E_INVALID_VERSION      (NMAS_E_BASE-52)     /* -1652 0xFFFFF98C */

/* OID of LDAP extenstion calls to read Universal Password */
#define NMASLDAP_GET_PASSWORD_REQUEST     "2.16.840.1.113719.1.39.42.100.13"
#define NMASLDAP_GET_PASSWORD_RESPONSE    "2.16.840.1.113719.1.39.42.100.14"

#define NMAS_LDAP_EXT_VERSION 1

int nmasldap_get_password(LDAP *ld,char *objectDN, char *pwd, size_t *pwdSize);

/* ------------------------------------------------------------------------
 *	berEncodePasswordData
 *	==============================
 *	RequestBer contents:
 *		clientVersion				INTEGER
 *		targetObjectDN				OCTET STRING
 *		password1				OCTET STRING
 *		password2				OCTET STRING
 *
 *	Description:
 *		This function takes the request BER value and input
 *		data items and BER encodes the data into the BER value
 *
 * ------------------------------------------------------------------------ */
static int berEncodePasswordData(struct berval **requestBV, char *object_dn)
{
	int err = 0;
	int rc = 0;
	size_t object_len = 0;
	BerElement *requestBer = NULL;

	if (!object_dn || !*object_dn) {
		err = NMAS_E_INVALID_PARAMETER;
		goto cleanup;
	}

	/* Allocate a BerElement for the request parameters.*/
	if ((requestBer = ber_alloc()) == NULL) {
		err = NMAS_E_FRAG_FAILURE;
		goto cleanup;
	}

	object_len = strlen(object_dn) + 1;
   
	rc = ber_printf(requestBer, "{io}", NMAS_LDAP_EXT_VERSION,
			object_dn, object_len);
	if (rc < 0) {
		err = NMAS_E_FRAG_FAILURE;
		goto cleanup;
	}

	/*
	 *	Convert the BER we just built to a berval that we'll
	 *	send with the extended request.
	 */
	if (ber_flatten(requestBer, requestBV) < 0) {
		err = NMAS_E_FRAG_FAILURE;
		goto cleanup;
	}

cleanup:
	if (requestBer) ber_free(requestBer, 1);

	return err;
}

/* ------------------------------------------------------------------------
 *	berDecodeLoginData()
 *	==============================
 *	ResponseBer contents:
 *		serverVersion				INTEGER
 *		error       				INTEGER
 *		data				       	OCTET STRING
 *
 *	Description:
 *		This function takes the reply BER Value and decodes
 *		the NMAS server version and return code and if a non
 *		null retData buffer was supplied, tries to decode the
 *		the return data and length
 *
 * ------------------------------------------------------------------------ */
static int berDecodeLoginData(struct berval *replyBV,int *serverVersion,
			      void *output, size_t *outlen)
{
	int rc = 0;
	int err = 0;
	BerElement *replyBer = NULL;

	rad_assert(output != NULL);
	rad_assert(outlen != NULL);

	if ((replyBer = ber_init(replyBV)) == NULL) {
		err = NMAS_E_SYSTEM_RESOURCES;
		goto cleanup;
	}

	rc = ber_scanf(replyBer, "{iis}", serverVersion, &err,
		       output, &outlen);
	if (rc == -1) {
		err = NMAS_E_FRAG_FAILURE;
		goto cleanup;
	}
	
cleanup:

	if(replyBer) ber_free(replyBer, 1);

	return err;
}

/* -----------------------------------------------------------------------
 *	nmasldap_get_password()
 *	==============================
 *
 *	Description:
 *		This API attempts to get the universal password
 *
 * ------------------------------------------------------------------------ */
int nmasldap_get_password(LDAP *ld,char *objectDN, char *pwd, size_t *pwdSize)
{
	int err = 0;
	struct berval *requestBV = NULL;
	char *replyOID = NULL;
	struct berval *replyBV = NULL;
	int serverVersion;
	size_t bufsize;
	char buffer[256];

	/* Validate  parameters. */
	if (!objectDN ||!*objectDN|| !pwdSize || !ld) {
		return NMAS_E_INVALID_PARAMETER;
	}

	err = berEncodePasswordData(&requestBV, objectDN);
	if (err) goto cleanup;

	/* Call the ldap_extended_operation (synchronously) */
	err = ldap_extended_operation_s(ld, NMASLDAP_GET_PASSWORD_REQUEST,
					requestBV, NULL, NULL,
					&replyOID, &replyBV);
	if (err) goto cleanup;

	/* Make sure there is a return OID */
	if (!replyOID) {
		err = NMAS_E_NOT_SUPPORTED;
		goto cleanup;
	}

	/* Is this what we were expecting to get back. */
	if (strcmp(replyOID, NMASLDAP_GET_PASSWORD_RESPONSE) != 0) {
		err = NMAS_E_NOT_SUPPORTED;
		goto cleanup;
	}

	/* Do we have a good returned berval? */
	if (!replyBV) {
		/*
		 *	No; returned berval means we experienced a rather
		 *	drastic error.  Return operations error.
		 */
		err = NMAS_E_SYSTEM_RESOURCES;
		goto cleanup;
	}

	bufsize = sizeof(buffer);
	err = berDecodeLoginData(replyBV, &serverVersion, buffer, &bufsize);
	if (err) goto cleanup;

	if (serverVersion != NMAS_LDAP_EXT_VERSION) {
		err = NMAS_E_INVALID_VERSION;
		goto cleanup;
	}

	if (bufsize >= MAX_STRING_LEN) {
		err = NMAS_E_BUFFER_OVERFLOW;
		goto cleanup;
	}

	memcpy(pwd, buffer, bufsize);
	pwd[bufsize] = '\0';
	*pwdSize = bufsize;

cleanup:
	if (replyBV) ber_bvfree(replyBV);

	/* Free the return OID string if one was returned. */
	if (replyOID) ldap_memfree(replyOID);

	/* Free memory allocated while building the request ber and berval. */
	if (requestBV) ber_bvfree(requestBV);

	return err;
}

#endif	/* WITH_EDIR */
