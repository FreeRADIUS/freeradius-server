/*
 * Copyright (C) 2002-2004 Novell, Inc.
 *
 * edir_ldapext.c  LDAP extension for reading eDirectory universal password
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

#include <ldap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* NMAS error codes */
#define NMAS_E_BASE                       (-1600)

#define NMAS_SUCCESS                      0
#define NMAS_E_SUCCESS                    NMAS_SUCCESS         /* Alias  */
#define NMAS_OK                           NMAS_SUCCESS         /* Alias  */

#define NMAS_E_FRAG_FAILURE               (NMAS_E_BASE-31)     /* -1631 0xFFFFF9A1 */
#define NMAS_E_BUFFER_OVERFLOW            (NMAS_E_BASE-33)     /* -1633 0xFFFFF99F */
#define NMAS_E_SYSTEM_RESOURCES           (NMAS_E_BASE-34)     /* -1634 0xFFFFF99E */
#define NMAS_E_INSUFFICIENT_MEMORY        (NMAS_E_BASE-35)     /* -1635 0xFFFFF99D */
#define NMAS_E_NOT_SUPPORTED              (NMAS_E_BASE-36)     /* -1636 0xFFFFF99C */
#define NMAS_E_INVALID_PARAMETER          (NMAS_E_BASE-43)     /* -1643 0xFFFFF995 */
#define NMAS_E_INVALID_VERSION            (NMAS_E_BASE-52)     /* -1652 0xFFFFF98C */

/* OID of LDAP extenstion calls to read Universal Password */
#define NMASLDAP_GET_PASSWORD_REQUEST         "2.16.840.1.113719.1.39.42.100.13"
#define NMASLDAP_GET_PASSWORD_RESPONSE        "2.16.840.1.113719.1.39.42.100.14"

#define NMAS_LDAP_EXT_VERSION 1

/* OID of LDAP extension call to perform NMAS authentication */
#define RADAUTH_OID_NMAS_AUTH_REQUEST         "2.16.840.1.113719.1.510.100.1"
#define RADAUTH_OID_NMAS_AUTH_REPLY           "2.16.840.1.113719.1.510.100.2"

#define RADAUTH_LDAP_EXT_VERSION 1

#define REQUEST_CHALLENGED 1


/* ------------------------------------------------------------------------
 *	berEncodePasswordData
 *	==============================
 *	RequestBer contents:
 *		clientVersion				INTEGER
 *		targetObjectDN				OCTET STRING
 *		password1					OCTET STRING
 *		password2					OCTET STRING
 *
 *	Description:
 *		This function takes the request BER value and input data items
 *		and BER encodes the data into the BER value
 *
 * ------------------------------------------------------------------------ */
int berEncodePasswordData(
	struct berval **requestBV,
	char    *objectDN,
	char    *password,
	char    *password2)
{
	int err = 0, rc=0;
	BerElement *requestBer = NULL;

	char    * utf8ObjPtr = NULL;
	int     utf8ObjSize = 0;
	char    * utf8PwdPtr = NULL;
	int     utf8PwdSize = 0;
	char    * utf8Pwd2Ptr = NULL;
	int     utf8Pwd2Size = 0;


	utf8ObjSize = strlen(objectDN)+1;
	utf8ObjPtr = objectDN;

	if (password != NULL)
	{
		utf8PwdSize = strlen(password)+1;
		utf8PwdPtr = password;
	}

	if (password2 != NULL)
	{
		utf8Pwd2Size = strlen(password2)+1;
		utf8Pwd2Ptr = password2;
	}

	/* Allocate a BerElement for the request parameters.*/
	if((requestBer = ber_alloc()) == NULL)
	{
		err = NMAS_E_FRAG_FAILURE;
		goto Cleanup;
	}

	if (password != NULL && password2 != NULL)
	{
		/* BER encode the NMAS Version, the objectDN, and the password */
		rc = ber_printf(requestBer, "{iooo}", NMAS_LDAP_EXT_VERSION, utf8ObjPtr, utf8ObjSize, utf8PwdPtr, utf8PwdSize, utf8Pwd2Ptr, utf8Pwd2Size);
	}
	else if (password != NULL)
	{
		/* BER encode the NMAS Version, the objectDN, and the password */
		rc = ber_printf(requestBer, "{ioo}", NMAS_LDAP_EXT_VERSION, utf8ObjPtr, utf8ObjSize, utf8PwdPtr, utf8PwdSize);
	}
	else
	{
		/* BER encode the NMAS Version and the objectDN */
		rc = ber_printf(requestBer, "{io}", NMAS_LDAP_EXT_VERSION, utf8ObjPtr, utf8ObjSize);
	}

	if (rc < 0)
	{
		err = NMAS_E_FRAG_FAILURE;
		goto Cleanup;
	}
	else
	{
		err = 0;
	}

	/*
	 * Convert the BER we just built to a berval that we'll send with the extended request.
	 */
	if(ber_flatten(requestBer, requestBV) == LBER_ERROR)
	{
		err = NMAS_E_FRAG_FAILURE;
		goto Cleanup;
	}

Cleanup:

	if(requestBer)
	{
		ber_free(requestBer, 1);
	}

	return err;
} /* End of berEncodePasswordData */

/* ------------------------------------------------------------------------
 *	berDecodeLoginData()
 *	==============================
 *	ResponseBer contents:
 *		serverVersion				INTEGER
 *		error       				INTEGER
 *		data						OCTET STRING
 *
 *	Description:
 *		This function takes the reply BER Value and decodes the
 *		NMAS server version and return code and if a non null retData
 *		buffer was supplied, tries to decode the the return data and length
 *
 * ------------------------------------------------------------------------ */
int berDecodeLoginData(
	struct berval *replyBV,
	int      *serverVersion,
	size_t   *retDataLen,
	void     *retData )
{
	int rc=0, err = 0;
	BerElement *replyBer = NULL;
	char    *retOctStr = NULL;
	size_t  retOctStrLen = 0;

	if((replyBer = ber_init(replyBV)) == NULL)
	{
		err = NMAS_E_SYSTEM_RESOURCES;
		goto Cleanup;
	}

	if(retData)
	{
		retOctStrLen = *retDataLen + 1;
		retOctStr = (char *)malloc(retOctStrLen);
		if(!retOctStr)
		{
			err = NMAS_E_SYSTEM_RESOURCES;
			goto Cleanup;
		}

		if( (rc = ber_scanf(replyBer, "{iis}", serverVersion, &err, retOctStr, &retOctStrLen)) != -1)
		{
			if (*retDataLen >= retOctStrLen)
			{
				memcpy(retData, retOctStr, retOctStrLen);
			}
			else if (!err)
			{
				err = NMAS_E_BUFFER_OVERFLOW;
			}

			*retDataLen = retOctStrLen;
		}
		else if (!err)
		{
			err = NMAS_E_FRAG_FAILURE;
		}
	}
	else
	{
		if( (rc = ber_scanf(replyBer, "{ii}", serverVersion, &err)) == -1)
		{
			if (!err)
			{
				err = NMAS_E_FRAG_FAILURE;
			}
		}
	}

Cleanup:

	if(replyBer)
	{
		ber_free(replyBer, 1);
	}

	if (retOctStr != NULL)
	{
		memset(retOctStr, 0, retOctStrLen);
		free(retOctStr);
	}

	return err;
} /* End of berDecodeLoginData */

/* -----------------------------------------------------------------------
 *	nmasldap_get_password()
 *	==============================
 *
 *	Description:
 *		This API attempts to get the universal password
 *
 * ------------------------------------------------------------------------ */
int nmasldap_get_password(
	LDAP	 *ld,
	char     *objectDN,
	size_t   *pwdSize,	// in bytes
	char     *pwd )
{
	int err = 0;

	struct berval *requestBV = NULL;
	char *replyOID = NULL;
	struct berval *replyBV = NULL;
	int serverVersion;
	char *pwdBuf;
	size_t pwdBufLen, bufferLen;

#ifdef	NOT_N_PLAT_NLM
	int currentThreadGroupID;
#endif

	/* Validate char    parameters. */
	if(objectDN == NULL || (strlen(objectDN) == 0) || pwdSize == NULL || ld == NULL)
	{
		return NMAS_E_INVALID_PARAMETER;
	}

	bufferLen = pwdBufLen = *pwdSize;
	pwdBuf = (char *)malloc(pwdBufLen+2);
	if(pwdBuf == NULL)
	{
		return NMAS_E_INSUFFICIENT_MEMORY;
	}

#ifdef	NOT_N_PLAT_NLM
	currentThreadGroupID = SetThreadGroupID(nmasLDAPThreadGroupID);
#endif

	err = berEncodePasswordData(&requestBV, objectDN, NULL, NULL);
	if(err)
	{
		goto Cleanup;
	}

	/* Call the ldap_extended_operation (synchronously) */
	if((err = ldap_extended_operation_s(ld, NMASLDAP_GET_PASSWORD_REQUEST, requestBV, NULL, NULL, &replyOID, &replyBV)))
	{
		goto Cleanup;
	}

	/* Make sure there is a return OID */
	if(!replyOID)
	{
		err = NMAS_E_NOT_SUPPORTED;
		goto Cleanup;
	}

	/* Is this what we were expecting to get back. */
	if(strcmp(replyOID, NMASLDAP_GET_PASSWORD_RESPONSE))
	{
		err = NMAS_E_NOT_SUPPORTED;
		goto Cleanup;
	}

	/* Do we have a good returned berval? */
	if(!replyBV)
	{
		/*
		 * No; returned berval means we experienced a rather drastic error.
		 * Return operations error.
		 */
		err = NMAS_E_SYSTEM_RESOURCES;
		goto Cleanup;
	}

	err = berDecodeLoginData(replyBV, &serverVersion, &pwdBufLen, pwdBuf);

	if(serverVersion != NMAS_LDAP_EXT_VERSION)
	{
		err = NMAS_E_INVALID_VERSION;
		goto Cleanup;
	}

	if (!err && pwdBufLen != 0)
	{
		if (*pwdSize >= pwdBufLen+1 && pwd != NULL)
		{
			memcpy(pwd, pwdBuf, pwdBufLen);
			pwd[pwdBufLen] = 0; /* add null termination */
		}
		*pwdSize = pwdBufLen; /* does not include null termination */
	}

Cleanup:

	if(replyBV)
	{
		ber_bvfree(replyBV);
	}

	/* Free the return OID string if one was returned. */
	if(replyOID)
	{
		ldap_memfree(replyOID);
	}

	/* Free memory allocated while building the request ber and berval. */
	if(requestBV)
	{
		ber_bvfree(requestBV);
	}

	if (pwdBuf != NULL)
	{
		memset(pwdBuf, 0, bufferLen);
		free(pwdBuf);
	}

#ifdef	NOT_N_PLAT_NLM
	SetThreadGroupID(currentThreadGroupID);
#endif

	/* Return the appropriate error/success code. */
	return err;
} /* end of nmasldap_get_password */

/* ------------------------------------------------------------------------
 *      berEncodeAuthData
 *      ==============================
 *      RequestBer contents:
 *              targetObjectDN                                  OCTET STRING
 *              pwd                                             OCTET STRING
 *              NasIP                                           OCTET STRING
 *              stete                                           OCTET STRING
 *
 *      Description:
 *              This function takes the request BER value and input data items
 *              and BER encodes the data into the BER value
 *
 * ------------------------------------------------------------------------ */
int berEncodeAuthData(
        struct berval **requestBV,
        char    *objectDN,
        char    *pwd,
        char    *sequence,
        char    *NasIP,
        char    *state,
        int     *auth_state)
{
        int err = 0, rc=0;
        BerElement *requestBer = NULL;

        char    * utf8ObjPtr = NULL;
        int     utf8ObjSize = 0;
        char    * utf8PwdPtr = NULL;
        int     utf8PwdSize = 0;
        char    * utf8NasIPPtr = NULL;
        int     utf8NasIPSize = 0;
        char    * utf8StatePtr = NULL;
        int     utf8StateSize = 0;
        char    * utf8SeqPtr = NULL;
        int     utf8SeqSize = 0;
        int state_present = 0;

        utf8ObjSize = strlen(objectDN)+1;
        utf8ObjPtr = objectDN;

        utf8PwdSize = strlen(pwd);
        utf8PwdPtr = pwd;

        utf8SeqSize = strlen(sequence)+1;
        utf8SeqPtr = sequence;

        utf8NasIPSize = strlen(NasIP)+1;
        utf8NasIPPtr = NasIP;

        /* Allocate a BerElement for the request parameters.*/
        if((requestBer = ber_alloc()) == NULL)
        {
                err = NMAS_E_FRAG_FAILURE;
                goto Cleanup;
        }

        /* BER encode the NMAS Version, the objectDN, and the password */
        rc = ber_printf(requestBer, "{ioooo", RADAUTH_LDAP_EXT_VERSION, utf8ObjPtr, utf8ObjSize, utf8PwdPtr, utf8PwdSize, utf8SeqPtr, utf8SeqSize, utf8NasIPPtr, utf8NasIPSize);

        if( *auth_state == -2)
        {
                utf8StateSize = strlen(state)+1;
                utf8StatePtr = state;
                state_present = 1;
                rc = ber_printf(requestBer, "io}", state_present, utf8StatePtr, utf8StateSize);
        }
        else
        {
                rc = ber_printf(requestBer, "i}", state_present);
        }

        if (rc < 0)
        {
                err = NMAS_E_FRAG_FAILURE;
                goto Cleanup;
        }
        else
        {
                err = 0;
        }
        /*
         * Convert the BER we just built to a berval that we'll send with the extended request.
         */
        if(ber_flatten(requestBer, requestBV) == -1)
        {
                err = NMAS_E_FRAG_FAILURE;
                goto Cleanup;
        }

Cleanup:

        if(requestBer)
        {
                ber_free(requestBer, 1);
        }

        return err;
} /* End of berEncodeAuthData */

/* ------------------------------------------------------------------------
 *      berDecodeAuthData()
 *      ==============================
 *      ResponseBer contents:
 *              serverVersion                           INTEGER
 *              auth_state                              INTEGER
 *              challenge_data                          OCTET STRING
 *
 *      Description:
 *              This function takes the reply BER Value and decodes the
 *              server version and return code and if a non null retData
 *              buffer was supplied, tries to decode the the return data and length
 *
 * ------------------------------------------------------------------------ */
int berDecodeAuthData(
        struct berval *replyBV,
        int      *errCode,
        size_t   *retDataLen,
        char     *retData,
        int      *auth_state )
{
        int rc=0, err = 0;
        BerElement *replyBer = NULL;
        struct berval   challenge = {0};

        if((replyBer = ber_init(replyBV)) == NULL)
        {
                err = NMAS_E_SYSTEM_RESOURCES; // fix err code
                goto Cleanup;
        }
        if( (rc = ber_scanf(replyBer, "{ii", errCode, auth_state)) != -1)
        {
                if ( *auth_state != REQUEST_CHALLENGED )
                {
                        if( (rc = ber_scanf(replyBer, "}")) != -1)
                                return err;
                }
                else
                {
                        if( (rc = ber_scanf(replyBer, "o}", &challenge)) != -1)
                        {
                                if (*retDataLen >= challenge.bv_len)
                                {
                                        memcpy(retData, challenge.bv_val, challenge.bv_len);
                                }
                                *retDataLen = challenge.bv_len;
                        }
                }
        }

Cleanup:
        if(replyBer)
        {
                ber_free(replyBer, 1);
        }

        return err;
}/* End of berDecodeLoginData */

/* -----------------------------------------------------------------------
 *      radLdapXtnNMASAuth()
 *      ==============================
 *
 *      Description:
 *              This API attempts to perform NMAS authentication.
 *
 * ------------------------------------------------------------------------ */
int radLdapXtnNMASAuth(
        LDAP    *ld,
        char    *objectDN,
        char    *pwd,
        char    *sequence,
        char    *NasIPaddr,
        size_t  *statesize,
        char    *state,
        int     *auth_state
)
{
        int err = 0;

        struct berval *requestBV = NULL;
        char *replyOID = NULL;
        struct berval *replyBV = NULL;
        int errCode;
        char *challenge;
        size_t challengesize;

        challengesize = *statesize;
        challenge = (char *)malloc(challengesize+2);
                if(challenge == NULL)
                        {
                                return NMAS_E_INSUFFICIENT_MEMORY;
                        }

         /* Validate char    parameters. */
        if(objectDN == NULL || (strlen(objectDN) == 0) || statesize == NULL || NasIPaddr == NULL || ld == NULL)
        {
                return NMAS_E_INVALID_PARAMETER;
        }

        err = berEncodeAuthData(&requestBV, objectDN, pwd, sequence, NasIPaddr, state, auth_state);

        if(err)
        {
                goto Cleanup;
        }

        /* Call the ldap_extended_operation (synchronously) */
        if((err = ldap_extended_operation_s(ld, RADAUTH_OID_NMAS_AUTH_REQUEST, requestBV, NULL, NULL, &replyOID, &replyBV))!=0)
        {
                goto Cleanup;
        }
        /* Make sure there is a return OID */
        if(!replyOID)
        {
                err = NMAS_E_NOT_SUPPORTED; // change error values
                goto Cleanup;
        }

        /* Is this what we were expecting to get back. */
        if(strcmp(replyOID, RADAUTH_OID_NMAS_AUTH_REPLY))
        {
                err = NMAS_E_NOT_SUPPORTED; // change return value
                goto Cleanup;
        }

        /* Do we have a good returned berval? */
        if(!replyBV)
        {
                /*
                 * No; returned berval means we experienced a rather drastic error.
                 * Return operations error.
                 */
                err = NMAS_E_SYSTEM_RESOURCES; //change return value
                goto Cleanup;
        }
        err = berDecodeAuthData(replyBV, &errCode, &challengesize, challenge, auth_state);

/* errCode return error in case of AUTH-REJECT */
        if (!err && challengesize!= 0)
        {
                if (*statesize >= challengesize+1 && challenge != NULL)
                {
                        memcpy(state, challenge, challengesize);
                        state[challengesize] = 0; /* add null termination */
                }
                *statesize = challengesize; /* does not include null termination */
        }

Cleanup:
        /* Free memory allocated for challenge  */
        if(challenge)
        {
                free(challenge);
        }

        if(replyBV)
        {
                ber_bvfree(replyBV);
        }

        /* Free the return OID string if one was returned. */
        if(replyOID)
        {
                ldap_memfree(replyOID);
        }

        /* Free memory allocated while building the request ber and berval. */
        if(requestBV)
        {
                ber_bvfree(requestBV);
        }

#ifdef  NOT_N_PLAT_NLM
        SetThreadGroupID(currentThreadGroupID);
#endif

        /* Return the appropriate error/success code. */
        return err;
}/* End of radLdapXtnNMASAuth */

