/*
 * rlm_mschap.c	
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000  The FreeRADIUS server project
 */


/*
 *  mschap.c    MS-CHAP module
 *
 *  Jay Miller  jaymiller@socket.net
 *
 *  This implements MS-CHAP, as described in RFC 2548
 *
 *  http://www.freeradius.org/rfc/rfc2548.txt
 *
 */

#include	"autoconf.h"
#include	"libradius.h"

#include	<stdio.h>
#include	<stdlib.h>
#include    	<string.h>

#include	"radiusd.h"
#include	"modules.h"

#include	"des.h"
#include        "md4.h"

#define PW_MSCHAP_RESPONSE  ((311 << 16) | 1)
#define PW_MSCHAP_CHALLENGE ((311 << 16) | 11)

static void parity_key(char * szOut, const char * szIn);
static void des_encrypt(const char *szClear, const char *szKey, char *szOut);
static void mschap(const char *szChallenge, const char *szPassword, char *szResponse);

/* 
 *	parity_key takes a 7-byte string in szIn and returns an
 *	8-byte string in szOut.  It inserts a 1 into every 8th bit.
 *	DES just strips these back out.
 */
static void parity_key(char * szOut, const char * szIn) {
	int i;
	unsigned char cNext = 0;
	unsigned char cWorking = 0;
	
	for (i = 0; i < 7; i++) {
		/* Shift operator works in place.  Copy the char out */
		cWorking = szIn[i];
		szOut[i] = (cWorking >> i) | cNext | 1;
		cWorking = szIn[i];
		cNext = (cWorking << (7 - i));
	}
	szOut[i] = cNext | 1;
}

/*
 *	des_encrypt takes an 8-byte string and a 7-byte key and
 *	returns an 8-byte DES encrypted string in szOut
 */
static void des_encrypt(const char *szClear, const char *szKey, char *szOut) {
	char szParityKey[9];
	unsigned long ulK[16][2];
	
	parity_key(szParityKey, szKey); /* Insert parity bits */
	strncpy(szOut, szClear, 8);     /* des encrypts in place */
	deskey(ulK, (unsigned char *) szParityKey, 0);  /* generate keypair */
	des(ulK, szOut);  /* encrypt */
}

/*
 *	mschap takes an 8-byte challenge string and a plain text
 *	password (up to 253 bytes) and returns a 24-byte response
 *	string in szResponse
 */
static void mschap(const char *szChallenge, const char *szPassword, char *szResponse) {
	char szMD4[21];
	char szUnicodePass[513];
	char nPasswordLen;
	int i;
	
	/* initialize hash string */
	for (i = 0; i < 21; i++) {
		szMD4[i] = '\0';
	}
	
	/*
	 *	Microsoft passwords are unicode.  Convert plain text password
	 *	to unicode by inserting a zero every other byte
	 */
	nPasswordLen = strlen(szPassword);
	for (i = 0; i < nPasswordLen; i++) {
		szUnicodePass[2 * i] = szPassword[i];
		szUnicodePass[2 * i + 1] = 0;
	}
	
	/* Encrypt plain text password to a 16-byte MD4 hash */
	md4_calc(szMD4, szUnicodePass, nPasswordLen * 2);
	
	/*
	 *
	 *	challenge_response takes an 8-byte challenge string and a
	 *	21-byte hash (16-byte hash padded to 21 bytes with zeros) and
	 *	returns a 24-byte response in szResponse
	 */
	des_encrypt(szChallenge, szMD4, szResponse);
	des_encrypt(szChallenge, szMD4 + 7, szResponse + 8);
	des_encrypt(szChallenge, szMD4 + 14, szResponse + 16);
}   


/* validate userid/passwd */
static int mschap_auth(void *instance, REQUEST *request)
{
	VALUE_PAIR *challenge, *response;
	uint8_t calculated[32];

	instance = instance;	/* -Wunused */

	/*
	 *	We need an MS-CHAP-Challenge attribute to calculate
	 *	the response.
	 */
	challenge = pairfind(request->packet->vps, PW_MSCHAP_CHALLENGE);
	if (!challenge) {
		radlog(L_AUTH, "rlm_mschap: Attribute \"MS-CHAP-Challenge\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	We need an MS-CHAP-Challenge attribute to calculate
	 *	the response.
	 */
	response = pairfind(request->packet->vps, PW_MSCHAP_RESPONSE);
	if (!response) {
		radlog(L_AUTH, "rlm_mschap: Attribute \"MS-CHAP-Response\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a Password attribute.
	 */
	if (!request->password) {
		radlog(L_AUTH, "rlm_mschap: Attribute \"Password\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *  Ensure that we're being passed a plain-text password,
	 *  and not anything else.
	 */
	if (request->password->attribute != PW_PASSWORD) {
		radlog(L_AUTH, "rlm_mschap: Attribute \"Password\" is required for authentication.  Cannot use \"%s\".", request->password->name);
		return RLM_MODULE_INVALID;
	}
	
	/*
	 *	Calculate the MS-CHAP response
	 */
	mschap(challenge->strvalue, request->password->strvalue, calculated);
	if (memcmp(response->strvalue + 26, calculated, 24) == 0) {
		return RLM_MODULE_OK;
	}
	
	return RLM_MODULE_REJECT;
}

module_t rlm_mschap = {
  "MS-CHAP",
  0,				/* type */
  NULL,				/* initialize */
  NULL,				/* instantiation */
  {
	  mschap_auth,		/* authenticate */
	  NULL,			/* authorize */
	  NULL,			/* pre-accounting */
	  NULL,			/* accounting */
	  NULL			/* checksimul */
  },
  NULL,				/* detach */
  NULL,				/* destroy */
};
