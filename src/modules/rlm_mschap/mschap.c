/*
 * mschap.c
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2001,2006,2010  The FreeRADIUS server project
 */


/*
 *  This implements MS-CHAP, as described in RFC 2548
 *
 *  http://www.freeradius.org/rfc/rfc2548.txt
 *
 */

#include	<freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>
#include	<freeradius-devel/rad_assert.h>
#include	<freeradius-devel/md5.h>
#include	<freeradius-devel/sha1.h>

#include 	<ctype.h>

#include	"smbdes.h"
#include	"mschap.h"

/*
 *	ntpwdhash converts Unicode password to 16-byte NT hash
 *	with MD4
 */
void mschap_ntpwdhash (uint8_t *szHash, const char *szPassword)
{
	char szUnicodePass[513];
	int nPasswordLen;
	int i;

	/*
	 *	NT passwords are unicode.  Convert plain text password
	 *	to unicode by inserting a zero every other byte
	 */
	nPasswordLen = strlen(szPassword);
	for (i = 0; i < nPasswordLen; i++) {
		szUnicodePass[i << 1] = szPassword[i];
		szUnicodePass[(i << 1) + 1] = 0;
	}

	/* Encrypt Unicode password to a 16-byte MD4 hash */
	fr_md4_calc(szHash, (uint8_t *) szUnicodePass, (nPasswordLen<<1) );
}


/*
 *	challenge_hash() is used by mschap2() and auth_response()
 *	implements RFC2759 ChallengeHash()
 *	generates 64 bit challenge
 */
void mschap_challenge_hash( const uint8_t *peer_challenge,
			    const uint8_t *auth_challenge,
			    const char *user_name, uint8_t *challenge )
{
	fr_SHA1_CTX Context;
	uint8_t hash[20];

	fr_SHA1Init(&Context);
	fr_SHA1Update(&Context, peer_challenge, 16);
	fr_SHA1Update(&Context, auth_challenge, 16);
	fr_SHA1Update(&Context, (const uint8_t *) user_name,
		      strlen(user_name));
	fr_SHA1Final(hash, &Context);
	memcpy(challenge, hash, 8);
}

/*
 *	auth_response() generates MS-CHAP v2 SUCCESS response
 *	according to RFC 2759 GenerateAuthenticatorResponse()
 *	returns 42-octet response string
 */
void mschap_auth_response(const char *username,
			  const uint8_t *nt_hash_hash,
			  uint8_t *ntresponse,
			  uint8_t *peer_challenge, uint8_t *auth_challenge,
			  char *response)
{
	fr_SHA1_CTX Context;
	static const uint8_t magic1[39] =
	{0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
	 0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
	 0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
	 0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74};

	static const uint8_t magic2[41] =
	{0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
	 0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
	 0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
	 0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
	 0x6E};

	static const char hex[16] = "0123456789ABCDEF";

	size_t i;
	uint8_t challenge[8];
	uint8_t digest[20];

	fr_SHA1Init(&Context);
	fr_SHA1Update(&Context, nt_hash_hash, 16);
	fr_SHA1Update(&Context, ntresponse, 24);
	fr_SHA1Update(&Context, magic1, 39);
	fr_SHA1Final(digest, &Context);
	mschap_challenge_hash(peer_challenge, auth_challenge, username, challenge);
	fr_SHA1Init(&Context);
	fr_SHA1Update(&Context, digest, 20);
	fr_SHA1Update(&Context, challenge, 8);
	fr_SHA1Update(&Context, magic2, 41);
	fr_SHA1Final(digest, &Context);

	/*
	 *	Encode the value of 'Digest' as "S=" followed by
	 *	40 ASCII hexadecimal digits and return it in
	 *	AuthenticatorResponse.
	 *	For example,
	 *	"S=0123456789ABCDEF0123456789ABCDEF01234567"
	 */
 	response[0] = 'S';
	response[1] = '=';

	/*
	 *	The hexadecimal digits [A-F] MUST be uppercase.
	 */
	for (i = 0; i < sizeof(digest); i++) {
		response[2 + (i * 2)] = hex[(digest[i] >> 4) & 0x0f];
		response[3 + (i * 2)] = hex[digest[i] & 0x0f];
	}
}

