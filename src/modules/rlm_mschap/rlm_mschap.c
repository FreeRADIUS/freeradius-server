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
 * Copyright 2000,2001  The FreeRADIUS server project
 */


/*
 *  mschap.c    MS-CHAP module
 *
 *  This implements MS-CHAP, as described in RFC 2548
 *
 *  http://www.freeradius.org/rfc/rfc2548.txt
 *
 */

/*
 *  If you have any questions on NTLM (Samba) passwords
 *  support, LM authentication and MS-CHAP v2 support
 *  please contact
 *
 *  Vladimir Dubrovin	vlad@sandy.ru
 *  aka
 *  ZARAZA		3APA3A@security.nnov.ru
 */

/*  MPPE support from Takahiro Wagatsuma <waga@sic.shibaura-it.ac.jp> */

#include	"autoconf.h"
#include	"libradius.h"

#include	<stdio.h>
#include	<stdlib.h>
#include    	<string.h>
#include 	<ctype.h>

#include	"radiusd.h"
#include	"modules.h"

#include        "md4.h"
#include        "md5.h"
#include	"sha1.h"
#include	"rad_assert.h"

static const char rcsid[] = "$Id$";

static const char *letters = "0123456789ABCDEF";

/*
 *	hex2bin converts hexadecimal strings into binary
 */
static int hex2bin (const char *szHex, unsigned char* szBin, int len)
{
	char * c1, * c2;
	int i;

   	for (i = 0; i < len; i++) {
		if( !(c1 = memchr(letters, toupper((int) szHex[i << 1]), 16)) ||
		    !(c2 = memchr(letters, toupper((int) szHex[(i << 1) + 1]), 16)))
		     break;
                 szBin[i] = ((c1-letters)<<4) + (c2-letters);
        }
        return i;
}

/*
 *	bin2hex creates hexadecimal presentation
 *	of binary data
 */
static void bin2hex (const unsigned char *szBin, char *szHex, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		szHex[i<<1] = letters[szBin[i] >> 4];
		szHex[(i<<1) + 1] = letters[szBin[i] & 0x0F];
	}
}


/* Allowable account control bits */
#define ACB_DISABLED   0x0001  /* 1 = User account disabled */
#define ACB_HOMDIRREQ  0x0002  /* 1 = Home directory required */
#define ACB_PWNOTREQ   0x0004  /* 1 = User password not required */
#define ACB_TEMPDUP    0x0008  /* 1 = Temporary duplicate account */
#define ACB_NORMAL     0x0010  /* 1 = Normal user account */
#define ACB_MNS        0x0020  /* 1 = MNS logon user account */
#define ACB_DOMTRUST   0x0040  /* 1 = Interdomain trust account */
#define ACB_WSTRUST    0x0080  /* 1 = Workstation trust account */
#define ACB_SVRTRUST   0x0100  /* 1 = Server trust account */
#define ACB_PWNOEXP    0x0200  /* 1 = User password does not expire */
#define ACB_AUTOLOCK   0x0400  /* 1 = Account auto locked */

static int pdb_decode_acct_ctrl(const char *p)
{
	int acct_ctrl = 0;
	int finished = 0;

	/*
	 * Check if the account type bits have been encoded after the
	 * NT password (in the form [NDHTUWSLXI]).
	 */

	if (*p != '[') return 0;

	for (p++; *p && !finished; p++) {
		switch (*p) {
			case 'N': /* 'N'o password. */
			  acct_ctrl |= ACB_PWNOTREQ;
			  break;

			case 'D':  /* 'D'isabled. */
			  acct_ctrl |= ACB_DISABLED ;
			  break;

			case 'H':  /* 'H'omedir required. */
			  acct_ctrl |= ACB_HOMDIRREQ;
			  break;

			case 'T': /* 'T'emp account. */
			  acct_ctrl |= ACB_TEMPDUP;
			  break;

			case 'U': /* 'U'ser account (normal). */
			  acct_ctrl |= ACB_NORMAL;
			  break;

			case 'M': /* 'M'NS logon user account. What is this? */
			  acct_ctrl |= ACB_MNS;
			  break;

			case 'W': /* 'W'orkstation account. */
			  acct_ctrl |= ACB_WSTRUST;
			  break;

			case 'S': /* 'S'erver account. */
			  acct_ctrl |= ACB_SVRTRUST;
			  break;

			case 'L': /* 'L'ocked account. */
			  acct_ctrl |= ACB_AUTOLOCK;
			  break;

			case 'X': /* No 'X'piry on password */
			  acct_ctrl |= ACB_PWNOEXP;
			  break;

			case 'I': /* 'I'nterdomain trust account. */
			  acct_ctrl |= ACB_DOMTRUST;
			  break;

		        case ' ': /* ignore spaces */
			  break;

			case ':':
			case '\n':
			case '\0':
			case ']':
			default:
			  finished = 1;
			  break;
		}
	}

	return acct_ctrl;
}


/*
 *	ntpwdhash converts Unicode password to 16-byte NT hash
 *	with MD4
 */
static void ntpwdhash (char *szHash, const char *szPassword)
{
	char szUnicodePass[513];
	char nPasswordLen;
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
	md4_calc(szHash, szUnicodePass, (nPasswordLen<<1) );
}


/*
 *	challenge_hash() is used by mschap2() and auth_response()
 *	implements RFC2759 ChallengeHash()
 *	generates 64 bit challenge
 */
static void challenge_hash( const char *peer_challenge,
			    const char *auth_challenge,
			    const char *user_name, char *challenge )
{
	SHA1_CTX Context;
	char hash[20];

	SHA1Init(&Context);
	SHA1Update(&Context, peer_challenge, 16);
	SHA1Update(&Context, auth_challenge, 16);
	SHA1Update(&Context, user_name, strlen(user_name));
	SHA1Final(hash, &Context);
	memcpy(challenge, hash, 8);
}

/*
 *	auth_response() generates MS-CHAP v2 SUCCESS response
 *	according to RFC 2759 GenerateAuthenticatorResponse()
 *	returns 42-octet response string
 */
static void auth_response(const char *username,
			  const char *nt_hash_hash,
			  char *ntresponse,
			  char *peer_challenge, char *auth_challenge,
			  char *response)
{
	SHA1_CTX Context;
	const char magic1[39] =
	{0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
	 0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
	 0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
	 0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74};

	const char magic2[41] =
	{0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
	 0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
	 0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
	 0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
	 0x6E};

        char challenge[8];
        char digest[20];

	SHA1Init(&Context);
	SHA1Update(&Context, nt_hash_hash, 16);
	SHA1Update(&Context, ntresponse, 24);
	SHA1Update(&Context, magic1, 39);
	SHA1Final(digest, &Context);
	challenge_hash(peer_challenge, auth_challenge, username, challenge);
	SHA1Init(&Context);
	SHA1Update(&Context, digest, 20);
	SHA1Update(&Context, challenge, 8);
	SHA1Update(&Context, magic2, 41);
	SHA1Final(digest, &Context);

	/*
	 *	Encode the value of 'Digest' as "S=" followed by
	 *	40 ASCII hexadecimal digits and return it in
	 *	AuthenticatorResponse.
	 *	For example,
	 *	"S=0123456789ABCDEF0123456789ABCDEF01234567"
	 */
 	response[0] = 'S';
	response[1] = '=';
	bin2hex(digest, response + 2, 20);
}


typedef struct rlm_mschap_t {
	int use_mppe;
	int require_encryption;
        int require_strong;
        int with_ntdomain_hack;	/* this should be in another module */
	char *passwd_file;
	char *xlat_name;
	char *auth_type;	/* I don't think this is needed... */
} rlm_mschap_t;


/*
 *	Does dynamic translation of strings.
 *
 *	Pulls NT-Response, LM-Response, or Challenge from MSCHAP
 *	attributes.
 */
static int mschap_xlat(void *instance, REQUEST *request,
		       char *fmt, char *out, size_t outlen,
		       RADIUS_ESCAPE_STRING func)
{
	int		i, data_len;
	uint8_t		*data = NULL;
	uint8_t		buffer[8];
	VALUE_PAIR	*user_name;
	VALUE_PAIR	*chap_challenge, *response;
	rlm_mschap_t	*inst = instance;

	chap_challenge = response = NULL;

	func = func;		/* -Wunused */

	/*
	 *	Challenge means MS-CHAPv1 challenge, or
	 *	hash of MS-CHAPv2 challenge, and peer challenge.
	 */
	if (strcasecmp(fmt, "Challenge") == 0) {
		chap_challenge = pairfind(request->packet->vps,
					  PW_MSCHAP_CHALLENGE);
		if (!chap_challenge) {
			DEBUG2("  rlm_mschap: No MS-CHAP-Challenge in the request.");
			return 0;
		}

		/*
		 *	MS-CHAP-Challenges are 8 octets,
		 *	for MS-CHAPv2
		 */
		if (chap_challenge->length == 8) {
			DEBUG2(" mschap1: %02x", chap_challenge->strvalue[0]);
			data = chap_challenge->strvalue;
			data_len = 8;

			/*
			 *	MS-CHAP-Challenges are 16 octets,
			 *	for MS-CHAPv2.
			 */
		} else if (chap_challenge->length == 16) {
			char *username_string;

			DEBUG2(" mschap2: %02x", chap_challenge->strvalue[0]);
			response = pairfind(request->packet->vps,
					    PW_MSCHAP2_RESPONSE);
			if (!response) {
				DEBUG2("  rlm_mschap: MS-CHAP2-Response is required to calculate MS-CHAPv1 challenge.");
				return 0;
			}

			/*
			 *	Responses are 50 octets.
			 */
			if (response->length < 50) {
				radlog(L_AUTH, "rlm_mschap: MS-CHAP-Response has the wrong format.");
				return 0;
			}

			user_name = pairfind(request->packet->vps,
					     PW_USER_NAME);
			if (!user_name) {
				DEBUG2("  rlm_mschap: User-Name is required to calculateMS-CHAPv1 Challenge.");
				return 0;
			}

			/*
			 *	with_ntdomain_hack moved here, too.
			 */
			if ((username_string = strchr(user_name->strvalue, '\\')) != NULL) {
				if (inst->with_ntdomain_hack) {
					username_string++;
				} else {
					DEBUG2("  rlm_mschap: NT Domain delimeter found, should we have enabled with_ntdomain_hack?");
					username_string = user_name->strvalue;
				}
			} else {
				username_string = user_name->strvalue;
			}

			/*
			 *	Get the MS-CHAPv1 challenge
			 *	from the MS-CHAPv2 peer challenge,
			 *	our challenge, and the user name.
			 */
			challenge_hash(response->strvalue + 2,
				       chap_challenge->strvalue,
				       user_name->strvalue, buffer);
			data = buffer;
			data_len = 8;
		} else {
			DEBUG2("  rlm_mschap: Invalid MS-CHAP challenge length");
			return 0;
		}
		
		/*
		 *	Get the MS-CHAPv1 response, or the MS-CHAPv2
		 *	response.
		 */
	} else if (strcasecmp(fmt, "NT-Response") == 0) {
		response = pairfind(request->packet->vps,
				    PW_MSCHAP_RESPONSE);
		if (!response) response = pairfind(request->packet->vps,
						   PW_MSCHAP2_RESPONSE);
		if (!response) {
			DEBUG2("  rlm_mschap: No MS-CHAP-Response or MS-CHAP2-Response was found in the request.");
			return 0;
		}

		/*
		 *	For MS-CHAPv1, the NT-Response exists only
		 *	if the second octet says so.
		 */
		if ((response->attribute == PW_MSCHAP_RESPONSE) &&
		    ((response->strvalue[1] & 0x01) == 0)) {
			DEBUG2("  rlm_mschap: No NT-Response in MS-CHAP-Response");
			return 0;
		}

		/*
		 *	MS-CHAP-Response and MS-CHAP2-Response have
		 *	the NT-Response at the same offset, and are
		 *	the same length.
		 */
		data = response->strvalue + 26;
		data_len = 24;
		
		/*
		 *	LM-Response is deprecated, and exists only
		 *	in MS-CHAPv1, and not often there.
		 */
	} else if (strcasecmp(fmt, "LM-Response") == 0) {
		response = pairfind(request->packet->vps,
				    PW_MSCHAP_RESPONSE);
		if (!response) {
			DEBUG2("  rlm_mschap: No MS-CHAP-Response was found in the request.");
			return 0;
		}

		/*
		 *	For MS-CHAPv1, the NT-Response exists only
		 *	if the second octet says so.
		 */
		if ((response->strvalue[1] & 0x01) != 0) {
			DEBUG2("  rlm_mschap: No LM-Response in MS-CHAP-Response");
			return 0;
		}
		data = response->strvalue + 2;
		data_len = 24;

		/*
		 *	Pull the NT-Domain out of the User-Name, if it exists.
		 */
	} else if (strcasecmp(fmt, "NT-Domain") == 0) {
		char *p;

		user_name = pairfind(request->packet->vps, PW_USER_NAME);
		if (!user_name) {
			DEBUG2("  rlm_mschap: No User-Name was found in the request.");
			return 0;
		}
		
		p = strchr(user_name->strvalue, '\\');
		if (!p) {
			DEBUG2("  rlm_mschap: No NT-Domain was found in the User-Name.");
			return 0;
		}

		/*
		 *	Hack.  This is simpler than the alternatives.
		 */
		*p = '\0';
		strNcpy(out, user_name->strvalue, outlen);
		*p = '\\';

		return strlen(out);

		/*
		 *	Pull the User-Name out of the User-Name...
		 */
	} else if (strcasecmp(fmt, "User-Name") == 0) {
		char *p;

		user_name = pairfind(request->packet->vps, PW_USER_NAME);
		if (!user_name) {
			DEBUG2("  rlm_mschap: No User-Name was found in the request.");
			return 0;
		}
		
		p = strchr(user_name->strvalue, '\\');
		if (p) {
			p++;	/* skip the backslash */
		} else {
			p = user_name->strvalue; /* use the whole User-Name */
		}

		strNcpy(out, p, outlen);
		return strlen(out);

	} else {
		DEBUG2("  rlm_mschap: Unknown expansion string \"%s\"",
		       fmt);
		return 0;
	}

	if (outlen == 0) return 0; /* nowhere to go, don't do anything */

	/*
	 *	Didn't set anything: this is bad.
	 */
	if (!data) {
		DEBUG2("  rlm_mschap: Failed to do anything intelligent");
		return 0;
	}

	/*
	 *	Check the output length.
	 */
	if (outlen < ((data_len * 2) + 1)) {
		data_len = (outlen - 1) / 2;
	}

	/*
	 *	
	 */
	for (i = 0; i < data_len; i++) {
		sprintf(out + (2 * i), "%02x", data[i]);
	}
	out[data_len * 2] = '\0';
	
	return data_len * 2;
}


static CONF_PARSER module_config[] = {
	/*
	 *	Cache the password by default.
	 */
	{ "use_mppe",    PW_TYPE_BOOLEAN,
	  offsetof(rlm_mschap_t,use_mppe), NULL, "yes" },
	{ "require_encryption",    PW_TYPE_BOOLEAN,
	  offsetof(rlm_mschap_t,require_encryption), NULL, "no" },
	{ "require_strong",    PW_TYPE_BOOLEAN,
	  offsetof(rlm_mschap_t,require_strong), NULL, "no" },
	{ "with_ntdomain_hack",     PW_TYPE_BOOLEAN,
	  offsetof(rlm_mschap_t,with_ntdomain_hack), NULL, "no" },
	{ "passwd",   PW_TYPE_STRING_PTR,
	  offsetof(rlm_mschap_t, passwd_file), NULL,  NULL },
	{ "authtype",   PW_TYPE_STRING_PTR,
	  offsetof(rlm_mschap_t, auth_type), NULL,  NULL },

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

/*
 *	deinstantiate module, free all memory allocated during
 *	mschap_instantiate()
 */
static int mschap_detach(void *instance){
#define inst ((rlm_mschap_t *)instance)
	if (inst->passwd_file) free(inst->passwd_file);
	if (inst->auth_type) free(inst->auth_type);
	if (inst->xlat_name) {
		xlat_unregister(inst->xlat_name, mschap_xlat);
		free(inst->xlat_name);
	}
	free(instance);
	return 0;
#undef inst
}

/*
 *	Create instance for our module. Allocate space for
 *	instance structure and read configuration parameters
 */
static int mschap_instantiate(CONF_SECTION *conf, void **instance)
{
	const char *xlat_name;
	rlm_mschap_t *inst;

	inst = *instance = rad_malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}

	/*
	 *	This module used to support SMB Password files, but it
	 *	made it too complicated.  If the user tries to
	 *	configure an SMB Password file, then die, with an
	 *	error message.
	 */
	if (inst->passwd_file) {
		radlog(L_ERR, "rlm_mschap: SMB password file is no longer supported in this module.  Use rlm_passwd module instead");
		mschap_detach(inst);
		return -1;
	}

	/*
	 *	Create the dynamic translation.
	 */
	xlat_name = cf_section_name2(conf);
	if (xlat_name == NULL)
		xlat_name = cf_section_name1(conf);
	if (xlat_name){
		inst->xlat_name = strdup(xlat_name);
		xlat_register(xlat_name, mschap_xlat, inst);
	}

	return 0;
}

/*
 *	add_reply() adds either MS-CHAP2-Success or MS-CHAP-Error
 *	attribute to reply packet
 */
static void add_reply(VALUE_PAIR** vp, unsigned char ident,
		      const char* name, const char* value, int len)
{
	VALUE_PAIR *reply_attr;
	reply_attr = pairmake(name, "", T_OP_EQ);
	if (!reply_attr) {
		DEBUG("  rlm_mschap: Failed to create attribute %s: %s\n", name, librad_errstr);
		return;
	}

	reply_attr->strvalue[0] = ident;
	memcpy(reply_attr->strvalue + 1, value, len);
	reply_attr->length = len + 1;
	pairadd(vp, reply_attr);
}

/*
 *	Add MPPE attributes to the reply.
 */
static void mppe_add_reply(VALUE_PAIR** vp,
			   const char* name, const char* value, int len)
{
       VALUE_PAIR *reply_attr;
       reply_attr = pairmake(name, "", T_OP_EQ);
       if (!reply_attr) {
	       DEBUG("rlm_mschap: mppe_add_reply failed to create attribute %s: %s\n", name, librad_errstr);
	       return;
       }

       memcpy(reply_attr->strvalue, value, len);
       reply_attr->length = len;
       pairadd(vp, reply_attr);
}


/*
 *	Do the MS-CHAP stuff.
 *
 *	This function is here so that all of the MS-CHAP related
 *	authentication is in one place, and we can perhaps later replace
 *	it with code to call winbindd, or something similar.
 */
static int do_mschap(VALUE_PAIR *password,
		     uint8_t	*challenge,
		     uint8_t	*response)
{
	uint8_t		calculated[32];

	/*
	 *	No password: can't do authentication.
	 */
	if (!password) {
		DEBUG2("  rlm_mschap: FAILED: No NT/LM-Password.  Cannot perform authentication.");
		return -1;
	}

	lrad_mschap(password->strvalue, challenge, calculated);
	if (memcmp(response, calculated, 24) != 0) {
		return -1;
	}

	return 0;
}


/*
 *	Data for the hashes.
 */
static const uint8_t SHSpad1[40] =
               { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static const uint8_t SHSpad2[40] =
               { 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
                 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
                 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
                 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2 };

static const uint8_t magic1[27] =
               { 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
                 0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
                 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79 };

static const uint8_t magic2[84] =
               { 0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
                 0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
                 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
                 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
                 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
                 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
                 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
                 0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
                 0x6b, 0x65, 0x79, 0x2e };

static const uint8_t magic3[84] =
               { 0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
                 0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
                 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
                 0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
                 0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
                 0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
                 0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
                 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
                 0x6b, 0x65, 0x79, 0x2e };


static void mppe_GetMasterKey(uint8_t *nt_hashhash,uint8_t *nt_response,
			      uint8_t *masterkey)
{
       uint8_t digest[20];
       SHA1_CTX Context;

       SHA1Init(&Context);
       SHA1Update(&Context,nt_hashhash,16);
       SHA1Update(&Context,nt_response,24);
       SHA1Update(&Context,magic1,27);
       SHA1Final(digest,&Context);

       memcpy(masterkey,digest,16);
}


static void mppe_GetAsymmetricStartKey(uint8_t *masterkey,uint8_t *sesskey,
				       int keylen,int issend)
{
       uint8_t digest[20];
       const uint8_t *s;
       SHA1_CTX Context;

       memset(digest,0,20);

       if(issend) {
               s = magic3;
       } else {
               s = magic2;
       }

       SHA1Init(&Context);
       SHA1Update(&Context,masterkey,16);
       SHA1Update(&Context,SHSpad1,40);
       SHA1Update(&Context,s,84);
       SHA1Update(&Context,SHSpad2,40);
       SHA1Final(digest,&Context);

       memcpy(sesskey,digest,keylen);
}


static void mppe_chap2_get_keys128(uint8_t *nt_hashhash,uint8_t *nt_response,
				   uint8_t *sendkey,uint8_t *recvkey)
{
       uint8_t masterkey[16];

       mppe_GetMasterKey(nt_hashhash,nt_response,masterkey);

       mppe_GetAsymmetricStartKey(masterkey,sendkey,16,1);
       mppe_GetAsymmetricStartKey(masterkey,recvkey,16,0);
}

/*
 *	Generate MPPE keys.
 */
static void mppe_chap2_gen_keys128(uint8_t *nt_hash,uint8_t *response,
				   uint8_t *sendkey,uint8_t *recvkey)
{
	uint8_t enckey1[16];
	uint8_t enckey2[16];
	/* uint8_t salt[2]; */
	uint8_t nt_hashhash[16];

	md4_calc(nt_hashhash,nt_hash,16);

	mppe_chap2_get_keys128(nt_hashhash,response,enckey1,enckey2);

	/*
	 *	dictionary.microsoft defines these attributes as
	 *	'encrypt=2'.  The functions in src/lib/radius.c will
	 *	take care of encrypting/decrypting them as appropriate,
	 *	so that we don't have to.
	 */
	memcpy (sendkey, enckey1, 16);
	memcpy (recvkey, enckey2, 16);
}


/*
 *	mschap_authorize() - authorize user if we can authenticate
 *	it later. Add Auth-Type attribute if present in module
 *	configuration (usually Auth-Type must be "MS-CHAP")
 */
static int mschap_authorize(void * instance, REQUEST *request)
{
#define inst ((rlm_mschap_t *)instance)
	VALUE_PAIR *challenge = NULL, *response = NULL;
	VALUE_PAIR *vp;
	const char *authtype_name = "MS-CHAP";

	challenge = pairfind(request->packet->vps, PW_MSCHAP_CHALLENGE);
	if (!challenge) {
		return RLM_MODULE_NOOP;
	}

	response = pairfind(request->packet->vps, PW_MSCHAP_RESPONSE);
	if (!response)
		response = pairfind(request->packet->vps, PW_MSCHAP2_RESPONSE);

	/*
	 *	Nothing we recognize.  Don't do anything.
	 */
	if (!response) {
		DEBUG2("  rlm_mschap: Found MS-CHAP-Challenge, but no MS-CHAP-Response.");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Choose MS-CHAP, or whatever else they told us to use.
	 */
	if (inst->auth_type) {
		authtype_name = inst->auth_type;
	}

	DEBUG2("  rlm_mschap: Found MS-CHAP attributes.  Setting 'Auth-Type  = %s'", authtype_name);

	/*
	 *	Set Auth-Type to MS-CHAP.  The authentication code
	 *	will take care of turning clear-text passwords into
	 *	NT/LM passwords.
	 */
	pairdelete(&request->config_items, PW_AUTHTYPE);
	vp = pairmake("Auth-Type", authtype_name, T_OP_EQ);
	rad_assert(vp != NULL);
	pairadd(&request->config_items, vp);

	return RLM_MODULE_OK;
#undef inst
}

/*
 *	mschap_authenticate() - authenticate user based on given
 *	attributes and configuration.
 *	We will try to find out password in configuration
 *	or in configured passwd file.
 *	If one is found we will check paraneters given by NAS.
 *
 *	If PW_SMB_ACCOUNT_CTRL is not set to ACB_PWNOTREQ we must have
 *	one of:
 *		PAP:      PW_PASSWORD or
 *		MS-CHAP:  PW_MSCHAP_CHALLENGE and PW_MSCHAP_RESPONSE or
 *		MS-CHAP2: PW_MSCHAP_CHALLENGE and PW_MSCHAP2_RESPONSE
 *	In case of password mismatch or locked account we MAY return
 *	PW_MSCHAP_ERROR for MS-CHAP or MS-CHAP v2
 *	If MS-CHAP2 succeeds we MUST return
 *	PW_MSCHAP2_SUCCESS
 */
static int mschap_authenticate(void * instance, REQUEST *request)
{
#define inst ((rlm_mschap_t *)instance)
	VALUE_PAIR *challenge = NULL, *response = NULL;
	VALUE_PAIR *password = NULL;
	VALUE_PAIR *lm_password, *nt_password, *smb_ctrl;
	VALUE_PAIR *username;
	VALUE_PAIR *reply_attr;
	uint8_t nthashhash[32];
	uint8_t msch2resp[42];
        uint8_t mppe_sendkey[34];
        uint8_t mppe_recvkey[34];
	char *username_string;
	int chap = 0;

	/*
	 *	Find the SMB-Account-Ctrl attribute, or the
	 *	SMB-Account-Ctrl-Text attribute.
	 */
	smb_ctrl = pairfind(request->config_items, PW_SMB_ACCOUNT_CTRL);
	if (!smb_ctrl) {
		password = pairfind(request->config_items,
				    PW_SMB_ACCOUNT_CTRL_TEXT);
		if (password) {
			smb_ctrl = pairmake("SMB-Account-CTRL", "0", T_OP_SET);
			pairadd(&request->config_items, smb_ctrl);
			smb_ctrl->lvalue = pdb_decode_acct_ctrl(password->strvalue);
		}
	}

	/*
	 *	We're configured to do MS-CHAP authentication.
	 *	and account control information exists.  Enforce it.
	 */
	if (smb_ctrl) {
		/*
		 *	Password is not required.
		 */
		if ((smb_ctrl->lvalue & ACB_PWNOTREQ) != 0) {
			DEBUG2("  rlm_mschap: SMB-Account-Ctrl says no password is required.");
			return RLM_MODULE_OK;
		}
	}

	/*
	 *	Decide how to get the passwords.
	 */
	password = pairfind(request->config_items, PW_PASSWORD);

	/*
	 *	We need an LM-Password.
	 */
	lm_password = pairfind(request->config_items, PW_LM_PASSWORD);
	if (lm_password) {
		/*
		 *	Allow raw octets.
		 */
		if ((lm_password->length == 16) ||
		    ((lm_password->length == 32) &&
		     (hex2bin(lm_password->strvalue,
			      lm_password->strvalue, 16) == 16))) {
			DEBUG2("  rlm_mschap: Found LM-Password");
			lm_password->length = 16;

		} else {
			radlog(L_ERR, "rlm_mschap: Invalid LM-Password");
			lm_password = NULL;
		}

	} else if (!password) {
		DEBUG2("  rlm_mschap: No User-Password configured.  Cannot create LM-Password.");

	} else {		/* there is a configured User-Password */
		lm_password = pairmake("LM-Password", "", T_OP_EQ);
		if (!lm_password) {
			radlog(L_ERR, "No memory");
		} else {
			lrad_lmpwdhash(password->strvalue,
				       lm_password->strvalue);
			lm_password->length = 16;
			pairadd(&request->config_items, lm_password);
		}
	}

	/*
	 *	We need an NT-Password.
	 */
	nt_password = pairfind(request->config_items, PW_NT_PASSWORD);
	if (nt_password) {
		if ((nt_password->length == 16) ||
		    ((nt_password->length == 32) &&
		     (hex2bin(nt_password->strvalue,
			      nt_password->strvalue, 16) == 16))) {
			DEBUG2("  rlm_mschap: Found NT-Password");
			nt_password->length = 16;

                } else {
			radlog(L_ERR, "rlm_mschap: Invalid NT-Password");
			nt_password = NULL;
		}
	} else if (!password) {
		DEBUG2("  rlm_mschap: No User-Password configured.  Cannot create NT-Password.");

	} else {		/* there is a configured User-Password */
		nt_password = pairmake("NT-Password", "", T_OP_EQ);
		if (!nt_password) {
			radlog(L_ERR, "No memory");
		} else {
			ntpwdhash(nt_password->strvalue, password->strvalue);
			nt_password->length = 16;
			pairadd(&request->config_items, nt_password);
		}
	}

	challenge = pairfind(request->packet->vps, PW_MSCHAP_CHALLENGE);
	if (!challenge) {
		DEBUG2("  rlm_mschap: No MS-CHAP-Challenge in the request");
		return RLM_MODULE_REJECT;
	}

	/*
	 *	We also require an MS-CHAP-Response.
	 */
	response = pairfind(request->packet->vps, PW_MSCHAP_RESPONSE);

	/*
	 *	MS-CHAP-Response, means MS-CHAPv1
	 */
	if (response) {
		int offset;

		/*
		 *	MS-CHAPv1 challenges are 8 octets.
		 */
		if (challenge->length < 8) {
			radlog(L_AUTH, "rlm_mschap: MS-CHAP-Challenge has the wrong format.");
			return RLM_MODULE_INVALID;
		}

		/*
		 *	Responses are 50 octets.
		 */
		if (response->length < 50) {
			radlog(L_AUTH, "rlm_mschap: MS-CHAP-Response has the wrong format.");
			return RLM_MODULE_INVALID;
		}

		/*
		 *	We are doing MS-CHAP.  Calculate the MS-CHAP
		 *	response
		 */
		if (response->strvalue[1] & 0x01) {
			DEBUG2("  rlm_mschap: doing MS-CHAPv1 with NT-Password");
			password = nt_password;
			offset = 26;
		} else {
			DEBUG2("  rlm_mschap: doing MS-CHAPv1 with LM-Password");
			password = lm_password;
			offset = 2;
		}

		/*
		 *	Do the MS-CHAP authentication.
		 */
		if (do_mschap(password, challenge->strvalue,
			      response->strvalue + offset) < 0) {
			DEBUG2("  rlm_mschap: MS-CHAP-Response is incorrect.");
			add_reply(&request->reply->vps, *response->strvalue,
				  "MS-CHAP-Error", "E=691 R=1", 9);
			return RLM_MODULE_REJECT;
		}

		chap = 1;

	} else if ((response = pairfind(request->packet->vps, PW_MSCHAP2_RESPONSE)) != NULL) {
		uint8_t	mschapv1_challenge[16];

		/*
		 *	MS-CHAPv2 challenges are 16 octets.
		 */
		if (challenge->length < 16) {
			radlog(L_AUTH, "rlm_mschap: MS-CHAP-Challenge has the wrong format.");
			return RLM_MODULE_INVALID;
		}

		/*
		 *	Responses are 50 octets.
		 */
		if (response->length < 50) {
			radlog(L_AUTH, "rlm_mschap: MS-CHAP-Response has the wrong format.");
			return RLM_MODULE_INVALID;
		}

		/*
		 *	We also require a User-Name
		 */
		username = pairfind(request->packet->vps, PW_USER_NAME);
		if (!username) {
			radlog(L_AUTH, "rlm_mschap: We require a User-Name for MS-CHAPv2");
			return RLM_MODULE_INVALID;
		}


		/*
		 *	with_ntdomain_hack moved here
		 */
		if ((username_string = strchr(username->strvalue, '\\')) != NULL) {
		        if (inst->with_ntdomain_hack) {
			        username_string++;
			} else {
				DEBUG2("  rlm_mschap: NT Domain delimeter found, should we have enabled with_ntdomain_hack?");
				username_string = username->strvalue;
			}
		} else {
		        username_string = username->strvalue;
		}

		/*
		 *	The old "mschapv2" function has been moved to
		 *	here.
		 *
		 *	MS-CHAPv2 takes some additional data to create an
		 *	MS-CHAPv1 challenge, and then does MS-CHAPv1.
		 */
		challenge_hash(response->strvalue + 2, /* peer challenge */
			       challenge->strvalue, /* our challenge */
			       username_string,	/* user name */
			       mschapv1_challenge); /* resulting challenge */
		
		DEBUG2("  rlm_mschap: doing MS-CHAPv2 with NT-Password");

		if (do_mschap(nt_password, mschapv1_challenge,
			      response->strvalue + 26) < 0) {
			DEBUG2("  rlm_mschap: FAILED: MS-CHAP2-Response is incorrect");
			add_reply(&request->reply->vps, *response->strvalue,
				  "MS-CHAP-Error", "E=691 R=1", 9);
			return RLM_MODULE_REJECT;
		}

		/*
		 *	Get the NT-hash-hash
		 */
		md4_calc(nthashhash, nt_password->strvalue, 16);

		auth_response(username_string, /* without the domain */
			      nthashhash, /* nt-hash-hash */
			      response->strvalue + 26, /* peer response */
			      response->strvalue + 2, /* peer challenge */
			      challenge->strvalue, /* our challenge */
			      msch2resp); /* calculated MPPE key */
		add_reply( &request->reply->vps, *response->strvalue,
			   "MS-CHAP2-Success", msch2resp, 42);
		chap = 2;

	} else {		/* Neither CHAPv1 or CHAPv2 response: die */
		radlog(L_AUTH, "rlm_mschap: No MS-CHAP response found");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	We have a CHAP response, but the account may be
	 *	disabled.  Reject the user with the same error code
	 *	we use when their password is invalid.
	 */
	if (smb_ctrl) {
		/*
		 *	Account is disabled.
		 *
		 *	They're found, but they don't exist, so we
		 *	return 'not found'.
		 */
		if (((smb_ctrl->lvalue & ACB_DISABLED) != 0) ||
		    ((smb_ctrl->lvalue & ACB_NORMAL) == 0)) {
			DEBUG2("  rlm_mschap: SMB-Account-Ctrl says that the account is disabled, or is not a normal account.");
			add_reply( &request->reply->vps, *response->strvalue,
				   "MS-CHAP-Error", "E=691 R=1", 9);
			return RLM_MODULE_NOTFOUND;
		}

		/*
		 *	User is locked out.
		 */
		if ((smb_ctrl->lvalue & ACB_AUTOLOCK) != 0) {
			DEBUG2("  rlm_mschap: SMB-Account-Ctrl says that the account is locked out.");
			add_reply( &request->reply->vps, *response->strvalue,
				   "MS-CHAP-Error", "E=647 R=0", 9);
			return RLM_MODULE_USERLOCK;
		}
	}

	/* now create MPPE attributes */
	if (inst->use_mppe) {
		if (chap == 1){
			DEBUG2("rlm_mschap: adding MS-CHAPv1 MPPE keys");
			memset(mppe_sendkey, 0, 32);
			if (lm_password) {
				memcpy(mppe_sendkey, lm_password->strvalue, 8);
			}

			if (nt_password) {
				/*
				 *	According to RFC 2548 we
				 *	should send NT hash.  But in
				 *	practice it doesn't work.
				 *	Instead, we should send nthashhash
				 *
				 *	This is an error on RFC 2548.
				 */
				md4_calc(mppe_sendkey + 8,
					 nt_password->strvalue, 16);
				mppe_add_reply(&request->reply->vps,
					       "MS-CHAP-MPPE-Keys",
					       mppe_sendkey, 32);
			}
		} else if (chap == 2) {
			DEBUG2("rlm_mschap: adding MS-CHAPv2 MPPE keys");
			mppe_chap2_gen_keys128(nt_password->strvalue,
					       response->strvalue + 26,
					       mppe_sendkey, mppe_recvkey);

			mppe_add_reply(&request->reply->vps,
				       "MS-MPPE-Recv-Key",
				       mppe_recvkey, 16);
			mppe_add_reply(&request->reply->vps,
				       "MS-MPPE-Send-Key",
				       mppe_sendkey, 16);

		}
		reply_attr = pairmake("MS-MPPE-Encryption-Policy",
				      (inst->require_encryption)? "0x00000002":"0x00000001",
				      T_OP_EQ);
		rad_assert(reply_attr != NULL);
		pairadd(&request->reply->vps, reply_attr);
		reply_attr = pairmake("MS-MPPE-Encryption-Types",
				      (inst->require_strong)? "0x00000004":"0x00000006",
				      T_OP_EQ);
		rad_assert(reply_attr != NULL);
		pairadd(&request->reply->vps, reply_attr);

	} /* else we weren't asked to use MPPE */

	return RLM_MODULE_OK;
#undef inst
}

module_t rlm_mschap = {
  "MS-CHAP",
  RLM_TYPE_THREAD_SAFE,		/* type */
  NULL,				/* initialize */
  mschap_instantiate,		/* instantiation */
  {
	  mschap_authenticate,	/* authenticate */
	  mschap_authorize,	/* authorize */
	  NULL,			/* pre-accounting */
	  NULL,			/* accounting */
	  NULL,			/* checksimul */
	  NULL,			/* pre-proxy */
	  NULL,			/* post-proxy */
	  NULL			/* post-auth */
  },
  mschap_detach,		/* detach */
  NULL,				/* destroy */
};
