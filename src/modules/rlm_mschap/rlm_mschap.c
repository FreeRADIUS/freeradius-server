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
#include 	<ctype.h>

#include	"radiusd.h"
#include	"modules.h"

#include	"des.h"
#include        "md4.h"
#include	"smbpass.h"

#define PW_MSCHAP_RESPONSE  ((dict_vendorcode(311) << 16) | 1)
#define PW_MSCHAP_CHALLENGE ((dict_vendorcode(311) << 16) | 11)

static void parity_key(char * szOut, const char * szIn);
static void des_encrypt(const char *szClear, const char *szKey, char *szOut);
static void mschap(const char *szChallenge, struct smb_passwd * smbPasswd, char *szResponse, int bUseNT);
void ntpwdhash (char *szHash, const char *szPassword);
void lmpwdhash (char *szHash, const char *szPassword);
struct smb_passwd *createsmbpw(char *password, int encode);

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
 *	ntpwdhash converts Unicode password to 16-byte NT hash
 *	with MD4
 */
void ntpwdhash (char *szHash, const char *szPassword){
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
 *	lmpwdhash converts 14-byte null-padded uppercase OEM
 *	password to 16-byte DES hash with predefined salt string
 */
void lmpwdhash (char *szHash, const char *szPassword){
	char szOEMPass[14];
	char stdText[] = "KGS!@#$%";
	int i;

	memset(szOEMPass, 0, 14);
	for(i = 0; i < 14 && szPassword[i]; i++)
		szOEMPass[i] = toupper(szPassword[i]);

	/* Obtain DES hash of OEM password */
	des_encrypt(stdText, szOEMPass, szHash); 
	des_encrypt(stdText, szOEMPass+7, szHash+8);
}


struct smb_passwd *createsmbpw(char *password, int encrypted)
{
  char * colon;
  static struct smb_passwd pw_buf;
  static unsigned char smbpwd[16];
  static unsigned char smbntpwd[16];


  pdb_init_smb(&pw_buf);
  pw_buf.acct_ctrl = ACB_NORMAL;
  pw_buf.smb_userid = 0;
  
  if(encrypted){
	if(hex2bin(password, smbpwd, 16) == 16 && password[32]==':'){
		pw_buf.smb_passwd=smbpwd;
	}
	colon = strchr(password, ':');
	if(colon && hex2bin(colon + 1, smbntpwd, 16) == 16){
		pw_buf.smb_nt_passwd = smbntpwd;
	}
  }	
  if(pw_buf.smb_passwd==NULL && pw_buf.smb_nt_passwd==NULL){
	ntpwdhash(smbntpwd, password);
	lmpwdhash(smbpwd, password);
	pw_buf.smb_passwd=smbpwd;
	pw_buf.smb_nt_passwd = smbntpwd;
  }
  return &pw_buf;
}



/*
 *	mschap takes an 8-byte challenge string and SMB password
 *	and returns a 24-byte response string in szResponse
 */
static void mschap(const char *szChallenge, struct smb_passwd * smbPasswd,
	char *szResponse, int bUseNT) {

	char szMD4[21];
	
	/* initialize hash string */
	memset(szMD4, 0, 21);
	
	memcpy(szMD4, (bUseNT)?
		smbPasswd->smb_nt_passwd : smbPasswd->smb_passwd, 16);
	
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

struct mschap_instance {
	int ignore_password;
	char *passwd_file;
};

static CONF_PARSER module_config[] = {
	/*
	 *	Cache the password by default.
	 */
	{ "ignore_password",    PW_TYPE_BOOLEAN,
	  offsetof(struct mschap_instance,ignore_password), NULL, "no" },
	{ "passwd",   PW_TYPE_STRING_PTR,
	  offsetof(struct mschap_instance,passwd_file), NULL,  NULL },
	
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

static int mschap_instantiate(CONF_SECTION *conf, void **instance)
{
	struct mschap_instance *inst;

	inst = *instance = rad_malloc(sizeof(struct mschap_instance));
	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}
	return 0;
}

static int mschap_detach(void *instance){
#define inst ((struct mschap_instance *)instance)
	if(inst->passwd_file)free(inst->passwd_file);
	free(instance);
	return 0;
#undef inst
}

/* validate userid/passwd */
static int mschap_auth(void * instance, REQUEST *request)
{
#define inst ((struct mschap_instance *)instance)
	VALUE_PAIR *password = NULL;
	VALUE_PAIR *challenge = NULL, *response = NULL;
	uint8_t calculated[32];
	struct smb_passwd *smbPasswd = NULL, *smbPasswd1 = NULL;
	int cleartext = 0;

	/*instance = instance;*/	/* -Wunused */

	/*
	 *	We need an MS-CHAP-Challenge attribute to calculate
	 *	the response.
	 */
	password = pairfind(request->packet->vps, PW_PASSWORD);
	if (password) {
		cleartext = 1;
		smbPasswd1 = createsmbpw(password->strvalue, 0);
	} else {
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
		if (response->length < 50) {
			radlog(L_AUTH, "rlm_mschap: Attribute \"MS-CHAP-Response\" has wrong format.");
			return RLM_MODULE_INVALID;
		}
	}

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a Password attribute.
	 *	Password can be either cleartext or NTLM-encoded
	 *	password in SAMBA format (hexadecimal string with
	 *	':' between LM and NT, like
	 *	aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
	 */
	if (!cleartext) password = pairfind(request->config_items, PW_PASSWORD);
	if (!cleartext && password && !inst->ignore_password)
		smbPasswd = createsmbpw(password->strvalue, 1);
	else if(inst->passwd_file){
		smbPasswd = getsmbfilepwname (inst->passwd_file, request->username->strvalue);
	}
	if(!smbPasswd){
		radlog(L_AUTH, "rlm_mschap: Configuration item \"Password\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}
	if(smbPasswd->acct_ctrl&ACB_DISABLED || smbPasswd->acct_ctrl&ACB_AUTOLOCK){
		return RLM_MODULE_REJECT;
	}
	if(smbPasswd->acct_ctrl&ACB_PWNOTREQ)return RLM_MODULE_OK;
	
	/*
	 *	If NAS sent cleartext password - encode it and check
	 *	only against passwd file. If either NT or LM hash match
	 *	return OK.
	 */
	if(cleartext){
		if ( (smbPasswd->smb_passwd && !memcmp(smbPasswd1->smb_passwd, smbPasswd->smb_passwd, 16)) ||
			(smbPasswd->smb_nt_passwd && !memcmp(smbPasswd1->smb_nt_passwd, smbPasswd->smb_nt_passwd, 16)) )
			return RLM_MODULE_OK;
		else return RLM_MODULE_REJECT;
	}

	/*
	 *	We are given with MS-CHAP
	 *	Calculate the MS-CHAP response
	 */
	if((response->strvalue[1] & 0x01) == 0 && smbPasswd->smb_passwd){
	/*
	 *	"Use NT response" flag is not set. Use LM response
	 *	first.
	 */
		mschap(challenge->strvalue, smbPasswd, 
			calculated, 0);
		if (memcmp(response->strvalue + 2, calculated, 24) == 0) {
			return RLM_MODULE_OK;
		}
	}
	if(smbPasswd->smb_nt_passwd){
		mschap(challenge->strvalue, smbPasswd, calculated, 1);
		if (memcmp(response->strvalue + 26, calculated, 24) == 0) {
			return RLM_MODULE_OK;
		}
	}
	
	return RLM_MODULE_REJECT;
#undef inst
}

module_t rlm_mschap = {
  "MS-CHAP",
  0,				/* type */
  NULL,				/* initialize */
  mschap_instantiate,		/* instantiation */
  {
	  mschap_auth,		/* authenticate */
	  NULL,			/* authorize */
	  NULL,			/* pre-accounting */
	  NULL,			/* accounting */
	  NULL			/* checksimul */
  },
  mschap_detach,		/* detach */
  NULL,				/* destroy */
};
