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
 *  Jay Miller  jaymiller@socket.net
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

#include	"des.h"
#include        "md5.h"
#include	"sha1.h"
#include	"smbpass.h"
#include	"rad_assert.h"

#define PW_MSCHAP_RESPONSE	((311 << 16) | 1)
#define PW_MSCHAP_CHALLENGE	((311 << 16) | 11)
#define PW_MSCHAP2_RESPONSE	((311 << 16) | 25)


typedef enum {
	NONE,
	CLEARTEXT,
	MSCHAP1,
	MSCHAP2} AUTHTYPE;

static void parity_key(char * szOut, const char * szIn);
static void des_encrypt(const char *szClear, const char *szKey, char *szOut);
static void mschap(const char *szChallenge, struct smb_passwd * smbPasswd, char *szResponse, int bUseNT);
static void ntpwdhash (char *szHash, const char *szPassword);
static void lmpwdhash (char *szHash, const char *szPassword);
static struct smb_passwd *createsmbpw(struct smb_passwd *pw_buf, const char* username, const char *password);
static void auth_response(struct smb_passwd * smbPasswd, char *ntresponse,
		char *peer_challenge, char *auth_challenge,
		char *response);
static void challenge_hash( const char* peer_challenge, const char* auth_challenge,
		     const char* user_name, char * challenge );
static void mschap2( const char *peer_challenge, const char *auth_challenge,
		struct smb_passwd * smbPasswd, char *response);
static void add_reply(VALUE_PAIR** vp, unsigned char ident,
                const char* name, const char* value, int len);

static void mppe_add_reply(VALUE_PAIR** vp,
               const char* name, const char* value, int len);

static void mppe_chap2_gen_keys128(uint8_t *secret,uint8_t *vector,
                               uint8_t *nt_hash,uint8_t *response,
                               uint8_t *sendkey,uint8_t *recvkey);

static void mppe_chap2_get_keys128(uint8_t *nt_hashhash,uint8_t *nt_response,
                               uint8_t *sendkey,uint8_t *recvkey);

static void mppe_GetMasterKey(uint8_t *nt_hashhash,uint8_t *nt_response,
                       uint8_t *masterkey);

static void mppe_GetAsymmetricStartKey(uint8_t *masterkey,uint8_t *sesskey,
                               int keylen,int issend);

static void mppe_gen_respkey(uint8_t* secret,uint8_t* vector,
                       uint8_t* salt,uint8_t* enckey,uint8_t* key);

void md4_calc (unsigned char *, unsigned char *, unsigned int);



/* 
 *	parity_key takes a 7-byte string in szIn and returns an
 *	8-byte string in szOut.  It inserts a 1 into every 8th bit.
 *	DES just strips these back out.
 */
static void parity_key(char * szOut, const char * szIn)
{
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
static void des_encrypt(const char *szClear, const char *szKey, char *szOut)
{
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
 *	lmpwdhash converts 14-byte null-padded uppercase OEM
 *	password to 16-byte DES hash with predefined salt string
 */
static void lmpwdhash (char *szHash, const char *szPassword)
{
	char szOEMPass[14];
	char stdText[] = "KGS!@#$%";
	int i;

	memset(szOEMPass, 0, 14);
	for (i = 0; i < 14 && szPassword[i]; i++)
		szOEMPass[i] = toupper(szPassword[i]);

	/* Obtain DES hash of OEM password */
	des_encrypt(stdText, szOEMPass, szHash); 
	des_encrypt(stdText, szOEMPass+7, szHash+8);
}

/*
 *	createsmbpw() creates smb_passwd structure from given
 *	user name and cleartext or ntlm-encrypter password
 *	if encrypted flag is not set only cleartext password
 *	allowed
 */
static struct smb_passwd *createsmbpw(struct smb_passwd *pw_buf, const char * username, const char *password)
{
	if(pw_buf == NULL) {
		return NULL;
	}
	pdb_init_smb(pw_buf);
	pw_buf->acct_ctrl = ACB_NORMAL;
	pw_buf->smb_userid = 0;
	setsmbname(pw_buf,username);
  
	if (pw_buf->smb_passwd==NULL && pw_buf->smb_nt_passwd==NULL) {
		ntpwdhash(pw_buf->smb_nt_passwd_value, password);
		lmpwdhash(pw_buf->smb_passwd_value, password);
		pw_buf->smb_passwd = pw_buf->smb_passwd_value;
		pw_buf->smb_nt_passwd = pw_buf->smb_nt_passwd_value;
	}
	return pw_buf;
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


/*
 *	challenge_hash() is used by mschap2() and auth_response()
 *	implements RFC2759 ChallengeHash()
 *	generates 64 bit challenge
 */
static void challenge_hash( const char* peer_challenge, const char* auth_challenge,
		     const char* user_name, char * challenge )
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

static void mschap2( const char *peer_challenge, const char *auth_challenge,
		struct smb_passwd * smbPasswd, char *response)
{
	char challenge[8];
	
	challenge_hash(peer_challenge, auth_challenge, smbPasswd->smb_name,
		challenge);
	mschap(challenge, smbPasswd, response, 1);
}

/*
 *	auth_response() generates MS-CHAP v2 SUCCESS response
 *	according to RFC 2759 GenerateAuthenticatorResponse()
 *	returns 42-octet response string
 */
static void auth_response(struct smb_passwd * smbPasswd, char *ntresponse,
		char *peer_challenge, char *auth_challenge,
		char *response)
{
	SHA1_CTX Context;
	char hashhash[16];
	char magic1[39] =
               {0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
                0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
                0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
                0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74};
                                             
	char magic2[41] =
               {0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
                0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
                0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
                0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
                0x6E};
        char challenge[8];
        char digest[20];

	/*
	 * Hash password hash into hashhash
	 */

	md4_calc(hashhash, smbPasswd->smb_nt_passwd, 16);

	SHA1Init(&Context);
	SHA1Update(&Context, hashhash, 16);
	SHA1Update(&Context, ntresponse, 24);
	SHA1Update(&Context, magic1, 39);
	SHA1Final(digest, &Context);
	challenge_hash(peer_challenge, auth_challenge, smbPasswd->smb_name,
		challenge);
	SHA1Init(&Context);
	SHA1Update(&Context, digest, 20);
	SHA1Update(&Context, challenge, 8);
	SHA1Update(&Context, magic2, 41);
	SHA1Final(digest, &Context);

	/*
	 * Encode the value of 'Digest' as "S=" followed by
	 * 40 ASCII hexadecimal digits and return it in
	 * AuthenticatorResponse.
	 * For example,
	 *   "S=0123456789ABCDEF0123456789ABCDEF01234567"
	 */
 
	response[0] = 'S';
	response[1] = '=';
	bin2hex(digest, response + 2, 20);
}

struct mschap_instance {
	int ignore_password;
	int use_mppe;
	int require_encryption;
	int require_strong;
	char *passwd_file;
	char *auth_type;
};

static CONF_PARSER module_config[] = {
	/*
	 *	Cache the password by default.
	 */
	{ "ignore_password",    PW_TYPE_BOOLEAN,
	  offsetof(struct mschap_instance,ignore_password), NULL, "no" },
	{ "use_mppe",    PW_TYPE_BOOLEAN,
	  offsetof(struct mschap_instance,use_mppe), NULL, "yes" },
	{ "require_encryption",    PW_TYPE_BOOLEAN,
	  offsetof(struct mschap_instance,require_encryption), NULL, "no" },
	{ "require_strong",    PW_TYPE_BOOLEAN,
	  offsetof(struct mschap_instance,require_strong), NULL, "no" },
	{ "passwd",   PW_TYPE_STRING_PTR,
	  offsetof(struct mschap_instance, passwd_file), NULL,  NULL },
	{ "authtype",   PW_TYPE_STRING_PTR,
	  offsetof(struct mschap_instance, auth_type), NULL,  NULL },
	
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

/*
 *	Create instance for our module. Allocate space for
 *	instance structure and read configuration parameters
 */
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

/*
 *	deinstantiate module, free all memory allocated during
 *	mschap_instantiate()
 */
static int mschap_detach(void *instance){
#define inst ((struct mschap_instance *)instance)
	if (inst->passwd_file) free(inst->passwd_file);
	if (inst->auth_type) free(inst->auth_type);
	free(instance);
	return 0;
#undef inst
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
		DEBUG("rlm_mschap: add_reply failed to create attribute %s: %s\n", name, librad_errstr);
		return;
	}

	reply_attr->strvalue[0] = ident;
	memcpy(reply_attr->strvalue + 1, value, len);
	reply_attr->length = len + 1;
	pairadd(vp, reply_attr);
}

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

static void mppe_chap2_gen_keys128(uint8_t *secret,uint8_t *vector,
                               uint8_t *nt_hash,uint8_t *response,
                               uint8_t *sendkey,uint8_t *recvkey)
{
	uint8_t enckey1[16];
	uint8_t enckey2[16];
	uint8_t salt[2];
	uint8_t nt_hashhash[16];

	md4_calc(nt_hashhash,nt_hash,16);

	mppe_chap2_get_keys128(nt_hashhash,response,enckey1,enckey2);

	salt[0] = (vector[0] ^ vector[1] ^ 0x3A) | 0x80;
	salt[1] = (vector[2] ^ vector[3] ^ vector[4]);

	mppe_gen_respkey(secret,vector,salt,enckey1,sendkey);

	salt[0] = (vector[0] ^ vector[1] ^ 0x4e) | 0x80;
	salt[1] = (vector[5] ^ vector[6] ^ vector[7]);

	mppe_gen_respkey(secret,vector,salt,enckey2,recvkey);
}

static void mppe_chap2_get_keys128(uint8_t *nt_hashhash,uint8_t *nt_response,
                               uint8_t *sendkey,uint8_t *recvkey)
{
       uint8_t masterkey[16];

       mppe_GetMasterKey(nt_hashhash,nt_response,masterkey);

       mppe_GetAsymmetricStartKey(masterkey,sendkey,16,1);
       mppe_GetAsymmetricStartKey(masterkey,recvkey,16,0);
}

static uint8_t SHSpad1[40] =
               { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static uint8_t SHSpad2[40] =
               { 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
                 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
                 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
                 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2 };

static uint8_t magic1[27] =
               { 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
                 0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
                 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79 };

static uint8_t magic2[84] =
               { 0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
                 0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
                 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
                 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
                 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
                 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
                 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
                 0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
                 0x6b, 0x65, 0x79, 0x2e };

static uint8_t magic3[84] =
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
       uint8_t *s;
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

static void mppe_gen_respkey(uint8_t* secret,uint8_t* vector,
                       uint8_t* salt,uint8_t* enckey,uint8_t* key)
{
       uint8_t plain[32];
       uint8_t buf[16];
       int i;
       MD5_CTX Context;
       int slen = strlen(secret);

       memset(key,0,34);

       memset(plain,0,32);
       plain[0] = 16;
       memcpy(plain + 1,enckey,16);

       MD5Init(&Context);
       MD5Update(&Context,secret,slen);
       MD5Update(&Context,vector,AUTH_VECTOR_LEN);
       MD5Update(&Context,salt,2);
       MD5Final(buf,&Context);

       for(i=0;i < 16;i++) {
               plain[i] ^= buf[i];
       }

       MD5Init(&Context);
       MD5Update(&Context,secret,slen);
       MD5Update(&Context,plain,16);
       MD5Final(buf,&Context);

       for(i=0;i < 16;i++) {
               plain[i + 16] ^= buf[i];
       }

       memcpy(key,salt,2);
       memcpy(key + 2,plain,32);
}


/*
 *	mschap_authorize() - authorize user if we can authenticate
 *	it later. Add Auth-Type attribute if present in module
 *	configuration (usually Auth-Type must be "MS-CHAP")
 */
static int mschap_authorize(void * instance, REQUEST *request)
{
#define inst ((struct mschap_instance *)instance)
	VALUE_PAIR *challenge = NULL, *response = NULL;
	VALUE_PAIR *reply_attr;
	VALUE_PAIR *password = NULL;
	struct smb_passwd smbPasswdValue, *smbPasswd = NULL;

	
	password = pairfind(request->config_items, PW_PASSWORD);
	challenge = pairfind(request->packet->vps, PW_MSCHAP_CHALLENGE);
	if (challenge) {
		response = pairfind(request->packet->vps, PW_MSCHAP_RESPONSE);
		if (!response)
			response = pairfind(request->packet->vps, PW_MSCHAP2_RESPONSE);
	}
	if (password && (!challenge || !response)) {
		/*  We have nothing related to MS-CHAP or NTLM */
		return RLM_MODULE_NOOP;
	}
	if (!request->username || *request->username->strvalue == 0) {
		/* Usernam must present */
		return RLM_MODULE_NOOP;
	}
	if (password && !inst->ignore_password)
		smbPasswd = createsmbpw(&smbPasswdValue, request->username->strvalue, password->strvalue);
	else if (inst->passwd_file) {
		smbPasswd = getsmbfilepwname (&smbPasswdValue, inst->passwd_file, request->username->strvalue);
	}
	if (!smbPasswd || !smbPasswd->acct_ctrl&ACB_NORMAL ||smbPasswd->acct_ctrl&ACB_DISABLED) {
		if(challenge && response){
			add_reply( &request->reply->vps, *response->strvalue,
				"MS-CHAP-Error", "E=691 R=1", 9);
		}
		return RLM_MODULE_NOTFOUND;
	}
	if (inst->auth_type){
		pairdelete(&request->config_items, PW_AUTHTYPE);
		reply_attr = pairmake("Auth-Type", inst->auth_type, T_OP_EQ);
		rad_assert(reply_attr != NULL);
		pairadd(&request->config_items, reply_attr);
	}
	if (smbPasswd->smb_passwd){
		reply_attr = pairmake("LM-Password", "", T_OP_EQ);
		rad_assert(reply_attr != NULL);
		reply_attr->length = 16;
		memcpy(reply_attr->strvalue, smbPasswd->smb_passwd, 16);
		pairadd(&request->config_items, reply_attr);
	}
	if (smbPasswd->smb_nt_passwd){
		reply_attr = pairmake("NT-Password", "", T_OP_EQ);
		rad_assert(reply_attr != NULL);
		reply_attr->length = 16;
		memcpy(reply_attr->strvalue, smbPasswd->smb_nt_passwd, 16);
		pairadd(&request->config_items, reply_attr);
	}

	reply_attr = pairmake("SMB-Account-CTRL", "0", T_OP_EQ);
	rad_assert(reply_attr != NULL);
	reply_attr->lvalue = smbPasswd->acct_ctrl;
	pairadd(&request->config_items, reply_attr);
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
#define inst ((struct mschap_instance *)instance)
	VALUE_PAIR *challenge = NULL, *response = NULL;
	VALUE_PAIR *password = NULL;
	VALUE_PAIR *reply_attr;
	uint8_t calculated[32];
	uint8_t msch2resp[42];
        uint8_t mppe_sendkey[34];
        uint8_t mppe_recvkey[34];
	struct smb_passwd smbPasswd, smbPasswd1Value, *smbPasswd1 = NULL;
	AUTHTYPE at = NONE;
	int res = 0;
	int len = 0;
	int chap = 0;
	
	
	
	pdb_init_smb(&smbPasswd);
	setsmbname(&smbPasswd,request->username->strvalue);
	password = pairfind(request->config_items, PW_SMB_ACCOUNT_CTRL);
	if(password){
		smbPasswd.acct_ctrl = password->lvalue;
		if (smbPasswd.acct_ctrl&ACB_PWNOTREQ) return RLM_MODULE_OK;
	}
	password = pairfind(request->config_items, PW_LM_PASSWORD);
	if(password){
		res++;
		smbPasswd.smb_passwd = password->strvalue;
	}
	password = pairfind(request->config_items, PW_NT_PASSWORD);
	if(password){
		res++;
		smbPasswd.smb_nt_passwd = password->strvalue;
	}
	if (!res) {
		/*
		 * We have neither NT nor LM passwords configured
	 	 */
	 	return RLM_MODULE_INVALID;
	 }
	
	/*
	 *	If NAS sent cleartext password - encode it and check
	 *	only against passwd file. If either NT or LM hash match
	 *	return OK.
	 */

	password = pairfind(request->packet->vps, PW_PASSWORD);
	if (password && request->username && *request->username->strvalue!= 0) {
		at = CLEARTEXT;
		smbPasswd1 = createsmbpw(&smbPasswd1Value,request->username->strvalue, password->strvalue);
		if ( (smbPasswd.smb_passwd && !memcmp(smbPasswd1->smb_passwd, smbPasswd.smb_passwd, 16)) ||
			(smbPasswd.smb_nt_passwd && !memcmp(smbPasswd1->smb_nt_passwd, smbPasswd.smb_nt_passwd, 16)) )
			return RLM_MODULE_OK;
		else return RLM_MODULE_REJECT;
	}
	else if ( (challenge = pairfind(request->packet->vps, PW_MSCHAP_CHALLENGE)) ){
		/*
		 *	We need an MS-CHAP-Challenge attribute to calculate
		 *	the response.
		 */
		res = RLM_MODULE_REJECT;
		if ( (response = pairfind(request->packet->vps, PW_MSCHAP_RESPONSE)) ){
			if (response->length < 50 || challenge->length < 8) {
				radlog(L_AUTH, "rlm_mschap: Attribute \"MS-CHAP-Response\" has wrong format.");
				return RLM_MODULE_INVALID;
			}
			/*
			 *	We are doing MS-CHAP
			 *	Calculate the MS-CHAP response
			 */
			if (smbPasswd.smb_nt_passwd && (response->strvalue[1] & 0x01)) {
			/*
			 * Try NT response first if UseNT flag is set
			 */
				mschap(challenge->strvalue, &smbPasswd, calculated, 1);
				if (memcmp(response->strvalue + 26, calculated, 24) == 0) {
					res = RLM_MODULE_OK;
				}
			 }

			if (res != RLM_MODULE_OK && smbPasswd.smb_passwd) {
			/*
			 *	Use LM response.
			 */
				mschap(challenge->strvalue, &smbPasswd, 
					calculated, 0);
				if (memcmp(response->strvalue + 2, calculated, 24) == 0) {
					res = RLM_MODULE_OK;
				}
	    		}
	    		chap = 1;
		}
		else if ( (response = pairfind(request->packet->vps, PW_MSCHAP2_RESPONSE)) ){
			if (response->length < 50 || challenge->length < 16) {
				radlog(L_AUTH, "rlm_mschap: Attribute \"MS-CHAP2-Response\" has wrong format.");
				return RLM_MODULE_INVALID;
			}
			/*
			 *	We are doing MS-CHAPv2
			 *	We need NT hash for it to calculate response
			 */
			if (smbPasswd.smb_nt_passwd) {
				mschap2(response->strvalue + 2,  challenge->strvalue,
					&smbPasswd, calculated);
				if (memcmp(response->strvalue + 26, calculated, 24) == 0) {
					auth_response(&smbPasswd, calculated,
						response->strvalue + 2,
						challenge->strvalue,
						msch2resp);
					add_reply( &request->reply->vps, *response->strvalue,
						"MS-CHAP2-Success", msch2resp, 42);
					res = RLM_MODULE_OK;
					chap = 2;
				}
			}
		}
		else {
			radlog(L_AUTH, "rlm_mschap: Response attribute is not found");
			return RLM_MODULE_INVALID;
		}
		if (res == RLM_MODULE_OK){
			if (smbPasswd.acct_ctrl&ACB_AUTOLOCK) {
				add_reply( &request->reply->vps, *response->strvalue,
					"MS-CHAP-Error", "E=647 R=0", 9);
				return RLM_MODULE_USERLOCK;
			}

			/* now create MPPE attributes */
			if (inst->use_mppe) {
				if (chap == 1){
					memset (mppe_sendkey, 0, 32);
					if (smbPasswd.smb_passwd) 
						memcpy(mppe_sendkey, smbPasswd.smb_passwd, 8);
					if (smbPasswd.smb_nt_passwd)
					/* 
					   According to RFC 2548 we should send NT hash.
					   But in practice it doesn't work and we should
					   send nthashhash instead
					   If someone have different information please
					   feel free to feedback.

						memcpy (mppe_sendkey+8,smbPasswd.smb_nt_passwd,16);   
					*/
						md4_calc(mppe_sendkey+8, smbPasswd.smb_nt_passwd,16);
					len = 32;
					rad_pwencode(mppe_sendkey, &len, 
						 request->secret, request->packet->vector);
					mppe_add_reply( &request->reply->vps,
						"MS-CHAP-MPPE-Keys",mppe_sendkey,len);
				}
				else if (chap == 2){
					mppe_chap2_gen_keys128(request->secret,request->packet->vector,
						smbPasswd.smb_nt_passwd,
						response->strvalue + 26,
						mppe_sendkey,mppe_recvkey);
					mppe_add_reply( &request->reply->vps,
						"MS-MPPE-Recv-Key",mppe_recvkey,34);
					mppe_add_reply( &request->reply->vps,
						"MS-MPPE-Send-Key",mppe_sendkey,34);
				}
				reply_attr = pairmake("MS-MPPE-Encryption-Policy",
					(inst->require_encryption)? "0x00000002":"0x00000001",
					T_OP_EQ);
				rad_assert(reply_attr != NULL);
				pairadd(&request->reply->vps, reply_attr);
				reply_attr = pairmake("MS-MPPE-Encryption-Types",
					(inst->require_strong)? "0x00000004":"0x0000006",
					T_OP_EQ);
				rad_assert(reply_attr != NULL);
				pairadd(&request->reply->vps, reply_attr);
			
			}
			return res;
		}
	}
	
	add_reply( &request->reply->vps, *response->strvalue,
		"MS-CHAP-Error", "E=691 R=1", 9);
	return RLM_MODULE_REJECT;
#undef inst
}

module_t rlm_mschap = {
  "MS-CHAP",
  RLM_TYPE_THREAD_SAFE,				/* type */
  NULL,				/* initialize */
  mschap_instantiate,		/* instantiation */
  {
	  mschap_authenticate,	/* authenticate */
	  mschap_authorize,	/* authorize */
	  NULL,			/* pre-accounting */
	  NULL,			/* accounting */
	  NULL			/* checksimul */
  },
  mschap_detach,		/* detach */
  NULL,				/* destroy */
};
