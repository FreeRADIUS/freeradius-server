/*
 * rlm_pap.c
 *
 * Version:  $Id$
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
 * Copyright 2001,2006  The FreeRADIUS server project
 * Copyright 2001  Kostas Kalevras <kkalev@noc.ntua.gr>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <ctype.h>

#include "../../include/md5.h"
#include "../../include/sha1.h"

#define PAP_ENC_INVALID	-1
#define PAP_ENC_CLEAR		0
#define PAP_ENC_CRYPT		1
#define PAP_ENC_MD5		2
#define PAP_ENC_SHA1		3
#define PAP_ENC_NT		4
#define PAP_ENC_LM		5
#define PAP_ENC_SMD5		6
#define PAP_ENC_SSHA		7
#define PAP_ENC_NS_MTA_MD5	8
#define PAP_ENC_AUTO		9
#define PAP_MAX_ENC		9


/*
 *      Define a structure for our module configuration.
 *
 *      These variables do not need to be in a structure, but it's
 *      a lot cleaner to do so, and a pointer to the structure can
 *      be used as the instance handle.
 */
typedef struct rlm_pap_t {
	const char *name;	/* CONF_SECTION->name, not strdup'd */
        char *scheme;  /* password encryption scheme */
	int sch;
	char norm_passwd;
	int auto_header;
} rlm_pap_t;

/*
 *      A mapping of configuration file names to internal variables.
 *
 *      Note that the string is dynamically allocated, so it MUST
 *      be freed.  When the configuration file parse re-reads the string,
 *      it free's the old one, and strdup's the new one, placing the pointer
 *      to the strdup'd string into 'config.string'.  This gets around
 *      buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
	{ "encryption_scheme", PW_TYPE_STRING_PTR, offsetof(rlm_pap_t,scheme), NULL, "auto" },
	{ "auto_header", PW_TYPE_BOOLEAN, offsetof(rlm_pap_t,auto_header), NULL, "no" },
	{ NULL, -1, 0, NULL, NULL }
};

static const LRAD_NAME_NUMBER schemes[] = {
	{ "clear", PAP_ENC_CLEAR },
	{ "crypt", PAP_ENC_CRYPT },
	{ "md5", PAP_ENC_MD5 },
	{ "sha1", PAP_ENC_SHA1 },
	{ "nt", PAP_ENC_NT },
	{ "lm", PAP_ENC_LM },
	{ "smd5", PAP_ENC_SMD5 },
	{ "ssha", PAP_ENC_SSHA },
	{ "auto", PAP_ENC_AUTO },
	{ NULL, PAP_ENC_INVALID }
};


/*
 *	For auto-header discovery.
 */
static const LRAD_NAME_NUMBER header_names[] = {
	{ "{clear}",	PW_CLEARTEXT_PASSWORD },
	{ "{cleartext}", PW_CLEARTEXT_PASSWORD },
	{ "{md5}",	PW_MD5_PASSWORD },
	{ "{smd5}",	PW_SMD5_PASSWORD },
	{ "{crypt}",	PW_CRYPT_PASSWORD },
	{ "{sha}",	PW_SHA_PASSWORD },
	{ "{ssha}",	PW_SSHA_PASSWORD },
	{ "{nt}",	PW_NT_PASSWORD },
	{ "{x-nthash}",	PW_NT_PASSWORD },
	{ "{ns-mta-md5}", PW_NS_MTA_MD5_PASSWORD },
	{ NULL, 0 }
};


static int pap_detach(void *instance)
{
	rlm_pap_t *inst = (rlm_pap_t *) instance;

	free(inst);

	return 0;
}


static int pap_instantiate(CONF_SECTION *conf, void **instance)
{
        rlm_pap_t *inst;

        /*
         *      Set up a storage area for instance data
         */
        inst = rad_malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

        /*
         *      If the configuration parameters can't be parsed, then
         *      fail.
         */
        if (cf_section_parse(conf, inst, module_config) < 0) {
		pap_detach(inst);
                return -1;
        }
	if (inst->scheme == NULL || strlen(inst->scheme) == 0){
		radlog(L_ERR, "rlm_pap: No scheme defined");
		pap_detach(inst);
		return -1;
	}

	inst->sch = lrad_str2int(schemes, inst->scheme, PAP_ENC_INVALID);
	if (inst->sch == PAP_ENC_INVALID) {
		radlog(L_ERR, "rlm_pap: Unknown scheme \"%s\"", inst->scheme);
		pap_detach(inst);
		return -1;
	}

        *instance = inst;
	inst->name = cf_section_name2(conf);
	if (!inst->name) {
		inst->name = cf_section_name1(conf);
	}

        return 0;
}


/*
 *	Decode one base64 chunk
 */
static int decode_it(const char *src, uint8_t *dst)
{
	int i;
	unsigned int x = 0;

	for(i = 0; i < 4; i++) {
		if (src[i] >= 'A' && src[i] <= 'Z')
			x = (x << 6) + (unsigned int)(src[i] - 'A' + 0);
		else if (src[i] >= 'a' && src[i] <= 'z')
			 x = (x << 6) + (unsigned int)(src[i] - 'a' + 26);
		else if(src[i] >= '0' && src[i] <= '9') 
			 x = (x << 6) + (unsigned int)(src[i] - '0' + 52);
		else if(src[i] == '+')
			x = (x << 6) + 62;
		else if (src[i] == '/')
			x = (x << 6) + 63;
		else if (src[i] == '=')
			x = (x << 6);
		else return 0;
	}
	
	dst[2] = (unsigned char)(x & 255); x >>= 8;
	dst[1] = (unsigned char)(x & 255); x >>= 8;
	dst[0] = (unsigned char)(x & 255); x >>= 8;
	
	return 1;
}


/*
 *	Base64 decoding.
 */
static int base64_decode (const char *src, uint8_t *dst)
{
	int length, equals;
	int i, num;
	char last[3];

	length = equals = 0;
	while (src[length] && src[length] != '=') length++;

	while (src[length + equals] == '=') equals++;

	num = (length + equals) / 4;
	
	for (i = 0; i < num - 1; i++) {
		if (!decode_it(src, dst)) return 0;
		src += 4;
		dst += 3;
	}

	decode_it(src, last);
	for (i = 0; i < (3 - equals); i++) {
		dst[i] = last[i];
	}

	return (num * 3) - equals;
}


/*
 *	Hex or base64 or bin auto-discovery.
 */
static void normify(VALUE_PAIR *vp, int min_length)
{
	int decoded;
	char buffer[64];
	
	if ((size_t) min_length >= sizeof(buffer)) return; /* paranoia */

	/*
	 *	Hex encoding.
	 */
	if (vp->length >= (2 * min_length)) {
		decoded = lrad_hex2bin(vp->vp_octets, buffer, vp->length >> 1);
		if (decoded == (vp->length >> 1)) {
			DEBUG2("rlm_pap: Normalizing %s from hex encoding", vp->name);
			memcpy(vp->vp_octets, buffer, decoded);
			vp->length = decoded;
			return;
		}
	}

	/*
	 *	Base 64 encoding.  It's at least 4/3 the original size,
	 *	and we want to avoid division...
	 */
	if ((vp->length * 3) >= ((min_length * 4))) {
		decoded = base64_decode(vp->vp_octets, buffer);
		if (decoded >= min_length) {
			DEBUG2("rlm_pap: Normalizing %s from base64 encoding", vp->name);
			memcpy(vp->vp_octets, buffer, decoded);
			vp->length = decoded;
			return;
		}
	}

	/*
	 *	Else unknown encoding, or already binary.  Leave it.
	 */
}


/*
 *	Authorize the user for PAP authentication.
 *
 *	This isn't strictly necessary, but it does make the
 *	server simpler to configure.
 */
static int pap_authorize(void *instance, REQUEST *request)
{
	rlm_pap_t *inst = instance;
	int auth_type = FALSE;
	int found_pw = FALSE;
	VALUE_PAIR *vp, *next;

	for (vp = request->config_items; vp != NULL; vp = next) {
		next = vp->next;

		switch (vp->attribute) {
		case PW_USER_PASSWORD: /* deprecated */
			found_pw = TRUE;

			/*
			 *	Look for '{foo}', and use them
			 */
			if (!inst->auto_header ||
			    (vp->vp_strvalue[0] != '{')) {
				break;
			}
			/* FALL-THROUGH */

		case PW_PASSWORD_WITH_HEADER: /* preferred */
		{
			int attr;
			uint8_t *p, *q;
			char buffer[64];
			VALUE_PAIR *new_vp;
			
			found_pw = TRUE;
			q = vp->vp_strvalue;
			p = strchr(q + 1, '}');
			if (!p) {
				/*
				 *	FIXME: Turn it into a
				 *	cleartext-password, unless it,
				 *	or user-password already
				 *	exists.
				 */
				break;
			}
			
			if ((size_t) (p - q) > sizeof(buffer)) break;
			
			memcpy(buffer, q, p - q + 1);
			buffer[p - q + 1] = '\0';
			
			attr = lrad_str2int(header_names, buffer, 0);
			if (!attr) {
				DEBUG2("rlm_pap: Found unknown header {%s}: Not doing anything", buffer);
				break;
			}
			
			new_vp = paircreate(attr, PW_TYPE_STRING);
			if (!new_vp) break; /* OOM */
			
			strcpy(new_vp->vp_strvalue, p + 1);/* bounds OK */
			new_vp->length = strlen(new_vp->vp_strvalue);
			pairadd(&request->config_items, new_vp);

			/*
			 *	May be old-style User-Password with header.
			 *	We've found the header & created the proper
			 *	attribute, so we should delete the old
			 *	User-Password here.
			 */
			pairdelete(&request->config_items, PW_USER_PASSWORD);
		}
			break;

		case PW_CLEARTEXT_PASSWORD:
		case PW_CRYPT_PASSWORD:
		case PW_NS_MTA_MD5_PASSWORD:
			found_pw = TRUE;
			break;	/* don't touch these */

		case PW_MD5_PASSWORD:
		case PW_SMD5_PASSWORD:
		case PW_NT_PASSWORD:
		case PW_LM_PASSWORD:
			normify(vp, 16); /* ensure it's in the right format */
			found_pw = TRUE;
			break;

		case PW_SHA_PASSWORD:
		case PW_SSHA_PASSWORD:
			normify(vp, 20); /* ensure it's in the right format */
			found_pw = TRUE;
			break;

			/*
			 *	If it's proxied somewhere, don't complain
			 *	about not having passwords or Auth-Type.
			 */
		case PW_PROXY_TO_REALM:
		{
			REALM *realm = realm_find(vp->vp_strvalue);
			if (realm && !realm->auth_pool) {
				return RLM_MODULE_NOOP;
			}
			break;
		}

		case PW_AUTH_TYPE:
			auth_type = TRUE;

			/*
			 *	Auth-Type := Accept
			 *	Auth-Type := Reject
			 */
			if ((vp->lvalue == 254) ||
			    (vp->lvalue == 4)) {
			    found_pw = 1;
			}
			break;

		default:
			break;	/* ignore it */
			
		}
	}

	/*
	 *	Print helpful warnings if there was no password.
	 */
	if (!found_pw) {
		/*
		 *	Likely going to be proxied.  Avoid printing
		 *	warning message.
		 */
		if (pairfind(request->config_items, PW_REALM) ||
		    (pairfind(request->config_items, PW_PROXY_TO_REALM))) {
			return RLM_MODULE_NOOP;
		}
		DEBUG("rlm_pap: WARNING! No \"known good\" password found for the user.  Authentication may fail because of this.");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Don't touch existing Auth-Types.
	 */
	if (auth_type) {
		DEBUG2("rlm_pap: Found existing Auth-Type, not changing it.");
		return RLM_MODULE_NOOP;
	}	

	/*
	 *	Can't do PAP if there's no password.
	 */
	if (!request->password ||
	    (request->password->attribute != PW_USER_PASSWORD)) {
		/*
		 *	Don't print out debugging messages if we know
		 *	they're useless.
		 */
		if (request->packet->code == PW_ACCESS_CHALLENGE) {
			return RLM_MODULE_NOOP;
		}

		DEBUG2("rlm_pap: No clear-text password in the request.  Not performing PAP.");
		return RLM_MODULE_NOOP;
	}

	vp = paircreate(PW_AUTH_TYPE, PW_TYPE_INTEGER);
	if (!vp) return RLM_MODULE_FAIL;
	pairparsevalue(vp, inst->name);

	pairadd(&request->config_items, vp);

	return RLM_MODULE_UPDATED;
}


/*
 *	Authenticate the user via one of any well-known password.
 */
static int pap_authenticate(void *instance, REQUEST *request)
{
	rlm_pap_t *inst = instance;
	VALUE_PAIR *vp;
	VALUE_PAIR *module_fmsg_vp;
	char module_fmsg[MAX_STRING_LEN];
	MD5_CTX md5_context;
	SHA1_CTX sha1_context;
	uint8_t digest[40];
	char buff[MAX_STRING_LEN];
	char buff2[MAX_STRING_LEN + 50];
	int scheme = PAP_ENC_INVALID;

	if (!request->password){
		radlog(L_AUTH, "rlm_pap: Attribute \"Password\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Clear-text passwords are the only ones we support.
	 */
	if (request->password->attribute != PW_USER_PASSWORD) {
		radlog(L_AUTH, "rlm_pap: Attribute \"User-Password\" is required for authentication. Cannot use \"%s\".", request->password->name);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	The user MUST supply a non-zero-length password.
	 */
	if (request->password->length == 0) {
		snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: empty password supplied");
		module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
		pairadd(&request->packet->vps, module_fmsg_vp);
		return RLM_MODULE_INVALID;
	}

	DEBUG("rlm_pap: login attempt with password %s",
	      request->password->vp_strvalue);

	/*
	 *	First, auto-detect passwords, by attribute in the
	 *	config items.
	 */
	if (inst->sch == PAP_ENC_AUTO) {
		for (vp = request->config_items; vp != NULL; vp = vp->next) {
			switch (vp->attribute) {
			case PW_USER_PASSWORD: /* deprecated */
			case PW_CLEARTEXT_PASSWORD: /* preferred */
				goto do_clear;
				
			case PW_CRYPT_PASSWORD:
				goto do_crypt;
				
			case PW_MD5_PASSWORD:
				goto do_md5;
				
			case PW_SHA_PASSWORD:
				goto do_sha;
				
			case PW_NT_PASSWORD:
				goto do_nt;

			case PW_LM_PASSWORD:
				goto do_lm;

			case PW_SMD5_PASSWORD:
				goto do_smd5;

			case PW_SSHA_PASSWORD:
				goto do_ssha;

			case PW_NS_MTA_MD5_PASSWORD:
				goto do_ns_mta_md5;

			default:
				break;	/* ignore it */
				
			}
		}

	fail:
		DEBUG("rlm_pap: No password configured for the user.  Cannot do authentication");
		return RLM_MODULE_FAIL;

	} else {
		vp = NULL;
		
		if (inst->sch == PAP_ENC_CRYPT) {
			vp = pairfind(request->config_items, PW_CRYPT_PASSWORD);
		}

		/*
		 *	Old-style: all passwords are in User-Password.
		 */
		if (!vp) {
			vp = pairfind(request->config_items, PW_USER_PASSWORD);
			if (!vp) goto fail;
		}
	}

	/*
	 *	Now that we've decided what to do, go do it.
	 */
	switch (scheme) {
	case PAP_ENC_CLEAR:
	do_clear:
		DEBUG("rlm_pap: Using clear text password.");
		if (strcmp((char *) vp->vp_strvalue,
			   (char *) request->password->vp_strvalue) != 0){
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: CLEAR TEXT password check failed");
			goto make_msg;
		}
	done:
		DEBUG("rlm_pap: User authenticated succesfully");
		return RLM_MODULE_OK;
		break;
		
	case PAP_ENC_CRYPT:
	do_crypt:
		DEBUG("rlm_pap: Using CRYPT encryption.");
		if (lrad_crypt_check((char *) request->password->vp_strvalue,
				     (char *) vp->vp_strvalue) != 0) {
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: CRYPT password check failed");
			goto make_msg;
		}
		goto done;
		break;
		
	case PW_MD5_PASSWORD:
	do_md5:
		DEBUG("rlm_pap: Using MD5 encryption.");

		normify(vp, 16);
		if (vp->length != 16) {
		DEBUG("rlm_pap: Configured MD5 password has incorrect length");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: Configured MD5 password has incorrect length");
			goto make_msg;
		}
		
		MD5Init(&md5_context);
		MD5Update(&md5_context, request->password->vp_strvalue,
			  request->password->length);
		MD5Final(digest, &md5_context);
		if (memcmp(digest, vp->vp_octets, vp->length) != 0) {
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: MD5 password check failed");
			goto make_msg;
		}
		goto done;
		break;
		
	case PW_SMD5_PASSWORD:
	do_smd5:
		DEBUG("rlm_pap: Using SMD5 encryption.");

		normify(vp, 16);
		if (vp->length <= 16) {
			DEBUG("rlm_pap: Configured SMD5 password has incorrect length");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: Configured SMD5 password has incorrect length");
			goto make_msg;
		}
		
		MD5Init(&md5_context);
		MD5Update(&md5_context, request->password->vp_strvalue,
			  request->password->length);
		MD5Update(&md5_context, &vp->vp_octets[16], vp->length - 16);
		MD5Final(digest, &md5_context);

		/*
		 *	Compare only the MD5 hash results, not the salt.
		 */
		if (memcmp(digest, vp->vp_octets, 16) != 0) {
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: SMD5 password check failed");
			goto make_msg;
		}
		goto done;
		break;
		
	case PW_SHA_PASSWORD:
	do_sha:
		DEBUG("rlm_pap: Using SHA1 encryption.");
		
		normify(vp, 20);
		if (vp->length != 20) {
			DEBUG("rlm_pap: Configured SHA1 password has incorrect length");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: Configured SHA1 password has incorrect length");
			goto make_msg;
		}
		
		SHA1Init(&sha1_context);
		SHA1Update(&sha1_context, request->password->vp_strvalue,
			   request->password->length);
		SHA1Final(digest,&sha1_context);
		if (memcmp(digest, vp->vp_octets, vp->length) != 0) {
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: SHA1 password check failed");
			goto make_msg;
		}
		goto done;
		break;
		
	case PW_SSHA_PASSWORD:
	do_ssha:
		DEBUG("rlm_pap: Using SSHA encryption.");
		
		normify(vp, 20);
		if (vp->length <= 20) {
			DEBUG("rlm_pap: Configured SSHA password has incorrect length");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: Configured SHA password has incorrect length");
			goto make_msg;
		}

		
		SHA1Init(&sha1_context);
		SHA1Update(&sha1_context, request->password->vp_strvalue,
			   request->password->length);
		SHA1Update(&sha1_context, &vp->vp_octets[20], vp->length - 20);
		SHA1Final(digest,&sha1_context);
		if (memcmp(digest, vp->vp_octets, 20) != 0) {
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: SSHA password check failed");
			goto make_msg;
		}
		goto done;
		break;
		
	case PW_NT_PASSWORD:
	do_nt:
		DEBUG("rlm_pap: Using NT encryption.");

		normify(vp, 16);
		if (vp->length != 16) {
			DEBUG("rlm_pap: Configured NT-Password has incorrect length");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: Configured NT-Password has incorrect length");
			goto make_msg;
		}
		
		sprintf(buff2,"%%{mschap:NT-Hash %s}",
			request->password->vp_strvalue);
		if (!radius_xlat(digest,sizeof(digest),buff2,request,NULL)){
			DEBUG("rlm_pap: mschap xlat failed");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: mschap xlat failed");
			goto make_msg;
		}
		if ((lrad_hex2bin(digest, digest, 16) != vp->length) ||
		    (memcmp(digest, vp->vp_octets, vp->length) != 0)) {
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: NT password check failed");
			goto make_msg;
		}
		goto done;
		break;
		
	case PW_LM_PASSWORD:
	do_lm:
		DEBUG("rlm_pap: Using LM encryption.");
		
		normify(vp, 16);
		if (vp->length != 16) {
			DEBUG("rlm_pap: Configured LM-Password has incorrect length");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: Configured LM-Password has incorrect length");
			goto make_msg;
		}
		sprintf(buff2,"%%{mschap:LM-Hash %s}",
			request->password->vp_strvalue);
		if (!radius_xlat(digest,sizeof(digest),buff2,request,NULL)){
			DEBUG("rlm_pap: mschap xlat failed");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: mschap xlat failed");
			goto make_msg;
		}
		if ((lrad_hex2bin(digest, digest, 16) != vp->length) ||
		    (memcmp(digest, vp->vp_octets, vp->length) != 0)) {
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: LM password check failed");
		make_msg:
			DEBUG("rlm_pap: Passwords don't match");
			module_fmsg_vp = pairmake("Module-Failure-Message",
						  module_fmsg, T_OP_EQ);
			pairadd(&request->packet->vps, module_fmsg_vp);
			return RLM_MODULE_REJECT;
		}
		goto done;
		break;

	case PAP_ENC_NS_MTA_MD5:
	do_ns_mta_md5:
		DEBUG("rlm_pap: Using NT-MTA-MD5 password");

		if (vp->length != 64) {
			DEBUG("rlm_pap: Configured NS-MTA-MD5-Password has incorrect length");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: Configured NS-MTA-MD5-Password has incorrect length");
			goto make_msg;
		}

		/*
		 *	Sanity check the value of NS-MTA-MD5-Password
		 */
		if (lrad_hex2bin(vp->vp_octets, buff, 32) != 16) {
			DEBUG("rlm_pap: Configured NS-MTA-MD5-Password has invalid value");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: Configured NS-MTA-MD5-Password has invalid value");
			goto make_msg;
		}

		/*
		 *	Ensure we don't have buffer overflows.
		 *
		 *	This really: sizeof(buff) - 2 - 2*32 - strlen(passwd)
		 */
		if (strlen(request->password->vp_strvalue) >= (sizeof(buff2) - 2 - 2 * 32)) {
			DEBUG("rlm_pap: Configured password is too long");
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: password is too long");
			goto make_msg;
		}

		/*
		 *	Set up the algorithm.
		 */
		{
			char *p = buff2;

			memcpy(p, &vp->vp_octets[32], 32);
			p += 32;
			*(p++) = 89;
			strcpy(p, request->password->vp_strvalue);
			p += strlen(p);
			*(p++) = 247;
			memcpy(p, &vp->vp_octets[32], 32);
			p += 32;

			MD5Init(&md5_context);
			MD5Update(&md5_context, buff2, p - buff2);
			MD5Final(digest, &md5_context);
		}
		if (memcmp(digest, buff, 16) != 0) {
			snprintf(module_fmsg,sizeof(module_fmsg),"rlm_pap: NS-MTA-MD5 password check failed");
			goto make_msg;
		}
		goto done;

	default:
		break;
	}

	DEBUG("rlm_pap: No password configured for the user.  Cannot do authentication");
	return RLM_MODULE_FAIL;
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_pap = {
	RLM_MODULE_INIT,
	"PAP",
	0,				/* type */
	pap_instantiate,		/* instantiation */
	pap_detach,			/* detach */
	{
		pap_authenticate,	/* authentication */
		pap_authorize,		/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
