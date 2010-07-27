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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2001,2006  The FreeRADIUS server project
 */

/*  MPPE support from Takahiro Wagatsuma <waga@sic.shibaura-it.ac.jp> */

#include	<freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>
#include	<freeradius-devel/rad_assert.h>
#include        <freeradius-devel/md5.h>
#include        <freeradius-devel/sha1.h>

#include 	<ctype.h>

#include	"mschap.h"
#include	"smbdes.h"

#ifdef __APPLE__
extern int od_mschap_auth(REQUEST *request, VALUE_PAIR *challenge, VALUE_PAIR * usernamepair);
#endif

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


typedef struct rlm_mschap_t {
	int use_mppe;
	int require_encryption;
        int require_strong;
        int with_ntdomain_hack;	/* this should be in another module */
	char *passwd_file;
	const char *xlat_name;
	char *ntlm_auth;
	const char *auth_type;
#ifdef __APPLE__
	int  open_directory;
#endif  
} rlm_mschap_t;


/*
 *	Does dynamic translation of strings.
 *
 *	Pulls NT-Response, LM-Response, or Challenge from MSCHAP
 *	attributes.
 */
static size_t mschap_xlat(void *instance, REQUEST *request,
		       char *fmt, char *out, size_t outlen,
		       RADIUS_ESCAPE_STRING func)
{
	size_t		i, data_len;
	uint8_t		*data = NULL;
	uint8_t		buffer[32];
	VALUE_PAIR	*user_name;
	VALUE_PAIR	*chap_challenge, *response;
	rlm_mschap_t	*inst = instance;

	response = NULL;

	func = func;		/* -Wunused */

	/*
	 *	Challenge means MS-CHAPv1 challenge, or
	 *	hash of MS-CHAPv2 challenge, and peer challenge.
	 */
	if (strncasecmp(fmt, "Challenge", 9) == 0) {
		chap_challenge = pairfind(request->packet->vps,
					  PW_MSCHAP_CHALLENGE,
					  VENDORPEC_MICROSOFT);
		if (!chap_challenge) {
			RDEBUG2("No MS-CHAP-Challenge in the request.");
			return 0;
		}

		/*
		 *	MS-CHAP-Challenges are 8 octets,
		 *	for MS-CHAPv2
		 */
		if (chap_challenge->length == 8) {
			RDEBUG2(" mschap1: %02x",
			       chap_challenge->vp_octets[0]);
			data = chap_challenge->vp_octets;
			data_len = 8;

			/*
			 *	MS-CHAP-Challenges are 16 octets,
			 *	for MS-CHAPv2.
			 */
		} else if (chap_challenge->length == 16) {
			VALUE_PAIR *name_attr, *response_name;
			char *username_string;

			RDEBUG2(" mschap2: %02x", chap_challenge->vp_octets[0]);
			response = pairfind(request->packet->vps,
					    PW_MSCHAP2_RESPONSE,
					    VENDORPEC_MICROSOFT);
			if (!response) {
				RDEBUG2("MS-CHAP2-Response is required to calculate MS-CHAPv1 challenge.");
				return 0;
			}

			/*
			 *	FIXME: Much of this is copied from
			 *	below.  We should put it into a
			 *	separate function.
			 */

			/*
			 *	Responses are 50 octets.
			 */
			if (response->length < 50) {
				radlog_request(L_AUTH, 0, request, "MS-CHAP-Response has the wrong format.");
				return 0;
			}

			user_name = pairfind(request->packet->vps,
					     PW_USER_NAME, 0);
			if (!user_name) {
				RDEBUG2("User-Name is required to calculate MS-CHAPv1 Challenge.");
				return 0;
			}

 			/*
			 *      Check for MS-CHAP-User-Name and if found, use it
			 *      to construct the MSCHAPv1 challenge.  This is
			 *      set by rlm_eap_mschap to the MS-CHAP Response
			 *      packet Name field.
			 *
			 *	We prefer this to the User-Name in the
			 *	packet.
			 */
			response_name = pairfind(request->packet->vps, PW_MS_CHAP_USER_NAME, 0);
			if (response_name) {
				name_attr = response_name;
			} else {
				name_attr = user_name;
			}

			/*
			 *	with_ntdomain_hack moved here, too.
			 */
			if ((username_string = strchr(name_attr->vp_strvalue, '\\')) != NULL) {
				if (inst->with_ntdomain_hack) {
					username_string++;
				} else {
					RDEBUG2("NT Domain delimeter found, should we have enabled with_ntdomain_hack?");
					username_string = name_attr->vp_strvalue;
				}
			} else {
				username_string = name_attr->vp_strvalue;
			}

			if (response_name &&
			    ((user_name->length != response_name->length) ||
			     (strncasecmp(user_name->vp_strvalue, response_name->vp_strvalue, user_name->length) != 0))) {
				RDEBUG("WARNING: User-Name (%s) is not the same as MS-CHAP Name (%s) from EAP-MSCHAPv2", user_name->vp_strvalue, response_name->vp_strvalue);
			}

			/*
			 *	Get the MS-CHAPv1 challenge
			 *	from the MS-CHAPv2 peer challenge,
			 *	our challenge, and the user name.
			 */
			RDEBUG2("Creating challenge hash with username: %s",
				username_string);
			mschap_challenge_hash(response->vp_octets + 2,
				       chap_challenge->vp_octets,
				       username_string, buffer);
			data = buffer;
			data_len = 8;
		} else {
			RDEBUG2("Invalid MS-CHAP challenge length");
			return 0;
		}

		/*
		 *	Get the MS-CHAPv1 response, or the MS-CHAPv2
		 *	response.
		 */
	} else if (strncasecmp(fmt, "NT-Response", 11) == 0) {
		response = pairfind(request->packet->vps,
				    PW_MSCHAP_RESPONSE, VENDORPEC_MICROSOFT);
		if (!response) response = pairfind(request->packet->vps,
						   PW_MSCHAP2_RESPONSE,
						   VENDORPEC_MICROSOFT);
		if (!response) {
			RDEBUG2("No MS-CHAP-Response or MS-CHAP2-Response was found in the request.");
			return 0;
		}

		/*
		 *	For MS-CHAPv1, the NT-Response exists only
		 *	if the second octet says so.
		 */
		if ((response->attribute == PW_MSCHAP_RESPONSE) &&
		    ((response->vp_octets[1] & 0x01) == 0)) {
			RDEBUG2("No NT-Response in MS-CHAP-Response");
			return 0;
		}

		/*
		 *	MS-CHAP-Response and MS-CHAP2-Response have
		 *	the NT-Response at the same offset, and are
		 *	the same length.
		 */
		data = response->vp_octets + 26;
		data_len = 24;

		/*
		 *	LM-Response is deprecated, and exists only
		 *	in MS-CHAPv1, and not often there.
		 */
	} else if (strncasecmp(fmt, "LM-Response", 11) == 0) {
		response = pairfind(request->packet->vps,
				    PW_MSCHAP_RESPONSE, VENDORPEC_MICROSOFT);
		if (!response) {
			RDEBUG2("No MS-CHAP-Response was found in the request.");
			return 0;
		}

		/*
		 *	For MS-CHAPv1, the NT-Response exists only
		 *	if the second octet says so.
		 */
		if ((response->vp_octets[1] & 0x01) != 0) {
			RDEBUG2("No LM-Response in MS-CHAP-Response");
			return 0;
		}
		data = response->vp_octets + 2;
		data_len = 24;

		/*
		 *	Pull the NT-Domain out of the User-Name, if it exists.
		 */
	} else if (strncasecmp(fmt, "NT-Domain", 9) == 0) {
		char *p, *q;

		user_name = pairfind(request->packet->vps, PW_USER_NAME, 0);
		if (!user_name) {
			RDEBUG2("No User-Name was found in the request.");
			return 0;
		}

		/*
		 *	First check to see if this is a host/ style User-Name
		 *	(a la Kerberos host principal)
		 */
		if (strncmp(user_name->vp_strvalue, "host/", 5) == 0) {
			/*
			 *	If we're getting a User-Name formatted in this way,
			 *	it's likely due to PEAP.  The Windows Domain will be
			 *	the first domain component following the hostname,
			 *	or the machine name itself if only a hostname is supplied
			 */
			p = strchr(user_name->vp_strvalue, '.');
			if (!p) {
				RDEBUG2("setting NT-Domain to same as machine name");
				strlcpy(out, user_name->vp_strvalue + 5, outlen);
			} else {
				p++;	/* skip the period */
				q = strchr(p, '.');
				/*
				 * use the same hack as below
				 * only if another period was found
				 */
				if (q) *q = '\0';
				strlcpy(out, p, outlen);
				if (q) *q = '.';
			}
		} else {
			p = strchr(user_name->vp_strvalue, '\\');
			if (!p) {
				RDEBUG2("No NT-Domain was found in the User-Name.");
				return 0;
			}

			/*
			 *	Hack.  This is simpler than the alternatives.
			 */
			*p = '\0';
			strlcpy(out, user_name->vp_strvalue, outlen);
			*p = '\\';
		}

		return strlen(out);

		/*
		 *	Pull the User-Name out of the User-Name...
		 */
	} else if (strncasecmp(fmt, "User-Name", 9) == 0) {
		char *p;

		user_name = pairfind(request->packet->vps, PW_USER_NAME, 0);
		if (!user_name) {
			RDEBUG2("No User-Name was found in the request.");
			return 0;
		}

		/*
		 *	First check to see if this is a host/ style User-Name
		 *	(a la Kerberos host principal)
		 */
		if (strncmp(user_name->vp_strvalue, "host/", 5) == 0) {
			/*
			 *	If we're getting a User-Name formatted in this way,
			 *	it's likely due to PEAP.  When authenticating this against
			 *	a Domain, Windows will expect the User-Name to be in the
			 *	format of hostname$, the SAM version of the name, so we
			 *	have to convert it to that here.  We do so by stripping
			 *	off the first 5 characters (host/), and copying everything
			 *	from that point to the first period into a string and appending
			 * 	a $ to the end.
			 */
			p = strchr(user_name->vp_strvalue, '.');
			/*
			 * use the same hack as above
			 * only if a period was found
			 */
			if (p) *p = '\0';
			snprintf(out, outlen, "%s$", user_name->vp_strvalue + 5);
			if (p) *p = '.';
		} else {
			p = strchr(user_name->vp_strvalue, '\\');
			if (p) {
				p++;	/* skip the backslash */
			} else {
				p = user_name->vp_strvalue; /* use the whole User-Name */
			}
			strlcpy(out, p, outlen);
		}

		return strlen(out);

		/*
		 * Return the NT-Hash of the passed string
		 */
	} else if (strncasecmp(fmt, "NT-Hash ", 8) == 0) {
		char *p;
		char buf2[1024];

		p = fmt + 8;	/* 7 is the length of 'NT-Hash' */
		if ((p == '\0')	 || (outlen <= 32))
			return 0;

		while (isspace(*p)) p++;

		if (!radius_xlat(buf2, sizeof(buf2),p,request,NULL)) {
			RDEBUG("xlat failed");
			*buffer = '\0';
			return 0;
		}

		mschap_ntpwdhash(buffer,buf2);

		fr_bin2hex(buffer, out, 16);
		out[32] = '\0';
		RDEBUG("NT-Hash of %s = %s", buf2, out);
		return 32;

		/*
		 * Return the LM-Hash of the passed string
		 */
	} else if (strncasecmp(fmt, "LM-Hash ", 8) == 0) {
		char *p;
		char buf2[1024];

		p = fmt + 8;	/* 7 is the length of 'LM-Hash' */
		if ((p == '\0') || (outlen <= 32))
			return 0;

		while (isspace(*p)) p++;

		if (!radius_xlat(buf2, sizeof(buf2),p,request,NULL)) {
			RDEBUG("xlat failed");
			*buffer = '\0';
			return 0;
		}

		smbdes_lmpwdhash(buf2, buffer);
		fr_bin2hex(buffer, out, 16);
		out[32] = '\0';
		RDEBUG("LM-Hash of %s = %s", buf2, out);
		return 32;
	} else {
		RDEBUG2("Unknown expansion string \"%s\"",
		       fmt);
		return 0;
	}

	if (outlen == 0) return 0; /* nowhere to go, don't do anything */

	/*
	 *	Didn't set anything: this is bad.
	 */
	if (!data) {
		RDEBUG2("Failed to do anything intelligent");
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


static const CONF_PARSER module_config[] = {
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
	{ "ntlm_auth",   PW_TYPE_STRING_PTR,
	  offsetof(rlm_mschap_t, ntlm_auth), NULL,  NULL },
#ifdef __APPLE__
	{ "use_open_directory",    PW_TYPE_BOOLEAN,
	  offsetof(rlm_mschap_t,open_directory), NULL, "yes" },
#endif

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

/*
 *	deinstantiate module, free all memory allocated during
 *	mschap_instantiate()
 */
static int mschap_detach(void *instance){
#define inst ((rlm_mschap_t *)instance)
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
	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) inst->xlat_name = cf_section_name1(conf);
	inst->xlat_name = strdup(inst->xlat_name);
	xlat_register(inst->xlat_name, mschap_xlat, inst);

	/*
	 *	For backwards compatibility
	 */
	if (!dict_valbyname(PW_AUTH_TYPE, 0, inst->xlat_name)) {
		inst->auth_type = "MS-CHAP";
	} else {
		inst->auth_type = inst->xlat_name;
	}

	return 0;
}

/*
 *	add_reply() adds either MS-CHAP2-Success or MS-CHAP-Error
 *	attribute to reply packet
 */
void mschap_add_reply(REQUEST *request, VALUE_PAIR** vp, unsigned char ident,
		      const char* name, const char* value, int len)
{
	VALUE_PAIR *reply_attr;
	reply_attr = pairmake(name, "", T_OP_EQ);
	if (!reply_attr) {
		RDEBUG("Failed to create attribute %s: %s\n", name, fr_strerror());
		return;
	}

	reply_attr->vp_octets[0] = ident;
	memcpy(reply_attr->vp_octets + 1, value, len);
	reply_attr->length = len + 1;
	pairadd(vp, reply_attr);
}

/*
 *	Add MPPE attributes to the reply.
 */
static void mppe_add_reply(REQUEST *request,
			   const char* name, const uint8_t * value, int len)
{
       VALUE_PAIR *vp;
       vp = radius_pairmake(request, &request->reply->vps, name, "", T_OP_EQ);
       if (!vp) {
	       RDEBUG("rlm_mschap: mppe_add_reply failed to create attribute %s: %s\n", name, fr_strerror());
	       return;
       }

       memcpy(vp->vp_octets, value, len);
       vp->length = len;
}


/*
 *	Do the MS-CHAP stuff.
 *
 *	This function is here so that all of the MS-CHAP related
 *	authentication is in one place, and we can perhaps later replace
 *	it with code to call winbindd, or something similar.
 */
static int do_mschap(rlm_mschap_t *inst,
		     REQUEST *request, VALUE_PAIR *password,
		     uint8_t *challenge, uint8_t *response,
		     uint8_t *nthashhash, int do_ntlm_auth)
{
	uint8_t		calculated[24];

	/*
	 *	Do normal authentication.
	 */
	if (!do_ntlm_auth) {
		/*
		 *	No password: can't do authentication.
		 */
		if (!password) {
			RDEBUG2("FAILED: No NT/LM-Password.  Cannot perform authentication.");
			return -1;
		}

		smbdes_mschap(password->vp_strvalue, challenge, calculated);
		if (memcmp(response, calculated, 24) != 0) {
			return -1;
		}

		/*
		 *	If the password exists, and is an NT-Password,
		 *	then calculate the hash of the NT hash.  Doing this
		 *	here minimizes work for later.
		 */
		if (password && (password->attribute == PW_NT_PASSWORD)) {
			fr_md4_calc(nthashhash, password->vp_octets, 16);
		} else {
			memset(nthashhash, 0, 16);
		}
	} else {		/* run ntlm_auth */
		int	result;
		char	buffer[256];

		memset(nthashhash, 0, 16);

		/*
		 *	Run the program, and expect that we get 16
		 */
		result = radius_exec_program(inst->ntlm_auth, request,
					     TRUE, /* wait */
					     buffer, sizeof(buffer),
					     NULL, NULL, 1);
		if (result != 0) {
			RDEBUG2("External script failed.");
			return -1;
		}

		/*
		 *	Parse the answer as an nthashhash.
		 *
		 *	ntlm_auth currently returns:
		 *	NT_KEY: 000102030405060708090a0b0c0d0e0f
		 */
		if (memcmp(buffer, "NT_KEY: ", 8) != 0) {
			RDEBUG2("Invalid output from ntlm_auth: expecting NT_KEY");
			return -1;
		}

		/*
		 *	Check the length.  It should be at least 32,
		 *	with an LF at the end.
		 */
		if (strlen(buffer + 8) < 32) {
			RDEBUG2("Invalid output from ntlm_auth: NT_KEY has unexpected length");
			return -1;
		}

		/*
		 *	Update the NT hash hash, from the NT key.
		 */
		if (fr_hex2bin(buffer + 8, nthashhash, 16) != 16) {
			RDEBUG2("Invalid output from ntlm_auth: NT_KEY has non-hex values");
			return -1;
		}
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
       fr_SHA1_CTX Context;

       fr_SHA1Init(&Context);
       fr_SHA1Update(&Context,nt_hashhash,16);
       fr_SHA1Update(&Context,nt_response,24);
       fr_SHA1Update(&Context,magic1,27);
       fr_SHA1Final(digest,&Context);

       memcpy(masterkey,digest,16);
}


static void mppe_GetAsymmetricStartKey(uint8_t *masterkey,uint8_t *sesskey,
				       int keylen,int issend)
{
       uint8_t digest[20];
       const uint8_t *s;
       fr_SHA1_CTX Context;

       memset(digest,0,20);

       if(issend) {
               s = magic3;
       } else {
               s = magic2;
       }

       fr_SHA1Init(&Context);
       fr_SHA1Update(&Context,masterkey,16);
       fr_SHA1Update(&Context,SHSpad1,40);
       fr_SHA1Update(&Context,s,84);
       fr_SHA1Update(&Context,SHSpad2,40);
       fr_SHA1Final(digest,&Context);

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
static void mppe_chap2_gen_keys128(uint8_t *nt_hashhash,uint8_t *response,
				   uint8_t *sendkey,uint8_t *recvkey)
{
	uint8_t enckey1[16];
	uint8_t enckey2[16];

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

	challenge = pairfind(request->packet->vps,
			     PW_MSCHAP_CHALLENGE,
			     VENDORPEC_MICROSOFT);
	if (!challenge) {
		return RLM_MODULE_NOOP;
	}

	response = pairfind(request->packet->vps,
			    PW_MSCHAP_RESPONSE,
			    VENDORPEC_MICROSOFT);
	if (!response)
		response = pairfind(request->packet->vps,
				    PW_MSCHAP2_RESPONSE,
				    VENDORPEC_MICROSOFT);

	/*
	 *	Nothing we recognize.  Don't do anything.
	 */
	if (!response) {
		RDEBUG2("Found MS-CHAP-Challenge, but no MS-CHAP-Response.");
		return RLM_MODULE_NOOP;
	}

	if (pairfind(request->config_items, PW_AUTH_TYPE, 0)) {
		RDEBUG2("Found existing Auth-Type.  Not changing it.");
		return RLM_MODULE_NOOP;
	}

	RDEBUG2("Found MS-CHAP attributes.  Setting 'Auth-Type  = %s'", inst->xlat_name);

	/*
	 *	Set Auth-Type to MS-CHAP.  The authentication code
	 *	will take care of turning clear-text passwords into
	 *	NT/LM passwords.
	 */
	if (!radius_pairmake(request, &request->config_items,
			     "Auth-Type", inst->auth_type, T_OP_EQ)) {
		return RLM_MODULE_FAIL;
	}

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
 *		PAP:      PW_USER_PASSWORD or
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
	VALUE_PAIR *challenge = NULL;
	VALUE_PAIR *response = NULL;
	VALUE_PAIR *password = NULL;
	VALUE_PAIR *lm_password, *nt_password, *smb_ctrl;
	VALUE_PAIR *username;
	uint8_t nthashhash[16];
	char msch2resp[42];
	char *username_string;
	int chap = 0;
	int		do_ntlm_auth;

	/*
	 *	If we have ntlm_auth configured, use it unless told
	 *	otherwise
	 */
	do_ntlm_auth = (inst->ntlm_auth != NULL);

	/*
	 *	If we have an ntlm_auth configuration, then we may
	 *	want to suppress it.
	 */
	if (do_ntlm_auth) {
		VALUE_PAIR *vp = pairfind(request->config_items,
					  PW_MS_CHAP_USE_NTLM_AUTH, 0);
		if (vp) do_ntlm_auth = vp->vp_integer;
	}

	/*
	 *	Find the SMB-Account-Ctrl attribute, or the
	 *	SMB-Account-Ctrl-Text attribute.
	 */
	smb_ctrl = pairfind(request->config_items, PW_SMB_ACCOUNT_CTRL, 0);
	if (!smb_ctrl) {
		password = pairfind(request->config_items,
				    PW_SMB_ACCOUNT_CTRL_TEXT, 0);
		if (password) {
			smb_ctrl = radius_pairmake(request,
						   &request->config_items,
						   "SMB-Account-CTRL", "0",
						   T_OP_SET);
			if (smb_ctrl) {
				smb_ctrl->vp_integer = pdb_decode_acct_ctrl(password->vp_strvalue);
			}
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
		if ((smb_ctrl->vp_integer & ACB_PWNOTREQ) != 0) {
			RDEBUG2("SMB-Account-Ctrl says no password is required.");
			return RLM_MODULE_OK;
		}
	}

	/*
	 *	Decide how to get the passwords.
	 */
	password = pairfind(request->config_items, PW_CLEARTEXT_PASSWORD, 0);

	/*
	 *	We need an LM-Password.
	 */
	lm_password = pairfind(request->config_items, PW_LM_PASSWORD, 0);
	if (lm_password) {
		/*
		 *	Allow raw octets.
		 */
		if ((lm_password->length == 16) ||
		    ((lm_password->length == 32) &&
		     (fr_hex2bin(lm_password->vp_strvalue,
				 lm_password->vp_octets, 16) == 16))) {
			RDEBUG2("Found LM-Password");
			lm_password->length = 16;

		} else {
			radlog_request(L_ERR, 0, request, "Invalid LM-Password");
			lm_password = NULL;
		}

	} else if (!password) {
		if (!do_ntlm_auth) RDEBUG2("No Cleartext-Password configured.  Cannot create LM-Password.");

	} else {		/* there is a configured Cleartext-Password */
		lm_password = radius_pairmake(request, &request->config_items,
					      "LM-Password", "", T_OP_EQ);
		if (!lm_password) {
			radlog_request(L_ERR, 0, request, "No memory");
		} else {
			smbdes_lmpwdhash(password->vp_strvalue,
					 lm_password->vp_octets);
			lm_password->length = 16;
		}
	}

	/*
	 *	We need an NT-Password.
	 */
	nt_password = pairfind(request->config_items, PW_NT_PASSWORD, 0);
	if (nt_password) {
		if ((nt_password->length == 16) ||
		    ((nt_password->length == 32) &&
		     (fr_hex2bin(nt_password->vp_strvalue,
				 nt_password->vp_octets, 16) == 16))) {
			RDEBUG2("Found NT-Password");
			nt_password->length = 16;

                } else {
			radlog_request(L_ERR, 0, request, "Invalid NT-Password");
			nt_password = NULL;
		}
	} else if (!password) {
		if (!do_ntlm_auth) RDEBUG2("No Cleartext-Password configured.  Cannot create NT-Password.");

	} else {		/* there is a configured Cleartext-Password */
		nt_password = radius_pairmake(request, &request->config_items,
					      "NT-Password", "", T_OP_EQ);
		if (!nt_password) {
			radlog_request(L_ERR, 0, request, "No memory");
			return RLM_MODULE_FAIL;
		} else {
			mschap_ntpwdhash(nt_password->vp_octets,
				  password->vp_strvalue);
			nt_password->length = 16;
		}
	}

	challenge = pairfind(request->packet->vps,
			     PW_MSCHAP_CHALLENGE,
			     VENDORPEC_MICROSOFT);
	if (!challenge) {
		RDEBUG2("No MS-CHAP-Challenge in the request");
		return RLM_MODULE_REJECT;
	}

	/*
	 *	We also require an MS-CHAP-Response.
	 */
	response = pairfind(request->packet->vps,
			    PW_MSCHAP_RESPONSE,
			    VENDORPEC_MICROSOFT);

	/*
	 *	MS-CHAP-Response, means MS-CHAPv1
	 */
	if (response) {
		int offset;

		/*
		 *	MS-CHAPv1 challenges are 8 octets.
		 */
		if (challenge->length < 8) {
			radlog_request(L_AUTH, 0, request, "MS-CHAP-Challenge has the wrong format.");
			return RLM_MODULE_INVALID;
		}

		/*
		 *	Responses are 50 octets.
		 */
		if (response->length < 50) {
			radlog_request(L_AUTH, 0, request, "MS-CHAP-Response has the wrong format.");
			return RLM_MODULE_INVALID;
		}

		/*
		 *	We are doing MS-CHAP.  Calculate the MS-CHAP
		 *	response
		 */
		if (response->vp_octets[1] & 0x01) {
			RDEBUG2("Told to do MS-CHAPv1 with NT-Password");
			password = nt_password;
			offset = 26;
		} else {
			RDEBUG2("Told to do MS-CHAPv1 with LM-Password");
			password = lm_password;
			offset = 2;
		}

		/*
		 *	Do the MS-CHAP authentication.
		 */
		if (do_mschap(inst, request, password, challenge->vp_octets,
			      response->vp_octets + offset, nthashhash,
			      do_ntlm_auth) < 0) {
			RDEBUG2("MS-CHAP-Response is incorrect.");
			mschap_add_reply(request, &request->reply->vps,
					 *response->vp_octets,
					 "MS-CHAP-Error", "E=691 R=1", 9);
			return RLM_MODULE_REJECT;
		}

		chap = 1;

	} else if ((response = pairfind(request->packet->vps, PW_MSCHAP2_RESPONSE, VENDORPEC_MICROSOFT)) != NULL) {
		uint8_t	mschapv1_challenge[16];
		VALUE_PAIR *name_attr, *response_name;

		/*
		 *	MS-CHAPv2 challenges are 16 octets.
		 */
		if (challenge->length < 16) {
			radlog_request(L_AUTH, 0, request, "MS-CHAP-Challenge has the wrong format.");
			return RLM_MODULE_INVALID;
		}

		/*
		 *	Responses are 50 octets.
		 */
		if (response->length < 50) {
			radlog_request(L_AUTH, 0, request, "MS-CHAP-Response has the wrong format.");
			return RLM_MODULE_INVALID;
		}

		/*
		 *	We also require a User-Name
		 */
		username = pairfind(request->packet->vps, PW_USER_NAME, 0);
		if (!username) {
			radlog_request(L_AUTH, 0, request, "We require a User-Name for MS-CHAPv2");
			return RLM_MODULE_INVALID;
		}

		/*
		 *      Check for MS-CHAP-User-Name and if found, use it
		 *      to construct the MSCHAPv1 challenge.  This is
		 *      set by rlm_eap_mschap to the MS-CHAP Response
		 *      packet Name field.
		 *
		 *	We prefer this to the User-Name in the
		 *	packet.
		 */
		response_name = pairfind(request->packet->vps, PW_MS_CHAP_USER_NAME, 0);
		if (response_name) {
			name_attr = response_name;
		} else {
			name_attr = username;
		}
		
		/*
		 *	with_ntdomain_hack moved here, too.
		 */
		if ((username_string = strchr(name_attr->vp_strvalue, '\\')) != NULL) {
			if (inst->with_ntdomain_hack) {
				username_string++;
			} else {
				RDEBUG2("NT Domain delimeter found, should we have enabled with_ntdomain_hack?");
				username_string = name_attr->vp_strvalue;
			}
		} else {
			username_string = name_attr->vp_strvalue;
		}
		
		if (response_name &&
		    ((username->length != response_name->length) ||
		     (strncasecmp(username->vp_strvalue, response_name->vp_strvalue, username->length) != 0))) {
			RDEBUG("ERROR: User-Name (%s) is not the same as MS-CHAP Name (%s) from EAP-MSCHAPv2", username->vp_strvalue, response_name->vp_strvalue);
			return RLM_MODULE_REJECT;
		}

#ifdef __APPLE__
		/*
		 *  No "known good" NT-Password attribute.  Try to do
		 *  OpenDirectory authentication.
		 *
		 *  If OD determines the user is an AD user it will return noop, which
		 *  indicates the auth process should continue directly to AD.
		 *  Otherwise OD will determine auth success/fail.
		 */
		if (!nt_password && inst->open_directory) {
			RDEBUG2("No NT-Password configured. Trying OpenDirectory Authentication.");
			int odStatus = od_mschap_auth(request, challenge, username);
			if (odStatus != RLM_MODULE_NOOP) {
				return odStatus;
			}
		}
#endif
		/*
		 *	The old "mschapv2" function has been moved to
		 *	here.
		 *
		 *	MS-CHAPv2 takes some additional data to create an
		 *	MS-CHAPv1 challenge, and then does MS-CHAPv1.
		 */
		RDEBUG2("Creating challenge hash with username: %s",
			username_string);
		mschap_challenge_hash(response->vp_octets + 2, /* peer challenge */
			       challenge->vp_octets, /* our challenge */
			       username_string,	/* user name */
			       mschapv1_challenge); /* resulting challenge */

		RDEBUG2("Told to do MS-CHAPv2 for %s with NT-Password",
		       username_string);

		if (do_mschap(inst, request, nt_password, mschapv1_challenge,
			      response->vp_octets + 26, nthashhash,
			      do_ntlm_auth) < 0) {
			RDEBUG2("FAILED: MS-CHAP2-Response is incorrect");
			mschap_add_reply(request, &request->reply->vps,
					 *response->vp_octets,
					 "MS-CHAP-Error", "E=691 R=1", 9);
			return RLM_MODULE_REJECT;
		}

		mschap_auth_response(username_string, /* without the domain */
			      nthashhash, /* nt-hash-hash */
			      response->vp_octets + 26, /* peer response */
			      response->vp_octets + 2, /* peer challenge */
			      challenge->vp_octets, /* our challenge */
			      msch2resp); /* calculated MPPE key */
		mschap_add_reply(request, &request->reply->vps, *response->vp_octets,
				 "MS-CHAP2-Success", msch2resp, 42);
		chap = 2;

	} else {		/* Neither CHAPv1 or CHAPv2 response: die */
		radlog_request(L_AUTH, 0, request, "No MS-CHAP response found");
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
		if (((smb_ctrl->vp_integer & ACB_DISABLED) != 0) ||
		    ((smb_ctrl->vp_integer & ACB_NORMAL) == 0)) {
			RDEBUG2("SMB-Account-Ctrl says that the account is disabled, or is not a normal account.");
			mschap_add_reply(request, &request->reply->vps,
					  *response->vp_octets,
					  "MS-CHAP-Error", "E=691 R=1", 9);
			return RLM_MODULE_NOTFOUND;
		}

		/*
		 *	User is locked out.
		 */
		if ((smb_ctrl->vp_integer & ACB_AUTOLOCK) != 0) {
			RDEBUG2("SMB-Account-Ctrl says that the account is locked out.");
			mschap_add_reply(request, &request->reply->vps,
					  *response->vp_octets,
					  "MS-CHAP-Error", "E=647 R=0", 9);
			return RLM_MODULE_USERLOCK;
		}
	}

	/* now create MPPE attributes */
	if (inst->use_mppe) {
		uint8_t mppe_sendkey[34];
		uint8_t mppe_recvkey[34];

		if (chap == 1){
			RDEBUG2("adding MS-CHAPv1 MPPE keys");
			memset(mppe_sendkey, 0, 32);
			if (lm_password) {
				memcpy(mppe_sendkey, lm_password->vp_octets, 8);
			}

			/*
			 *	According to RFC 2548 we
			 *	should send NT hash.  But in
			 *	practice it doesn't work.
			 *	Instead, we should send nthashhash
			 *
			 *	This is an error on RFC 2548.
			 */
			/*
			 *	do_mschap cares to zero nthashhash if NT hash
			 *	is not available.
			 */
			memcpy(mppe_sendkey + 8,
			       nthashhash, 16);
			mppe_add_reply(request,
				       "MS-CHAP-MPPE-Keys",
				       mppe_sendkey, 32);
		} else if (chap == 2) {
			RDEBUG2("adding MS-CHAPv2 MPPE keys");
			mppe_chap2_gen_keys128(nthashhash,
					       response->vp_octets + 26,
					       mppe_sendkey, mppe_recvkey);

			mppe_add_reply(request,
				       "MS-MPPE-Recv-Key",
				       mppe_recvkey, 16);
			mppe_add_reply(request,
				       "MS-MPPE-Send-Key",
				       mppe_sendkey, 16);

		}
		radius_pairmake(request, &request->reply->vps,
				"MS-MPPE-Encryption-Policy",
				(inst->require_encryption)? "0x00000002":"0x00000001",
				T_OP_EQ);
		radius_pairmake(request, &request->reply->vps,
				"MS-MPPE-Encryption-Types",
				(inst->require_strong)? "0x00000004":"0x00000006",
				T_OP_EQ);
	} /* else we weren't asked to use MPPE */

	return RLM_MODULE_OK;
#undef inst
}

module_t rlm_mschap = {
	RLM_MODULE_INIT,
	"MS-CHAP",
	RLM_TYPE_THREAD_SAFE,		/* type */
	mschap_instantiate,		/* instantiation */
	mschap_detach,		/* detach */
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
};
