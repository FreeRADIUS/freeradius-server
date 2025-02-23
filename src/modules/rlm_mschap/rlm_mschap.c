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
 * @file rlm_mschap.c
 * @brief Implemented mschap authentication.
 *
 * @copyright 2000,2001,2006  The FreeRADIUS server project
 */

/*  MPPE support from Takahiro Wagatsuma <waga@sic.shibaura-it.ac.jp> */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/md5.h>
#include <freeradius-devel/sha1.h>

#include <ctype.h>

#include "rlm_mschap.h"
#include "mschap.h"
#include "smbdes.h"

#ifdef WITH_AUTH_WINBIND
#include "auth_wbclient.h"
#endif

#ifdef HAVE_OPENSSL_CRYPTO_H
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */
#  include	<openssl/rc4.h>
#endif

#ifdef __APPLE__
int od_mschap_auth(REQUEST *request, VALUE_PAIR *challenge, VALUE_PAIR * usernamepair);
#endif

/* Allowable account control bits */
#define ACB_DISABLED	0x00010000	//!< User account disabled.
#define ACB_HOMDIRREQ	0x00020000	//!< Home directory required.
#define ACB_PWNOTREQ	0x00040000	//!< User password not required.
#define ACB_TEMPDUP	0x00080000	//!< Temporary duplicate account.
#define ACB_NORMAL	0x00100000	//!< Normal user account.
#define ACB_MNS		0x00200000	//!< MNS logon user account.
#define ACB_DOMTRUST	0x00400000	//!< Interdomain trust account.
#define ACB_WSTRUST	0x00800000	//!< Workstation trust account.
#define ACB_SVRTRUST	0x01000000	//!< Server trust account.
#define ACB_PWNOEXP	0x02000000	//!< User password does not expire.
#define ACB_AUTOLOCK	0x04000000	//!< Account auto locked.
#define ACB_PW_EXPIRED	0x00020000	//!< Password Expired.

static int pdb_decode_acct_ctrl(char const *p)
{
	int acct_ctrl = 0;
	int done = 0;

	/*
	 * Check if the account type bits have been encoded after the
	 * NT password (in the form [NDHTUWSLXI]).
	 */

	if (*p != '[') return 0;

	for (p++; *p && !done; p++) {
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

		case 'e': /* 'e'xpired, the password has */
			acct_ctrl |= ACB_PW_EXPIRED;
			break;

		case ' ': /* ignore spaces */
			break;

		case ':':
		case '\n':
		case '\0':
		case ']':
		default:
			done = 1;
			break;
		}
	}

	return acct_ctrl;
}


/*
 *	Does dynamic translation of strings.
 *
 *	Pulls NT-Response, LM-Response, or Challenge from MSCHAP
 *	attributes.
 */
static ssize_t mschap_xlat(void *instance, REQUEST *request,
			   char const *fmt, char *out, size_t outlen)
{
	size_t		i, data_len;
	uint8_t const  	*data = NULL;
	uint8_t		buffer[32];
	VALUE_PAIR	*user_name;
	VALUE_PAIR	*chap_challenge, *response;
	rlm_mschap_t	*inst = instance;

	response = NULL;

	/*
	 *	Challenge means MS-CHAPv1 challenge, or
	 *	hash of MS-CHAPv2 challenge, and peer challenge.
	 */
	if (strncasecmp(fmt, "Challenge", 9) == 0) {
		chap_challenge = fr_pair_find_by_num(request->packet->vps, PW_MSCHAP_CHALLENGE, VENDORPEC_MICROSOFT, TAG_ANY);
		if (!chap_challenge) {
			REDEBUG("No MS-CHAP-Challenge in the request");
			return -1;
		}

		/*
		 *	MS-CHAP-Challenges are 8 octets,
		 *	for MS-CHAPv1
		 */
		if (chap_challenge->vp_length == 8) {
			RDEBUG2("mschap1: %02x", chap_challenge->vp_octets[0]);
			data = chap_challenge->vp_octets;
			data_len = 8;

			/*
			 *	MS-CHAP-Challenges are 16 octets,
			 *	for MS-CHAPv2.
			 */
		} else if (chap_challenge->vp_length == 16) {
			VALUE_PAIR *name_attr, *response_name;
			char const *username_string;

			response = fr_pair_find_by_num(request->packet->vps, PW_MSCHAP2_RESPONSE, VENDORPEC_MICROSOFT, TAG_ANY);
			if (!response) {
				REDEBUG("MS-CHAP2-Response is required to calculate MS-CHAPv1 challenge");
				return -1;
			}

			/*
			 *	FIXME: Much of this is copied from
			 *	below.  We should put it into a
			 *	separate function.
			 */

			/*
			 *	Responses are 50 octets.
			 */
			if (response->vp_length < 50) {
				REDEBUG("MS-CHAP-Response has the wrong format");
				return -1;
			}

			user_name = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
			if (!user_name) {
				REDEBUG("User-Name is required to calculate MS-CHAPv1 Challenge");
				return -1;
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
			response_name = fr_pair_find_by_num(request->packet->vps, PW_MS_CHAP_USER_NAME, 0, TAG_ANY);
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
					RWDEBUG2("NT Domain delimiter found, should we have enabled with_ntdomain_hack?");
					username_string = name_attr->vp_strvalue;
				}
			} else {
				username_string = name_attr->vp_strvalue;
			}

			if (response_name &&
			    ((user_name->vp_length != response_name->vp_length) ||
			     (strncasecmp(user_name->vp_strvalue, response_name->vp_strvalue,
			     		  user_name->vp_length) != 0))) {
				RWDEBUG2("User-Name (%s) is not the same as MS-CHAP Name (%s) from EAP-MSCHAPv2",
					 user_name->vp_strvalue, response_name->vp_strvalue);
			}

			/*
			 *	Get the MS-CHAPv1 challenge
			 *	from the MS-CHAPv2 peer challenge,
			 *	our challenge, and the user name.
			 */
			RDEBUG2("Creating challenge hash with username: %s", username_string);
			mschap_challenge_hash(response->vp_octets + 2,
				       chap_challenge->vp_octets,
				       username_string, buffer);
			data = buffer;
			data_len = 8;
		} else {
			REDEBUG("Invalid MS-CHAP challenge length");
			return -1;
		}

	/*
	 *	Get the MS-CHAPv1 response, or the MS-CHAPv2
	 *	response.
	 */
	} else if (strncasecmp(fmt, "NT-Response", 11) == 0) {
		response = fr_pair_find_by_num(request->packet->vps, PW_MSCHAP_RESPONSE, VENDORPEC_MICROSOFT, TAG_ANY);
		if (!response) response = fr_pair_find_by_num(request->packet->vps, PW_MSCHAP2_RESPONSE, VENDORPEC_MICROSOFT, TAG_ANY);
		if (!response) {
			REDEBUG("No MS-CHAP-Response or MS-CHAP2-Response was found in the request");
			return -1;
		}

		/*
		 *	For MS-CHAPv1, the NT-Response exists only
		 *	if the second octet says so.
		 */
		if ((response->da->vendor == VENDORPEC_MICROSOFT) &&
		    (response->da->attr == PW_MSCHAP_RESPONSE) &&
		    ((response->vp_octets[1] & 0x01) == 0)) {
			REDEBUG("No NT-Response in MS-CHAP-Response");
			return -1;
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
		response = fr_pair_find_by_num(request->packet->vps, PW_MSCHAP_RESPONSE, VENDORPEC_MICROSOFT, TAG_ANY);
		if (!response) {
			REDEBUG("No MS-CHAP-Response was found in the request");
			return -1;
		}

		/*
		 *	For MS-CHAPv1, the LM-Response exists only
		 *	if the second octet says so.
		 */
		if ((response->vp_octets[1] & 0x01) != 0) {
			REDEBUG("No LM-Response in MS-CHAP-Response");
			return -1;
		}
		data = response->vp_octets + 2;
		data_len = 24;

	/*
	 *	Pull the domain name out of the User-Name, if it exists.
	 *
	 *	This is the full domain name, not just the name after host/
	 */
	} else if (strncasecmp(fmt, "Domain-Name", 11) == 0) {
		char *p;

		user_name = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
		if (!user_name) {
			REDEBUG("No User-Name was found in the request");
			return -1;
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
				strlcpy(out, p, outlen);
			}
		} else {
			p = strchr(user_name->vp_strvalue, '\\');
			if (!p) {
				REDEBUG("No NT-Domain was found in the User-Name");
				return -1;
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
	 *	Pull the NT-Domain out of the User-Name, if it exists.
	 */
	} else if (strncasecmp(fmt, "NT-Domain", 9) == 0) {
		char *p, *q;

		user_name = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
		if (!user_name) {
			REDEBUG("No User-Name was found in the request");
			return -1;
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
				REDEBUG("No NT-Domain was found in the User-Name");
				return -1;
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
		char const *p, *q;

		user_name = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
		if (!user_name) {
			REDEBUG("No User-Name was found in the request");
			return -1;
		}

		/*
		 *	First check to see if this is a host/ style User-Name
		 *	(a la Kerberos host principal)
		 */
		if (strncmp(user_name->vp_strvalue, "host/", 5) == 0) {
			p = user_name->vp_strvalue + 5;
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
			q = strchr(p, '.');

			/*
			 * use the same hack as above
			 * only if a period was found
			 */
			if (q) {
				snprintf(out, outlen, "%.*s$",
					 (int) (q - p), p);
			} else {
				snprintf(out, outlen, "%s$", p);
			}
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
		char const *p;

		p = fmt + 8;	/* 7 is the length of 'NT-Hash' */
		if ((*p == '\0') || (outlen <= 32))
			return 0;

		while (isspace((uint8_t) *p)) p++;

		if (mschap_ntpwdhash(buffer, p) < 0) {
			REDEBUG("Failed generating NT-Password");
			*buffer = '\0';
			return -1;
		}

		fr_bin2hex(out, buffer, NT_DIGEST_LENGTH);
		out[32] = '\0';
		RDEBUG("NT-Hash of \"known-good\" password: %s", out);
		return 32;

	/*
	 * Return the LM-Hash of the passed string
	 */
	} else if (strncasecmp(fmt, "LM-Hash ", 8) == 0) {
		char const *p;

		p = fmt + 8;	/* 7 is the length of 'LM-Hash' */
		if ((*p == '\0') || (outlen <= 32))
			return 0;

		while (isspace((uint8_t) *p)) p++;

		smbdes_lmpwdhash(p, buffer);
		fr_bin2hex(out, buffer, LM_DIGEST_LENGTH);
		out[32] = '\0';
		RDEBUG("LM-Hash of %s = %s", p, out);
		return 32;
	} else {
		REDEBUG("Unknown expansion string '%s'", fmt);
		return -1;
	}

	if (outlen == 0) return 0; /* nowhere to go, don't do anything */

	/*
	 *	Didn't set anything: this is bad.
	 */
	if (!data) {
		RWDEBUG2("Failed to do anything intelligent");
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


#ifdef WITH_AUTH_WINBIND
/*
 *	Free connection pool winbind context
 */
static int _mod_conn_free(struct wbcContext **wb_ctx)
{
	wbcCtxFree(*wb_ctx);

	return 0;
}

/*
 *	Create connection pool winbind context
 */
static void *mod_conn_create(TALLOC_CTX *ctx, UNUSED void *instance)
{
	struct wbcContext **wb_ctx;

	wb_ctx = talloc_zero(ctx, struct wbcContext *);
	*wb_ctx = wbcCtxCreate();

	if (*wb_ctx == NULL) {
		ERROR("failed to create winbind context");
		talloc_free(wb_ctx);
		return NULL;
	}

	talloc_set_destructor(wb_ctx, _mod_conn_free);

	return *wb_ctx;
}
#endif


static const CONF_PARSER passchange_config[] = {
	{ "ntlm_auth", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_mschap_t, ntlm_cpw), NULL },
	{ "ntlm_auth_username", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_mschap_t, ntlm_cpw_username), NULL },
	{ "ntlm_auth_domain", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_mschap_t, ntlm_cpw_domain), NULL },
	{ "local_cpw", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_mschap_t, local_cpw), NULL },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER module_config[] = {
	/*
	 *	Cache the password by default.
	 */
	{ "use_mppe", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_mschap_t, use_mppe), "yes" },
	{ "require_encryption", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_mschap_t, require_encryption), "no" },
	{ "require_strong", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_mschap_t, require_strong), "no" },
	{ "with_ntdomain_hack", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_mschap_t, with_ntdomain_hack), "yes" },
	{ "ntlm_auth", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_mschap_t, ntlm_auth), NULL },
	{ "ntlm_auth_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_mschap_t, ntlm_auth_timeout), NULL },
	{ "passchange", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) passchange_config },
	{ "allow_retry", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_mschap_t, allow_retry), "yes" },
	{ "retry_msg", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_mschap_t, retry_msg), NULL },
	{ "winbind_username", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_TMPL, rlm_mschap_t, wb_username), NULL },
	{ "winbind_domain", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_TMPL, rlm_mschap_t, wb_domain), NULL },
	{ "winbind_retry_with_normalised_username", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_mschap_t, wb_retry_with_normalised_username), "no" },
#ifdef __APPLE__
	{ "use_open_directory", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_mschap_t, open_directory), "yes" },
#endif
	CONF_PARSER_TERMINATOR
};


static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	char const *name;
	rlm_mschap_t *inst = instance;

	/*
	 *	Create the dynamic translation.
	 */
	name = cf_section_name2(conf);
	if (!name) name = cf_section_name1(conf);
	inst->xlat_name = name;
	xlat_register(inst->xlat_name, mschap_xlat, NULL, inst);

	return 0;
}

/*
 *	Create instance for our module. Allocate space for
 *	instance structure and read configuration parameters
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_mschap_t *inst = instance;

	/*
	 *	For backwards compatibility
	 */
	if (!dict_valbyname(PW_AUTH_TYPE, 0, inst->xlat_name)) {
		inst->auth_type = "MS-CHAP";
	} else {
		inst->auth_type = inst->xlat_name;
	}

	/*
	 *	Set auth method
	 */
	inst->method = AUTH_INTERNAL;

	if (inst->wb_username) {
#ifdef WITH_AUTH_WINBIND
		inst->method = AUTH_WBCLIENT;

		inst->wb_pool = fr_connection_pool_module_init(conf, inst, mod_conn_create, NULL, NULL);
		if (!inst->wb_pool) {
			cf_log_err_cs(conf, "Unable to initialise winbind connection pool");
			return -1;
		}
#else
		cf_log_err_cs(conf, "'winbind' is not enabled in this build.");
		return -1;
#endif
	}

	/* preserve existing behaviour: this option overrides all */
	if (inst->ntlm_auth) {
		inst->method = AUTH_NTLMAUTH_EXEC;
	}

	switch (inst->method) {
	case AUTH_INTERNAL:
		DEBUG("rlm_mschap (%s): using internal authentication", inst->xlat_name);
		break;
	case AUTH_NTLMAUTH_EXEC:
		DEBUG("rlm_mschap (%s): authenticating by calling 'ntlm_auth'", inst->xlat_name);
		break;
#ifdef WITH_AUTH_WINBIND
	case AUTH_WBCLIENT:
		DEBUG("rlm_mschap (%s): authenticating directly to winbind", inst->xlat_name);
		break;
#endif
	}

	/*
	 *	Check ntlm_auth_timeout is sane
	 */
	if (!inst->ntlm_auth_timeout) {
		inst->ntlm_auth_timeout = EXEC_TIMEOUT;
	}
	if (inst->ntlm_auth_timeout < 1) {
		cf_log_err_cs(conf, "ntml_auth_timeout '%d' is too small (minimum: 1)",
			      inst->ntlm_auth_timeout);
		return -1;
	}
	if (inst->ntlm_auth_timeout > 10) {
		cf_log_err_cs(conf, "ntlm_auth_timeout '%d' is too large (maximum: 10)",
			      inst->ntlm_auth_timeout);
		return -1;
	}

	return 0;
}

/*
 *	Tidy up instance
 */
static int mod_detach(UNUSED void *instance)
{
#ifdef WITH_AUTH_WINBIND
	rlm_mschap_t *inst = instance;

	fr_connection_pool_free(inst->wb_pool);
#endif

	return 0;
}

/*
 *	add_reply() adds either MS-CHAP2-Success or MS-CHAP-Error
 *	attribute to reply packet
 */
void mschap_add_reply(REQUEST *request, unsigned char ident,
		      char const *name, char const *value, size_t len)
{
	VALUE_PAIR *vp;

	vp = pair_make_reply(name, NULL, T_OP_EQ);
	if (!vp) {
		REDEBUG("Failed to create attribute %s: %s", name, fr_strerror());
		return;
	}

	/* Account for the ident byte */
	vp->vp_length = len + 1;
	if (vp->da->type == PW_TYPE_STRING) {
		char *p;

		vp->vp_strvalue = p = talloc_array(vp, char, vp->vp_length + 1);
		p[vp->vp_length] = '\0';	/* Always \0 terminate */
		p[0] = ident;
		memcpy(p + 1, value, len);
	} else {
		uint8_t *p;

		vp->vp_octets = p = talloc_array(vp, uint8_t, vp->vp_length);
		p[0] = ident;
		memcpy(p + 1, value, len);
	}
}

/*
 *	Add MPPE attributes to the reply.
 */
static void mppe_add_reply(REQUEST *request, char const* name, uint8_t const * value, size_t len)
{
       VALUE_PAIR *vp;

       vp = pair_make_reply(name, NULL, T_OP_EQ);
       if (!vp) {
	       REDEBUG("mppe_add_reply failed to create attribute %s: %s", name, fr_strerror());
	       return;
       }

       fr_pair_value_memcpy(vp, value, len);
}

static int write_all(int fd, char const *buf, int len) {
	int rv,done=0;

	while (done < len) {
		rv = write(fd, buf+done, len-done);
		if (rv <= 0)
			break;
		done += rv;
	}
	return done;
}

/*
 * Perform an MS-CHAP2 password change
 */

static int CC_HINT(nonnull (1, 2, 4, 5)) do_mschap_cpw(rlm_mschap_t *inst,
						       REQUEST *request,
#ifdef HAVE_OPENSSL_CRYPTO_H
						       VALUE_PAIR *nt_password,
#else
						       UNUSED VALUE_PAIR *nt_password,
#endif
						       uint8_t *new_nt_password,
						       uint8_t *old_nt_hash,
						       MSCHAP_AUTH_METHOD method)
{
	if (inst->ntlm_cpw && method != AUTH_INTERNAL) {
		/*
		 * we're going to run ntlm_auth in helper-mode
		 * we're expecting to use the ntlm-change-password-1 protocol
		 * which needs the following on stdin:
		 *
		 * username: %{mschap:User-Name}
		 * nt-domain: %{mschap:NT-Domain}
		 * new-nt-password-blob: bin2hex(new_nt_password) - 1032 bytes encoded
		 * old-nt-hash-blob: bin2hex(old_nt_hash) - 32 bytes encoded
		 * new-lm-password-blob: 00000...0000 - 1032 bytes null
		 * old-lm-hash-blob: 000....000 - 32 bytes null
		 * .\n
		 *
		 * ...and it should then print out
		 *
		 * Password-Change: Yes
		 *
		 * or
		 *
		 * Password-Change: No
		 * Password-Change-Error: blah
		 */

		int to_child=-1;
		int from_child=-1;
		pid_t pid, child_pid;
		int status, len;
		char buf[2048];
		char *pmsg;
		char const *emsg;

		RDEBUG("Doing MS-CHAPv2 password change via ntlm_auth helper");

		/*
		 * Start up ntlm_auth with a pipe on stdin and stdout
		 */

		pid = radius_start_program(inst->ntlm_cpw, request, true, &to_child, &from_child, NULL, false);
		if (pid < 0) {
			REDEBUG("could not exec ntlm_auth cpw command");
			return -1;
		}

		/*
		 * write the stuff to the client
		 */

		if (inst->ntlm_cpw_username) {
			len = radius_xlat(buf, sizeof(buf) - 2, request, inst->ntlm_cpw_username, NULL, NULL);
			if (len < 0) {
				goto ntlm_auth_err;
			}

			buf[len++] = '\n';
			buf[len] = '\0';

			if (write_all(to_child, buf, len) != len) {
				REDEBUG("Failed to write username to child");
				goto ntlm_auth_err;
			}
		} else {
			RWDEBUG2("No ntlm_auth username set, passchange will definitely fail!");
		}

		if (inst->ntlm_cpw_domain) {
			len = radius_xlat(buf, sizeof(buf) - 2, request, inst->ntlm_cpw_domain, NULL, NULL);
			if (len < 0) {
				goto ntlm_auth_err;
			}

			buf[len++] = '\n';
			buf[len] = '\0';

			if (write_all(to_child, buf, len) != len) {
				REDEBUG("Failed to write domain to child");
				goto ntlm_auth_err;
			}
		} else {
			RWDEBUG2("No ntlm_auth domain set, username must be full-username to work");
		}

		/* now the password blobs */
		len = sprintf(buf, "new-nt-password-blob: ");
		fr_bin2hex(buf+len, new_nt_password, 516);
		buf[len+1032] = '\n';
		buf[len+1033] = '\0';
		len = strlen(buf);
		if (write_all(to_child, buf, len) != len) {
			RDEBUG2("failed to write new password blob to child");
			goto ntlm_auth_err;
		}

		len = sprintf(buf, "old-nt-hash-blob: ");
		fr_bin2hex(buf+len, old_nt_hash, NT_DIGEST_LENGTH);
		buf[len+32] = '\n';
		buf[len+33] = '\0';
		len = strlen(buf);
		if (write_all(to_child, buf, len) != len) {
			REDEBUG("Failed to write old hash blob to child");
			goto ntlm_auth_err;
		}

		/*
		 *  In current samba versions, failure to supply empty LM password/hash
		 *  blobs causes the change to fail.
		 */
		len = sprintf(buf, "new-lm-password-blob: %01032i\n", 0);
		if (write_all(to_child, buf, len) != len) {
			REDEBUG("Failed to write dummy LM password to child");
			goto ntlm_auth_err;
		}
		len = sprintf(buf, "old-lm-hash-blob: %032i\n", 0);
		if (write_all(to_child, buf, len) != len) {
			REDEBUG("Failed to write dummy LM hash to child");
			goto ntlm_auth_err;
		}
		if (write_all(to_child, ".\n", 2) != 2) {
			REDEBUG("Failed to send finish to child");
			goto ntlm_auth_err;
		}
		close(to_child);
		to_child = -1;

		/*
		 *  Read from the child
		 */
		len = radius_readfrom_program(from_child, pid, 10, buf, sizeof(buf));
		if (len < 0) {
			/* radius_readfrom_program will have closed from_child for us */
			REDEBUG("Failure reading from child");
			return -1;
		}
		close(from_child);
		from_child = -1;

		buf[len] = 0;
		RDEBUG2("ntlm_auth said: %s", buf);

		child_pid = rad_waitpid(pid, &status);
		if (child_pid == 0) {
			REDEBUG("Timeout waiting for child");
			return -1;
		}
		if (child_pid != pid) {
			REDEBUG("Abnormal exit status: %s", fr_syserror(errno));
			return -1;
		}

		if (strstr(buf, "Password-Change: Yes")) {
			RDEBUG2("ntlm_auth password change succeeded");
			return 0;
		}

		pmsg = strstr(buf, "Password-Change-Error: ");
		if (pmsg) {
			emsg = strsep(&pmsg, "\n");
		} else {
			emsg = "could not find error";
		}
		REDEBUG("ntlm auth password change failed: %s", emsg);

ntlm_auth_err:
		/* safe because these either need closing or are == -1 */
		close(to_child);
		close(from_child);

		return -1;

	} else if (inst->local_cpw) {
#ifdef HAVE_OPENSSL_CRYPTO_H
		/*
		 *  Decrypt the new password blob, add it as a temporary request
		 *  variable, xlat the local_cpw string, then remove it
		 *
		 *  this allows is to write e..g
		 *
		 *  %{sql:insert into ...}
		 *
		 *  ...or...
		 *
		 *  %{exec:/path/to %{mschap:User-Name} %{MS-CHAP-New-Password}}"
		 *
		 */
		VALUE_PAIR *new_pass, *new_hash;
		uint8_t *p, *q;
		char *x;
		size_t i;
		size_t passlen;
		ssize_t result_len;
		char result[253];
		uint8_t nt_pass_decrypted[516], old_nt_hash_expected[NT_DIGEST_LENGTH];

		if (!nt_password) {
			RDEBUG("Local MS-CHAPv2 password change requires NT-Password attribute");
			return -1;
		} else {
			RDEBUG("Doing MS-CHAPv2 password change locally");
		}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		{
			EVP_CIPHER_CTX *ctx;
			int ntlen = sizeof(nt_pass_decrypted);

			ctx = EVP_CIPHER_CTX_new();
			if (!ctx) {
				REDEBUG("Failed getting RC4 from OpenSSL");
			error:
				if (ctx) EVP_CIPHER_CTX_free(ctx);
				return -1;
			}

			if (!EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, nt_password->vp_octets, NULL)) {
				REDEBUG("Failed setting key value");
				goto error;;
			}

			if (!EVP_CIPHER_CTX_set_key_length(ctx, nt_password->vp_length)) {
				REDEBUG("Failed setting key length");
				goto error;
			}

			if (!EVP_EncryptUpdate(ctx, nt_pass_decrypted, &ntlen, new_nt_password, ntlen)) {
				REDEBUG("Failed getting output");
				goto error;
			}

			EVP_CIPHER_CTX_free(ctx);
		}
#else
		{
			RC4_KEY key;

			/*
			 *  Decrypt the blob
			 */
			RC4_set_key(&key, nt_password->vp_length, nt_password->vp_octets);
			RC4(&key, 516, new_nt_password, nt_pass_decrypted);
		}
#endif

		/*
		 *  pwblock is
		 *  512-N bytes random pad
		 *  N bytes password as utf-16-le
		 *  4 bytes - N as big-endian int
		 */
		passlen = nt_pass_decrypted[512];
		passlen += nt_pass_decrypted[513] << 8;
		if ((nt_pass_decrypted[514] != 0) ||
		    (nt_pass_decrypted[515] != 0)) {
			REDEBUG("Decrypted new password blob claims length > 65536, "
				"probably an invalid NT-Password");
			return -1;
		}

		/*
		 *  Sanity check - passlen positive and <= 512 if not, crypto has probably gone wrong
		 */
		if (passlen > 512) {
			REDEBUG("Decrypted new password blob claims length %zu > 512, "
				"probably an invalid NT-Password", passlen);
			return -1;
		}

		p = nt_pass_decrypted + 512 - passlen;

		/*
		 *  The new NT hash - this should be preferred over the
		 *  cleartext password as it avoids unicode hassles.
		 */
		new_hash = pair_make_request("MS-CHAP-New-NT-Password", NULL, T_OP_EQ);
		new_hash->vp_length = NT_DIGEST_LENGTH;
		new_hash->vp_octets = q = talloc_array(new_hash, uint8_t, new_hash->vp_length);
		fr_md4_calc(q, p, passlen);

		/*
		 *  Check that nt_password encrypted with new_hash
		 *  matches the old_hash value from the client.
		 */
		smbhash(old_nt_hash_expected, nt_password->vp_octets, q);
		smbhash(old_nt_hash_expected+8, nt_password->vp_octets+8, q + 7);
		if (memcmp(old_nt_hash_expected, old_nt_hash, NT_DIGEST_LENGTH)!=0) {
			REDEBUG("Old NT hash value from client does not match our value");
			return -1;
		}

		/*
		 *  The new cleartext password, which is utf-16 do some unpleasant vileness
		 *  to turn it into utf8 without pulling in libraries like iconv.
		 *
		 *  First pass: get the length of the converted string.
		 */
		new_pass = pair_make_request("MS-CHAP-New-Cleartext-Password", NULL, T_OP_EQ);
		new_pass->vp_length = 0;

		i = 0;
		while (i < passlen) {
			int c;

			c = p[i++];
			c += p[i++] << 8;

			/*
			 *  Gah. nasty. maybe we should just pull in iconv?
			 */
			if (c < 0x7f) {
				new_pass->vp_length++;
			} else if (c < 0x7ff) {
				new_pass->vp_length += 2;
			} else {
				new_pass->vp_length += 3;
			}
		}

		new_pass->vp_strvalue = x = talloc_array(new_pass, char, new_pass->vp_length + 1);

		/*
		 *	Second pass: convert the characters from UTF-16 to UTF-8.
		 */
		i = 0;
		while (i < passlen) {
			int c;

			c = p[i++];
			c += p[i++] << 8;

			/*
			 *  Gah. nasty. maybe we should just pull in iconv?
			 */
			if (c < 0x7f) {
				*x++ = c;

			} else if (c < 0x7ff) {
				*x++ = 0xc0 + (c >> 6);
				*x++ = 0x80 + (c & 0x3f);

			} else {
				*x++ = 0xe0 + (c >> 12);
				*x++ = 0x80 + ((c>>6) & 0x3f);
				*x++ = 0x80 + (c & 0x3f);
			}
		}

		*x = '\0';

		/* Perform the xlat */
		result_len = radius_xlat(result, sizeof(result), request, inst->local_cpw, NULL, NULL);
		if (result_len < 0){
			return -1;
		} else if (result_len == 0) {
			REDEBUG("Local MS-CHAPv2 password change - xlat didn't give any result, assuming failure");
			return -1;
		}

		RDEBUG("MS-CHAPv2 password change succeeded: %s", result);

		/*
		 *  Update the NT-Password attribute with the new hash this lets us
		 *  fall through to the authentication code using the new hash,
		 *  not the old one.
		 */
		fr_pair_value_memcpy(nt_password, new_hash->vp_octets, new_hash->vp_length);

		/*
		 *  Rock on! password change succeeded.
		 */
		return 0;
#else
		REDEBUG("Local MS-CHAPv2 password changes require OpenSSL support");
		return -1;
#endif
	} else {
		REDEBUG("MS-CHAPv2 password change not configured");
	}

	return -1;
}

/*
 *	Do the MS-CHAP stuff.
 *
 *	This function is here so that all of the MS-CHAP related
 *	authentication is in one place, and we can perhaps later replace
 *	it with code to call winbindd, or something similar.
 */
static int CC_HINT(nonnull (1, 2, 4, 5 ,6)) do_mschap(rlm_mschap_t *inst, REQUEST *request, VALUE_PAIR *password,
						      uint8_t const *challenge, uint8_t const *response,
						      uint8_t nthashhash[NT_DIGEST_LENGTH], MSCHAP_AUTH_METHOD method)
{
	uint8_t	calculated[24];

	memset(nthashhash, 0, NT_DIGEST_LENGTH);

	switch (method) {
		/*
		 *	Do normal authentication.
		 */
	case AUTH_INTERNAL:
		/*
		 *	No password: can't do authentication.
		 */
		if (!password) {
			REDEBUG("FAILED: No NT-Password.  Cannot perform authentication");
			return -1;
		}

		smbdes_mschap(password->vp_octets, challenge, calculated);
		if (rad_digest_cmp(response, calculated, 24) != 0) {
			return -1;
		}

		/*
		 *	If the password exists, and is an NT-Password,
		 *	then calculate the hash of the NT hash.  Doing this
		 *	here minimizes work for later.
		 */
		if (!password->da->vendor &&
		    (password->da->attr == PW_NT_PASSWORD)) {
			fr_md4_calc(nthashhash, password->vp_octets, MD4_DIGEST_LENGTH);
		}
		break;

		/*
		 *	Run ntlm_auth
		 */
	case AUTH_NTLMAUTH_EXEC: {
		int	result;
		char	buffer[256];
		size_t	len;

		/*
		 *	Run the program, and expect that we get 16
		 */
		result = radius_exec_program(request, buffer, sizeof(buffer), NULL, request, inst->ntlm_auth, NULL,
					     true, true, inst->ntlm_auth_timeout);
		if (result != 0) {
			char *p;

			/*
			 *	Do checks for numbers, which are
			 *	language neutral.  They're also
			 *	faster.
			 */
			p = strcasestr(buffer, "0xC0000");
			if (p) {
				int rcode = 0;

				p += 7;
				if (strcmp(p, "224") == 0) {
					rcode = -648;

				} else if (strcmp(p, "234") == 0) {
					rcode = -647;

				} else if (strcmp(p, "072") == 0) {
					rcode = -691;

				} else if (strcasecmp(p, "05E") == 0) {
					rcode = -2;
				}

				if (rcode != 0) {
					REDEBUG2("%s", buffer);
					return rcode;
				}

				/*
				 *	Else fall through to more ridiculous checks.
				 */
			}

			/*
			 *	Look for variants of expire password.
			 */
			if (strcasestr(buffer, "0xC0000224") ||
			    strcasestr(buffer, "Password expired") ||
			    strcasestr(buffer, "Password has expired") ||
			    strcasestr(buffer, "Password must be changed") ||
			    strcasestr(buffer, "Must change password")) {
				return -648;
			}

			if (strcasestr(buffer, "0xC0000234") ||
			    strcasestr(buffer, "Account locked out")) {
				REDEBUG2("%s", buffer);
				return -647;
			}

			if (strcasestr(buffer, "0xC0000072") ||
			    strcasestr(buffer, "Account disabled")) {
				REDEBUG2("%s", buffer);
				return -691;
			}

			if (strcasestr(buffer, "0xC000005E") ||
			    strcasestr(buffer, "No logon servers")) {
				REDEBUG2("%s", buffer);
				return -2;
			}

			if (strcasestr(buffer, "could not obtain winbind separator") ||
			    strcasestr(buffer, "Reading winbind reply failed")) {
				REDEBUG2("%s", buffer);
				return -2;
			}

			RDEBUG2("External script failed");
			p = strchr(buffer, '\n');
			if (p) *p = '\0';

			REDEBUG("External script says: %s", buffer);
			return -1;
		}

		/*
		 *	Parse the answer as an nthashhash.
		 *
		 *	ntlm_auth currently returns:
		 *	NT_KEY: 000102030405060708090a0b0c0d0e0f
		 */
		if (memcmp(buffer, "NT_KEY: ", 8) != 0) {
			REDEBUG("Invalid output from ntlm_auth: expecting 'NT_KEY: ' prefix");
			return -1;
		}

		/*
		 *	Check the length.  It should be at least 32, with an LF at the end.
		 */
		len = strlen(buffer + 8);
		if (len < 32) {
			REDEBUG2("Invalid output from ntlm_auth: NT_KEY too short, expected 32 bytes got %zu bytes",
				 len);

			return -1;
		}

		/*
		 *	Update the NT hash hash, from the NT key.
		 */
		if (fr_hex2bin(nthashhash, NT_DIGEST_LENGTH, buffer + 8, len) != NT_DIGEST_LENGTH) {
			REDEBUG("Invalid output from ntlm_auth: NT_KEY has non-hex values");
			return -1;
		}
		break;
	}

#ifdef WITH_AUTH_WINBIND
		/*
		 *	Process auth via the wbclient library
		 */
	case AUTH_WBCLIENT:
		return do_auth_wbclient(inst, request, challenge, response, nthashhash);
#endif

		/* We should never reach this line */
	default:
		RERROR("Internal error: Unknown mschap auth method (%d)", method);
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


static void mppe_GetMasterKey(uint8_t const *nt_hashhash,uint8_t const *nt_response,
			      uint8_t *masterkey)
{
       uint8_t digest[20];
       fr_sha1_ctx Context;

       fr_sha1_init(&Context);
       fr_sha1_update(&Context,nt_hashhash,NT_DIGEST_LENGTH);
       fr_sha1_update(&Context,nt_response,24);
       fr_sha1_update(&Context,magic1,27);
       fr_sha1_final(digest,&Context);

       memcpy(masterkey,digest,16);
}


static void mppe_GetAsymmetricStartKey(uint8_t *masterkey,uint8_t *sesskey,
				       int keylen,int issend)
{
       uint8_t digest[20];
       const uint8_t *s;
       fr_sha1_ctx Context;

       memset(digest,0,20);

       if(issend) {
	       s = magic3;
       } else {
	       s = magic2;
       }

       fr_sha1_init(&Context);
       fr_sha1_update(&Context,masterkey,16);
       fr_sha1_update(&Context,SHSpad1,40);
       fr_sha1_update(&Context,s,84);
       fr_sha1_update(&Context,SHSpad2,40);
       fr_sha1_final(digest,&Context);

       memcpy(sesskey,digest,keylen);
}


static void mppe_chap2_get_keys128(uint8_t const *nt_hashhash,uint8_t const *nt_response,
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
static void mppe_chap2_gen_keys128(uint8_t const *nt_hashhash,uint8_t const *response,
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
 *	mod_authorize() - authorize user if we can authenticate
 *	it later. Add Auth-Type attribute if present in module
 *	configuration (usually Auth-Type must be "MS-CHAP")
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void * instance, REQUEST *request)
{
	rlm_mschap_t *inst = instance;
	VALUE_PAIR *challenge = NULL;

	challenge = fr_pair_find_by_num(request->packet->vps, PW_MSCHAP_CHALLENGE, VENDORPEC_MICROSOFT, TAG_ANY);
	if (!challenge) {
		return RLM_MODULE_NOOP;
	}

	if (!fr_pair_find_by_num(request->packet->vps, PW_MSCHAP_RESPONSE, VENDORPEC_MICROSOFT, TAG_ANY) &&
	    !fr_pair_find_by_num(request->packet->vps, PW_MSCHAP2_RESPONSE, VENDORPEC_MICROSOFT, TAG_ANY) &&
	    !fr_pair_find_by_num(request->packet->vps, PW_MSCHAP2_CPW, VENDORPEC_MICROSOFT, TAG_ANY)) {
		RDEBUG2("Found MS-CHAP-Challenge, but no MS-CHAP response or change-password");
		return RLM_MODULE_NOOP;
	}

	if (fr_pair_find_by_num(request->config, PW_AUTH_TYPE, 0, TAG_ANY)) {
		RWDEBUG2("Auth-Type already set.  Not setting to MS-CHAP");
		return RLM_MODULE_NOOP;
	}

	RDEBUG2("Found MS-CHAP attributes.  Setting 'Auth-Type  = %s'", inst->xlat_name);

	/*
	 *	Set Auth-Type to MS-CHAP.  The authentication code
	 *	will take care of turning cleartext passwords into
	 *	NT/LM passwords.
	 */
	if (!pair_make_config("Auth-Type", inst->auth_type, T_OP_EQ)) {
		return RLM_MODULE_FAIL;
	}

	return RLM_MODULE_OK;
}

static rlm_rcode_t mschap_error(rlm_mschap_t *inst, REQUEST *request, unsigned char ident,
				int mschap_result, int mschap_version, VALUE_PAIR *smb_ctrl)
{
	rlm_rcode_t	rcode = RLM_MODULE_OK;
	int		error = 0;
	int		retry = 0;
	char const	*message = NULL;

	int		i;
	char		new_challenge[33], buffer[128];
	char		*p;

	if ((mschap_result == -648) ||
	    ((mschap_result == 0) &&
	     (smb_ctrl && ((smb_ctrl->vp_integer & ACB_PW_EXPIRED) != 0)))) {
		REDEBUG("Password has expired.  User should retry authentication");
		error = 648;

		/*
		 *	A password change is NOT a retry!  We MUST have retry=0 here.
		 */
		retry = 0;
		message = "Password expired";
		rcode = RLM_MODULE_REJECT;

		/*
		 *	Account is disabled.
		 *
		 *	They're found, but they don't exist, so we
		 *	return 'not found'.
		 */
	} else if ((mschap_result == -691) ||
		   (smb_ctrl && (((smb_ctrl->vp_integer & ACB_DISABLED) != 0) ||
				 ((smb_ctrl->vp_integer & (ACB_NORMAL|ACB_WSTRUST)) == 0)))) {
		REDEBUG("SMB-Account-Ctrl (or ntlm_auth) "
			"says that the account is disabled, "
			"or is not a normal or workstation trust account");
		error = 691;
		retry = 0;
		message = "Account disabled";
		rcode = RLM_MODULE_NOTFOUND;

		/*
		 *	User is locked out.
		 */
	} else if ((mschap_result == -647) ||
		   (smb_ctrl && ((smb_ctrl->vp_integer & ACB_AUTOLOCK) != 0))) {
		REDEBUG("SMB-Account-Ctrl (or ntlm_auth) "
			"says that the account is locked out");
		error = 647;
		retry = 0;
		message = "Account locked out";
		rcode = RLM_MODULE_USERLOCK;
	} else if (mschap_result == -2) {
		RDEBUG("Authentication failed");
		error = 691;
		retry = inst->allow_retry;
		message = "Authentication failed";
		rcode = RLM_MODULE_FAIL;

	} else if (mschap_result < 0) {
		REDEBUG("MS-CHAP2-Response is incorrect");
		error = 691;
		retry = inst->allow_retry;
		message = "Authentication rejected";
		rcode = RLM_MODULE_REJECT;
	}

	if (rcode == RLM_MODULE_OK) return RLM_MODULE_OK;

	switch (mschap_version) {
	case 1:
		for (p = new_challenge, i = 0; i < 2; i++) p += snprintf(p, 9, "%08x", fr_rand());
		snprintf(buffer, sizeof(buffer), "E=%i R=%i C=%s V=2",
			 error, retry, new_challenge);
		break;

	case 2:
		for (p = new_challenge, i = 0; i < 4; i++) p += snprintf(p, 9, "%08x", fr_rand());
		snprintf(buffer, sizeof(buffer), "E=%i R=%i C=%s V=3 M=%s",
			 error, retry, new_challenge, message);
		break;

	default:
		return RLM_MODULE_FAIL;
	}
	mschap_add_reply(request, ident, "MS-CHAP-Error", buffer, strlen(buffer));

	return rcode;
}

/*
 *	mod_authenticate() - authenticate user based on given
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
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
	rlm_mschap_t *inst = instance;
	VALUE_PAIR *challenge = NULL;
	VALUE_PAIR *response = NULL;
	VALUE_PAIR *cpw = NULL;
	VALUE_PAIR *password = NULL;
	VALUE_PAIR *nt_password, *smb_ctrl;
	VALUE_PAIR *username;
	uint8_t nthashhash[NT_DIGEST_LENGTH];
	char msch2resp[42];
	char const *username_string;
	int mschap_version = 0;
	int mschap_result;
	MSCHAP_AUTH_METHOD auth_method;

	/*
	 *	If we have ntlm_auth configured, use it unless told
	 *	otherwise
	 */
	auth_method = inst->method;

	/*
	 *	If we have an ntlm_auth configuration, then we may
	 *	want to suppress it.
	 */
	if (auth_method != AUTH_INTERNAL) {
		VALUE_PAIR *vp = fr_pair_find_by_num(request->config, PW_MS_CHAP_USE_NTLM_AUTH, 0, TAG_ANY);
		if (vp && vp->vp_integer == 0) auth_method = AUTH_INTERNAL;
	}

	/*
	 *	Find the SMB-Account-Ctrl attribute, or the
	 *	SMB-Account-Ctrl-Text attribute.
	 */
	smb_ctrl = fr_pair_find_by_num(request->config, PW_SMB_ACCOUNT_CTRL, 0, TAG_ANY);
	if (!smb_ctrl) {
		password = fr_pair_find_by_num(request->config, PW_SMB_ACCOUNT_CTRL_TEXT, 0, TAG_ANY);
		if (password) {
			smb_ctrl = pair_make_config("SMB-Account-CTRL", "0", T_OP_SET);
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
			RDEBUG2("SMB-Account-Ctrl says no password is required");
			return RLM_MODULE_OK;
		}
	}

	/*
	 *	Decide how to get the passwords.
	 */
	password = fr_pair_find_by_num(request->config, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY);

	/*
	 *	We need an NT-Password.
	 */
	nt_password = fr_pair_find_by_num(request->config, PW_NT_PASSWORD, 0, TAG_ANY);
	if (nt_password) {
		VERIFY_VP(nt_password);

		switch (nt_password->vp_length) {
		case NT_DIGEST_LENGTH:
			RDEBUG2("Found NT-Password");
			break;

		/* 0x */
		case 34:
		case 32:
			RWDEBUG("NT-Password has not been normalized by the 'pap' module (likely still in hex format).  "
				"Authentication may fail");
			nt_password = NULL;
			break;

		default:
			RWDEBUG("NT-Password found but incorrect length, expected " STRINGIFY(NT_DIGEST_LENGTH)
				" bytes got %zu bytes.  Authentication may fail", nt_password->vp_length);
			nt_password = NULL;
			break;
		}
	}

	/*
	 *	... or a Cleartext-Password, which we now transform into an NT-Password
	 */
	if (!nt_password) {
		uint8_t *p;

		if (password) {
			RDEBUG2("Found Cleartext-Password, hashing to create NT-Password");
			nt_password = pair_make_config("NT-Password", NULL, T_OP_EQ);
			if (!nt_password) {
				RERROR("No memory");
				return RLM_MODULE_FAIL;
			}
			nt_password->vp_length = NT_DIGEST_LENGTH;
			nt_password->vp_octets = p = talloc_array(nt_password, uint8_t, nt_password->vp_length);

			if (mschap_ntpwdhash(p, password->vp_strvalue) < 0) {
				RERROR("Failed generating NT-Password - %s", fr_strerror());
				return RLM_MODULE_FAIL;
			}
		} else if (auth_method == AUTH_INTERNAL) {
			RWDEBUG2("No Cleartext-Password configured.  Cannot create NT-Password");
		}
	}

	cpw = fr_pair_find_by_num(request->packet->vps, PW_MSCHAP2_CPW, VENDORPEC_MICROSOFT, TAG_ANY);
	if (cpw) {
		/*
		 * mschap2 password change request
		 * we cheat - first decode and execute the passchange
		 * we then extract the response, add it into the request
		 * then jump into mschap2 auth with the chal/resp
		 */
		uint8_t		new_nt_encrypted[516], old_nt_encrypted[NT_DIGEST_LENGTH];
		VALUE_PAIR	*nt_enc=NULL;
		int		seq, new_nt_enc_len;
		uint8_t		*p;

		RDEBUG("MS-CHAPv2 password change request received");

		if (cpw->vp_length != 68) {
			REDEBUG("MS-CHAP2-CPW has the wrong format: length %zu != 68", cpw->vp_length);
			return RLM_MODULE_INVALID;
		}

		if (cpw->vp_octets[0] != 7) {
			REDEBUG("MS-CHAP2-CPW has the wrong format: code %d != 7", cpw->vp_octets[0]);
			return RLM_MODULE_INVALID;
		}

		/*
		 *  look for the new (encrypted) password
		 *  bah stupid composite attributes
		 *  we're expecting 3 attributes with the leading bytes
		 *  06:<mschapid>:00:01:<1st chunk>
		 *  06:<mschapid>:00:02:<2nd chunk>
		 *  06:<mschapid>:00:03:<3rd chunk>
		 */
		new_nt_enc_len = 0;
		for (seq = 1; seq < 4; seq++) {
			vp_cursor_t cursor;
			int found = 0;

			for (nt_enc = fr_cursor_init(&cursor, &request->packet->vps);
			     nt_enc;
			     nt_enc = fr_cursor_next(&cursor)) {
				if (nt_enc->da->vendor != VENDORPEC_MICROSOFT)
					continue;

				if (nt_enc->da->attr != PW_MSCHAP_NT_ENC_PW)
					continue;

				if (nt_enc->vp_length < 4) {
					REDEBUG("MS-CHAP-NT-Enc-PW with invalid format");
					return RLM_MODULE_INVALID;
				}

				if (nt_enc->vp_octets[0] != 6) {
					REDEBUG("MS-CHAP-NT-Enc-PW with invalid format");
					return RLM_MODULE_INVALID;
				}

				if ((nt_enc->vp_octets[2] == 0) && (nt_enc->vp_octets[3] == seq)) {
					found = 1;
					break;
				}
			}

			if (!found) {
				REDEBUG("Could not find MS-CHAP-NT-Enc-PW w/ sequence number %d", seq);
				return RLM_MODULE_INVALID;
			}

			if ((new_nt_enc_len + nt_enc->vp_length - 4) > sizeof(new_nt_encrypted)) {
				REDEBUG("Unpacked MS-CHAP-NT-Enc-PW length > 516");
				return RLM_MODULE_INVALID;
			}

			memcpy(new_nt_encrypted + new_nt_enc_len, nt_enc->vp_octets + 4, nt_enc->vp_length - 4);
			new_nt_enc_len += nt_enc->vp_length - 4;
		}

		if (new_nt_enc_len != 516) {
			REDEBUG("Unpacked MS-CHAP-NT-Enc-PW length != 516");
			return RLM_MODULE_INVALID;
		}

		/*
		 * RFC 2548 is confusing here
		 * it claims:
		 *
		 * 1 byte code
		 * 1 byte ident
		 * 16 octets - old hash encrypted with new hash
		 * 24 octets - peer challenge
		 *   this is actually:
		 *   16 octets - peer challenge
		 *    8 octets - reserved
		 * 24 octets - nt response
		 * 2 octets  - flags (ignored)
		 */

		memcpy(old_nt_encrypted, cpw->vp_octets + 2, sizeof(old_nt_encrypted));

		RDEBUG2("Password change payload valid");

		/* perform the actual password change */
		if (do_mschap_cpw(inst, request, nt_password, new_nt_encrypted, old_nt_encrypted, auth_method) < 0) {
			char buffer[128];

			REDEBUG("Password change failed");

			snprintf(buffer, sizeof(buffer), "E=709 R=0 M=Password change failed");
			mschap_add_reply(request, cpw->vp_octets[1], "MS-CHAP-Error", buffer, strlen(buffer));

			return RLM_MODULE_REJECT;
		}
		RDEBUG("Password change successful");

		/*
		 *  Clear any expiry bit so the user can now login;
		 *  obviously the password change action will need
		 *  to have cleared this bit in the config/SQL/wherever
		 */
		if (smb_ctrl && smb_ctrl->vp_integer & ACB_PW_EXPIRED) {
			RDEBUG("Clearing expiry bit in SMB-Acct-Ctrl to allow authentication");
			smb_ctrl->vp_integer &= ~ACB_PW_EXPIRED;
		}

		/*
		 *  Extract the challenge & response from the end of the password
		 *  change, add them into the request and then continue with
		 *  the authentication
		 */
		response = radius_pair_create(request->packet, &request->packet->vps,
					     PW_MSCHAP2_RESPONSE,
					     VENDORPEC_MICROSOFT);
		response->vp_length = 50;
		response->vp_octets = p = talloc_array(response, uint8_t, response->vp_length);

		/* ident & flags */
		p[0] = cpw->vp_octets[1];
		p[1] = 0;
		/* peer challenge and client NT response */
		memcpy(p + 2, cpw->vp_octets + 18, 48);
	}

	challenge = fr_pair_find_by_num(request->packet->vps, PW_MSCHAP_CHALLENGE, VENDORPEC_MICROSOFT, TAG_ANY);
	if (!challenge) {
		REDEBUG("You set 'Auth-Type = MS-CHAP' for a request that does not contain any MS-CHAP attributes!");
		return RLM_MODULE_REJECT;
	}

	/*
	 *	We also require an MS-CHAP-Response.
	 */
	response = fr_pair_find_by_num(request->packet->vps, PW_MSCHAP_RESPONSE, VENDORPEC_MICROSOFT, TAG_ANY);

	/*
	 *	MS-CHAP-Response, means MS-CHAPv1
	 */
	if (response) {
		int		offset;
		rlm_rcode_t	rcode;
		mschap_version = 1;

		/*
		 *	MS-CHAPv1 challenges are 8 octets.
		 */
		if (challenge->vp_length < 8) {
			REDEBUG("MS-CHAP-Challenge has the wrong format");
			return RLM_MODULE_INVALID;
		}

		/*
		 *	Responses are 50 octets.
		 */
		if (response->vp_length < 50) {
			REDEBUG("MS-CHAP-Response has the wrong format");
			return RLM_MODULE_INVALID;
		}

		/*
		 *	We are doing MS-CHAP.  Calculate the MS-CHAP
		 *	response
		 */
		if (response->vp_octets[1] & 0x01) {
			RDEBUG2("Client is using MS-CHAPv1 with NT-Password");
			password = nt_password;
			offset = 26;
		} else {
			REDEBUG2("Client is using MS-CHAPv1 with unsupported method LM-Password");
			return RLM_MODULE_FAIL;
		}

		/*
		 *	Do the MS-CHAP authentication.
		 */
		mschap_result = do_mschap(inst, request, password, challenge->vp_octets,
					  response->vp_octets + offset, nthashhash, auth_method);
		/*
		 *	Check for errors, and add MSCHAP-Error if necessary.
		 */
		rcode = mschap_error(inst, request, *response->vp_octets,
				     mschap_result, mschap_version, smb_ctrl);
		if (rcode != RLM_MODULE_OK) return rcode;
	} else if ((response = fr_pair_find_by_num(request->packet->vps, PW_MSCHAP2_RESPONSE,
						   VENDORPEC_MICROSOFT, TAG_ANY)) != NULL) {
		uint8_t		mschapv1_challenge[16];
		VALUE_PAIR	*name_attr, *response_name, *peer_challenge_attr;
		rlm_rcode_t	rcode;
		uint8_t const *peer_challenge;

		mschap_version = 2;

		/*
		 *	MS-CHAPv2 challenges are 16 octets.
		 */
		if (challenge->vp_length < 16) {
			REDEBUG("MS-CHAP-Challenge has the wrong format");
			return RLM_MODULE_INVALID;
		}

		/*
		 *	Responses are 50 octets.
		 */
		if (response->vp_length < 50) {
			REDEBUG("MS-CHAP-Response has the wrong format");
			return RLM_MODULE_INVALID;
		}

		/*
		 *	We also require a User-Name
		 */
		username = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
		if (!username) {
			REDEBUG("We require a User-Name for MS-CHAPv2");
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
		response_name = fr_pair_find_by_num(request->packet->vps, PW_MS_CHAP_USER_NAME, 0, TAG_ANY);
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
				RWDEBUG2("NT Domain delimiter found, should with_ntdomain_hack of been enabled?");
				username_string = name_attr->vp_strvalue;
			}
		} else {
			username_string = name_attr->vp_strvalue;
		}

		if (response_name && ((username->vp_length != response_name->vp_length) ||
		    (strncasecmp(username->vp_strvalue, response_name->vp_strvalue, username->vp_length) != 0))) {
			RWDEBUG("User-Name (%s) is not the same as MS-CHAP Name (%s) from EAP-MSCHAPv2",
				username->vp_strvalue, response_name->vp_strvalue);
		}

#ifdef __APPLE__
		/*
		 *  No "known good" NT-Password attribute.  Try to do
		 *  OpenDirectory authentication.
		 *
		 *  If OD determines the user is an OD user it will return noop, which
		 *  indicates the auth process should continue directly to OD.
		 *  Otherwise OD will determine auth success/fail.
		 */
		if (!nt_password && inst->open_directory) {
			RDEBUG2("No NT-Password configured. Trying OpenDirectory Authentication");
			int odStatus = od_mschap_auth(request, challenge, username);
			if (odStatus != RLM_MODULE_NOOP) {
				return odStatus;
			}
		}
#endif
		peer_challenge = response->vp_octets + 2;

		peer_challenge_attr = fr_pair_find_by_num(request->config, PW_MS_CHAP_PEER_CHALLENGE, 0, TAG_ANY);
		if (peer_challenge_attr) {
			RDEBUG2("Overriding peer challenge");
			peer_challenge = peer_challenge_attr->vp_octets;
		}

		/*
		 *	The old "mschapv2" function has been moved to
		 *	here.
		 *
		 *	MS-CHAPv2 takes some additional data to create an
		 *	MS-CHAPv1 challenge, and then does MS-CHAPv1.
		 */
		RDEBUG2("Creating challenge hash with username: %s", username_string);
		mschap_challenge_hash(peer_challenge,		/* peer challenge */
				      challenge->vp_octets,	/* our challenge */
				      username_string,		/* user name */
				      mschapv1_challenge);	/* resulting challenge */

		RDEBUG2("Client is using MS-CHAPv2");
		mschap_result = do_mschap(inst, request, nt_password, mschapv1_challenge,
					  response->vp_octets + 26, nthashhash, auth_method);
		rcode = mschap_error(inst, request, *response->vp_octets,
				     mschap_result, mschap_version, smb_ctrl);
		if (rcode != RLM_MODULE_OK) return rcode;

#ifdef WITH_AUTH_WINBIND
		if (inst->wb_retry_with_normalised_username) {
			if ((response_name = fr_pair_find_by_num(request->packet->vps, PW_MS_CHAP_USER_NAME, 0, TAG_ANY))) {
				if (strcmp(username_string, response_name->vp_strvalue)) {
					RDEBUG2("Changing username %s to %s", username_string, response_name->vp_strvalue);
					username_string = response_name->vp_strvalue;
				}
			}
		}
#endif

		mschap_auth_response(username_string,		/* without the domain */
				     nthashhash,		/* nt-hash-hash */
				     response->vp_octets + 26,	/* peer response */
				     peer_challenge,		/* peer challenge */
				     challenge->vp_octets,	/* our challenge */
				     msch2resp);		/* calculated MPPE key */
		mschap_add_reply(request, *response->vp_octets, "MS-CHAP2-Success", msch2resp, 42);

	} else {		/* Neither CHAPv1 or CHAPv2 response: die */
		REDEBUG("You set 'Auth-Type = MS-CHAP' for a request that does not contain any MS-CHAP attributes!");
		return RLM_MODULE_INVALID;
	}

	/* now create MPPE attributes */
	if (inst->use_mppe) {
		uint8_t mppe_sendkey[34];
		uint8_t mppe_recvkey[34];

		if (mschap_version == 1) {
			RDEBUG2("adding MS-CHAPv1 MPPE keys");
			memset(mppe_sendkey, 0, 32);

			/*
			 *	According to RFC 2548 we
			 *	should send NT hash.  But in
			 *	practice it doesn't work.
			 *	Instead, we should send nthashhash
			 *
			 *	This is an error in RFC 2548.
			 */
			/*
			 *	do_mschap cares to zero nthashhash if NT hash
			 *	is not available.
			 */
			memcpy(mppe_sendkey + 8, nthashhash, NT_DIGEST_LENGTH);
			mppe_add_reply(request, "MS-CHAP-MPPE-Keys", mppe_sendkey, 24);

		} else if (mschap_version == 2) {
			RDEBUG2("Adding MS-CHAPv2 MPPE keys");
			mppe_chap2_gen_keys128(nthashhash, response->vp_octets + 26, mppe_sendkey, mppe_recvkey);

			mppe_add_reply(request, "MS-MPPE-Recv-Key", mppe_recvkey, 16);
			mppe_add_reply(request, "MS-MPPE-Send-Key", mppe_sendkey, 16);

		}
		pair_make_reply("MS-MPPE-Encryption-Policy",
			       (inst->require_encryption) ? "0x00000002":"0x00000001", T_OP_EQ);
		pair_make_reply("MS-MPPE-Encryption-Types",
			       (inst->require_strong) ? "0x00000004":"0x00000006", T_OP_EQ);
	} /* else we weren't asked to use MPPE */

	return RLM_MODULE_OK;
#undef inst
}

extern module_t rlm_mschap;
module_t rlm_mschap = {
	.magic		= RLM_MODULE_INIT,
	.name		= "mschap",
	.type		= 0,
	.inst_size	= sizeof(rlm_mschap_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize
	},
};
