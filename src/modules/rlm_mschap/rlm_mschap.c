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
 * @copyright 2000, 2001, 2006  The FreeRADIUS server project
 */

/*  MPPE support from Takahiro Wagatsuma <waga@sic.shibaura-it.ac.jp> */
RCSID("$Id$")

#define LOG_PREFIX "rlm_mschap (%s) - "
#define LOG_PREFIX_ARGS dl_module_instance_name_by_data(inst)

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/password.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/radius/defs.h>

#include <freeradius-devel/util/hex.h>
#include <freeradius-devel/util/md4.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/sha1.h>

#include <sys/wait.h>
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
int od_mschap_auth(request_t *request, fr_pair_t *challenge, fr_pair_t * usernamepair);
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
#define ACB_FR_EXPIRED	0x00020000	//!< Password Expired.

static const CONF_PARSER passchange_config[] = {
	{ FR_CONF_OFFSET("ntlm_auth", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_mschap_t, ntlm_cpw) },
	{ FR_CONF_OFFSET("ntlm_auth_username", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_mschap_t, ntlm_cpw_username) },
	{ FR_CONF_OFFSET("ntlm_auth_domain", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_mschap_t, ntlm_cpw_domain) },
	{ FR_CONF_OFFSET("local_cpw", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_mschap_t, local_cpw) },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER winbind_config[] = {
	{ FR_CONF_OFFSET("username", FR_TYPE_TMPL, rlm_mschap_t, wb_username) },
	{ FR_CONF_OFFSET("domain", FR_TYPE_TMPL, rlm_mschap_t, wb_domain) },
#ifdef WITH_AUTH_WINBIND
	{ FR_CONF_OFFSET("retry_with_normalised_username", FR_TYPE_BOOL, rlm_mschap_t, wb_retry_with_normalised_username), .dflt = "no" },
#endif
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("normalise", FR_TYPE_BOOL, rlm_mschap_t, normify), .dflt = "yes" },

	/*
	 *	Cache the password by default.
	 */
	{ FR_CONF_OFFSET("use_mppe", FR_TYPE_BOOL, rlm_mschap_t, use_mppe), .dflt = "yes" },
	{ FR_CONF_OFFSET("require_encryption", FR_TYPE_BOOL, rlm_mschap_t, require_encryption), .dflt = "no" },
	{ FR_CONF_OFFSET("require_strong", FR_TYPE_BOOL, rlm_mschap_t, require_strong), .dflt = "no" },
	{ FR_CONF_OFFSET("with_ntdomain_hack", FR_TYPE_BOOL, rlm_mschap_t, with_ntdomain_hack), .dflt = "yes" },
	{ FR_CONF_OFFSET("ntlm_auth", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_mschap_t, ntlm_auth) },
	{ FR_CONF_OFFSET("ntlm_auth_timeout", FR_TYPE_TIME_DELTA, rlm_mschap_t, ntlm_auth_timeout) },

	{ FR_CONF_POINTER("passchange", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) passchange_config },
	{ FR_CONF_OFFSET("allow_retry", FR_TYPE_BOOL, rlm_mschap_t, allow_retry), .dflt = "yes" },
	{ FR_CONF_OFFSET("retry_msg", FR_TYPE_STRING, rlm_mschap_t, retry_msg) },


#ifdef __APPLE__
	{ FR_CONF_OFFSET("use_open_directory", FR_TYPE_BOOL, rlm_mschap_t, open_directory), .dflt = "yes" },
#endif

	{ FR_CONF_POINTER("winbind", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) winbind_config },

	/*
	 *	These are now in a subsection above.
	 */
	{ FR_CONF_OFFSET("winbind_username", FR_TYPE_TMPL | FR_TYPE_DEPRECATED, rlm_mschap_t, wb_username) },
	{ FR_CONF_OFFSET("winbind_domain", FR_TYPE_TMPL | FR_TYPE_DEPRECATED, rlm_mschap_t, wb_domain) },
#ifdef WITH_AUTH_WINBIND
	{ FR_CONF_OFFSET("winbind_retry_with_normalised_username", FR_TYPE_BOOL | FR_TYPE_DEPRECATED, rlm_mschap_t, wb_retry_with_normalised_username) },
#endif
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_mschap_dict[];
fr_dict_autoload_t rlm_mschap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

fr_dict_attr_t const *attr_auth_type;
fr_dict_attr_t const *attr_cleartext_password;
fr_dict_attr_t const *attr_eap_identity;
fr_dict_attr_t const *attr_ms_chap_new_cleartext_password;
fr_dict_attr_t const *attr_ms_chap_new_nt_password;
fr_dict_attr_t const *attr_ms_chap_peer_challenge;
fr_dict_attr_t const *attr_ms_chap_use_ntlm_auth;
fr_dict_attr_t const *attr_ms_chap_user_name;
fr_dict_attr_t const *attr_nt_password;
fr_dict_attr_t const *attr_smb_account_ctrl_text;
fr_dict_attr_t const *attr_smb_account_ctrl;

fr_dict_attr_t const *attr_user_name;
fr_dict_attr_t const *attr_ms_chap_error;

fr_dict_attr_t const *attr_ms_chap_challenge;
fr_dict_attr_t const *attr_ms_chap_response;
fr_dict_attr_t const *attr_ms_chap2_response;
fr_dict_attr_t const *attr_ms_chap2_success;

fr_dict_attr_t const *attr_ms_chap_mppe_keys;
fr_dict_attr_t const *attr_ms_mppe_encryption_policy;
fr_dict_attr_t const *attr_ms_mppe_recv_key;
fr_dict_attr_t const *attr_ms_mppe_send_key;
fr_dict_attr_t const *attr_ms_mppe_encryption_types;
fr_dict_attr_t const *attr_ms_chap2_cpw;

extern fr_dict_attr_autoload_t rlm_mschap_dict_attr[];
fr_dict_attr_autoload_t rlm_mschap_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_cleartext_password, .name = "Password.Cleartext", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_eap_identity, .name = "EAP-Identity", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_new_cleartext_password, .name = "MS-CHAP-New-Password.Cleartext", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_new_nt_password, .name = "MS-CHAP-New-NT-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_peer_challenge, .name = "MS-CHAP-Peer-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_use_ntlm_auth, .name = "MS-CHAP-Use-NTLM-Auth", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_user_name, .name = "MS-CHAP-User-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_nt_password, .name = "NT-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_smb_account_ctrl_text, .name = "SMB-Account-Ctrl-Text", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_smb_account_ctrl, .name = "SMB-Account-Ctrl", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_ms_chap_error, .name = "MS-CHAP-Error", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_ms_chap_challenge, .name = "Vendor-Specific.Microsoft.CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_chap_response, .name = "MS-CHAP-Response", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_chap2_response, .name = "MS-CHAP2-Response", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_chap2_success, .name = "MS-CHAP2-Success", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_chap_mppe_keys, .name = "MS-CHAP-MPPE-Keys", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_encryption_policy, .name = "MS-MPPE-Encryption-Policy", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_recv_key, .name = "Vendor-Specific.Microsoft.MPPE-Recv-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_send_key, .name = "Vendor-Specific.Microsoft.MPPE-Send-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_encryption_types, .name = "MS-MPPE-Encryption-Types", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_ms_chap2_cpw, .name = "MS-CHAP2-CPW", .type = FR_TYPE_OCTETS, .dict = &dict_radius },

	{ NULL }
};

static fr_pair_t *mschap_identity_find(request_t *request)
{
	fr_pair_t *vp;

	vp = fr_pair_find_by_da(&request->request_pairs, attr_user_name);
	if (vp) return vp;

	vp = fr_pair_find_by_da(&request->request_pairs, attr_eap_identity);
	if (vp) return vp;

	REDEBUG("No user identity found in current request");

	return NULL;
}

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
			acct_ctrl |= ACB_FR_EXPIRED;
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


/** Get data from MSCHAP attributes
 *
 * Pulls NT-Response, LM-Response, or Challenge from MSCHAP
 * attributes.
 *
 * @ingroup xlat_functions
 */
static ssize_t mschap_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   void const *mod_inst, UNUSED void const *xlat_inst,
			   request_t *request, char const *fmt)
{
	size_t			i, data_len;
	uint8_t const  		*data = NULL;
	uint8_t			buffer[32];
	fr_pair_t		*user_name;
	fr_pair_t		*chap_challenge, *response;
	rlm_mschap_t const	*inst = mod_inst;

	response = NULL;

	/*
	 *	Challenge means MS-CHAPv1 challenge, or
	 *	hash of MS-CHAPv2 challenge, and peer challenge.
	 */
	if (strncasecmp(fmt, "Challenge", 9) == 0) {
		chap_challenge = fr_pair_find_by_da(&request->request_pairs, attr_ms_chap_challenge);
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
			fr_pair_t	*name_vp;
			fr_pair_t	*response_name;
			char const	*username_str;
			size_t		username_len;

			response = fr_pair_find_by_da(&request->request_pairs, attr_ms_chap2_response);
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

			user_name = mschap_identity_find(request);
			if (!user_name) return -1;

			/*
			 *      Check for MS-CHAP-User-Name and if found, use it
			 *      to construct the MSCHAPv1 challenge.  This is
			 *      set by rlm_eap_mschap to the MS-CHAP Response
			 *      packet Name field.
			 *
			 *	We prefer this to the User-Name in the
			 *	packet.
			 */
			response_name = fr_pair_find_by_da(&request->request_pairs, attr_ms_chap_user_name);
			if (response_name) {
				name_vp = response_name;
			} else {
				name_vp = user_name;
			}

			/*
			 *	with_ntdomain_hack moved here, too.
			 */
			username_str = memchr(name_vp->vp_strvalue, '\\', name_vp->vp_length);
			if (username_str != NULL) {
				if (inst->with_ntdomain_hack) {
					username_str++;
				} else {
					RWDEBUG2("NT Domain delimiter found, should 'with_ntdomain_hack' be enabled?");
					username_str = name_vp->vp_strvalue;
				}
			} else {
				username_str = name_vp->vp_strvalue;
			}
			username_len = name_vp->vp_length - (username_str - name_vp->vp_strvalue);

			if (response_name &&
			    ((user_name->vp_length != response_name->vp_length) ||
			     (memcmp(user_name->vp_strvalue, response_name->vp_strvalue, user_name->vp_length) != 0))) {
				RWDEBUG2("%pP is not the same as %pP from EAP-MSCHAPv2", user_name, response_name);
			}

			/*
			 *	Get the MS-CHAPv1 challenge
			 *	from the MS-CHAPv2 peer challenge,
			 *	our challenge, and the user name.
			 */
			RDEBUG2("Creating challenge with username \"%pV\"",
				fr_box_strvalue_len(username_str, username_len));
			mschap_challenge_hash(buffer, response->vp_octets + 2, chap_challenge->vp_octets,
					      username_str, username_len);
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
		response = fr_pair_find_by_da(&request->request_pairs, attr_ms_chap_response);
		if (!response) response = fr_pair_find_by_da(&request->request_pairs, attr_ms_chap2_response);
		if (!response) {
			REDEBUG("No MS-CHAP-Response or MS-CHAP2-Response was found in the request");
			return -1;
		}

		/*
		 *	For MS-CHAPv1, the NT-Response exists only
		 *	if the second octet says so.
		 */
		if ((response->da == attr_ms_chap_response) && ((response->vp_octets[1] & 0x01) == 0)) {
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
		response = fr_pair_find_by_da(&request->request_pairs, attr_ms_chap_response);
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
	 *	Pull the NT-Domain out of the User-Name, if it exists.
	 */
	} else if (strncasecmp(fmt, "NT-Domain", 9) == 0) {
		char *p, *q;

		user_name = mschap_identity_find(request);
		if (!user_name) return -1;

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
				strlcpy(*out, user_name->vp_strvalue + 5, outlen);
			} else {
				p++;	/* skip the period */
				q = strchr(p, '.');
				/*
				 * use the same hack as below
				 * only if another period was found
				 */
				if (q) *q = '\0';
				strlcpy(*out, p, outlen);
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
			strlcpy(*out, user_name->vp_strvalue, outlen);
			*p = '\\';
		}

		return strlen(*out);

	/*
	 *	Pull the User-Name out of the User-Name...
	 */
	} else if (strncasecmp(fmt, "User-Name", 9) == 0) {
		char const *p, *q;

		user_name = mschap_identity_find(request);
		if (!user_name) return -1;

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
				snprintf(*out, outlen, "%.*s$", (int) (q - p), p);
			} else {
				snprintf(*out, outlen, "%s$", p);
			}
		} else {
			p = strchr(user_name->vp_strvalue, '\\');
			if (p) {
				p++;	/* skip the backslash */
			} else {
				p = user_name->vp_strvalue; /* use the whole User-Name */
			}
			strlcpy(*out, p, outlen);
		}

		return strlen(*out);

	/*
	 * Return the NT-Hash of the passed string
	 */
	} else if (strncasecmp(fmt, "NT-Hash ", 8) == 0) {
		char const *p;

		p = fmt + 8;	/* 7 is the length of 'NT-Hash' */
		if ((*p == '\0') || (outlen <= 32))
			return 0;

		fr_skip_whitespace(p);

		if (mschap_nt_password_hash(buffer, p) < 0) {
			REDEBUG("Failed generating NT-Password");
			*buffer = '\0';
			return -1;
		}

		fr_bin2hex(&FR_SBUFF_OUT(*out, (NT_DIGEST_LENGTH * 2) + 1), &FR_DBUFF_TMP(buffer, NT_DIGEST_LENGTH), SIZE_MAX);
		(*out)[32] = '\0';
		RDEBUG2("NT-Hash of \"known-good\" password: %s", *out);
		return 32;

	/*
	 * Return the LM-Hash of the passed string
	 */
	} else if (strncasecmp(fmt, "LM-Hash ", 8) == 0) {
		char const *p;

		p = fmt + 8;	/* 7 is the length of 'LM-Hash' */
		if ((*p == '\0') || (outlen <= 32))
			return 0;

		fr_skip_whitespace(p);

		smbdes_lmpwdhash(p, buffer);
		fr_bin2hex(&FR_SBUFF_OUT(*out, (LM_DIGEST_LENGTH * 2) + 1), &FR_DBUFF_TMP(buffer, LM_DIGEST_LENGTH), SIZE_MAX);
		(*out)[32] = '\0';
		RDEBUG2("LM-Hash of %s = %s", p, *out);
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
		sprintf((*out) + (2 * i), "%02x", data[i]);
	}
	(*out)[data_len * 2] = '\0';

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
static void *mod_conn_create(TALLOC_CTX *ctx, void *instance, UNUSED fr_time_delta_t timeout)
{
	struct wbcContext **wb_ctx;
	rlm_mschap_t const	*inst = talloc_get_type_abort_const(instance, rlm_mschap_t);

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

/*
 *	Add MPPE attributes to the reply.
 */
static void mppe_add_reply(UNUSED rlm_mschap_t const *inst,
			   request_t *request, fr_dict_attr_t const *da, uint8_t const *value, size_t len)
{
	fr_pair_t *vp;

	MEM(pair_update_reply(&vp, da) >= 0);
	fr_pair_value_memdup(vp, value, len, false);
	RINDENT();
	RDEBUG2("&reply.%pP", vp);
	REXDENT();
}

static int write_all(int fd, char const *buf, int len) {
	int rv, done=0;

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

static int CC_HINT(nonnull (1, 2, 4, 5)) do_mschap_cpw(rlm_mschap_t const *inst,
						       request_t *request,
#ifdef HAVE_OPENSSL_CRYPTO_H
						       fr_pair_t *nt_password,
#else
						       UNUSED fr_pair_t *nt_password,
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

		RDEBUG2("Doing MS-CHAPv2 password change via ntlm_auth helper");

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
			len = xlat_eval(buf, sizeof(buf) - 2, request, inst->ntlm_cpw_username, NULL, NULL);
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
			len = xlat_eval(buf, sizeof(buf) - 2, request, inst->ntlm_cpw_domain, NULL, NULL);
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
		fr_bin2hex(&FR_SBUFF_OUT(buf + len, sizeof(buf) - len), &FR_DBUFF_TMP(new_nt_password, 516), SIZE_MAX);
		buf[len+1032] = '\n';
		buf[len+1033] = '\0';
		len = strlen(buf);
		if (write_all(to_child, buf, len) != len) {
			RDEBUG2("failed to write new password blob to child");
			goto ntlm_auth_err;
		}

		len = sprintf(buf, "old-nt-hash-blob: ");
		fr_bin2hex(&FR_SBUFF_OUT(buf + len, sizeof(buf) - len), &FR_DBUFF_TMP(old_nt_hash, NT_DIGEST_LENGTH), SIZE_MAX);
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
		len = radius_readfrom_program(from_child, pid, fr_time_delta_from_sec(10), buf, sizeof(buf));
		if (len < 0) {
			/* radius_readfrom_program will have closed from_child for us */
			REDEBUG("Failure reading from child");
			return -1;
		}
		close(from_child);
		from_child = -1;

		buf[len] = 0;
		RDEBUG2("ntlm_auth said: %s", buf);

		child_pid = waitpid(pid, &status, 0);
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
		fr_pair_t *new_pass, *new_hash;
		uint8_t *p, *q;
		char *x;
		size_t i;
		size_t passlen;
		ssize_t result_len;
		char result[253];
		uint8_t nt_pass_decrypted[516], old_nt_hash_expected[NT_DIGEST_LENGTH];
		RC4_KEY key;
		size_t len = 0;

		if (!nt_password) {
			RDEBUG2("Local MS-CHAPv2 password change requires NT-Password attribute");
			return -1;
		} else {
			RDEBUG2("Doing MS-CHAPv2 password change locally");
		}

		/*
		 *  Decrypt the blob
		 */
		RC4_set_key(&key, nt_password->vp_length, nt_password->vp_octets);
		RC4(&key, 516, new_nt_password, nt_pass_decrypted);

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
		MEM(pair_update_request(&new_hash, attr_ms_chap_new_nt_password) >= 0);
		MEM(fr_pair_value_mem_alloc(new_hash, &q, NT_DIGEST_LENGTH, false) == 0);
		fr_md4_calc(q, p, passlen);

		/*
		 *  Check that nt_password encrypted with new_hash
		 *  matches the old_hash value from the client.
		 */
		smbhash(old_nt_hash_expected, nt_password->vp_octets, q);
		smbhash(old_nt_hash_expected + 8, nt_password->vp_octets + 8, q + 7);
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
		MEM(pair_update_request(&new_pass, attr_ms_chap_new_cleartext_password) >= 0);
		new_pass->vp_length = 0;

		i = 0;
		len = 0;
		while (i < passlen) {
			int c;

			c = p[i++];
			c += p[i++] << 8;

			/*
			 *  Gah. nasty. maybe we should just pull in iconv?
			 */
			if (c < 0x7f) {
				len++;
			} else if (c < 0x7ff) {
				len += 2;
			} else {
				len += 3;
			}
		}

		MEM(fr_pair_value_bstr_alloc(new_pass, &x, len, true) == 0);

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
		result_len = xlat_eval(result, sizeof(result), request, inst->local_cpw, NULL, NULL);
		if (result_len < 0){
			return -1;
		} else if (result_len == 0) {
			REDEBUG("Local MS-CHAPv2 password change - xlat didn't give any result, assuming failure");
			return -1;
		}

		RDEBUG2("MS-CHAPv2 password change succeeded: %s", result);

		/*
		 *  Update the NT-Password attribute with the new hash this lets us
		 *  fall through to the authentication code using the new hash,
		 *  not the old one.
		 */
		fr_pair_value_memdup(nt_password, new_hash->vp_octets, new_hash->vp_length, false);

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
static int CC_HINT(nonnull (1, 2, 4, 5, 6)) do_mschap(rlm_mschap_t const *inst,
						      request_t *request,
						      fr_pair_t *password,
						      uint8_t const *challenge,
						      uint8_t const *response,
						      uint8_t nthashhash[static NT_DIGEST_LENGTH],
						      MSCHAP_AUTH_METHOD method)
{
	uint8_t	calculated[24];

	memset(nthashhash, 0, NT_DIGEST_LENGTH);

	switch (method) {
	case AUTH_INTERNAL:
	/*
	 *	Do normal authentication.
	 */
		{
		/*
		 *	No password: can't do authentication.
		 */
		if (!password) {
			REDEBUG("FAILED: No NT/LM-Password.  Cannot perform authentication");
			return -1;
		}

		smbdes_mschap(password->vp_octets, challenge, calculated);
		if (fr_digest_cmp(response, calculated, 24) != 0) {
			return -1;
		}

		/*
		 *	If the password exists, and is an NT-Password,
		 *	then calculate the hash of the NT hash.  Doing this
		 *	here minimizes work for later.
		 */
		if (password->da == attr_nt_password) fr_md4_calc(nthashhash, password->vp_octets, MD4_DIGEST_LENGTH);
		break;
		}
	case AUTH_NTLMAUTH_EXEC:
	/*
	 *	Run ntlm_auth
	 */
		{
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
				result = 0;

				p += 7;
				if (strcmp(p, "224") == 0) {
					result = -648;

				} else if (strcmp(p, "234") == 0) {
					result = -647;

				} else if (strcmp(p, "072") == 0) {
					result = -691;

				} else if (strcasecmp(p, "05E") == 0) {
					result = -2;
				}

				if (result != 0) {
					REDEBUG2("%s", buffer);
					return result;
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
		if (fr_hex2bin(NULL, &FR_DBUFF_TMP(nthashhash, NT_DIGEST_LENGTH),
			       &FR_SBUFF_IN(buffer + 8, len), false) != NT_DIGEST_LENGTH) {
			REDEBUG("Invalid output from ntlm_auth: NT_KEY has non-hex values");
			return -1;
		}

		break;
		}
#ifdef WITH_AUTH_WINBIND
	case AUTH_WBCLIENT:
	/*
	 *	Process auth via the wbclient library
	 */
		return do_auth_wbclient(inst, request, challenge, response, nthashhash);
#endif
	default:
		/* We should never reach this line */
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


static void mppe_GetMasterKey(uint8_t const *nt_hashhash, uint8_t const *nt_response,
			      uint8_t *masterkey)
{
       uint8_t digest[20];
       fr_sha1_ctx Context;

       fr_sha1_init(&Context);
       fr_sha1_update(&Context, nt_hashhash, NT_DIGEST_LENGTH);
       fr_sha1_update(&Context, nt_response, 24);
       fr_sha1_update(&Context, magic1, 27);
       fr_sha1_final(digest, &Context);

       memcpy(masterkey, digest, 16);				//-V512
}


static void mppe_GetAsymmetricStartKey(uint8_t *masterkey, uint8_t *sesskey,
				       int keylen, int issend)
{
       uint8_t digest[20];
       const uint8_t *s;
       fr_sha1_ctx Context;

       memset(digest, 0, 20);

       if(issend) {
	       s = magic3;
       } else {
	       s = magic2;
       }

       fr_sha1_init(&Context);
       fr_sha1_update(&Context, masterkey, 16);
       fr_sha1_update(&Context, SHSpad1, 40);
       fr_sha1_update(&Context, s, 84);
       fr_sha1_update(&Context, SHSpad2, 40);
       fr_sha1_final(digest, &Context);

       memcpy(sesskey, digest, keylen);
}


static void mppe_chap2_get_keys128(uint8_t const *nt_hashhash, uint8_t const *nt_response,
				   uint8_t *sendkey, uint8_t *recvkey)
{
       uint8_t masterkey[16];

       mppe_GetMasterKey(nt_hashhash, nt_response, masterkey);

       mppe_GetAsymmetricStartKey(masterkey, sendkey, 16, 1);
       mppe_GetAsymmetricStartKey(masterkey, recvkey, 16, 0);
}

/*
 *	Generate MPPE keys.
 */
static void mppe_chap2_gen_keys128(uint8_t const *nt_hashhash, uint8_t const *response,
				   uint8_t *sendkey, uint8_t *recvkey)
{
	uint8_t enckey1[16];
	uint8_t enckey2[16];

	mppe_chap2_get_keys128(nt_hashhash, response, enckey1, enckey2);

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
static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_mschap_t const 	*inst = talloc_get_type_abort_const(mctx->instance, rlm_mschap_t);
	fr_pair_t		*challenge = NULL;

	challenge = fr_pair_find_by_da(&request->request_pairs, attr_ms_chap_challenge);
	if (!challenge) RETURN_MODULE_NOOP;

	if (!fr_pair_find_by_da(&request->request_pairs, attr_ms_chap_response) &&
	    !fr_pair_find_by_da(&request->request_pairs, attr_ms_chap2_response) &&
	    !fr_pair_find_by_da(&request->request_pairs, attr_ms_chap2_cpw)) {
		RDEBUG2("Found MS-CHAP-Challenge, but no MS-CHAP response or Change-Password");
		RETURN_MODULE_NOOP;
	}

	if (!inst->auth_type) {
		WARN("No 'authenticate %s {...}' section or 'Auth-Type = %s' set.  Cannot setup MS-CHAP authentication",
		     inst->name, inst->name);
		RETURN_MODULE_NOOP;
	}

	if (!module_section_type_set(request, attr_auth_type, inst->auth_type)) RETURN_MODULE_NOOP;

	RETURN_MODULE_OK;
}

static unlang_action_t mschap_error(rlm_rcode_t *p_result, rlm_mschap_t const *inst, request_t *request,
				    unsigned char ident, int mschap_result, int mschap_version, fr_pair_t *smb_ctrl)
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
	     (smb_ctrl && ((smb_ctrl->vp_uint32 & ACB_FR_EXPIRED) != 0)))) {
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
		   (smb_ctrl && (((smb_ctrl->vp_uint32 & ACB_DISABLED) != 0) ||
				 ((smb_ctrl->vp_uint32 & (ACB_NORMAL|ACB_WSTRUST)) == 0)))) {
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
		   (smb_ctrl && ((smb_ctrl->vp_uint32 & ACB_AUTOLOCK) != 0))) {
		REDEBUG("SMB-Account-Ctrl (or ntlm_auth) "
			"says that the account is locked out");
		error = 647;
		retry = 0;
		message = "Account locked out";
		rcode = RLM_MODULE_DISALLOW;

	} else if (mschap_result < 0) {
		REDEBUG("MS-CHAP2-Response is incorrect");
		error = 691;
		retry = inst->allow_retry;
		message = "Authentication failed";
		rcode = RLM_MODULE_REJECT;
	}

	if (rcode == RLM_MODULE_OK) RETURN_MODULE_OK;

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
		RETURN_MODULE_FAIL;
	}
	mschap_add_reply(request, ident, attr_ms_chap_error, buffer, strlen(buffer));

	RETURN_MODULE_RCODE(rcode);
}


/** Find an NT-Password value, or create one from a Password.Cleartext, or Password.With-Header attribute
 *
 * @param[out] ephemeral	Whether we created a new password
 *				attribute.  Usually the caller will
 *				either want to insert this into a
 *				list or free it.
 * @param[out] out		Our new NT-Password.
 * @param[in] inst		Module configuration.
 * @param[in] request		The current request.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int CC_HINT(nonnull(1, 2, 3)) nt_password_find(bool *ephemeral, fr_pair_t **out,
						      rlm_mschap_t const *inst, request_t *request)
{
	fr_pair_t		*password;
	fr_dict_attr_t const	*allowed_passwords[] = { attr_cleartext_password, attr_nt_password };

	*out = NULL;		/* Init output pointer */

	password = password_find(ephemeral, request, request,
				 allowed_passwords, NUM_ELEMENTS(allowed_passwords), inst->normify);
	if (!password) {
		if (inst->method == AUTH_INTERNAL) {
			/*
			 *	Search for passwords in the parent
			 *	FIXME: This is a hack and should be removed
			 *	When EAP-MSCHAPv2 supports sections.
			 */
			if (request->parent) {
				password = password_find(ephemeral, request->parent, request->parent,
							 allowed_passwords,
							 NUM_ELEMENTS(allowed_passwords), inst->normify);
				if (password) goto found_password;
			}

			/*
			 *	If we're doing internal auth, then this is an issue
			 */
			RWDEBUG2("No &control.%s or &control.%s found.  Cannot create NT-Password",
				 attr_cleartext_password->name, attr_nt_password->name);
			return -1;

		/*
		 *	..if we're not, then we can call out to external sources.
		 */
		} else {
			return -1;
		}
	}

found_password:
	if (password->da == attr_cleartext_password) {
		uint8_t		*p;
		int		ret;
		fr_pair_t	*nt_password;

		MEM(nt_password = fr_pair_afrom_da(request, attr_nt_password));
		MEM(fr_pair_value_mem_alloc(nt_password, &p, NT_DIGEST_LENGTH, false) == 0);
		ret = mschap_nt_password_hash(p, password->vp_strvalue);

		if (ret < 0) {
			RERROR("Failed generating NT-Password");
			talloc_free(nt_password);
			if (*ephemeral) talloc_list_free(&password);
			return -1;
		}

		if (RDEBUG_ENABLED3) {
			RDEBUG3("Hashed &control.%pP to create %s = %pV",
				password, attr_nt_password->name, fr_box_octets(p, NT_DIGEST_LENGTH));
		} else {
			RDEBUG2("Hashed &control.%s to create %s", attr_nt_password->name, password->da->name);
		}

		if (*ephemeral) talloc_list_free(&password);

		*ephemeral = true;	/* We generated a temporary password */
		*out = nt_password;

		return 0;
	}

	fr_assert(password->da == attr_nt_password);

	if (RDEBUG_ENABLED3) {
		RDEBUG3("Found &control.%pP", password);
	} else {
		RDEBUG2("Found &control.%s", attr_nt_password->name);
	}
	*out = password;

	return 0;
}

/*
 *	mschap_cpw_request_process() - do the work to handle an MS-CHAP password
 *	change request.
 */
static unlang_action_t CC_HINT(nonnull) mschap_process_cpw_request(rlm_rcode_t *p_result,
								   rlm_mschap_t const *inst,
								   request_t *request,
								   fr_pair_t *cpw,
								   fr_pair_t *nt_password)
{
	uint8_t		new_nt_encrypted[516], old_nt_encrypted[NT_DIGEST_LENGTH];
	fr_pair_t	*nt_enc=NULL;
	int		seq, new_nt_enc_len;

	/*
	 *	mschap2 password change request.
	 *
	 *	We cheat - first decode and execute the passchange.
	 *	Then extract the response, add it into the request
	 *	and then jump into mschap2 auth with the challenge/
	 *	response.
	 */
	RDEBUG2("MS-CHAPv2 password change request received");

	if (cpw->vp_length != 68) {
		REDEBUG("MS-CHAP2-CPW has the wrong format: length %zu != 68", cpw->vp_length);
		RETURN_MODULE_INVALID;
	}

	if (cpw->vp_octets[0] != 7) {
		REDEBUG("MS-CHAP2-CPW has the wrong format: code %d != 7", cpw->vp_octets[0]);
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Look for the new (encrypted) password.
	 *
	 *	Bah, stupid composite attributes...
	 *	we're expecting 3 attributes with the leading bytes -
	 *	06:<mschapid>:00:01:<1st chunk>
	 *	06:<mschapid>:00:02:<2nd chunk>
	 *	06:<mschapid>:00:03:<3rd chunk>
	 */
	new_nt_enc_len = 0;
	for (seq = 1; seq < 4; seq++) {
		fr_cursor_t cursor;
		int found = 0;

		for (nt_enc = fr_cursor_init(&cursor, &request->request_pairs);
		     nt_enc;
		     nt_enc = fr_cursor_next(&cursor)) {
			if (fr_dict_vendor_num_by_da(nt_enc->da) != VENDORPEC_MICROSOFT) continue;

			if (nt_enc->da->attr != FR_MSCHAP_NT_ENC_PW) continue;

			if (nt_enc->vp_length < 4) {
				REDEBUG("MS-CHAP-NT-Enc-PW with invalid format");
				RETURN_MODULE_INVALID;
			}

			if (nt_enc->vp_octets[0] != 6) {
				REDEBUG("MS-CHAP-NT-Enc-PW with invalid format");
				RETURN_MODULE_INVALID;
			}

			if ((nt_enc->vp_octets[2] == 0) && (nt_enc->vp_octets[3] == seq)) {
				found = 1;
				break;
			}
		}

		if (!found) {
			REDEBUG("Could not find MS-CHAP-NT-Enc-PW w/ sequence number %d", seq);
			RETURN_MODULE_INVALID;
		}

		if ((new_nt_enc_len + nt_enc->vp_length - 4) > sizeof(new_nt_encrypted)) {
			REDEBUG("Unpacked MS-CHAP-NT-Enc-PW length > 516");
			RETURN_MODULE_INVALID;
		}

		memcpy(new_nt_encrypted + new_nt_enc_len, nt_enc->vp_octets + 4, nt_enc->vp_length - 4);
		new_nt_enc_len += nt_enc->vp_length - 4;
	}

	if (new_nt_enc_len != 516) {
		REDEBUG("Unpacked MS-CHAP-NT-Enc-PW length != 516");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	RFC 2548 is confusing here. It claims:
	 *
	 *	1 byte code
	 *	1 byte ident
	 *	16 octets - old hash encrypted with new hash
	 *	24 octets - peer challenge
	 *	  this is actually:
	 *	  16 octets - peer challenge
	 *	   8 octets - reserved
	 *	24 octets - nt response
	 *	2 octets  - flags (ignored)
	 */

	memcpy(old_nt_encrypted, cpw->vp_octets + 2, sizeof(old_nt_encrypted));

	RDEBUG2("Password change payload valid");

	/*
	 *	Perform the actual password change
	 */
	if (do_mschap_cpw(inst, request, nt_password, new_nt_encrypted, old_nt_encrypted, inst->method) < 0) {
		char buffer[128];

		REDEBUG("Password change failed");

		snprintf(buffer, sizeof(buffer), "E=709 R=0 M=Password change failed");
		mschap_add_reply(request, cpw->vp_octets[1], attr_ms_chap_error, buffer, strlen(buffer));

		RETURN_MODULE_REJECT;
	}

	RDEBUG2("Password change successful");

	RETURN_MODULE_OK;
}

static CC_HINT(nonnull(1,2,3,4,5,8,9)) unlang_action_t mschap_process_response(rlm_rcode_t *p_result,
									       int *mschap_version,
									       uint8_t nthashhash[static NT_DIGEST_LENGTH],
									       rlm_mschap_t const *inst,
									       request_t *request,
									       fr_pair_t *smb_ctrl,
									       fr_pair_t *nt_password,
									       fr_pair_t *challenge,
									       fr_pair_t *response,
									       MSCHAP_AUTH_METHOD method)
{
	int			offset;
	rlm_rcode_t		mschap_result;

	*mschap_version = 1;

	RDEBUG2("Processing MS-CHAPv1 response");

	/*
	 *	MS-CHAPv1 challenges are 8 octets.
	 */
	if (challenge->vp_length < 8) {
		REDEBUG("MS-CHAP-Challenge has the wrong format");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Responses are 50 octets.
	 */
	if (response->vp_length < 50) {
		REDEBUG("MS-CHAP-Response has the wrong format");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	We are doing MS-CHAP.  Calculate the MS-CHAP
	 *	response
	 */
	if (!(response->vp_octets[1] & 0x01)) {
		REDEBUG2("Client used unsupported method LM-Password");
		RETURN_MODULE_FAIL;
	}

	offset = 26;

	/*
	 *	Do the MS-CHAP authentication.
	 */
	mschap_result = do_mschap(inst, request, nt_password, challenge->vp_octets,
				  response->vp_octets + offset, nthashhash, method);

	/*
	 *	Check for errors, and add MSCHAP-Error if necessary.
	 */
	return mschap_error(p_result, inst, request, *response->vp_octets, mschap_result, *mschap_version, smb_ctrl);
}

static unlang_action_t CC_HINT(nonnull(1,2,3,4,5,8,9)) mschap_process_v2_response(rlm_rcode_t *p_result,
										  int *mschap_version,
									    	  uint8_t nthashhash[static NT_DIGEST_LENGTH],
									    	  rlm_mschap_t const *inst,
									    	  request_t *request,
									    	  fr_pair_t *smb_ctrl,
									   	  fr_pair_t *nt_password,
									    	  fr_pair_t *challenge,
									    	  fr_pair_t *response,
									    	  MSCHAP_AUTH_METHOD method)
{
		uint8_t		mschap_challenge[16];
		fr_pair_t	*user_name, *name_vp, *response_name, *peer_challenge_attr;
		uint8_t const	*peer_challenge;
		char const	*username_str;
		size_t		username_len;
		int		mschap_result;
		rlm_rcode_t	rcode;
		char		msch2resp[42];

		*mschap_version = 2;

		RDEBUG2("Processing MS-CHAPv2 response");

		/*
		 *	MS-CHAPv2 challenges are 16 octets.
		 */
		if (challenge->vp_length < 16) {
			REDEBUG("MS-CHAP-Challenge has the wrong format");
			RETURN_MODULE_INVALID;
		}

		/*
		 *	Responses are 50 octets.
		 */
		if (response->vp_length < 50) {
			REDEBUG("MS-CHAP-Response has the wrong format");
			RETURN_MODULE_INVALID;
		}

		/*
		 *	We also require a User-Name
		 */
		user_name = mschap_identity_find(request);
		if (!user_name) RETURN_MODULE_FAIL;

		/*
		 *      Check for MS-CHAP-User-Name and if found, use it
		 *      to construct the MSCHAPv1 challenge.  This is
		 *      set by rlm_eap_mschap to the MS-CHAP Response
		 *      packet Name field.
		 *
		 *	We prefer this to the User-Name in the
		 *	packet.
		 */
		response_name = fr_pair_find_by_da(&request->request_pairs, attr_ms_chap_user_name);
		name_vp = response_name ? response_name : user_name;

		/*
		 *	with_ntdomain_hack moved here, too.
		 */
		if ((username_str = strchr(name_vp->vp_strvalue, '\\')) != NULL) {
			if (inst->with_ntdomain_hack) {
				username_str++;
			} else {
				RWDEBUG2("NT Domain delimiter found, should 'with_ntdomain_hack' be enabled?");
				username_str = name_vp->vp_strvalue;
			}
		} else {
			username_str = name_vp->vp_strvalue;
		}
		username_len = name_vp->vp_length - (username_str - name_vp->vp_strvalue);

		if (response_name && ((user_name->vp_length != response_name->vp_length) ||
		    (strncasecmp(user_name->vp_strvalue, response_name->vp_strvalue, user_name->vp_length) != 0))) {
			RWDEBUG("%pP is not the same as %pP from EAP-MSCHAPv2", user_name, response_name);
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
			RDEBUG2("No NT-Password available. Trying OpenDirectory Authentication");
			rcode = od_mschap_auth(request, challenge, user_name);
			if (rcode != RLM_MODULE_NOOP) RETURN_MODULE_RCODE(rcode);
		}
#endif
		peer_challenge = response->vp_octets + 2;

		peer_challenge_attr = fr_pair_find_by_da(&request->control_pairs, attr_ms_chap_peer_challenge);
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
		RDEBUG2("Creating challenge with username \"%pV\"",
			fr_box_strvalue_len(username_str, username_len));
		mschap_challenge_hash(mschap_challenge,		/* resulting challenge */
				      peer_challenge,			/* peer challenge */
				      challenge->vp_octets,		/* our challenge */
				      username_str, username_len);	/* user name */

		mschap_result = do_mschap(inst, request, nt_password, mschap_challenge,
					  response->vp_octets + 26, nthashhash, method);

		/*
		 *	Check for errors, and add MSCHAP-Error if necessary.
		 */
		mschap_error(&rcode, inst, request, *response->vp_octets,
			     mschap_result, *mschap_version, smb_ctrl);
		if (rcode != RLM_MODULE_OK) RETURN_MODULE_RCODE(rcode);

#ifdef WITH_AUTH_WINBIND
		if (inst->wb_retry_with_normalised_username) {
			response_name = fr_pair_find_by_da(&request->request_pairs, attr_ms_chap_user_name);
			if (response_name) {
				if (strcmp(username_str, response_name->vp_strvalue)) {
					RDEBUG2("Normalising username %pV -> %pV",
						fr_box_strvalue_len(username_str, username_len),
						&response_name->data);
					username_str = response_name->vp_strvalue;
				}
			}
		}
#endif

		mschap_auth_response(username_str,		/* without the domain */
				     username_len,		/* Length of username str */
				     nthashhash,		/* nt-hash-hash */
				     response->vp_octets + 26,	/* peer response */
				     peer_challenge,		/* peer challenge */
				     challenge->vp_octets,	/* our challenge */
				     msch2resp);		/* calculated MPPE key */
		mschap_add_reply(request, *response->vp_octets, attr_ms_chap2_success, msch2resp, 42);

		RETURN_MODULE_OK;
}

/*
 *	mod_authenticate() - authenticate user based on given
 *	attributes and configuration.
 *	We will try to find out password in configuration
 *	or in configured passwd file.
 *	If one is found we will check paraneters given by NAS.
 *
 *	If SMB-Account-Ctrl is not set to ACB_PWNOTREQ we must have
 *	one of:
 *		PAP:      User-Password or
 *		MS-CHAP:  MS-CHAP-Challenge and MS-CHAP-Response or
 *		MS-CHAP2: MS-CHAP-Challenge and MS-CHAP2-Response
 *	In case of password mismatch or locked account we MAY return
 *	MS-CHAP-Error for MS-CHAP or MS-CHAP v2
 *	If MS-CHAP2 succeeds we MUST return MS-CHAP2-Success
 */
static unlang_action_t CC_HINT(nonnull) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_mschap_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_mschap_t);
	fr_pair_t		*challenge = NULL;
	fr_pair_t		*response = NULL;
	fr_pair_t		*cpw = NULL;
	fr_pair_t		*nt_password = NULL, *smb_ctrl;
	uint8_t			nthashhash[NT_DIGEST_LENGTH];
	int			mschap_version = 0;

	MSCHAP_AUTH_METHOD	method;
	bool			ephemeral = false;
	rlm_rcode_t		rcode = RLM_MODULE_OK;

	/*
	 *	If we have ntlm_auth configured, use it unless told
	 *	otherwise
	 */
	method = inst->method;

	/*
	 *	If we have an ntlm_auth configuration, then we may
	 *	want to suppress it.
	 */
	if (method != AUTH_INTERNAL) {
		fr_pair_t *vp = fr_pair_find_by_da(&request->control_pairs, attr_ms_chap_use_ntlm_auth);
		if (vp && vp->vp_bool == false) method = AUTH_INTERNAL;
	}

	/*
	 *	Find the SMB-Account-Ctrl attribute, or the
	 *	SMB-Account-Ctrl-Text attribute.
	 */
	smb_ctrl = fr_pair_find_by_da(&request->control_pairs, attr_smb_account_ctrl);
	if (!smb_ctrl) {
		fr_pair_t *smb_account_ctrl_text;

		smb_account_ctrl_text = fr_pair_find_by_da(&request->control_pairs, attr_smb_account_ctrl_text);
		if (smb_account_ctrl_text) {
			MEM(pair_add_control(&smb_ctrl, attr_smb_account_ctrl) >= 0);
			smb_ctrl->vp_uint32 = pdb_decode_acct_ctrl(smb_account_ctrl_text->vp_strvalue);
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
		if ((smb_ctrl->vp_uint32 & ACB_PWNOTREQ) != 0) {
			RDEBUG2("SMB-Account-Ctrl says no password is required");
			RETURN_MODULE_OK;
		}
	}

	/*
	 *	Look for or create an NT-Password
	 *
	 *      NT-Password can be NULL here if we didn't find an
	 *	input attribute, and we're calling out to an
	 *	external password store.
	 */
	if (nt_password_find(&ephemeral, &nt_password, mctx->instance, request) < 0) RETURN_MODULE_FAIL;

	/*
	 *	Check to see if this is a change password request, and process
	 *	it accordingly if so.
	 */
	cpw = fr_pair_find_by_da(&request->request_pairs, attr_ms_chap2_cpw);
	if (cpw) {
		uint8_t		*p;

		mschap_process_cpw_request(&rcode, mctx->instance, request, cpw, nt_password);
		if (rcode != RLM_MODULE_OK) goto finish;

		/*
		 *	Clear any expiry bit so the user can now login;
		 *	obviously the password change action will need
		 *	to have cleared this bit in the config/SQL/wherever.
		 */
		if (smb_ctrl && smb_ctrl->vp_uint32 & ACB_FR_EXPIRED) {
			RDEBUG2("Clearing expiry bit in SMB-Acct-Ctrl to allow authentication");
			smb_ctrl->vp_uint32 &= ~ACB_FR_EXPIRED;
		}

		/*
		 *	Extract the challenge & response from the end of the
		 *	password change, add them into the request and then
		 *	continue with the authentication.
		 */
		MEM(pair_update_request(&response, attr_ms_chap2_response) >= 0);
		MEM(fr_pair_value_mem_alloc(response, &p, 50, cpw->vp_tainted) == 0);

		/* ident & flags */
		p[0] = cpw->vp_octets[1];
		p[1] = 0;
		/* peer challenge and client NT response */
		memcpy(p + 2, cpw->vp_octets + 18, 48);
	}

	challenge = fr_pair_find_by_da(&request->request_pairs, attr_ms_chap_challenge);
	if (!challenge) {
		REDEBUG("&control.Auth-Type = %s set for a request that does not contain &%s",
			inst->name, attr_ms_chap_challenge->name);
		rcode = RLM_MODULE_INVALID;
		goto finish;
	}

	/*
	 *	We also require an MS-CHAP-Response.
	 */
	if ((response = fr_pair_find_by_da(&request->request_pairs, attr_ms_chap_response))) {
		mschap_process_response(&rcode,
					&mschap_version, nthashhash,
					inst, request,
					smb_ctrl, nt_password,
					challenge, response,
					method);
		if (rcode != RLM_MODULE_OK) goto finish;
	} else if ((response = fr_pair_find_by_da(&request->request_pairs, attr_ms_chap2_response))) {
		mschap_process_v2_response(&rcode,
					   &mschap_version, nthashhash,
					   inst, request,
					   smb_ctrl, nt_password,
					   challenge, response,
					   method);
		if (rcode != RLM_MODULE_OK) goto finish;
	} else {		/* Neither CHAPv1 or CHAPv2 response: die */
		REDEBUG("&control.Auth-Type = %s set for a request that does not contain &%s or &%s attributes",
			inst->name, attr_ms_chap_response->name, attr_ms_chap2_response->name);
		rcode = RLM_MODULE_INVALID;
		goto finish;
	}

	/* now create MPPE attributes */
	if (inst->use_mppe) {
		fr_pair_t	*vp;
		uint8_t		mppe_sendkey[34];
		uint8_t		mppe_recvkey[34];

		switch (mschap_version) {
		case 1:
			RDEBUG2("Generating MS-CHAPv1 MPPE keys");
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
			mppe_add_reply(inst, request, attr_ms_chap_mppe_keys, mppe_sendkey, 24);	//-V666
			break;

		case 2:
			RDEBUG2("Generating MS-CHAPv2 MPPE keys");
			mppe_chap2_gen_keys128(nthashhash, response->vp_octets + 26, mppe_sendkey, mppe_recvkey);

			mppe_add_reply(inst, request, attr_ms_mppe_recv_key, mppe_recvkey, 16);
			mppe_add_reply(inst, request, attr_ms_mppe_send_key, mppe_sendkey, 16);
			break;

		default:
			fr_assert(0);
			break;
		}

		MEM(pair_update_reply(&vp, attr_ms_mppe_encryption_policy) >= 0);
		vp->vp_uint32 = inst->require_encryption ? 2 : 1;

		MEM(pair_update_reply(&vp, attr_ms_mppe_encryption_types) >= 0);
		vp->vp_uint32 = inst->require_strong ? 4 : 6;
	} /* else we weren't asked to use MPPE */

finish:
	if (ephemeral) talloc_list_free(&nt_password);

	RETURN_MODULE_RCODE(rcode);
}

/*
 *	Create instance for our module. Allocate space for
 *	instance structure and read configuration parameters
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_mschap_t		*inst = instance;

	inst->auth_type = fr_dict_enum_by_name(attr_auth_type, inst->name, -1);
	if (!inst->auth_type) {
		WARN("Failed to find 'authenticate %s {...}' section.  MS-CHAP authentication will likely not work",
		     inst->name);
	}

	/*
	 *	Set auth method
	 */
	inst->method = AUTH_INTERNAL;

	if (inst->wb_username) {
#ifdef WITH_AUTH_WINBIND
		inst->method = AUTH_WBCLIENT;

		inst->wb_pool = module_connection_pool_init(conf, inst, mod_conn_create, NULL, NULL, NULL, NULL);
		if (!inst->wb_pool) {
			cf_log_err(conf, "Unable to initialise winbind connection pool");
			return -1;
		}
#else
		cf_log_err(conf, "'winbind' auth not enabled at compiled time");
		return -1;
#endif
	}

	/* preserve existing behaviour: this option overrides all */
	if (inst->ntlm_auth) {
		inst->method = AUTH_NTLMAUTH_EXEC;
	}

	switch (inst->method) {
	case AUTH_INTERNAL:
		DEBUG("Using internal authentication");
		break;
	case AUTH_NTLMAUTH_EXEC:
		DEBUG("Authenticating by calling 'ntlm_auth'");
		break;
#ifdef WITH_AUTH_WINBIND
	case AUTH_WBCLIENT:
		DEBUG("Authenticating directly to winbind");
		break;
#endif
	}

	/*
	 *	Check ntlm_auth_timeout is sane
	 */
	if (!inst->ntlm_auth_timeout) {
		inst->ntlm_auth_timeout = fr_time_delta_from_sec(EXEC_TIMEOUT);
	}
	if (inst->ntlm_auth_timeout < fr_time_delta_from_sec(1)) {
		cf_log_err(conf, "ntml_auth_timeout '%pVs' is too small (minimum: 1s)",
			   fr_box_time_delta(inst->ntlm_auth_timeout));
		return -1;
	}
	if (inst->ntlm_auth_timeout > fr_time_delta_from_sec(10)) {
		cf_log_err(conf, "ntlm_auth_timeout '%pVs' is too large (maximum: 10s)",
			   fr_box_time_delta(inst->ntlm_auth_timeout));
		return -1;
	}

	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	char const		*name;
	rlm_mschap_t		*inst = instance;

	/*
	 *	Create the dynamic translation.
	 */
	name = cf_section_name2(conf);
	if (!name) name = cf_section_name1(conf);
	inst->name = name;

	xlat_register_legacy(inst, inst->name, mschap_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN);

	return 0;
}

/*
 *	Tidy up instance
 */
static int mod_detach(
#ifndef WITH_AUTH_WINBIND
		      UNUSED
#endif
		      void *instance)
{
#ifdef WITH_AUTH_WINBIND
	rlm_mschap_t *inst = instance;

	fr_pool_free(inst->wb_pool);
#endif

	return 0;
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
