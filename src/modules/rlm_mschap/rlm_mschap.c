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

#define LOG_PREFIX mctx->mi->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/exec_legacy.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/password.h>
#include <freeradius-devel/tls/strerror.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/radius/defs.h>

#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/md4.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/sha1.h>

#include <freeradius-devel/unlang/action.h>
#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/xlat_func.h>

#include <sys/wait.h>

#include "rlm_mschap.h"
#include "smbdes.h"

#ifdef WITH_AUTH_WINBIND
#include "auth_wbclient.h"
#endif

#ifdef WITH_TLS
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */
#  include <freeradius-devel/tls/openssl_user_macros.h>
#  include <openssl/rc4.h>
#endif

#ifdef __APPLE__
unlang_action_t od_mschap_auth(unlang_result_t *p_result, request_t *request, fr_pair_t *challenge, fr_pair_t *usernamepair,
			       mschap_auth_call_env_t *env_data);
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

static const conf_parser_t passchange_config[] = {
	{ FR_CONF_OFFSET_FLAGS("ntlm_auth", CONF_FLAG_XLAT, rlm_mschap_t, ntlm_cpw) },
	CONF_PARSER_TERMINATOR
};

#ifdef WITH_AUTH_WINBIND
static conf_parser_t reuse_winbind_config[] = {
	FR_SLAB_CONFIG_CONF_PARSER
	CONF_PARSER_TERMINATOR
};
#endif

static const conf_parser_t winbind_config[] = {
	{ FR_CONF_OFFSET("username", rlm_mschap_t, wb_username) },
#ifdef WITH_AUTH_WINBIND
	{ FR_CONF_OFFSET("retry_with_normalised_username", rlm_mschap_t, wb_retry_with_normalised_username), .dflt = "no" },
	{ FR_CONF_OFFSET_SUBSECTION("reuse", 0, rlm_mschap_t, reuse, reuse_winbind_config) },
#endif
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("normalise", rlm_mschap_t, normify), .dflt = "yes" },

	/*
	 *	Cache the password by default.
	 */
	{ FR_CONF_OFFSET("use_mppe", rlm_mschap_t, use_mppe), .dflt = "yes" },
	{ FR_CONF_OFFSET("require_encryption", rlm_mschap_t, require_encryption), .dflt = "no" },
	{ FR_CONF_OFFSET("require_strong", rlm_mschap_t, require_strong), .dflt = "no" },
	{ FR_CONF_OFFSET("with_ntdomain_hack", rlm_mschap_t, with_ntdomain_hack), .dflt = "yes" },
	{ FR_CONF_OFFSET_FLAGS("ntlm_auth", CONF_FLAG_XLAT, rlm_mschap_t, ntlm_auth) },
	{ FR_CONF_OFFSET("ntlm_auth_timeout", rlm_mschap_t, ntlm_auth_timeout) },

	{ FR_CONF_POINTER("passchange", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) passchange_config },
	{ FR_CONF_OFFSET("allow_retry", rlm_mschap_t, allow_retry), .dflt = "yes" },
	{ FR_CONF_OFFSET("retry_msg", rlm_mschap_t, retry_msg) },


#ifdef __APPLE__
	{ FR_CONF_OFFSET("use_open_directory", rlm_mschap_t, open_directory), .dflt = "yes" },
#endif

	{ FR_CONF_POINTER("winbind", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) winbind_config },

	/*
	 *	These are now in a subsection above.
	 */
	{ FR_CONF_DEPRECATED("winbind_username", rlm_mschap_t, wb_username) },
#ifdef WITH_AUTH_WINBIND
	{ FR_CONF_DEPRECATED("winbind_retry_with_normalised_username", rlm_mschap_t, wb_retry_with_normalised_username) },
#endif
	CONF_PARSER_TERMINATOR
};

#define MSCHAP_CALL_ENV(_x) \
static const call_env_method_t mschap_ ## _x ## _method_env = { \
	FR_CALL_ENV_METHOD_OUT(mschap_ ## _x ## _call_env_t), \
	.env = (call_env_parser_t[]){ \
		{ FR_CALL_ENV_SUBSECTION("attributes", NULL, CALL_ENV_FLAG_REQUIRED, _x ## _call_env) }, \
		CALL_ENV_TERMINATOR \
	} \
}

#define MSCHAP_COMMON_CALL_ENV(_x) \
{ FR_CALL_ENV_PARSE_ONLY_OFFSET("chap_challenge", FR_TYPE_OCTETS, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED, mschap_ ## _x ## _call_env_t, chap_challenge), \
			       .pair.dflt = "Vendor-Specific.Microsoft.CHAP-Challenge", .pair.dflt_quote = T_BARE_WORD }, \
{ FR_CALL_ENV_PARSE_ONLY_OFFSET("chap_response", FR_TYPE_OCTETS, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED, mschap_ ## _x ## _call_env_t, chap_response), \
			       .pair.dflt = "Vendor-Specific.Microsoft.CHAP-Response", .pair.dflt_quote = T_BARE_WORD }, \
{ FR_CALL_ENV_PARSE_ONLY_OFFSET("chap2_response", FR_TYPE_OCTETS, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED, mschap_ ## _x ## _call_env_t, chap2_response), \
			       .pair.dflt = "Vendor-Specific.Microsoft.CHAP2-Response", .pair.dflt_quote = T_BARE_WORD }

#define MSCHAP_OPT_CALL_ENV(_opt, _x) \
{ FR_CALL_ENV_PARSE_ONLY_OFFSET(STRINGIFY(_opt), FR_TYPE_OCTETS, CALL_ENV_FLAG_ATTRIBUTE, mschap_ ## _x ## _call_env_t, _opt) }

typedef struct {
	tmpl_t const	*username;
	tmpl_t const	*chap_challenge;
	tmpl_t const	*chap_response;
	tmpl_t const	*chap2_response;
} mschap_xlat_call_env_t;

static const call_env_parser_t xlat_call_env[] = {
	{ FR_CALL_ENV_PARSE_ONLY_OFFSET("username", FR_TYPE_STRING, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED, mschap_xlat_call_env_t, username), .pair.dflt = "User-Name", .pair.dflt_quote = T_BARE_WORD },
	MSCHAP_COMMON_CALL_ENV(xlat),
	CALL_ENV_TERMINATOR
};

MSCHAP_CALL_ENV(xlat);

static const call_env_parser_t auth_call_env[] = {
	{ FR_CALL_ENV_PARSE_ONLY_OFFSET("username", FR_TYPE_STRING, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED, mschap_auth_call_env_t, username), .pair.dflt = "User-Name", .pair.dflt_quote = T_BARE_WORD },
	MSCHAP_COMMON_CALL_ENV(auth),
	MSCHAP_OPT_CALL_ENV(chap2_success, auth),
	MSCHAP_OPT_CALL_ENV(chap_error, auth),
	MSCHAP_OPT_CALL_ENV(chap_mppe_keys, auth),
	MSCHAP_OPT_CALL_ENV(mppe_encryption_policy, auth),
	MSCHAP_OPT_CALL_ENV(mppe_recv_key, auth),
	MSCHAP_OPT_CALL_ENV(mppe_send_key, auth),
	MSCHAP_OPT_CALL_ENV(mppe_encryption_types, auth),
	MSCHAP_OPT_CALL_ENV(chap2_cpw, auth),
	MSCHAP_OPT_CALL_ENV(chap_nt_enc_pw, auth),
	CALL_ENV_TERMINATOR
};

static const call_env_method_t mschap_auth_method_env = {
	FR_CALL_ENV_METHOD_OUT(mschap_auth_call_env_t),
	.env = (call_env_parser_t[]){ \
		{ FR_CALL_ENV_SUBSECTION("attributes", NULL, CALL_ENV_FLAG_REQUIRED, auth_call_env) },
		{ FR_CALL_ENV_SUBSECTION("passchange", NULL, CALL_ENV_FLAG_SUBSECTION,
			((call_env_parser_t[]) {
				{ FR_CALL_ENV_PARSE_ONLY_OFFSET("ntlm_auth_username", FR_TYPE_STRING, CALL_ENV_FLAG_NONE, mschap_auth_call_env_t, ntlm_cpw_username) },
				{ FR_CALL_ENV_PARSE_ONLY_OFFSET("ntlm_auth_domain", FR_TYPE_STRING, CALL_ENV_FLAG_NONE, mschap_auth_call_env_t, ntlm_cpw_domain) },
				{ FR_CALL_ENV_PARSE_ONLY_OFFSET("local_cpw", FR_TYPE_STRING, CALL_ENV_FLAG_NONE, mschap_auth_call_env_t, local_cpw) },
				CALL_ENV_TERMINATOR
			}))},
		{ FR_CALL_ENV_SUBSECTION("winbind", NULL, CALL_ENV_FLAG_NONE,
			((call_env_parser_t[]) {
				{ FR_CALL_ENV_OFFSET("username", FR_TYPE_STRING, CALL_ENV_FLAG_NONE, mschap_auth_call_env_t, wb_username) },
				{ FR_CALL_ENV_OFFSET("domain", FR_TYPE_STRING, CALL_ENV_FLAG_NULLABLE, mschap_auth_call_env_t, wb_domain) },
				CALL_ENV_TERMINATOR
			}))},
		CALL_ENV_TERMINATOR
	}
};

typedef struct {
	tmpl_t const	*chap_challenge;
	tmpl_t const	*chap_response;
	tmpl_t const	*chap2_response;
	tmpl_t const	*chap2_cpw;
} mschap_autz_call_env_t;

static const call_env_parser_t autz_call_env[] = {
	MSCHAP_COMMON_CALL_ENV(autz),
	MSCHAP_OPT_CALL_ENV(chap2_cpw, autz),
	CALL_ENV_TERMINATOR
};

MSCHAP_CALL_ENV(autz);

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_mschap_dict[];
fr_dict_autoload_t rlm_mschap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	DICT_AUTOLOAD_TERMINATOR
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

extern fr_dict_attr_autoload_t rlm_mschap_dict_attr[];
fr_dict_attr_autoload_t rlm_mschap_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_cleartext_password, .name = "Password.Cleartext", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_eap_identity, .name = "EAP-Identity", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_new_cleartext_password, .name = "MS-CHAP-New-Cleartext-Password", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_new_nt_password, .name = "MS-CHAP-New-NT-Password", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_peer_challenge, .name = "MS-CHAP-Peer-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_use_ntlm_auth, .name = "MS-CHAP-Use-NTLM-Auth", .type = FR_TYPE_UINT8, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_user_name, .name = "MS-CHAP-User-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_nt_password, .name = "Password.NT", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_smb_account_ctrl_text, .name = "SMB-Account-Ctrl-Text", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_smb_account_ctrl, .name = "SMB-Account-Ctrl", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	DICT_AUTOLOAD_TERMINATOR
};

static fr_pair_t *mschap_identity_find(request_t *request, fr_dict_attr_t const *attr_user_name)
{
	fr_pair_t *vp;

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_name);
	if (vp) return vp;

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_eap_identity);
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

static xlat_arg_parser_t const mschap_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	{ .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Get data from MSCHAP attributes
 *
 * Pulls NT-Response, LM-Response, or Challenge from MSCHAP
 * attributes.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t mschap_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 xlat_ctx_t const *xctx,
				 request_t *request, fr_value_box_list_t *in)
{
	mschap_xlat_call_env_t	*env_data = talloc_get_type_abort(xctx->env_data, mschap_xlat_call_env_t);
	size_t			data_len;
	uint8_t const  		*data = NULL;
	uint8_t			buffer[32];
	fr_pair_t		*user_name;
	fr_pair_t		*chap_challenge, *response;
	rlm_mschap_t const	*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_mschap_t);
	fr_value_box_t		*arg = fr_value_box_list_head(in);
	fr_value_box_t		*vb;
	bool			tainted = false;

	response = NULL;

	/*
	 *	Challenge means MS-CHAPv1 challenge, or
	 *	hash of MS-CHAPv2 challenge, and peer challenge.
	 */
	if (strncasecmp(arg->vb_strvalue, "Challenge", 9) == 0) {
		chap_challenge = fr_pair_find_by_da_nested(&request->request_pairs, NULL,
							   tmpl_attr_tail_da(env_data->chap_challenge));
		if (!chap_challenge) {
			REDEBUG("No MS-CHAP-Challenge in the request");
			return XLAT_ACTION_FAIL;
		}
		tainted = chap_challenge->vp_tainted;

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

			response = fr_pair_find_by_da_nested(&request->request_pairs, NULL,
							     tmpl_attr_tail_da(env_data->chap2_response));
			if (!response) {
				REDEBUG("Vendor-Specific.Microsoft.CHAP2-Response is required to calculate MS-CHAPv1 challenge");
				return XLAT_ACTION_FAIL;
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
				REDEBUG("Vendor-Specific.Microsoft.CHAP-Response has the wrong format");
				return XLAT_ACTION_FAIL;
			}

			user_name = mschap_identity_find(request, tmpl_attr_tail_da(env_data->username));
			if (!user_name) return XLAT_ACTION_FAIL;

			/*
			 *      Check for MS-CHAP-User-Name and if found, use it
			 *      to construct the MSCHAPv1 challenge.  This is
			 *      set by rlm_eap_mschap to the MS-CHAP Response
			 *      packet Name field.
			 *
			 *	We prefer this to the User-Name in the
			 *	packet.
			 */
			response_name = fr_pair_find_by_da(&request->request_pairs, NULL, attr_ms_chap_user_name);
			name_vp = response_name ? response_name : user_name;

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
			return XLAT_ACTION_FAIL;
		}

	/*
	 *	Get the MS-CHAPv1 response, or the MS-CHAPv2
	 *	response.
	 */
	} else if (strncasecmp(arg->vb_strvalue, "NT-Response", 11) == 0) {
		response = fr_pair_find_by_da_nested(&request->request_pairs, NULL,
						     tmpl_attr_tail_da(env_data->chap_response));
		if (!response) response = fr_pair_find_by_da_nested(&request->request_pairs, NULL,
								    tmpl_attr_tail_da(env_data->chap2_response));
		if (!response) {
			REDEBUG("No MS-CHAP-Response or MS-CHAP2-Response was found in the request");
			return XLAT_ACTION_FAIL;
		}
		tainted = response->vp_tainted;

		/*
		 *	For MS-CHAPv1, the NT-Response exists only
		 *	if the second octet says so.
		 */
		if ((response->da == tmpl_attr_tail_da(env_data->chap_response)) && ((response->vp_octets[1] & 0x01) == 0)) {
			REDEBUG("No NT-Response in MS-CHAP-Response");
			return XLAT_ACTION_FAIL;
		}

		if (response->vp_length < 50) {
			REDEBUG("Vendor-Specific.Microsoft.CHAP-Response has the wrong format");
			return XLAT_ACTION_FAIL;
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
	} else if (strncasecmp(arg->vb_strvalue, "LM-Response", 11) == 0) {
		response = fr_pair_find_by_da_nested(&request->request_pairs, NULL,
						     tmpl_attr_tail_da(env_data->chap_response));
		if (!response) {
			REDEBUG("No MS-CHAP-Response was found in the request");
			return XLAT_ACTION_FAIL;
		}
		tainted = response->vp_tainted;

		if (response->vp_length < 50) {
			REDEBUG("Vendor-Specific.Microsoft.CHAP-Response has the wrong format");
			return XLAT_ACTION_FAIL;
		}
		/*
		 *	For MS-CHAPv1, the LM-Response exists only
		 *	if the second octet says so.
		 */
		if ((response->vp_octets[1] & 0x01) != 0) {
			REDEBUG("No LM-Response in MS-CHAP-Response");
			return XLAT_ACTION_FAIL;
		}
		data = response->vp_octets + 2;
		data_len = 24;

	/*
	 *	Pull the domain name out of the User-Name, if it exists.
	 *
	 *	This is the full domain name, not just the name after host/
	 */
	} else if (strncasecmp(arg->vb_strvalue, "Domain-Name", 11) == 0) {
		char *p;

		MEM(vb = fr_value_box_alloc_null(ctx));

		user_name = mschap_identity_find(request, tmpl_attr_tail_da(env_data->username));
		if (!user_name) return XLAT_ACTION_FAIL;

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
				RDEBUG2("setting Domain-Name to same as machine name");
				fr_value_box_strdup(ctx, vb, NULL, user_name->vp_strvalue + 5, user_name->vp_tainted);
			} else {
				p++;	/* skip the period */

				fr_value_box_strdup(ctx, vb, NULL, p, user_name->vp_tainted);
			}
		} else {
			p = strchr(user_name->vp_strvalue, '\\');
			if (!p) {
				REDEBUG("No domain name was found in the User-Name");
				talloc_free(vb);
				return XLAT_ACTION_FAIL;
			}

			/*
			 *	Hack.  This is simpler than the alternatives.
			 */
			*p = '\0';
			fr_value_box_strdup(ctx, vb, NULL, user_name->vp_strvalue, user_name->vp_tainted);
			*p = '\\';
		}

		fr_dcursor_append(out, vb);
		return XLAT_ACTION_DONE;

	/*
	 *	Pull the NT-Domain out of the User-Name, if it exists.
	 */
	} else if (strncasecmp(arg->vb_strvalue, "NT-Domain", 9) == 0) {
		char *p, *q;

		MEM(vb = fr_value_box_alloc_null(ctx));

		user_name = mschap_identity_find(request, tmpl_attr_tail_da(env_data->username));
		if (!user_name) return XLAT_ACTION_FAIL;

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
				fr_value_box_strdup(ctx, vb, NULL, user_name->vp_strvalue + 5, user_name->vp_tainted);
			} else {
				p++;	/* skip the period */
				q = strchr(p, '.');
				/*
				 * use the same hack as below
				 * only if another period was found
				 */
				if (q) *q = '\0';
				fr_value_box_strdup(ctx, vb, NULL, p, user_name->vp_tainted);
				if (q) *q = '.';
			}
		} else {
			p = strchr(user_name->vp_strvalue, '\\');
			if (!p) {
				REDEBUG("No NT-Domain was found in the User-Name");
				talloc_free(vb);
				return XLAT_ACTION_FAIL;
			}

			/*
			 *	Hack.  This is simpler than the alternatives.
			 */
			*p = '\0';
			fr_value_box_strdup(ctx, vb, NULL, user_name->vp_strvalue, user_name->vp_tainted);
			*p = '\\';
		}

		fr_dcursor_append(out, vb);
		return XLAT_ACTION_DONE;

	/*
	 *	Pull the User-Name out of the User-Name...
	 */
	} else if (strncasecmp(arg->vb_strvalue, "User-Name", 9) == 0) {
		char const *p, *q;

		user_name = mschap_identity_find(request, tmpl_attr_tail_da(env_data->username));
		if (!user_name) return XLAT_ACTION_FAIL;

		MEM(vb = fr_value_box_alloc_null(ctx));

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
				fr_value_box_asprintf(ctx, vb, NULL, true, "%.*s$", (int) (q - p), p);
			} else {
				fr_value_box_asprintf(ctx, vb, NULL, true, "%s$", p);
			}
		} else {
			p = strchr(user_name->vp_strvalue, '\\');
			if (p) {
				p++;	/* skip the backslash */
			} else {
				p = user_name->vp_strvalue; /* use the whole User-Name */
			}
			fr_value_box_strdup(ctx, vb, NULL, p, user_name->vp_tainted);
		}

		fr_dcursor_append(out, vb);
		return XLAT_ACTION_DONE;

	/*
	 * Return the NT-Hash of the passed string
	 */
	} else if (strncasecmp(arg->vb_strvalue, "NT-Hash", 7) == 0) {
		arg = fr_value_box_list_next(in, arg);
		if ((!arg) || (arg->vb_length == 0))
			return XLAT_ACTION_FAIL;

		if (mschap_nt_password_hash(buffer, arg->vb_strvalue) < 0) {
			REDEBUG("Failed generating Password.NT");
			*buffer = '\0';
			return XLAT_ACTION_FAIL;
		}

		MEM(vb = fr_value_box_alloc_null(ctx));
		fr_value_box_memdup(ctx, vb, NULL, buffer, NT_DIGEST_LENGTH, false);
		RDEBUG2("NT-Hash of \"known-good\" password: %pV", vb);
		fr_dcursor_append(out, vb);
		return XLAT_ACTION_DONE;

	/*
	 * Return the LM-Hash of the passed string
	 */
	} else if (strncasecmp(arg->vb_strvalue, "LM-Hash", 7) == 0) {
		arg = fr_value_box_list_next(in, arg);
		if ((!arg) || (arg->vb_length == 0))
			return XLAT_ACTION_FAIL;

		smbdes_lmpwdhash(arg->vb_strvalue, buffer);

		MEM(vb = fr_value_box_alloc_null(ctx));
		fr_value_box_memdup(ctx, vb, NULL, buffer, LM_DIGEST_LENGTH, false);
		RDEBUG2("LM-Hash of %s = %pV", arg->vb_strvalue, vb);
		fr_dcursor_append(out, vb);
		return XLAT_ACTION_DONE;
	} else {
		REDEBUG("Unknown expansion string '%pV'", arg);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Didn't set anything: this is bad.
	 */
	if (!data) {
		RWDEBUG2("Failed to do anything intelligent");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(ctx, vb, NULL, data, data_len, tainted);

	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}


#ifdef WITH_AUTH_WINBIND
/*
 *	Free winbind context
 */
static int _mod_ctx_free(winbind_ctx_t *wbctx)
{
	wbcCtxFree(wbctx->ctx);
	return 0;
}

/*
 *	Create winbind context
 */
static int winbind_ctx_alloc(winbind_ctx_t *wbctx, UNUSED void *uctx)
{
	wbctx->ctx = wbcCtxCreate();
	if (!wbctx->ctx) {
		fr_strerror_printf("Unable to create winbind context");
		return -1;
	}
	talloc_set_destructor(wbctx, _mod_ctx_free);
	return 0;
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
	RDEBUG2("reply.%pP", vp);
	REXDENT();
}

/*
 *	Write a string to an fd, followed by "\n"
 */
static int write_all(int fd, char const *buf, size_t len)
{
	char const *p = buf;
	char const *end = buf + len;

	while (p < end) {
		ssize_t slen;

		slen = write(fd, p, end - p);
		if (slen <= 0) return -1;

		fr_assert((size_t) slen <= (size_t) (end - p));

		p += slen;
	}

	if (write(fd, "\n", 1) <= 0) return -1;

	return 0;
}

/*
 * Perform an MS-CHAP2 password change
 */

static int CC_HINT(nonnull) do_mschap_cpw(rlm_mschap_t const *inst, request_t *request, mschap_auth_ctx_t *auth_ctx,
					  uint8_t *new_nt_password, uint8_t *old_nt_hash)
{
	mschap_cpw_ctx_t	*cpw_ctx = auth_ctx->cpw_ctx;
	fr_value_box_t		*vb;

	if (inst->ntlm_cpw && auth_ctx->method != AUTH_INTERNAL) {
		/*
		 * we're going to run ntlm_auth in helper-mode
		 * we're expecting to use the ntlm-change-password-1 protocol
		 * which needs the following on stdin:
		 *
		 * username: %mschap(User-Name)
		 * nt-domain: %mschap(NT-Domain)
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

		size_t		size;
		int		status, len, to_child=-1, from_child=-1;
		pid_t		pid, child_pid;
		char		buf[2048];
		char		*pmsg;
		char const	*emsg;

		RDEBUG2("Doing MS-CHAPv2 password change via ntlm_auth helper");

		/*
		 * Start up ntlm_auth with a pipe on stdin and stdout
		 */

		pid = radius_start_program_legacy(&to_child, &from_child, NULL, inst->ntlm_cpw, request, true, NULL, false);
		if (pid < 0) {
			REDEBUG("could not exec ntlm_auth cpw command");
			return -1;
		}

		/*
		 * write the stuff to the client
		 */

		vb = fr_value_box_list_head(&cpw_ctx->cpw_user);
		if (!vb) goto ntlm_auth_err;

		if (write_all(to_child, vb->vb_strvalue, vb->vb_length) < 0) {
			REDEBUG("Failed to write username to child");
			goto ntlm_auth_err;
		}

		if (auth_ctx->env_data->ntlm_cpw_domain) {
			vb = fr_value_box_list_head(&cpw_ctx->cpw_domain);
			if (!vb) goto no_domain;

			if (write_all(to_child, vb->vb_strvalue, vb->vb_length) < 0) {
				REDEBUG("Failed to write domain to child");
				goto ntlm_auth_err;
			}
		} else {
		no_domain:
			RWDEBUG2("No ntlm_auth domain set, username must be full-username to work");
		}

		/* now the password blobs */
		size = snprintf(buf, sizeof(buf), "new-nt-password-blob: ");
		fr_base16_encode(&FR_SBUFF_OUT(buf + size, sizeof(buf) - size), &FR_DBUFF_TMP(new_nt_password, 516));
		size = strlen(buf);
		if (write_all(to_child, buf, size) < 0) {
			RDEBUG2("failed to write new password blob to child");
			goto ntlm_auth_err;
		}

		size = snprintf(buf, sizeof(buf), "old-nt-hash-blob: ");
		fr_base16_encode(&FR_SBUFF_OUT(buf + size, sizeof(buf) - size), &FR_DBUFF_TMP(old_nt_hash, NT_DIGEST_LENGTH));
		size = strlen(buf);
		if (write_all(to_child, buf, size) < 0) {
			REDEBUG("Failed to write old hash blob to child");
			goto ntlm_auth_err;
		}

		/*
		 *  In current samba versions, failure to supply empty LM password/hash
		 *  blobs causes the change to fail.
		 */
		size = snprintf(buf, sizeof(buf), "new-lm-password-blob: %01032i", 0);
		if (write_all(to_child, buf, size) < 0) {
			REDEBUG("Failed to write dummy LM password to child");
			goto ntlm_auth_err;
		}
		size = snprintf(buf, sizeof(buf), "old-lm-hash-blob: %032i", 0);
		if (write_all(to_child, buf, size) < 0) {
			REDEBUG("Failed to write dummy LM hash to child");
			goto ntlm_auth_err;
		}
		if (write_all(to_child, ".", 1) < 0) {
			REDEBUG("Failed to send finish to child");
			goto ntlm_auth_err;
		}
		close(to_child);
		to_child = -1;

		/*
		 *  Read from the child
		 */
		len = radius_readfrom_program_legacy(from_child, pid, fr_time_delta_from_sec(10), buf, sizeof(buf));
		if (len < 0) {
			/* radius_readfrom_program_legacy will have closed from_child for us */
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

		/*
		 *  Decrypt the new password blob, add it as a temporary request
		 *  variable, xlat the local_cpw string, then remove it
		 *
		 *  this allows is to write e..g
		 *
		 *  %sql(insert into ...)
		 *
		 *  ...or...
		 *
		 *  %exec('/path/to', %mschap(User-Name), %{MS-CHAP-New-Cleartext-Password})"
		 *
		 */
#ifdef WITH_TLS
	} else if (auth_ctx->env_data->local_cpw) {
		RDEBUG2("Doing MS-CHAPv2 password change locally");

		vb = fr_value_box_list_head(&cpw_ctx->local_cpw_result);

		if (!vb){
			return -1;
		} else if (vb->vb_length == 0) {
			REDEBUG("Local MS-CHAPv2 password change - didn't give any result, assuming failure");
			return -1;
		}

		RDEBUG2("MS-CHAPv2 password change succeeded: %pV", vb);

		/*
		 *  Update the Password.NT attribute with the new hash this lets us
		 *  fall through to the authentication code using the new hash,
		 *  not the old one.
		 */
		fr_pair_value_memdup(auth_ctx->nt_password, auth_ctx->cpw_ctx->new_hash->vp_octets,
				     auth_ctx->cpw_ctx->new_hash->vp_length, false);

		/*
		 *  Rock on! password change succeeded.
		 */
		return 0;
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
static int CC_HINT(nonnull) do_mschap(rlm_mschap_t const *inst, request_t *request,
				      mschap_auth_ctx_t *auth_ctx,
				      uint8_t const *challenge, uint8_t const *response,
				      uint8_t nthashhash[static NT_DIGEST_LENGTH])
{
	uint8_t		calculated[24];
	fr_pair_t	*password = auth_ctx->nt_password;

	memset(nthashhash, 0, NT_DIGEST_LENGTH);

	switch (auth_ctx->method) {
	case AUTH_INTERNAL:
	case AUTH_AUTO:
	/*
	 *	Do normal authentication.
	 */
		{
		/*
		 *	No password: can't do authentication.
		 */
		if (!password) {
			if (auth_ctx->method == AUTH_AUTO) goto do_ntlm;

			REDEBUG("FAILED: No Password.NT/LM.  Cannot perform authentication");
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
	do_ntlm:
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
		result = radius_exec_program_legacy(buffer, sizeof(buffer), request, inst->ntlm_auth, NULL,
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
		if (fr_base16_decode(NULL, &FR_DBUFF_TMP(nthashhash, NT_DIGEST_LENGTH),
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
		return do_auth_wbclient(inst, request, challenge, response, nthashhash, auth_ctx);
#endif
	default:
		/* We should never reach this line */
		RERROR("Internal error: Unknown mschap auth method (%d)", auth_ctx->method);
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
	 *	'encrypt=Tunnel-Password'.  The functions in src/lib/radius.c will
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
static unlang_action_t CC_HINT(nonnull) mod_authorize(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_mschap_t const 	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_mschap_t);
	mschap_autz_call_env_t	*env_data = talloc_get_type_abort(mctx->env_data, mschap_autz_call_env_t);
	fr_pair_t		*challenge = NULL;
	fr_pair_t		*parent;

	challenge = fr_pair_find_by_da_nested(&request->request_pairs, NULL, tmpl_attr_tail_da(env_data->chap_challenge));
	if (!challenge) RETURN_UNLANG_NOOP;

	/*
	 *	The responses MUST be in the same group as the challenge.
	 */
	parent = fr_pair_parent(challenge);
	fr_assert(parent != NULL);

	if (!fr_pair_find_by_da(&parent->vp_group, NULL, tmpl_attr_tail_da(env_data->chap_response)) &&
	    !fr_pair_find_by_da(&parent->vp_group, NULL, tmpl_attr_tail_da(env_data->chap2_response)) &&
	    (env_data->chap2_cpw &&
	     !fr_pair_find_by_da(&parent->vp_group, NULL, tmpl_attr_tail_da(env_data->chap2_cpw)))) {
		RDEBUG2("Found MS-CHAP-Challenge, but no MS-CHAP response or Change-Password");
		RETURN_UNLANG_NOOP;
	}

	if (!inst->auth_type) {
		WARN("No 'authenticate %s {...}' section or 'Auth-Type = %s' set.  Cannot setup MS-CHAP authentication",
		     mctx->mi->name, mctx->mi->name);
		RETURN_UNLANG_NOOP;
	}

	if (!module_rlm_section_type_set(request, attr_auth_type, inst->auth_type)) RETURN_UNLANG_NOOP;

	RETURN_UNLANG_OK;
}

static unlang_action_t mschap_error(unlang_result_t *p_result, rlm_mschap_t const *inst, request_t *request,
				    unsigned char ident, int mschap_result, int mschap_version, fr_pair_t *smb_ctrl,
				    mschap_auth_call_env_t *env_data)
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
		REDEBUG("%s is incorrect", mschap_version == 1 ? env_data->chap_response->name : env_data->chap2_response->name);
		error = 691;
		retry = inst->allow_retry;
		message = "Authentication failed";
		rcode = RLM_MODULE_REJECT;
	}

	if (rcode == RLM_MODULE_OK) RETURN_UNLANG_OK;

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
		RETURN_UNLANG_FAIL;
	}
	if (env_data->chap_error) mschap_add_reply(request, ident, tmpl_attr_tail_da(env_data->chap_error),
						   buffer, strlen(buffer));

	RETURN_UNLANG_RCODE(rcode);
}


/** Find a Password.NT value, or create one from a Password.Cleartext, or Password.With-Header attribute
 *
 * @param[in] ctx		to allocate ephemeral passwords in.
 * @param[out] out		Our new Password.NT.
 * @param[in] inst		Module configuration.
 * @param[in] request		The current request.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int CC_HINT(nonnull(1, 2, 3)) nt_password_find(TALLOC_CTX *ctx, fr_pair_t **out,
						      rlm_mschap_t const *inst, request_t *request)
{
	fr_pair_t		*password;
	fr_dict_attr_t const	*allowed_passwords[] = { attr_cleartext_password, attr_nt_password };
	bool			ephemeral;

	*out = NULL;		/* Init output pointer */

	password = password_find(&ephemeral, ctx, request,
				 allowed_passwords, NUM_ELEMENTS(allowed_passwords), inst->normify);
	if (!password) {
		if (inst->method == AUTH_INTERNAL) {
			/*
			 *	Search for passwords in the parent
			 *	FIXME: This is a hack and should be removed
			 *	When EAP-MSCHAPv2 supports sections.
			 */
			if (request->parent) {
				password = password_find(&ephemeral, ctx, request->parent,
							 allowed_passwords,
							 NUM_ELEMENTS(allowed_passwords), inst->normify);
				if (password) goto found_password;
			}

			/*
			 *	If we're doing internal auth, then this is an issue
			 */
			REDEBUG2("No control.%s.%s or control.%s.%s found.  Cannot create Password.NT",
				 attr_cleartext_password->parent->name, attr_cleartext_password->name,
				 attr_nt_password->parent->name, attr_nt_password->name);
			return -1;

		/*
		 *	..if we're not, then we can call out to external sources.
		 */
		} else {
			return 0;
		}
	}

found_password:
	if (password->da == attr_cleartext_password) {
		uint8_t		*p;
		int		ret;
		fr_pair_t	*nt_password;

		MEM(nt_password = fr_pair_afrom_da(ctx, attr_nt_password));
		MEM(fr_pair_value_mem_alloc(nt_password, &p, NT_DIGEST_LENGTH, false) == 0);
		ret = mschap_nt_password_hash(p, password->vp_strvalue);

		if (ret < 0) {
			RERROR("Failed generating Password.NT");
			talloc_free(nt_password);
			if (ephemeral) TALLOC_FREE(password);
			return -1;
		}

		if (RDEBUG_ENABLED3) {
			RDEBUG3("Hashed control.%pP to create %s = %pV",
				password, attr_nt_password->name, fr_box_octets(p, NT_DIGEST_LENGTH));
		} else {
			RDEBUG2("Hashed control.%s to create %s", attr_nt_password->name, password->da->name);
		}

		if (ephemeral) TALLOC_FREE(password);

		*out = nt_password;

		return 0;
	}

	fr_assert(password->da == attr_nt_password);

	if (RDEBUG_ENABLED3) {
		RDEBUG3("Found control.%pP", password);
	} else {
		RDEBUG2("Found control.%s", attr_nt_password->name);
	}
	*out = password;

	return 0;
}

/*
 *	mschap_cpw_request_process() - do the work to handle an MS-CHAP password
 *	change request.
 */
static unlang_action_t CC_HINT(nonnull) mschap_process_cpw_request(unlang_result_t *p_result,
								   rlm_mschap_t const *inst,
								   request_t *request,
								   mschap_auth_ctx_t *auth_ctx)
{
	mschap_auth_call_env_t	*env_data = auth_ctx->env_data;
	mschap_cpw_ctx_t	*cpw_ctx = auth_ctx->cpw_ctx;

	/*
	 *	Perform the actual password change
	 */
	if (do_mschap_cpw(inst, request, auth_ctx, cpw_ctx->new_nt_encrypted, cpw_ctx->old_nt_hash) < 0) {
		char buffer[128];

		REDEBUG("Password change failed");

		if (env_data->chap_error) {
			snprintf(buffer, sizeof(buffer), "E=709 R=0 M=Password change failed");
			mschap_add_reply(request, auth_ctx->cpw->vp_octets[1],
					 tmpl_attr_tail_da(env_data->chap_error), buffer, strlen(buffer));
		}

		RETURN_UNLANG_REJECT;
	}

	RDEBUG2("Password change successful");

	RETURN_UNLANG_OK;
}

/** Validate data required for change password requests.
 *
 */
static int mschap_cpw_prepare(request_t *request, mschap_auth_ctx_t *auth_ctx)
{
	mschap_auth_call_env_t	*env_data = auth_ctx->env_data;
	mschap_cpw_ctx_t	*cpw_ctx;
	fr_pair_t		*nt_enc = NULL;
	int			seq, new_nt_enc_len;

	/*
	 *	mschap2 password change request.
	 *
	 *	We cheat - first decode and execute the passchange.
	 *	Then extract the response, add it into the request
	 *	and then jump into mschap2 auth with the challenge/
	 *	response.
	 */
	RDEBUG2("MS-CHAPv2 password change request received");

	if (auth_ctx->cpw->vp_length != 68) {
		REDEBUG("%s has the wrong format: length %zu != 68", env_data->chap2_cpw->name, auth_ctx->cpw->vp_length);
		return -1;
	}

	if (auth_ctx->cpw->vp_octets[0] != 7) {
		REDEBUG("%s has the wrong format: code %d != 7", env_data->chap2_cpw->name, auth_ctx->cpw->vp_octets[0]);
		return -1;
	}

	MEM(auth_ctx->cpw_ctx = talloc_zero(auth_ctx, mschap_cpw_ctx_t));
	cpw_ctx = auth_ctx->cpw_ctx;

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
		int found = 0;

		while ((nt_enc = fr_pair_find_by_da_nested(&request->request_pairs, nt_enc,
							   tmpl_attr_tail_da(env_data->chap_nt_enc_pw)))) {
			if (nt_enc->vp_length < 4) {
				REDEBUG("%s with invalid format", env_data->chap_nt_enc_pw->name);
				return -1;
			}

			if (nt_enc->vp_octets[0] != 6) {
				REDEBUG("%s with invalid format", env_data->chap_nt_enc_pw->name);
				return -1;
			}

			if ((nt_enc->vp_octets[2] == 0) && (nt_enc->vp_octets[3] == seq)) {
				found = 1;
				break;
			}
		}

		if (!found) {
			REDEBUG("Could not find %s with sequence number %d", env_data->chap_nt_enc_pw->name, seq);
			return -1;
		}

		if ((new_nt_enc_len + nt_enc->vp_length - 4) > sizeof(cpw_ctx->new_nt_encrypted)) {
			REDEBUG("Unpacked %s length > 516", env_data->chap_nt_enc_pw->name);
			return -1;
		}

		memcpy(cpw_ctx->new_nt_encrypted + new_nt_enc_len, nt_enc->vp_octets + 4, nt_enc->vp_length - 4);
		new_nt_enc_len += nt_enc->vp_length - 4;
	}

	if (new_nt_enc_len != 516) {
		REDEBUG("Unpacked %s length is %d - should be 516", env_data->chap_nt_enc_pw->name, new_nt_enc_len);
		return -1;
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

	memcpy(cpw_ctx->old_nt_hash, auth_ctx->cpw->vp_octets + 2, sizeof(cpw_ctx->old_nt_hash));

	RDEBUG2("Password change payload valid");
	return 0;
}

static CC_HINT(nonnull) unlang_action_t mschap_process_response(unlang_result_t *p_result, int *mschap_version,
								uint8_t nthashhash[static NT_DIGEST_LENGTH],
								rlm_mschap_t const *inst, request_t *request,
								mschap_auth_ctx_t *auth_ctx,
								fr_pair_t *challenge, fr_pair_t *response)
{
	int			offset;
	rlm_rcode_t		mschap_result;
	mschap_auth_call_env_t	*env_data = auth_ctx->env_data;

	*mschap_version = 1;

	RDEBUG2("Processing MS-CHAPv1 response");

	/*
	 *	MS-CHAPv1 challenges are 8 octets.
	 */
	if (challenge->vp_length < 8) {
		REDEBUG("%s has the wrong format", env_data->chap_challenge->name);
		RETURN_UNLANG_INVALID;
	}

	/*
	 *	Responses are 50 octets.
	 */
	if (response->vp_length < 50) {
		REDEBUG("%s has the wrong format", env_data->chap_response->name);
		RETURN_UNLANG_INVALID;
	}

	/*
	 *	We are doing MS-CHAP.  Calculate the MS-CHAP
	 *	response
	 */
	if (!(response->vp_octets[1] & 0x01)) {
		REDEBUG2("Client used unsupported method LM-Password");
		RETURN_UNLANG_FAIL;
	}

	offset = 26;

	/*
	 *	Do the MS-CHAP authentication.
	 */
	mschap_result = do_mschap(inst, request, auth_ctx, challenge->vp_octets, response->vp_octets + offset, nthashhash);

	/*
	 *	Check for errors, and add MSCHAP-Error if necessary.
	 */
	return mschap_error(p_result, inst, request, *response->vp_octets, mschap_result, *mschap_version, auth_ctx->smb_ctrl, env_data);
}

static unlang_action_t CC_HINT(nonnull) mschap_process_v2_response(unlang_result_t *p_result, int *mschap_version,
								   uint8_t nthashhash[static NT_DIGEST_LENGTH],
								   rlm_mschap_t const *inst, request_t *request,
								   mschap_auth_ctx_t *auth_ctx,
								   fr_pair_t *challenge, fr_pair_t *response)
{
	uint8_t		mschap_challenge[16];
	fr_pair_t	*user_name, *name_vp, *response_name, *peer_challenge_attr;
	uint8_t const	*peer_challenge;
	char const	*username_str;
	size_t		username_len;
	int		mschap_result;
	char		msch2resp[42];
	mschap_auth_call_env_t	*env_data = auth_ctx->env_data;

	*mschap_version = 2;

	RDEBUG2("Processing MS-CHAPv2 response");

	/*
	 *	MS-CHAPv2 challenges are 16 octets.
	 */
	if (challenge->vp_length < 16) {
		REDEBUG("%s has the wrong format", env_data->chap_challenge->name);
		RETURN_UNLANG_INVALID;
	}

	/*
	 *	Responses are 50 octets.
	 */
	if (response->vp_length < 50) {
		REDEBUG("%s has the wrong format", env_data->chap2_response->name);
		RETURN_UNLANG_INVALID;
	}

	/*
	 *	We also require a User-Name
	 */
	user_name = mschap_identity_find(request, tmpl_attr_tail_da(env_data->username));
	if (!user_name) RETURN_UNLANG_FAIL;

	/*
	 *      Check for MS-CHAP-User-Name and if found, use it
	 *      to construct the MSCHAPv1 challenge.  This is
	 *      set by rlm_eap_mschap to the MS-CHAP Response
	 *      packet Name field.
	 *
	 *	We prefer this to the User-Name in the
	 *	packet.
	 */
	response_name = fr_pair_find_by_da(&request->request_pairs, NULL, attr_ms_chap_user_name);
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
	 *  No "known good" Password.NT attribute.  Try to do
	 *  OpenDirectory authentication.
	 *
	 *  If OD determines the user is an AD user it will return noop, which
	 *  indicates the auth process should continue directly to AD.
	 *  Otherwise OD will determine auth success/fail.
	 */
	if (!auth_ctx->nt_password && inst->open_directory) {
		RDEBUG2("No Password.NT available. Trying OpenDirectory Authentication");
		od_mschap_auth(p_result, request, challenge, user_name, env_data);
		if (p_result->rcode != RLM_MODULE_NOOP) return UNLANG_ACTION_CALCULATE_RESULT;
	}
#endif
	peer_challenge = response->vp_octets + 2;

	peer_challenge_attr = fr_pair_find_by_da(&request->control_pairs, NULL, attr_ms_chap_peer_challenge);
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

	mschap_result = do_mschap(inst, request, auth_ctx, mschap_challenge, response->vp_octets + 26, nthashhash);

	/*
	 *	Check for errors, and add MSCHAP-Error if necessary.
	 */
	mschap_error(p_result, inst, request, *response->vp_octets,
		     mschap_result, *mschap_version, auth_ctx->smb_ctrl, env_data);
	if (p_result->rcode != RLM_MODULE_OK) return UNLANG_ACTION_CALCULATE_RESULT;

#ifdef WITH_AUTH_WINBIND
	if (inst->wb_retry_with_normalised_username) {
		response_name = fr_pair_find_by_da(&request->request_pairs, NULL, attr_ms_chap_user_name);
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
	if (env_data->chap2_success) mschap_add_reply(request, *response->vp_octets,
						      tmpl_attr_tail_da(env_data->chap2_success), msch2resp, 42);

	RETURN_UNLANG_OK;
}

/** Complete mschap authentication after any tmpls have been expanded.
 *
 */
static unlang_action_t mod_authenticate_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	mschap_auth_ctx_t	*auth_ctx = talloc_get_type_abort(mctx->rctx, mschap_auth_ctx_t);
	mschap_auth_call_env_t	*env_data = talloc_get_type_abort(auth_ctx->env_data, mschap_auth_call_env_t);
	rlm_mschap_t const	*inst = talloc_get_type_abort_const(auth_ctx->inst, rlm_mschap_t);
	fr_pair_t		*challenge = NULL;
	fr_pair_t		*response = NULL;
	fr_pair_t		*parent;
	uint8_t			nthashhash[NT_DIGEST_LENGTH];
	int			mschap_version = 0;

	p_result->rcode = RLM_MODULE_OK;

	if (auth_ctx->cpw) {
		uint8_t		*p;

		/*
		 *	Password change does require the NT password
		 */
		if (!auth_ctx->nt_password) {
			REDEBUG("Missing Password.NT - required for change password request");
			RETURN_UNLANG_FAIL;
		}
		if (!env_data->chap_nt_enc_pw) {
			REDEBUG("chap_nt_enc_pw option is not set - required for change password request");
			RETURN_UNLANG_INVALID;
		}

		mschap_process_cpw_request(p_result, inst, request, auth_ctx);
		if (p_result->rcode != RLM_MODULE_OK) goto finish;

		/*
		 *	Clear any expiry bit so the user can now login;
		 *	obviously the password change action will need
		 *	to have cleared this bit in the config/SQL/wherever.
		 */
		if (auth_ctx->smb_ctrl && auth_ctx->smb_ctrl->vp_uint32 & ACB_FR_EXPIRED) {
			RDEBUG2("Clearing expiry bit in SMB-Acct-Ctrl to allow authentication");
			auth_ctx->smb_ctrl->vp_uint32 &= ~ACB_FR_EXPIRED;
		}

		/*
		 *	Extract the challenge & response from the end of the
		 *	password change, add them into the request and then
		 *	continue with the authentication.
		 */
		MEM(pair_update_request(&response, tmpl_attr_tail_da(env_data->chap2_response)) >= 0);
		MEM(fr_pair_value_mem_alloc(response, &p, 50, auth_ctx->cpw->vp_tainted) == 0);

		/* ident & flags */
		p[0] = auth_ctx->cpw->vp_octets[1];
		p[1] = 0;
		/* peer challenge and client NT response */
		memcpy(p + 2, auth_ctx->cpw->vp_octets + 18, 48);
	}

	challenge = fr_pair_find_by_da_nested(&request->request_pairs, NULL, tmpl_attr_tail_da(env_data->chap_challenge));
	if (!challenge) {
		REDEBUG("control.Auth-Type = %s set for a request that does not contain %s",
			auth_ctx->name, env_data->chap_challenge->name);
		p_result->rcode = RLM_MODULE_INVALID;
		goto finish;
	}

	/*
	 *	The responses MUST be in the same group as the challenge.
	 */
	parent = fr_pair_parent(challenge);
	fr_assert(parent != NULL);

	/*
	 *	We also require an MS-CHAP-Response.
	 */
	if ((response = fr_pair_find_by_da(&parent->vp_group, NULL, tmpl_attr_tail_da(env_data->chap_response)))) {
		mschap_process_response(p_result,
					&mschap_version, nthashhash,
					inst, request,
					auth_ctx,
					challenge, response);
		if (p_result->rcode != RLM_MODULE_OK) goto finish;
	} else if ((response = fr_pair_find_by_da_nested(&parent->vp_group, NULL, tmpl_attr_tail_da(env_data->chap2_response)))) {
		mschap_process_v2_response(p_result,
					   &mschap_version, nthashhash,
					   inst, request,
					   auth_ctx,
					   challenge, response);
		if (p_result->rcode != RLM_MODULE_OK) goto finish;
	} else {		/* Neither CHAPv1 or CHAPv2 response: die */
		REDEBUG("control.Auth-Type = %s set for a request that does not contain %s or %s attributes",
			auth_ctx->name, env_data->chap_response->name, env_data->chap2_response->name);
		p_result->rcode = RLM_MODULE_INVALID;
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
			mppe_add_reply(inst, request, tmpl_attr_tail_da(env_data->chap_mppe_keys), mppe_sendkey, 24);	//-V666
			break;

		case 2:
			RDEBUG2("Generating MS-CHAPv2 MPPE keys");
			mppe_chap2_gen_keys128(nthashhash, response->vp_octets + 26, mppe_sendkey, mppe_recvkey);

			mppe_add_reply(inst, request, tmpl_attr_tail_da(env_data->mppe_recv_key), mppe_recvkey, 16);
			mppe_add_reply(inst, request, tmpl_attr_tail_da(env_data->mppe_send_key), mppe_sendkey, 16);
			break;

		default:
			fr_assert(0);
			break;
		}

		MEM(pair_update_reply(&vp, tmpl_attr_tail_da(env_data->mppe_encryption_policy)) >= 0);
		vp->vp_uint32 = inst->require_encryption ? 2 : 1;

		MEM(pair_update_reply(&vp, tmpl_attr_tail_da(env_data->mppe_encryption_types)) >= 0);
		vp->vp_uint32 = inst->require_strong ? 4 : 6;
	} /* else we weren't asked to use MPPE */

finish:
	return UNLANG_ACTION_CALCULATE_RESULT;
}

#ifdef WITH_TLS
/** Decrypt the new cleartext password when handling change password requests
 *
 */
static int mschap_new_pass_decrypt(request_t *request, mschap_auth_ctx_t *auth_ctx)
{
	EVP_CIPHER_CTX	*evp_ctx;
	uint8_t		nt_pass_decrypted[516], old_nt_hash_expected[NT_DIGEST_LENGTH];
	int		c, ntlen = sizeof(nt_pass_decrypted);
	size_t		passlen, i = 0, len = 0;
	char		*x;
	uint8_t		*p, *q;
	fr_pair_t	*new_pass;

	MEM(evp_ctx = EVP_CIPHER_CTX_new());

	if (unlikely(EVP_EncryptInit_ex(evp_ctx, EVP_rc4(), NULL, auth_ctx->nt_password->vp_octets, NULL) != 1)) {
		fr_tls_strerror_printf(NULL);
		RPERROR("Failed initialising RC4 ctx");
		return -1;
	}

	if (unlikely(EVP_CIPHER_CTX_set_key_length(evp_ctx, auth_ctx->nt_password->vp_length)) != 1) {
		fr_tls_strerror_printf(NULL);
		RPERROR("Failed setting key length");
		return -1;
	}

	if (unlikely(EVP_EncryptUpdate(evp_ctx, nt_pass_decrypted, &ntlen, auth_ctx->cpw_ctx->new_nt_encrypted, ntlen) != 1)) {
		fr_tls_strerror_printf(NULL);
		RPERROR("Failed ingesting new password");
		return -1;
	}

 	EVP_CIPHER_CTX_free(evp_ctx);

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
		REDEBUG("Decrypted new password blob claims length > 65536, probably an invalid Password.NT");
		return -1;
	}

	/*
	 *  Sanity check - passlen positive and <= 512 if not, crypto has probably gone wrong
	 */
	if (passlen > 512) {
		REDEBUG("Decrypted new password blob claims length %zu > 512, "
			"probably an invalid Password.NT", passlen);
		return -1;
	}

	p = nt_pass_decrypted + 512 - passlen;

	/*
	 *  The new NT hash - this should be preferred over the
	 *  cleartext password as it avoids unicode hassles.
	 */
	MEM(pair_update_request(&auth_ctx->cpw_ctx->new_hash, attr_ms_chap_new_nt_password) >= 0);
	MEM(fr_pair_value_mem_alloc(auth_ctx->cpw_ctx->new_hash, &q, NT_DIGEST_LENGTH, false) == 0);
	fr_md4_calc(q, p, passlen);

	/*
	 *  Check that nt_password encrypted with new_hash
	 *  matches the old_hash value from the client.
	 */
	smbhash(old_nt_hash_expected, auth_ctx->nt_password->vp_octets, q);
	smbhash(old_nt_hash_expected + 8, auth_ctx->nt_password->vp_octets + 8, q + 7);
	if (fr_digest_cmp(old_nt_hash_expected, auth_ctx->cpw_ctx->old_nt_hash, NT_DIGEST_LENGTH)!=0) {
		REDEBUG("Old NT hash value from client does not match our value");
		RHEXDUMP1(old_nt_hash_expected, NT_DIGEST_LENGTH, "expected");
		RHEXDUMP1(auth_ctx->cpw_ctx->old_nt_hash, NT_DIGEST_LENGTH, "got");
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

	while (i < passlen) {
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
	return 0;
}
#endif

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
static unlang_action_t CC_HINT(nonnull) mod_authenticate(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_mschap_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_mschap_t);
#ifdef WITH_AUTH_WINBIND
	rlm_mschap_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_mschap_thread_t);
#endif
	mschap_auth_call_env_t	*env_data = talloc_get_type_abort(mctx->env_data, mschap_auth_call_env_t);
	mschap_auth_ctx_t	*auth_ctx;

	MEM(auth_ctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), mschap_auth_ctx_t));

	/*
	 *	If we have ntlm_auth configured, use it unless told
	 *	otherwise
	 */
	*auth_ctx = (mschap_auth_ctx_t) {
		.name = mctx->mi->name,
		.inst = inst,
		.method = inst->method,
		.env_data = env_data,
#ifdef WITH_AUTH_WINBIND
		.t = t,
#endif
	};

	/*
	 *	If we have an ntlm_auth configuration, then we may
	 *	want to suppress it.
	 */
	if (auth_ctx->method != AUTH_INTERNAL) {
		fr_pair_t *vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_ms_chap_use_ntlm_auth);
		if (vp && (vp->vp_uint8 <= AUTH_AUTO)) auth_ctx->method = vp->vp_uint8;
	}

	/*
	 *	Find the SMB-Account-Ctrl attribute, or the
	 *	SMB-Account-Ctrl-Text attribute.
	 */
	auth_ctx->smb_ctrl = fr_pair_find_by_da(&request->control_pairs, NULL, attr_smb_account_ctrl);
	if (!auth_ctx->smb_ctrl) {
		fr_pair_t *smb_account_ctrl_text;

		smb_account_ctrl_text = fr_pair_find_by_da(&request->control_pairs, NULL, attr_smb_account_ctrl_text);
		if (smb_account_ctrl_text) {
			MEM(pair_append_control(&auth_ctx->smb_ctrl, attr_smb_account_ctrl) >= 0);
			auth_ctx->smb_ctrl->vp_uint32 = pdb_decode_acct_ctrl(smb_account_ctrl_text->vp_strvalue);
		}
	}

	/*
	 *	We're configured to do MS-CHAP authentication.
	 *	and account control information exists.  Enforce it.
	 */
	if (auth_ctx->smb_ctrl) {
		/*
		 *	Password is not required.
		 */
		if ((auth_ctx->smb_ctrl->vp_uint32 & ACB_PWNOTREQ) != 0) {
			RDEBUG2("SMB-Account-Ctrl says no password is required");
			RETURN_UNLANG_OK;
		}
	}

	/*
	 *	Look for or create an Password.NT
	 *
	 *      Password.NT can be NULL here if we didn't find an
	 *	input attribute, and we're calling out to an
	 *	external password store.
	 */
	if (nt_password_find(auth_ctx, &auth_ctx->nt_password, mctx->mi->data, request) < 0) RETURN_UNLANG_FAIL;

	/*
	 *	Check to see if this is a change password request, and process
	 *	it accordingly if so.
	 */
	if (env_data->chap2_cpw) auth_ctx->cpw = fr_pair_find_by_da_nested(&request->request_pairs, NULL,
									   tmpl_attr_tail_da(env_data->chap2_cpw));
	if (auth_ctx->cpw) {
		/*
		 *	Password change does require the NT password
		 */
		if (!auth_ctx->nt_password) {
			REDEBUG("Missing Password.NT - required for change password request");
			RETURN_UNLANG_FAIL;
		}

		if (mschap_cpw_prepare(request, auth_ctx) < 0) RETURN_UNLANG_FAIL;

		switch (auth_ctx->method) {
		case AUTH_INTERNAL:
#ifdef WITH_TLS
			if (mschap_new_pass_decrypt(request, auth_ctx) < 0) RETURN_UNLANG_FAIL;

			if (unlang_module_yield(request, mod_authenticate_resume, NULL, 0, auth_ctx) == UNLANG_ACTION_FAIL) {
				RETURN_UNLANG_FAIL;
			}

			fr_value_box_list_init(&auth_ctx->cpw_ctx->local_cpw_result);
			if (unlang_tmpl_push(auth_ctx, NULL, &auth_ctx->cpw_ctx->local_cpw_result, request,
					     env_data->local_cpw, NULL, UNLANG_SUB_FRAME) < 0) RETURN_UNLANG_FAIL;
			break;
#else
			REDEBUG("Local MS-CHAPv2 password changes require OpenSSL support");
			RETURN_UNLANG_INVALID;
#endif

		default:
			if (!env_data->ntlm_cpw_username) {
				REDEBUG("No ntlm_auth username set, passchange will definitely fail!");
				RETURN_UNLANG_FAIL;
			}

			/*
			 *	Run the resumption function where we're done with:
			 */
			if (unlang_module_yield(request, mod_authenticate_resume, NULL, 0, auth_ctx) == UNLANG_ACTION_FAIL) {
				RETURN_UNLANG_FAIL;
			};

			/*
			 *	a) Expanding the domain, if specified
			 */
			if (env_data->ntlm_cpw_domain) {
				fr_value_box_list_init(&auth_ctx->cpw_ctx->cpw_domain);
				if (unlang_tmpl_push(auth_ctx, NULL, &auth_ctx->cpw_ctx->cpw_domain, request,
						     env_data->ntlm_cpw_domain, NULL, UNLANG_SUB_FRAME) < 0) RETURN_UNLANG_FAIL;
			}

			fr_value_box_list_init(&auth_ctx->cpw_ctx->cpw_user);

			/*
			 *	b) Expanding the username
			 */
			if (unlang_tmpl_push(auth_ctx, NULL, &auth_ctx->cpw_ctx->cpw_user, request,
					     env_data->ntlm_cpw_username, NULL, UNLANG_SUB_FRAME) < 0) RETURN_UNLANG_FAIL;
			break;
		}

		return UNLANG_ACTION_PUSHED_CHILD;
	}

	/*
	 *	Not doing password change, just jump straight to the resumption function...
	 */
	{
		module_ctx_t our_mctx = *mctx;
		our_mctx.rctx = auth_ctx;

		return mod_authenticate_resume(p_result, &our_mctx, request);
	}
}

/*
 *	Create instance for our module. Allocate space for
 *	instance structure and read configuration parameters
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_mschap_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_mschap_t);
	CONF_SECTION		*conf = mctx->mi->conf;

	inst->auth_type = fr_dict_enum_by_name(attr_auth_type, mctx->mi->name, -1);
	if (!inst->auth_type) {
		WARN("Failed to find 'authenticate %s {...}' section.  MS-CHAP authentication will likely not work",
		     mctx->mi->name);
	}

	/*
	 *	Set auth method
	 */
	inst->method = AUTH_INTERNAL;

	if (inst->wb_username) {
#ifdef WITH_AUTH_WINBIND
		inst->method = AUTH_WBCLIENT;
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
	case AUTH_AUTO:
		DEBUG("Using auto password or ntlm_auth");
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
	if (!fr_time_delta_ispos(inst->ntlm_auth_timeout)) {
		inst->ntlm_auth_timeout = fr_time_delta_from_sec(EXEC_TIMEOUT);
	}
	if (fr_time_delta_lt(inst->ntlm_auth_timeout, fr_time_delta_from_sec(1))) {
		cf_log_err(conf, "ntml_auth_timeout '%pVs' is too small (minimum: 1s)",
			   fr_box_time_delta(inst->ntlm_auth_timeout));
		return -1;
	}
	if (fr_time_delta_gt(inst->ntlm_auth_timeout, fr_time_delta_from_sec(10))) {
		cf_log_err(conf, "ntlm_auth_timeout '%pVs' is too large (maximum: 10s)",
			   fr_box_time_delta(inst->ntlm_auth_timeout));
		return -1;
	}

#define CHECK_OPTION(_option) cp = cf_pair_find(attrs, STRINGIFY(_option)); \
if (!cp) { \
	WARN("Missing option \"" STRINGIFY(_option) "\", setting use_mppe to \"no\""); \
	inst->use_mppe = false; \
	goto done_mppe_check; \
}

	/*
	 *	Check that MPPE attributes are in the module config, if the option is enabled.
	 *	Validity of them will be checked when the module is compiled.
	 */
	if (inst->use_mppe) {
		CONF_SECTION	*attrs = cf_section_find(conf, "attributes", NULL);
		CONF_PAIR	*cp;

		if (!attrs) {
			cf_log_err(conf, "Missing required \"attributes\" section");
			return -1;
		}
		CHECK_OPTION(chap_mppe_keys)
		CHECK_OPTION(mppe_encryption_policy)
		CHECK_OPTION(mppe_recv_key)
		CHECK_OPTION(mppe_send_key)
		CHECK_OPTION(mppe_encryption_types)
	}
done_mppe_check:

	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	xlat_t *xlat;

	xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, NULL, mschap_xlat, FR_TYPE_VOID);
	xlat_func_args_set(xlat, mschap_xlat_args);
	xlat_func_call_env_set(xlat, &mschap_xlat_method_env);

	return 0;
}

#ifdef WITH_AUTH_WINBIND
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_mschap_t const	*inst = talloc_get_type_abort(mctx->mi->data, rlm_mschap_t);
	rlm_mschap_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_mschap_thread_t);

	t->inst = inst;
	if (!(t->slab = mschap_slab_list_alloc(t, mctx->el, &inst->reuse, winbind_ctx_alloc, NULL, NULL, false, false))) {
		ERROR("Connection handle pool instantiation failed");
		return -1;
	}

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_mschap_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_mschap_thread_t);
	talloc_free(t->slab);
	return 0;
}
#endif

extern module_rlm_t rlm_mschap;
module_rlm_t rlm_mschap = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "mschap",
		.inst_size	= sizeof(rlm_mschap_t),
		.config		= module_config,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate,
#ifdef WITH_AUTH_WINBIND
		.thread_inst_size	= sizeof(rlm_mschap_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach
#endif
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME("authenticate", CF_IDENT_ANY), .method = mod_authenticate, .method_env = &mschap_auth_method_env },
			{ .section = SECTION_NAME("recv", CF_IDENT_ANY), .method = mod_authorize, .method_env = &mschap_autz_method_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
