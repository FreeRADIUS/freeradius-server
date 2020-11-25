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
 * @file rlm_yubikey.c
 * @brief Authentication for yubikey OTP tokens.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@networkradius.com)
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 Network RADIUS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/radius/radius.h>
#include "rlm_yubikey.h"

#ifdef HAVE_YKCLIENT
static const CONF_PARSER validation_config[] = {
	{ FR_CONF_OFFSET("client_id", FR_TYPE_UINT32, rlm_yubikey_t, client_id), .dflt = 0 },
	{ FR_CONF_OFFSET("api_key", FR_TYPE_STRING | FR_TYPE_SECRET, rlm_yubikey_t, api_key) },
	CONF_PARSER_TERMINATOR
};
#endif

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("id_length", FR_TYPE_UINT32, rlm_yubikey_t, id_len), .dflt = "12" },
	{ FR_CONF_OFFSET("split", FR_TYPE_BOOL, rlm_yubikey_t, split), .dflt = "yes" },
	{ FR_CONF_OFFSET("decrypt", FR_TYPE_BOOL, rlm_yubikey_t, decrypt), .dflt = "no" },
	{ FR_CONF_OFFSET("validate", FR_TYPE_BOOL, rlm_yubikey_t, validate), .dflt = "no" },
#ifdef HAVE_YKCLIENT
	{ FR_CONF_POINTER("validation", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) validation_config },
#endif
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_yubikey_dict[];
fr_dict_autoload_t rlm_yubikey_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_user_password;
static fr_dict_attr_t const *attr_yubikey_key;
static fr_dict_attr_t const *attr_yubikey_public_id;
static fr_dict_attr_t const *attr_yubikey_private_id;
static fr_dict_attr_t const *attr_yubikey_counter;
static fr_dict_attr_t const *attr_yubikey_timestamp;
static fr_dict_attr_t const *attr_yubikey_random;
static fr_dict_attr_t const *attr_yubikey_otp;

extern fr_dict_attr_autoload_t rlm_yubikey_dict_attr[];
fr_dict_attr_autoload_t rlm_yubikey_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_yubikey_key, .name = "Yubikey-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_yubikey_public_id, .name = "Yubikey-Public-ID", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_yubikey_private_id, .name = "Yubikey-Private-ID", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_yubikey_counter, .name = "Yubikey-Counter", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_yubikey_timestamp, .name = "Yubikey-Timestamp", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_yubikey_random, .name = "Yubikey-Random", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_yubikey_otp, .name = "Yubikey-OTP", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};

static char const modhextab[] = "cbdefghijklnrtuv";
static char const hextab[] = "0123456789abcdef";

#define is_modhex(x) (memchr(modhextab, tolower(x), 16))

/** Convert yubikey modhex to normal hex
 *
 * The same buffer may be passed as modhex and hex to convert the modhex in place.
 *
 * Modhex and hex must be the same size.
 *
 * @param[in] modhex data.
 * @param[in] len of input and output buffers.
 * @param[out] hex where to write the standard hexits.
 * @return
 *	- The number of bytes written to the output buffer.
 *	- -1 on failure.
 */
static ssize_t modhex2hex(char const *modhex, uint8_t *hex, size_t len)
{
	size_t i;
	char *c1, *c2;

	for (i = 0; i < len; i++) {
		if (modhex[i << 1] == '\0') {
			break;
		}

		/*
		 *	We only deal with whole bytes
		 */
		if (modhex[(i << 1) + 1] == '\0')
			return -1;

		if (!(c1 = memchr(modhextab, tolower((int) modhex[i << 1]), 16)) ||
		    !(c2 = memchr(modhextab, tolower((int) modhex[(i << 1) + 1]), 16)))
			return -1;

		hex[i] = hextab[c1 - modhextab];
		hex[i + 1] = hextab[c2 - modhextab];
	}

	return i;
}

/** Xlat to convert Yubikey modhex to standard hex
 *
 * Example:
@verbatim
"%{modhextohex:vvrbuctetdhc}" == "ffc1e0d3d260"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static ssize_t modhex_to_hex_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			  	  UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			  	  request_t *request, char const *fmt)
{
	ssize_t len;

	if (outlen < strlen(fmt)) return 0;

	/*
	 *	mod2hex allows conversions in place
	 */
	len = modhex2hex(fmt, (uint8_t *) *out, strlen(fmt));
	if (len <= 0) {
		REDEBUG("Modhex string invalid");
		return -1;
	}

	return len;
}


static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_yubikey_t *inst = instance;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

#ifndef HAVE_YUBIKEY
	if (inst->decrypt) {
		cf_log_err(conf, "Requires libyubikey for OTP decryption");
		return -1;
	}
#endif

	if (!cf_section_name2(conf)) return 0;

	xlat_register_legacy(inst, "modhextohex", modhex_to_hex_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN);

	return 0;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_yubikey_t *inst = instance;

	inst->auth_type = fr_dict_enum_by_name(attr_auth_type, inst->name, -1);
	if (!inst->auth_type) {
		WARN("Failed to find 'authenticate %s {...}' section.  Yubikey authentication will likely not work",
		     inst->name);
	}

	if (inst->validate) {
#ifdef HAVE_YKCLIENT
		CONF_SECTION *cs;

		cs = cf_section_find(conf, "validation", CF_IDENT_ANY);
		if (!cs) {
			cf_log_err(conf, "Missing validation section");
			return -1;
		}

		if (rlm_yubikey_ykclient_init(cs, inst) < 0) {
			return -1;
		}
#else
		cf_log_err(conf, "Requires libykclient for OTP validation against Yubicloud servers");
		return -1;
#endif
	}

	return 0;
}

#ifdef HAVE_YKCLIENT
static int mod_detach(void *instance)
{
	rlm_yubikey_ykclient_detach((rlm_yubikey_t *) instance);
	return 0;
}
#endif

static int CC_HINT(nonnull) otp_string_valid(rlm_yubikey_t const *inst, char const *otp, size_t len)
{
	size_t i;

	for (i = inst->id_len; i < len; i++) {
		if (!is_modhex(otp[i])) return -i;
	}

	return 1;
}


/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_yubikey_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_yubikey_t);
	char const		*passcode;
	size_t			len;
	fr_pair_t		*vp, *password;
	char const		*otp;
	size_t			password_len;
	int			ret;

	/*
	 *	Can't do yubikey auth if there's no password.
	 */
	password = fr_pair_find_by_da(&request->request_pairs, attr_user_password);
	if (!password) {
		/*
		 *	Don't print out debugging messages if we know
		 *	they're useless.
		 */
		if ((request->dict == dict_radius) && request->packet->code != FR_CODE_ACCESS_CHALLENGE) {
			RDEBUG2("No cleartext password in the request. Can't do Yubikey authentication");
		}

		RETURN_MODULE_NOOP;
	}

	passcode = password->vp_strvalue;
	len = password->vp_length;

	/*
	 *	Now see if the passcode is the correct length (in its raw
	 *	modhex encoded form).
	 *
	 *	<public_id (6-16 bytes)> + <aes-block (32 bytes)>
	 *
	 */
	if (len < (inst->id_len + YUBIKEY_TOKEN_LEN)) {
		RDEBUG2("User-Password value is not the correct length, expected at least %u bytes, got %zu bytes",
			inst->id_len + YUBIKEY_TOKEN_LEN, len);
		RETURN_MODULE_NOOP;
	}

	password_len = (len - (inst->id_len + YUBIKEY_TOKEN_LEN));
	otp = passcode + password_len;
	ret = otp_string_valid(inst, otp, (inst->id_len + YUBIKEY_TOKEN_LEN));
	if (ret <= 0) {
		if (RDEBUG_ENABLED3) {
			RDMARKER(otp, -(ret), "User-Password (aes-block) value contains non modhex chars");
		} else {
			RDEBUG2("User-Password (aes-block) value contains non modhex chars");
		}
		RETURN_MODULE_NOOP;
	}

	/* May be a concatenation, check the last 32 bytes are modhex */
	if (inst->split) {
		/*
		 *	Insert a new request attribute just containing the OTP
		 *	portion.
		 */
		MEM(pair_update_request(&vp, attr_yubikey_otp) >= 0);
		fr_pair_value_strdup(vp, otp);

		/*
		 *	Replace the existing string buffer for the password
		 *	attribute with one just containing the password portion.
		 */
		MEM(fr_pair_value_bstr_realloc(password, NULL, password_len) == 0);

		RINDENT();
		if (RDEBUG_ENABLED3) {
			RDEBUG3("&request.%pP", vp);
			RDEBUG3("&request.%pP", password);
		} else {
			RDEBUG2("&request.%s := <<< secret >>>", vp->da->name);
			RDEBUG2("&request.%s := <<< secret >>>", password->da->name);
		}
		REXDENT();

		/*
		 *	So the ID split code works on the non password portion.
		 */
		passcode = vp->vp_strvalue;
	}

	/*
	 *	Split out the Public ID in case another module in authorize
	 *	needs to verify it's associated with the user.
	 *
	 *	It's left up to the user if they want to decode it or not.
	 */
	if (inst->id_len) {
		MEM(pair_update_request(&vp, attr_yubikey_public_id) >= 0);
		fr_pair_value_bstrndup(vp, passcode, inst->id_len, true);
	}

	if (!inst->auth_type) {
		WARN("No 'authenticate %s {...}' section or 'Auth-Type = %s' set.  Cannot setup Yubikey authentication",
		     inst->name, inst->name);
		RETURN_MODULE_NOOP;
	}

	if (!module_section_type_set(request, attr_auth_type, inst->auth_type)) RETURN_MODULE_NOOP;

	RETURN_MODULE_OK;
}


/*
 *	Authenticate the user with the given password.
 */
static unlang_action_t CC_HINT(nonnull) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_yubikey_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_yubikey_t);
	rlm_rcode_t		rcode = RLM_MODULE_NOOP;
	char const		*passcode = NULL;
	fr_pair_t const	*vp;
	size_t			len;
	int			ret;

	vp = fr_pair_find_by_da(&request->request_pairs, attr_yubikey_otp);
	if (!vp) {
		RDEBUG2("No Yubikey-OTP attribute found, falling back to User-Password");
		/*
		 *	Can't do yubikey auth if there's no password.
		 */
		vp = fr_pair_find_by_da(&request->request_pairs, attr_user_password);
		if (!vp) {
			REDEBUG("No User-Password in the request. Can't do Yubikey authentication");
			RETURN_MODULE_INVALID;
		}
	}

	passcode = vp->vp_strvalue;
	len = vp->vp_length;

	/*
	 *	Verify the passcode is the correct length (in its raw
	 *	modhex encoded form).
	 *
	 *	<public_id (6-16 bytes)> + <aes-block (32 bytes)>
	 */
	if (len != (inst->id_len + YUBIKEY_TOKEN_LEN)) {
		REDEBUG("%s value is not the correct length, expected bytes %u, got bytes %zu",
			vp->da->name, inst->id_len + YUBIKEY_TOKEN_LEN, len);
		RETURN_MODULE_INVALID;
	}

	ret = otp_string_valid(inst, passcode, (inst->id_len + YUBIKEY_TOKEN_LEN));
	if (ret <= 0) {
		if (RDEBUG_ENABLED3) {
			REMARKER(passcode, -ret, "Passcode (aes-block) value contains non modhex chars");
		} else {
			RERROR("Passcode (aes-block) value contains non modhex chars");
		}
		RETURN_MODULE_INVALID;
	}

#ifdef HAVE_YUBIKEY
	if (inst->decrypt) {

		rlm_yubikey_decrypt(&rcode, inst, request, passcode);
		if (rcode != RLM_MODULE_OK) RETURN_MODULE_RCODE(rcode);
		/* Fall-Through to doing ykclient auth in addition to local auth */
	}
#endif

#ifdef HAVE_YKCLIENT
	if (inst->validate) return rlm_yubikey_validate(p_result, inst, request, passcode);
#endif
	RETURN_MODULE_RCODE(rcode);
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
extern module_t rlm_yubikey;
module_t rlm_yubikey = {
	.magic		= RLM_MODULE_INIT,
	.name		= "yubikey",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_yubikey_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
#ifdef HAVE_YKCLIENT
	.detach		= mod_detach,
#endif
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize
	},
};
