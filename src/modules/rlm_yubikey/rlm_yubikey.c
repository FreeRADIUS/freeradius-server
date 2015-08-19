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
 * @author Arran Cudbard-Bell <a.cudbardb@networkradius.com>
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 Network RADIUS <info@networkradius.com>
 */
RCSID("$Id$")

#include "rlm_yubikey.h"

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */

#ifdef HAVE_YKCLIENT
static const CONF_PARSER validation_config[] = {
	{ "client_id", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_yubikey_t, client_id), 0 },
	{ "api_key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, rlm_yubikey_t, api_key), NULL },
	CONF_PARSER_TERMINATOR
};
#endif

static const CONF_PARSER module_config[] = {
	{ "id_length", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_yubikey_t, id_len), "12" },
	{ "split", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_yubikey_t, split), "yes" },
	{ "decrypt", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_yubikey_t, decrypt), "no" },
	{ "validate", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_yubikey_t, validate), "no" },
#ifdef HAVE_YKCLIENT
	{ "validation", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) validation_config },
#endif
	CONF_PARSER_TERMINATOR
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
 * @return The number of bytes written to the output buffer, or -1 on error.
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

/**
 * @brief Convert Yubikey modhex to standard hex
 *
 * Example: "%{modhextohex:vvrbuctetdhc}" == "ffc1e0d3d260"
 */
static ssize_t modhex_to_hex_xlat(UNUSED void *instance, REQUEST *request, char const *fmt, char *out, size_t outlen)
{
	ssize_t len;

	if (outlen < strlen(fmt)) {
		*out = '\0';
		return 0;
	}

	/*
	 *	mod2hex allows conversions in place
	 */
	len = modhex2hex(fmt, (uint8_t *) out, strlen(fmt));
	if (len <= 0) {
		*out = '\0';
		REDEBUG("Modhex string invalid");

		return -1;
	}

	return len;
}


static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_yubikey_t *inst = instance;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

#ifndef HAVE_YUBIKEY
	if (inst->decrypt) {
		cf_log_err_cs(conf, "Requires libyubikey for OTP decryption");
		return -1;
	}
#endif

	if (!cf_section_name2(conf)) return 0;

	xlat_register("modhextohex", modhex_to_hex_xlat, NULL, inst);

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
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_yubikey_t *inst = instance;

	if (inst->validate) {
#ifdef HAVE_YKCLIENT
		CONF_SECTION *cs;

		cs = cf_section_sub_find(conf, "validation");
		if (!cs) {
			cf_log_err_cs(conf, "Missing validation section");
			return -1;
		}

		if (rlm_yubikey_ykclient_init(cs, inst) < 0) {
			return -1;
		}
#else
		cf_log_err_cs(conf, "Requires libykclient for OTP validation against Yubicloud servers");
		return -1;
#endif
	}

	return 0;
}

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
#ifdef HAVE_YKCLIENT
static int mod_detach(void *instance)
{
	rlm_yubikey_ykclient_detach((rlm_yubikey_t *) instance);
	return 0;
}
#endif

static int CC_HINT(nonnull) otp_string_valid(rlm_yubikey_t *inst, char const *otp, size_t len)
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
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
{
	rlm_yubikey_t *inst = instance;

	DICT_VALUE *dval;
	char const *passcode;
	size_t len;
	VALUE_PAIR *vp;

	/*
	 *	Can't do yubikey auth if there's no password.
	 */
	if (!request->password || (request->password->da->attr != PW_USER_PASSWORD)) {
		/*
		 *	Don't print out debugging messages if we know
		 *	they're useless.
		 */
		if (request->packet->code == PW_CODE_ACCESS_CHALLENGE) {
			return RLM_MODULE_NOOP;
		}

		RDEBUG2("No cleartext password in the request. Can't do Yubikey authentication");

		return RLM_MODULE_NOOP;
	}

	passcode = request->password->vp_strvalue;
	len = request->password->vp_length;

	/*
	 *	Now see if the passcode is the correct length (in its raw
	 *	modhex encoded form).
	 *
	 *	<public_id (6-16 bytes)> + <aes-block (32 bytes)>
	 *
	 */
	if (len > (inst->id_len + YUBIKEY_TOKEN_LEN)) {
		/* May be a concatenation, check the last 32 bytes are modhex */
		if (inst->split) {
			char const *otp;
			char *password;
			size_t password_len;
			int ret;

			password_len = (len - (inst->id_len + YUBIKEY_TOKEN_LEN));
			otp = passcode + password_len;
			ret = otp_string_valid(inst, otp, (inst->id_len + YUBIKEY_TOKEN_LEN));
			if (ret <= 0) {
				if (RDEBUG_ENABLED3) {
					RDMARKER(otp, -ret, "User-Password (aes-block) value contains non modhex chars");
				} else {
					RDEBUG("User-Password (aes-block) value contains non modhex chars");
				}
				return RLM_MODULE_NOOP;
			}

			/*
			 *	Insert a new request attribute just containing the OTP
			 *	portion.
			 */
			vp = pair_make_request("Yubikey-OTP", otp, T_OP_SET);
			if (!vp) {
				REDEBUG("Failed creating 'Yubikey-OTP' attribute");
				return RLM_MODULE_FAIL;
			}

			/*
			 *	Replace the existing string buffer for the password
			 *	attribute with one just containing the password portion.
			 */
			MEM(password = talloc_array(request->password, char, password_len + 1));
			strlcpy(password, passcode, password_len + 1);
			fr_pair_value_strsteal(request->password, password);

			RINDENT();
			if (RDEBUG_ENABLED3) {
				RDEBUG3("&request:Yubikey-OTP := '%s'", vp->vp_strvalue);
				RDEBUG3("&request:User-Password := '%s'", request->password->vp_strvalue);
			} else {
				RDEBUG2("&request:Yubikey-OTP := <<< secret >>>");
				RDEBUG2("&request:User-Password := <<< secret >>>");
			}
			REXDENT();
			/*
			 *	So the ID split code works on the non password portion.
			 */
			passcode = vp->vp_strvalue;
		}
	} else if (len < (inst->id_len + YUBIKEY_TOKEN_LEN)) {
		RDEBUG2("User-Password value is not the correct length, expected at least %u bytes, got %zu bytes",
			inst->id_len + YUBIKEY_TOKEN_LEN, len);
		return RLM_MODULE_NOOP;
	} else {
		int ret;

		ret = otp_string_valid(inst, passcode, (inst->id_len + YUBIKEY_TOKEN_LEN));
		if (ret <= 0) {
			if (RDEBUG_ENABLED3) {
				RDMARKER(passcode, -ret, "User-Password (aes-block) value contains non modhex chars");
			} else {
				RDEBUG("User-Password (aes-block) value contains non modhex chars");
			}
			return RLM_MODULE_NOOP;
		}
	}

	dval = dict_valbyname(PW_AUTH_TYPE, 0, inst->name);
	if (dval) {
		vp = radius_pair_create(request, &request->config, PW_AUTH_TYPE, 0);
		vp->vp_integer = dval->value;
	}

	/*
	 *	Split out the Public ID in case another module in authorize
	 *	needs to verify it's associated with the user.
	 *
	 *	It's left up to the user if they want to decode it or not.
	 */
	if (inst->id_len) {
		vp = fr_pair_make(request, &request->packet->vps, "Yubikey-Public-ID", NULL, T_OP_SET);
		if (!vp) {
			REDEBUG("Failed creating Yubikey-Public-ID");

			return RLM_MODULE_FAIL;
		}

		fr_pair_value_bstrncpy(vp, passcode, inst->id_len);
	}

	return RLM_MODULE_OK;
}


/*
 *	Authenticate the user with the given password.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
	rlm_rcode_t rcode = RLM_MODULE_NOOP;
	rlm_yubikey_t *inst = instance;
	char const *passcode = NULL;
	DICT_ATTR const *da;
	VALUE_PAIR const *vp;
	size_t len;
	int ret;

	da = dict_attrbyname("Yubikey-OTP");
	if (!da) {
		RDEBUG2("No Yubikey-OTP attribute defined, falling back to User-Password");
		goto user_password;
	}

	vp = fr_pair_find_by_da(request->packet->vps, da, TAG_ANY);
	if (vp) {
		passcode = vp->vp_strvalue;
		len = vp->vp_length;
	} else {
		RDEBUG2("No Yubikey-OTP attribute found, falling back to User-Password");
	user_password:
		/*
		 *	Can't do yubikey auth if there's no password.
		 */
		if (!request->password || (request->password->da->attr != PW_USER_PASSWORD)) {
			REDEBUG("No User-Password in the request. Can't do Yubikey authentication");
			return RLM_MODULE_INVALID;
		}

		vp = request->password;
		passcode = request->password->vp_strvalue;
		len = request->password->vp_length;
	}

	/*
	 *	Verify the passcode is the correct length (in its raw
	 *	modhex encoded form).
	 *
	 *	<public_id (6-16 bytes)> + <aes-block (32 bytes)>
	 */
	if (len != (inst->id_len + YUBIKEY_TOKEN_LEN)) {
		REDEBUG("%s value is not the correct length, expected bytes %u, got bytes %zu",
			vp->da->name, inst->id_len + YUBIKEY_TOKEN_LEN, len);
		return RLM_MODULE_INVALID;
	}

	ret = otp_string_valid(inst, passcode, (inst->id_len + YUBIKEY_TOKEN_LEN));
	if (ret <= 0) {
		if (RDEBUG_ENABLED3) {
			REMARKER(passcode, -ret, "Passcode (aes-block) value contains non modhex chars");
		} else {
			RERROR("Passcode (aes-block) value contains non modhex chars");
		}
		return RLM_MODULE_INVALID;
	}

#ifdef HAVE_YUBIKEY
	if (inst->decrypt) {
		rcode = rlm_yubikey_decrypt(inst, request, passcode);
		if (rcode != RLM_MODULE_OK) {
			return rcode;
		}
		/* Fall-Through to doing ykclient auth in addition to local auth */
	}
#endif

#ifdef HAVE_YKCLIENT
	if (inst->validate) {
		return rlm_yubikey_validate(inst, request, passcode);
	}
#endif
	return rcode;
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
