/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
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
#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <ctype.h>

#include <yubikey.h>

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_yubikey_t {
	const char 	*name;		//!< Instance name.
	int		auth_type;	//!< Our Auth-Type.
	unsigned int	id_len;		//!< The length of the Public ID
					//!< portion of the OTP string.
} rlm_yubikey_t;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
	{ "id_length", PW_TYPE_INTEGER, offsetof(rlm_yubikey_t, id_len), NULL, "12"},
	
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

static const char *modhextab = "cbdefghijklnrtuv";

#define is_modhex(x) (memchr(modhextab, tolower(x), 16))

/** Convert yubikey modhex data to binary
 *
 * This is a simpler version of the yubikey function which also does input
 * checking.
 *
 * @param[in] hex modhex data.
 * @param[out] bin where to write the decoded data.
 * @param[in] len The size of the output buffer.
 * @return The number of bytes written to the output buffer, or -1 on error.
 */
static size_t modhex2bin(const char *hex, uint8_t *bin, size_t len)
{
	size_t i;
	char *c1, *c2;

	for (i = 0; i < len; i++) {
		if (hex[i << 1] == '\0') {
			break;
		}
		
		/*
		 *	We only deal with whole bytes
		 */	
		if (hex[(i << 1) + 1] == '\0')
			return -1;
		
		if (!(c1 = memchr(modhextab, tolower((int) hex[i << 1]), 16)) ||
		    !(c2 = memchr(modhextab, tolower((int) hex[(i << 1) + 1]), 16)))
			return -1;
		 bin[i] = ((c1 - modhextab) <<4) + (c2 - modhextab);
	}

	return i;
}

/**
 * @brief Convert Yubikey modhex to standard hex
 *
 * Example: "%{modhextohex:vvrbuctetdhc}" == "ffc1e0d3d260"
 */
static size_t modhex_to_hex_xlat(UNUSED void *instance, REQUEST *request, const char *fmt, char *out, size_t outlen)
{	
	char buffer[1024];
	uint8_t decbuf[1024], *p;
	
	ssize_t declen;
	size_t freespace = outlen;
	size_t len;

	len = radius_xlat(buffer, sizeof(buffer), fmt, request, NULL, NULL);
	if (!len) {
		RDEBUGE("expansion of format string failed.");
		*out = '\0';
		return 0;
	}
	
	declen = modhex2bin(buffer, decbuf, sizeof(decbuf));
	if (declen < 0) {
		RDEBUGE("modhex string invalid");
		*out = '\0';
		return 0;
	}
	
	p = decbuf;
	while ((declen-- > 0) && (--freespace > 0)) {
		if (freespace < 3) {
			break;
		}
		
		snprintf(out, 3, "%02x", *p++);
		
		/* Already decremented */
		freespace -= 1;
		out += 2;
	}

	return outlen - freespace;
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
	DICT_VALUE *dval;

	inst->name = cf_section_name2(conf);
	if (!inst->name) {
		inst->name = cf_section_name1(conf);
	}

	dval = dict_valbyname(PW_AUTH_TYPE, 0, inst->name);
	if (dval) {
		inst->auth_type = dval->value;
	} else {
		inst->auth_type = 0;
	}
	
	if (YUBIKEY_UID_SIZE > MAX_STRING_LEN) {
		DEBUGE("rlm_yubikey: YUBIKEY_UID_SIZE too big");
		return -1;
	}
	
	xlat_register("modhextohex", modhex_to_hex_xlat, inst);

	return 0;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t mod_authorize(void *instance, REQUEST *request)
{
	rlm_yubikey_t *inst = instance;
	
	char *passcode;
	size_t i, len;
	VALUE_PAIR *vp;
	
	/*
	 *	Can't do yubikey auth if there's no password.
	 */
	if (!request->password || (request->password->da->attr != PW_USER_PASSWORD)) {
		/*
		 *	Don't print out debugging messages if we know
		 *	they're useless.
		 */
		if (request->packet->code == PW_ACCESS_CHALLENGE) {
			return RLM_MODULE_NOOP;
		}

		RDEBUG2("No Clear-Text password in the request. Can't do Yubikey authentication.");
			
		return RLM_MODULE_NOOP;
	}

	passcode = request->password->vp_strvalue;
	len = request->password->length;
	/*
	 *	Now see if the passcode is the correct length (in its raw
	 *	modhex encoded form).
	 *
	 *	<public_id (6-16 bytes)> + <aes-block (32 bytes)>
	 *	
	 */
	if (len != (inst->id_len + 32)) {
		RDEBUG2("User-Password value is not the correct length, expected %u, got %zu", inst->id_len + 32, len);
		return RLM_MODULE_NOOP;	
	}

	for (i = inst->id_len; i < len; i++) {
		if (!is_modhex(*passcode)) {
			RDEBUG2("User-Password (aes-block) value contains non modhex chars");
			
			return RLM_MODULE_NOOP;	
		}
	}
	
	if (inst->auth_type) {
		vp = radius_paircreate(request, &request->config_items, PW_AUTH_TYPE, 0);
		vp->vp_integer = inst->auth_type;
	}
	
	/*
	 *	Split out the Public ID in case another module in authorize
	 *	needs to verify it's associated with the user.
	 *
	 *	It's left up to the user if they want to decode it or not.
	 */
	if (inst->id_len) {
		vp = pairmake(request, &request->packet->vps, "Yubikey-Public-ID", NULL, T_OP_SET);
		
		strlcpy(vp->vp_strvalue, passcode, inst->id_len + 1);
		
		vp->length = inst->id_len;
	}

	return RLM_MODULE_OK;
}

/*
 *	Authenticate the user with the given password.
 */
static rlm_rcode_t mod_authenticate(void *instance, REQUEST *request)
{
	rlm_yubikey_t *inst = instance;
	
	char *passcode;
	size_t i, len;
	uint32_t counter;

	const DICT_ATTR *da;	
	VALUE_PAIR *key, *vp;
	yubikey_token_st token;
	
	char private_id[(YUBIKEY_UID_SIZE * 2) + 1];
	
	/*
	 *	Can't do yubikey auth if there's no password.
	 */
	if (!request->password || (request->password->da->attr != PW_USER_PASSWORD)) {
		RDEBUGE("No Clear-Text password in the request. Can't do Yubikey authentication.");
		return RLM_MODULE_FAIL;
	}
	
	passcode = request->password->vp_strvalue;
	len = request->password->length;
	/*
	 *	Verify the passcode is the correct length (in its raw
	 *	modhex encoded form).
	 *
	 *	<public_id (6-16 bytes)> + <aes-block (32 bytes)>
	 */
	if (len != (inst->id_len + 32)) {
		RDEBUGE("User-Password value is not the correct length, expected %u, got %zu", inst->id_len + 32, len);
		return RLM_MODULE_FAIL;	
	}

	for (i = inst->id_len; i < len; i++) {
		if (!is_modhex(*passcode)) {
			RDEBUG2("User-Password (aes-block) value contains non modhex chars");
			return RLM_MODULE_FAIL;	
		}
	}
	
	da = dict_attrbyname("Yubikey-Key");
	key = pairfind(request->config_items, da->attr, da->vendor, TAG_ANY);
	if (!key) {
		RDEBUGE("Yubikey-Key attribute not found in control list, can't decrypt OTP data");
		return RLM_MODULE_FAIL;
	}

	if (key->length != YUBIKEY_KEY_SIZE) {
		RDEBUGE("Yubikey-Key length incorrect, expected %u got %zu", YUBIKEY_KEY_SIZE, key->length);
		return RLM_MODULE_FAIL;	
	}
	
	yubikey_parse(request->password->vp_octets + inst->id_len,
		      key->vp_octets, &token);

	/*
	 *	Apparently this just uses byte offsets...
	 */
	if (!yubikey_crc_ok_p((uint8_t *) &token)) {
		RDEBUGE("Decrypting OTP token data failed, rejecting");	
		return RLM_MODULE_REJECT;
	}
	
	RDEBUG("Token data decrypted successfully");
	
	if (request->options && request->radlog) {
		(void) fr_bin2hex((uint8_t*) &token.uid,
				  (char *) &private_id, YUBIKEY_UID_SIZE);
		RDEBUG2("Private ID	: 0x%s", private_id);
		RDEBUG2("Session counter   : %u", yubikey_counter(token.ctr));
		RDEBUG2("# used in session : %u", token.use);
		RDEBUG2("Token timetamp    : %u",
			(token.tstph << 16) | token.tstpl);
		RDEBUG2("Random data       : %u", token.rnd);
		RDEBUG2("CRC data          : 0x%x", token.crc);
	}

	/*
	 *	Private ID used for validation purposes
	 */
	vp = pairmake(request, &request->packet->vps, "Yubikey-Private-ID", NULL, T_OP_SET);	
	memcpy(vp->vp_octets, token.uid, YUBIKEY_UID_SIZE);
	vp->length = YUBIKEY_UID_SIZE;
	
	/*
	 *	Token timestamp
	 */
	vp = pairmake(request, &request->packet->vps, "Yubikey-Timestamp", NULL, T_OP_SET);
	vp->vp_integer = (token.tstph << 16) | token.tstpl;
	vp->length = 4;
	
	/*
	 *	Token random
	 */
	vp = pairmake(request, &request->packet->vps, "Yubikey-Random", NULL, T_OP_SET);
	vp->vp_integer = token.rnd;
	vp->length = 4;
	
	/*
	 *	Combine the two counter fields together so we can do
	 *	replay attack checks.
	 */
	counter = (yubikey_counter(token.ctr) << 16) | token.use;
	
	vp = pairmake(request, &request->packet->vps, "Yubikey-Counter", NULL, T_OP_SET);
	vp->vp_integer = counter;
	vp->length = 4;
	
	/*
	 *	Now we check for replay attacks
	 */
	vp = pairfind(request->config_items, vp->da->attr, vp->da->vendor, TAG_ANY);
	if (!vp) {
		RDEBUGW("Yubikey-Counter not found in control list, skipping replay attack checks");
		return RLM_MODULE_OK;
	}

	if (counter <= vp->vp_integer) {
		RDEBUGE("Replay attack detected! Counter value %u, is lt or eq to last known counter value %u",
			counter, vp->vp_integer);
		return RLM_MODULE_REJECT;	
	}

	return RLM_MODULE_OK;
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
module_t rlm_yubikey = {
	RLM_MODULE_INIT,
	"yubikey",
	RLM_TYPE_THREAD_SAFE,		/* type */
	sizeof(rlm_yubikey_t),
	module_config,
	mod_instantiate,		/* instantiation */
	NULL,				/* detach */
	{
		mod_authenticate,	/* authentication */
		mod_authorize,		/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
