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
 * @file rlm_chap.c
 * @brief Process chap authentication requests.
 *
 * @copyright 2001,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/password.h>
#include <freeradius-devel/server/module.h>

typedef struct {
	char const		*name;		//!< Auth-Type value for this module instance.
	bool			normify;
	fr_dict_enum_t		*auth_type;
} rlm_chap_t;

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_radius;

extern fr_dict_autoload_t rlm_chap_dict[];
fr_dict_autoload_t rlm_chap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_cleartext_password;
static fr_dict_attr_t const *attr_password_with_header;

static fr_dict_attr_t const *attr_chap_password;
static fr_dict_attr_t const *attr_chap_challenge;
static fr_dict_attr_t const *attr_user_name;

extern fr_dict_attr_autoload_t rlm_chap_dict_attr[];
fr_dict_attr_autoload_t rlm_chap_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_cleartext_password, .name = "Cleartext-Password", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_password_with_header, .name = "Password-With-Header", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_chap_password, .name = "Chap-Password", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_chap_challenge, .name = "Chap-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("normalise", FR_TYPE_BOOL, rlm_chap_t, normify), .dflt = "yes" },
	CONF_PARSER_TERMINATOR
};

static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_chap_t	*inst = instance;
	VALUE_PAIR	*vp;

	if (fr_pair_find_by_da(request->control, attr_auth_type, TAG_ANY) != NULL) {
		RDEBUG3("Auth-Type is already set.  Not setting 'Auth-Type := %s'", inst->name);
		return RLM_MODULE_NOOP;
	}

	/*
	 *	This case means the warnings below won't be printed
	 *	unless there's a CHAP-Password in the request.
	 */
	if (!fr_pair_find_by_da(request->packet->vps, attr_chap_password, TAG_ANY)) return RLM_MODULE_NOOP;

	/*
	 *	Create the CHAP-Challenge if it wasn't already in the packet.
	 *
	 *	This is so that the rest of the code does not need to
	 *	understand CHAP.
	 */
	vp = fr_pair_find_by_da(request->packet->vps, attr_chap_challenge, TAG_ANY);
	if (!vp) {
		RDEBUG2("Creating &%s from request authenticator", attr_chap_challenge->name);

		MEM(vp = fr_pair_afrom_da(request->packet, attr_chap_challenge));
		fr_pair_value_memcpy(vp, request->packet->vector, sizeof(request->packet->vector), true);
		fr_pair_add(&request->packet->vps, vp);
	}

	if (!module_section_type_set(request, attr_auth_type, inst->auth_type)) return RLM_MODULE_NOOP;

	return RLM_MODULE_OK;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_chap_t		*inst = instance;
	VALUE_PAIR const	*known_good;
	VALUE_PAIR		*chap, *username;
	uint8_t			pass_str[FR_MAX_STRING_LEN];
	TALLOC_CTX		*tmp_ctx;
	fr_dict_attr_t const	*allowed_passwords[] = { attr_password_with_header, attr_cleartext_password };

	username = fr_pair_find_by_da(request->packet->vps, attr_user_name, TAG_ANY);
	if (!username) {
		REDEBUG("&User-Name attribute is required for authentication");
		return RLM_MODULE_INVALID;
	}

	chap = fr_pair_find_by_da(request->packet->vps, attr_chap_password, TAG_ANY);
	if (!chap) {
		REDEBUG("You set '&control:Auth-Type = CHAP' for a request that "
			"does not contain a CHAP-Password attribute!");
		return RLM_MODULE_INVALID;
	}

	if (chap->vp_length == 0) {
		REDEBUG("&request:CHAP-Password is empty");
		return RLM_MODULE_INVALID;
	}

	if (chap->vp_length != RADIUS_CHAP_CHALLENGE_LENGTH + 1) {
		REDEBUG("&request:CHAP-Password has invalid length");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Holds any ephemeral attributes
	 */
	MEM(tmp_ctx = talloc_named_const(request, 0, "password_tmp_ctx"));

	/*
	 *	Retrieve the normalised version of
	 *	the known_good password, without
	 *	mangling the current password attributes
	 *	in the request.
	 */
	known_good = password_find(tmp_ctx, request,
				   allowed_passwords, NUM_ELEMENTS(allowed_passwords),
				   inst->normify);
	if (!known_good) {
		REDEBUG("No \"known good\" password found for user");
		talloc_free(tmp_ctx);
		return RLM_MODULE_FAIL;
	}
	fr_radius_encode_chap_password(pass_str, request->packet, chap->vp_octets[0], known_good);

	if (RDEBUG_ENABLED3) {
		uint8_t	const	*p;
		size_t		length;
		VALUE_PAIR	*vp;

		RDEBUG3("Comparing with \"known good\" &control:%pP", known_good);

		vp = fr_pair_find_by_da(request->packet->vps, attr_chap_challenge, TAG_ANY);
		if (vp) {
			RDEBUG2("Using challenge from &request:CHAP-Challenge");
			p = vp->vp_octets;
			length = vp->vp_length;
		} else {
			RDEBUG2("Using challenge from authenticator field");
			p = request->packet->vector;
			length = sizeof(request->packet->vector);
		}

		RINDENT();
		RDEBUG3("CHAP challenge : %pH", fr_box_octets(p, length));
		RDEBUG3("Client sent    : %pH", fr_box_octets(chap->vp_octets + 1, RADIUS_CHAP_CHALLENGE_LENGTH));
		RDEBUG3("We calculated  : %pH", fr_box_octets(pass_str + 1, RADIUS_CHAP_CHALLENGE_LENGTH));
		REXDENT();
	} else {
		RDEBUG2("Comparing with \"known good\" Cleartext-Password");
	}

	if (fr_digest_cmp(pass_str + 1, chap->vp_octets + 1, RADIUS_CHAP_CHALLENGE_LENGTH) != 0) {
		REDEBUG("Password comparison failed: password is incorrect");
		talloc_free(tmp_ctx);
		return RLM_MODULE_REJECT;
	}

	RDEBUG2("CHAP user \"%pV\" authenticated successfully", &username->data);

	talloc_free(tmp_ctx);

	return RLM_MODULE_OK;
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_chap_t	*inst = instance;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	if (fr_dict_enum_add_alias_next(attr_auth_type, inst->name) < 0) {
		PERROR("Failed adding %s alias", attr_auth_type->name);
		return -1;
	}
	inst->auth_type = fr_dict_enum_by_alias(attr_auth_type, inst->name, -1);
	rad_assert(inst->auth_type);

	return 0;
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
extern module_t rlm_chap;
module_t rlm_chap = {
	.magic		= RLM_MODULE_INIT,
	.name		= "chap",
	.inst_size	= sizeof(rlm_chap_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.dict		= &dict_radius,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
	},
};
