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
 * @copyright 2001,2006  The FreeRADIUS server project
 * @copyright 2001  Kostas Kalevras <kkalev@noc.ntua.gr>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

typedef struct {
	char const		*name;		//!< Auth-Type value for this module instance.
	fr_dict_enum_t		*auth_type;
} rlm_chap_t;

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_cleartext_password;

static fr_dict_attr_t const *attr_chap_password;
static fr_dict_attr_t const *attr_chap_challenge;
static fr_dict_attr_t const *attr_user_password;

extern fr_dict_attr_autoload_t rlm_chap_dict_attr[];
fr_dict_attr_autoload_t rlm_chap_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_cleartext_password, .name = "Cleartext-Password", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_chap_password, .name = "Chap-Password", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_chap_challenge, .name = "Chap-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};

extern fr_dict_autoload_t rlm_chap_dict[];
fr_dict_autoload_t rlm_chap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_chap_t	*inst = instance;
	VALUE_PAIR	*vp;

	if (!fr_pair_find_by_da(request->packet->vps, attr_chap_password, TAG_ANY)) return RLM_MODULE_NOOP;

	/*
	 *	Create the CHAP-Challenge if it wasn't already in the packet.
	 *
	 *	This is so that the rest of the code does not need to
	 *	understand CHAP.
	 */

	vp = fr_pair_find_by_da(request->packet->vps, attr_chap_challenge, TAG_ANY);
	if (!vp) {
		RDEBUG("creating CHAP-Challenge from the request authenticator");

		MEM(vp = fr_pair_afrom_da(request->packet, attr_chap_challenge));
		fr_pair_value_memcpy(vp, request->packet->vector, sizeof(request->packet->vector));
		fr_pair_add(&request->packet->vps, vp);
	}

	if (fr_pair_find_by_da(request->control, attr_auth_type, TAG_ANY) != NULL) {
		RWDEBUG2("&control:%s already set.  Not setting to %pV", attr_auth_type->name, inst->auth_type->alias);
		return RLM_MODULE_NOOP;
	}

	RDEBUG("&control:%s = %s", attr_auth_type->name, inst->auth_type->alias);

	MEM(vp = pair_update_control(attr_auth_type, TAG_ANY));
	fr_value_box_copy(vp, &vp->data, inst->auth_type->value);
	vp->data.enumv = vp->da;

	return RLM_MODULE_OK;
}


/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(UNUSED void *instance, UNUSED void *thread, REQUEST *request)
{
	VALUE_PAIR *password, *chap;
	uint8_t pass_str[FR_MAX_STRING_LEN];

	if (!request->username) {
		REDEBUG("&request:User-Name attribute is required for authentication");
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

	if (chap->vp_length != CHAP_VALUE_LENGTH + 1) {
		REDEBUG("&request:CHAP-Password has invalid length");
		return RLM_MODULE_INVALID;
	}

	password = fr_pair_find_by_da(request->control, attr_cleartext_password, TAG_ANY);
	if (password == NULL) {
		if (fr_pair_find_by_da(request->control, attr_user_password, TAG_ANY) != NULL){
			REDEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			REDEBUG("!!! Please update your configuration so that the \"known !!!");
			REDEBUG("!!! good\" cleartext password is in Cleartext-Password,  !!!");
			REDEBUG("!!! and NOT in User-Password.                            !!!");
			REDEBUG("!!!						          !!!");
			REDEBUG("!!! Authentication will fail because of this.	          !!!");
			REDEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		}

		REDEBUG("&control:Cleartext-Password is required for authentication");
		return RLM_MODULE_FAIL;
	}

	fr_radius_encode_chap_password(pass_str, request->packet, chap->vp_octets[0], password);

	if (RDEBUG_ENABLED3) {
		uint8_t const *p;
		size_t length;
		VALUE_PAIR *vp;
		char buffer[CHAP_VALUE_LENGTH * 2 + 1];

		RDEBUG3("Comparing with \"known good\" &control:Cleartext-Password value \"%s\"",
			password->vp_strvalue);

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

		fr_bin2hex(buffer, p, length);
		RINDENT();
		RDEBUG3("CHAP challenge : %s", buffer);

		fr_bin2hex(buffer, chap->vp_octets + 1, CHAP_VALUE_LENGTH);
		RDEBUG3("Client sent    : %s", buffer);

		fr_bin2hex(buffer, pass_str + 1, CHAP_VALUE_LENGTH);
		RDEBUG3("We calculated  : %s", buffer);
		REXDENT();
	} else {
		RDEBUG2("Comparing with \"known good\" Cleartext-Password");
	}

	if (fr_digest_cmp(pass_str + 1, chap->vp_octets + 1, CHAP_VALUE_LENGTH) != 0) {
		REDEBUG("Password comparison failed: password is incorrect");
		return RLM_MODULE_REJECT;
	}

	RDEBUG("CHAP user \"%s\" authenticated successfully", request->username->vp_strvalue);

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
	inst->auth_type = fr_dict_enum_by_alias(attr_auth_type, inst->name);
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
extern rad_module_t rlm_chap;
rad_module_t rlm_chap = {
	.magic		= RLM_MODULE_INIT,
	.name		= "chap",
	.inst_size	= sizeof(rlm_chap_t),
	.bootstrap	= mod_bootstrap,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
	},
};
