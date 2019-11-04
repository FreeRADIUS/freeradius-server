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
 * @file rlm_example.c
 * @brief Example module code.
 *
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 your name (your name\@address)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/rad_assert.h>

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct {
	bool		boolean;
	uint32_t	value;
	char const	*string;
	fr_ipaddr_t	ipaddr;
} rlm_example_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("integer", FR_TYPE_UINT32, rlm_example_t, value), .dflt = "1" },
	{ FR_CONF_OFFSET("boolean", FR_TYPE_BOOL, rlm_example_t, boolean), .dflt = "no" },
	{ FR_CONF_OFFSET("string", FR_TYPE_STRING, rlm_example_t, string) },
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_IPV4_ADDR, rlm_example_t, ipaddr), .dflt = "*" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t *dict_radius;

extern fr_dict_autoload_t rlm_example_dict[];
fr_dict_autoload_t rlm_example_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_reply_message;
static fr_dict_attr_t const *attr_state;

extern fr_dict_attr_autoload_t rlm_example_dict_attr[];
fr_dict_attr_autoload_t rlm_example_dict_attr[] = {
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_reply_message, .name = "Reply-Message", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },

	{ NULL }
};

static int rlm_example_cmp(UNUSED void *instance, REQUEST *request, UNUSED VALUE_PAIR *thing, VALUE_PAIR *check,
			   UNUSED VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
{
	rad_assert(check->vp_type == FR_TYPE_STRING);

	RINFO("Example-Paircmp called with \"%pV\"", &check->data);

	if (strcmp(check->vp_strvalue, "yes") == 0) return 0;
	return 1;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_example_t	*inst = instance;

	/*
	 *	Do more work here
	 */
	if (!inst->boolean) {
		cf_log_err(conf, "Boolean is false: forcing error!");
		return -1;
	}

	if (paircmp_register_by_name("Example-Paircmp", attr_user_name, false, rlm_example_cmp, inst) < 0) {
		return -1;
	}

	return 0;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(UNUSED void *instance, UNUSED void *thread, REQUEST *request)
{
	VALUE_PAIR *vp;

	/*
	 *  Look for the 'state' attribute.
	 */
	vp = fr_pair_find_by_da(request->packet->vps, attr_state, TAG_ANY);
	if (vp != NULL) {
		RDEBUG2("Found reply to access challenge");
		return RLM_MODULE_OK;
	}

	MEM(pair_update_reply(&vp, attr_reply_message) >= 0);
	if (vp->vp_length == 0) fr_pair_value_strcpy(vp, "This is a challenge");

	MEM(pair_add_reply(&vp, attr_state) >= 0);
	fr_pair_value_memcpy(vp, (uint8_t *){ 0x00 }, 1, true);

	/*
	 *  Mark the packet as an Access-Challenge packet.
	 *
	 *  The server will take care of sending it to the user.
	 */
	request->reply->code = FR_CODE_ACCESS_CHALLENGE;
	RDEBUG2("Sending Access-Challenge");

	return RLM_MODULE_HANDLED;
}

/*
 *	Authenticate the user with the given password.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(UNUSED void *instance, UNUSED void *thread, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

#ifdef WITH_ACCOUNTING
/*
 *	Massage the request before recording it or proxying it
 */
static rlm_rcode_t CC_HINT(nonnull) mod_preacct(UNUSED void *instance, UNUSED void *thread, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(UNUSED void *instance, UNUSED void *thread, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}
#endif


/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int mod_detach(UNUSED void *instance)
{
	/* free things here */
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
extern module_t rlm_example;
module_t rlm_example = {
	.magic		= RLM_MODULE_INIT,
	.name		= "example",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_example_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
#ifdef WITH_ACCOUNTING
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
#endif
	},
};
