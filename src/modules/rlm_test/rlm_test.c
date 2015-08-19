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
 * @file rlm_test.c
 * @brief test module code.
 *
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 your name \<your address\>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_test_t {
	bool		boolean;
	uint32_t	value;
	char const	*string;
	fr_ipaddr_t	ipaddr;
} rlm_test_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ "integer", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_test_t, value), "1" },
	{ "boolean", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_test_t, boolean), "no" },
	{ "string", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_test_t, string), NULL },
	{ "ipaddr", FR_CONF_OFFSET(PW_TYPE_IPV4_ADDR, rlm_test_t, ipaddr), "*" },
	CONF_PARSER_TERMINATOR
};

static int rlm_test_cmp(UNUSED void *instance, REQUEST *request, UNUSED VALUE_PAIR *thing, VALUE_PAIR *check,
			UNUSED VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
{
	rad_assert(check->da->type == PW_TYPE_STRING);

	RINFO("test-Paircmp called with \"%s\"", check->vp_strvalue);

	if (strcmp(check->vp_strvalue, "yes") == 0) return 0;
	return 1;
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
static int mod_instantiate(UNUSED CONF_SECTION *conf, void *instance)
{
	rlm_test_t *inst = instance;
	ATTR_FLAGS flags;

	memset(&flags, 0, sizeof(flags));

	if (dict_addattr("test-Paircmp", -1, 0, PW_TYPE_STRING, flags) < 0) {
		ERROR("Failed creating paircmp attribute: %s", fr_strerror());

		return -1;
	}

	paircompare_register(dict_attrbyname("test-Paircmp"), dict_attrbyvalue(PW_USER_NAME, 0), false,
			     rlm_test_cmp, inst);

	/*
	 *	Log some messages
	 */
	INFO("rlm_test: Informational message");
	WARN("rlm_test: Warning message");
	ERROR("rlm_test: Error message");
	DEBUG("rlm_test: Debug message");
	DEBUG2("rlm_test: Debug2 message");
	DEBUG3("rlm_test: Debug3 message");
	DEBUG4("rlm_test: Debug4 message");
	AUTH("rlm_test: Auth message");
	ACCT("rlm_test: Acct message");
	PROXY("rlm_test: Proxy message");

	return 0;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(UNUSED void *instance, REQUEST *request)
{
	RINFO("RINFO message");
	RDEBUG("RDEBUG message");
	RDEBUG2("RDEBUG2 message");

	RWARN("RWARN message");
	RWDEBUG("RWDEBUG message");
	RWDEBUG("RWDEBUG2 message");

	RAUTH("RAUTH message");
	RACCT("RACCT message");
	RPROXY("RPROXY message");

	/*
	 *	 Should appear wavy
	 */
	RERROR("RERROR error message");
	RINDENT();
	REDEBUG("RDEBUG error message");
	REXDENT();
	REDEBUG2("RDEBUG2 error message");
	RINDENT();
	REDEBUG3("RDEBUG3 error message");
	REXDENT();
	REDEBUG4("RDEBUG4 error message");

	return RLM_MODULE_OK;
}

/*
 *	Authenticate the user with the given password.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(UNUSED void *instance, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

#ifdef WITH_ACCOUNTING
/*
 *	Massage the request before recording it or proxying it
 */
static rlm_rcode_t CC_HINT(nonnull) mod_preacct(UNUSED void *instance, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(UNUSED void *instance, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

/*
 *	See if a user is already logged in. Sets request->simul_count to the
 *	current session count for this user and sets request->simul_mpp to 2
 *	if it looks like a multilink attempt based on the requested IP
 *	address, otherwise leaves request->simul_mpp alone.
 *
 *	Check twice. If on the first pass the user exceeds his
 *	max. number of logins, do a second pass and validate all
 *	logins by querying the terminal server (using eg. SNMP).
 */
static rlm_rcode_t CC_HINT(nonnull) mod_checksimul(UNUSED void *instance, REQUEST *request)
{
	request->simul_count=0;

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
extern module_t rlm_test;
module_t rlm_test = {
	.magic		= RLM_MODULE_INIT,
	.name		= "test",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_test_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
#ifdef WITH_ACCOUNTING
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_SESSION]		= mod_checksimul
#endif
	},
};
