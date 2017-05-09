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

#define LOG_PREFIX "rlm_test - "

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
	vp_tmpl_t	*tmpl;
	vp_tmpl_t	**tmpl_m;
	char const	*string;
	char const	**string_m;

	bool		boolean;
	bool		*boolean_m;

	uint32_t	integer;
	uint32_t	*integer_m;

	fr_ipaddr_t	ipv4_addr;
	fr_ipaddr_t	ipv4_prefix;

	fr_ipaddr_t	ipv6_addr;
	fr_ipaddr_t	ipv6_prefix;

	fr_ipaddr_t	combo_ipaddr;

	fr_ipaddr_t	*ipv4_addr_m;
	fr_ipaddr_t	*ipv4_prefix_m;

	fr_ipaddr_t	*ipv6_addr_m;
	fr_ipaddr_t	*ipv6_prefix_m;

	fr_ipaddr_t	*combo_ipaddr_m;

	fr_ipaddr_t	ipaddr;

	time_t		date;
	time_t		*date_m;

	size_t		abinary[32/sizeof(size_t)];
	size_t		abinary_m[32/sizeof(size_t)];

	uint8_t const	*octets;
	uint8_t const	**octets_m;

	uint8_t		byte;
	uint8_t		*byte_m;

	uint8_t		ifid[8];
	uint8_t		*ifid_m[8];

	uint16_t	shortint;
	uint16_t	shortint_m;

	uint8_t		ethernet[6];
	uint8_t		ethernet_m[6];

	int32_t		sinteger;
	int32_t		*sinteger_m;

	uint64_t	integer64;
	uint64_t	*integer64_m;

	_timeval_t	timeval;
	_timeval_t	*timeval_m;
} rlm_test_t;

typedef struct {
	pthread_t	value;
} rlm_test_thread_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("tmpl", FR_TYPE_TMPL, rlm_test_t, tmpl), .dflt = "&User-Name", .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("tmpl_m", FR_TYPE_TMPL | FR_TYPE_MULTI, rlm_test_t, tmpl_m), .dflt = "%{User-Name}", .quote = T_DOUBLE_QUOTED_STRING },

	{ FR_CONF_OFFSET("string", FR_TYPE_STRING, rlm_test_t, string) },
	{ FR_CONF_OFFSET("string_m", FR_TYPE_STRING | FR_TYPE_MULTI, rlm_test_t, string_m) },

	{ FR_CONF_OFFSET("boolean", FR_TYPE_BOOLEAN, rlm_test_t, boolean), .dflt = "no" },
	{ FR_CONF_OFFSET("boolean_m", FR_TYPE_BOOLEAN | FR_TYPE_MULTI, rlm_test_t, boolean_m), .dflt = "no" },

	{ FR_CONF_OFFSET("integer", FR_TYPE_INTEGER, rlm_test_t, integer), .dflt = "1" },
	{ FR_CONF_OFFSET("integer_m", FR_TYPE_INTEGER | FR_TYPE_MULTI, rlm_test_t, integer_m), .dflt = "2" },

	{ FR_CONF_OFFSET("ipv4_addr", FR_TYPE_IPV4_ADDR, rlm_test_t, ipv4_addr), .dflt = "*" },
	{ FR_CONF_OFFSET("ipv4_addr_m", FR_TYPE_IPV4_ADDR | FR_TYPE_MULTI, rlm_test_t, ipv4_addr_m), .dflt = "*" },

	{ FR_CONF_OFFSET("ipv4_prefix", FR_TYPE_IPV4_PREFIX, rlm_test_t, ipv4_addr), .dflt = "192.168.0.1/24" },
	{ FR_CONF_OFFSET("ipv4_prefix_m", FR_TYPE_IPV4_PREFIX | FR_TYPE_MULTI, rlm_test_t, ipv4_addr_m), .dflt = "192.168.0.1/24" },

	{ FR_CONF_OFFSET("ipv6_addr", FR_TYPE_IPV6_ADDR, rlm_test_t, ipv6_addr), .dflt = "*" },
	{ FR_CONF_OFFSET("ipv6_addr_m", FR_TYPE_IPV6_ADDR | FR_TYPE_MULTI, rlm_test_t, ipv6_addr_m), .dflt = "*" },

	{ FR_CONF_OFFSET("ipv6_prefix", FR_TYPE_IPV6_PREFIX, rlm_test_t, ipv6_prefix), .dflt = "::1/128" },
	{ FR_CONF_OFFSET("ipv6_prefix_m", FR_TYPE_IPV6_PREFIX | FR_TYPE_MULTI, rlm_test_t, ipv6_prefix_m), .dflt = "::1/128" },

	{ FR_CONF_OFFSET("combo", FR_TYPE_COMBO_IP_ADDR, rlm_test_t, combo_ipaddr), .dflt = "::1/128" },
	{ FR_CONF_OFFSET("combo_m", FR_TYPE_COMBO_IP_ADDR | FR_TYPE_MULTI, rlm_test_t, combo_ipaddr_m), .dflt = "::1/128" },

	{ FR_CONF_OFFSET("date", FR_TYPE_DATE, rlm_test_t, date) },
	{ FR_CONF_OFFSET("date_m", FR_TYPE_DATE | FR_TYPE_MULTI, rlm_test_t, date_m) },

	{ FR_CONF_OFFSET("abinary", FR_TYPE_ABINARY, rlm_test_t, abinary) },
	{ FR_CONF_OFFSET("abinary_m", FR_TYPE_ABINARY | FR_TYPE_MULTI, rlm_test_t, abinary_m) },

	{ FR_CONF_OFFSET("octets", FR_TYPE_OCTETS, rlm_test_t, octets) },
	{ FR_CONF_OFFSET("octets_m", FR_TYPE_OCTETS | FR_TYPE_MULTI, rlm_test_t, octets_m) },

	{ FR_CONF_OFFSET("bytes", FR_TYPE_BYTE, rlm_test_t, byte) },
	{ FR_CONF_OFFSET("bytes_m", FR_TYPE_BYTE | FR_TYPE_MULTI, rlm_test_t, byte_m) },

	{ FR_CONF_OFFSET("ifid", FR_TYPE_IFID, rlm_test_t, ifid) },
	{ FR_CONF_OFFSET("ifid_m", FR_TYPE_IFID | FR_TYPE_MULTI, rlm_test_t, ifid_m) },

	{ FR_CONF_OFFSET("short", FR_TYPE_SHORT, rlm_test_t, shortint) },
	{ FR_CONF_OFFSET("short_m", FR_TYPE_SHORT | FR_TYPE_MULTI, rlm_test_t, shortint_m) },

	{ FR_CONF_OFFSET("ethernet", FR_TYPE_ETHERNET, rlm_test_t, ethernet) },
	{ FR_CONF_OFFSET("ethernet_m", FR_TYPE_ETHERNET | FR_TYPE_MULTI, rlm_test_t, ethernet_m) },

	{ FR_CONF_OFFSET("signed", FR_TYPE_SIGNED, rlm_test_t, sinteger) },
	{ FR_CONF_OFFSET("signed_m", FR_TYPE_SIGNED | FR_TYPE_MULTI, rlm_test_t, sinteger_m) },

	{ FR_CONF_OFFSET("uint64", FR_TYPE_INTEGER64, rlm_test_t, integer64) },
	{ FR_CONF_OFFSET("uint64_m", FR_TYPE_INTEGER64 | FR_TYPE_MULTI, rlm_test_t, integer64_m) },

	{ FR_CONF_OFFSET("timeval", FR_TYPE_TIMEVAL, rlm_test_t, timeval) },
	{ FR_CONF_OFFSET("timeval_m", FR_TYPE_TIMEVAL | FR_TYPE_MULTI, rlm_test_t, timeval_m) },

	CONF_PARSER_TERMINATOR
};

static int rlm_test_cmp(UNUSED void *instance, REQUEST *request, UNUSED VALUE_PAIR *thing, VALUE_PAIR *check,
			UNUSED VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
{
	rad_assert(check->vp_type == FR_TYPE_STRING);

	RINFO("test-Paircmp called with \"%s\"", check->vp_strvalue);

	if (strcmp(check->vp_strvalue, "yes") == 0) return 0;
	return 1;
}

static int mod_thread_instantiate(UNUSED CONF_SECTION  const *cs, UNUSED void *instance, UNUSED fr_event_list_t *el,
				  void *thread)
{
	rlm_test_thread_t *t = thread;

	t->value = pthread_self();
	INFO("Performing instantiation for thread %p (ctx %p)", (void *)t->value, t);

	return 0;
}

static int mod_thread_detach(void *thread)
{
	rlm_test_thread_t *t = thread;

	INFO("Performing detach for thread %p", (void *)t->value);

	if (!rad_cond_assert(t->value == pthread_self())) return RLM_MODULE_FAIL;

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
static int mod_instantiate(UNUSED CONF_SECTION *conf, void *instance)
{
	rlm_test_t *inst = instance;

	paircompare_register_byname("test-Paircmp", fr_dict_attr_by_num(NULL, 0, PW_USER_NAME), false,
				    rlm_test_cmp, inst);

	/*
	 *	Log some messages
	 */
	INFO("Informational message");
	WARN("Warning message");
	ERROR("Error message");
	DEBUG("Debug message");
	DEBUG2("Debug2 message");
	DEBUG3("Debug3 message");
	DEBUG4("Debug4 message");
	AUTH("Auth message");
	ACCT("Acct message");
	PROXY("Proxy message");

	return 0;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(UNUSED void *instance, void *thread, REQUEST *request)
{
	rlm_test_thread_t *t = thread;

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

	if (!rad_cond_assert(t->value == pthread_self())) return RLM_MODULE_FAIL;

	return RLM_MODULE_OK;
}

/*
 *	Authenticate the user with the given password.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(UNUSED void *instance, void *thread, UNUSED REQUEST *request)
{
	rlm_test_thread_t *t = thread;

	if (!rad_cond_assert(t->value == pthread_self())) return RLM_MODULE_FAIL;

	return RLM_MODULE_OK;
}

#ifdef WITH_ACCOUNTING
/*
 *	Massage the request before recording it or proxying it
 */
static rlm_rcode_t CC_HINT(nonnull) mod_preacct(UNUSED void *instance, void *thread, UNUSED REQUEST *request)
{
	rlm_test_thread_t *t = thread;

	if (!rad_cond_assert(t->value == pthread_self())) return RLM_MODULE_FAIL;

	return RLM_MODULE_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(UNUSED void *instance, void *thread, UNUSED REQUEST *request)
{
	rlm_test_thread_t *t = thread;

	if (!rad_cond_assert(t->value == pthread_self())) return RLM_MODULE_FAIL;

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
static rlm_rcode_t CC_HINT(nonnull) mod_checksimul(UNUSED void *instance, void *thread, REQUEST *request)
{
	rlm_test_thread_t *t = thread;

	request->simul_count = 0;

	if (!rad_cond_assert(t->value == pthread_self())) return RLM_MODULE_FAIL;

	return RLM_MODULE_OK;
}
#endif

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
extern rad_module_t rlm_test;
rad_module_t rlm_test = {
	.magic			= RLM_MODULE_INIT,
	.name			= "test",
	.type			= RLM_TYPE_THREAD_SAFE,
	.inst_size		= sizeof(rlm_test_t),
	.thread_inst_size	= sizeof(rlm_test_thread_t),
	.config			= module_config,
	.instantiate		= mod_instantiate,
	.thread_instantiate	= mod_thread_instantiate,
	.thread_detach		= mod_thread_detach,
	.detach			= mod_detach,
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
