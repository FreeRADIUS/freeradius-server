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
 * @copyright 2013 your name (email@example.org)
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_test - "

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

	uint8_t const	*octets;
	uint8_t const	**octets_m;

	uint8_t		byte;
	uint8_t		*byte_m;

	uint8_t		ifid[8];
	/*
	 *	clang correctly performs type compatibility checks between
	 *	arrays with a specific length, but for pointers to pointers
	 *	to arrays of specific length
	 *	(which is what FR_TYPE_CONF_CHECK receives) the check doesn't
	 *	seem to work.
	 *
	 *	So the "multi" variants of ethernet and ifid buffers, must
	 *	be a **.
	 */
	uint8_t		**ifid_m;
	uint16_t	shortint;
	uint16_t	*shortint_m;

	uint8_t		ethernet[6];
	/*
	 *	See above...
	 */
	uint8_t		**ethernet_m;

	int32_t		int32;
	int32_t		*int32_m;

	uint64_t	uint64;
	uint64_t	*uint64_m;

	fr_time_delta_t	time_delta;
	fr_time_delta_t	*time_delta_m;
} rlm_test_t;

typedef struct {
	pthread_t	value;
} rlm_test_thread_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("tmpl", FR_TYPE_TMPL, rlm_test_t, tmpl), .dflt = "&Tmp-String-0", .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("tmpl_m", FR_TYPE_TMPL | FR_TYPE_MULTI, rlm_test_t, tmpl_m), .dflt = "&Tmp-String-0", .quote = T_DOUBLE_QUOTED_STRING },

	{ FR_CONF_OFFSET("string", FR_TYPE_STRING, rlm_test_t, string) },
	{ FR_CONF_OFFSET("string_m", FR_TYPE_STRING | FR_TYPE_MULTI, rlm_test_t, string_m) },

	{ FR_CONF_OFFSET("boolean", FR_TYPE_BOOL, rlm_test_t, boolean), .dflt = "no" },
	{ FR_CONF_OFFSET("boolean_m", FR_TYPE_BOOL | FR_TYPE_MULTI, rlm_test_t, boolean_m), .dflt = "no" },

	{ FR_CONF_OFFSET("integer", FR_TYPE_UINT32, rlm_test_t, integer), .dflt = "1" },
	{ FR_CONF_OFFSET("integer_m", FR_TYPE_UINT32 | FR_TYPE_MULTI, rlm_test_t, integer_m), .dflt = "2" },

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

	{ FR_CONF_OFFSET("octets", FR_TYPE_OCTETS, rlm_test_t, octets) },
	{ FR_CONF_OFFSET("octets_m", FR_TYPE_OCTETS | FR_TYPE_MULTI, rlm_test_t, octets_m) },

	{ FR_CONF_OFFSET("bytes", FR_TYPE_UINT8, rlm_test_t, byte) },
	{ FR_CONF_OFFSET("bytes_m", FR_TYPE_UINT8 | FR_TYPE_MULTI, rlm_test_t, byte_m) },

	{ FR_CONF_OFFSET("ifid", FR_TYPE_IFID, rlm_test_t, ifid) },
	{ FR_CONF_OFFSET("ifid_m", FR_TYPE_IFID | FR_TYPE_MULTI, rlm_test_t, ifid_m) },

	{ FR_CONF_OFFSET("short", FR_TYPE_UINT16, rlm_test_t, shortint) },
	{ FR_CONF_OFFSET("short_m", FR_TYPE_UINT16 | FR_TYPE_MULTI, rlm_test_t, shortint_m) },

	{ FR_CONF_OFFSET("ethernet", FR_TYPE_ETHERNET, rlm_test_t, ethernet) },
	{ FR_CONF_OFFSET("ethernet_m", FR_TYPE_ETHERNET | FR_TYPE_MULTI, rlm_test_t, ethernet_m) },

	{ FR_CONF_OFFSET("signed", FR_TYPE_INT32, rlm_test_t, int32) },
	{ FR_CONF_OFFSET("signed_m", FR_TYPE_INT32 | FR_TYPE_MULTI, rlm_test_t, int32_m) },

	{ FR_CONF_OFFSET("uint64", FR_TYPE_UINT64, rlm_test_t, uint64) },
	{ FR_CONF_OFFSET("uint64_m", FR_TYPE_UINT64 | FR_TYPE_MULTI, rlm_test_t, uint64_m) },

	{ FR_CONF_OFFSET("time_delta", FR_TYPE_TIME_DELTA, rlm_test_t, time_delta) },
	{ FR_CONF_OFFSET("time_delta_t", FR_TYPE_TIME_DELTA | FR_TYPE_MULTI, rlm_test_t, time_delta_m) },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_test_dict[];
fr_dict_autoload_t rlm_test_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_user_name;

extern fr_dict_attr_autoload_t rlm_test_dict_attr[];
fr_dict_attr_autoload_t rlm_test_dict_attr[] = {
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};

static int rlm_test_cmp(UNUSED void *instance, REQUEST *request, UNUSED VALUE_PAIR *thing, VALUE_PAIR *check,
			UNUSED VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
{
	rad_assert(check->vp_type == FR_TYPE_STRING);

	RINFO("Test-Paircmp called with \"%pV\"", &check->data);

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

static int mod_thread_detach(UNUSED fr_event_list_t *el, void *thread)
{
	rlm_test_thread_t *t = thread;

	INFO("Performing detach for thread %p", (void *)t->value);

	if (!fr_cond_assert(t->value == pthread_self())) return RLM_MODULE_FAIL;

	return 0;
}

/*
 *	Do any per-module bootstrapping that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int mod_bootstrap(void *instance, UNUSED CONF_SECTION *conf)
{
	rlm_test_t *inst = instance;

	if (paircmp_register_by_name("Test-Paircmp", attr_user_name, false,
					rlm_test_cmp, inst) < 0) {
		PERROR("Failed registering \"Test-Paircmp\"");
		return -1;
	}

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

	if (!fr_cond_assert(t->value == pthread_self())) return RLM_MODULE_FAIL;

	return RLM_MODULE_OK;
}

/*
 *	Authenticate the user with the given password.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(UNUSED void *instance, void *thread, UNUSED REQUEST *request)
{
	rlm_test_thread_t *t = thread;

	if (!fr_cond_assert(t->value == pthread_self())) return RLM_MODULE_FAIL;

	return RLM_MODULE_OK;
}

#ifdef WITH_ACCOUNTING
/*
 *	Massage the request before recording it or proxying it
 */
static rlm_rcode_t CC_HINT(nonnull) mod_preacct(UNUSED void *instance, void *thread, UNUSED REQUEST *request)
{
	rlm_test_thread_t *t = thread;

	if (!fr_cond_assert(t->value == pthread_self())) return RLM_MODULE_FAIL;

	return RLM_MODULE_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(UNUSED void *instance, void *thread, UNUSED REQUEST *request)
{
	rlm_test_thread_t *t = thread;

	if (!fr_cond_assert(t->value == pthread_self())) return RLM_MODULE_FAIL;

	return RLM_MODULE_OK;
}
#endif

/*
 *	Write accounting information to this modules database.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_return(UNUSED void *instance, UNUSED void *thread, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

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
	.magic			= RLM_MODULE_INIT,
	.name			= "test",
	.type			= RLM_TYPE_THREAD_SAFE,
	.inst_size		= sizeof(rlm_test_t),
	.thread_inst_size	= sizeof(rlm_test_thread_t),
	.config			= module_config,
	.bootstrap		= mod_bootstrap,
	.thread_instantiate	= mod_thread_instantiate,
	.thread_detach		= mod_thread_detach,
	.detach			= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
#ifdef WITH_ACCOUNTING
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
#endif
	},
	.method_names = (module_method_names_t[]){
		{ "recv",	"Access-Challenge", mod_return },
		{ "recv",	CF_IDENT_ANY,	mod_return },
		{ "name1_null",	NULL,		mod_return },
		{ "send",	CF_IDENT_ANY,	mod_return },
		{ CF_IDENT_ANY, CF_IDENT_ANY,	mod_return },

		MODULE_NAME_TERMINATOR
	}
};
