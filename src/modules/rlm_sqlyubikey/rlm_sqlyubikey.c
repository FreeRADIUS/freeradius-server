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
 * @file rlm_sqlyubikey.c
 * @brief Update Yubikey OTP token values in SQL database.
 *
 * @copyright 2015  The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <rlm_sql.h>

/*
 *	Minimalist structure for our module configuration.
 */
typedef struct rlm_sqlyubikey_t {
	char const *sql_instance_name;
	rlm_sql_t *sql_inst;

	char const *query_counter;     //!< SQL query to update session counter (16-bits monotonic increasing per plugin) concatenated with use (8-bit monotonic per press during plugin)
	char const *query_timestamp;   //!< SQL query to update timestamp value (24-bit rollover random start per plugin)
} rlm_sqlyubikey_t;

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
	{ "sql-instance-name", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, rlm_sqlyubikey_t, sql_instance_name), NULL },
	{ "sql_module_instance", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_sqlyubikey_t, sql_instance_name), "sql" },

	{ "query_counter", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_sqlyubikey_t, query_counter), NULL },
	{ "query_timestamp", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_sqlyubikey_t, query_timestamp), NULL },

	{ NULL, -1, 0, NULL, NULL }
};

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
	rlm_sqlyubikey_t *inst = instance;
	module_instance_t *mod_inst;

	rad_assert(inst->query_counter && *inst->query_counter);
	rad_assert(inst->query_timestamp && *inst->query_timestamp);

	mod_inst = find_module_instance(cf_section_find("modules"),
		inst->sql_instance_name, true);
	if (!mod_inst) {
		cf_log_err_cs(conf, "failed to find sql instance named %s",
			inst->sql_instance_name);
		return -1;
	}
	inst->sql_inst = (rlm_sql_t *) mod_inst->insthandle;

	return 0;
}

/*
 *	Translate and issue SQL query.
 */
static rlm_rcode_t sqlyubikey_query(rlm_sqlyubikey_t *inst, REQUEST *request, rlm_sql_handle_t *handle, char const *query)
{
	rlm_sql_t *sql_inst = inst->sql_inst;
	char *expanded = NULL;
	int ret;

	if (radius_axlat(&expanded, request, query, sql_inst->sql_escape_func, sql_inst) < 0)
		return RLM_MODULE_FAIL;

	ret = sql_inst->sql_query(&handle, sql_inst, expanded);
	talloc_free(expanded);
	if (ret < 0)
		return RLM_MODULE_NOOP;

	sql_inst->module->sql_finish_query(handle, sql_inst->config);

	return RLM_MODULE_OK;
}

/*
 *	Update the attribute-value(s) for this user in the database.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST *request)
{
	rlm_rcode_t rcode;
	rlm_sqlyubikey_t *inst = instance;
	rlm_sql_handle_t *handle;

	handle = fr_connection_get(inst->sql_inst->pool);
	if (!handle) {
		REDEBUG("cannot get sql connection");
		return RLM_MODULE_FAIL;
	}

	if (inst->sql_inst->sql_set_user(inst->sql_inst, request, NULL) < 0)
		rcode = RLM_MODULE_FAIL;
	else if ((rcode = sqlyubikey_query(inst, request, handle, inst->query_counter)) == RLM_MODULE_FAIL)
		;
	else
		rcode = sqlyubikey_query(inst, request, handle, inst->query_timestamp);

	fr_connection_release(inst->sql_inst->pool, handle);

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
module_t rlm_sqlyubikey = {
	RLM_MODULE_INIT,
	"sqlyubikey",
	RLM_TYPE_THREAD_SAFE,		/* type */
	sizeof(rlm_sqlyubikey_t),
	module_config,
	mod_instantiate,	/* instantiation */
	NULL,				/* detach */
	{
		NULL,			/* authentication */
		NULL,			/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		mod_post_auth	/* post-auth */
	},
};
