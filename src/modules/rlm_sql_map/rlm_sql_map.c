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
 * @file rlm_sql_map.c
 * @brief Tracks data usage and other counters using SQL.
 *
 * @copyright 2021  The FreeRADIUS server project
 * @copyright 2021  Alan DeKok <aland@ox.org>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>

#include <rlm_sql.h>

typedef struct rlm_sql_map_t {
	char const	*sql_instance_name;	//!< Instance of SQL module to use,
						//!< usually just 'sql'.
	bool		multiple_rows;		//!< Process all rows creating an attr[*] array

	char const	*query;			//!< SQL query to retrieve current

	rlm_sql_t	*sql_inst;

	CONF_SECTION	*cs;

	/*
	 *	SQL columns to RADIUS stuff
	 */
	vp_map_t	*user_map;
} rlm_sql_map_t;

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
	{ "sql_module_instance", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_sql_map_t, sql_instance_name), NULL },
	{ "multiple_rows", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_sql_map_t, multiple_rows), "no" },
	{ "query", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_REQUIRED | PW_TYPE_NOT_EMPTY, rlm_sql_map_t, query), NULL },

	CONF_PARSER_TERMINATOR
};

#define SQL_MAX_ATTRMAP (128)

static int sql_map_verify(vp_map_t *map, UNUSED void *instance)
{
	/*
	 *	Destinations where we can put the VALUE_PAIRs we
	 *	create using SQL values.
	 */
	switch (map->lhs->type) {
	case TMPL_TYPE_ATTR:
		break;

	case TMPL_TYPE_ATTR_UNDEFINED:
		cf_log_err(map->ci, "Unknown attribute %s", map->lhs->tmpl_unknown_name);
		return -1;

	default:
		cf_log_err(map->ci, "Left hand side of map must be an attribute, not a %s",
			   fr_int2str(tmpl_names, map->lhs->type, "<INVALID>"));
		return -1;
	}

	/*
	 *	The RHS MUST be only a column number.
	 */
	switch (map->rhs->type) {
	case TMPL_TYPE_LITERAL:
	case TMPL_TYPE_DATA:
		if (tmpl_cast_in_place(map->rhs, PW_TYPE_INTEGER, NULL) < 0) {
			cf_log_err(map->ci, "Failed parsing right hand side of map as an integer.");
			return -1;
		}

		if (map->rhs->tmpl_data_value.integer > SQL_MAX_ATTRMAP) {
			cf_log_err(map->ci, "Column number %u is larger than allowed maximum %u",
				map->rhs->tmpl_data_value.integer, SQL_MAX_ATTRMAP);
			return -1;
		}
		break;

	default:
		cf_log_err(map->ci, "Right hand side of map must be a column number, not a %s",
			   fr_int2str(tmpl_names, map->rhs->type, "<INVALID>"));
		return -1;
	}

	/*
	 *	Only =, :=, += and -= operators are supported for SQL mappings.
	 */
	switch (map->op) {
	case T_OP_SET:
	case T_OP_EQ:
	case T_OP_SUB:
	case T_OP_ADD:
		break;

	default:
		cf_log_err(map->ci, "Operator \"%s\" not allowed for SQL mappings",
			   fr_int2str(fr_tokens, map->op, "<INVALID>"));
		return -1;
	}

	return 0;
}

typedef struct sql_map_row_s {
	int		num_columns;
	char		**row;
} sql_map_row_t;


/** Callback for map_to_request
 *
 * Performs exactly the same job as map_to_vp, but pulls attribute values from SQL entries
 *
 * @see map_to_vp
 */
static int sql_map_getvalue(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, vp_map_t const *map, void *uctx)
{
	VALUE_PAIR	*head = NULL, *vp;
	int		column;
	sql_map_row_t	*data = uctx;
	char		*value;
	vp_cursor_t	cursor;

	*out = NULL;
	fr_cursor_init(&cursor, &head);

	switch (map->lhs->type) {
	/*
	 *	Iterate over all the retrieved values,
	 *	don't try and be clever about changing operators
	 *	just use whatever was set in the attribute map.
	 */
	case TMPL_TYPE_ATTR:
		fr_assert(map->rhs->type == TMPL_TYPE_DATA);
		fr_assert(map->rhs->tmpl_data_type == PW_TYPE_INTEGER);

		column = map->rhs->tmpl_data_value.integer;
		if (column >= data->num_columns) {
			RWDEBUG("Ignoring source column number %u, as it is larger than the number of returned columns %d",
				column, data->num_columns);
			return 0;
		}

		if (!data->row[column]) {
			RWDEBUG("Ignoring source column number %u - it is empty", column);
			return 0;
		}
		
		value = data->row[column];

		vp = fr_pair_afrom_da(ctx, map->lhs->tmpl_da);
		rad_assert(vp);

		vp->op = map->op;
		vp->tag = map->lhs->tmpl_tag;

		if (fr_pair_value_from_str(vp, value, -1) < 0) {
			char *escaped;

			escaped = fr_aprints(vp, value, -1, '"');
			RWDEBUG("Failed parsing value \"%s\" for attribute %s: %s", escaped,
				map->lhs->tmpl_da->name, fr_strerror());
			talloc_free(vp); /* also frees escaped */
			break;
		}

		fr_cursor_insert(&cursor, vp);
		break;

	default:
		rad_assert(0);
	}

	*out = head;

	return 0;
}


/** Convert attribute map into valuepairs
 *
 * Use the attribute map built earlier to convert SQL values into valuepairs and insert them into whichever
 * list they need to go into.
 *
 * This is *NOT* atomic, but there's no condition for which we should error out...
 *
 * @param[in] inst module configuration.
 * @param[in] request Current request.
 * @param[in] handle associated with entry.
 * @return
 *	- Number of maps successfully applied.
 *	- -1 on failure.
 */
static int sql_map_do(const rlm_sql_map_t *inst, REQUEST *request, rlm_sql_handle_t **handle)
{
	vp_map_t const		*map;
	int			applied = 0;	/* How many maps have been applied to the current request */
	sql_map_row_t		ctx;

	/*
	 *	Cache all of the rows in a simple array.
	 */
	while ((inst->sql_inst->module->sql_fetch_row)(*handle, inst->sql_inst->config) == RLM_SQL_OK) {
#ifdef __clang_analyzer__
		if (!*handle) return -1; /* only true when return code is not RLM_SQL_OK */
#endif

		ctx.row = (*handle)->row;
		ctx.num_columns = (inst->sql_inst->module->sql_num_fields)(*handle, inst->sql_inst->config);

		if (applied >= 1 && !inst->multiple_rows) {
			RWDEBUG("Ignoring multiple rows. Enable the option 'multiple_rows' if you need multiple rows.");
			break;
		}

		for (map = inst->user_map; map != NULL; map = map->next) {
			/*
			 *	If something bad happened, just skip, this is probably
			 *	a case of the dst being incorrect for the current
			 *	request context
			 */
			if (map_to_request(request, map, sql_map_getvalue, &ctx) < 0) {
				return -1;	/* Fail */
			}
		}

		applied++;
	}

	return applied;
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
	rlm_sql_map_t *inst = instance;
	module_instance_t *sql_inst;
	CONF_SECTION *update;

	sql_inst = module_instantiate(cf_section_find("modules"),
					inst->sql_instance_name);
	if (!sql_inst) {
		cf_log_err_cs(conf, "Failed to find sql instance named %s",
			   inst->sql_instance_name);
		return -1;
	}
	inst->sql_inst = (rlm_sql_t *)sql_inst->insthandle;

	inst->cs = conf;

	/*
	 *	Build the attribute map
	 */
	update = cf_section_sub_find(inst->cs, "update");
	if (!update) {
		cf_log_err_cs(conf, "Failed to find 'update' section");
		return -1;
	}

	if (map_afrom_cs(&inst->user_map, update,
			 PAIR_LIST_REPLY, PAIR_LIST_REQUEST, sql_map_verify, inst,
			 SQL_MAX_ATTRMAP) < 0) {
		return -1;
	}

	return 0;
}

static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_sql_map_t *inst = instance;
	char const *p = inst->query;

	if (!p || !*p) {
		cf_log_err_cs(conf, "'query' cannot be empty");
		return -1;
	}

	while (isspace((uint8_t) *p)) p++;

	if ((strncasecmp(p, "insert", 6) == 0) ||
	    (strncasecmp(p, "update", 6) == 0) ||
	    (strncasecmp(p, "delete", 6) == 0)) {
		cf_log_err_cs(conf, "'query' MUST be 'SELECT ...', not 'INSERT', 'UPDATE', or 'DELETE'");
		return -1;
	}

	return 0;
}


/** Detach from the SQL server and cleanup internal state.
 *
 */
static int mod_detach(void *instance)
{
	rlm_sql_map_t *inst = instance;

	talloc_free(inst->user_map);

	return 0;
}


/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_map(void *instance, REQUEST *request)
{
	int res;
	rlm_rcode_t rcode = RLM_MODULE_NOOP;
	char *query;
	rlm_sql_map_t *inst = instance;
	rlm_sql_handle_t *handle;

	handle = fr_connection_get(inst->sql_inst->pool);
	if (!handle) {
		REDEBUG("Failed reserving SQL connection");
		return RLM_MODULE_FAIL;
	}

	if (inst->sql_inst->sql_set_user(inst->sql_inst, request, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	if (radius_axlat(&query, request, inst->query, inst->sql_inst->sql_escape_func, handle) < 0) {
		return RLM_MODULE_FAIL;
	}

	res = inst->sql_inst->sql_select_query(inst->sql_inst, request, &handle, query);
	talloc_free(query);
	if (res != RLM_SQL_OK) {
		if (handle) fr_connection_release(inst->sql_inst->pool, handle);

		return RLM_MODULE_FAIL;
	}

	fr_assert(handle != NULL);

	if (sql_map_do(inst, request, &handle) > 0) rcode = RLM_MODULE_UPDATED;

	if (handle) {
		(inst->sql_inst->module->sql_finish_query)(handle, inst->sql_inst->config);

		fr_connection_release(inst->sql_inst->pool, handle);
	}

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
extern module_t rlm_sql_map;
module_t rlm_sql_map = {
	.magic		= RLM_MODULE_INIT,
	.name		= "sqlcounter",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_sql_map_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_map,
		[MOD_AUTHORIZE]		= mod_map,
		[MOD_PREACCT]		= mod_map,
		[MOD_ACCOUNTING]	= mod_map,
		[MOD_PRE_PROXY]		= mod_map,
		[MOD_POST_PROXY]	= mod_map,
		[MOD_POST_AUTH]		= mod_map,
#ifdef WITH_COA
		[MOD_RECV_COA]		= mod_map,
		[MOD_SEND_COA]		= mod_map
#endif
	},
};

