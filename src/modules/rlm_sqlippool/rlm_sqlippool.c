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
 * @file rlm_sqlippool.c
 * @brief Allocates an IPv4 address from pools stored in SQL.
 *
 * @copyright 2002 Globe.Net Communications Limited
 * @copyright 2006 The FreeRADIUS server project
 * @copyright 2006 Suntel Communications
 */
RCSID("$Id$")

#define LOG_PREFIX inst->name

#include <rlm_sql.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/radius/radius.h>

#include <ctype.h>


#define MAX_QUERY_LEN 4096

/*
 *	Define a structure for our module configuration.
 */
typedef struct {
	char const      *name;
	char const	*sql_name;

	uint32_t	lease_duration;

	rlm_sql_t const	*sql;

	char const	*pool_name;
	fr_dict_attr_t const *allocated_address_da; //!< the attribute for IP address allocation
	char const	*allocated_address_attr;	//!< name of the IP address attribute
	tmpl_t		*requested_address;	//!< name of the requested IP address attribute

						/* Alloc sequence */
	char const	*alloc_begin;		//!< SQL query to begin.
	char const	*alloc_existing;	//!< SQL query to find existing IP.
	char const	*alloc_requested;	//!< SQL query to find requested IP.
	char const	*alloc_find;		//!< SQL query to find an unused IP.
	char const	*alloc_update;		//!< SQL query to mark an IP as used.
	char const	*alloc_commit;		//!< SQL query to commit.

	char const	*pool_check;		//!< Query to check for the existence of the pool.

						/* Update sequence */
	char const	*update_begin;		//!< SQL query to begin.
	char const	*update_free;		//!< SQL query to clear offered IPs
	char const	*update_update;		//!< SQL query to update an IP entry.
	char const	*update_commit;		//!< SQL query to commit.

						/* Release sequence */
	char const	*release_begin;		//!< SQL query to begin.
	char const	*release_clear;       	//!< SQL query to clear an IP entry.
	char const	*release_commit;	//!< SQL query to commit.

						/* Bulk release sequence */
	char const	*bulk_release_begin;	//!< SQL query to begin.
	char const	*bulk_release_clear;	//!< SQL query to bulk clear several IPs.
	char const	*bulk_release_commit;	//!< SQL query to commit.

						/* Mark sequence */
	char const	*mark_begin;		//!< SQL query to begin.
	char const	*mark_update;		//!< SQL query to mark an IP.
	char const	*mark_commit;		//!< SQL query to commit.

						/* Logging Section */
	char const	*log_exists;		//!< There was an ip address already assigned.
	char const	*log_success;		//!< We successfully allocated ip address from pool.
	char const	*log_clear;		//!< We successfully deallocated ip address from pool.
	char const	*log_failed;		//!< Failed to allocate ip from the pool.
	char const	*log_nopool;		//!< There was no Framed-IP-Address but also no Pool-Name.

						/* Reserved to handle 255.255.255.254 Requests */
	char const	*defaultpool;		//!< Default Pool-Name if there is none in the check items.

} rlm_sqlippool_t;

static conf_parser_t message_config[] = {
	{ FR_CONF_OFFSET_FLAGS("exists", CONF_FLAG_XLAT, rlm_sqlippool_t, log_exists) },
	{ FR_CONF_OFFSET_FLAGS("success", CONF_FLAG_XLAT, rlm_sqlippool_t, log_success) },
	{ FR_CONF_OFFSET_FLAGS("clear", CONF_FLAG_XLAT, rlm_sqlippool_t, log_clear) },
	{ FR_CONF_OFFSET_FLAGS("failed", CONF_FLAG_XLAT, rlm_sqlippool_t, log_failed) },
	{ FR_CONF_OFFSET_FLAGS("nopool", CONF_FLAG_XLAT, rlm_sqlippool_t, log_nopool) },
	CONF_PARSER_TERMINATOR
};

static conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("sql_module_instance", rlm_sqlippool_t, sql_name), .dflt = "sql" },

	{ FR_CONF_OFFSET("lease_duration", rlm_sqlippool_t, lease_duration), .dflt = "86400" },

	{ FR_CONF_OFFSET("pool_name", rlm_sqlippool_t, pool_name) },

	{ FR_CONF_OFFSET_FLAGS("allocated_address_attr", CONF_FLAG_REQUIRED | CONF_FLAG_NOT_EMPTY, rlm_sqlippool_t, allocated_address_attr) },

	{ FR_CONF_OFFSET("requested_address", rlm_sqlippool_t, requested_address) },

	{ FR_CONF_OFFSET("default_pool", rlm_sqlippool_t, defaultpool), .dflt = "main_pool" },


	{ FR_CONF_OFFSET_FLAGS("alloc_begin", CONF_FLAG_XLAT, rlm_sqlippool_t, alloc_begin), .dflt = "START TRANSACTION" },

	{ FR_CONF_OFFSET_FLAGS("alloc_existing", CONF_FLAG_XLAT, rlm_sqlippool_t, alloc_existing) },

	{ FR_CONF_OFFSET_FLAGS("alloc_requested", CONF_FLAG_XLAT, rlm_sqlippool_t, alloc_requested) },

	{ FR_CONF_OFFSET_FLAGS("alloc_find", CONF_FLAG_XLAT | CONF_FLAG_REQUIRED, rlm_sqlippool_t, alloc_find) },

	{ FR_CONF_OFFSET_FLAGS("alloc_update", CONF_FLAG_XLAT, rlm_sqlippool_t, alloc_update) },

	{ FR_CONF_OFFSET_FLAGS("alloc_commit", CONF_FLAG_XLAT, rlm_sqlippool_t, alloc_commit), .dflt = "COMMIT" },


	{ FR_CONF_OFFSET_FLAGS("pool_check", CONF_FLAG_XLAT, rlm_sqlippool_t, pool_check) },


	{ FR_CONF_OFFSET_FLAGS("update_begin", CONF_FLAG_XLAT, rlm_sqlippool_t, update_begin) },

	{ FR_CONF_OFFSET_FLAGS("update_free", CONF_FLAG_XLAT, rlm_sqlippool_t, update_free) },

	{ FR_CONF_OFFSET_FLAGS("update_update", CONF_FLAG_XLAT, rlm_sqlippool_t, update_update) },

	{ FR_CONF_OFFSET_FLAGS("update_commit", CONF_FLAG_XLAT, rlm_sqlippool_t, update_commit) },


	{ FR_CONF_OFFSET_FLAGS("release_begin", CONF_FLAG_XLAT, rlm_sqlippool_t, release_begin) },

	{ FR_CONF_OFFSET_FLAGS("release_clear", CONF_FLAG_XLAT, rlm_sqlippool_t, release_clear) },

	{ FR_CONF_OFFSET_FLAGS("release_commit", CONF_FLAG_XLAT, rlm_sqlippool_t, release_commit) },


	{ FR_CONF_OFFSET_FLAGS("bulk_release_begin", CONF_FLAG_XLAT, rlm_sqlippool_t, bulk_release_begin) },

	{ FR_CONF_OFFSET_FLAGS("bulk_release_clear", CONF_FLAG_XLAT, rlm_sqlippool_t, bulk_release_clear) },

	{ FR_CONF_OFFSET_FLAGS("bulk_release_commit", CONF_FLAG_XLAT, rlm_sqlippool_t, bulk_release_commit) },


	{ FR_CONF_OFFSET_FLAGS("mark_begin", CONF_FLAG_XLAT, rlm_sqlippool_t, mark_begin) },

	{ FR_CONF_OFFSET_FLAGS("mark_update", CONF_FLAG_XLAT, rlm_sqlippool_t, mark_update) },

	{ FR_CONF_OFFSET_FLAGS("mark_commit", CONF_FLAG_XLAT, rlm_sqlippool_t, mark_commit) },


	{ FR_CONF_POINTER("messages", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) message_config },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_sqlippool_dict[];
fr_dict_autoload_t rlm_sqlippool_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_pool_name;
static fr_dict_attr_t const *attr_module_success_message;
static fr_dict_attr_t const *attr_acct_status_type;

extern fr_dict_attr_autoload_t rlm_sqlippool_dict_attr[];
fr_dict_attr_autoload_t rlm_sqlippool_dict_attr[] = {
	{ .out = &attr_module_success_message, .name = "Module-Success-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_pool_name, .name = "IP-Pool.Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_acct_status_type, .name = "Acct-Status-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },

	{ NULL }
};

/*
 *	Replace %<whatever> in a string.
 *
 *	%P	pool_name
 *	%I	param
 *	%J	lease_duration
 *
 */
static int sqlippool_expand(char * out, int outlen, char const * fmt,
			    rlm_sqlippool_t const *data, char * param, int param_len)
{
	char *q;
	char const *p;
	char tmp[40]; /* For temporary storing of integers */

	q = out;
	for (p = fmt; *p ; p++) {
		int freespace;
		int c;

		/* Calculate freespace in output */
		freespace = outlen - (q - out);
		if (freespace <= 1)
			break;

		c = *p;
		if (c != '%') {
			*q++ = *p;
			continue;
		}

		if (*++p == '\0') {
			break;
		}

		if (c == '%') {
			switch (*p) {
			case 'P': /* pool name */
				strlcpy(q, data->pool_name, freespace);
				q += strlen(q);
				break;
			case 'I': /* IP address */
				if (param && param_len > 0) {
					if (param_len > freespace) {
						strlcpy(q, param, freespace);
						q += strlen(q);
					}
					else {
						memcpy(q, param, param_len);
						q += param_len;
					}
				}
				break;
			case 'J': /* lease duration */
				snprintf(tmp, sizeof(tmp), "%u", data->lease_duration);
				strlcpy(q, tmp, freespace);
				q += strlen(q);
				break;

			default:
				*q++ = '%';
				*q++ = *p;
				break;
			}
		}
	}
	*q = '\0';

#if 0
	DEBUG2("sqlippool_expand: \"%s\"", out);
#endif

	return strlen(out);
}

/** Perform a single sqlippool query
 *
 * Mostly wrapper around sql_query which does some special sqlippool sequence substitutions and expands
 * the format string.
 *
 * @param fmt sql query to expand.
 * @param handle sql connection handle.
 * @param data Instance of rlm_sqlippool.
 * @param request Current request.
 * @param param ip address string.
 * @param param_len ip address string len.
 * @return
 *	- 0 on success.
 *	- < 0 on error.
 */
static int sqlippool_command(char const *fmt, rlm_sql_handle_t **handle,
			     rlm_sqlippool_t const *data, request_t *request,
			     char *param, int param_len)
{
	char query[MAX_QUERY_LEN];
	char *expanded = NULL;

	int ret;
	int affected;

	/*
	 *	If we don't have a command, do nothing.
	 */
	if (!fmt || !*fmt) return 0;

	/*
	 *	No handle?  That's an error.
	 */
	if (!handle || !*handle) return -1;

	/*
	 *	@todo this needs to die (should just be done in xlat expansion)
	 */
	sqlippool_expand(query, sizeof(query), fmt, data, param, param_len);

	if (xlat_aeval(request, &expanded, request, query, data->sql->sql_escape_func, *handle) < 0) return -1;

	ret = data->sql->query(data->sql, request, handle, expanded);
	talloc_free(expanded);
	if (ret < 0){
		return -1;
	}

	/*
	 *	No handle, we can't continue.
	 */
	if (!*handle) return -1;

	affected = (data->sql->driver->sql_affected_rows)(*handle, &data->sql->config);

	(data->sql->driver->sql_finish_query)(*handle, &data->sql->config);

	return affected;
}

/*
 *	Don't repeat yourself
 */
#define DO_PART(_x) if(sqlippool_command(inst->_x, &handle, inst, request, NULL, 0) <0) goto error

/*
 * Query the database expecting a single result row
 */
static int CC_HINT(nonnull (1, 3, 4, 5)) sqlippool_query1(char *out, int outlen, char const *fmt,
							  rlm_sql_handle_t **handle, rlm_sqlippool_t *data,
							  request_t *request, char *param, int param_len)
{
	char query[MAX_QUERY_LEN];
	char *expanded = NULL;

	int rlen, retval;

	rlm_sql_row_t row;

	/*
	 *	@todo this needs to die (should just be done in xlat expansion)
	 */
	sqlippool_expand(query, sizeof(query), fmt, data, param, param_len);

	*out = '\0';

	/*
	 *	Do an xlat on the provided string
	 */
	if (xlat_aeval(request, &expanded, request, query, data->sql->sql_escape_func, *handle) < 0) {
		return 0;
	}
	retval = data->sql->select(data->sql, request, handle, expanded);
	talloc_free(expanded);

	if ((retval != 0) || !*handle) {
		REDEBUG("database query error on '%s'", query);
		return 0;
	}

	if (data->sql->fetch_row(&row, data->sql, request, handle) < 0) {
		REDEBUG("Failed fetching query result");
		goto finish;
	}

	if (!row) {
		REDEBUG("SQL query did not return any results");
		goto finish;
	}

	if (!row[0]) {
		REDEBUG("The first column of the result was NULL");
		goto finish;
	}

	rlen = strlen(row[0]);
	if (rlen >= outlen) {
		RDEBUG2("insufficient string space");
		goto finish;
	}

	strcpy(out, row[0]);
	retval = rlen;

finish:
	(data->sql->driver->sql_finish_select_query)(*handle, &data->sql->config);

	return retval;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_sqlippool_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	inst->name = talloc_asprintf(inst, "%s - %s", mctx->inst->name, inst->sql_name);

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
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	module_instance_t	*sql;
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	CONF_SECTION		*conf = mctx->inst->conf;
	char const		*pool_name = NULL;

	pool_name = cf_section_name2(conf);
	if (pool_name != NULL) {
		inst->pool_name = talloc_typed_strdup(inst, pool_name);
	} else {
		inst->pool_name = talloc_typed_strdup(inst, "ippool");
	}
	sql = module_rlm_by_name(NULL, inst->sql_name);
	if (!sql) {
		cf_log_err(conf, "failed to find sql instance named %s",
			   inst->sql_name);
		return -1;
	}

	inst->allocated_address_da = fr_dict_attr_search_by_qualified_oid(NULL, dict_freeradius,
									  inst->allocated_address_attr, false, false);
	if (!inst->allocated_address_da) {
		cf_log_perr(conf, "Failed resolving attribute");
		return -1;
	}

	switch (inst->allocated_address_da->type) {
	default:
		cf_log_err(conf, "Cannot use non-IP attributes for 'allocated_address_attr = %s'", inst->allocated_address_attr);
		return -1;

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
		break;
	}

	if (inst->requested_address) {
		if (!tmpl_is_xlat(inst->requested_address)) {
			cf_log_err(conf, "requested_address must be a double quoted expansion, not %s",
				   tmpl_type_to_str(inst->requested_address->type));
		}
	}

	inst->sql = (rlm_sql_t *) sql->dl_inst->data;

	if (strcmp(talloc_get_name(inst->sql), "rlm_sql_t") != 0) {
		cf_log_err(conf, "Module \"%s\" is not an instance of the rlm_sql module",
			      inst->sql_name);
		return -1;
	}

	return 0;
}


/*
 *	If we have something to log, then we log it.
 *	Otherwise we return the retcode as soon as possible
 */
static unlang_action_t do_logging(rlm_rcode_t *p_result, UNUSED rlm_sqlippool_t const *inst, request_t *request,
				  char const *str, rlm_rcode_t rcode)
{
	char		*expanded = NULL;
	fr_pair_t	*vp;

	if (!str || !*str) RETURN_MODULE_RCODE(rcode);

	MEM(pair_append_request(&vp, attr_module_success_message) == 0);
	if (xlat_aeval(vp, &expanded, request, str, NULL, NULL) < 0) {
		pair_delete_request(vp);
		RETURN_MODULE_RCODE(rcode);
	}
	fr_pair_value_bstrdup_buffer_shallow(vp, expanded, true);

	RETURN_MODULE_RCODE(rcode);
}


/*
 *	Allocate an IP number from the pool.
 */
static unlang_action_t CC_HINT(nonnull) mod_alloc(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	char			allocation[FR_MAX_STRING_LEN];
	int			allocation_len;
	fr_pair_t		*vp = NULL;
	rlm_sql_handle_t	*handle;

	/*
	 *	If there is a Framed-IP-Address attribute in the reply do nothing
	 */
	if (fr_pair_find_by_da(&request->reply_pairs, NULL, inst->allocated_address_da) != NULL) {
		RDEBUG2("%s already exists", inst->allocated_address_da->name);

		return do_logging(p_result, inst, request, inst->log_exists, RLM_MODULE_NOOP);
	}

	if (fr_pair_find_by_da(&request->control_pairs, NULL, attr_pool_name) == NULL) {
		RDEBUG2("No %s defined", attr_pool_name->name);

		return do_logging(p_result, inst, request, inst->log_nopool, RLM_MODULE_NOOP);
	}

	handle = fr_pool_connection_get(inst->sql->pool, request);
	if (!handle) {
		REDEBUG("Failed reserving SQL connection");
		RETURN_MODULE_FAIL;
	}

	if (inst->sql->sql_set_user(inst->sql, request, NULL) < 0) {
		RETURN_MODULE_FAIL;
	}

	DO_PART(alloc_begin);

	/*
	 *	If there is a query for finding the existing IP
	 *	run that first
	 */
	if (inst->alloc_existing && *inst->alloc_existing) {
		allocation_len = sqlippool_query1(allocation, sizeof(allocation),
						  inst->alloc_existing, &handle,
						  inst, request, (char *) NULL, 0);
		if (!handle) RETURN_MODULE_FAIL;
	} else {
		allocation_len = 0;
	}

	/*
	 *	If no existing IP was found and we have a requested IP address
	 *	and a query to find whether it is available then try that
	 */
	if ((allocation_len == 0) && inst->alloc_requested && *inst->alloc_requested) {
		char buffer[128];
		char *ip = NULL;
		ssize_t slen;

		slen = tmpl_expand(&ip, buffer, sizeof(buffer), request, inst->requested_address, NULL, NULL);
		if (slen < 0) RETURN_MODULE_FAIL;

		if (slen > 0) {
			allocation_len = sqlippool_query1(allocation, sizeof(allocation),
							  inst->alloc_requested, &handle,
							  inst, request, (char *) NULL, 0);
			if (!handle) RETURN_MODULE_FAIL;
		}
	}

	/*
	 *	If no existing IP was found (or no query was run),
	 *	run the query to find a free IP
	 */
	if (allocation_len == 0) {
		allocation_len = sqlippool_query1(allocation, sizeof(allocation),
						  inst->alloc_find, &handle,
						  inst, request, (char *) NULL, 0);
		if (!handle) RETURN_MODULE_FAIL;
	}

	/*
	 *	Nothing found...
	 */
	if (allocation_len == 0) {
		DO_PART(alloc_commit);

		/*
		 *Should we perform pool-check ?
		 */
		if (inst->pool_check && *inst->pool_check) {

			/*
			 *Ok, so the allocate-find query found nothing ...
			 *Let's check if the pool exists at all
			 */
			allocation_len = sqlippool_query1(allocation, sizeof(allocation),
							  inst->pool_check, &handle, inst, request,
							  (char *) NULL, 0);
			if (!handle) RETURN_MODULE_FAIL;

			fr_pool_connection_release(inst->sql->pool, request, handle);

			if (allocation_len) {

				/*
				 *	Pool exists after all... So,
				 *	the failure to allocate the IP
				 *	address was most likely due to
				 *	the depletion of the pool. In
				 *	that case, we should return
				 *	NOTFOUND
				 */
				RDEBUG2("pool appears to be full");
				return do_logging(p_result, inst, request, inst->log_failed, RLM_MODULE_NOTFOUND);
			}

			/*
			 *	Pool doesn't exist in the table. It
			 *	may be handled by some other instance of
			 *	sqlippool, so we should just ignore this
			 *	allocation failure and return NOOP
			 */
			RDEBUG2("IP address could not be allocated as no pool exists with that name");
			RETURN_MODULE_NOOP;

		}

		fr_pool_connection_release(inst->sql->pool, request, handle);

		RDEBUG2("IP address could not be allocated");
		return do_logging(p_result, inst, request, inst->log_failed, RLM_MODULE_NOOP);
	}

	/*
	 *	See if we can create the VP from the returned data.  If not,
	 *	error out.  If so, add it to the list.
	 */
	MEM(vp = fr_pair_afrom_da(request->reply_ctx, inst->allocated_address_da));
	if (fr_pair_value_from_str(vp, allocation, allocation_len, NULL, true) < 0) {
		DO_PART(alloc_commit);

		talloc_free(vp);
		RDEBUG2("Invalid IP number [%s] returned from instbase query.", allocation);
		fr_pool_connection_release(inst->sql->pool, request, handle);
		return do_logging(p_result, inst, request, inst->log_failed, RLM_MODULE_NOOP);
	}

	/*
	 *	UPDATE
	 */
	if (sqlippool_command(inst->alloc_update, &handle, inst, request,
			      allocation, allocation_len) < 0) {
	error:
		talloc_free(vp);
		if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
		RETURN_MODULE_FAIL;
	}

	DO_PART(alloc_commit);

	RDEBUG2("Allocated IP %s", allocation);
	fr_pair_append(&request->reply_pairs, vp);

	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);

	return do_logging(p_result, inst, request, inst->log_success, RLM_MODULE_OK);
}

/*
 *	Update a lease.
 */
static unlang_action_t CC_HINT(nonnull) mod_update(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	rlm_sql_handle_t	*handle;
	int			affected;

	handle = fr_pool_connection_get(inst->sql->pool, request);
	if (!handle) {
		REDEBUG("Failed reserving SQL connection");
		RETURN_MODULE_FAIL;
	}

	if (inst->sql->sql_set_user(inst->sql, request, NULL) < 0) {
		RETURN_MODULE_FAIL;
	}

	DO_PART(update_begin);

	/*
	 *  An optional query which can be used to tidy up before updates
	 *  primarily intended for multi-server setups sharing a common database
	 *  allowing for tidy up of multiple offered addresses in a DHCP context.
	 */
	DO_PART(update_free);

	affected = sqlippool_command(inst->update_update, &handle, inst, request, NULL, 0);

	if (affected < 0) {
	error:
		if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
		RETURN_MODULE_FAIL;
	}

	DO_PART(update_commit);

	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);

	if (affected > 0) {
		/*
		 * The lease has been updated - return OK
		 */
		return do_logging(p_result, inst, request, inst->log_success, RLM_MODULE_OK);
	} else {
		/*
		 * The lease could not be updated - return notfound
		 */
		return do_logging(p_result, inst, request, inst->log_failed, RLM_MODULE_NOTFOUND);
	}
}

/*
 *	Release a lease.
 */
static unlang_action_t CC_HINT(nonnull) mod_release(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	rlm_sql_handle_t	*handle;

	handle = fr_pool_connection_get(inst->sql->pool, request);
	if (!handle) {
		REDEBUG("Failed reserving SQL connection");
		RETURN_MODULE_FAIL;
	}

	if (inst->sql->sql_set_user(inst->sql, request, NULL) < 0) {
		RETURN_MODULE_FAIL;
	}

	DO_PART(release_begin);
	DO_PART(release_clear);
	DO_PART(release_commit);

	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
	RETURN_MODULE_OK;

	error:
	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
	RETURN_MODULE_FAIL;
}

/*
 *	Release a collection of leases.
 */
static unlang_action_t CC_HINT(nonnull) mod_bulk_release(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	rlm_sql_handle_t	*handle;

	handle = fr_pool_connection_get(inst->sql->pool, request);
	if (!handle) {
		REDEBUG("Failed reserving SQL connection");
		RETURN_MODULE_FAIL;
	}

	if (inst->sql->sql_set_user(inst->sql, request, NULL) < 0) {
		RETURN_MODULE_FAIL;
	}

	DO_PART(bulk_release_begin);
	DO_PART(bulk_release_clear);
	DO_PART(bulk_release_commit);

	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
	RETURN_MODULE_OK;

	error:
	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
	RETURN_MODULE_FAIL;
}

/*
 *	Mark a lease.  Typically for DHCP Decline where IPs need to be marked
 *	as invalid
 */
static unlang_action_t CC_HINT(nonnull) mod_mark(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	rlm_sql_handle_t	*handle;

	handle = fr_pool_connection_get(inst->sql->pool, request);
	if (!handle) {
		REDEBUG("Failed reserving SQL connection");
		RETURN_MODULE_FAIL;
	}

	if (inst->sql->sql_set_user(inst->sql, request, NULL) < 0) {
		RETURN_MODULE_FAIL;
	}

	DO_PART(mark_begin);
	DO_PART(mark_update);
	DO_PART(mark_commit);

	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
	RETURN_MODULE_OK;

	error:
	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
	RETURN_MODULE_FAIL;
}

/*
 *	Check Accounting packets for their accounting status
 *	Call the relevant module based on the status
 */
static unlang_action_t CC_HINT(nonnull) mod_accounting(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_pair_t		*vp;

	int			acct_status_type;

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_acct_status_type);
	if (!vp) {
		RDEBUG2("Could not find account status type in packet");
		RETURN_MODULE_NOOP;
	}
	acct_status_type = vp->vp_uint32;

	switch (acct_status_type) {
	case FR_STATUS_START:
	case FR_STATUS_ALIVE:
		return mod_update(p_result, mctx, request);

	case FR_STATUS_STOP:
		return mod_release(p_result, mctx, request);

	case FR_STATUS_ACCOUNTING_ON:
	case FR_STATUS_ACCOUNTING_OFF:
		return mod_bulk_release(p_result, mctx, request);

        default:
		/* We don't care about any other accounting packet */
		RETURN_MODULE_NOOP;
	}
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_sqlippool;
module_rlm_t rlm_sqlippool = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "sqlippool",
		.flags		= MODULE_TYPE_THREAD_SAFE,
		.inst_size	= sizeof(rlm_sqlippool_t),
		.config		= module_config,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate
	},
	.method_names = (module_method_name_t[]){
		{ .name1 = "accounting",	.name2 = CF_IDENT_ANY,		.method = mod_accounting },
		{ .name1 = "send",		.name2 = CF_IDENT_ANY,		.method = mod_alloc },

		{ .name1 = "recv",		.name2 = "Discover",		.method = mod_alloc },
		{ .name1 = "recv",		.name2 = "Request",		.method = mod_update },
		{ .name1 = "recv",		.name2 = "Confirm",		.method = mod_update },
		{ .name1 = "recv",		.name2 = "Rebind",		.method = mod_update },
		{ .name1 = "recv",		.name2 = "Renew",		.method = mod_update },
		{ .name1 = "recv",		.name2 = "Release",		.method = mod_release },
		{ .name1 = "recv",		.name2 = "Decline",		.method = mod_mark },

		{ .name1 = "ippool",		.name2 = "alloc",		.method = mod_alloc },
		{ .name1 = "ippool",		.name2 = "update",		.method = mod_update },
		{ .name1 = "ippool",		.name2 = "release",		.method = mod_release },
		{ .name1 = "ippool",		.name2 = "bulk-release",	.method = mod_bulk_release },
		{ .name1 = "ippool",		.name2 = "mark",		.method = mod_mark },

		MODULE_NAME_TERMINATOR
	}

};
