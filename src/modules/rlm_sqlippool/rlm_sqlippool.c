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

#define LOG_PREFIX "rlm_sql_ippool (%s) - "
#define LOG_PREFIX_ARGS inst->sql_instance_name

#include <rlm_sql.h>
#include <freeradius-devel/util/debug.h>

#include <ctype.h>


#define MAX_QUERY_LEN 4096

/*
 *	Define a structure for our module configuration.
 */
typedef struct {
	char const	*sql_instance_name;

	uint32_t	lease_duration;

	rlm_sql_t const	*sql_inst;

	char const	*pool_name;
	fr_dict_attr_t const *framed_ip_address; //!< the attribute for IP address allocation
	char const	*attribute_name;	//!< name of the IP address attribute
	fr_dict_attr_t const *req_framed_ip_address; //!< the attribute for requested IP address
	char const	*req_attribute_name;	//!< name of the requested IP address attribute

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

static CONF_PARSER message_config[] = {
	{ FR_CONF_OFFSET("exists", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, log_exists) },
	{ FR_CONF_OFFSET("success", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, log_success) },
	{ FR_CONF_OFFSET("clear", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, log_clear) },
	{ FR_CONF_OFFSET("failed", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, log_failed) },
	{ FR_CONF_OFFSET("nopool", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, log_nopool) },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("sql_module_instance", FR_TYPE_STRING | FR_TYPE_REQUIRED, rlm_sqlippool_t, sql_instance_name), .dflt = "sql" },

	{ FR_CONF_OFFSET("lease_duration", FR_TYPE_UINT32, rlm_sqlippool_t, lease_duration), .dflt = "86400" },

	{ FR_CONF_OFFSET("pool_name", FR_TYPE_STRING, rlm_sqlippool_t, pool_name) },

	{ FR_CONF_OFFSET("attribute_name", FR_TYPE_STRING | FR_TYPE_REQUIRED | FR_TYPE_NOT_EMPTY, rlm_sqlippool_t, attribute_name), .dflt = "Framed-IP-Address" },

	{ FR_CONF_OFFSET("req_attribute_name", FR_TYPE_STRING, rlm_sqlippool_t, req_attribute_name) },

	{ FR_CONF_OFFSET("default_pool", FR_TYPE_STRING, rlm_sqlippool_t, defaultpool), .dflt = "main_pool" },


	{ FR_CONF_OFFSET("alloc_begin", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, alloc_begin), .dflt = "START TRANSACTION" },

	{ FR_CONF_OFFSET("alloc_existing", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, alloc_existing) },

	{ FR_CONF_OFFSET("alloc_requested", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, alloc_requested) },

	{ FR_CONF_OFFSET("alloc_find", FR_TYPE_STRING | FR_TYPE_XLAT | FR_TYPE_REQUIRED, rlm_sqlippool_t, alloc_find) },

	{ FR_CONF_OFFSET("alloc_update", FR_TYPE_STRING | FR_TYPE_XLAT , rlm_sqlippool_t, alloc_update) },

	{ FR_CONF_OFFSET("alloc_commit", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, alloc_commit), .dflt = "COMMIT" },


	{ FR_CONF_OFFSET("pool_check", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, pool_check) },


	{ FR_CONF_OFFSET("update_begin", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, update_begin) },

	{ FR_CONF_OFFSET("update_free", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, update_free) },

	{ FR_CONF_OFFSET("update_update", FR_TYPE_STRING | FR_TYPE_XLAT , rlm_sqlippool_t, update_update) },

	{ FR_CONF_OFFSET("update_commit", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, update_commit) },


	{ FR_CONF_OFFSET("release_begin", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, release_begin) },

	{ FR_CONF_OFFSET("release_clear", FR_TYPE_STRING | FR_TYPE_XLAT , rlm_sqlippool_t, release_clear) },

	{ FR_CONF_OFFSET("release_commit", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, release_commit) },


	{ FR_CONF_OFFSET("bulk_release_begin", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, bulk_release_begin) },

	{ FR_CONF_OFFSET("bulk_release_clear", FR_TYPE_STRING | FR_TYPE_XLAT , rlm_sqlippool_t, bulk_release_clear) },

	{ FR_CONF_OFFSET("bulk_release_commit", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, bulk_release_commit) },


	{ FR_CONF_OFFSET("mark_begin", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, mark_begin) },

	{ FR_CONF_OFFSET("mark_update", FR_TYPE_STRING | FR_TYPE_XLAT , rlm_sqlippool_t, mark_update) },

	{ FR_CONF_OFFSET("mark_commit", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_sqlippool_t, mark_commit) },


	{ FR_CONF_POINTER("messages", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) message_config },
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
	{ .out = &attr_pool_name, .name = "Pool-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
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
				sprintf(tmp, "%u", data->lease_duration);
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
			     rlm_sqlippool_t const *data, REQUEST *request,
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

	if (xlat_aeval(request, &expanded, request, query, data->sql_inst->sql_escape_func, *handle) < 0) return -1;

	ret = data->sql_inst->sql_query(data->sql_inst, request, handle, expanded);
	if (ret < 0){
		talloc_free(expanded);
		return -1;
	}
	talloc_free(expanded);

	/*
	 *	No handle, we can't continue.
	 */
	if (!*handle) return -1;

	affected = (data->sql_inst->driver->sql_affected_rows)(*handle, data->sql_inst->config);

	(data->sql_inst->driver->sql_finish_query)(*handle, data->sql_inst->config);

	return affected;
}

/*
 *	Don't repeat yourself
 */
#undef DO
#define DO(_x) if(sqlippool_command(inst->_x, handle, inst, request, NULL, 0) < 0) return RLM_MODULE_FAIL
#define DO_PART(_x) if(sqlippool_command(inst->_x, &handle, inst, request, NULL, 0) <0) goto error

/*
 * Query the database expecting a single result row
 */
static int CC_HINT(nonnull (1, 3, 4, 5)) sqlippool_query1(char *out, int outlen, char const *fmt,
							  rlm_sql_handle_t **handle, rlm_sqlippool_t *data,
							  REQUEST *request, char *param, int param_len)
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
	if (xlat_aeval(request, &expanded, request, query, data->sql_inst->sql_escape_func, *handle) < 0) {
		return 0;
	}
	retval = data->sql_inst->sql_select_query(data->sql_inst, request, handle, expanded);
	talloc_free(expanded);

	if ((retval != 0) || !*handle) {
		REDEBUG("database query error on '%s'", query);
		return 0;
	}

	if (data->sql_inst->sql_fetch_row(&row, data->sql_inst, request, handle) < 0) {
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
	(data->sql_inst->driver->sql_finish_select_query)(*handle, data->sql_inst->config);

	return retval;
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
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	module_instance_t	*sql_inst;
	rlm_sqlippool_t		*inst = instance;
	char const		*pool_name = NULL;

	pool_name = cf_section_name2(conf);
	if (pool_name != NULL) {
		inst->pool_name = talloc_typed_strdup(inst, pool_name);
	} else {
		inst->pool_name = talloc_typed_strdup(inst, "ippool");
	}
	sql_inst = module_by_name(NULL, inst->sql_instance_name);
	if (!sql_inst) {
		cf_log_err(conf, "failed to find sql instance named %s",
			   inst->sql_instance_name);
		return -1;
	}

	if (fr_dict_attr_by_qualified_name(&inst->framed_ip_address,
					   dict_freeradius, inst->attribute_name, false) != FR_DICT_ATTR_OK) {
		cf_log_perr(conf, "Failed resolving attribute");
		return -1;
	}

	switch (inst->framed_ip_address->type) {
	default:
		cf_log_err(conf, "Cannot use non-IP attributes for 'attribute_name = %s'", inst->attribute_name);
		return -1;

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
		break;
	}

	if (inst->req_attribute_name) {
		if (fr_dict_attr_by_qualified_name(&inst->req_framed_ip_address,
						   dict_freeradius, inst->req_attribute_name, false) != FR_DICT_ATTR_OK) {
			cf_log_perr(conf, "Failed resolving requested attribute");
			return -1;
		}

		switch (inst->req_framed_ip_address->type) {
		default:
			cf_log_err(conf, "Cannot use non-IP attributes for 'req_attribute_name = %s'", inst->req_attribute_name);
			return -1;

		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_IPV4_PREFIX:
		case FR_TYPE_IPV6_ADDR:
		case FR_TYPE_IPV6_PREFIX:
			break;
		}
	}

	inst->sql_inst = (rlm_sql_t *) sql_inst->dl_inst->data;

	if (strcmp(cf_section_name1(inst->sql_inst->cs), "sql") != 0) {
		cf_log_err(conf, "Module \"%s\" is not an instance of the rlm_sql module",
			      inst->sql_instance_name);
		return -1;
	}

	return 0;
}


/*
 *	If we have something to log, then we log it.
 *	Otherwise we return the retcode as soon as possible
 */
static int do_logging(UNUSED rlm_sqlippool_t const *inst, REQUEST *request, char const *str, int rcode)
{
	char		*expanded = NULL;
	fr_pair_t	*vp;

	if (!str || !*str) return rcode;

	MEM(pair_add_request(&vp, attr_module_success_message) == 0);
	if (xlat_aeval(request, &expanded, request, str, NULL, NULL) < 0) {
		pair_delete_request(vp);
		return rcode;
	}
	fr_pair_value_bstrdup_buffer_shallow(vp, expanded, true);

	return rcode;
}


/*
 *	Allocate an IP number from the pool.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_alloc(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->instance, rlm_sqlippool_t);
	char			allocation[FR_MAX_STRING_LEN];
	int			allocation_len;
	fr_pair_t		*vp;
	rlm_sql_handle_t	*handle;

	/*
	 *	If there is a Framed-IP-Address attribute in the reply do nothing
	 */
	if (fr_pair_find_by_da(request->reply_pairs, inst->framed_ip_address) != NULL) {
		RDEBUG2("%s already exists", inst->framed_ip_address->name);

		return do_logging(inst, request, inst->log_exists, RLM_MODULE_NOOP);
	}

	if (fr_pair_find_by_da(request->control_pairs, attr_pool_name) == NULL) {
		RDEBUG2("No %s defined", attr_pool_name->name);

		return do_logging(inst, request, inst->log_nopool, RLM_MODULE_NOOP);
	}

	handle = fr_pool_connection_get(inst->sql_inst->pool, request);
	if (!handle) {
		REDEBUG("Failed reserving SQL connection");
		return RLM_MODULE_FAIL;
	}

	if (inst->sql_inst->sql_set_user(inst->sql_inst, request, NULL) < 0) {
		return RLM_MODULE_FAIL;
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
		if (!handle) return RLM_MODULE_FAIL;
	} else {
		allocation_len = 0;
	}

	/*
	 *	If no existing IP was found and we have a requested IP address
	 *	and a query to find whether it is available then try that
	 */
	if (allocation_len == 0 && inst->alloc_requested && *inst->alloc_requested &&
	    fr_pair_find_by_da(request->request_pairs, inst->req_framed_ip_address) != NULL) {
		allocation_len = sqlippool_query1(allocation, sizeof(allocation),
						  inst->alloc_requested, &handle,
						  inst, request, (char *) NULL, 0);
		if (!handle) return RLM_MODULE_FAIL;
	}


	/*
	 *	If no existing IP was found (or no query was run),
	 *	run the query to find a free IP
	 */
	if (allocation_len == 0) {
		allocation_len = sqlippool_query1(allocation, sizeof(allocation),
						  inst->alloc_find, &handle,
						  inst, request, (char *) NULL, 0);
		if (!handle) return RLM_MODULE_FAIL;
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
			if (!handle) return RLM_MODULE_FAIL;

			fr_pool_connection_release(inst->sql_inst->pool, request, handle);

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
				return do_logging(inst, request, inst->log_failed, RLM_MODULE_NOTFOUND);

			}

			/*
			 *	Pool doesn't exist in the table. It
			 *	may be handled by some other instance of
			 *	sqlippool, so we should just ignore this
			 *	allocation failure and return NOOP
			 */
			RDEBUG2("IP address could not be allocated as no pool exists with that name");
			return RLM_MODULE_NOOP;

		}

		fr_pool_connection_release(inst->sql_inst->pool, request, handle);

		RDEBUG2("IP address could not be allocated");
		return do_logging(inst, request, inst->log_failed, RLM_MODULE_NOOP);
	}

	/*
	 *	See if we can create the VP from the returned data.  If not,
	 *	error out.  If so, add it to the list.
	 */
	MEM(vp = fr_pair_afrom_da(request->reply, inst->framed_ip_address));
	if (fr_pair_value_from_str(vp, allocation, allocation_len, '\0', true) < 0) {
		DO_PART(alloc_commit);

		RDEBUG2("Invalid IP number [%s] returned from instbase query.", allocation);
		fr_pool_connection_release(inst->sql_inst->pool, request, handle);
		return do_logging(inst, request, inst->log_failed, RLM_MODULE_NOOP);
	}

	RDEBUG2("Allocated IP %s", allocation);
	fr_pair_add(&request->reply_pairs, vp);

	/*
	 *	UPDATE
	 */
	if (sqlippool_command(inst->alloc_update, &handle, inst, request,
			      allocation, allocation_len) < 0) {
	error:
		if (handle) fr_pool_connection_release(inst->sql_inst->pool, request, handle);
		return RLM_MODULE_FAIL;
	}

	DO_PART(alloc_commit);

	if (handle) fr_pool_connection_release(inst->sql_inst->pool, request, handle);

	return do_logging(inst, request, inst->log_success, RLM_MODULE_OK);
}

/*
 *	Update a lease.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_update(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->instance, rlm_sqlippool_t);
	rlm_sql_handle_t	*handle;
	int			affected;

	handle = fr_pool_connection_get(inst->sql_inst->pool, request);
	if (!handle) {
		REDEBUG("Failed reserving SQL connection");
		return RLM_MODULE_FAIL;
	}

	if (inst->sql_inst->sql_set_user(inst->sql_inst, request, NULL) < 0) {
		return RLM_MODULE_FAIL;
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
		if (handle) fr_pool_connection_release(inst->sql_inst->pool, request, handle);
		return RLM_MODULE_FAIL;
	}

	DO_PART(update_commit);

	if (handle) fr_pool_connection_release(inst->sql_inst->pool, request, handle);

	if (affected > 0) {
		/*
		 * The lease has been updated - return OK
		 */
		return do_logging(inst, request, inst->log_success, RLM_MODULE_OK);
	} else {
		/*
		 * The lease could not be updated - return notfound
		 */
		return do_logging(inst, request, inst->log_failed, RLM_MODULE_NOTFOUND);
	}
}

/*
 *	Release a lease.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_release(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->instance, rlm_sqlippool_t);
	rlm_sql_handle_t	*handle;

	handle = fr_pool_connection_get(inst->sql_inst->pool, request);
	if (!handle) {
		REDEBUG("Failed reserving SQL connection");
		return RLM_MODULE_FAIL;
	}

	if (inst->sql_inst->sql_set_user(inst->sql_inst, request, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	DO_PART(release_begin);
	DO_PART(release_clear);
	DO_PART(release_commit);

	if (handle) fr_pool_connection_release(inst->sql_inst->pool, request, handle);
	return RLM_MODULE_OK;

	error:
	if (handle) fr_pool_connection_release(inst->sql_inst->pool, request, handle);
	return RLM_MODULE_FAIL;
}

/*
 *	Release a collection of leases.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_bulk_release(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->instance, rlm_sqlippool_t);
	rlm_sql_handle_t	*handle;

	handle = fr_pool_connection_get(inst->sql_inst->pool, request);
	if (!handle) {
		REDEBUG("Failed reserving SQL connection");
		return RLM_MODULE_FAIL;
	}

	if (inst->sql_inst->sql_set_user(inst->sql_inst, request, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	DO_PART(bulk_release_begin);
	DO_PART(bulk_release_clear);
	DO_PART(bulk_release_commit);

	if (handle) fr_pool_connection_release(inst->sql_inst->pool, request, handle);
	return RLM_MODULE_OK;

	error:
	if (handle) fr_pool_connection_release(inst->sql_inst->pool, request, handle);
	return RLM_MODULE_FAIL;
}

/*
 *	Mark a lease.  Typically for DHCP Decline where IPs need to be marked
 *	as invalid
 */
static rlm_rcode_t CC_HINT(nonnull) mod_mark(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->instance, rlm_sqlippool_t);
	rlm_sql_handle_t	*handle;

	handle = fr_pool_connection_get(inst->sql_inst->pool, request);
	if (!handle) {
		REDEBUG("Failed reserving SQL connection");
		return RLM_MODULE_FAIL;
	}

	if (inst->sql_inst->sql_set_user(inst->sql_inst, request, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	DO_PART(mark_begin);
	DO_PART(mark_update);
	DO_PART(mark_commit);

	if (handle) fr_pool_connection_release(inst->sql_inst->pool, request, handle);
	return RLM_MODULE_OK;

	error:
	if (handle) fr_pool_connection_release(inst->sql_inst->pool, request, handle);
	return RLM_MODULE_FAIL;
}

/*
 *	Check Accounting packets for their accoutning status
 *	Call the relevant module based on the status
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(module_ctx_t const *mctx, REQUEST *request)
{
	int			rcode = RLM_MODULE_NOOP;
	fr_pair_t		*vp;

	int			acct_status_type;

	vp = fr_pair_find_by_da(request->request_pairs, attr_acct_status_type);
	if (!vp) {
		RDEBUG2("Could not find account status type in packet");
		return RLM_MODULE_NOOP;
	}
	acct_status_type = vp->vp_uint32;


	switch (acct_status_type) {
	case FR_STATUS_START:
	case FR_STATUS_ALIVE:
		rcode = mod_update(mctx, request);
		break;

	case FR_STATUS_STOP:
		rcode = mod_release(mctx, request);
		break;

	case FR_STATUS_ACCOUNTING_ON:
	case FR_STATUS_ACCOUNTING_OFF:
		rcode = mod_bulk_release(mctx, request);
		break;

        default:
		/* We don't care about any other accounting packet */
		return RLM_MODULE_NOOP;
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
extern module_t rlm_sqlippool;
module_t rlm_sqlippool = {
	.magic		= RLM_MODULE_INIT,
	.name		= "sqlippool",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_sqlippool_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_POST_AUTH]		= mod_alloc
	},
	.method_names = (module_method_names_t[]){
		{ "recv",	"DHCP-Discover",	mod_alloc },
		{ "recv",	"DHCP-Request",		mod_update },
		{ "recv",	"DHCP-Release",		mod_release },
		{ "recv",	"DHCP-Decline",		mod_mark },

		{ "ippool",	"alloc",		mod_alloc },
		{ "ippool",	"update",		mod_update },
		{ "ippool",	"release",		mod_release },
		{ "ippool",	"bulk-release",		mod_bulk_release },
		{ "ippool",	"mark",			mod_mark },

		MODULE_NAME_TERMINATOR
	}

};
