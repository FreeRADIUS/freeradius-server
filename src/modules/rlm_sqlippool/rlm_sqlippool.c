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
 * @brief Allocates an IP address / prefix from pools stored in SQL.
 *
 * @copyright 2002  Globe.Net Communications Limited
 * @copyright 2006  The FreeRADIUS server project
 * @copyright 2006  Suntel Communications
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>

#include <rlm_sql.h>

#define MAX_QUERY_LEN 4096

/*
 *	Define a structure for our module configuration.
 */
typedef struct rlm_sqlippool_t {
	char const	*sql_instance_name;

	uint32_t	lease_duration;

	rlm_sql_t	*sql_inst;

	char const	*pool_name;
	bool		ipv6;			//!< Whether or not we do IPv6 pools.
	bool		allow_duplicates;	//!< assign even if it already exists
	char const	*attribute_name;	//!< name of the IP address attribute

	DICT_ATTR const *framed_ip_address; 	//!< the attribute for IP address allocation

	time_t		last_clear;		//!< So we only do it once a second.
	char const	*allocate_begin;	//!< SQL query to begin.
	char const	*allocate_clear;	//!< SQL query to clear an IP.
	char const	*allocate_find;		//!< SQL query to find an unused IP.
	char const	*allocate_update;	//!< SQL query to mark an IP as used.
	char const	*allocate_commit;	//!< SQL query to commit.

	char const	*pool_check;		//!< Query to check for the existence of the pool.

						/* Start sequence */
	char const	*start_begin;		//!< SQL query to begin.
	char const	*start_update;		//!< SQL query to update an IP entry.
	char const	*start_commit;		//!< SQL query to commit.

						/* Alive sequence */
	char const	*alive_begin;		//!< SQL query to begin.
	char const	*alive_update;		//!< SQL query to update an IP entry.
	char const	*alive_commit;		//!< SQL query to commit.

						/* Stop sequence */
	char const	*stop_begin;		//!< SQL query to begin.
	char const	*stop_clear;		//!< SQL query to clear an IP.
	char const	*stop_commit;		//!< SQL query to commit.

						/* On sequence */
	char const	*on_begin;		//!< SQL query to begin.
	char const	*on_clear;		//!< SQL query to clear an entire NAS.
	char const	*on_commit;		//!< SQL query to commit.

						/* Off sequence */
	char const	*off_begin;		//!< SQL query to begin.
	char const	*off_clear;		//!< SQL query to clear an entire NAS.
	char const	*off_commit;		//!< SQL query to commit.

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
	{ "exists", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, log_exists), NULL },
	{ "success", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, log_success), NULL },
	{ "clear", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, log_clear), NULL },
	{ "failed", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, log_failed), NULL },
	{ "nopool", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, log_nopool), NULL },
	CONF_PARSER_TERMINATOR
};

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static CONF_PARSER module_config[] = {
	{ "sql-instance-name", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, rlm_sqlippool_t, sql_instance_name), NULL },
	{ "sql_module_instance", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_sqlippool_t, sql_instance_name), "sql" },

	{ "lease-duration", FR_CONF_OFFSET(PW_TYPE_INTEGER | PW_TYPE_DEPRECATED, rlm_sqlippool_t, lease_duration), NULL },
	{ "lease_duration", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_sqlippool_t, lease_duration), "86400" },

	{ "pool-name", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, rlm_sqlippool_t, pool_name), NULL },
	{ "pool_name", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_sqlippool_t, pool_name), "" },

	{ "default-pool", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, rlm_sqlippool_t, defaultpool), NULL },
	{ "default_pool", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_sqlippool_t, defaultpool), "main_pool" },


	{ "ipv6", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_sqlippool_t, ipv6), NULL},
	{ "allow_duplicates", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_sqlippool_t, allow_duplicates), NULL},
	{ "attribute_name", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_sqlippool_t, attribute_name), NULL},

	{ "allocate-begin", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, allocate_begin), NULL },
	{ "allocate_begin", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, allocate_begin), "START TRANSACTION" },

	{ "allocate-clear", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, allocate_clear), NULL },
	{ "allocate_clear", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT , rlm_sqlippool_t, allocate_clear), ""  },

	{ "allocate-find", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, allocate_find), NULL },
	{ "allocate_find", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_REQUIRED, rlm_sqlippool_t, allocate_find), ""  },

	{ "allocate-update", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, allocate_update), NULL },
	{ "allocate_update", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT , rlm_sqlippool_t, allocate_update), ""  },

	{ "allocate-commit", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, allocate_commit), NULL },
	{ "allocate_commit", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, allocate_commit), "COMMIT" },


	{ "pool-check", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, pool_check), NULL },
	{ "pool_check", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, pool_check), ""  },


	{ "start-begin", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, start_begin), NULL },
	{ "start_begin", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, start_begin), "START TRANSACTION" },

	{ "start-update", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, start_update), NULL },
	{ "start_update", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT , rlm_sqlippool_t, start_update), ""  },

	{ "start-commit", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, start_commit), NULL },
	{ "start_commit", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, start_commit), "COMMIT" },


	{ "alive-begin", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, alive_begin), NULL },
	{ "alive_begin", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, alive_begin), "START TRANSACTION" },

	{ "alive-update", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, alive_update), NULL },
	{ "alive_update", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT , rlm_sqlippool_t, alive_update), ""  },

	{ "alive-commit", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, alive_commit), NULL },
	{ "alive_commit", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, alive_commit), "COMMIT" },


	{ "stop-begin", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, stop_begin), NULL },
	{ "stop_begin", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, stop_begin), "START TRANSACTION" },

	{ "stop-clear", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, stop_clear), NULL },
	{ "stop_clear", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT , rlm_sqlippool_t, stop_clear), ""  },

	{ "stop-commit", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, stop_commit), NULL },
	{ "stop_commit", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, stop_commit), "COMMIT" },


	{ "on-begin", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, on_begin), NULL },
	{ "on_begin", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, on_begin), "START TRANSACTION" },

	{ "on-clear", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, on_clear), NULL },
	{ "on_clear", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT , rlm_sqlippool_t, on_clear), ""  },

	{ "on-commit", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, on_commit), NULL },
	{ "on_commit", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, on_commit), "COMMIT" },


	{ "off-begin", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, off_begin), NULL },
	{ "off_begin", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, off_begin), "START TRANSACTION" },

	{ "off-clear", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, off_clear), NULL },
	{ "off_clear", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT , rlm_sqlippool_t, off_clear), ""  },

	{ "off-commit", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_DEPRECATED, rlm_sqlippool_t, off_commit), NULL },
	{ "off_commit", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_sqlippool_t, off_commit), "COMMIT" },

	{ "messages", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) message_config },
	CONF_PARSER_TERMINATOR
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
			    rlm_sqlippool_t *data, char * param, int param_len)
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
				sprintf(tmp, "%d", data->lease_duration);
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
 * @return 0 on success or < 0 on error.
 */
static int sqlippool_command(char const *fmt, rlm_sql_handle_t **handle,
			     rlm_sqlippool_t *data, REQUEST *request,
			     char *param, int param_len)
{
	char query[MAX_QUERY_LEN];
	char *expanded = NULL;

	int ret;

	/*
	 *	If we don't have a command, do nothing.
	 */
	if (!fmt || !*fmt) return 0;

	/*
	 *	@todo this needs to die (should just be done in xlat expansion)
	 */
	sqlippool_expand(query, sizeof(query), fmt, data, param, param_len);

	if (radius_axlat(&expanded, request, query, data->sql_inst->sql_escape_func, data->sql_inst) < 0) return -1;

	ret = data->sql_inst->sql_query(data->sql_inst, request, handle, expanded);
	if (ret < 0){
		talloc_free(expanded);
		return -1;
	}
	talloc_free(expanded);

	if (*handle) (data->sql_inst->module->sql_finish_query)(*handle, data->sql_inst->config);

	return 0;
}

/*
 *	Don't repeat yourself
 */
#undef DO
#define DO(_x) sqlippool_command(inst->_x, handle, inst, request, NULL, 0)
#define DO_PART(_x) sqlippool_command(inst->_x, &handle, inst, request, NULL, 0)

/*
 * Query the database expecting a single result row
 */
static int CC_HINT(nonnull (1, 3, 4, 5)) sqlippool_query1(char *out, int outlen, char const *fmt,
							  rlm_sql_handle_t *handle, rlm_sqlippool_t *data,
							  REQUEST *request, char *param, int param_len)
{
	char query[MAX_QUERY_LEN];
	char *expanded = NULL;

	int rlen, retval;

	/*
	 *	@todo this needs to die (should just be done in xlat expansion)
	 */
	sqlippool_expand(query, sizeof(query), fmt, data, param, param_len);

	*out = '\0';

	/*
	 *	Do an xlat on the provided string
	 */
	if (radius_axlat(&expanded, request, query, data->sql_inst->sql_escape_func, data->sql_inst) < 0) {
		return 0;
	}
	retval = data->sql_inst->sql_select_query(data->sql_inst, request, &handle, expanded);
	talloc_free(expanded);

	if (retval != 0){
		REDEBUG("database query error on '%s'", query);
		return 0;
	}

	if (data->sql_inst->sql_fetch_row(data->sql_inst, request, &handle) < 0) {
		REDEBUG("Failed fetching query result");
		goto finish;
	}

	if (!handle->row) {
		REDEBUG("SQL query did not return any results");
		goto finish;
	}

	if (!handle->row[0]) {
		REDEBUG("The first column of the result was NULL");
		goto finish;
	}

	rlen = strlen(handle->row[0]);
	if (rlen >= outlen) {
		RDEBUG("insufficient string space");
		goto finish;
	}

	strcpy(out, handle->row[0]);
	retval = rlen;
finish:
	(data->sql_inst->module->sql_finish_select_query)(handle, data->sql_inst->config);

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
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	module_instance_t *sql_inst;
	rlm_sqlippool_t *inst = instance;
	char const *pool_name = NULL;

	pool_name = cf_section_name2(conf);
	if (pool_name != NULL) {
		inst->pool_name = talloc_typed_strdup(inst, pool_name);
	} else {
		inst->pool_name = talloc_typed_strdup(inst, "ippool");
	}
	sql_inst = module_instantiate(cf_section_find("modules"),
					inst->sql_instance_name);
	if (!sql_inst) {
		cf_log_err_cs(conf, "failed to find sql instance named %s",
			   inst->sql_instance_name);
		return -1;
	}

	if (inst->attribute_name) {
		DICT_ATTR const *da;

		da = dict_attrbyname(inst->attribute_name);
		if (!da) {
		fail:
			cf_log_err_cs(conf, "Unknown attribute 'attribute_name = %s'", inst->attribute_name);
			return -1;
		}

		switch (da->type) {
		default:
			cf_log_err_cs(conf, "Cannot use non-IP attributes for 'attribute_name = %s'", inst->attribute_name);
			return -1;

		case PW_TYPE_IPV4_ADDR:
		case PW_TYPE_IPV6_ADDR:
		case PW_TYPE_IPV4_PREFIX:
		case PW_TYPE_IPV6_PREFIX:
			break;

		}

		inst->framed_ip_address = da;
	} else {
		if (!inst->ipv6) {
			inst->attribute_name = "Framed-IP-Address";
			inst->framed_ip_address = dict_attrbyvalue(PW_FRAMED_IP_ADDRESS, 0);
		} else {
			inst->attribute_name = "Framed-IPv6-Prefix";
			inst->framed_ip_address = dict_attrbyvalue(PW_FRAMED_IPV6_PREFIX, 0);
		}

		if (!inst->framed_ip_address) goto fail;
	}

	if (strcmp(sql_inst->entry->name, "rlm_sql") != 0) {
		cf_log_err_cs(conf, "Module \"%s\""
		       " is not an instance of the rlm_sql module",
		       inst->sql_instance_name);
		return -1;
	}

	inst->sql_inst = (rlm_sql_t *) sql_inst->insthandle;
	return 0;
}


/*
 *	If we have something to log, then we log it.
 *	Otherwise we return the retcode as soon as possible
 */
static int do_logging(REQUEST *request, char const *str, int rcode)
{
	char *expanded = NULL;

	if (!str || !*str) return rcode;

	if (radius_axlat(&expanded, request, str, NULL, NULL) < 0) {
		return rcode;
	}

	pair_make_config("Module-Success-Message", expanded, T_OP_SET);

	talloc_free(expanded);

	return rcode;
}


/*
 *	Allocate an IP number from the pool.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST *request)
{
	rlm_sqlippool_t *inst = (rlm_sqlippool_t *) instance;
	char allocation[MAX_STRING_LEN];
	int allocation_len;
	VALUE_PAIR *vp;
	rlm_sql_handle_t *handle;
	time_t now;

	/*
	 *	If there is already an attribute in the reply do nothing
	 */
	if (!inst->allow_duplicates && (fr_pair_find_by_num(request->reply->vps, inst->framed_ip_address->attr, inst->framed_ip_address->vendor, TAG_ANY) != NULL)) {
		RDEBUG("%s already exists", inst->attribute_name);

		return do_logging(request, inst->log_exists, RLM_MODULE_NOOP);
	}

	if (fr_pair_find_by_num(request->config, PW_POOL_NAME, 0, TAG_ANY) == NULL) {
		RDEBUG("No Pool-Name defined");

		return do_logging(request, inst->log_nopool, RLM_MODULE_NOOP);
	}

	handle = fr_connection_get(inst->sql_inst->pool);
	if (!handle) {
		REDEBUG("Failed reserving SQL connection");
		return RLM_MODULE_FAIL;
	}

	if (inst->sql_inst->sql_set_user(inst->sql_inst, request, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Limit the number of clears we do.  There are minor
	 *	race conditions for the check, but so what.  The
	 *	actual work is protected by a transaction.  The idea
	 *	here is that if we're allocating 100 IPs a second,
	 *	we're only do 1 CLEAR per second.
	 */
	now = time(NULL);
	if (inst->last_clear < now) {
		inst->last_clear = now;

		DO_PART(allocate_begin);
		DO_PART(allocate_clear);
		DO_PART(allocate_commit);
	}

	DO_PART(allocate_begin);

	allocation_len = sqlippool_query1(allocation, sizeof(allocation),
					  inst->allocate_find, handle,
					  inst, request, (char *) NULL, 0);

	/*
	 *	Nothing found...
	 */
	if (allocation_len == 0) {
		DO_PART(allocate_commit);

		/*
		 *Should we perform pool-check ?
		 */
		if (inst->pool_check && *inst->pool_check) {

			/*
			 *Ok, so the allocate-find query found nothing ...
			 *Let's check if the pool exists at all
			 */
			allocation_len = sqlippool_query1(allocation, sizeof(allocation),
							  inst->pool_check, handle, inst, request,
							  (char *) NULL, 0);

			fr_connection_release(inst->sql_inst->pool, handle);

			if (allocation_len) {

				/*
				 *	Pool exists after all... So,
				 *	the failure to allocate the IP
				 *	address was most likely due to
				 *	the depletion of the pool. In
				 *	that case, we should return
				 *	NOTFOUND
				 */
				RDEBUG("pool appears to be full");
				return do_logging(request, inst->log_failed, RLM_MODULE_NOTFOUND);

			}

			/*
			 *	Pool doesn't exist in the table. It
			 *	may be handled by some other instance of
			 *	sqlippool, so we should just ignore this
			 *	allocation failure and return NOOP
			 */
			RDEBUG("IP address could not be allocated as no pool exists with that name");
			return RLM_MODULE_NOOP;

		}

		fr_connection_release(inst->sql_inst->pool, handle);

		RDEBUG("IP address could not be allocated");
		return do_logging(request, inst->log_failed, RLM_MODULE_NOOP);
	}

	/*
	 *	See if we can create the VP from the returned data.  If not,
	 *	error out.  If so, add it to the list.
	 */
	vp = fr_pair_afrom_num(request->reply, inst->framed_ip_address->attr, inst->framed_ip_address->vendor);
	if (fr_pair_value_from_str(vp, allocation, allocation_len) < 0) {
		DO_PART(allocate_commit);

		RDEBUG("Invalid IP number [%s] returned from instbase query.", allocation);
		fr_connection_release(inst->sql_inst->pool, handle);
		return do_logging(request, inst->log_failed, RLM_MODULE_NOOP);
	}

	RDEBUG("Allocated IP %s", allocation);
	fr_pair_add(&request->reply->vps, vp);

	/*
	 *	UPDATE
	 */
	sqlippool_command(inst->allocate_update, &handle, inst, request,
			  allocation, allocation_len);

	DO_PART(allocate_commit);

	fr_connection_release(inst->sql_inst->pool, handle);

	return do_logging(request, inst->log_success, RLM_MODULE_OK);
}

static int mod_accounting_start(rlm_sql_handle_t **handle,
				rlm_sqlippool_t *inst, REQUEST *request)
{
	DO(start_begin);
	DO(start_update);
	DO(start_commit);

	return RLM_MODULE_OK;
}

static int mod_accounting_alive(rlm_sql_handle_t **handle,
				rlm_sqlippool_t *inst, REQUEST *request)
{
	DO(alive_begin);
	DO(alive_update);
	DO(alive_commit);
	return RLM_MODULE_OK;
}

static int mod_accounting_stop(rlm_sql_handle_t **handle,
			       rlm_sqlippool_t *inst, REQUEST *request)
{
	DO(stop_begin);
	DO(stop_clear);
	DO(stop_commit);

	return do_logging(request, inst->log_clear, RLM_MODULE_OK);
}

static int mod_accounting_on(rlm_sql_handle_t **handle,
			     rlm_sqlippool_t *inst, REQUEST *request)
{
	DO(on_begin);
	DO(on_clear);
	DO(on_commit);

	return RLM_MODULE_OK;
}

static int mod_accounting_off(rlm_sql_handle_t **handle,
			      rlm_sqlippool_t *inst, REQUEST *request)
{
	DO(off_begin);
	DO(off_clear);
	DO(off_commit);

	return RLM_MODULE_OK;
}

/*
 *	Check for an Accounting-Stop
 *	If we find one and we have allocated an IP to this nas/port
 *	combination, then deallocate it.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(void *instance, REQUEST *request)
{
	int			rcode = RLM_MODULE_NOOP;
	VALUE_PAIR		*vp;

	int			acct_status_type;

	rlm_sqlippool_t		*inst = (rlm_sqlippool_t *) instance;
	rlm_sql_handle_t	*handle;

	vp = fr_pair_find_by_num(request->packet->vps, PW_ACCT_STATUS_TYPE, 0, TAG_ANY);
	if (!vp) {
		RDEBUG("Could not find account status type in packet");
		return RLM_MODULE_NOOP;
	}
	acct_status_type = vp->vp_integer;

	switch (acct_status_type) {
	case PW_STATUS_START:
	case PW_STATUS_ALIVE:
	case PW_STATUS_STOP:
	case PW_STATUS_ACCOUNTING_ON:
	case PW_STATUS_ACCOUNTING_OFF:
		break;		/* continue through to the next section */

	default:
		/* We don't care about any other accounting packet */
		return RLM_MODULE_NOOP;
	}

	handle = fr_connection_get(inst->sql_inst->pool);
	if (!handle) {
		RDEBUG("Failed reserving SQL connection");
		return RLM_MODULE_FAIL;
	}

	if (inst->sql_inst->sql_set_user(inst->sql_inst, request, NULL) < 0) return RLM_MODULE_FAIL;

	switch (acct_status_type) {
	case PW_STATUS_START:
		rcode = mod_accounting_start(&handle, inst, request);
		break;

	case PW_STATUS_ALIVE:
		rcode = mod_accounting_alive(&handle, inst, request);
		break;

	case PW_STATUS_STOP:
		rcode = mod_accounting_stop(&handle, inst, request);
		break;

	case PW_STATUS_ACCOUNTING_ON:
		rcode = mod_accounting_on(&handle, inst, request);
		break;

	case PW_STATUS_ACCOUNTING_OFF:
		rcode = mod_accounting_off(&handle, inst, request);
		break;
	}

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
		[MOD_POST_AUTH]		= mod_post_auth
	},
};
