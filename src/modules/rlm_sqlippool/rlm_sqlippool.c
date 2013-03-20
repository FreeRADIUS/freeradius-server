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
 * @file rlm_sqlippool.c
 * @brief Allocates an IPv4 address from pools stored in SQL.
 *
 * @copyright 2002  Globe.Net Communications Limited
 * @copyright 2006  The FreeRADIUS server project
 * @copyright 2006  Suntel Communications
 */
#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <ctype.h>

#include <rlm_sql.h>

/*
 *	Define a structure for our module configuration.
 */
typedef struct rlm_sqlippool_t {
	char *sql_instance_name;

	int lease_duration;

	rlm_sql_t *sql_inst;

	char *pool_name;

	/* We ended up removing the init
	   queries so that its up to user
	   to create the db structure and put the required
	   information in there
	*/
				/* Allocation sequence */
	char *allocate_begin;	/* SQL query to begin */
	char *allocate_clear;	/* SQL query to clear an IP */
	char *allocate_find;	/* SQL query to find an unused IP */
	char *allocate_update;	/* SQL query to mark an IP as used */
	char *allocate_commit;	/* SQL query to commit */
	char *allocate_rollback; /* SQL query to rollback */

	char *pool_check;	/* Query to check for the existence of the pool */

				/* Start sequence */
	char *start_begin;	/* SQL query to begin */
	char *start_update;	/* SQL query to update an IP entry */
	char *start_commit;	/* SQL query to commit */
	char *start_rollback;	/* SQL query to rollback */

				/* Alive sequence */
	char *alive_begin;	/* SQL query to begin */
	char *alive_update;	/* SQL query to update an IP entry */
	char *alive_commit;	/* SQL query to commit */
	char *alive_rollback;	/* SQL query to rollback */

				/* Stop sequence */
	char *stop_begin;	/* SQL query to begin */
	char *stop_clear;	/* SQL query to clear an IP */
	char *stop_commit;	/* SQL query to commit */
	char *stop_rollback;	/* SQL query to rollback */

				/* On sequence */
	char *on_begin;		/* SQL query to begin */
	char *on_clear;		/* SQL query to clear an entire NAS */
	char *on_commit;	/* SQL query to commit */
	char *on_rollback;	/* SQL query to rollback */

				/* Off sequence */
	char *off_begin;	/* SQL query to begin */
	char *off_clear;	/* SQL query to clear an entire NAS */
	char *off_commit;	/* SQL query to commit */
	char *off_rollback;	/* SQL query to rollback */

				/* Logging Section */
	char *log_exists;	/* There was an ip address already assigned */
	char *log_success;	/* We successfully allocated ip address from pool */
	char *log_clear;	/* We successfully deallocated ip address from pool */
	char *log_failed;	/* Failed to allocate ip from the pool */
	char *log_nopool;	/* There was no Framed-IP-Address but also no Pool-Name */

				/* Reserved to handle 255.255.255.254 Requests */
	char *defaultpool;	/* Default Pool-Name if there is none in the check items */

} rlm_sqlippool_t;

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
  {"sql-instance-name",PW_TYPE_STRING_PTR,
   offsetof(rlm_sqlippool_t,sql_instance_name), NULL, "sql"},

  { "lease-duration", PW_TYPE_INTEGER,
    offsetof(rlm_sqlippool_t,lease_duration), NULL, "86400"},

  { "pool-name"	    , PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t, pool_name), NULL, ""},

  { "allocate-begin", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,allocate_begin), NULL, "START TRANSACTION" },
  { "allocate-clear", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,allocate_clear), NULL, "" },
  { "allocate-find", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,allocate_find), NULL, "" },
  { "allocate-update", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,allocate_update), NULL, "" },
  { "allocate-commit", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,allocate_commit), NULL, "COMMIT" },
  { "allocate-rollback", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,allocate_rollback), NULL, "ROLLBACK" },

  { "pool-check", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,pool_check), NULL, "" },

  { "start-begin", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,start_begin), NULL, "START TRANSACTION" },
  { "start-update", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,start_update), NULL, "" },
  { "start-commit", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,start_commit), NULL, "COMMIT" },
  { "start-rollback", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,start_rollback), NULL, "ROLLBACK" },

  { "alive-begin", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,alive_begin), NULL, "START TRANSACTION" },
  { "alive-update", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,alive_update), NULL, "" },
  { "alive-commit", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,alive_commit), NULL, "COMMIT" },
  { "alive-rollback", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,alive_rollback), NULL, "ROLLBACK" },

  { "stop-begin", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,stop_begin), NULL, "START TRANSACTION" },
  { "stop-clear", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,stop_clear), NULL, "" },
  { "stop-commit", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,stop_commit), NULL, "COMMIT" },
  { "stop-rollback", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,stop_rollback), NULL, "ROLLBACK" },

  { "on-begin", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,on_begin), NULL, "START TRANSACTION" },
  { "on-clear", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,on_clear), NULL, "" },
  { "on-commit", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,on_commit), NULL, "COMMIT" },
  { "on-rollback", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,on_rollback), NULL, "ROLLBACK" },

  { "off-begin", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,off_begin), NULL, "START TRANSACTION" },
  { "off-clear", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,off_clear), NULL, "" },
  { "off-commit", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,off_commit), NULL, "COMMIT" },
  { "off-rollback", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t,off_rollback), NULL, "ROLLBACK" },

  { "sqlippool_log_exists", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t, log_exists), NULL, "" },
  { "sqlippool_log_success", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t, log_success), NULL, "" },
  { "sqlippool_log_clear", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t, log_clear), NULL, "" },
  { "sqlippool_log_failed", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t, log_failed), NULL, "" },
  { "sqlippool_log_nopool", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t, log_nopool), NULL, "" },

  { "defaultpool", PW_TYPE_STRING_PTR,
    offsetof(rlm_sqlippool_t, defaultpool), NULL, "main_pool" },

  { NULL, -1, 0, NULL, NULL }
};

/*
 *	Replace %<whatever> in a string.
 *
 *	%P	pool_name
 *	%I	param
 *	%J	lease_duration
 *
 */
static int sqlippool_expand(char * out, int outlen, const char * fmt,
			    rlm_sqlippool_t *data, char * param, int param_len)
{
	char *q;
	const char *p;
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
		if (c != '%' && c != '$' && c != '\\') {
			*q++ = *p;
			continue;
		}

		if (*++p == '\0')
			break;

		if (c == '\\') {
			switch(*p) {
			case '\\':
				*q++ = '\\';
				break;
			case 't':
				*q++ = '\t';
				break;
			case 'n':
				*q++ = '\n';
				break;
			default:
				*q++ = c;
				*q++ = *p;
				break;
			}
		}
		else if (c == '%') {
			switch(*p) {
			case '%':
				*q++ = *p;
				break;
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
	DEBUG2("sqlippool_expand: '%s'", out);
#endif

	return strlen(out);
}

/*
 * Query the database executing a command with no result rows
 */
static int sqlippool_command(const char * fmt, rlm_sql_handle_t * handle,
			     rlm_sqlippool_t *data, REQUEST * request,
			     char * param, int param_len)
{
	char expansion[MAX_QUERY_LEN];
	char query[MAX_QUERY_LEN];

	sqlippool_expand(expansion, sizeof(expansion),
			 fmt, data, param, param_len);

	/*
	 * Do an xlat on the provided string
	 */
	if (request) {
		if (!radius_xlat(query, sizeof(query), expansion, request, data->sql_inst->sql_escape_func, data->sql_inst)) {
			radlog(L_ERR, "sqlippool_command: xlat failed on: '%s'", query);
			return 0;
		}
	} else {
		strcpy(query, expansion);
	}

#if 0
	DEBUG2("sqlippool_command: '%s'", query);
#endif
	if (data->sql_inst->sql_query(&handle, data->sql_inst, query)){
		radlog(L_ERR, "sqlippool_command: database query error in: '%s'", query);
		return 0;
	}

	(data->sql_inst->module->sql_finish_query)(handle,
						   data->sql_inst->config);
	return 0;
}

/*
 * Query the database expecting a single result row
 */
static int sqlippool_query1(char * out, int outlen, const char * fmt,
			    rlm_sql_handle_t * handle, rlm_sqlippool_t *data,
			    REQUEST * request, char * param, int param_len)
{
	char expansion[MAX_QUERY_LEN];
	char query[MAX_QUERY_LEN];
	int rlen, retval = 0;

	sqlippool_expand(expansion, sizeof(expansion),
			 fmt, data, param, param_len);

	/*
	 * Do an xlat on the provided string
	 */
	if (request) {
		if (!radius_xlat(query, sizeof(query), expansion, request, data->sql_inst->sql_escape_func, data->sql_inst)) {
			radlog(L_ERR, "sqlippool_command: xlat failed.");
			out[0] = '\0';
			return 0;
		}
	}
	else {
		strcpy(query, expansion);
	}

	if (data->sql_inst->sql_select_query(&handle, data->sql_inst, query)){
		radlog(L_ERR, "sqlippool_query1: database query error");
		out[0] = '\0';
		return 0;
	}

	out[0] = '\0';

	if (!data->sql_inst->sql_fetch_row(&handle, data->sql_inst)) {
		if (handle->row) {
			if (handle->row[0]) {
				if ((rlen = strlen(handle->row[0])) < outlen) {
					strcpy(out, handle->row[0]);
					retval = rlen;
				} else {
					RDEBUG("insufficient string space");
				}
			} else {
				RDEBUG("row[0] returned NULL");
			}
		} else {
			RDEBUG("SQL query did not return any results");
		}
	} else {
		RDEBUG("SQL query did not succeed");
	}

	(data->sql_inst->module->sql_finish_select_query)(handle,
							  data->sql_inst->config);
	return retval;
}

#define IS_EMPTY(_x) (!_x ||!*_x)

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
static int mod_instantiate(CONF_SECTION *conf, void **instance)
{
	module_instance_t *sqlinst;
	rlm_sqlippool_t *inst;
	const char * pool_name = NULL;

	/*
	 *	Set up a storage area for instance data
	 */
	*instance = inst = talloc_zero(conf, rlm_sqlippool_t);

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		return -1;
	}

	if (IS_EMPTY(inst->sql_instance_name)) {
		radlog(L_ERR, "rlm_sqlippool: the 'sql-instance-name' variable must be set.");
		return -1;
	}

	/*
	 *	Check that all the queries are in place
	 */

	if (IS_EMPTY(inst->allocate_clear)) {
		radlog(L_ERR, "rlm_sqlippool: the 'allocate-clear' statement must be set.");
		return -1;
	}

	if (IS_EMPTY(inst->allocate_find)) {
		radlog(L_ERR, "rlm_sqlippool: the 'allocate-find' statement must be set.");
		return -1;
	}

	if (IS_EMPTY(inst->allocate_update)) {
		radlog(L_ERR, "rlm_sqlippool: the 'allocate-update' statement must be set.");
		return -1;
	}

	if (IS_EMPTY(inst->start_update)) {
		radlog(L_ERR, "rlm_sqlippool: the 'start-update' statement must be set.");
		return -1;
	}

	if (IS_EMPTY(inst->alive_update)) {
		radlog(L_ERR, "rlm_sqlippool: the 'alive-update' statement must be set.");
		return -1;
	}

	if (IS_EMPTY(inst->stop_clear)) {
		radlog(L_ERR, "rlm_sqlippool: the 'stop-clear' statement must be set.");
		return -1;
	}

	if (IS_EMPTY(inst->on_clear)) {
		radlog(L_ERR, "rlm_sqlippool: the 'on-clear' statement must be set.");
		return -1;
	}

	if (IS_EMPTY(inst->off_clear)) {
		radlog(L_ERR, "rlm_sqlippool: the 'off-clear' statement must be set.");
		return -1;
	}

	pool_name = cf_section_name2(conf);
	if (pool_name != NULL)
		inst->pool_name = talloc_strdup(inst, pool_name);
	else
		inst->pool_name = talloc_strdup(inst, "ippool");

	sqlinst = find_module_instance(cf_section_find("modules"),
				       inst->sql_instance_name, 1);
	if (!sqlinst) {
		radlog(L_ERR, "mod_instantiate: failed to find sql instance named %s", inst->sql_instance_name);
		return -1;
	}

	if (strcmp(sqlinst->entry->name, "rlm_sql") != 0) {
		radlog(L_ERR, "mod_instantiate: Module \"%s\""
		       " is not an instance of the rlm_sql module",
		       inst->sql_instance_name);
		return -1;
	}

	inst->sql_inst = (rlm_sql_t *) sqlinst->insthandle;
	return 0;
}


/*
 * if we have something to log, then we log it
 * otherwise we return the retcode as soon as possible
 */
static int do_logging(char *str, int retcode)
{
	if (str && (*str != '\0'))
		radlog(L_INFO,"%s", str);
	return retcode;
}


/*
 *	Allocate an IP number from the pool.
 */
static rlm_rcode_t mod_post_auth(void *instance, REQUEST * request)
{
	rlm_sqlippool_t * inst = (rlm_sqlippool_t *) instance;
	char allocation[MAX_STRING_LEN];
	int allocation_len;
	uint32_t ip_allocation;
	VALUE_PAIR * vp;
	rlm_sql_handle_t * handle;
	fr_ipaddr_t ipaddr;
	char logstr[MAX_STRING_LEN];

	/*
	 * If there is a Framed-IP-Address attribute in the reply do nothing
	 */
	if (pairfind(request->reply->vps, PW_FRAMED_IP_ADDRESS, 0, TAG_ANY) != NULL) {
		/* We already have a Framed-IP-Address */
		radius_xlat(logstr, sizeof(logstr), inst->log_exists,
			    request, NULL, NULL);
		RDEBUG("Framed-IP-Address already exists");

		return do_logging(logstr, RLM_MODULE_NOOP);
	}

	if (pairfind(request->config_items, PW_POOL_NAME, 0, TAG_ANY) == NULL) {
		RDEBUG("No Pool-Name defined.");
		radius_xlat(logstr, sizeof(logstr), inst->log_nopool,
			    request, NULL, NULL);

		return do_logging(logstr, RLM_MODULE_NOOP);
	}

	handle = inst->sql_inst->sql_get_socket(inst->sql_inst);
	if (handle == NULL) {
		RDEBUG("cannot allocate sql connection");
		return RLM_MODULE_FAIL;
	}

	if (inst->sql_inst->sql_set_user(inst->sql_inst, request, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	/*
	 * BEGIN
	 */
	sqlippool_command(inst->allocate_begin, handle, inst, request,
			  (char *) NULL, 0);

	/*
	 * CLEAR
	 */
	sqlippool_command(inst->allocate_clear, handle, inst, request,
			  (char *) NULL, 0);

	/*
	 * FIND
	 */
	allocation_len = sqlippool_query1(allocation, sizeof(allocation),
					  inst->allocate_find, handle,
					  inst, request, (char *) NULL, 0);

	/*
	 *	Nothing found...
	 */
	if (allocation_len == 0) {
		/*
		 * COMMIT
		 */
		sqlippool_command(inst->allocate_commit, handle, instance,
				  request, (char *) NULL, 0);

		/*
		 * Should we perform pool-check ?
		 */
		if (inst->pool_check && *inst->pool_check) {

			/*
			 * Ok, so the allocate-find query found nothing ...
			 * Let's check if the pool exists at all
			 */
			allocation_len = sqlippool_query1(allocation, sizeof(allocation),
						 inst->pool_check, handle, inst, request,
						(char *) NULL, 0);

			inst->sql_inst->sql_release_socket(inst->sql_inst, handle);

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
				radius_xlat(logstr, sizeof(logstr), inst->log_failed, request, NULL, NULL);
				return do_logging(logstr, RLM_MODULE_NOTFOUND);

			}

			/*
			 *	Pool doesn't exist in the table. It
			 *	may be handled by some other instance of
			 *	sqlippool, so we should just ignore this
			 *	allocation failure and return NOOP
			 */
			RDEBUG("IP address could not be allocated as no pool exists with that name.");
			return RLM_MODULE_NOOP;

		}

		inst->sql_inst->sql_release_socket(inst->sql_inst, handle);

		RDEBUG("IP address could not be allocated.");
		radius_xlat(logstr, sizeof(logstr), inst->log_failed,
			    request, NULL, NULL);

		return do_logging(logstr, RLM_MODULE_NOOP);
	}


	/*
	 *  FIXME: Make it work with the ipv6 addresses
	 */
	if ((ip_hton(allocation, AF_INET, &ipaddr) < 0) ||
	    ((ip_allocation = ipaddr.ipaddr.ip4addr.s_addr) == INADDR_NONE)) {
		/*
		 * COMMIT
		 */
		sqlippool_command(inst->allocate_commit, handle, instance,
				  request, (char *) NULL, 0);

		RDEBUG("Invalid IP number [%s] returned from instbase query.", allocation);
		inst->sql_inst->sql_release_socket(inst->sql_inst, handle);
		radius_xlat(logstr, sizeof(logstr), inst->log_failed,
			    request, NULL, NULL);

		return do_logging(logstr, RLM_MODULE_NOOP);
	}

	/*
	 * UPDATE
	 */
	sqlippool_command(inst->allocate_update, handle, inst, request,
			  allocation, allocation_len);

	RDEBUG("Allocated IP %s [%08x]", allocation, ip_allocation);

	vp = radius_paircreate(request, &request->reply->vps,
			       PW_FRAMED_IP_ADDRESS, 0);
	vp->vp_ipaddr = ip_allocation;

	/*
	 * COMMIT
	 */
	sqlippool_command(inst->allocate_commit, handle, inst, request,
			  (char *) NULL, 0);

	inst->sql_inst->sql_release_socket(inst->sql_inst, handle);
	radius_xlat(logstr, sizeof(logstr), inst->log_success, request, NULL, NULL);

	return do_logging(logstr, RLM_MODULE_OK);
}

static int mod_accounting_start(rlm_sql_handle_t * handle,
				      rlm_sqlippool_t *inst, REQUEST *request)
{
	/*
	 * BEGIN
	 */
	sqlippool_command(inst->start_begin, handle, inst, request,
			  (char *) NULL, 0);

	/*
	 * UPDATE
	 */
	sqlippool_command(inst->start_update, handle, inst, request,
			  (char *) NULL, 0);

	/*
	 * COMMIT
	 */
	sqlippool_command(inst->start_commit, handle, inst, request,
			  (char *) NULL, 0);

	return RLM_MODULE_OK;
}

static int mod_accounting_alive(rlm_sql_handle_t * handle,
				      rlm_sqlippool_t *inst, REQUEST *request)
{
	/*
	 * BEGIN
	 */
	sqlippool_command(inst->alive_begin, handle, inst, request,
			  (char *) NULL, 0);

	/*
	 * UPDATE
	 */
	sqlippool_command(inst->alive_update, handle, inst, request,
			  (char *) NULL, 0);

	/*
	 * COMMIT
	 */
	sqlippool_command(inst->alive_commit, handle, inst, request,
			  (char *) NULL, 0);

	return RLM_MODULE_OK;
}

static int mod_accounting_stop(rlm_sql_handle_t * handle,
				      rlm_sqlippool_t *inst, REQUEST *request)
{
	char    logstr[MAX_STRING_LEN];

	/*
	 * BEGIN
	 */
	sqlippool_command(inst->stop_begin, handle, inst, request,
			  (char *) NULL, 0);

	/*
	 * CLEAR
	 */
	sqlippool_command(inst->stop_clear, handle, inst, request,
			  (char *) NULL, 0);

	/*
	 * COMMIT
	 */
	sqlippool_command(inst->stop_commit, handle, inst, request,
			  (char *) NULL, 0);

	radius_xlat(logstr, sizeof(logstr), inst->log_clear, request, NULL, NULL);

	return do_logging(logstr, RLM_MODULE_OK);
}

static int mod_accounting_on(rlm_sql_handle_t * handle,
				      rlm_sqlippool_t *inst, REQUEST *request)
{
	/*
	 * BEGIN
	 */
	sqlippool_command(inst->on_begin, handle, inst, request,
			  (char *) NULL, 0);

	/*
	 * CLEAR
	 */
	sqlippool_command(inst->on_clear, handle, inst, request,
			  (char *) NULL, 0);

	/*
	 * COMMIT
	 */
	sqlippool_command(inst->on_commit, handle, inst, request,
			  (char *) NULL, 0);

	return RLM_MODULE_OK;
}

static int mod_accounting_off(rlm_sql_handle_t * handle,
				      rlm_sqlippool_t *inst, REQUEST *request)
{
	/*
	 * BEGIN
	 */
	sqlippool_command(inst->off_begin, handle, inst, request,
			  (char *) NULL, 0);

	/*
	 * CLEAR
	 */
	sqlippool_command(inst->off_clear, handle, inst, request,
			  (char *) NULL, 0);

	/*
	 * COMMIT
	 */
	sqlippool_command(inst->off_commit, handle, inst, request,
			  (char *) NULL, 0);

	return RLM_MODULE_OK;
}

/*
 *	Check for an Accounting-Stop
 *	If we find one and we have allocated an IP to this nas/port
 *	combination, then deallocate it.
 */
static rlm_rcode_t mod_accounting(void * instance, REQUEST * request)
{
	int rcode;
	VALUE_PAIR * vp;
	int acct_status_type;
	rlm_sqlippool_t * inst = (rlm_sqlippool_t *) instance;
	rlm_sql_handle_t * handle;

	vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE, 0, TAG_ANY);
	if (!vp) {
		RDEBUG("Could not find account status type in packet.");
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

	handle = inst->sql_inst->sql_get_socket(inst->sql_inst);
	if (handle == NULL) {
		RDEBUG("cannot allocate sql connection");
		return RLM_MODULE_NOOP;
	}

	if (inst->sql_inst->sql_set_user(inst->sql_inst, request, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	switch (acct_status_type) {
	case PW_STATUS_START:
		rcode = mod_accounting_start(handle, inst, request);
		break;

	case PW_STATUS_ALIVE:
		rcode = mod_accounting_alive(handle, inst, request);
		break;

	case PW_STATUS_STOP:
		rcode = mod_accounting_stop(handle, inst, request);
		break;

	case PW_STATUS_ACCOUNTING_ON:
		rcode = mod_accounting_on(handle, inst, request);
		break;

	case PW_STATUS_ACCOUNTING_OFF:
		rcode = mod_accounting_off(handle, inst, request);
		break;
	}

	inst->sql_inst->sql_release_socket(inst->sql_inst, handle);

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
module_t rlm_sqlippool = {
	RLM_MODULE_INIT,
	"SQL IP Pool",
	RLM_TYPE_THREAD_SAFE,		/* type */
	mod_instantiate,		/* instantiation */
	NULL,				/* detach */
	{
		NULL,			/* authentication */
		NULL,			/* authorization */
		NULL,			/* preaccounting */
		mod_accounting,	/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		mod_post_auth	/* post-auth */
	},
};
