/*
 *  rlm_sqlippool.c     rlm_sqlippool - FreeRADIUS SQL IP Pool Module
 *
 * Version:  $Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2002  Globe.Net Communications Limited
 * Copyright 2006  The FreeRADIUS server project
 * Copyright 2006  Suntel Communications
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/libradius.h>

#include <stdlib.h>
#include <ctype.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/modpriv.h>

#include <rlm_sql.h>

/*
 *	Define a structure for our module configuration.
 */
typedef struct rlm_sqlippool_t {
	char *sql_instance_name;

	int lease_duration;

	SQL_INST *sql_inst;

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
	char *log_failed;	/* Failed to allocate ip from the pool */
	char *log_nopool;	/* There was no Framed-IP-Address but also no Pool-Name */

				/* Reserved to handle 255.255.255.254 Requests */
	char *defaultpool;   /* Default Pool-Name if there is non in the check items */

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
  {"sql-instance-name",PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,sql_instance_name), NULL, "sql"},

  { "lease-duration", PW_TYPE_INTEGER, offsetof(rlm_sqlippool_t,lease_duration), NULL, "86400"},

  { "pool-name"	    , PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t, pool_name), NULL, ""},

  { "allocate-begin", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,allocate_begin), NULL, "BEGIN" },
  { "allocate-clear", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,allocate_clear), NULL, "" },
  { "allocate-find", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,allocate_find), NULL, "" },
  { "allocate-update", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,allocate_update), NULL, "" },
  { "allocate-commit", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,allocate_commit), NULL, "COMMIT" },
  { "allocate-rollback", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,allocate_rollback), NULL, "ROLLBACK" },

  { "start-begin", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,start_begin), NULL, "BEGIN" },
  { "start-update", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,start_update), NULL, "" },
  { "start-commit", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,start_commit), NULL, "COMMIT" },
  { "start-rollback", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,start_rollback), NULL, "ROLLBACK" },

  { "alive-begin", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,alive_begin), NULL, "BEGIN" },
  { "alive-update", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,alive_update), NULL, "" },
  { "alive-commit", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,alive_commit), NULL, "COMMIT" },
  { "alive-rollback", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,alive_rollback), NULL, "ROLLBACK" },

  { "stop-begin", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,stop_begin), NULL, "BEGIN" },
  { "stop-clear", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,stop_clear), NULL, "" },
  { "stop-commit", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,stop_commit), NULL, "COMMIT" },
  { "stop-rollback", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,stop_rollback), NULL, "ROLLBACK" },

  { "on-begin", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,on_begin), NULL, "BEGIN" },
  { "on-clear", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,on_clear), NULL, "" },
  { "on-commit", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,on_commit), NULL, "COMMIT" },
  { "on-rollback", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,on_rollback), NULL, "ROLLBACK" },

  { "off-begin", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,off_begin), NULL, "BEGIN" },
  { "off-clear", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,off_clear), NULL, "" },
  { "off-commit", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,off_commit), NULL, "COMMIT" },
  { "off-rollback", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t,off_rollback), NULL, "ROLLBACK" },

  { "sqlippool_log_exists", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t, log_exists), NULL, "" },
  { "sqlippool_log_success", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t, log_success), NULL, "" },
  { "sqlippool_log_failed", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t, log_failed), NULL, "" },
  { "sqlippool_log_nopool", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t, log_nopool), NULL, "" },

  { "defaultpool", PW_TYPE_STRING_PTR, offsetof(rlm_sqlippool_t, defaultpool), NULL, "main_pool" },



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
static int sqlippool_expand(char * out, int outlen, const char * fmt, void * instance, char * param, int param_len)
{
	rlm_sqlippool_t * data = (rlm_sqlippool_t *) instance;
	char *q;
	const char *p;
	char tmp[40]; /* For temporary storing of integers */
	int openbraces;

	openbraces = 0;
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
			/*
			 * We check if we're inside an open brace.  If we are
			 * then we assume this brace is NOT literal, but is
			 * a closing brace and apply it 
			 */
			if((c == '}') && openbraces) {
				openbraces--;
				continue;
			}
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
				strNcpy(q, data->pool_name, freespace); 
				q += strlen(q);
				break;
			case 'I': /* IP address */
				if (param && param_len > 0) {
					if (param_len > freespace) {
						strNcpy(q, param, freespace);
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
				strNcpy(q, tmp, freespace); 
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
static int sqlippool_command(const char * fmt, SQLSOCK * sqlsocket, void * instance, REQUEST * request, char * param, int param_len)
{
	rlm_sqlippool_t * data = (rlm_sqlippool_t *) instance;
	char expansion[MAX_STRING_LEN * 4];
	char query[MAX_STRING_LEN * 4];

	sqlippool_expand(expansion, sizeof(expansion), fmt, instance, param, param_len);

	/*
	 * Do an xlat on the provided string
	 */
	if (request) {
		if (!radius_xlat(query, sizeof(query), expansion, request, NULL)) {
			radlog(L_ERR, "sqlippool_command: xlat failed.");
			return 0;
		}
	}
	else {
		strcpy(query, expansion);
	}

#if 0
	DEBUG2("sqlippool_command: '%s'", query);
#endif
	if (rlm_sql_query(sqlsocket, data->sql_inst, query)){
		radlog(L_ERR, "sqlippool_command: database query error in: '%s'", query);
		return 0;
	}

	(data->sql_inst->module->sql_finish_query)(sqlsocket, data->sql_inst->config);
	return 0;
}

/*
 * Query the database expecting a single result row
 */
static int sqlippool_query1(char * out, int outlen, const char * fmt, SQLSOCK * sqlsocket, void * instance, REQUEST * request, char * param, int param_len)
{
	rlm_sqlippool_t * data = (rlm_sqlippool_t *) instance;
	char expansion[MAX_STRING_LEN * 4];
	char query[MAX_STRING_LEN * 4];
	SQL_ROW row;
	int rlen, retval = 0;

	sqlippool_expand(expansion, sizeof(expansion), fmt, instance, param, param_len);

	/*
	 * Do an xlat on the provided string
	 */
	if (request) {
		if (!radius_xlat(query, sizeof(query), expansion, request, NULL)) {
			radlog(L_ERR, "sqlippool_command: xlat failed.");
			out[0] = '\0';
			return 0;
		}
	}
	else {
		strcpy(query, expansion);
	}

#if 0
	DEBUG2("sqlippool_query1: '%s'", query);
#endif
	if (rlm_sql_select_query(sqlsocket, data->sql_inst, query)){
		radlog(L_ERR, "sqlippool_query1: database query error");
		out[0] = '\0';
		return 0;
	}

	out[0] = '\0';

	if (!rlm_sql_fetch_row(sqlsocket, data->sql_inst)) {
		if (sqlsocket->row) {
			if (sqlsocket->row[0]) {
				if ((rlen = strlen(sqlsocket->row[0])) < outlen) {
					strcpy(out, sqlsocket->row[0]);
					retval = rlen;
				} else DEBUG("sqlippool_query1: insufficient string space");
			} else DEBUG("sqlippool_query1: row[0] returned NULL");
		} else DEBUG("sqlippool_query1: SQL query did not return any results");
	} else DEBUG("sqlippool_query1: SQL query did not succeed");

	(data->sql_inst->module->sql_finish_select_query)(sqlsocket, data->sql_inst->config);
	return retval;
}

static int sqlippool_initialize_sql(void * instance)
{

	rlm_sqlippool_t * data = (rlm_sqlippool_t *) instance;

	SQLSOCK * sqlsocket;

	sqlsocket = sql_get_socket(data->sql_inst);
	if (sqlsocket == NULL) {
		DEBUG("rlm_sqlippool: cannot allocate sql connection for initialization sequence");
		return 0;
	}

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
static int sqlippool_instantiate(CONF_SECTION * conf, void ** instance)
{
	rlm_sqlippool_t * data;
	char * pool_name = NULL;

	/*
	 *	Set up a storage area for instance data
	 */
	data = rad_malloc(sizeof(*data));
	memset(data, 0, sizeof(*data));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, data, module_config) < 0) {
		free(data);
		return -1;
	}

	if (data->sql_instance_name == NULL || strlen(data->sql_instance_name) == 0) {
		radlog(L_ERR, "rlm_sqlippool: the 'sql-instance-name' variable must be set.");
		free(data);
		exit(0);
	}

	/*
	 *	Check that all the queries are in place
	 */

	if (data->allocate_clear == NULL || strlen(data->allocate_clear) == 0) {
		radlog(L_ERR, "rlm_sqlippool: the 'allocate-clear' statement must be set.");
		free(data);
		exit(0);
	}

	if (data->allocate_find == NULL || strlen(data->allocate_find) == 0) {
		radlog(L_ERR, "rlm_sqlippool: the 'allocate_find' statement must be set.");
		free(data);
		exit(0);
	}

	if (data->allocate_update == NULL || strlen(data->allocate_update) == 0) {
		radlog(L_ERR, "rlm_sqlippool: the 'allocate_update' statement must be set.");
		free(data);
		exit(0);
	}

	if (data->start_update == NULL || strlen(data->start_update) == 0) {
		radlog(L_ERR, "rlm_sqlippool: the 'start-update' statement must be set.");
		free(data);
		exit(0);
	}

	if (data->alive_update == NULL || strlen(data->alive_update) == 0) {
		radlog(L_ERR, "rlm_sqlippool: the 'alive-update' statement must be set.");
		free(data);
		exit(0);
	}

	if (data->stop_clear == NULL || strlen(data->stop_clear) == 0) {
		radlog(L_ERR, "rlm_sqlippool: the 'stop-clear' statement must be set.");
		free(data);
		exit(0);
	}

	if (data->on_clear == NULL || strlen(data->on_clear) == 0) {
		radlog(L_ERR, "rlm_sqlippool: the 'on-clear' statement must be set.");
		free(data);
		exit(0);
	}

	if (data->off_clear == NULL || strlen(data->off_clear) == 0) {
		radlog(L_ERR, "rlm_sqlippool: the 'off-clear' statement must be set.");
		free(data);
		exit(0);
	}

	pool_name = cf_section_name2(conf);
	if (pool_name != NULL)
		data->pool_name = strdup(pool_name);
	else
		data->pool_name = strdup("ippool");

	if ( !(data->sql_inst = (SQL_INST *) (find_module_instance(cf_section_find("modules"), data->sql_instance_name))->insthandle) )
	{
		radlog(L_ERR, "sqlippool_instantiate: failed to find sql instance named %s", data->sql_instance_name);
		free(data);
		exit(0);
	}

	sqlippool_initialize_sql(data);
	*instance = data;
	return 0;
}


/* Do "hit and run!"
 * if we have something to log, then we log it
 * otherwise we return the retcode as soon as possible 
 * </tuyan>
 */
static int do_logging(char *str, int retcode)
{
	if (strlen(str))
		radlog(L_INFO,"%s", str);	
	return retcode;
}


/*
 *	Allocate an IP number from the pool.
 */
static int sqlippool_postauth(void *instance, REQUEST * request)
{
	rlm_sqlippool_t * data = (rlm_sqlippool_t *) instance;
	char allocation[MAX_STRING_LEN];
	int allocation_len;
	uint32_t ip_allocation;
	VALUE_PAIR * vp;
	SQLSOCK * sqlsocket;
	lrad_ipaddr_t ipaddr;

	VALUE_PAIR *callingsid;
	VALUE_PAIR *pair;

	int do_callingsid = 0;
	int do_calledsid = 0;

	char    logstr[MAX_STRING_LEN];

	/*
	 * If there is a Framed-IP-Address attribute in the reply do nothing
	 */
	if (pairfind(request->reply->vps, PW_FRAMED_IP_ADDRESS) != NULL) {
		/* We already have a Framed-IP-Address */
		radius_xlat(logstr, sizeof(logstr), data->log_exists, request, NULL);
		DEBUG("rlm_sqlippool: Framed-IP-Address already exists");

		return do_logging(logstr, RLM_MODULE_NOOP);
	}

	if (pairfind(request->config_items, PW_POOL_NAME) == NULL) {
		DEBUG("rlm_sqlippool: We Dont have Pool-Name in check items.. Lets do nothing..");
		radius_xlat(logstr, sizeof(logstr), data->log_nopool, request, NULL);

		return do_logging(logstr, RLM_MODULE_NOOP);
	}
	
	if (pairfind(request->packet->vps, PW_NAS_IP_ADDRESS) == NULL) {
		DEBUG("rlm_sqlippool: unknown NAS-IP-Address");
		return RLM_MODULE_NOOP;
	}

	if (pairfind(request->packet->vps, PW_NAS_PORT) == NULL) {
		DEBUG("rlm_sqlippool: unknown NAS-Port");
		return RLM_MODULE_NOOP;
	}

	sqlsocket = sql_get_socket(data->sql_inst);
	if (sqlsocket == NULL) {
		DEBUG("rlm_sqlippool: cannot allocate sql connection");
		return RLM_MODULE_FAIL;
	}

	/*
	 * BEGIN
	 */
	sqlippool_command(data->allocate_begin, sqlsocket, instance, request,
			  (char *) NULL, 0);

	/*
	 * CLEAR
	 */
	sqlippool_command(data->allocate_clear, sqlsocket, instance, request,
			  (char *) NULL, 0);

	/*
	 * FIND
	 */
	allocation_len = sqlippool_query1(allocation, sizeof(allocation),
					  data->allocate_find, sqlsocket, instance, request,
					  (char *) NULL, 0);

	if (allocation_len == 0)
	{	
		/*
		 * COMMIT
		 */
		sqlippool_command(data->allocate_commit, sqlsocket, instance, request,
				  (char *) NULL, 0);

		DEBUG("rlm_sqlippool: IP number could not be allocated.");
		sql_release_socket(data->sql_inst, sqlsocket);
		radius_xlat(logstr, sizeof(logstr), data->log_failed, request, NULL);
	
		return do_logging(logstr, RLM_MODULE_NOTFOUND);
	}

	
	/*
	 *  FIXME: Make it work with the ipv6 addresses
	 */
	if ((ip_hton(allocation, AF_INET, &ipaddr) < 0) ||
	    ((ip_allocation = ipaddr.ipaddr.ip4addr.s_addr) == INADDR_NONE))
	{
		/*
		 * COMMIT
		 */
		sqlippool_command(data->allocate_commit, sqlsocket, instance, request,
				  (char *) NULL, 0);

		DEBUG("rlm_sqlippool: Invalid IP number [%s] returned from database query.", allocation);
		sql_release_socket(data->sql_inst, sqlsocket);
		radius_xlat(logstr, sizeof(logstr), data->log_failed, request, NULL);	
		
		return do_logging(logstr, RLM_MODULE_NOOP);
	}

	/*
	 * UPDATE
	 */
	sqlippool_command(data->allocate_update, sqlsocket, instance, request,
			  allocation, allocation_len);

	DEBUG("rlm_sqlippool: Allocated IP %s [%08x]", allocation, ip_allocation);

	if ((vp = paircreate(PW_FRAMED_IP_ADDRESS, PW_TYPE_IPADDR)) == NULL) {
		radlog(L_ERR|L_CONS, "no memory");
		sql_release_socket(data->sql_inst, sqlsocket);
		return RLM_MODULE_NOOP;
	}
	vp->lvalue = ip_allocation;
	pairadd(&request->reply->vps, vp);

	/*
	 * COMMIT
	 */
	sqlippool_command(data->allocate_commit, sqlsocket, instance, request,
			  (char *) NULL, 0);

	sql_release_socket(data->sql_inst, sqlsocket);
	radius_xlat(logstr, sizeof(logstr), data->log_success, request, NULL);

	return do_logging(logstr, RLM_MODULE_OK);
}

static int sqlippool_accounting_start(void * instance, REQUEST * request)
{
	rlm_sqlippool_t * data = (rlm_sqlippool_t *) instance;
	SQLSOCK * sqlsocket;

	if (pairfind(request->packet->vps, PW_NAS_PORT) == NULL) {
		DEBUG("rlm_ippool: Could not find port number in packet.");
		return RLM_MODULE_NOOP;
	}

	if (pairfind(request->packet->vps, PW_NAS_IP_ADDRESS) == NULL) {
		DEBUG("rlm_ippool: Could not find nas information in packet.");
		return RLM_MODULE_NOOP;
	}

	sqlsocket = sql_get_socket(data->sql_inst);
	if (sqlsocket == NULL) {
		DEBUG("rlm_sqlippool: cannot allocate sql connection");
		return RLM_MODULE_NOOP;
	}

	/*
	 * BEGIN
	 */
	sqlippool_command(data->start_begin, sqlsocket, instance, request,
			  (char *) NULL, 0);

	/*
	 * UPDATE
	 */
	sqlippool_command(data->start_update, sqlsocket, instance, request,
			  (char *) NULL, 0);

	/*
	 * COMMIT
	 */
	sqlippool_command(data->start_commit, sqlsocket, instance, request,
			  (char *) NULL, 0);

	sql_release_socket(data->sql_inst, sqlsocket);

	return RLM_MODULE_OK;
}

static int sqlippool_accounting_alive(void * instance, REQUEST * request)
{
	rlm_sqlippool_t * data = (rlm_sqlippool_t *) instance;
	SQLSOCK * sqlsocket;

	if (pairfind(request->packet->vps, PW_NAS_PORT) == NULL) {
		DEBUG("rlm_ippool: Could not find port number in packet.");
		return RLM_MODULE_NOOP;
	}

	if (pairfind(request->packet->vps, PW_NAS_IP_ADDRESS) == NULL) {
		DEBUG("rlm_ippool: Could not find nas information in packet.");
		return RLM_MODULE_NOOP;
	}

	sqlsocket = sql_get_socket(data->sql_inst);
	if (sqlsocket == NULL) {
		DEBUG("rlm_sqlippool: cannot allocate sql connection");
		return RLM_MODULE_NOOP;
	}

	/*
	 * BEGIN
	 */
	sqlippool_command(data->alive_begin, sqlsocket, instance, request,
			  (char *) NULL, 0);

	/*
	 * UPDATE
	 */
	sqlippool_command(data->alive_update, sqlsocket, instance, request,
			  (char *) NULL, 0);

	/*
	 * COMMIT
	 */
	sqlippool_command(data->alive_commit, sqlsocket, instance, request,
			  (char *) NULL, 0);

	sql_release_socket(data->sql_inst, sqlsocket);

	return RLM_MODULE_OK;
}

static int sqlippool_accounting_stop(void * instance, REQUEST * request)
{
	rlm_sqlippool_t * data = (rlm_sqlippool_t *) instance;
	SQLSOCK * sqlsocket;

	if (pairfind(request->packet->vps, PW_NAS_PORT) == NULL) {
		DEBUG("rlm_ippool: Could not find port number in packet.");
		return RLM_MODULE_NOOP;
	}

	if (pairfind(request->packet->vps, PW_NAS_IP_ADDRESS) == NULL) {
		DEBUG("rlm_ippool: Could not find nas information in packet.");
		return RLM_MODULE_NOOP;
	}

	sqlsocket = sql_get_socket(data->sql_inst);
	if (sqlsocket == NULL) {
		DEBUG("rlm_sqlippool: cannot allocate sql connection");
		return RLM_MODULE_NOOP;
	}

	/*
	 * BEGIN
	 */
	sqlippool_command(data->stop_begin, sqlsocket, instance, request,
			  (char *) NULL, 0);

	/*
	 * CLEAR
	 */
	sqlippool_command(data->stop_clear, sqlsocket, instance, request,
			  (char *) NULL, 0);

	/*
	 * COMMIT
	 */
	sqlippool_command(data->stop_commit, sqlsocket, instance, request,
			  (char *) NULL, 0);

	sql_release_socket(data->sql_inst, sqlsocket);

	return RLM_MODULE_OK;
}

static int sqlippool_accounting_on(void * instance, REQUEST * request)
{
	rlm_sqlippool_t * data = (rlm_sqlippool_t *) instance;
	SQLSOCK * sqlsocket;

	if (pairfind(request->packet->vps, PW_NAS_IP_ADDRESS) == NULL) {
		DEBUG("rlm_ippool: Could not find nas information in packet.");
		return RLM_MODULE_NOOP;
	}

	sqlsocket = sql_get_socket(data->sql_inst);
	if (sqlsocket == NULL) {
		DEBUG("rlm_sqlippool: cannot allocate sql connection");
		return RLM_MODULE_NOOP;
	}

	/*
	 * BEGIN
	 */
	sqlippool_command(data->on_begin, sqlsocket, instance, request,
			  (char *) NULL, 0);

	/*
	 * CLEAR
	 */
	sqlippool_command(data->on_clear, sqlsocket, instance, request,
			  (char *) NULL, 0);

	/*
	 * COMMIT
	 */
	sqlippool_command(data->on_commit, sqlsocket, instance, request,
			  (char *) NULL, 0);

	sql_release_socket(data->sql_inst, sqlsocket);

	return RLM_MODULE_OK;
}

static int sqlippool_accounting_off(void * instance, REQUEST * request)
{
	rlm_sqlippool_t * data = (rlm_sqlippool_t *) instance;
	SQLSOCK * sqlsocket;

	if (pairfind(request->packet->vps, PW_NAS_IP_ADDRESS) == NULL) {
		DEBUG("rlm_ippool: Could not find nas information in packet.");
		return RLM_MODULE_NOOP;
	}

	sqlsocket = sql_get_socket(data->sql_inst);
	if (sqlsocket == NULL) {
		DEBUG("rlm_sqlippool: cannot allocate sql connection");
		return RLM_MODULE_NOOP;
	}

	/*
	 * BEGIN
	 */
	sqlippool_command(data->off_begin, sqlsocket, instance, request,
			  (char *) NULL, 0);

	/*
	 * CLEAR
	 */
	sqlippool_command(data->off_clear, sqlsocket, instance, request,
			  (char *) NULL, 0);

	/*
	 * COMMIT
	 */
	sqlippool_command(data->off_commit, sqlsocket, instance, request,
			  (char *) NULL, 0);

	sql_release_socket(data->sql_inst, sqlsocket);

	return RLM_MODULE_OK;
}

/*
 *	Check for an Accounting-Stop
 *	If we find one and we have allocated an IP to this nas/port combination, deallocate it.	
 */
static int sqlippool_accounting(void * instance, REQUEST * request)
{
	VALUE_PAIR * vp;
	int acct_status_type;

	vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE);
	if (vp == NULL) {
		DEBUG("rlm_sqlippool: Could not find account status type in packet.");
		return RLM_MODULE_NOOP;
	}
	acct_status_type = vp->lvalue;

	switch (acct_status_type) {
	case PW_STATUS_START:
		return sqlippool_accounting_start(instance, request);

	case PW_STATUS_ALIVE:
		return sqlippool_accounting_alive(instance, request);

	case PW_STATUS_STOP:
		return sqlippool_accounting_stop(instance, request);

	case PW_STATUS_ACCOUNTING_ON:
		return sqlippool_accounting_on(instance, request);

	case PW_STATUS_ACCOUNTING_OFF:
		return sqlippool_accounting_off(instance, request);

	default:
		/* We don't care about any other accounting packet */
		return RLM_MODULE_NOOP;
	}
}

static int sqlippool_detach(void *instance)
{
	rlm_sqlippool_t * data = (rlm_sqlippool_t *) instance;

	free(data->sql_instance_name);
	free(data->pool_name);

	

	free(data->allocate_begin);
	free(data->allocate_clear);
	free(data->allocate_find);
	free(data->allocate_update);
	free(data->allocate_commit);
	free(data->allocate_rollback);

	free(data->start_begin);
	free(data->start_update);
	free(data->start_commit);
	free(data->start_rollback);

	free(data->alive_begin);
	free(data->alive_update);
	free(data->alive_commit);
	free(data->alive_rollback);

	free(data->stop_begin);
	free(data->stop_clear);
	free(data->stop_commit);
	free(data->stop_rollback);

	free(data->on_begin);
	free(data->on_clear);
	free(data->on_commit);
	free(data->on_rollback);

	free(data->off_begin);
	free(data->off_clear);
	free(data->off_commit);
	free(data->off_rollback);
	
	free(data->log_exists);
	free(data->log_failed);
	free(data->log_nopool);
	free(data->log_success);
	free(data->defaultpool);
	
	

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
module_t rlm_sqlippool = {
	RLM_MODULE_INIT,
	"SQL IP Pool",	
	RLM_TYPE_THREAD_SAFE,		/* type */
	sqlippool_instantiate,		/* instantiation */
	sqlippool_detach,		/* detach */
	{
		NULL,			/* authentication */
		NULL,			/* authorization */
		NULL,			/* preaccounting */
		sqlippool_accounting,	/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		sqlippool_postauth	/* post-auth */
	},
};
