/*
 * rlm_sql.c		SQL Module
 * 		Main SQL module file. Most ICRADIUS code is located in sql.c
 *
 * Version:	$Id$
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
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Mike Machado <mike@innercite.com>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

static const char rcsid[] =
	"$Id$";

#include "autoconf.h"

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>

#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"
#include "rlm_sql.h"
#include "rad_assert.h"

static CONF_PARSER module_config[] = {
	{"driver",PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_driver), NULL, "mysql"},
	{"server",PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_server), NULL, "localhost"},
	{"port",PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_port), NULL, ""},
	{"login", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_login), NULL, ""},
	{"password", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_password), NULL, ""},
	{"radius_db", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_db), NULL, "radius"},
	{"acct_table", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_acct_table), NULL, "radacct"},
	{"acct_table2", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_acct_table2), NULL, "radacct"},
	{"authcheck_table", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_authcheck_table), NULL, "radcheck"},
	{"authreply_table", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_authreply_table), NULL, "radreply"},
	{"groupcheck_table", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_groupcheck_table), NULL, "radgroupcheck"},
	{"groupreply_table", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_groupreply_table), NULL, "radgroupreply"},
	{"usergroup_table", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_usergroup_table), NULL, "usergroup"},
	{"nas_table", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_nas_table), NULL, "nas"},
	{"dict_table", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_dict_table), NULL, "dictionary"},
	{"sqltrace", PW_TYPE_BOOLEAN, offsetof(SQL_CONFIG,sqltrace), NULL, "0"},
	{"sqltracefile", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,tracefile), NULL, SQLTRACEFILE},
	{"deletestalesessions", PW_TYPE_BOOLEAN, offsetof(SQL_CONFIG,deletestalesessions), NULL, "0"},
	{"num_sql_socks", PW_TYPE_INTEGER, offsetof(SQL_CONFIG,num_sql_socks), NULL, "5"},
	{"sql_user_name", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,query_user), NULL, ""},
	{"authorize_check_query", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,authorize_check_query), NULL, ""},
	{"authorize_reply_query", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,authorize_reply_query), NULL, ""},
	{"authorize_group_check_query", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,authorize_group_check_query), NULL, ""},
	{"authorize_group_reply_query", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,authorize_group_reply_query), NULL, ""},
	{"authenticate_query", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,authenticate_query), NULL, ""},
	{"accounting_onoff_query", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,accounting_onoff_query), NULL, ""},
	{"accounting_update_query", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,accounting_update_query), NULL, ""},
	{"accounting_start_query", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,accounting_start_query), NULL, ""},
	{"accounting_start_query_alt", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,accounting_start_query_alt), NULL, ""},
	{"accounting_stop_query", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,accounting_stop_query), NULL, ""},
	{"accounting_stop_query_alt", PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,accounting_stop_query_alt), NULL, ""},
	{"connect_failure_retry_delay", PW_TYPE_INTEGER, offsetof(SQL_CONFIG,connect_failure_retry_delay), NULL, "60"},

	{NULL, -1, 0, NULL, NULL}
};

/***********************************************************************
 * start of main routines
 ***********************************************************************/
static int rlm_sql_init(void) {

	/*
	 * FIXME:
	 * We should put the sqlsocket array here once
	 * the module code is reworked to not unload
	 * modules on HUP.  This way we can have
	 * persistant connections.  -jcarneal
	 */
	return 0;
}

/*
 *	sql xlat function. Right now only SELECTs are supported. Only
 *	the first element of the SELECT result will be used.
 */
static int sql_xlat(void *instance, REQUEST *request, char *fmt, char *out, int freespace,
			RADIUS_ESCAPE_STRING func)
{
	SQLSOCK *sqlsocket;
	SQL_ROW row;
	SQL_INST *inst=instance;
	char querystr[MAX_QUERY_LEN];
	int ret = 0;

	DEBUG("rlm_sql: - sql_xlat");
	/*
	 * Do an xlat on the provided string (nice recursive operation).
	 */
	if (!radius_xlat(querystr, sizeof(querystr), fmt, request, func)){
		radlog(L_ERR, "rlm_sql: xlat failed.");
		return 0;
	}

	sqlsocket = sql_get_socket(inst);
	if (sqlsocket == NULL)
		return 0;
	if ((inst->module->sql_select_query)(sqlsocket,inst->config,querystr) <0){
		radlog(L_ERR, "rlm_sql: database query error");
		sql_release_socket(inst,sqlsocket);
		return 0;
	}
	row = (inst->module->sql_fetch_row)(sqlsocket, inst->config);
	(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
	sql_release_socket(inst,sqlsocket);
	if (row == NULL){
		DEBUG("rlm_sql: SQL query did not return any results");
		return 0;
	}
	if (row[0] == NULL){
		DEBUG("rlm_sql: row[0] returned NULL");
		return 0;
	}
	ret = strlen(row[0]);
	if (ret > freespace){
		DEBUG("rlm_sql: sql_xlat:: Insufficient string space");
		return 0;
	}
	strncpy(out,row[0],ret);
	DEBUG("rlm_sql: - sql_xlat finished");

	return ret;
}

/*
 *	Translate the SQL queries.
 */
static int sql_escape_func(char *out, int outlen, const char *in)
{
	int len = 0;
	
	while (in[0]) {
		/*
		 *  Only one byte left.
		 */
		if (outlen <= 1) {
			break;
		}
		
		/*
		 *	Non-printable characters get replaced with their
		 *	mime-encoded equivalents.
		 */
		if ((in[0] < 32) ||
		    strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-", *in) == NULL) {
			snprintf(out, outlen, "=%02X", (unsigned char) in[0]);
			in++;
			out += 3;
			outlen -= 3;
			len += 3;
			continue;
		}
		
		/*
		 *	Else it's a nice character.
		 */
		*out = *in;
		out++;
		in++;
		outlen--;
		len++;
	}
	*out = '\0';
	return len;
}

static int rlm_sql_instantiate(CONF_SECTION * conf, void **instance) {

	SQL_INST *inst;
	lt_dlhandle *handle;
	char *xlat_name;

	inst = rad_malloc(sizeof(SQL_INST));
	memset(inst, 0, sizeof(SQL_INST));

	inst->config = rad_malloc(sizeof(SQL_CONFIG));
	memset(inst->config, 0, sizeof(SQL_CONFIG));

	/*
	 * If the configuration parameters can't be parsed, then
	 * fail.
	 */
	if (cf_section_parse(conf, inst->config, module_config) < 0) {
		free(inst->config);
		free(inst);
		return -1;
	}

	if (inst->config->num_sql_socks > MAX_SQL_SOCKS) {
		radlog(L_ERR | L_CONS, "sql_instantiate:  number of sqlsockets cannot exceed MAX_SQL_SOCKS, %d", MAX_SQL_SOCKS);
		free(inst->config);
		free(inst);
		return -1;
	}

	handle = lt_dlopenext(inst->config->sql_driver);
	if (handle == NULL) {
		radlog(L_ERR, "rlm_sql: Could not link driver %s: %s", inst->config->sql_driver, lt_dlerror());
		radlog(L_ERR, "rlm_sql: Make sure it (and all its dependent libraries!) are in the search path of your system's ld.");
		return -1;
	}

	inst->module = (rlm_sql_module_t *) lt_dlsym(handle, inst->config->sql_driver);
	if (!inst->module) {
		radlog(L_ERR, "rlm_sql: Could not link symbol %s: %s", inst->config->sql_driver, lt_dlerror());
		return -1;
	}

	radlog(L_INFO, "rlm_sql: Driver %s loaded and linked", inst->config->sql_driver);
	radlog(L_INFO, "rlm_sql: Attempting to connect to %s@%s:%s/%s", inst->config->sql_login, inst->config->sql_server, inst->config->sql_port, inst->config->sql_db);

	if (sql_init_socketpool(inst) < 0) {
		free(inst->config);
		free(inst);
		return -1;
	}
	xlat_name = cf_section_name2(conf);
	if (xlat_name == NULL)
		xlat_name = cf_section_name1(conf);
	if (xlat_name){
		inst->config->xlat_name = strdup(xlat_name);
		xlat_register(xlat_name, sql_xlat, inst);
	}

	*instance = inst;

	return RLM_MODULE_OK;
}

static int rlm_sql_destroy(void) {

	return 0;
}

static int rlm_sql_detach(void *instance) {

	SQL_INST *inst = instance;

	sql_poolfree(inst);
	if (inst->config->xlat_name)
		xlat_unregister(inst->config->xlat_name,sql_xlat);
	free(inst->config);
	free(inst);

	return 0;
}


static int rlm_sql_authorize(void *instance, REQUEST * request) {

	VALUE_PAIR *check_tmp = NULL;
	VALUE_PAIR *reply_tmp = NULL;
	VALUE_PAIR *passwd_item = NULL;
	int     found = 0;
	SQLSOCK *sqlsocket;
	SQL_INST *inst = instance;
	SQL_ROW row;
	char    querystr[MAX_QUERY_LEN];

	/* sqlusername holds the sql escaped username. The original
	 * username is at most MAX_STRING_LEN chars long and
	 * *sql_escape_string doubles its length in the worst case.
	 * Throw in an extra 10 to account for trailing NULs and to have
	 * a safety margin. */
	char   sqlusername[2 * MAX_STRING_LEN + 10];

	/*
	 *	They MUST have a user name to do SQL authorization.
	 */
	if ((request->username == NULL) ||
	    (request->username->length == 0)) {
		radlog(L_ERR, "zero length username not permitted\n");
		return RLM_MODULE_INVALID;
	}


	/*
	 *  After this point, ALL 'return's MUST release the SQL socket!
	 */

	/*
	 * Set, escape, and check the user attr here
	 */
	if (sql_set_user(inst, request, sqlusername, 0) < 0)
		return RLM_MODULE_FAIL;
	radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authorize_check_query, request, sql_escape_func);

	sqlsocket = sql_get_socket(inst);
	if (sqlsocket == NULL) {
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_SQL_USER_NAME);
		return(RLM_MODULE_FAIL);
	}

	found = sql_getvpdata(inst, sqlsocket, &check_tmp, querystr, PW_VP_USERDATA);
	/*
	 *      Find the entry for the user.
	 */
	if (found > 0) {
		radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authorize_group_check_query, request, sql_escape_func);
		sql_getvpdata(inst, sqlsocket, &check_tmp, querystr, PW_VP_GROUPDATA);
		radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authorize_reply_query, request, sql_escape_func);
		sql_getvpdata(inst, sqlsocket, &reply_tmp, querystr, PW_VP_USERDATA);
		radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authorize_group_reply_query, request, sql_escape_func);
		sql_getvpdata(inst, sqlsocket, &reply_tmp, querystr, PW_VP_GROUPDATA);
	} else if (found < 0) {
		radlog(L_ERR, "rlm_sql:  SQL query error; rejecting user");
		sql_release_socket(inst, sqlsocket);
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_SQL_USER_NAME);
		return RLM_MODULE_FAIL;

	} else {
		int     gcheck;
		
		radlog(L_DBG, "rlm_sql: User %s not found", sqlusername);

                /*
		 * We didn't find the user in radcheck, so we try looking
		 * for radgroupcheck entry
		 */
                radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authorize_group_check_query, request, sql_escape_func);
                gcheck = sql_getvpdata(inst, sqlsocket, &check_tmp, querystr, PW_VP_GROUPDATA);
                radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authorize_group_reply_query, request, sql_escape_func);
                sql_getvpdata(inst, sqlsocket, &reply_tmp, querystr, PW_VP_GROUPDATA);
                if (gcheck) {
                        found = 1;
                } else {
                        /*
                        * We didn't find the user, so we try looking
                        * for a DEFAULT entry
                        */
                        if (sql_set_user(inst, request, sqlusername, "DEFAULT") < 0) {
                                sql_release_socket(inst, sqlsocket);
                                return RLM_MODULE_FAIL;
                        }
                        radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authorize_group_check_query, request, sql_escape_func);
                        gcheck = sql_getvpdata(inst, sqlsocket, &check_tmp, querystr, PW_VP_GROUPDATA);
                        radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authorize_group_reply_query, request, sql_escape_func);
                        gcheck = sql_getvpdata(inst, sqlsocket, &reply_tmp, querystr, PW_VP_GROUPDATA);
                        if (gcheck)
                                found = 1;
                }
        }
	if (!found) {
		radlog(L_DBG, "rlm_sql: DEFAULT not found", sqlusername);
		sql_release_socket(inst, sqlsocket);
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_SQL_USER_NAME);
		return RLM_MODULE_NOTFOUND;
	}
#if 0 /* FIXME: Debug being printed elsewhere? */
	/*
	 * Uncomment these lines for debugging
	 * Recompile, and run 'radiusd -X'
	 *
	 DEBUG2("rlm_sql:  check items");
	 vp_printlist(stderr, check_tmp);
	 DEBUG2("rlm_sql:  reply items");
	 vp_printlist(stderr, reply_tmp);
	 */
#endif

#if 0 /* FIXME: this is the *real* authorizing */
	vp_printlist(stderr, check_tmp);
#endif
	if (paircmp(request, request->packet->vps, check_tmp, &reply_tmp) != 0) {
		radlog(L_INFO, "rlm_sql: Pairs do not match [%s]", sqlusername);
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_SQL_USER_NAME);
		sql_release_socket(inst, sqlsocket);
		pairfree(&reply_tmp);
		pairfree(&check_tmp);
		return RLM_MODULE_NOTFOUND;
	}

	pairmove(&request->reply->vps, &reply_tmp);
	pairmove(&request->config_items, &check_tmp);
	pairfree(&reply_tmp);
	pairfree(&check_tmp);

	if (inst->config->authenticate_query){
		radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authenticate_query, request, sql_escape_func);
	
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_SQL_USER_NAME);

		if ((inst->module->sql_select_query)(sqlsocket, inst->config, querystr) < 0) {
			radlog(L_ERR, "rlm_sql_authorize: database query error");
			sql_release_socket(inst, sqlsocket);
			return RLM_MODULE_FAIL;
		}

		row = (inst->module->sql_fetch_row)(sqlsocket, inst->config);
		(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
		sql_release_socket(inst, sqlsocket);

		if (row == NULL) {
			radlog(L_ERR, "rlm_sql_authorize: no rows returned from query (no such user)");
			return RLM_MODULE_OK;
		}

		if (row[0] == NULL) {
			radlog(L_ERR, "rlm_sql_authorize: row[0] returned NULL.");
			return RLM_MODULE_OK;
		}
		if ((passwd_item = pairmake("User-Password",row[0],T_OP_SET)) != NULL)
			pairadd(&request->config_items,passwd_item);
		goto move_on;
	}
	/* Remove the username we (maybe) added above */
	pairdelete(&request->packet->vps, PW_SQL_USER_NAME);
	sql_release_socket(inst, sqlsocket);

move_on:
	return RLM_MODULE_OK;
}

/*
 *	Accounting: save the account data to our sql table
 */
static int rlm_sql_accounting(void *instance, REQUEST * request) {

	SQLSOCK *sqlsocket = NULL;
	VALUE_PAIR *pair;
	SQL_INST *inst = instance;
	int     numaffected = 0;
	int     acctstatustype = 0;
	char    querystr[MAX_QUERY_LEN];
	char    logstr[MAX_QUERY_LEN];
	char	sqlusername[MAX_STRING_LEN];

#ifdef CISCO_ACCOUNTING_HACK
	int     acctsessiontime = 0;
#endif


	memset(querystr, 0, MAX_QUERY_LEN);

	/*
	 * Find the Acct Status Type
	 */
	if ((pair = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE)) != NULL) {
		acctstatustype = pair->lvalue;
	} else {
		radius_xlat(logstr, MAX_QUERY_LEN, "rlm_sql:  packet has no account status type.  [user '%{User-Name}', nas '%{NAS-IP-Address}']", request, sql_escape_func);
		radlog(L_ERR, logstr);
		return RLM_MODULE_INVALID;
	}

	switch (acctstatustype) {
			/*
			 * The Terminal server informed us that it was rebooted
			 * STOP all records from this NAS 
			 */
		case PW_STATUS_ACCOUNTING_ON:
		case PW_STATUS_ACCOUNTING_OFF:
			radlog(L_INFO, "rlm_sql:  received Acct On/Off packet");
			radius_xlat(querystr, MAX_QUERY_LEN, inst->config->accounting_onoff_query, request, sql_escape_func);
			query_log(inst, querystr);

			sqlsocket = sql_get_socket(inst);
			if (sqlsocket == NULL)
				return(RLM_MODULE_FAIL);
			if (querystr) {
				if ((inst->module->sql_query)(sqlsocket, inst->config, querystr) < 0)
					radlog(L_ERR, "rlm_sql: Couldn't update SQL accounting for Acct On/Off packet - %s", (char *)(inst->module->sql_error)(sqlsocket, inst->config));
				(inst->module->sql_finish_query)(sqlsocket, inst->config);
			}

			break;

			/*
			 * Got an update accounting packet
			 */
		case PW_STATUS_ALIVE:

			radius_xlat(querystr, MAX_QUERY_LEN, inst->config->accounting_update_query, request, sql_escape_func);
			query_log(inst, querystr);

			sqlsocket = sql_get_socket(inst);
			if (sqlsocket == NULL)
				return(RLM_MODULE_FAIL);
			if (querystr) {
				if ((inst->module->sql_query)(sqlsocket, inst->config, querystr) < 0)
					radlog(L_ERR, "rlm_sql: Couldn't update SQL accounting for ALIVE packet - %s", (char *)(inst->module->sql_error)(sqlsocket, inst->config));
				(inst->module->sql_finish_query)(sqlsocket, inst->config);
			}

			break;

			/*
			 * Got accounting start packet
			 */
		case PW_STATUS_START:

			/*
			 * Set, escape, and check the user attr here
			 */
			if(sql_set_user(inst, request, sqlusername, 0) < 0)
				return RLM_MODULE_FAIL;

			radius_xlat(querystr, MAX_QUERY_LEN, inst->config->accounting_start_query, request, sql_escape_func);
			query_log(inst, querystr);

			sqlsocket = sql_get_socket(inst);
			if (sqlsocket == NULL)
				return(RLM_MODULE_FAIL);
			if (querystr) {
				if ((inst->module->sql_query)(sqlsocket, inst->config, querystr) < 0) {
					radlog(L_ERR, "rlm_sql: Couldn't update SQL accounting" " for START packet - %s", (char *)(inst->module->sql_error)(sqlsocket, inst->config));

					/*
					 * We failed the insert above.  It's probably because 
					 * the stop record came before the start.  We try an
					 * our alternate query now (typically an UPDATE)
					 */
					radius_xlat(querystr, MAX_QUERY_LEN, inst->config->accounting_start_query_alt, request, sql_escape_func);
					query_log(inst, querystr);

					if (querystr) {
						if ((inst->module->sql_query)(sqlsocket, inst->config, querystr) < 0) {
							radlog(L_ERR, "rlm_sql: Couldn't update SQL" "accounting START record - %s", (char *)(inst->module->sql_error)(sqlsocket, inst->config));
						}
						(inst->module->sql_finish_query)(sqlsocket, inst->config);
					}
				}
				(inst->module->sql_finish_query)(sqlsocket, inst->config);
			}
			break;

			/*
			 * Got accounting stop packet
			 */
		case PW_STATUS_STOP:

			/*
			 * Set, escape, and check the user attr here
			 */
			if(sql_set_user(inst, request, sqlusername, 0) < 0)
				return RLM_MODULE_FAIL;

			radius_xlat(querystr, MAX_QUERY_LEN, inst->config->accounting_stop_query, request, sql_escape_func);
			query_log(inst, querystr);

			sqlsocket = sql_get_socket(inst);
			if (sqlsocket == NULL)
				return(RLM_MODULE_FAIL);
			if (querystr) {
				if ((inst->module->sql_query)(sqlsocket, inst->config, querystr) < 0) {
					radlog(L_ERR, "rlm_sql: Couldn't update SQL accounting STOP record - %s", (char *)(inst->module->sql_error)(sqlsocket, inst->config));
				}
				else {
					numaffected = (inst->module->sql_affected_rows)(sqlsocket, inst->config);
					if (numaffected < 1) {
						/*
						 * If our update above didn't match anything
						 * we assume it's because we haven't seen a 
						 * matching Start record.  So we have to
						 * insert this stop rather than do an update
						 */
#ifdef CISCO_ACCOUNTING_HACK
					        /*
					         * If stop but zero session length AND no previous
					         * session found, drop it as in invalid packet
				        	 * This is to fix CISCO's aaa from filling our
				        	 * table with bogus crap
					         */
					        if ((pair = pairfind(request->packet->vps, PW_ACCT_SESSION_TIME)) != NULL)
					                acctsessiontime = pair->lvalue;
	
					        if (acctsessiontime <= 0) {
				        	        radius_xlat(logstr, MAX_QUERY_LEN, "rlm_sql:  Stop packet with zero session length.  (user '%{User-Name}', nas '%{NAS-IP-Address}')", request, sql_escape_func);
					                radlog(L_ERR, logstr);
				        	        sql_release_socket(inst, sqlsocket);
				                	return RLM_MODULE_NOOP;
					        }
#endif

						radius_xlat(querystr, MAX_QUERY_LEN, inst->config->accounting_stop_query_alt, request, sql_escape_func);
						query_log(inst, querystr);

						if (querystr) {
							if ((inst->module->sql_query)(sqlsocket, inst->config, querystr) < 0) {
								radlog(L_ERR, "rlm_sql: Couldn't insert SQL accounting STOP record - %s", (char *)(inst->module->sql_error)(sqlsocket, inst->config));
							}
							(inst->module->sql_finish_query)(sqlsocket, inst->config);
						}
					}
				}
				(inst->module->sql_finish_query)(sqlsocket, inst->config);
			}
			break;
	}

	sql_release_socket(inst, sqlsocket);

	return RLM_MODULE_OK;
}


/* globally exported name */
module_t rlm_sql = {
	"SQL",
	RLM_TYPE_THREAD_SAFE,	/* type: reserved */
	rlm_sql_init,		/* initialization */
	rlm_sql_instantiate,	/* instantiation */
	{
		NULL,			/* authentication */
		rlm_sql_authorize,	/* authorization */
		NULL,			/* preaccounting */
		rlm_sql_accounting,	/* accounting */
		NULL			/* checksimul */
	},
	rlm_sql_detach,		/* detach */
	rlm_sql_destroy,	/* destroy */
};
