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
 *
 * If you want this code to look right, set your tabstop to 2 or 3 
 * for vi users -  :set ts=3
 *
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

static CONF_PARSER module_config[] = {
	{"driver",PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_driver), NULL, "mysql"},
	{"server",PW_TYPE_STRING_PTR, offsetof(SQL_CONFIG,sql_server), NULL, "localhost"},
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


static int rlm_sql_instantiate(CONF_SECTION * conf, void **instance) {

	SQL_INST *inst;
	lt_dlhandle *handle;

	inst = rad_malloc(sizeof(SQL_INST));
	memset(inst, 0, sizeof(SQL_INST));

	inst->config = rad_malloc(sizeof(SQL_CONFIG));
	memset(inst->config, 0, sizeof(SQL_CONFIG));

#if HAVE_PTHREAD_H
	inst->lock = (pthread_mutex_t *) rad_malloc(sizeof(pthread_mutex_t));
	pthread_mutex_init(inst->lock, NULL);

	inst->notfull = (pthread_cond_t *) rad_malloc(sizeof(pthread_cond_t));
	pthread_cond_init(inst->notfull, NULL);
#endif

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
		radlog(L_ERR | L_CONS, "sql_instantiate:  number of sqlsockets cannot exceed %d", MAX_SQL_SOCKS);
		free(inst->config);
		free(inst);
		return -1;
	}

	handle = lt_dlopenext(inst->config->sql_driver);
	if (handle == NULL) {
		radlog(L_ERR, "rlm_sql: Could not link driver %s: %s", inst->config->sql_driver, lt_dlerror());
		return -1;
	}

	inst->module = (rlm_sql_module_t *) lt_dlsym(handle, inst->config->sql_driver);
	if (!inst->module) {
		radlog(L_ERR, "rlm_sql: Could not link symbol %s: %s", inst->config->sql_driver, lt_dlerror());
		return -1;
	}

	radlog(L_INFO, "rlm_sql: Driver %s loaded and linked", inst->config->sql_driver);
	radlog(L_INFO, "rlm_sql: Attempting to connect to %s@%s:%s", inst->config->sql_login, inst->config->sql_server, inst->config->sql_db);

	if (sql_init_socketpool(inst) < 0) {
		free(inst->config);
		free(inst);
		return -1;
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
	free(inst->config);
	free(inst);

	return 0;
}


static int rlm_sql_authorize(void *instance, REQUEST * request) {

	VALUE_PAIR *check_tmp = NULL;
	VALUE_PAIR *reply_tmp = NULL;
	int     found = 0;
	SQLSOCK *sqlsocket;
	SQL_INST *inst = instance;
	char    querystr[MAX_QUERY_LEN];
	char   sqlusername[MAX_STRING_LEN];

	/*
	 *	They MUST have a user name to do SQL authorization.
	 */
	if ((!request->username) ||
	    (request->username->length == 0)) {
		radlog(L_ERR, "zero length username not permitted\n");
		return RLM_MODULE_INVALID;
	}

	sqlsocket = sql_get_socket(inst);

	/*
	 * Set, escape, and check the user attr here
	 */
	if(sql_set_user(inst, request, sqlusername, 0) < 0) 
		return RLM_MODULE_FAIL;
	radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authorize_check_query, request, NULL);
	found = sql_getvpdata(inst, sqlsocket, &check_tmp, querystr, PW_VP_USERDATA);
	/*
	 *      Find the entry for the user.
	 */
	if (found > 0) {
		radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authorize_group_check_query, request, NULL);
		sql_getvpdata(inst, sqlsocket, &check_tmp, querystr, PW_VP_GROUPDATA);
		radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authorize_reply_query, request, NULL);
		sql_getvpdata(inst, sqlsocket, &reply_tmp, querystr, PW_VP_USERDATA);
		radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authorize_group_reply_query, request, NULL);
		sql_getvpdata(inst, sqlsocket, &reply_tmp, querystr, PW_VP_GROUPDATA);
	} else if (found < 0) {
		radlog(L_ERR, "rlm_sql:  SQL query error; rejecting user");
		sql_release_socket(inst, sqlsocket);
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_SQL_USER_NAME);
		return RLM_MODULE_INVALID;

	} else {

		int     gcheck;

		/*
		 * We didn't find the user, so we try looking
		 * for a DEFAULT entry
		 */
		if(sql_set_user(inst, request, sqlusername, "DEFAULT") < 0) 
			return RLM_MODULE_FAIL;
		radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authorize_group_check_query, request, NULL);
		gcheck = sql_getvpdata(inst, sqlsocket, &check_tmp, querystr, PW_VP_GROUPDATA);
		radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authorize_group_reply_query, request, NULL);
		gcheck = sql_getvpdata(inst, sqlsocket, &reply_tmp, querystr, PW_VP_GROUPDATA);
		if (gcheck)
			found = 1;
	}
	/* Remove the username we (maybe) added above */
	pairdelete(&request->packet->vps, PW_SQL_USER_NAME);

	sql_release_socket(inst, sqlsocket);

	if (!found) {
		radlog(L_DBG, "rlm_sql: User %s not found and DEFAULT not found", sqlusername);
		return RLM_MODULE_NOTFOUND;
	}

	/*
	 * Uncomment these lines for debugging
	 * Recompile, and run 'radiusd -X'
	 *
	 DEBUG2("rlm_sql:  check items");
	 vp_printlist(stderr, check_tmp);
	 DEBUG2("rlm_sql:  reply items");
	 vp_printlist(stderr, reply_tmp);
	 */

	vp_printlist(stderr, check_tmp);
	if (paircmp(request->packet->vps, check_tmp, &reply_tmp) != 0) {
		radlog(L_INFO, "rlm_sql: Pairs do not match [%s]", sqlusername);
		return RLM_MODULE_FAIL;
	}

	pairmove(&request->reply->vps, &reply_tmp);
	pairmove(&request->config_items, &check_tmp);
	pairfree(&reply_tmp);
	pairfree(&check_tmp);

	return RLM_MODULE_OK;
}

static int rlm_sql_authenticate(void *instance, REQUEST * request) {

	char   sqlusername[MAX_STRING_LEN];
	char    querystr[MAX_QUERY_LEN];
	SQL_ROW row;
	SQLSOCK *sqlsocket;
	SQL_INST *inst = instance;

	/*
	 *      Ensure that a password attribute exists.
	 */
	if ((request->password == NULL) ||
			(request->password->length == 0) ||
			(request->password->attribute != PW_PASSWORD)) {
		radlog(L_AUTH, "rlm_sql: Attribute \"Password\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	sqlsocket = sql_get_socket(inst);

	/*
	 * 1. Set username to escaped value
	 * 2. Translate vars in the query
	 * 3. Remove SQL-User-Name local attr
	 */
	if(sql_set_user(inst, request, sqlusername, 0) < 0) 
		return RLM_MODULE_FAIL;
	radius_xlat(querystr, MAX_QUERY_LEN, inst->config->authenticate_query, request, NULL);
	pairdelete(&request->packet->vps, PW_SQL_USER_NAME);

	if ((inst->module->sql_select_query)(sqlsocket, inst->config, querystr) < 0) {
		radlog(L_ERR, "rlm_sql_authenticate: database query error");
		sql_release_socket(inst, sqlsocket);
		return RLM_MODULE_REJECT;
	}

	row = (inst->module->sql_fetch_row)(sqlsocket, inst->config);
	(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
	sql_release_socket(inst, sqlsocket);

	if (row == NULL) {
		radlog(L_ERR, "rlm_sql_authenticate: no rows returned from query (no such user)");
		return RLM_MODULE_REJECT;
	}

	/* If this is a null the server will seg fault */
	if (row[0] == NULL) {
		radlog(L_ERR, "rlm_sql_authenticate: row[0] returned null.");
		return RLM_MODULE_REJECT;
	}

	/*
	 * Just compare the two 
	 */
	if (strncmp(request->password->strvalue, row[0], request->password->length) != 0) {
		return RLM_MODULE_REJECT;
	}
	return RLM_MODULE_OK;

}

/*
 *	Accounting: save the account data to our sql table
 */
static int rlm_sql_accounting(void *instance, REQUEST * request) {

	SQLSOCK *sqlsocket;
	VALUE_PAIR *pair;
	SQL_INST *inst = instance;
	int     numaffected = 0;
	int     acctstatustype = 0;
	char    querystr[MAX_QUERY_LEN];
	char    logstr[MAX_QUERY_LEN];

#ifdef CISCO_ACCOUNTING_HACK
	int     acctsessiontime = 0;
#endif

	sqlsocket = sql_get_socket(inst);
	memset(querystr, 0, MAX_QUERY_LEN);

	/*
	 * Find the Acct Status Type
	 */
	if ((pair = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE)) != NULL) {
		acctstatustype = pair->lvalue;
	} else {
		radius_xlat(logstr, MAX_QUERY_LEN, "rlm_sql:  packet has no account status type.  [user '%{User-Name}', nas '%{NAS-IP-Address}']", request, NULL);
		radlog(L_ERR, logstr);
		return 0;
	}

#ifdef CISCO_ACCOUNTING_HACK
	/*
	 * If stop but zero session length AND no previous
	 * session found, drop it as in invalid packet 
	 * This is to fix CISCO's aaa from filling our  
	 * table with bogus crap
	 */
	if ((pair = pairfind(request->packet->vps, PW_ACCT_SESSION_TIME)) != NULL)
		acctsessiontime = pair->lvalue;

	if ((acctsessiontime <= 0) && (acctstatustype == PW_STATUS_STOP)) {
		radius_xlat(logstr, MAX_QUERY_LEN, "rlm_sql:  Stop packet with zero session" " length.  (user '%{User-Name}', nas '%{NAS-IP-Address}')", request, NULL);
		radlog(L_ERR, logstr);
		return 0;
	}
#endif

	switch (acctstatustype) {
			/*
			 * The Terminal server informed us that it was rebooted
			 * STOP all records from this NAS 
			 */
		case PW_STATUS_ACCOUNTING_ON:
		case PW_STATUS_ACCOUNTING_OFF:
			radlog(L_INFO, "rlm_sql:  received Acct On/Off packet");
			radius_xlat(querystr, MAX_QUERY_LEN, inst->config->accounting_onoff_query, request, NULL);
			query_log(inst, querystr);

			if (querystr) {
				if ((inst->module->sql_query)(sqlsocket, inst->config, querystr) < 0)
					radlog(L_ERR, "rlm_sql: Couldn't update SQL accounting for ALIVE packet - %s", (char *)(inst->module->sql_error)(sqlsocket, inst->config));
				(inst->module->sql_finish_query)(sqlsocket, inst->config);
			}

			break;

			/*
			 * Got an update accounting packet
			 */
		case PW_STATUS_ALIVE:

			radius_xlat(querystr, MAX_QUERY_LEN, inst->config->accounting_update_query, request, NULL);
			query_log(inst, querystr);

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

			radius_xlat(querystr, MAX_QUERY_LEN, inst->config->accounting_start_query, request, NULL);
			query_log(inst, querystr);

			if (querystr) {
				if ((inst->module->sql_query)(sqlsocket, inst->config, querystr) < 0) {
					radlog(L_ERR, "rlm_sql: Couldn't update SQL accounting" " for ALIVE packet - %s", (char *)(inst->module->sql_error)(sqlsocket, inst->config));
					(inst->module->sql_finish_query)(sqlsocket, inst->config);

					/*
					 * We failed the insert above.  It's probably because 
					 * the stop record came before the start.  We try an
					 * our alternate query now (typically an UPDATE)
					 */
					radius_xlat(querystr, MAX_QUERY_LEN, inst->config->accounting_start_query_alt, request, NULL);
					query_log(inst, querystr);

					if (querystr) {
						if ((inst->module->sql_query)(sqlsocket, inst->config, querystr) < 0) {
							radlog(L_ERR, "rlm_sql: Couldn't update SQL" "accounting START record - %s", (char *)(inst->module->sql_error)(sqlsocket, inst->config));
						}
						(inst->module->sql_finish_query)(sqlsocket, inst->config);
					}
				}
			}
			break;

			/*
			 * Got accounting stop packet
			 */
		case PW_STATUS_STOP:

			radius_xlat(querystr, MAX_QUERY_LEN, inst->config->accounting_stop_query, request, NULL);
			query_log(inst, querystr);

			if (querystr) {
				if ((querystr) && (inst->module->sql_query)(sqlsocket, inst->config, querystr) < 0) {
					radlog(L_ERR, "rlm_sql: Couldn't insert SQL accounting START record - %s", (char *)(inst->module->sql_error)(sqlsocket, inst->config));
				}
				(inst->module->sql_finish_query)(sqlsocket, inst->config);
			}

			numaffected = (inst->module->sql_affected_rows)(sqlsocket, inst->config);
			if (numaffected < 1) {
				/*
				 * If our update above didn't match anything
				 * we assume it's because we haven't seen a 
				 * matching Start record.  So we have to
				 * insert this stop rather than do an update
				 */
				radius_xlat(querystr, MAX_QUERY_LEN, inst->config->accounting_stop_query_alt, request, NULL);
				query_log(inst, querystr);

				if (querystr) {
					if ((inst->module->sql_query)(sqlsocket, inst->config, querystr) < 0) {
						radlog(L_ERR, "rlm_sql: Couldn't update SQL accounting START record - %s", (char *)(inst->module->sql_error)(sqlsocket, inst->config));
					}
					(inst->module->sql_finish_query)(sqlsocket, inst->config);
				}
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
		rlm_sql_authenticate,	/* authentication */
		rlm_sql_authorize,	/* authorization */
		NULL,			/* preaccounting */
		rlm_sql_accounting,	/* accounting */
		NULL			/* checksimul */
	},
	rlm_sql_detach,		/* detach */
	rlm_sql_destroy,	/* destroy */
};
