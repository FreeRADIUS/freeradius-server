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

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"
#include "rlm_sql.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static SQL_CONFIG config;

static CONF_PARSER module_config[] = {
	{"driver",PW_TYPE_STRING_PTR, &config.sql_driver, "mysql"},
	{"server",PW_TYPE_STRING_PTR, &config.sql_server, "localhost"},
	{"login", PW_TYPE_STRING_PTR, &config.sql_login, ""},
	{"password", PW_TYPE_STRING_PTR, &config.sql_password, ""},
	{"radius_db", PW_TYPE_STRING_PTR, &config.sql_db, "radius"},
	{"acct_table", PW_TYPE_STRING_PTR, &config.sql_acct_table, "radacct"},
	{"acct_table2", PW_TYPE_STRING_PTR, &config.sql_acct_table2, "radacct"},
	{"authcheck_table", PW_TYPE_STRING_PTR, &config.sql_authcheck_table, "radcheck"},
	{"authreply_table", PW_TYPE_STRING_PTR, &config.sql_authreply_table, "radreply"},
	{"groupcheck_table", PW_TYPE_STRING_PTR, &config.sql_groupcheck_table, "radgroupcheck"},
	{"groupreply_table", PW_TYPE_STRING_PTR, &config.sql_groupreply_table, "radgroupreply"},
	{"usergroup_table", PW_TYPE_STRING_PTR, &config.sql_usergroup_table, "usergroup"},
	{"nas_table", PW_TYPE_STRING_PTR, &config.sql_nas_table, "nas"},
	{"dict_table", PW_TYPE_STRING_PTR, &config.sql_dict_table, "dictionary"},
	{"sqltrace", PW_TYPE_BOOLEAN, &config.sqltrace, "0"},
	{"sqltracefile", PW_TYPE_STRING_PTR, &config.tracefile, SQLTRACEFILE},
	{"deletestalesessions", PW_TYPE_BOOLEAN, &config.deletestalesessions, "0"},
	{"num_sql_socks", PW_TYPE_INTEGER, &config.num_sql_socks, "5"},
	{"authorize_query", PW_TYPE_STRING_PTR, &config.authorize_query, ""},
	{"authorize_group_query", PW_TYPE_STRING_PTR, &config.authorize_group_query, ""},
	{"authenticate_query", PW_TYPE_STRING_PTR, &config.authenticate_query, ""},
	{"accounting_onoff_query", PW_TYPE_STRING_PTR, &config.accounting_onoff_query, ""},
	{"accounting_update_query", PW_TYPE_STRING_PTR, &config.accounting_update_query, ""},
	{"accounting_start_query", PW_TYPE_STRING_PTR, &config.accounting_start_query, ""},
	{"accounting_start_query_alt", PW_TYPE_STRING_PTR, &config.accounting_start_query_alt, ""},
	{"accounting_stop_query", PW_TYPE_STRING_PTR, &config.accounting_stop_query, ""},
	{"accounting_stop_query_alt", PW_TYPE_STRING_PTR, &config.accounting_stop_query_alt, ""},

	{NULL, -1, NULL, NULL}
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
	if (cf_section_parse(conf, module_config) < 0) {
		free(inst->config);
		free(inst);
		return -1;
	}

	if (config.num_sql_socks > MAX_SQL_SOCKS) {
		radlog(L_ERR | L_CONS, "sql_instantiate:  number of sqlsockets cannot exceed %d", MAX_SQL_SOCKS);
		free(inst->config);
		free(inst);
		return -1;
	}

	inst->config->sql_driver = config.sql_driver;
	inst->config->sql_server = config.sql_server;
	inst->config->sql_login = config.sql_login;
	inst->config->sql_password = config.sql_password;
	inst->config->sql_db = config.sql_db;
	inst->config->sql_acct_table = config.sql_acct_table;
	inst->config->sql_acct_table2 = config.sql_acct_table2;
	inst->config->sql_authcheck_table = config.sql_authcheck_table;
	inst->config->sql_authreply_table = config.sql_authreply_table;
	inst->config->sql_groupcheck_table = config.sql_groupcheck_table;
	inst->config->sql_groupreply_table = config.sql_groupreply_table;
	inst->config->sql_usergroup_table = config.sql_usergroup_table;
	inst->config->sql_nas_table = config.sql_nas_table;
	inst->config->sql_dict_table = config.sql_dict_table;
	inst->config->sqltrace = config.sqltrace;
	inst->config->tracefile = config.tracefile;
	inst->config->deletestalesessions = config.deletestalesessions;
	inst->config->num_sql_socks = config.num_sql_socks;
	inst->config->authorize_query = config.authorize_query;
	inst->config->authorize_group_query = config.authorize_group_query;
	inst->config->authenticate_query = config.authenticate_query;
	inst->config->accounting_onoff_query = config.accounting_onoff_query;
	inst->config->accounting_update_query = config.accounting_update_query;
	inst->config->accounting_start_query = config.accounting_start_query;
	inst->config->accounting_start_query_alt = config.accounting_start_query_alt;
	inst->config->accounting_stop_query = config.accounting_stop_query;
	inst->config->accounting_stop_query_alt = config.accounting_stop_query_alt;

	config.sql_driver = NULL;
	config.sql_server = NULL;
	config.sql_login = NULL;
	config.sql_password = NULL;
	config.sql_db = NULL;
	config.sql_acct_table = NULL;
	config.sql_acct_table2 = NULL;
	config.sql_authcheck_table = NULL;
	config.sql_authreply_table = NULL;
	config.sql_groupcheck_table = NULL;
	config.sql_groupreply_table = NULL;
	config.sql_usergroup_table = NULL;
	config.sql_nas_table = NULL;
	config.sql_dict_table = NULL;
	config.tracefile = NULL;
	config.authorize_query = NULL;
	config.authorize_group_query = NULL;
	config.authenticate_query = NULL;
	config.accounting_onoff_query = NULL;
	config.accounting_update_query = NULL;
	config.accounting_start_query = NULL;
	config.accounting_start_query_alt = NULL;
	config.accounting_stop_query = NULL;
	config.accounting_stop_query_alt = NULL;


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
	char   *name;
	SQLSOCK *sqlsocket;
	SQL_INST *inst = instance;
	char    querystr[MAX_QUERY_LEN];
	char    saveuser[MAX_STRING_LEN];
	int     savelen = 0;

	VALUE_PAIR *uservp = NULL;

	sqlsocket = sql_get_socket(inst);

	/*
	 * Set, escape, and check the user attr here
	 */
	uservp = set_userattr(inst, sqlsocket, request->packet->vps, NULL, saveuser, &savelen);
	name = uservp->strvalue;
	if (name[0] == 0) {
		radlog(L_ERR, "zero length username not permitted\n");
		sql_release_socket(inst, sqlsocket);
		restore_userattr(uservp, saveuser, savelen);
		return -1;
	}

	radius_xlat2(querystr, MAX_QUERY_LEN, inst->config->authorize_query, request);
	found = sql_getvpdata(inst, sqlsocket, &check_tmp, &reply_tmp, querystr, PW_VP_USERDATA);
	/*
	 *      Find the entry for the user.
	 */
	if (found > 0) {
		radius_xlat2(querystr, MAX_QUERY_LEN, inst->config->authorize_group_query, request);
		sql_getvpdata(inst, sqlsocket, &check_tmp, &reply_tmp, querystr, PW_VP_GROUPDATA);
	} else if (found < 0) {
		radlog(L_ERR, "rlm_sql:  SQL query error; rejecting user");
		sql_release_socket(inst, sqlsocket);
		restore_userattr(uservp, saveuser, savelen);
		return -1;

	} else {

		int     gcheck;

		/*
		 * We didn't find the user, so we try looking
		 * for a DEFAULT entry
		 */
		set_userattr(inst, sqlsocket, uservp, "DEFAULT", NULL, NULL);
		radius_xlat2(querystr, MAX_QUERY_LEN, inst->config->authorize_group_query, request);
		gcheck = sql_getvpdata(inst, sqlsocket, &check_tmp, &reply_tmp, querystr, PW_VP_GROUPDATA);
		if (gcheck)
			found = 1;
	}
	restore_userattr(uservp, saveuser, savelen);

	sql_release_socket(inst, sqlsocket);

	if (!found) {
		radlog(L_DBG, "rlm_sql: User %s not found and DEFAULT not found", name);
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

	if (paircmp(request->packet->vps, check_tmp, &reply_tmp) != 0) {
		radlog(L_INFO, "rlm_sql: Pairs do not match [%s]", name);
		return RLM_MODULE_FAIL;
	}

	pairmove(&request->reply->vps, &reply_tmp);
	pairmove(&request->config_items, &check_tmp);
	pairfree(&reply_tmp);
	pairfree(&check_tmp);

	return RLM_MODULE_OK;
}

static int rlm_sql_authenticate(void *instance, REQUEST * request) {

	SQL_ROW row;
	SQLSOCK *sqlsocket;
	char    querystr[MAX_QUERY_LEN];
	VALUE_PAIR *uservp;
	char    saveuser[MAX_STRING_LEN];
	int     savelen = 0;
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
	 * 3. Replace User-Name attr with saved value
	 */
	uservp = set_userattr(inst, sqlsocket, request->packet->vps, NULL, saveuser, &savelen);
	radius_xlat2(querystr, MAX_QUERY_LEN, inst->config->authenticate_query, request);
	restore_userattr(uservp, saveuser, savelen);

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
		radius_xlat2(logstr, MAX_QUERY_LEN, "rlm_sql:  packet has no account status type.  [user '%{User-Name}', nas '%{NAS-IP-Address}']", request);
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
		radius_xlat2(logstr, MAX_QUERY_LEN, "rlm_sql:  Stop packet with zero session" " length.  (user '%{User-Name}', nas '%{NAS-IP-Address}')", request);
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
			radius_xlat2(querystr, MAX_QUERY_LEN, inst->config->accounting_onoff_query, request);
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

			radius_xlat2(querystr, MAX_QUERY_LEN, inst->config->accounting_update_query, request);
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

			radius_xlat2(querystr, MAX_QUERY_LEN, inst->config->accounting_start_query, request);
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
					radius_xlat2(querystr, MAX_QUERY_LEN, inst->config->accounting_start_query_alt, request);
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

			radius_xlat2(querystr, MAX_QUERY_LEN, inst->config->accounting_stop_query, request);
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
				radius_xlat2(querystr, MAX_QUERY_LEN, inst->config->accounting_stop_query_alt, request);
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
	rlm_sql_authorize,	/* authorization */
	rlm_sql_authenticate,	/* authentication */
	NULL,			/* preaccounting */
	rlm_sql_accounting,	/* accounting */
	NULL,			/* checksimul */
	rlm_sql_detach,		/* detach */
	rlm_sql_destroy,	/* destroy */
};
