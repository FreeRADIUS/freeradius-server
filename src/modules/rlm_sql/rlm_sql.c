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

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"
#include "rlm_sql.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static SQL_CONFIG config;

static CONF_PARSER module_config[] = {
	{"server", PW_TYPE_STRING_PTR, &config.sql_server, "localhost"},
	{"login", PW_TYPE_STRING_PTR, &config.sql_login, ""},
	{"password", PW_TYPE_STRING_PTR, &config.sql_password, ""},
	{"radius_db", PW_TYPE_STRING_PTR, &config.sql_db, "radius"},
	{"acct_table", PW_TYPE_STRING_PTR, &config.sql_acct_table, "radacct"},
	{"authcheck_table", PW_TYPE_STRING_PTR, &config.sql_authcheck_table, "radcheck"},
	{"authreply_table", PW_TYPE_STRING_PTR, &config.sql_authreply_table, "radreply"},
	{"groupcheck_table", PW_TYPE_STRING_PTR, &config.sql_groupcheck_table, "radgroupcheck"},
	{"groupreply_table", PW_TYPE_STRING_PTR, &config.sql_groupreply_table, "radgroupreply"},
	{"usergroup_table", PW_TYPE_STRING_PTR, &config.sql_usergroup_table, "usergroup"},
	{"realm_table", PW_TYPE_STRING_PTR, &config.sql_realm_table, "realms"},
	{"realmgroup_table", PW_TYPE_STRING_PTR, &config.sql_realmgroup_table, "realmgroup"},
	{"nas_table", PW_TYPE_STRING_PTR, &config.sql_nas_table, "nas"},
	{"dict_table", PW_TYPE_STRING_PTR, &config.sql_dict_table, "dictionary"},
	{"sensitiveusername", PW_TYPE_BOOLEAN, &config.sensitiveusername, "1"},
	{"sqltrace", PW_TYPE_BOOLEAN, &config.sqltrace, "0"},
	{"sqltracefile", PW_TYPE_STRING_PTR, &config.tracefile, SQLTRACEFILE},
	{"deletestalesessions", PW_TYPE_BOOLEAN, &config.deletestalesessions, "0"},
	{"num_sql_socks", PW_TYPE_INTEGER, &config.num_sql_socks, "5"},

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

static int rlm_sql_instantiate(CONF_SECTION *conf, void **instance) {

	SQL_INST *inst;

	if ((inst = malloc(sizeof(SQL_INST))) == NULL) {
		radlog(L_ERR | L_CONS, "sql_instantiate:  no memory");
		return -1;
	}
	memset(inst, 0, sizeof(SQL_INST));
	if ((inst->config = malloc(sizeof(SQL_CONFIG))) == NULL) {
		radlog(L_ERR | L_CONS, "sql_instantiate:  no memory");
		free(inst);
		return -1;
	}
	memset(inst->config, 0, sizeof(SQL_CONFIG));

#if HAVE_PTHREAD_H
	inst->lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if (inst->lock == NULL)
		return -1;
	pthread_mutex_init(inst->lock, NULL);

	inst->notfull = (pthread_cond_t *)malloc(sizeof(pthread_cond_t));
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

	if(config.num_sql_socks > MAX_SQL_SOCKS) {
		radlog(L_ERR | L_CONS, "sql_instantiate:  number of sqlsockets cannot exceed %d", MAX_SQL_SOCKS);
		free(inst->config);
		free(inst);
		return -1;
	}

	inst->config->sql_server		= config.sql_server;
	inst->config->sql_login			= config.sql_login;
	inst->config->sql_password		= config.sql_password;
	inst->config->sql_db			= config.sql_db;
	inst->config->sql_acct_table		= config.sql_acct_table;	
	inst->config->sql_authcheck_table	= config.sql_authcheck_table;
	inst->config->sql_authreply_table	= config.sql_authreply_table;
	inst->config->sql_groupcheck_table	= config.sql_groupcheck_table;
	inst->config->sql_groupreply_table	= config.sql_groupreply_table;
	inst->config->sql_usergroup_table	= config.sql_usergroup_table;
	inst->config->sql_realm_table		= config.sql_realm_table;
	inst->config->sql_realmgroup_table	= config.sql_realmgroup_table;
	inst->config->sql_nas_table		= config.sql_nas_table;
	inst->config->sql_dict_table		= config.sql_dict_table;
	inst->config->sensitiveusername		= config.sensitiveusername;
	inst->config->sqltrace			= config.sqltrace;
	inst->config->tracefile			= config.tracefile;
	inst->config->deletestalesessions	= config.deletestalesessions;
	inst->config->num_sql_socks		= config.num_sql_socks;

	config.sql_server		= NULL;
	config.sql_login		= NULL;
	config.sql_password		= NULL;
	config.sql_db			= NULL;
	config.sql_acct_table		= NULL;
	config.sql_authcheck_table	= NULL;
	config.sql_authreply_table	= NULL;
	config.sql_groupcheck_table	= NULL;
	config.sql_groupreply_table	= NULL;
	config.sql_usergroup_table	= NULL;
	config.sql_realm_table		= NULL;
	config.sql_realmgroup_table	= NULL;
	config.sql_nas_table		= NULL;
	config.sql_dict_table		= NULL;
	config.tracefile		= NULL;

	radlog(L_INFO, "rlm_sql: Attempting to connect to %s@%s:%s",
		inst->config->sql_login, inst->config->sql_server,
		inst->config->sql_db);

	if(sql_init_socketpool(inst) < 0) {
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

	int     nas_port = 0;
	VALUE_PAIR *check_tmp = NULL;
	VALUE_PAIR *reply_tmp = NULL;
	VALUE_PAIR *tmp;
	int     found = 0;
	char   *name;
	SQLSOCK *sqlsocket;
	SQL_INST *inst = instance;

	name = request->username->strvalue;

	/*
	 *      Check for valid input, zero length names not permitted
	 */
	if (name[0] == 0) {
		radlog(L_ERR, "zero length username not permitted\n");
		return -1;
	}

	sqlsocket = sql_get_socket(inst);

	/*
	 *      Find the NAS port ID.
	 */
	if ((tmp = pairfind(request->packet->vps, PW_NAS_PORT_ID)) != NULL)
		nas_port = tmp->lvalue;


	/*
	 *      Find the entry for the user.
	 */
	if ((found = sql_getvpdata(inst, sqlsocket, inst->config->sql_authcheck_table, &check_tmp, name, PW_VP_USERDATA)) > 0) {
		sql_getvpdata(inst, sqlsocket, inst->config->sql_groupcheck_table, &check_tmp, name, PW_VP_GROUPDATA);
		sql_getvpdata(inst, sqlsocket, inst->config->sql_authreply_table, &reply_tmp, name, PW_VP_USERDATA);
		sql_getvpdata(inst, sqlsocket, inst->config->sql_groupreply_table, &reply_tmp, name, PW_VP_GROUPDATA);
	} else if(found < 0) {
		radlog(L_ERR, "rlm_sql:  SQL query error; rejecting user");
		return -1;

	} else {

		int     gcheck, greply;

		gcheck = sql_getvpdata(inst, sqlsocket, inst->config->sql_groupcheck_table, &check_tmp, "DEFAULT", PW_VP_GROUPDATA);
		greply = sql_getvpdata(inst, sqlsocket, inst->config->sql_groupreply_table, &reply_tmp, "DEFAULT", PW_VP_GROUPDATA);
		if (gcheck && greply)
			found = 1;
	}

	sql_release_socket(inst, sqlsocket);

	if (!found) {
		radlog(L_DBG,"rlm_sql: User %s not found and DEFAULT not found", name);
		return RLM_MODULE_NOTFOUND;
	}

	if (paircmp(request->packet->vps, check_tmp, &reply_tmp) != 0) {
		radlog(L_INFO,"rlm_sql: Pairs do not match [%s]", name);
		return RLM_MODULE_FAIL;
	}

	pairmove(&request->reply->vps, &reply_tmp);
	pairmove(&request->config_items, &check_tmp);
	pairfree(&reply_tmp);
	pairfree(&check_tmp);

	return RLM_MODULE_OK;
}

static int
rlm_sql_authenticate(void *instance, REQUEST *request)
{

	SQL_ROW row;
	SQLSOCK *sqlsocket;
	char   *querystr;
	char    escaped_user[AUTH_STRING_LEN * 3];
	char   *user;
	const char query[] = "SELECT Value FROM %s WHERE UserName = '%s' AND Attribute = 'Password'";
	SQL_INST *inst = instance;

	user = request->username->strvalue;

	/*
	 *      Ensure that a password attribute exists.
	 */
	if ((request->password == NULL) ||
			(request->password->length == 0) ||
			(request->password->attribute != PW_PASSWORD)) {
		radlog(L_AUTH, "rlm_sql: Attribute \"Password\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	sql_escape_string(escaped_user, user, strlen(user));

	/*
	 *      This should really be replaced with a static buffer...
	 */
	if ((querystr = malloc(strlen(escaped_user) +
												 strlen(inst->config->sql_authcheck_table) +
												 sizeof(query))) == NULL) {
		radlog(L_ERR | L_CONS, "no memory");
		exit(1);
	}

	sprintf(querystr, query, inst->config->sql_authcheck_table, escaped_user);
	sqlsocket = sql_get_socket(inst);
	if (sql_select_query(inst, sqlsocket, querystr) < 0) {
		radlog(L_ERR,"rlm_sql_authenticate: database query error");
		sql_release_socket(inst, sqlsocket);
		return RLM_MODULE_REJECT;
	}

	row = sql_fetch_row(sqlsocket);
	sql_finish_select_query(sqlsocket);
	sql_release_socket(inst, sqlsocket);
	sql_free_result(sqlsocket);
	free(querystr);

	if (row == NULL) {
		radlog(L_ERR,"rlm_sql_authenticate: no rows returned from query (no such user)");
		return RLM_MODULE_REJECT;
	}

	/* Just compare the two */
	if (strncmp(request->password->strvalue,
		row[0],
		request->password->length) != 0) {
			return RLM_MODULE_REJECT;
	}
	return RLM_MODULE_OK;

}

/*
 *	Accounting: save the account data to our sql table
 */
static int rlm_sql_accounting(void *instance, REQUEST * request) {

	time_t  nowtime;
	struct tm *tim;
	char    datebuf[20];
	VALUE_PAIR *pair;
	SQLACCTREC *sqlrecord;
	SQLSOCK *sqlsocket;
	DICT_VALUE *dval;
	SQL_INST *inst = instance;
	int lentmp = 0;

	/*
	 * FIXME:  Should we really do this malloc?
	 * Why not a static structure, because this malloc is 
	 * relatively expensive considering we do it for every
	 * accounting packet
	 */
	if ((sqlrecord = malloc(sizeof(SQLACCTREC))) == NULL) {
		radlog(L_ERR | L_CONS, "no memory");
		exit(1);
	}
	memset(sqlrecord, 0, sizeof(SQLACCTREC));

	pair = request->packet->vps;
	while (pair != (VALUE_PAIR *) NULL) {

		/*
		 * Check the pairs to see if they are anything we are interested in. 
		 */
		switch (pair->attribute) {
			case PW_ACCT_SESSION_ID:
				strncpy(sqlrecord->AcctSessionId, pair->strvalue, SQLBIGREC);
				break;

			case PW_ACCT_UNIQUE_SESSION_ID:
				strncpy(sqlrecord->AcctUniqueId, pair->strvalue, SQLBIGREC);
				break;

			case PW_USER_NAME:
				strncpy(sqlrecord->UserName, pair->strvalue, SQLBIGREC);
				break;

			case PW_NAS_IP_ADDRESS:
				ip_ntoa(sqlrecord->NASIPAddress, pair->lvalue);
				//ipaddr2str(sqlrecord->NASIPAddress, pair->lvalue);
				break;

			case PW_NAS_PORT_ID:
				sqlrecord->NASPortId = pair->lvalue;
				break;

			case PW_NAS_PORT_TYPE:
				dval = dict_valbyattr(PW_NAS_PORT_TYPE, pair->lvalue);
				if (dval != NULL) {
					strncpy(sqlrecord->NASPortType, dval->name, SQLBIGREC);
				}
				break;

			case PW_ACCT_STATUS_TYPE:
				sqlrecord->AcctStatusTypeId = pair->lvalue;
				dval = dict_valbyattr(PW_ACCT_STATUS_TYPE, pair->lvalue);
				if (dval != NULL) {
					strncpy(sqlrecord->AcctStatusType, dval->name, SQLBIGREC);
				}
				break;

			case PW_ACCT_SESSION_TIME:
				sqlrecord->AcctSessionTime = pair->lvalue;
				break;

			case PW_ACCT_AUTHENTIC:
				dval = dict_valbyattr(PW_ACCT_AUTHENTIC, pair->lvalue);
				if (dval != NULL) {
					strncpy(sqlrecord->AcctAuthentic, dval->name, SQLBIGREC);
				}
				break;

			case PW_CONNECT_INFO:
				strncpy(sqlrecord->ConnectInfo, pair->strvalue, SQLBIGREC);
				break;

			case PW_ACCT_INPUT_OCTETS:
				sqlrecord->AcctInputOctets = pair->lvalue;
				break;

			case PW_ACCT_OUTPUT_OCTETS:
				sqlrecord->AcctOutputOctets = pair->lvalue;
				break;

			case PW_CALLED_STATION_ID:
				strncpy(sqlrecord->CalledStationId, pair->strvalue, SQLLILREC);
				break;

			case PW_CALLING_STATION_ID:
      	/* USR 00 workaround */
				lentmp = strlen(pair->strvalue);
				if(lentmp > 10) {
					strncpy(sqlrecord->CallingStationId, pair->strvalue+(lentmp-10), SQLLILREC);
				} else {
					strncpy(sqlrecord->CallingStationId, pair->strvalue, SQLLILREC);
				}
				break;

			case PW_ACCT_TERMINATE_CAUSE:
				dval = dict_valbyattr(PW_ACCT_TERMINATE_CAUSE, pair->lvalue);
				if(dval != NULL) {
					strncpy(sqlrecord->AcctTerminateCause, dval->name, SQLBIGREC);
				}
				break;

			case PW_SERVICE_TYPE:
				dval = dict_valbyattr(PW_SERVICE_TYPE, pair->lvalue);
				if (dval != NULL) {
					strncpy(sqlrecord->ServiceType, dval->name, SQLBIGREC);
				}
				break;

			case PW_FRAMED_PROTOCOL:
				dval = dict_valbyattr(PW_FRAMED_PROTOCOL, pair->lvalue);
				if (dval != NULL) {
					strncpy(sqlrecord->FramedProtocol, dval->name, SQLBIGREC);
				}
				break;

			case PW_FRAMED_IP_ADDRESS:
				ip_ntoa(sqlrecord->FramedIPAddress, pair->lvalue);
				//ipaddr2str(sqlrecord->FramedIPAddress, pair->lvalue);
				break;

			case PW_ACCT_DELAY_TIME:
				sqlrecord->AcctDelayTime = pair->lvalue;
				break;

			/* 
			 * FIXME:  USR VSA for:  USR-Connect-Speed 
			 * Ugly hack.  Will go away when conf-based
			 * tables are implemented
			 */
      case 167971:
				dval = dict_valbyattr(167971, pair->lvalue);
				if(dval != NULL)  {
					strncpy(sqlrecord->ConnectInfo, dval->name, SQLBIGREC);
				}
				break;

			/* Appears to be LE-Terminate-Detail */
			case 65538:
				strncpy(sqlrecord->AcctTerminateCause, pair->strvalue, SQLBIGREC);
				break;

			default:
				break;
		}

		pair = pair->next;
	}


	nowtime = request->timestamp - sqlrecord->AcctDelayTime;
	tim = localtime(&nowtime);
	strftime(datebuf, sizeof(datebuf), "%Y%m%d%H%M%S", tim);

	strncpy(sqlrecord->AcctTimeStamp, datebuf, 20);

	sqlsocket = sql_get_socket(inst);
	sql_save_acct(inst, sqlsocket, sqlrecord);
	sql_release_socket(inst, sqlsocket);

	return RLM_MODULE_OK;
}


/* globally exported name */
module_t rlm_sql = {
	"SQL",
	0,			/* type: reserved */
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
