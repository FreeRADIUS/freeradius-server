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

static char *allowed_chars = NULL;

static CONF_PARSER module_config[] = {
	{"driver",PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_driver), NULL, "mysql"},
	{"server",PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_server), NULL, "localhost"},
	{"port",PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_port), NULL, ""},
	{"login", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_login), NULL, ""},
	{"password", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_password), NULL, ""},
	{"radius_db", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_db), NULL, "radius"},
	{"acct_table", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_acct_table), NULL, "radacct"},
	{"acct_table2", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_acct_table2), NULL, "radacct"},
	{"authcheck_table", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_authcheck_table), NULL, "radcheck"},
	{"authreply_table", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_authreply_table), NULL, "radreply"},
	{"groupcheck_table", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_groupcheck_table), NULL, "radgroupcheck"},
	{"groupreply_table", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_groupreply_table), NULL, "radgroupreply"},
	{"usergroup_table", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_usergroup_table), NULL, "usergroup"},
	{"read_groups", PW_TYPE_BOOLEAN,
	 offsetof(SQL_CONFIG,read_groups), NULL, "yes"},
	{"nas_table", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_nas_table), NULL, "nas"},
	{"dict_table", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_dict_table), NULL, "dictionary"},
	{"sqltrace", PW_TYPE_BOOLEAN,
	 offsetof(SQL_CONFIG,sqltrace), NULL, "no"},
	{"sqltracefile", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,tracefile), NULL, SQLTRACEFILE},
	{"readclients", PW_TYPE_BOOLEAN,
	 offsetof(SQL_CONFIG,do_clients), NULL, "no"},
	{"deletestalesessions", PW_TYPE_BOOLEAN,
	 offsetof(SQL_CONFIG,deletestalesessions), NULL, "no"},
	{"num_sql_socks", PW_TYPE_INTEGER,
	 offsetof(SQL_CONFIG,num_sql_socks), NULL, "5"},
	{"sql_user_name", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,query_user), NULL, ""},
	{"default_user_profile", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,default_profile), NULL, ""},
	{"authorize_check_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,authorize_check_query), NULL, ""},
	{"authorize_reply_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,authorize_reply_query), NULL, ""},
	{"authorize_group_check_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,authorize_group_check_query), NULL, ""},
	{"authorize_group_reply_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,authorize_group_reply_query), NULL, ""},
	{"accounting_onoff_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,accounting_onoff_query), NULL, ""},
	{"accounting_update_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,accounting_update_query), NULL, ""},
	{"accounting_update_query_alt", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,accounting_update_query_alt), NULL, ""},
	{"accounting_start_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,accounting_start_query), NULL, ""},
	{"accounting_start_query_alt", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,accounting_start_query_alt), NULL, ""},
	{"accounting_stop_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,accounting_stop_query), NULL, ""},
	{"accounting_stop_query_alt", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,accounting_stop_query_alt), NULL, ""},
	{"group_membership_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,groupmemb_query), NULL, ""},
	{"connect_failure_retry_delay", PW_TYPE_INTEGER,
	 offsetof(SQL_CONFIG,connect_failure_retry_delay), NULL, "60"},
	{"simul_count_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,simul_count_query), NULL, ""},
	{"simul_verify_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,simul_verify_query), NULL, ""},
	{"postauth_table", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,sql_postauth_table), NULL, "radpostauth"},
	{"postauth_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,postauth_query), NULL, ""},
	{"safe-characters", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,allowed_chars), NULL, 
	"@abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_: /"},

	{NULL, -1, 0, NULL, NULL}
};

/*
 *	Fall-Through checking function from rlm_files.c
 */
static int fallthrough(VALUE_PAIR *vp)
{
	VALUE_PAIR *tmp;
	tmp = pairfind(vp, PW_FALL_THROUGH);

	return tmp ? tmp->lvalue : 0;
}


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
 *	Yucky prototype.
 */
static int sql_set_user(SQL_INST *inst, REQUEST *request, char *sqlusername, const char *username);
static int generate_sql_clients(SQL_INST *inst);
static int sql_escape_func(char *out, int outlen, const char *in);

/*
 *	sql xlat function. Right now only SELECTs are supported. Only
 *	the first element of the SELECT result will be used.
 */
static int sql_xlat(void *instance, REQUEST *request,
		    char *fmt, char *out, int freespace,
		    RADIUS_ESCAPE_STRING func)
{
	SQLSOCK *sqlsocket;
	SQL_ROW row;
	SQL_INST *inst = instance;
	char querystr[MAX_QUERY_LEN];
	char sqlusername[2 * MAX_STRING_LEN + 10];
	int ret = 0;

	DEBUG("rlm_sql (%s): - sql_xlat", inst->config->xlat_name);
	/*
         * Add SQL-User-Name attribute just in case it is needed
         *  We could search the string fmt for SQL-User-Name to see if this is
         *  needed or not
         */
	sql_set_user(inst, request, sqlusername, NULL);
	/*
	 * Do an xlat on the provided string (nice recursive operation).
	 */
	if (!radius_xlat(querystr, sizeof(querystr), fmt, request, sql_escape_func)) {
		radlog(L_ERR, "rlm_sql (%s): xlat failed.",
		       inst->config->xlat_name);
		return 0;
	}

	query_log(request, inst,querystr);
	sqlsocket = sql_get_socket(inst);
	if (sqlsocket == NULL)
		return 0;
	if (rlm_sql_select_query(sqlsocket,inst,querystr)){
		radlog(L_ERR, "rlm_sql (%s): database query error, %s: %s",
		       inst->config->xlat_name,querystr,
		       (char *)(inst->module->sql_error)(sqlsocket, inst->config));
		sql_release_socket(inst,sqlsocket);
		return 0;
	}

	ret = rlm_sql_fetch_row(sqlsocket, inst);

	if (ret) {
		DEBUG("rlm_sql (%s): SQL query did not succeed",
		      inst->config->xlat_name);
		(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
		sql_release_socket(inst,sqlsocket);
		return 0;
	}

	row = sqlsocket->row;
	if (row == NULL) {
		DEBUG("rlm_sql (%s): SQL query did not return any results",
		      inst->config->xlat_name);
		(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
		sql_release_socket(inst,sqlsocket);
		return 0;
	}

	if (row[0] == NULL){
		DEBUG("rlm_sql (%s): row[0] returned NULL",
		      inst->config->xlat_name);
		(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
		sql_release_socket(inst,sqlsocket);
		return 0;
	}
	ret = strlen(row[0]);
	if (ret > freespace){
		DEBUG("rlm_sql (%s): sql_xlat:: Insufficient string space",
		      inst->config->xlat_name);
		(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
		sql_release_socket(inst,sqlsocket);
		return 0;
	}

	strncpy(out,row[0],ret);

	DEBUG("rlm_sql (%s): - sql_xlat finished",
	      inst->config->xlat_name);

	(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
	sql_release_socket(inst,sqlsocket);
	return ret;
}

static int generate_sql_clients(SQL_INST *inst)
{
	SQLSOCK *sqlsocket;
	SQL_ROW row;
	char querystr[MAX_QUERY_LEN];
	RADCLIENT *c;
	char *netmask;
	unsigned int i = 0;
	
	DEBUG("rlm_sql (%s): - generate_sql_clients",inst->config->xlat_name);

	if (inst->config->sql_nas_table == NULL){
		radlog(L_ERR, "rlm_sql (%s): sql_nas_table is NULL.",inst->config->xlat_name);
		return -1;
	}
	snprintf(querystr,MAX_QUERY_LEN - 1,"SELECT id,nasname,shortname,type,secret FROM %s",inst->config->sql_nas_table);

	DEBUG("rlm_sql (%s): Query: %s",inst->config->xlat_name,querystr);
	sqlsocket = sql_get_socket(inst);
	if (sqlsocket == NULL)
		return -1;
	if (rlm_sql_select_query(sqlsocket,inst,querystr)){
		radlog(L_ERR, "rlm_sql (%s): database query error, %s: %s",
			inst->config->xlat_name,querystr,
			(char *)(inst->module->sql_error)(sqlsocket, inst->config));
		sql_release_socket(inst,sqlsocket);
		return -1;
	}

	while(rlm_sql_fetch_row(sqlsocket, inst) == 0) {
		i++;
		row = sqlsocket->row;
		if (row == NULL)
			break;
/*
 * Format:
 * Row1	Row2	Row3		Row4	Row5	Row6	Row7		Row8
 *
 * id	nasname	shortname	type	ports	secret	community	description
 *
 */

		if (!row[0]){
			radlog(L_ERR, "rlm_sql (%s): No row id found on pass %d",inst->config->xlat_name,i);
			continue;
		}
		if (!row[1]){
			radlog(L_ERR, "rlm_sql (%s): No nasname found for row %s",inst->config->xlat_name,row[0]);
			continue;
		}
		if (strlen(row[1]) >= sizeof(c->longname)){
			radlog(L_ERR, "rlm_sql (%s): nasname of length %d is greater than the allowed maximum of %d",
				inst->config->xlat_name,strlen(row[1]),sizeof(c->longname) - 1);
			continue;
		}	
		
		if (!row[2]){
			radlog(L_ERR, "rlm_sql (%s): No short name found for row %s",inst->config->xlat_name,row[0]);
			continue;
		}
		if (strlen(row[2]) >= sizeof(c->shortname)){
			radlog(L_ERR, "rlm_sql (%s): shortname of length %d is greater than the allowed maximum of %d",
				inst->config->xlat_name,strlen(row[2]),sizeof(c->shortname) - 1);
			continue;
		}
		if (row[3] && strlen(row[3]) >= sizeof(c->nastype)){
			radlog(L_ERR, "rlm_sql (%s): nastype of length %d is greater than the allowed maximum of %d",
				inst->config->xlat_name,strlen(row[3]),sizeof(c->nastype) - 1);
			continue;
		}
		if (!row[4]){
			radlog(L_ERR, "rlm_sql (%s): No secret found for row %s",inst->config->xlat_name,row[0]);
			continue;
		}
		if (strlen(row[4]) >= sizeof(c->secret)){
			radlog(L_ERR, "rlm_sql (%s): secret of length %d is greater than the allowed maximum of %d",
				inst->config->xlat_name,strlen(row[4]),sizeof(c->secret) - 1);
			continue;
		}

		DEBUG("rlm_sql (%s): Read entry nasname=%s,shortname=%s,secret=%s",inst->config->xlat_name,
			row[1],row[2],row[4]);

		c = rad_malloc(sizeof(RADCLIENT));
		memset(c, 0, sizeof(RADCLIENT));

		c->netmask = ~0;
		netmask = strchr(row[1], '/');
		
		/*
		 *      Look for netmasks.
		 */
		c->netmask = ~0;
		if (netmask) {
			int mask_length;

			mask_length = atoi(netmask + 1);
			if ((mask_length < 0) || (mask_length > 32)) {
				radlog(L_ERR, "rlm_sql (%s): Invalid value '%s' for IP network mask for nasname %s.",
						inst->config->xlat_name, netmask + 1,row[1]);
				free(c);
				continue;
			}

			if (mask_length == 0) {
				c->netmask = 0;
			} else {
				c->netmask = ~0 << (32 - mask_length);
			}

			*netmask = '\0';
			c->netmask = htonl(c->netmask);
		}

		c->ipaddr = ip_getaddr(row[1]);
		if (c->ipaddr == INADDR_NONE) {
			radlog(L_CONS|L_ERR, "rlm_sql (%s): Failed to look up hostname %s",
					inst->config->xlat_name, row[1]);
			free(c);
			continue;
		}

		/*
		 *      Update the client name again...
		 */
		if (netmask) {
			*netmask = '/';
			c->ipaddr &= c->netmask;
			strcpy(c->longname, row[1]);
		} else {
			ip_hostname(c->longname, sizeof(c->longname),
					c->ipaddr);
		}

		strcpy((char *)c->secret, row[4]);
		strcpy(c->shortname, row[2]);
		if(row[3] != NULL)
			strcpy(c->nastype, row[3]);

		DEBUG("rlm_sql (%s): Adding client %s (%s) to clients list",inst->config->xlat_name,
			c->longname,c->shortname);

		c->next = mainconfig.clients;
		mainconfig.clients = c;

	}
	(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
	sql_release_socket(inst, sqlsocket);

	return 0;
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
		    strchr(allowed_chars, *in) == NULL) {
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

/*
 *	Set the SQl user name.
 */
static int sql_set_user(SQL_INST *inst, REQUEST *request, char *sqlusername, const char *username)
{
	VALUE_PAIR *vp=NULL;
	char tmpuser[MAX_STRING_LEN];

	tmpuser[0]=0;
	sqlusername[0]=0;

	/* Remove any user attr we added previously */
	pairdelete(&request->packet->vps, PW_SQL_USER_NAME);

	if (username != NULL) {
		strNcpy(tmpuser, username, MAX_STRING_LEN);
	} else if (strlen(inst->config->query_user)) {
		radius_xlat(tmpuser, sizeof(tmpuser), inst->config->query_user, request, NULL);
	} else {
		return 0;
	}

	if (*tmpuser) {
		strNcpy(sqlusername, tmpuser, sizeof(tmpuser));
		DEBUG2("rlm_sql (%s): sql_set_user escaped user --> '%s'",
		       inst->config->xlat_name, sqlusername);
		vp = pairmake("SQL-User-Name", sqlusername, 0);
		if (vp == NULL) {
			radlog(L_ERR, "%s", librad_errstr);
			return -1;
		}

		pairadd(&request->packet->vps, vp);
		return 0;
	}
	return -1;
}


static void sql_grouplist_free (SQL_GROUPLIST **group_list)
{
	SQL_GROUPLIST *last;

	while(*group_list) {
		last = *group_list;
		*group_list = (*group_list)->next;
		free(last);
	}
}


static int sql_get_grouplist (SQL_INST *inst, SQLSOCK *sqlsocket, REQUEST *request, SQL_GROUPLIST **group_list)
{
	char    querystr[MAX_QUERY_LEN];
	int     num_groups = 0;
	SQL_ROW row;
	SQL_GROUPLIST   *group_list_tmp;

	/* NOTE: sql_set_user should have been run before calling this function */

	group_list_tmp = *group_list = NULL;

	if (inst->config->groupmemb_query[0] == 0)
		return 1;

	if (!radius_xlat(querystr, sizeof(querystr), inst->config->groupmemb_query, request, sql_escape_func)) {
		radlog(L_ERR, "rlm_sql (%s): xlat failed.",
			inst->config->xlat_name);
		return -1;
	}
	
	if (rlm_sql_select_query(sqlsocket, inst, querystr) < 0) {
		radlog(L_ERR, "rlm_sql (%s): database query error, %s: %s",
			inst->config->xlat_name,querystr,
			(char *)(inst->module->sql_error)(sqlsocket,inst->config));
		return -1;
	}
	while (rlm_sql_fetch_row(sqlsocket, inst) == 0) {
		row = sqlsocket->row;
		if (row == NULL)
			break;
		if (row[0] == NULL){
			DEBUG("rlm_sql (%s): row[0] returned NULL",
				inst->config->xlat_name);
			(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
			sql_grouplist_free(group_list);
			return -1;
		}
		if (*group_list == NULL) {
			*group_list = rad_malloc(sizeof(SQL_GROUPLIST));
			group_list_tmp = *group_list;
		} else {
			group_list_tmp->next = rad_malloc(sizeof(SQL_GROUPLIST));
			group_list_tmp = group_list_tmp->next;
		}
		group_list_tmp->next = NULL;
		strNcpy(group_list_tmp->groupname, row[0], MAX_STRING_LEN);
	}

	(inst->module->sql_finish_select_query)(sqlsocket, inst->config);

	return num_groups;
}


/*
 * sql groupcmp function. That way we can do group comparisons (in the users file for example)
 * with the group memberships reciding in sql
 * The group membership query should only return one element which is the username. The returned
 * username will then be checked with the passed check string.
 */

static int sql_groupcmp(void *instance, REQUEST *req, VALUE_PAIR *request, VALUE_PAIR *check,
			VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	SQLSOCK *sqlsocket;
	SQL_INST *inst = instance;
	char sqlusername[2 * MAX_STRING_LEN + 10];
	SQL_GROUPLIST *group_list, *group_list_tmp;

	check_pairs = check_pairs;
	reply_pairs = reply_pairs;
	request = request;

	DEBUG("rlm_sql (%s): - sql_groupcmp", inst->config->xlat_name);
	if (!check || !check->strvalue || !check->length){
		DEBUG("rlm_sql (%s): sql_groupcmp: Illegal group name",
		      inst->config->xlat_name);
		return 1;
	}
	if (req == NULL){
		DEBUG("rlm_sql (%s): sql_groupcmp: NULL request",
		      inst->config->xlat_name);
		return 1;
	}
	/*
	 * Set, escape, and check the user attr here
	 */
	if (sql_set_user(inst, req, sqlusername, 0) < 0)
		return 1;

	/*
	 *	Get a socket for this lookup
	 */
	sqlsocket = sql_get_socket(inst);
	if (sqlsocket == NULL) {
		/* Remove the username we (maybe) added above */
		pairdelete(&req->packet->vps, PW_SQL_USER_NAME);
		return 1;
	}

	/*
	 *	Get the list of groups this user is a member of
	 */
	if (sql_get_grouplist(inst, sqlsocket, req, &group_list)) {
		radlog(L_ERR, "rlm_sql (%s): Error getting group membership",
		       inst->config->xlat_name);
		/* Remove the username we (maybe) added above */
		pairdelete(&req->packet->vps, PW_SQL_USER_NAME);
		sql_release_socket(inst, sqlsocket);
		return 1;
	}

	for (group_list_tmp = group_list; group_list_tmp != NULL; group_list_tmp = group_list_tmp->next) {
		if (strcmp(group_list_tmp->groupname, check->strvalue) == 0){
			DEBUG("rlm_sql (%s): - sql_groupcmp finished: User is a member of group %s",
			      inst->config->xlat_name,
			      (char *)check->strvalue);
			/* Free the grouplist */
			sql_grouplist_free(&group_list);
			/* Remove the username we (maybe) added above */
			pairdelete(&req->packet->vps, PW_SQL_USER_NAME);
			sql_release_socket(inst, sqlsocket);
			return 0;
		}
	}

	/* Free the grouplist */
	sql_grouplist_free(&group_list);
	/* Remove the username we (maybe) added above */
	pairdelete(&req->packet->vps, PW_SQL_USER_NAME);
	sql_release_socket(inst,sqlsocket);

	DEBUG("rlm_sql (%s): - sql_groupcmp finished: User is NOT a member of group %s",
	      inst->config->xlat_name, (char *)check->strvalue);

	return 1;
}



static int rlm_sql_process_groups(SQL_INST *inst, REQUEST *request, SQLSOCK *sqlsocket, int *dofallthrough)
{
	VALUE_PAIR *check_tmp = NULL;
	VALUE_PAIR *reply_tmp = NULL;
	SQL_GROUPLIST *group_list, *group_list_tmp;
	VALUE_PAIR *sql_group = NULL;
	char    querystr[MAX_QUERY_LEN];
	int found = 0;
	int rows;

	/*
	 *	Get the list of groups this user is a member of
	 */
	if (sql_get_grouplist(inst, sqlsocket, request, &group_list)) {
		radlog(L_ERR, "rlm_sql (%s): Error retrieving group list",
		       inst->config->xlat_name);
		return -1;
	}

	for (group_list_tmp = group_list; group_list_tmp != NULL && *dofallthrough != 0; group_list_tmp = group_list_tmp->next) {
		/*
		 *	Add the Sql-Group attribute to the request list so we know
		 *	which group we're retrieving attributes for
		 */
		sql_group = pairmake("Sql-Group", group_list_tmp->groupname, T_OP_EQ);
		if (!sql_group) {
			radlog(L_ERR, "rlm_sql (%s): Error creating Sql-Group attribute",
			       inst->config->xlat_name);
			return -1;	
		}
		pairadd(&request->packet->vps, sql_group);
		if (!radius_xlat(querystr, sizeof(querystr), inst->config->authorize_group_check_query, request, sql_escape_func)) {
			radlog(L_ERR, "rlm_sql (%s): Error generating query; rejecting user",
			       inst->config->xlat_name);
			/* Remove the grouup we added above */
			pairdelete(&request->packet->vps, PW_SQL_GROUP);
			return -1;
		}
		rows = sql_getvpdata(inst, sqlsocket, &check_tmp, querystr);
		if (rows < 0) {
			radlog(L_ERR, "rlm_sql (%s): Error retrieving check pairs for group %s",
			       inst->config->xlat_name, group_list_tmp->groupname);
			/* Remove the grouup we added above */
			pairdelete(&request->packet->vps, PW_SQL_GROUP);
			pairfree(&check_tmp);
			return -1;	
		} else if (rows > 0) {
			/*
			 *	Only do this if *some* check pairs were returned
			 */
			if (paircmp(request, request->packet->vps, check_tmp, &request->reply->vps) == 0) {
				found = 1;
				DEBUG2("rlm_sql (%s): User found in group %s",
					inst->config->xlat_name, group_list_tmp->groupname);
				/*
				 *	Now get the reply pairs since the paircmp matched
				 */
				if (!radius_xlat(querystr, sizeof(querystr), inst->config->authorize_group_reply_query, request, sql_escape_func)) {
					radlog(L_ERR, "rlm_sql (%s): Error generating query; rejecting user",
					       inst->config->xlat_name);
					/* Remove the grouup we added above */
					pairdelete(&request->packet->vps, PW_SQL_GROUP);
					pairfree(&check_tmp);
					return -1;
				}
				if (sql_getvpdata(inst, sqlsocket, &reply_tmp, querystr) < 0) {
					radlog(L_ERR, "rlm_sql (%s): Error retrieving reply pairs for group %s",
					       inst->config->xlat_name, group_list_tmp->groupname);
					/* Remove the grouup we added above */
					pairdelete(&request->packet->vps, PW_SQL_GROUP);
					pairfree(&check_tmp);
					pairfree(&reply_tmp);
					return -1;
				}
				*dofallthrough = fallthrough(reply_tmp);
				pairxlatmove(request, &request->reply->vps, &reply_tmp);
				pairxlatmove(request, &request->config_items, &check_tmp);
			}
		}

		/*
		 * Delete the Sql-Group we added above
		 * And clear out the pairlists
		 */
		pairdelete(&request->packet->vps, PW_SQL_GROUP);
		pairfree(&check_tmp);
		pairfree(&reply_tmp);
	}

	sql_grouplist_free(&group_list);
	return found;
}


static int rlm_sql_detach(void *instance)
{
	SQL_INST *inst = instance;

	if (inst->sqlpool) {
		sql_poolfree(inst);
	}

	if (inst->config->xlat_name) {
		xlat_unregister(inst->config->xlat_name,(RAD_XLAT_FUNC)sql_xlat);
		free(inst->config->xlat_name);
	}

	paircompare_unregister(PW_SQL_GROUP, sql_groupcmp);

	if (inst->config) {
		int i;

		/*
		 *	Free up dynamically allocated string pointers.
		 */
		for (i = 0; module_config[i].name != NULL; i++) {
			char **p;
			if (module_config[i].type != PW_TYPE_STRING_PTR) {
				continue;
			}

			/*
			 *	Treat 'config' as an opaque array of bytes,
			 *	and take the offset into it.  There's a
			 *      (char*) pointer at that offset, and we want
			 *	to point to it.
			 */
			p = (char **) (((char *)inst->config) + module_config[i].offset);
			if (!*p) { /* nothing allocated */
				continue;
			}
			free(*p);
			*p = NULL;
		}
		free(inst->config);
		inst->config = NULL;
	}

	if (inst->handle) {
#if 0
		/*
		 *	FIXME: Call the modules 'destroy' function?
		 */
		lt_dlclose(inst->handle);	/* ignore any errors */
#endif
	}
	free(inst);

	return 0;
}
static int rlm_sql_instantiate(CONF_SECTION * conf, void **instance)
{
	SQL_INST *inst;
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
		rlm_sql_detach(inst);
		return -1;
	}

	xlat_name = cf_section_name2(conf);
	if (xlat_name == NULL)
		xlat_name = cf_section_name1(conf);
	if (xlat_name){
		inst->config->xlat_name = strdup(xlat_name);
		xlat_register(xlat_name, (RAD_XLAT_FUNC)sql_xlat, inst);
	}

	if (inst->config->num_sql_socks > MAX_SQL_SOCKS) {
		radlog(L_ERR | L_CONS, "rlm_sql (%s): sql_instantiate: number of sqlsockets cannot exceed MAX_SQL_SOCKS, %d",
		       inst->config->xlat_name, MAX_SQL_SOCKS);
		rlm_sql_detach(inst);
		return -1;
	}

	/*
	 *	Sanity check for crazy people.
	 */
	if (strncmp(inst->config->sql_driver, "rlm_sql_", 8) != 0) {
		radlog(L_ERR, "rlm_sql (%s): \"%s\" is NOT an SQL driver!",
		       inst->config->xlat_name, inst->config->sql_driver);
		rlm_sql_detach(inst);
		return -1;
	}

	inst->handle = lt_dlopenext(inst->config->sql_driver);
	if (inst->handle == NULL) {
		radlog(L_ERR, "rlm_sql (%s): Could not link driver %s: %s",
		       inst->config->xlat_name, inst->config->sql_driver,
		       lt_dlerror());
		radlog(L_ERR, "rlm_sql (%s): Make sure it (and all its dependent libraries!) are in the search path of your system's ld.",
		       inst->config->xlat_name);
		rlm_sql_detach(inst);
		return -1;
	}

	inst->module = (rlm_sql_module_t *) lt_dlsym(inst->handle, inst->config->sql_driver);
	if (!inst->module) {
		radlog(L_ERR, "rlm_sql (%s): Could not link symbol %s: %s",
		       inst->config->xlat_name, inst->config->sql_driver,
		       lt_dlerror());
		rlm_sql_detach(inst);
		return -1;
	}

	radlog(L_INFO, "rlm_sql (%s): Driver %s (module %s) loaded and linked",
	       inst->config->xlat_name, inst->config->sql_driver,
	       inst->module->name);
	radlog(L_INFO, "rlm_sql (%s): Attempting to connect to %s@%s:%s/%s",
	       inst->config->xlat_name, inst->config->sql_login,
	       inst->config->sql_server, inst->config->sql_port,
	       inst->config->sql_db);

	if (sql_init_socketpool(inst) < 0) {
		rlm_sql_detach(inst);
		return -1;
	}
	paircompare_register(PW_SQL_GROUP, PW_USER_NAME, sql_groupcmp, inst);

	if (inst->config->do_clients){
		if (generate_sql_clients(inst) == -1){
			radlog(L_ERR, "rlm_sql (%s): generate_sql_clients() returned error",inst->config->xlat_name);
			rlm_sql_detach(inst);
			return -1;
		}
	}
	allowed_chars = inst->config->allowed_chars;

	*instance = inst;

	return RLM_MODULE_OK;
}

static int rlm_sql_destroy(void)
{
	return 0;
}


static int rlm_sql_authorize(void *instance, REQUEST * request)
{
	VALUE_PAIR *check_tmp = NULL;
	VALUE_PAIR *reply_tmp = NULL;
	VALUE_PAIR *user_profile = NULL;
	int     found = 0;
	int	dofallthrough = 1;
	int	rows;
	SQLSOCK *sqlsocket;
	SQL_INST *inst = instance;
	char    querystr[MAX_QUERY_LEN];

	/* sqlusername holds the sql escaped username. The original
	 * username is at most MAX_STRING_LEN chars long and
	 * *sql_escape_string doubles its length in the worst case.
	 * Throw in an extra 10 to account for trailing NULs and to have
	 * a safety margin. */
	char   sqlusername[2 * MAX_STRING_LEN + 10];
	/*
	 * the profile username is used as the sqlusername during
	 * profile checking so that we don't overwrite the orignal
	 * sqlusername string
	 */
	char   profileusername[2 * MAX_STRING_LEN + 10];

	/*
	 *	They MUST have a user name to do SQL authorization.
	 */
	if ((request->username == NULL) ||
	    (request->username->length == 0)) {
		radlog(L_ERR, "rlm_sql (%s): zero length username not permitted\n", inst->config->xlat_name);
		return RLM_MODULE_INVALID;
	}


	/*
	 * Set, escape, and check the user attr here
	 */
	if (sql_set_user(inst, request, sqlusername, NULL) < 0)
		return RLM_MODULE_FAIL;


	/*
	 * reserve a socket
	 */
	sqlsocket = sql_get_socket(inst);
	if (sqlsocket == NULL) {
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_SQL_USER_NAME);
		return RLM_MODULE_FAIL;
	}


	/*
	 *  After this point, ALL 'return's MUST release the SQL socket!
	 */

	/*
	 * Alright, start by getting the specific entry for the user
	 */
	if (!radius_xlat(querystr, sizeof(querystr), inst->config->authorize_check_query, request, sql_escape_func)) {
		radlog(L_ERR, "rlm_sql (%s): Error generating query; rejecting user",
		       inst->config->xlat_name);
		sql_release_socket(inst, sqlsocket);
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_SQL_USER_NAME);
		return RLM_MODULE_FAIL;
	}
	rows = sql_getvpdata(inst, sqlsocket, &check_tmp, querystr);
	if (rows < 0) {
		radlog(L_ERR, "rlm_sql (%s): SQL query error; rejecting user",
		       inst->config->xlat_name);
		sql_release_socket(inst, sqlsocket);
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_SQL_USER_NAME);
		pairfree(&check_tmp);
		return RLM_MODULE_FAIL;
	} else if (rows > 0) {
		/*
		 *	Only do this if *some* check pairs were returned
		 */
		if (paircmp(request, request->packet->vps, check_tmp, &request->reply->vps) == 0) {
			found = 1;
			DEBUG2("rlm_sql (%s): User found in radcheck table", inst->config->xlat_name);
			/*
			 *	Now get the reply pairs since the paircmp matched
			 */
			if (!radius_xlat(querystr, sizeof(querystr), inst->config->authorize_reply_query, request, sql_escape_func)) {
				radlog(L_ERR, "rlm_sql (%s): Error generating query; rejecting user",
				       inst->config->xlat_name);
				sql_release_socket(inst, sqlsocket);
				/* Remove the username we (maybe) added above */
				pairdelete(&request->packet->vps, PW_SQL_USER_NAME);
				pairfree(&check_tmp);
				return RLM_MODULE_FAIL;
			}
			if (sql_getvpdata(inst, sqlsocket, &reply_tmp, querystr) < 0) {
				radlog(L_ERR, "rlm_sql (%s): SQL query error; rejecting user",
				       inst->config->xlat_name);
				sql_release_socket(inst, sqlsocket);
				/* Remove the username we (maybe) added above */
				pairdelete(&request->packet->vps, PW_SQL_USER_NAME);
				pairfree(&check_tmp);
				pairfree(&reply_tmp);
				return RLM_MODULE_FAIL;
			}
			if (!inst->config->read_groups)
				dofallthrough = fallthrough(reply_tmp);
			pairxlatmove(request, &request->reply->vps, &reply_tmp);
			pairxlatmove(request, &request->config_items, &check_tmp);
		}
	}

	/*
	 *	Clear out the pairlists
	 */
	pairfree(&check_tmp);
	pairfree(&reply_tmp);

	/*
	 *	dofallthrough is set to 1 by default so that if the user information
	 *	is not found, we will still process groups.  If the user information,
	 *	however, *is* found, Fall-Through must be set in order to process
	 *	the groups as well
	 */
	if (dofallthrough) {
		rows = rlm_sql_process_groups(inst, request, sqlsocket, &dofallthrough);
		if (rows < 0) {
			radlog(L_ERR, "rlm_sql (%s): Error processing groups; rejecting user",
			       inst->config->xlat_name);
			sql_release_socket(inst, sqlsocket);
			/* Remove the username we (maybe) added above */
			pairdelete(&request->packet->vps, PW_SQL_USER_NAME);
			return RLM_MODULE_FAIL;
		} else if (rows > 0) {
			found = 1;
		}
	}

	/*
	 *	repeat the above process with the default profile or User-Profile
	 */
	if (dofallthrough) {
		int profile_found = 0;
		/*
	 	* Check for a default_profile or for a User-Profile.
		*/
		user_profile = pairfind(request->config_items, PW_USER_PROFILE);
		if (inst->config->default_profile[0] != 0 || user_profile != NULL){
			char *profile = inst->config->default_profile;

			if (user_profile != NULL)
				profile = user_profile->strvalue;
			if (profile && strlen(profile)){
				radlog(L_DBG, "rlm_sql (%s): Checking profile %s",
				       inst->config->xlat_name, profile);
				if (sql_set_user(inst, request, profileusername, profile) < 0) {
					radlog(L_ERR, "rlm_sql (%s): Error setting profile; rejecting user",
					       inst->config->xlat_name);
					sql_release_socket(inst, sqlsocket);
					/* Remove the username we (maybe) added above */
					pairdelete(&request->packet->vps, PW_SQL_USER_NAME);
					return RLM_MODULE_FAIL;
				} else {
					profile_found = 1;
				}
			}
		}

		if (profile_found) {
			rows = rlm_sql_process_groups(inst, request, sqlsocket, &dofallthrough);
			if (rows < 0) {
				radlog(L_ERR, "rlm_sql (%s): Error processing profile groups; rejecting user",
				       inst->config->xlat_name);
				sql_release_socket(inst, sqlsocket);
				/* Remove the username we (maybe) added above */
				pairdelete(&request->packet->vps, PW_SQL_USER_NAME);
				return RLM_MODULE_FAIL;
			} else if (rows > 0) {
				found = 1;
			}
		}
	}

	/* Remove the username we (maybe) added above */
	pairdelete(&request->packet->vps, PW_SQL_USER_NAME);
	sql_release_socket(inst, sqlsocket);

	if (!found) {
		radlog(L_DBG, "rlm_sql (%s): User %s not found",
		       inst->config->xlat_name, sqlusername);
		return RLM_MODULE_NOTFOUND;
	} else {
		return RLM_MODULE_OK;
	}
}

/*
 *	Accounting: save the account data to our sql table
 */
static int rlm_sql_accounting(void *instance, REQUEST * request) {

	SQLSOCK *sqlsocket = NULL;
	VALUE_PAIR *pair;
	SQL_INST *inst = instance;
	int	ret = RLM_MODULE_OK;
	int     numaffected = 0;
	int     acctstatustype = 0;
	char    querystr[MAX_QUERY_LEN];
	char    logstr[MAX_QUERY_LEN];
	char	sqlusername[2 * MAX_STRING_LEN + 10];

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
		radius_xlat(logstr, sizeof(logstr), "rlm_sql: packet has no account status type.  [user '%{User-Name}', nas '%{NAS-IP-Address}']", request, sql_escape_func);
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
			radlog(L_INFO, "rlm_sql (%s): received Acct On/Off packet", inst->config->xlat_name);
			radius_xlat(querystr, sizeof(querystr), inst->config->accounting_onoff_query, request, sql_escape_func);
			query_log(request, inst, querystr);

			sqlsocket = sql_get_socket(inst);
			if (sqlsocket == NULL)
				return(RLM_MODULE_FAIL);
			if (*querystr) { /* non-empty query */
				if (rlm_sql_query(sqlsocket, inst, querystr)) {
					radlog(L_ERR, "rlm_sql (%s): Couldn't update SQL accounting for Acct On/Off packet - %s",
					       inst->config->xlat_name,
					       (char *)(inst->module->sql_error)(sqlsocket, inst->config));
					ret = RLM_MODULE_FAIL;
				}
				(inst->module->sql_finish_query)(sqlsocket, inst->config);
			}

			break;

			/*
			 * Got an update accounting packet
			 */
		case PW_STATUS_ALIVE:

			/*
			 * Set, escape, and check the user attr here
			 */
			sql_set_user(inst, request, sqlusername, NULL);

			radius_xlat(querystr, sizeof(querystr), inst->config->accounting_update_query, request, sql_escape_func);
			query_log(request, inst, querystr);

			sqlsocket = sql_get_socket(inst);
			if (sqlsocket == NULL)
				return(RLM_MODULE_FAIL);
			if (*querystr) { /* non-empty query */
				if (rlm_sql_query(sqlsocket, inst, querystr)) {
					radlog(L_ERR, "rlm_sql (%s): Couldn't update SQL accounting ALIVE record - %s",
					       inst->config->xlat_name,
					       (char *)(inst->module->sql_error)(sqlsocket, inst->config));
					ret = RLM_MODULE_FAIL;
				}
				else {
					numaffected = (inst->module->sql_affected_rows)(sqlsocket, inst->config);
					if (numaffected < 1) {

						/*
						 * If our update above didn't match anything
						 * we assume it's because we haven't seen a
						 * matching Start record.  So we have to
						 * insert this update rather than do an update
						 */
						radius_xlat(querystr, sizeof(querystr), inst->config->accounting_update_query_alt, request, sql_escape_func);
						query_log(request, inst, querystr);
						if (*querystr) { /* non-empty query */
							if (rlm_sql_query(sqlsocket, inst, querystr)) {
								radlog(L_ERR, "rlm_sql (%s): Couldn't insert SQL accounting ALIVE record - %s",
									   inst->config->xlat_name,
									   (char *)(inst->module->sql_error)(sqlsocket, inst->config));
								ret = RLM_MODULE_FAIL;
							}
							(inst->module->sql_finish_query)(sqlsocket, inst->config);
						}
					}
				}
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
			sql_set_user(inst, request, sqlusername, NULL);

			radius_xlat(querystr, sizeof(querystr), inst->config->accounting_start_query, request, sql_escape_func);
			query_log(request, inst, querystr);

			sqlsocket = sql_get_socket(inst);
			if (sqlsocket == NULL)
				return(RLM_MODULE_FAIL);
			if (*querystr) { /* non-empty query */
				if (rlm_sql_query(sqlsocket, inst, querystr)) {
					radlog(L_ERR, "rlm_sql (%s): Couldn't insert SQL accounting START record - %s",
					       inst->config->xlat_name,
					       (char *)(inst->module->sql_error)(sqlsocket, inst->config));

					/*
					 * We failed the insert above.  It's probably because
					 * the stop record came before the start.  We try
					 * our alternate query now (typically an UPDATE)
					 */
					radius_xlat(querystr, sizeof(querystr), inst->config->accounting_start_query_alt, request, sql_escape_func);
					query_log(request, inst, querystr);

					if (*querystr) { /* non-empty query */
						if (rlm_sql_query(sqlsocket, inst, querystr)) {
							radlog(L_ERR, "rlm_sql (%s): Couldn't update SQL accounting START record - %s",
							       inst->config->xlat_name,
							       (char *)(inst->module->sql_error)(sqlsocket, inst->config));
							ret = RLM_MODULE_FAIL;
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
			sql_set_user(inst, request, sqlusername, NULL);

			radius_xlat(querystr, sizeof(querystr), inst->config->accounting_stop_query, request, sql_escape_func);
			query_log(request, inst, querystr);

			sqlsocket = sql_get_socket(inst);
			if (sqlsocket == NULL)
				return(RLM_MODULE_FAIL);
			if (*querystr) { /* non-empty query */
				if (rlm_sql_query(sqlsocket, inst, querystr)) {
					radlog(L_ERR, "rlm_sql (%s): Couldn't update SQL accounting STOP record - %s",
					       inst->config->xlat_name,
					       (char *)(inst->module->sql_error)(sqlsocket, inst->config));
					ret = RLM_MODULE_FAIL;
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
				        	        radius_xlat(logstr, sizeof(logstr), "rlm_sql: Stop packet with zero session length.  (user '%{User-Name}', nas '%{NAS-IP-Address}')", request, sql_escape_func);
					                radlog(L_ERR, logstr);
				        	        sql_release_socket(inst, sqlsocket);
				                	ret = RLM_MODULE_NOOP;
					        }
#endif

						radius_xlat(querystr, sizeof(querystr), inst->config->accounting_stop_query_alt, request, sql_escape_func);
						query_log(request, inst, querystr);

						if (*querystr) { /* non-empty query */
							if (rlm_sql_query(sqlsocket, inst, querystr)) {
								radlog(L_ERR, "rlm_sql (%s): Couldn't insert SQL accounting STOP record - %s",
										inst->config->xlat_name,
										(char *)(inst->module->sql_error)(sqlsocket, inst->config));
								ret = RLM_MODULE_FAIL;
							}
							(inst->module->sql_finish_query)(sqlsocket, inst->config);
						}
					}
				}
				(inst->module->sql_finish_query)(sqlsocket, inst->config);
			}
			break;

			/*
			 *	Anything else is ignored.
			 */
		default:
			radlog(L_INFO, "rlm_sql (%s): Unsupported Acct-Status-Type = %d", inst->config->xlat_name, acctstatustype);
			return RLM_MODULE_NOOP;
			break;

	}

	sql_release_socket(inst, sqlsocket);

	return ret;
}


/*
 *        See if a user is already logged in. Sets request->simul_count to the
 *        current session count for this user.
 *
 *        Check twice. If on the first pass the user exceeds his
 *        max. number of logins, do a second pass and validate all
 *        logins by querying the terminal server (using eg. SNMP).
 */

static int rlm_sql_checksimul(void *instance, REQUEST * request) {
	SQLSOCK 	*sqlsocket;
	SQL_INST	*inst = instance;
	SQL_ROW		row;
	char		querystr[MAX_QUERY_LEN];
	char		sqlusername[2*MAX_STRING_LEN+10];
	int		check = 0;
        uint32_t        ipno = 0;
        char            *call_num = NULL;
	VALUE_PAIR      *vp;
	int		ret;
	uint32_t	nas_addr = 0;
	int		nas_port = 0;

	/* If simul_count_query is not defined, we don't do any checking */
	if (inst->config->simul_count_query[0] == 0) {
		return RLM_MODULE_NOOP;
	}

	if((request->username == NULL) || (request->username->length == 0)) {
		radlog(L_ERR, "rlm_sql (%s): Zero Length username not permitted\n", inst->config->xlat_name);
		return RLM_MODULE_INVALID;
	}


	if(sql_set_user(inst, request, sqlusername, 0) <0)
		return RLM_MODULE_FAIL;

	radius_xlat(querystr, sizeof(querystr), inst->config->simul_count_query, request, sql_escape_func);

	/* initialize the sql socket */
	sqlsocket = sql_get_socket(inst);
	if(sqlsocket == NULL)
		return RLM_MODULE_FAIL;

	if(rlm_sql_select_query(sqlsocket, inst, querystr)) {
		radlog(L_ERR, "rlm_sql (%s) sql_checksimul: Database query failed", inst->config->xlat_name);
		sql_release_socket(inst, sqlsocket);
		return RLM_MODULE_FAIL;
	}

	ret = rlm_sql_fetch_row(sqlsocket, inst);

	if (ret != 0) {
		(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
		sql_release_socket(inst, sqlsocket);
		return RLM_MODULE_FAIL;
	}

	row = sqlsocket->row;
	if (row == NULL) {
		(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
		sql_release_socket(inst, sqlsocket);
		return RLM_MODULE_FAIL;
	}

	request->simul_count = atoi(row[0]);
	(inst->module->sql_finish_select_query)(sqlsocket, inst->config);

	if(request->simul_count < request->simul_max) {
		sql_release_socket(inst, sqlsocket);
		return RLM_MODULE_OK;
	}

	/* Looks like too many sessions, so lets start verifying them */

	if (inst->config->simul_verify_query[0] == 0) {
		/* No verify query defined, so skip verify step and rely on count query only */
		sql_release_socket(inst, sqlsocket);
		return RLM_MODULE_OK;
	}

	radius_xlat(querystr, sizeof(querystr), inst->config->simul_verify_query, request, sql_escape_func);
	if(rlm_sql_select_query(sqlsocket, inst, querystr)) {
		radlog(L_ERR, "rlm_sql (%s): sql_checksimul: Database query error", inst->config->xlat_name);
		sql_release_socket(inst, sqlsocket);
		return RLM_MODULE_FAIL;
	}

        /*
         *      Setup some stuff, like for MPP detection.
         */
	request->simul_count = 0;

        if ((vp = pairfind(request->packet->vps, PW_FRAMED_IP_ADDRESS)) != NULL)
                ipno = vp->lvalue;
        if ((vp = pairfind(request->packet->vps, PW_CALLING_STATION_ID)) != NULL)
                call_num = vp->strvalue;


	while (rlm_sql_fetch_row(sqlsocket, inst) == 0) {
		row = sqlsocket->row;
		if (row == NULL)
			break;
		if (!row[2]){
			(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
			sql_release_socket(inst, sqlsocket);
			DEBUG("rlm_sql (%s): Cannot zap stale entry. No username present in entry.", inst->config->xlat_name);
			return RLM_MODULE_FAIL;
		}
		if (!row[1]){
			(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
			sql_release_socket(inst, sqlsocket);
			DEBUG("rlm_sql (%s): Cannot zap stale entry. No session id in entry.", inst->config->xlat_name);
			return RLM_MODULE_FAIL;
		}
		if (row[3])
			nas_addr = inet_addr(row[3]);
		if (row[4])
			nas_port = atoi(row[4]);

		check = rad_check_ts(nas_addr, nas_port, row[2], row[1]);

                /*
                 *      Failed to check the terminal server for
                 *      duplicate logins: Return an error.
                 */
		if (check < 0) {
			(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
			sql_release_socket(inst, sqlsocket);
			DEBUG("rlm_sql (%s) rad_check_ts() failed.",
			      inst->config->xlat_name);
			return RLM_MODULE_FAIL;
		}

		if(check == 1) {
			++request->simul_count;

                        /*
                         *      Does it look like a MPP attempt?
                         */
                        if (row[5] && ipno && inet_addr(row[5]) == ipno)
                                request->simul_mpp = 2;
                        else if (row[6] && call_num &&
                                !strncmp(row[6],call_num,16))
                                request->simul_mpp = 2;
		}
		else {
                        /*
                         *      Stale record - zap it.
                         */
			uint32_t framed_addr = 0;
			char proto = 'P';

			if (row[5])
				framed_addr = inet_addr(row[5]);
			if (row[7])
				if (strcmp(row[7],"SLIP") == 0)
					proto = 'S';

			session_zap(request,
				    nas_addr,nas_port,row[2],row[1],
				    framed_addr, proto);
		}
	}

	(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
	sql_release_socket(inst, sqlsocket);

	/* The Auth module apparently looks at request->simul_count, not the return value
	   of this module when deciding to deny a call for too many sessions */
	return RLM_MODULE_OK;

}

/*
 *	Execute postauth_query after authentication
 */
static int rlm_sql_postauth(void *instance, REQUEST *request) {
	SQLSOCK 	*sqlsocket = NULL;
	SQL_INST	*inst = instance;
	char		querystr[MAX_QUERY_LEN];
	char		sqlusername[2*MAX_STRING_LEN+10];

	DEBUG("rlm_sql (%s): Processing sql_postauth", inst->config->xlat_name);

	if(sql_set_user(inst, request, sqlusername, 0) <0)
		return RLM_MODULE_FAIL;

	/* If postauth_query is not defined, we stop here */
	if (inst->config->postauth_query[0] == '\0')
		return RLM_MODULE_NOOP;

	/* Expand variables in the query */
	memset(querystr, 0, MAX_QUERY_LEN);
	radius_xlat(querystr, sizeof(querystr), inst->config->postauth_query,
		    request, sql_escape_func);
	query_log(request, inst, querystr);
	DEBUG2("rlm_sql (%s) in sql_postauth: query is %s",
	       inst->config->xlat_name, querystr);

	/* Initialize the sql socket */
	sqlsocket = sql_get_socket(inst);
	if (sqlsocket == NULL)
		return RLM_MODULE_FAIL;

	/* Process the query */
	if (rlm_sql_query(sqlsocket, inst, querystr)) {
		radlog(L_ERR, "rlm_sql (%s) in sql_postauth: Database query error - %s",
		       inst->config->xlat_name,
		       (char *)(inst->module->sql_error)(sqlsocket, inst->config));
		sql_release_socket(inst, sqlsocket);
		return RLM_MODULE_FAIL;
	}
	(inst->module->sql_finish_query)(sqlsocket, inst->config);

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
		rlm_sql_checksimul,	/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		rlm_sql_postauth	/* post-auth */
	},
	rlm_sql_detach,		/* detach */
	rlm_sql_destroy,	/* destroy */
};
