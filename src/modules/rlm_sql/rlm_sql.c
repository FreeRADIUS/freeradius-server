
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2012  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Mike Machado <mike@innercite.com>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <ctype.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/token.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/stat.h>

#include "rlm_sql.h"

static const CONF_PARSER section_config[] = {
	{ "reference",  PW_TYPE_STRING_PTR,
	  offsetof(rlm_sql_config_section_t, reference), NULL, ".query"},
	  
	{"logfile", PW_TYPE_STRING_PTR,
	 offsetof(rlm_sql_config_section_t, logfile), NULL, NULL},
	{NULL, -1, 0, NULL, NULL}
};

static const CONF_PARSER module_config[] = {
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
	{"filename", PW_TYPE_FILENAME, /* for sqlite */
	 offsetof(SQL_CONFIG,sql_file), NULL, NULL},
	{"read_groups", PW_TYPE_BOOLEAN,
	 offsetof(SQL_CONFIG,read_groups), NULL, "yes"},
	{"readclients", PW_TYPE_BOOLEAN,
	 offsetof(SQL_CONFIG,do_clients), NULL, "no"},
	{"deletestalesessions", PW_TYPE_BOOLEAN,
	 offsetof(SQL_CONFIG,deletestalesessions), NULL, "yes"},
	{"sql_user_name", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,query_user), NULL, ""},
	{"logfile", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,logfile), NULL, NULL},
	{"default_user_profile", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,default_profile), NULL, ""},
	{"nas_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,nas_query), NULL, "SELECT id,nasname,shortname,type,secret FROM nas"},
	{"authorize_check_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,authorize_check_query), NULL, ""},
	{"authorize_reply_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,authorize_reply_query), NULL, NULL},
	{"authorize_group_check_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,authorize_group_check_query), NULL, ""},
	{"authorize_group_reply_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,authorize_group_reply_query), NULL, ""},
	{"group_membership_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,groupmemb_query), NULL, NULL},
#ifdef WITH_SESSION_MGMT
	{"simul_count_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,simul_count_query), NULL, ""},
	{"simul_verify_query", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,simul_verify_query), NULL, ""},
#endif
	{"safe-characters", PW_TYPE_STRING_PTR,
	 offsetof(SQL_CONFIG,allowed_chars), NULL,
	"@abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_: /"},

	/*
	 *	This only works for a few drivers.
	 */
	{"query_timeout", PW_TYPE_INTEGER,
	 offsetof(SQL_CONFIG,query_timeout), NULL, NULL},
	 
	{NULL, -1, 0, NULL, NULL}
};

/*
 *	Fall-Through checking function from rlm_files.c
 */
static int fallthrough(VALUE_PAIR *vp)
{
	VALUE_PAIR *tmp;
	tmp = pairfind(vp, PW_FALL_THROUGH, 0);

	return tmp ? tmp->vp_integer : 0;
}



/*
 *	Yucky prototype.
 */
static int generate_sql_clients(SQL_INST *inst);
static size_t sql_escape_func(REQUEST *, char *out, size_t outlen, const char *in, void *arg);

/*
 *			SQL xlat function
 *
 *  For selects the first value of the first column will be returned,
 *  for inserts, updates and deletes the number of rows afftected will be
 *  returned instead.
 */
static size_t sql_xlat(void *instance, REQUEST *request,
		    const char *fmt, char *out, size_t freespace)
{
	SQLSOCK *sqlsocket;
	SQL_ROW row;
	SQL_INST *inst = instance;
	char querystr[MAX_QUERY_LEN];
	char sqlusername[MAX_STRING_LEN];
	size_t ret = 0;

	RDEBUG("sql_xlat");

	/*
         * Add SQL-User-Name attribute just in case it is needed
         *  We could search the string fmt for SQL-User-Name to see if this is
         *  needed or not
         */
	sql_set_user(inst, request, sqlusername, NULL);
	/*
	 * Do an xlat on the provided string (nice recursive operation).
	 */
	if (!radius_xlat(querystr, sizeof(querystr), fmt, request, sql_escape_func, inst)) {
		radlog(L_ERR, "rlm_sql (%s): xlat failed.",
		       inst->config->xlat_name);
		return 0;
	}

	sqlsocket = sql_get_socket(inst);
	if (sqlsocket == NULL)
		return 0;

	rlm_sql_query_log(inst, request, NULL, querystr);

	/*
	 *	If the query starts with any of the following prefixes,
	 *	then return the number of rows affected
	 */
	if ((strncasecmp(querystr, "insert", 6) == 0) ||
	    (strncasecmp(querystr, "update", 6) == 0) ||
	    (strncasecmp(querystr, "delete", 6) == 0)) {
		int numaffected;
		char buffer[21]; /* 64bit max is 20 decimal chars + null byte */

		if (rlm_sql_query(&sqlsocket,inst,querystr)) {
			sql_release_socket(inst,sqlsocket);
			
			return 0;
		}
	       
		numaffected = (inst->module->sql_affected_rows)(sqlsocket,
								inst->config);
		if (numaffected < 1) {
			RDEBUG("rlm_sql (%s): SQL query affected no rows",
				inst->config->xlat_name);
		}

		/*
		 *	Don't chop the returned number if freespace is
		 *	too small.  This hack is necessary because
		 *	some implementations of snprintf return the
		 *	size of the written data, and others return
		 *	the size of the data they *would* have written
		 *	if the output buffer was large enough.
		 */
		snprintf(buffer, sizeof(buffer), "%d", numaffected);
		ret = strlen(buffer);
		if (ret >= freespace){
			RDEBUG("rlm_sql (%s): Can't write result, insufficient string space",
			       inst->config->xlat_name);
			(inst->module->sql_finish_query)(sqlsocket,
							 inst->config);
			sql_release_socket(inst,sqlsocket);
			return 0;
		}
		
		memcpy(out, buffer, ret + 1); /* we did bounds checking above */

		(inst->module->sql_finish_query)(sqlsocket, inst->config);
		sql_release_socket(inst,sqlsocket);
		return ret;
	} /* else it's a SELECT statement */

	if (rlm_sql_select_query(&sqlsocket,inst,querystr)){
		sql_release_socket(inst,sqlsocket);
		return 0;
	}

	ret = rlm_sql_fetch_row(&sqlsocket, inst);
	if (ret) {
		RDEBUG("SQL query did not succeed");
		(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
		sql_release_socket(inst,sqlsocket);
		return 0;
	}

	row = sqlsocket->row;
	if (row == NULL) {
		RDEBUG("SQL query did not return any results");
		(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
		sql_release_socket(inst,sqlsocket);
		return 0;
	}

	if (row[0] == NULL){
		RDEBUG("Null value in first column");
		(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
		sql_release_socket(inst,sqlsocket);
		return 0;
	}
	ret = strlen(row[0]);
	if (ret >= freespace){
		RDEBUG("Insufficient string space");
		(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
		sql_release_socket(inst,sqlsocket);
		return 0;
	}

	strlcpy(out,row[0],freespace);

	RDEBUG("sql_xlat finished");

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
	char *prefix_ptr = NULL;
	unsigned int i = 0;
	int numf = 0;

	DEBUG("rlm_sql (%s): Processing generate_sql_clients",
	      inst->config->xlat_name);

	/* NAS query isn't xlat'ed */
	strlcpy(querystr, inst->config->nas_query, sizeof(querystr));
	DEBUG("rlm_sql (%s) in generate_sql_clients: query is %s",
	      inst->config->xlat_name, querystr);

	sqlsocket = sql_get_socket(inst);
	if (sqlsocket == NULL)
		return -1;
	if (rlm_sql_select_query(&sqlsocket,inst,querystr)){
		return -1;
	}

	while(rlm_sql_fetch_row(&sqlsocket, inst) == 0) {
		i++;
		row = sqlsocket->row;
		if (row == NULL)
			break;
		/*
		 *  The return data for each row MUST be in the following order:
		 *
		 *  0. Row ID (currently unused)
		 *  1. Name (or IP address)
		 *  2. Shortname
		 *  3. Type
		 *  4. Secret
		 *  5. Virtual Server (optional)
		 */
		if (!row[0]){
			radlog(L_ERR, "rlm_sql (%s): No row id found on pass %d",inst->config->xlat_name,i);
			continue;
		}
		if (!row[1]){
			radlog(L_ERR, "rlm_sql (%s): No nasname found for row %s",inst->config->xlat_name,row[0]);
			continue;
		}
		if (!row[2]){
			radlog(L_ERR, "rlm_sql (%s): No short name found for row %s",inst->config->xlat_name,row[0]);
			continue;
		}
		if (!row[4]){
			radlog(L_ERR, "rlm_sql (%s): No secret found for row %s",inst->config->xlat_name,row[0]);
			continue;
		}

		DEBUG("rlm_sql (%s): Read entry nasname=%s,shortname=%s,secret=%s",inst->config->xlat_name,
			row[1],row[2],row[4]);

		c = rad_malloc(sizeof(*c));
		memset(c, 0, sizeof(*c));

#ifdef WITH_DYNAMIC_CLIENTS
		c->dynamic = 1;
#endif

		/*
		 *	Look for prefixes
		 */
		c->prefix = -1;
		prefix_ptr = strchr(row[1], '/');
		if (prefix_ptr) {
			c->prefix = atoi(prefix_ptr + 1);
			if ((c->prefix < 0) || (c->prefix > 128)) {
				radlog(L_ERR, "rlm_sql (%s): Invalid Prefix value '%s' for IP.",
				       inst->config->xlat_name, prefix_ptr + 1);
				free(c);
				continue;
			}
			/* Replace '/' with '\0' */
			*prefix_ptr = '\0';
		}

		/*
		 *	Always get the numeric representation of IP
		 */
		if (ip_hton(row[1], AF_UNSPEC, &c->ipaddr) < 0) {
			radlog(L_CONS|L_ERR, "rlm_sql (%s): Failed to look up hostname %s: %s",
			       inst->config->xlat_name,
			       row[1], fr_strerror());
			free(c);
			continue;
		} else {
			char buffer[256];
			ip_ntoh(&c->ipaddr, buffer, sizeof(buffer));
			c->longname = strdup(buffer);
		}

		if (c->prefix < 0) switch (c->ipaddr.af) {
		case AF_INET:
			c->prefix = 32;
			break;
		case AF_INET6:
			c->prefix = 128;
			break;
		default:
			break;
		}

		/*
		 *	Other values (secret, shortname, nastype, virtual_server)
		 */
		c->secret = strdup(row[4]);
		c->shortname = strdup(row[2]);
		if(row[3] != NULL)
			c->nastype = strdup(row[3]);

		numf = (inst->module->sql_num_fields)(sqlsocket, inst->config);
		if ((numf > 5) && (row[5] != NULL) && *row[5]) c->server = strdup(row[5]);

		DEBUG("rlm_sql (%s): Adding client %s (%s, server=%s) to clients list",
		      inst->config->xlat_name,
		      c->longname,c->shortname, c->server ? c->server : "<none>");
		if (!client_add(NULL, c)) {
			sql_release_socket(inst, sqlsocket);
			DEBUG("rlm_sql (%s): Failed to add client %s (%s) to clients list.  Maybe there's a duplicate?",
			      inst->config->xlat_name,
			      c->longname,c->shortname);
			client_free(c);
			return -1;
		}
	}
	(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
	sql_release_socket(inst, sqlsocket);

	return 0;
}


/*
 *	Translate the SQL queries.
 */
static size_t sql_escape_func(UNUSED REQUEST *request, char *out, size_t outlen, const char *in, void *arg)
{
	SQL_INST *inst = arg;
	size_t len = 0;

	while (in[0]) {
		/*
		 *	Non-printable characters get replaced with their
		 *	mime-encoded equivalents.
		 */
		if ((in[0] < 32) ||
		    strchr(inst->config->allowed_chars, *in) == NULL) {
			/*
			 *	Only 3 or less bytes available.
			 */
			if (outlen <= 3) {
				break;
			}

			snprintf(out, outlen, "=%02X", (unsigned char) in[0]);
			in++;
			out += 3;
			outlen -= 3;
			len += 3;
			continue;
		}

		/*
		 *	Only one byte left.
		 */
		if (outlen <= 1) {
			break;
		}

		/*
		 *	Allowed character.
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
 *	Set the SQL user name.
 *
 *	We don't call the escape function here. The resulting string
 *	will be escaped later in the queries xlat so we don't need to
 *	escape it twice. (it will make things wrong if we have an
 *	escape candidate character in the username)
 */
int sql_set_user(SQL_INST *inst, REQUEST *request, char *sqlusername, const char *username)
{
	VALUE_PAIR *vp=NULL;
	char tmpuser[MAX_STRING_LEN];

	tmpuser[0] = '\0';
	sqlusername[0]= '\0';

	/* Remove any user attr we added previously */
	pairdelete(&request->packet->vps, PW_SQL_USER_NAME, 0);

	if (username != NULL) {
		strlcpy(tmpuser, username, sizeof(tmpuser));
	} else if (strlen(inst->config->query_user)) {
		radius_xlat(tmpuser, sizeof(tmpuser), inst->config->query_user, request, NULL, NULL);
	} else {
		return 0;
	}

	strlcpy(sqlusername, tmpuser, MAX_STRING_LEN);
	RDEBUG2("sql_set_user escaped user --> '%s'", sqlusername);
	vp = radius_pairmake(request, &request->packet->vps,
			     "SQL-User-Name", NULL, 0);
	if (!vp) {
		radlog(L_ERR, "%s", fr_strerror());
		return -1;
	}

	strlcpy(vp->vp_strvalue, tmpuser, sizeof(vp->vp_strvalue));
	vp->length = strlen(vp->vp_strvalue);

	return 0;

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

	if (!inst->config->groupmemb_query ||
	    (inst->config->groupmemb_query[0] == 0))
		return 0;

	if (!radius_xlat(querystr, sizeof(querystr), inst->config->groupmemb_query, request, sql_escape_func, inst)) {
		radlog_request(L_ERR, 0, request, "xlat \"%s\" failed.",
			       inst->config->groupmemb_query);
		return -1;
	}

	if (rlm_sql_select_query(&sqlsocket, inst, querystr) < 0) {
		return -1;
	}
	while (rlm_sql_fetch_row(&sqlsocket, inst) == 0) {
		row = sqlsocket->row;
		if (row == NULL)
			break;
		if (row[0] == NULL){
			RDEBUG("row[0] returned NULL");
			(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
			sql_grouplist_free(group_list);
			return -1;
		}
		if (*group_list == NULL) {
			*group_list = rad_malloc(sizeof(SQL_GROUPLIST));
			group_list_tmp = *group_list;
		} else {
			rad_assert(group_list_tmp != NULL);
			group_list_tmp->next = rad_malloc(sizeof(SQL_GROUPLIST));
			group_list_tmp = group_list_tmp->next;
		}
		group_list_tmp->next = NULL;
		strlcpy(group_list_tmp->groupname, row[0], MAX_STRING_LEN);
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

static int sql_groupcmp(void *instance, REQUEST *request, VALUE_PAIR *request_vp, VALUE_PAIR *check,
			VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	SQLSOCK *sqlsocket;
	SQL_INST *inst = instance;
	char sqlusername[MAX_STRING_LEN];
	SQL_GROUPLIST *group_list, *group_list_tmp;

	check_pairs = check_pairs;
	reply_pairs = reply_pairs;
	request_vp = request_vp;

	RDEBUG("sql_groupcmp");
	if (!check || !check->vp_strvalue || !check->length){
		RDEBUG("sql_groupcmp: Illegal group name");
		return 1;
	}
	if (!request){
		RDEBUG("sql_groupcmp: NULL request");
		return 1;
	}
	/*
	 * Set, escape, and check the user attr here
	 */
	if (sql_set_user(inst, request, sqlusername, NULL) < 0)
		return 1;

	/*
	 *	Get a socket for this lookup
	 */
	sqlsocket = sql_get_socket(inst);
	if (sqlsocket == NULL) {
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_SQL_USER_NAME, 0);
		return 1;
	}

	/*
	 *	Get the list of groups this user is a member of
	 */
	if (sql_get_grouplist(inst, sqlsocket, request, &group_list) < 0) {
		radlog_request(L_ERR, 0, request,
			       "Error getting group membership");
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_SQL_USER_NAME, 0);
		sql_release_socket(inst, sqlsocket);
		return 1;
	}

	for (group_list_tmp = group_list; group_list_tmp != NULL; group_list_tmp = group_list_tmp->next) {
		if (strcmp(group_list_tmp->groupname, check->vp_strvalue) == 0){
			RDEBUG("sql_groupcmp finished: User is a member of group %s",
			       check->vp_strvalue);
			/* Free the grouplist */
			sql_grouplist_free(&group_list);
			/* Remove the username we (maybe) added above */
			pairdelete(&request->packet->vps, PW_SQL_USER_NAME, 0);
			sql_release_socket(inst, sqlsocket);
			return 0;
		}
	}

	/* Free the grouplist */
	sql_grouplist_free(&group_list);
	/* Remove the username we (maybe) added above */
	pairdelete(&request->packet->vps, PW_SQL_USER_NAME, 0);
	sql_release_socket(inst,sqlsocket);

	RDEBUG("sql_groupcmp finished: User is NOT a member of group %s",
	       check->vp_strvalue);

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
	if (sql_get_grouplist(inst, sqlsocket, request, &group_list) < 0) {
		radlog_request(L_ERR, 0, request, "Error retrieving group list");
		return -1;
	}

	for (group_list_tmp = group_list; group_list_tmp != NULL && *dofallthrough != 0; group_list_tmp = group_list_tmp->next) {
		/*
		 *	Add the Sql-Group attribute to the request list so we know
		 *	which group we're retrieving attributes for
		 */
		sql_group = pairmake("Sql-Group", group_list_tmp->groupname, T_OP_EQ);
		if (!sql_group) {
			radlog_request(L_ERR, 0, request,
				       "Error creating Sql-Group attribute");
			sql_grouplist_free(&group_list);
			return -1;
		}
		pairadd(&request->packet->vps, sql_group);
		if (!radius_xlat(querystr, sizeof(querystr), inst->config->authorize_group_check_query, request, sql_escape_func, inst)) {
			radlog_request(L_ERR, 0, request,
				       "Error generating query; rejecting user");
			/* Remove the grouup we added above */
			pairdelete(&request->packet->vps, PW_SQL_GROUP, 0);
			sql_grouplist_free(&group_list);
			return -1;
		}
		rows = sql_getvpdata(inst, &sqlsocket, &check_tmp, querystr);
		if (rows < 0) {
			radlog_request(L_ERR, 0, request, "Error retrieving check pairs for group %s",
			       group_list_tmp->groupname);
			/* Remove the grouup we added above */
			pairdelete(&request->packet->vps, PW_SQL_GROUP, 0);
			pairfree(&check_tmp);
			sql_grouplist_free(&group_list);
			return -1;
		} else if (rows > 0) {
			/*
			 *	Only do this if *some* check pairs were returned
			 */
			if (paircompare(request, request->packet->vps, check_tmp, &request->reply->vps) == 0) {
				found = 1;
				RDEBUG2("User found in group %s",
					group_list_tmp->groupname);
				/*
				 *	Now get the reply pairs since the paircompare matched
				 */
				if (!radius_xlat(querystr, sizeof(querystr), inst->config->authorize_group_reply_query, request, sql_escape_func, inst)) {
					radlog_request(L_ERR, 0, request, "Error generating query; rejecting user");
					/* Remove the grouup we added above */
					pairdelete(&request->packet->vps, PW_SQL_GROUP, 0);
					pairfree(&check_tmp);
					sql_grouplist_free(&group_list);
					return -1;
				}
				if (sql_getvpdata(inst, &sqlsocket, &reply_tmp, querystr) < 0) {
					radlog_request(L_ERR, 0, request, "Error retrieving reply pairs for group %s",
					       group_list_tmp->groupname);
					/* Remove the grouup we added above */
					pairdelete(&request->packet->vps, PW_SQL_GROUP, 0);
					pairfree(&check_tmp);
					pairfree(&reply_tmp);
					sql_grouplist_free(&group_list);
					return -1;
				}
				*dofallthrough = fallthrough(reply_tmp);
				pairxlatmove(request, &request->reply->vps, &reply_tmp);
				pairxlatmove(request, &request->config_items, &check_tmp);
			}
		} else {
			/*
			 *	rows == 0.  This is like having the username on a line
			 * 	in the user's file with no check vp's.  As such, we treat
			 *	it as found and add the reply attributes, so that we
			 *	match expected behavior
			 */
			found = 1;
			RDEBUG2("User found in group %s",
				group_list_tmp->groupname);
			/*
			 *	Now get the reply pairs since the paircompare matched
			 */
			if (!radius_xlat(querystr, sizeof(querystr), inst->config->authorize_group_reply_query, request, sql_escape_func, inst)) {
				radlog_request(L_ERR, 0, request, "Error generating query; rejecting user");
				/* Remove the grouup we added above */
				pairdelete(&request->packet->vps, PW_SQL_GROUP, 0);
				pairfree(&check_tmp);
				sql_grouplist_free(&group_list);
				return -1;
			}
			if (sql_getvpdata(inst, &sqlsocket, &reply_tmp, querystr) < 0) {
				radlog_request(L_ERR, 0, request, "Error retrieving reply pairs for group %s",
				       group_list_tmp->groupname);
				/* Remove the grouup we added above */
				pairdelete(&request->packet->vps, PW_SQL_GROUP, 0);
				pairfree(&check_tmp);
				pairfree(&reply_tmp);
				sql_grouplist_free(&group_list);
				return -1;
			}
			*dofallthrough = fallthrough(reply_tmp);
			pairxlatmove(request, &request->reply->vps, &reply_tmp);
			pairxlatmove(request, &request->config_items, &check_tmp);
		}

		/*
		 * Delete the Sql-Group we added above
		 * And clear out the pairlists
		 */
		pairdelete(&request->packet->vps, PW_SQL_GROUP, 0);
		pairfree(&check_tmp);
		pairfree(&reply_tmp);
	}

	sql_grouplist_free(&group_list);
	return found;
}


static int rlm_sql_detach(void *instance)
{
	SQL_INST *inst = instance;

	paircompare_unregister(PW_SQL_GROUP, sql_groupcmp);

	if (inst->config) {
		int i;

		if (inst->pool) sql_poolfree(inst);

		if (inst->config->xlat_name) {
			xlat_unregister(inst->config->xlat_name, sql_xlat, instance);
			free(inst->config->xlat_name);
		}

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

static int parse_sub_section(CONF_SECTION *parent, 
	 		     UNUSED SQL_INST *instance,
	 		     rlm_sql_config_section_t *config,
	 		     rlm_components_t comp)
{
	CONF_SECTION *cs;

	const char *name = section_type_value[comp].section;
	
	cs = cf_section_sub_find(parent, name);
	if (!cs) {
		radlog(L_INFO, "Couldn't find configuration for %s. Will return NOOP for calls from this section.", name);
		
		 return 1;
	}
	
	if (cf_section_parse(cs, config, section_config) < 0) {
		radlog(L_ERR, "Failed parsing configuration for section %s",
		       name);
		
		return -1;
	}
		
	config->cs = cs;

	return 1;
}

static int rlm_sql_instantiate(CONF_SECTION * conf, void **instance)
{
	SQL_INST *inst;
	const char *xlat_name;

	inst = rad_malloc(sizeof(SQL_INST));
	memset(inst, 0, sizeof(SQL_INST));

	/*
	 *	Export these methods, too.  This avoids RTDL_GLOBAL.
	 */
	inst->sql_set_user		= sql_set_user;
	inst->sql_get_socket		= sql_get_socket;
	inst->sql_release_socket	= sql_release_socket;
	inst->sql_escape_func		= sql_escape_func;
	inst->sql_query			= rlm_sql_query;
	inst->sql_select_query		= rlm_sql_select_query;
	inst->sql_fetch_row		= rlm_sql_fetch_row;
	
	inst->config = rad_malloc(sizeof(SQL_CONFIG));
	memset(inst->config, 0, sizeof(SQL_CONFIG));
	inst->cs = conf;
		
	/*
	 *	If the configuration parameters can't be parsed, then fail.
	 */
	if ((cf_section_parse(conf, inst->config, module_config) < 0) ||
	    (parse_sub_section(conf, inst,
			       &inst->config->accounting,
			       RLM_COMPONENT_ACCT) < 0) ||
	    (parse_sub_section(conf, inst,
			       &inst->config->postauth,
			       RLM_COMPONENT_POST_AUTH) < 0)) {
		radlog(L_ERR, "Failed parsing configuration");
		goto error;
	}

	xlat_name = cf_section_name2(conf);
	if (xlat_name == NULL) {
		xlat_name = cf_section_name1(conf);
	} else {
		char *group_name;
		DICT_ATTR *dattr;
		ATTR_FLAGS flags;

		/*
		 *	Allocate room for <instance>-SQL-Group
		 */
		group_name = rad_malloc((strlen(xlat_name) + 1 + 11) * sizeof(char));
		sprintf(group_name,"%s-SQL-Group", xlat_name);
		DEBUG("rlm_sql Creating new attribute %s",group_name);

		memset(&flags, 0, sizeof(flags));
		dict_addattr(group_name, 0, PW_TYPE_STRING, -1, flags);
		dattr = dict_attrbyname(group_name);
		if (dattr == NULL){
			radlog(L_ERR, "rlm_sql: Failed to create attribute %s",
			       group_name);
			       
			free(group_name);

			goto error;
		}

		if (inst->config->groupmemb_query && 
		    inst->config->groupmemb_query[0]) {
			DEBUG("rlm_sql: Registering sql_groupcmp for %s",
			      group_name);
			paircompare_register(dattr->attr, PW_USER_NAME,
					     sql_groupcmp, inst);
		}

		free(group_name);
	}
	
	rad_assert(xlat_name);

	/*
	 *	Register the SQL xlat function
	 */
	inst->config->xlat_name = strdup(xlat_name);
	xlat_register(xlat_name, sql_xlat, inst);
		
	/*
	 *	Sanity check for crazy people.
	 */
	if (strncmp(inst->config->sql_driver, "rlm_sql_", 8) != 0) {
		radlog(L_ERR, "\"%s\" is NOT an SQL driver!",
		       inst->config->sql_driver);
		goto error;
	}

	/*
	 *	Load the appropriate driver for our database
	 */
	inst->handle = lt_dlopenext(inst->config->sql_driver);
	if (inst->handle == NULL) {
		radlog(L_ERR, "Could not link driver %s: %s",
		       inst->config->sql_driver,
		       lt_dlerror());
		radlog(L_ERR, "Make sure it (and all its dependent libraries!)"
		       "are in the search path of your system's ld.");

		goto error;
	}

	inst->module = (rlm_sql_module_t *) lt_dlsym(inst->handle,
						     inst->config->sql_driver);
	if (!inst->module) {
		radlog(L_ERR, "Could not link symbol %s: %s",
		       inst->config->sql_driver,
		       lt_dlerror());

		goto error;
	}

	radlog(L_INFO, "rlm_sql (%s): Driver %s (module %s) loaded and linked",
	       inst->config->xlat_name, inst->config->sql_driver,
	       inst->module->name);

	/*
	 *	Initialise the connection pool for this instance
	 */
	radlog(L_INFO, "rlm_sql (%s): Attempting to connect to %s@%s:%s/%s",
	       inst->config->xlat_name, inst->config->sql_login,
	       inst->config->sql_server, inst->config->sql_port,
	       inst->config->sql_db);
	       
	if (sql_init_socketpool(inst) < 0)
		goto error;

	if (inst->config->groupmemb_query && 
	    inst->config->groupmemb_query[0]) {
		paircompare_register(PW_SQL_GROUP, PW_USER_NAME, sql_groupcmp, inst);
	}

	if (inst->config->do_clients) {
		if (generate_sql_clients(inst) == -1){
			radlog(L_ERR, "Failed to load clients from SQL.");
			
			goto error;
		}
	}

	*instance = inst;

	return RLM_MODULE_OK;
	
	error:
	rlm_sql_detach(inst);
	
	return -1;
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
	char	sqlusername[MAX_STRING_LEN];
	/*
	 * the profile username is used as the sqlusername during
	 * profile checking so that we don't overwrite the orignal
	 * sqlusername string
	 */
	char   profileusername[MAX_STRING_LEN];

	/*
	 * Set, escape, and check the user attr here
	 */
	if (sql_set_user(inst, request, sqlusername, NULL) < 0)
		return RLM_MODULE_FAIL;


	/*
	 *  Reserve a socket
	 */
	sqlsocket = sql_get_socket(inst);
	if (sqlsocket == NULL) {
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_SQL_USER_NAME, 0);
		return RLM_MODULE_FAIL;
	}


	/*
	 *  After this point, ALL 'return's MUST release the SQL socket!
	 */

	/*
	 * Alright, start by getting the specific entry for the user
	 */
	if (!radius_xlat(querystr, sizeof(querystr), inst->config->authorize_check_query, request, sql_escape_func, inst)) {
		radlog_request(L_ERR, 0, request, "Error generating query; rejecting user");
		sql_release_socket(inst, sqlsocket);
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_SQL_USER_NAME, 0);
		return RLM_MODULE_FAIL;
	}
	rows = sql_getvpdata(inst, &sqlsocket, &check_tmp, querystr);
	if (rows < 0) {
		radlog_request(L_ERR, 0, request, "SQL query error; rejecting user");
		sql_release_socket(inst, sqlsocket);
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_SQL_USER_NAME, 0);
		pairfree(&check_tmp);
		return RLM_MODULE_FAIL;
	} else if (rows > 0) {
		/*
		 *	Only do this if *some* check pairs were returned
		 */
		if (paircompare(request, request->packet->vps, check_tmp, &request->reply->vps) == 0) {
			found = 1;
			RDEBUG2("User found in radcheck table");

			if (inst->config->authorize_reply_query &&
			    *inst->config->authorize_reply_query) {

			/*
			 *	Now get the reply pairs since the paircompare matched
			 */
			if (!radius_xlat(querystr, sizeof(querystr), inst->config->authorize_reply_query, request, sql_escape_func, inst)) {
				radlog_request(L_ERR, 0, request, "Error generating query; rejecting user");
				sql_release_socket(inst, sqlsocket);
				/* Remove the username we (maybe) added above */
				pairdelete(&request->packet->vps, PW_SQL_USER_NAME, 0);
				pairfree(&check_tmp);
				return RLM_MODULE_FAIL;
			}
			if (sql_getvpdata(inst, &sqlsocket, &reply_tmp, querystr) < 0) {
				radlog_request(L_ERR, 0, request, "SQL query error; rejecting user");
				sql_release_socket(inst, sqlsocket);
				/* Remove the username we (maybe) added above */
				pairdelete(&request->packet->vps, PW_SQL_USER_NAME, 0);
				pairfree(&check_tmp);
				pairfree(&reply_tmp);
				
				return RLM_MODULE_FAIL;
			}

			if (!inst->config->read_groups)
				dofallthrough = fallthrough(reply_tmp);
			pairxlatmove(request, &request->reply->vps, &reply_tmp);
			}
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
			radlog_request(L_ERR, 0, request, "Error processing groups; rejecting user");
			sql_release_socket(inst, sqlsocket);
			/* Remove the username we (maybe) added above */
			pairdelete(&request->packet->vps, PW_SQL_USER_NAME, 0);
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
		user_profile = pairfind(request->config_items, PW_USER_PROFILE, 0);
		if (inst->config->default_profile[0] != 0 || user_profile != NULL){
			char *profile = inst->config->default_profile;

			if (user_profile != NULL)
				profile = user_profile->vp_strvalue;
			if (profile && strlen(profile)){
				RDEBUG("Checking profile %s", profile);
				if (sql_set_user(inst, request, profileusername, profile) < 0) {
					radlog_request(L_ERR, 0, request, "Error setting profile; rejecting user");
					sql_release_socket(inst, sqlsocket);
					/* Remove the username we (maybe) added above */
					pairdelete(&request->packet->vps, PW_SQL_USER_NAME, 0);
					return RLM_MODULE_FAIL;
				} else {
					profile_found = 1;
				}
			}
		}

		if (profile_found) {
			rows = rlm_sql_process_groups(inst, request, sqlsocket, &dofallthrough);
			if (rows < 0) {
				radlog_request(L_ERR, 0, request, "Error processing profile groups; rejecting user");
				sql_release_socket(inst, sqlsocket);
				/* Remove the username we (maybe) added above */
				pairdelete(&request->packet->vps, PW_SQL_USER_NAME, 0);
				return RLM_MODULE_FAIL;
			} else if (rows > 0) {
				found = 1;
			}
		}
	}

	/* Remove the username we (maybe) added above */
	pairdelete(&request->packet->vps, PW_SQL_USER_NAME, 0);
	sql_release_socket(inst, sqlsocket);

	if (!found) {
		RDEBUG("User %s not found", sqlusername);
		return RLM_MODULE_NOTFOUND;
	} else {
		return RLM_MODULE_OK;
	}
}

/*
 *	Generic function for failing between a bunch of queries.
 *
 *	Uses the same principle as rlm_linelog, expanding the 'reference' config
 *	item using xlat to figure out what query it should execute.
 *
 *	If the reference matches multiple config items, and a query fails or
 *	doesn't update any rows, the next matching config item is used.
 *  
 */
static int rlm_sql_redundant(SQL_INST *inst, REQUEST *request, 
			     rlm_sql_config_section_t *section)
{
	int		ret = RLM_MODULE_OK;

	SQLSOCK		*sqlsocket = NULL;
	int		sql_ret;
	int		numaffected = 0;

	CONF_ITEM	*item;
	CONF_PAIR	*pair;
	const char	*attr = NULL;
	const char	*value;

	char	path[MAX_STRING_LEN];
	char	querystr[MAX_QUERY_LEN];
	char	sqlusername[MAX_STRING_LEN];
	
	char	*p = path;

	if (!section || !section->reference) {
		RDEBUG("No configuration provided for this section");
		
		return RLM_MODULE_NOOP;	
	}
	
	sql_set_user(inst, request, sqlusername, NULL);
	
	if (section->reference[0] != '.')
		*p++ = '.';
	
	if (radius_xlat(p, (sizeof(path) - (p - path)) - 1,
			section->reference, request, NULL, NULL) < 0)
		return RLM_MODULE_FAIL;

	item = cf_reference_item(NULL, section->cs, path);
	if (!item)
		return RLM_MODULE_FAIL;

	if (cf_item_is_section(item)){
		radlog(L_ERR, "Sections are not supported as references");
		
		return RLM_MODULE_FAIL;
	}
	
	pair = cf_itemtopair(item);
	attr = cf_pair_attr(pair);
	
	RDEBUG2("Using query template '%s'", attr);
	
	sqlsocket = sql_get_socket(inst);
	if (sqlsocket == NULL)
		return RLM_MODULE_FAIL;

	while (TRUE) {
		value = cf_pair_value(pair);
		if (!value)
			goto null_query;
		
		radius_xlat(querystr, sizeof(querystr), value, request,
			    sql_escape_func, inst);
		if (!*querystr)
			goto null_query;
		
		rlm_sql_query_log(inst, request, section, querystr);
		
		sql_ret = rlm_sql_query(&sqlsocket, inst, querystr);	
		if (sql_ret == SQL_DOWN)
			return RLM_MODULE_FAIL;
			
		rad_assert(sqlsocket);
	
		/* 
		 *  Assume all other errors are incidental, and just meant our
		 *  operation failed and its not a client or SQL syntax error.
		 */
		if (sql_ret == 0) {
			numaffected = (inst->module->sql_affected_rows)
					(sqlsocket, inst->config);
			if (numaffected > 0)
				break;
				
			RDEBUG("No records updated");
		}

		(inst->module->sql_finish_query)(sqlsocket, inst->config);
		
		/*
		 *  We assume all entries with the same name form a redundant
		 *  set of queries.
		 */
		pair = cf_pair_find_next(section->cs, pair, attr);
		
		if (!pair) {
			RDEBUG("No additional queries configured");
			
			ret = RLM_MODULE_NOOP;
			
			goto release;
		}

		RDEBUG("Trying next query...");
	}
	
	(inst->module->sql_finish_query)(sqlsocket, inst->config);

	release:
	
	sql_release_socket(inst, sqlsocket);

	return ret;
	
	null_query:
	
	RDEBUG("Ignoring null query");
	
	sql_release_socket(inst, sqlsocket);

	return RLM_MODULE_NOOP;
}

#ifdef WITH_ACCOUNTING

/*
 *	Accounting: Insert or update session data in our sql table
 */
static int rlm_sql_accounting(void *instance, REQUEST * request) {
	SQL_INST *inst = instance;		

	return rlm_sql_redundant(inst, request, &inst->config->accounting); 
}

#endif

#ifdef WITH_SESSION_MGMT
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
	char		sqlusername[MAX_STRING_LEN];
	int		check = 0;
        uint32_t        ipno = 0;
        char            *call_num = NULL;
	VALUE_PAIR      *vp;
	int		ret;
	uint32_t	nas_addr = 0;
	int		nas_port = 0;

	/* If simul_count_query is not defined, we don't do any checking */
	if (!inst->config->simul_count_query ||
	    (inst->config->simul_count_query[0] == 0)) {
		return RLM_MODULE_NOOP;
	}

	if((request->username == NULL) || (request->username->length == 0)) {
		radlog_request(L_ERR, 0, request,
					   "Zero Length username not permitted\n");
		return RLM_MODULE_INVALID;
	}


	if(sql_set_user(inst, request, sqlusername, NULL) < 0)
		return RLM_MODULE_FAIL;

	radius_xlat(querystr, sizeof(querystr), inst->config->simul_count_query, request, sql_escape_func, inst);

	/* initialize the sql socket */
	sqlsocket = sql_get_socket(inst);
	if(sqlsocket == NULL)
		return RLM_MODULE_FAIL;

	if(rlm_sql_select_query(&sqlsocket, inst, querystr)) {
		sql_release_socket(inst, sqlsocket);
		return RLM_MODULE_FAIL;
	}

	ret = rlm_sql_fetch_row(&sqlsocket, inst);
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

	/*
	 *	Looks like too many sessions, so let's start verifying
	 *	them, unless told to rely on count query only.
	 */
	if (!inst->config->simul_verify_query ||
	    (inst->config->simul_verify_query[0] == '\0')) {
		sql_release_socket(inst, sqlsocket);
		return RLM_MODULE_OK;
	}

	radius_xlat(querystr, sizeof(querystr), inst->config->simul_verify_query, request, sql_escape_func, inst);
	if(rlm_sql_select_query(&sqlsocket, inst, querystr)) {
		sql_release_socket(inst, sqlsocket);
		return RLM_MODULE_FAIL;
	}

        /*
         *      Setup some stuff, like for MPP detection.
         */
	request->simul_count = 0;

        if ((vp = pairfind(request->packet->vps, PW_FRAMED_IP_ADDRESS, 0)) != NULL)
                ipno = vp->vp_ipaddr;
        if ((vp = pairfind(request->packet->vps, PW_CALLING_STATION_ID, 0)) != NULL)
                call_num = vp->vp_strvalue;


	while (rlm_sql_fetch_row(&sqlsocket, inst) == 0) {
		row = sqlsocket->row;
		if (row == NULL)
			break;
		if (!row[2]){
			(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
			sql_release_socket(inst, sqlsocket);
			RDEBUG("Cannot zap stale entry. No username present in entry.", inst->config->xlat_name);
			return RLM_MODULE_FAIL;
		}
		if (!row[1]){
			(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
			sql_release_socket(inst, sqlsocket);
			RDEBUG("Cannot zap stale entry. No session id in entry.", inst->config->xlat_name);
			return RLM_MODULE_FAIL;
		}
		if (row[3])
			nas_addr = inet_addr(row[3]);
		if (row[4])
			nas_port = atoi(row[4]);

		check = rad_check_ts(nas_addr, nas_port, row[2], row[1]);

		if (check == 0) {
			/*
			 *	Stale record - zap it.
			 */
			if (inst->config->deletestalesessions == TRUE) {
				uint32_t framed_addr = 0;
				char proto = 0;
				int sess_time = 0;

				if (row[5])
					framed_addr = inet_addr(row[5]);
				if (row[7]){
					if (strcmp(row[7], "PPP") == 0)
						proto = 'P';
					else if (strcmp(row[7], "SLIP") == 0)
						proto = 'S';
				}
				if (row[8])
					sess_time = atoi(row[8]);
				session_zap(request, nas_addr, nas_port,
					    row[2], row[1], framed_addr,
					    proto, sess_time);
			}
		}
		else if (check == 1) {
			/*
			 *	User is still logged in.
			 */
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
			 *      Failed to check the terminal server for
			 *      duplicate logins: return an error.
			 */
			(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
			sql_release_socket(inst, sqlsocket);
			radlog_request(L_ERR, 0, request, "Failed to check the terminal server for user '%s'.", row[2]);
			return RLM_MODULE_FAIL;
		}
	}

	(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
	sql_release_socket(inst, sqlsocket);

	/*
	 *	The Auth module apparently looks at request->simul_count,
	 *	not the return value of this module when deciding to deny
	 *	a call for too many sessions.
	 */
	return RLM_MODULE_OK;
}
#endif

/*
 *	Postauth: Write a record of the authentication attempt
 */
static int rlm_sql_postauth(void *instance, REQUEST * request) {
	SQL_INST *inst = instance;
	
	return rlm_sql_redundant(inst, request, &inst->config->postauth); 
}

/*
 *	Execute postauth_query after authentication
 */


/* globally exported name */
module_t rlm_sql = {
	RLM_MODULE_INIT,
	"SQL",
	RLM_TYPE_THREAD_SAFE,	/* type: reserved */
	rlm_sql_instantiate,	/* instantiation */
	rlm_sql_detach,		/* detach */
	{
		NULL,			/* authentication */
		rlm_sql_authorize,	/* authorization */
		NULL,			/* preaccounting */
#ifdef WITH_ACCOUNTING
		rlm_sql_accounting,	/* accounting */
#else
		NULL,
#endif
#ifdef WITH_SESSION_MGMT
		rlm_sql_checksimul,	/* checksimul */
#else
		NULL,
#endif
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		rlm_sql_postauth	/* post-auth */
	},
};
