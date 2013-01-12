/*
 * rlm_redisn.c		REDISN Module
 * 		Main REDISN module file. Most REDIS code is located in redisn.c
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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Mike Machado <mike@innercite.com>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2011  Manuel Guesdon <mguesdon@oxymium.net>
 *
 * Precision from MGuesdon: Most code come from rlm_sql.c
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/stat.h>

#include "rlm_redisn.h"
#define PW_REDIS_GROUP                  1136
#define PW_REDIS_USER_NAME		PW_SQL_USER_NAME
static char *allowed_chars = NULL;

static const CONF_PARSER module_config[] = {
	{"servers",PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,redisn_servers), NULL, "0@localhost/6379"},
	{"vp_separator", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,vp_separator), NULL, ""},
	{"read_groups", PW_TYPE_BOOLEAN,
	 offsetof(REDIS_INST,read_groups), NULL, "yes"},
	{"redistrace", PW_TYPE_BOOLEAN,
	 offsetof(REDIS_INST,redisntrace), NULL, "no"},
	{"redistracefile", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,tracefile), NULL, REDISNTRACEFILE},
	{"readclients", PW_TYPE_BOOLEAN,
	 offsetof(REDIS_INST,do_clients), NULL, "no"},
	{"deletestalesessions", PW_TYPE_BOOLEAN,
	 offsetof(REDIS_INST,deletestalesessions), NULL, "yes"},
	{"num_connections", PW_TYPE_INTEGER,
	 offsetof(REDIS_INST,num_redisn_socks), NULL, "5"},
	{"lifetime", PW_TYPE_INTEGER,
	 offsetof(REDIS_INST,lifetime), NULL, "0"},
	{"max_queries", PW_TYPE_INTEGER,
	 offsetof(REDIS_INST,max_queries), NULL, "0"},
	{"redis_user_name", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,query_user), NULL, ""},
	{"default_user_profile", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,default_profile), NULL, ""},
	{"nas_query", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,nas_query), NULL, "SELECT id,nasname,shortname,type,secret FROM nas"},
	{"authorize_check_query", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,authorize_check_query), NULL, ""},
	{"authorize_reply_query", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,authorize_reply_query), NULL, NULL},
	{"authorize_group_check_query", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,authorize_group_check_query), NULL, ""},
	{"authorize_group_reply_query", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,authorize_group_reply_query), NULL, ""},
	{"accounting_on_query", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,accounting_on_query), NULL, ""},
	{"accounting_off_query", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,accounting_off_query), NULL, ""},
	{"accounting_update_query", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,accounting_update_query), NULL, ""},
	{"accounting_start_query", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,accounting_start_query), NULL, ""},
	{"accounting_stop_query", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,accounting_stop_query), NULL, ""},
	{"group_membership_query", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,groupmemb_query), NULL, NULL},
	{"connect_failure_retry_delay", PW_TYPE_INTEGER,
	 offsetof(REDIS_INST,connect_failure_retry_delay), NULL, "60"},
	{"simul_count_query", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,simul_count_query), NULL, ""},
	{"simul_verify_query", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,simul_verify_query), NULL, ""},
	{"postauth_query", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,postauth_query), NULL, ""},
	{"safe-characters", PW_TYPE_STRING_PTR,
	 offsetof(REDIS_INST,allowed_chars), NULL,
	"@abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:/"},
	{"query_timeout", PW_TYPE_INTEGER,
	 offsetof(REDIS_INST,query_timeout), NULL, "0"},
	{NULL, -1, 0, NULL, NULL}
};

/*
 *	Fall-Through checking function from rlm_files.c
 */
static int fallthrough(VALUE_PAIR *vp)
{
	VALUE_PAIR *tmp;
	tmp = pairfind(vp, PW_FALL_THROUGH, 0, TAG_ANY);

	DEBUG("rlm_redisn: fallthrough: %sfound => %d",
	      tmp ? "" : "not ",
	      tmp ? tmp->vp_integer : 0);

	return tmp ? tmp->vp_integer : 0;
}



/*
 *	Yucky prototype.
 */
static int generate_redisn_clients(REDIS_INST *inst);
static size_t redisn_escape_func(REQUEST *,char *out, size_t outlen, const char *in, void *arg);

/*
 *	redisn xlat function. Right now only xGET are supported. Only
 *	the first element of the SELECT result will be used.
 */
static int redisn_xlat(void *instance, REQUEST *request,
		    char *fmt, char *out, size_t freespace,
		    UNUSED RADIUS_ESCAPE_STRING func)
{
	REDISSOCK *redis_socket=NULL;
	REDIS_ROW row;
	REDIS_INST *inst = instance;
	char querystr[MAX_QUERY_LEN];
	char redisnusername[MAX_STRING_LEN];
	size_t ret = 0;

	RDEBUG("redisn_xlat");

	/*
         * Add REDISN-User-Name attribute just in case it is needed
         *  We could search the string fmt for REDISN-User-Name to see if this is
         *  needed or not
         */
	redisn_set_user(inst, request, redisnusername, NULL);
	/*
	 * Do an xlat on the provided string (nice recursive operation).
	 */
	if (!radius_xlat(querystr, sizeof(querystr), fmt, request, redisn_escape_func, inst)) {
		radlog(L_ERR, "rlm_redisn (%s): xlat failed.",
		       inst->xlat_name);
		return 0;
	}

	query_log(request, inst, querystr);
	redis_socket = redisn_get_socket(inst);
	if (redis_socket == NULL)
		return 0;

	if (rlm_redisn_query(inst, redis_socket, querystr)<0) {
	  radlog(L_ERR, "rlm_redisn (%s): database query error, %s",
		 inst->xlat_name,querystr);
	  redisn_release_socket(inst,redis_socket);
	  return 0;
	  }

	ret = rlm_redisn_fetch_row(inst, redis_socket);

	if (ret) {
		RDEBUG("REDIS query did not succeed");
		(inst->redisn_finish_query)(inst, redis_socket);
		redisn_release_socket(inst,redis_socket);
		return 0;
	}

	row = redis_socket->row;
	if (row == NULL) {
		RDEBUG("REDIS query did not return any results");
		(inst->redisn_finish_query)(inst, redis_socket);
		redisn_release_socket(inst,redis_socket);
		return 0;
	}

	if (row[0] == NULL){
		RDEBUG("row[0] returned NULL");
		(inst->redisn_finish_query)(inst, redis_socket);
		redisn_release_socket(inst,redis_socket);
		return 0;
	}
	ret = strlen(row[0]);
	if (ret >= freespace){
		RDEBUG("Insufficient string space");
		(inst->redisn_finish_query)(inst, redis_socket);
		redisn_release_socket(inst,redis_socket);
		return 0;
	}

	strlcpy(out,row[0],freespace);

	RDEBUG("redisn_xlat finished");

	(inst->redisn_finish_query)(inst,redis_socket);
	redisn_release_socket(inst,redis_socket);
	return ret;
}

static int generate_redisn_clients(REDIS_INST *inst)
{
	REDISSOCK *redis_socket=NULL;
	REDIS_ROW row;
	char querystr[MAX_QUERY_LEN];
	RADCLIENT *c=NULL;
	char *prefix_ptr = NULL;
	unsigned int i = 0;

	DEBUG("rlm_redisn (%s): Processing generate_redisn_clients",
	      inst->xlat_name);

	/* NAS query isn't xlat'ed */
	strlcpy(querystr, inst->nas_query, sizeof(querystr));
	DEBUG("rlm_redisn (%s) in generate_redisn_clients: query is %s",
	      inst->xlat_name, querystr);

	redis_socket = redisn_get_socket(inst);
	if (redis_socket == NULL)
		return -1;
	if (rlm_redisn_query(inst, redis_socket,querystr)){
		radlog(L_ERR, "rlm_redisn (%s): database query error, %s",
		       inst->xlat_name,querystr);
		redisn_release_socket(inst,redis_socket);
		return -1;
	}

	while(rlm_redisn_fetch_row(inst, redis_socket) == 0) {
		i++;
		row = redis_socket->row;
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
			radlog(L_ERR, "rlm_redisn (%s): No row id found on pass %d",inst->xlat_name,i);
			continue;
		}
		if (!row[1]){
			radlog(L_ERR, "rlm_redisn (%s): No nasname found for row %s",inst->xlat_name,row[0]);
			continue;
		}
		if (!row[2]){
			radlog(L_ERR, "rlm_redisn (%s): No short name found for row %s",inst->xlat_name,row[0]);
			continue;
		}
		if (!row[4]){
			radlog(L_ERR, "rlm_redisn (%s): No secret found for row %s",inst->xlat_name,row[0]);
			continue;
		}

		DEBUG("rlm_redisn (%s): Read entry nasname=%s,shortname=%s,secret=%s",inst->xlat_name,
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
				radlog(L_ERR, "rlm_redisn (%s): Invalid Prefix value '%s' for IP.",
				       inst->xlat_name, prefix_ptr + 1);
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
			radlog(L_CONS|L_ERR, "rlm_redisn (%s): Failed to look up hostname %s: %s",
			       inst->xlat_name,
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

		if ((redis_socket->num_fields > 5) && 
		    (row[5] != NULL) && 
		    *row[5] != '\0') 
		  c->server = strdup(row[5]);

		DEBUG("rlm_redisn (%s): Adding client %s (%s, server=%s) to clients list",
		      inst->xlat_name,
		      c->longname,c->shortname, c->server ? c->server : "<none>");
		if (!client_add(NULL, c)) {
			redisn_release_socket(inst, redis_socket);
			DEBUG("rlm_redisn (%s): Failed to add client %s (%s) to clients list.  Maybe there's a duplicate?",
			      inst->xlat_name,
			      c->longname,c->shortname);
			client_free(c);
			return -1;
		}
	}
	(inst->redisn_finish_query)(inst, redis_socket);
	redisn_release_socket(inst, redis_socket);

	return 0;
}


/*
 *	Translate the REDISN queries.
 */
static size_t redisn_escape_func(UNUSED REQUEST *request, char *out, size_t outlen,
				 const char *in, void *arg)
{
	REDIS_INST *inst = arg;
	size_t len = 0;

	while (in[0]) {
		/*
		 *	Non-printable characters get replaced with their
		 *	mime-encoded equivalents.
		 */
		if ((in[0] < 32) ||
		    strchr(inst->allowed_chars, *in) == NULL) {
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
 *	Set the REDISN user name.
 *
 *	We don't call the escape function here. The resulting string
 *	will be escaped later in the queries xlat so we don't need to
 *	escape it twice. (it will make things wrong if we have an
 *	escape candidate character in the username)
 */
int redisn_set_user(REDIS_INST *inst, REQUEST *request, char *redisnusername, const char *username)
{
	VALUE_PAIR *vp=NULL;
	char tmpuser[MAX_STRING_LEN];

	tmpuser[0] = '\0';
	redisnusername[0]= '\0';

	/* Remove any user attr we added previously */
	pairdelete(&request->packet->vps, PW_REDIS_USER_NAME, 0, TAG_ANY);

	if (username != NULL) {
		strlcpy(tmpuser, username, sizeof(tmpuser));
	} else if (strlen(inst->query_user)) {
		radius_xlat(tmpuser, sizeof(tmpuser), inst->query_user, request, NULL, inst);
	} else {
		return 0;
	}

	strlcpy(redisnusername, tmpuser, MAX_STRING_LEN);
	RDEBUG2("redisn_set_user escaped user --> '%s'", redisnusername);
	vp = radius_pairmake(request, &request->packet->vps,
			     "REDISN-User-Name", NULL, 0);
	if (!vp) {
		radlog(L_ERR, "%s", fr_strerror());
		return -1;
	}

	strlcpy(vp->vp_strvalue, tmpuser, sizeof(vp->vp_strvalue));
	vp->length = strlen(vp->vp_strvalue);

	return 0;

}


static void redisn_grouplist_free (REDISN_GROUPLIST **group_list)
{
	REDISN_GROUPLIST *last;

	while(*group_list) {
		last = *group_list;
		*group_list = (*group_list)->next;
		free(last);
	}
}


static int redisn_get_grouplist (REDIS_INST *inst, REDISSOCK *redis_socket, REQUEST *request, REDISN_GROUPLIST **group_list)
{
	char    querystr[MAX_QUERY_LEN];
	int     num_groups = 0;
	REDIS_ROW row;
	REDISN_GROUPLIST   *group_list_tmp;

	/* NOTE: redisn_set_user should have been run before calling this function */

	group_list_tmp = *group_list = NULL;

	if (!inst->groupmemb_query ||
	    (inst->groupmemb_query[0] == 0))
		return 0;

	if (!radius_xlat(querystr, sizeof(querystr), inst->groupmemb_query, request, redisn_escape_func, inst)) {
		radlog_request(L_ERR, 0, request, "xlat \"%s\" failed.",
			       inst->groupmemb_query);
		return -1;
	}

	if (rlm_redisn_query(inst, redis_socket, querystr) < 0) {
		radlog_request(L_ERR, 0, request,
			       "database query error, %s",
			       querystr);
		return -1;
	}
	while (rlm_redisn_fetch_row(inst, redis_socket) == 0) {
		row = redis_socket->row;
		if (row == NULL)
			break;
		if (row[0] == NULL){
			RDEBUG("row[0] returned NULL");
			(inst->redisn_finish_query)(inst, redis_socket);
			redisn_grouplist_free(group_list);
			return -1;
		}
		if (*group_list == NULL) {
			*group_list = rad_malloc(sizeof(REDISN_GROUPLIST));
			group_list_tmp = *group_list;
		} else {
			rad_assert(group_list_tmp != NULL);
			group_list_tmp->next = rad_malloc(sizeof(REDISN_GROUPLIST));
			group_list_tmp = group_list_tmp->next;
		}
		group_list_tmp->next = NULL;
		DEBUG("redisn: redisn_get_grouplist: got groupname: %s\n",row[0]);
		strlcpy(group_list_tmp->groupname, row[0], MAX_STRING_LEN);
	}

	(inst->redisn_finish_query)(inst, redis_socket);

	return num_groups;
}


/*
 * redisn groupcmp function. That way we can do group comparisons (in the users file for example)
 * with the group memberships reciding in redisn
 * The group membership query should only return one element which is the username. The returned
 * username will then be checked with the passed check string.
 */

static int redisn_groupcmp(void *instance, REQUEST *request, VALUE_PAIR *request_vp, VALUE_PAIR *check,
			VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	REDISSOCK *redis_socket;
	REDIS_INST *inst = instance;
	char redisnusername[MAX_STRING_LEN];
	REDISN_GROUPLIST *group_list, *group_list_tmp;

	check_pairs = check_pairs;
	reply_pairs = reply_pairs;
	request_vp = request_vp;

	RDEBUG("redisn_groupcmp");
	if (!check || !check->vp_strvalue || !check->length){
		RDEBUG("redisn_groupcmp: Illegal group name");
		return 1;
	}
	if (!request){
		RDEBUG("redisn_groupcmp: NULL request");
		return 1;
	}
	/*
	 * Set, escape, and check the user attr here
	 */
	if (redisn_set_user(inst, request, redisnusername, NULL) < 0)
		return 1;

	/*
	 *	Get a socket for this lookup
	 */
	redis_socket = redisn_get_socket(inst);
	if (redis_socket == NULL) {
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_REDIS_USER_NAME, 0, TAG_ANY);
		return 1;
	}

	/*
	 *	Get the list of groups this user is a member of
	 */
	if (redisn_get_grouplist(inst, redis_socket, request, &group_list) < 0) {
		radlog_request(L_ERR, 0, request,
			       "Error getting group membership");
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_REDIS_USER_NAME, 0, TAG_ANY);
		redisn_release_socket(inst, redis_socket);
		return 1;
	}

	for (group_list_tmp = group_list; group_list_tmp != NULL; group_list_tmp = group_list_tmp->next) {
		if (strcmp(group_list_tmp->groupname, check->vp_strvalue) == 0){
			RDEBUG("redisn_groupcmp finished: User is a member of group %s",
			       check->vp_strvalue);
			/* Free the grouplist */
			redisn_grouplist_free(&group_list);
			/* Remove the username we (maybe) added above */
			pairdelete(&request->packet->vps, PW_REDIS_USER_NAME, 0, TAG_ANY);
			redisn_release_socket(inst, redis_socket);
			return 0;
		}
	}

	/* Free the grouplist */
	redisn_grouplist_free(&group_list);
	/* Remove the username we (maybe) added above */
	pairdelete(&request->packet->vps, PW_REDIS_USER_NAME, 0, TAG_ANY);
	redisn_release_socket(inst,redis_socket);

	RDEBUG("redisn_groupcmp finished: User is NOT a member of group %s",
	       check->vp_strvalue);

	return 1;
}



static int rlm_redisn_process_groups(REDIS_INST *inst, REQUEST *request, REDISSOCK *redis_socket, int *dofallthrough)
{
	VALUE_PAIR *check_tmp = NULL;
	VALUE_PAIR *reply_tmp = NULL;
	REDISN_GROUPLIST *group_list, *group_list_tmp;
	VALUE_PAIR *redisn_group = NULL;
	char    querystr[MAX_QUERY_LEN];
	int found = 0;
	int rows;

	/*
	 *	Get the list of groups this user is a member of
	 */
	if (redisn_get_grouplist(inst, redis_socket, request, &group_list) < 0) {
		radlog_request(L_ERR, 0, request, "Error retrieving group list");
		return -1;
	}

	for (group_list_tmp = group_list; group_list_tmp != NULL && *dofallthrough != 0; group_list_tmp = group_list_tmp->next) {
		/*
		 *	Add the Redis-Group attribute to the request list so we know
		 *	which group we're retrieving attributes for
		 */
	  DEBUG("rlm_redisn_process_groups: group_list_tmp->groupname: %s\n",
		group_list_tmp->groupname);
		redisn_group = pairmake("Redis-Group", group_list_tmp->groupname, T_OP_EQ);
		if (!redisn_group) {
			radlog_request(L_ERR, 0, request,
				       "Error creating Redis-Group attribute");
			redisn_grouplist_free(&group_list);
			return -1;
		}
		pairadd(&request->packet->vps, redisn_group);
		if (!radius_xlat(querystr, sizeof(querystr), inst->authorize_group_check_query, request, redisn_escape_func, inst)) {
			radlog_request(L_ERR, 0, request,
				       "Error generating query; rejecting user");
			/* Remove the grouup we added above */
			pairdelete(&request->packet->vps, PW_REDIS_GROUP, 0, TAG_ANY);
			redisn_grouplist_free(&group_list);
			return -1;
		}
		rows = redisn_getvpdata(inst, redis_socket, &check_tmp, querystr);
		if (rows < 0) {
			radlog_request(L_ERR, 0, request, "Error retrieving check pairs for group %s",
			       group_list_tmp->groupname);
			/* Remove the grouup we added above */
			pairdelete(&request->packet->vps, PW_REDIS_GROUP, 0, TAG_ANY);
			pairfree(&check_tmp);
			redisn_grouplist_free(&group_list);
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
				if (!radius_xlat(querystr, sizeof(querystr), inst->authorize_group_reply_query, request, redisn_escape_func, inst)) {
					radlog_request(L_ERR, 0, request, "Error generating query; rejecting user");
					/* Remove the grouup we added above */
					pairdelete(&request->packet->vps, PW_REDIS_GROUP, 0, TAG_ANY);
					pairfree(&check_tmp);
					redisn_grouplist_free(&group_list);
					return -1;
				}
				if (redisn_getvpdata(inst, redis_socket, &reply_tmp, querystr) < 0) {
					radlog_request(L_ERR, 0, request, "Error retrieving reply pairs for group %s",
					       group_list_tmp->groupname);
					/* Remove the grouup we added above */
					pairdelete(&request->packet->vps, PW_REDIS_GROUP, 0, TAG_ANY);
					pairfree(&check_tmp);
					pairfree(&reply_tmp);
					redisn_grouplist_free(&group_list);
					return -1;
				}
				*dofallthrough = fallthrough(reply_tmp);
				DEBUG("rlm_redisn (%s) %d: *dofallthrough: %d",
				      inst->xlat_name,
				      __LINE__,*dofallthrough);
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
			if (!radius_xlat(querystr, sizeof(querystr), inst->authorize_group_reply_query, request, redisn_escape_func, inst)) {
				radlog_request(L_ERR, 0, request, "Error generating query; rejecting user");
				/* Remove the grouup we added above */
				pairdelete(&request->packet->vps, PW_REDIS_GROUP, 0, TAG_ANY);
				pairfree(&check_tmp);
				redisn_grouplist_free(&group_list);
				return -1;
			}
			DEBUG("rlm_redisn %d: PROCESSSGROUP",__LINE__);
			if (redisn_getvpdata(inst, redis_socket, &reply_tmp, querystr) < 0) {
				radlog_request(L_ERR, 0, request, "Error retrieving reply pairs for group %s",
				       group_list_tmp->groupname);
				/* Remove the grouup we added above */
				pairdelete(&request->packet->vps, PW_REDIS_GROUP, 0, TAG_ANY);
				pairfree(&check_tmp);
				pairfree(&reply_tmp);
				redisn_grouplist_free(&group_list);
				return -1;
			}
			*dofallthrough = fallthrough(reply_tmp);
			DEBUG("rlm_redisn (%s) %d: *dofallthrough: %d",
			      inst->xlat_name,
			      __LINE__,*dofallthrough);
			pairxlatmove(request, &request->reply->vps, &reply_tmp);
			pairxlatmove(request, &request->config_items, &check_tmp);
		}

		/*
		 * Delete the Redis-Group we added above
		 * And clear out the pairlists
		 */
		pairdelete(&request->packet->vps, PW_REDIS_GROUP, 0, TAG_ANY);
		pairfree(&check_tmp);
		pairfree(&reply_tmp);
	}

	redisn_grouplist_free(&group_list);
	return found;
}


static int rlm_redisn_detach(void *instance)
{
	REDIS_INST *inst = instance;
	paircompare_unregister(PW_REDIS_GROUP, redisn_groupcmp);

	int i;
	
	if (inst->redisnpool) {
	  redisn_poolfree(inst);
	}

	if (inst->xlat_name) {
	  xlat_unregister(inst->xlat_name,(RAD_XLAT_FUNC)redisn_xlat, instance);
	  free(inst->xlat_name);
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
	  p = (char **) (((char *)inst) + module_config[i].offset);
	  if (!*p) { /* nothing allocated */
	    continue;
	  }
	  free(*p);
	  *p = NULL;
	}
	/*
	 *	Catch multiple instances of the module.
	 */
	if (allowed_chars == inst->allowed_chars) {
	  allowed_chars = NULL;
	}

	if (inst->servers_count>0) {
	  if (inst->server_names) {
	    for(i=0;i<inst->servers_count;i++) {
	      if (inst->server_names[i])
		free(inst->server_names[i]);
	      if (inst->server_passwords[i])
		free(inst->server_passwords[i]);
	    }
	    free(inst->server_names);
	  }
	  if (inst->server_ports)
	    free(inst->server_ports);
	  if (inst->server_dbs)
	    free(inst->server_dbs);
	  if (inst->server_passwords)
	    free(inst->server_passwords);
	  if (inst->server_connect_afters)
	    free(inst->server_connect_afters);
	}	  
	
	free(inst);

	return 0;
}

static int explode_servers(REDIS_INST *inst)
{
  DEBUG("inst->redisn_servers=%s",inst->redisn_servers);
  if (inst->redisn_servers==NULL
      || inst->redisn_servers[0]=='\0') {
    radlog(L_CONS | L_ERR, "rlm_redisn (%s): Bad server",
	   inst->xlat_name);
    return -1;
  } 
  else {
    inst->servers_count=redisn_split_string(&inst->server_names,inst->redisn_servers,',',0);
    DEBUG("inst->servers_count=%d\n",inst->servers_count);
    if (inst->servers_count==0) {
      radlog(L_CONS | L_ERR, "rlm_redisn (%s): Bad server",
	     inst->xlat_name);
      return -1;
    }
    else {
      inst->server_ports=(int*)rad_malloc(inst->servers_count*sizeof(int));
      inst->server_passwords=(char**)rad_malloc(inst->servers_count*sizeof(char*));      
      inst->server_dbs=(int*)rad_malloc(inst->servers_count*sizeof(int));
      inst->server_connect_afters=(time_t*)rad_malloc(inst->servers_count*sizeof(time_t));
      int i=0;
      //format: [[DbId][:Password]]@]ServerName_or_IP[/Port],
      for(i=0;i<inst->servers_count;i++) {
	char* server=inst->server_names[i];
	DEBUG("server string #%d: %s\n",i,server);
	char* name_pos=NULL;
	char* port_pos=NULL;
	inst->server_ports[i]=0;
	inst->server_passwords[i]=NULL;
	inst->server_dbs[i]=0;
	inst->server_connect_afters[i]=0;
	name_pos=strchr(server,'@');
	DEBUG("server #%d: name=%s\n",i,name_pos);
	if (name_pos==NULL) {
	  name_pos=server;	  
	}
	else {
	  char* password_pos=strchr(server,':');
	  DEBUG("server #%d: pwd pos=%s\n",i,password_pos);
	  if (password_pos!=NULL &&
	      password_pos<name_pos) {
	    inst->server_passwords[i]=rad_malloc((name_pos-password_pos)*sizeof(char));
	    strncpy(inst->server_passwords[i],password_pos+1,name_pos-password_pos);
	    inst->server_passwords[i][name_pos-password_pos-1]='\0';
	  }
	  inst->server_dbs[i]=atoi(server);
	  name_pos++;//skip '@'
	}
	port_pos=strchr(name_pos,'/');
	DEBUG("server #%d: port_pos=%s\n",i,port_pos);
	if (port_pos==NULL) {
	  inst->server_ports[i]=6379;
	  memmove(inst->server_names[i],name_pos,strlen(name_pos)+1);
	}
	else {
	  inst->server_ports[i]=atoi(port_pos+1);
	  memmove(inst->server_names[i],name_pos,port_pos-name_pos);	  
	  inst->server_names[i][port_pos-name_pos]='\0';
	}
	if (inst->server_ports[i]<=0) {
	  radlog(L_CONS | L_ERR, "rlm_redisn (%s): Bad server #%d",
		 inst->xlat_name,(i+1));
	  return -1;
	}
	DEBUG("rlm_redisn (%s): server #%d: %d:%s@%s/%d\n",
	      inst->xlat_name,
	      i,
	      inst->server_dbs[i],
	      (inst->server_passwords[i] ? inst->server_passwords[i] : ""),
	      inst->server_names[i],
	      inst->server_ports[i]);
      }
    }
  }
  return 0;
}

static int rlm_redisn_instantiate(CONF_SECTION * conf, void **instance)
{
  static size_t query2Queries[]=
    { offsetof(REDIS_INST,accounting_on_query),
      offsetof(REDIS_INST,accounting_on_queries),
      offsetof(REDIS_INST,accounting_off_query),
      offsetof(REDIS_INST,accounting_off_queries),
      offsetof(REDIS_INST,accounting_update_query),
      offsetof(REDIS_INST,accounting_update_queries),
      offsetof(REDIS_INST,accounting_start_query),
      offsetof(REDIS_INST,accounting_start_queries),
      offsetof(REDIS_INST,accounting_stop_query),
      offsetof(REDIS_INST,accounting_stop_queries),
      0
    };

	REDIS_INST *inst;
	const char *xlat_name;

	inst = rad_malloc(sizeof(REDIS_INST));
	memset(inst, 0, sizeof(REDIS_INST));

	/*
	 *	Export these methods, too.  This avoids RTDL_GLOBAL.
	 */
	inst->redisn_set_user = redisn_set_user;
	inst->redisn_get_socket = redisn_get_socket;
	inst->redisn_release_socket = redisn_release_socket;
	inst->redisn_escape_func = redisn_escape_func;
	inst->redisn_query = rlm_redisn_query;
	inst->redisn_finish_query = rlm_redisn_finish_query;
	inst->redisn_fetch_row = rlm_redisn_fetch_row;

	/*
	 * If the configuration parameters can't be parsed, then
	 * fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		rlm_redisn_detach(inst);
		return -1;
	}
DEBUG("rlm_redisn (%s): vp_separator=%s\n",inst->xlat_name,inst->vp_separator);
	if (inst->vp_separator==NULL || 
	    inst->vp_separator[0]=='\0') {
	  radlog(L_CONS | L_ERR, "rlm_redisn (%s): Bad vp_separator",
		 inst->xlat_name);
	  free(inst);
	  return -1;
	}
	if (inst->vp_separator[0]=='0'
	    && inst->vp_separator[1]=='x') {
	  long int sep=strtol(inst->vp_separator+2,NULL,16);
	  if (sep<=0
	      || sep>255) {
	    radlog(L_CONS | L_ERR, "rlm_redisn (%s): Bad vp_separator",
		   inst->xlat_name);
	    free(inst);
	    return -1;
	    }
	  else {
	    //we have space as len is at least 2
	    inst->vp_separator[0]=(char)sep;
	    inst->vp_separator[1]=0;
	  }
	}
	else if (inst->vp_separator[1]!='\0') {
	  radlog(L_CONS | L_ERR, "rlm_redisn (%s): Bad vp_separator",
		 inst->xlat_name);
	  free(inst);
	  return -1;
	}

	if (explode_servers(inst)!=0){
	  free(inst);
	  return -1;
	}

	{
	  int q=0;
	  while(query2Queries[q]>0) {
	    DEBUG("rlm_redisn (%s): query #%d\n",inst->xlat_name,q);
	      char **queryPtr = (char **) (((char *)inst) + query2Queries[q]);
	      char ***queriesPtr = (char ***) (((char *)inst) + query2Queries[q+1]);
	      if (*queryPtr &&
		  **queryPtr!='\0') {
		DEBUG("rlm_redisn (%s): query #%d: %s\n",inst->xlat_name,q,*queryPtr);
		redisn_split_string(queriesPtr,*queryPtr,'\n',1);		
		DEBUG("rlm_redisn (%s): query #%d: q0=%s\n",inst->xlat_name,q,*queriesPtr[0]);
	      }
	      q+=2;
	    };	  
	}
	

	xlat_name = cf_section_name2(conf);
	if (xlat_name == NULL) {
		xlat_name = cf_section_name1(conf);
	} else {
		char *group_name;
		DICT_ATTR *dattr;
		ATTR_FLAGS flags;

		/*
		 * Allocate room for <instance>-REDISN-Group
		 */
		group_name = rad_malloc((strlen(xlat_name) + 1 + 11) * sizeof(char));
		sprintf(group_name,"%s-REDISN-Group",xlat_name);
		DEBUG("rlm_redisn Creating new attribute %s",group_name);

		memset(&flags, 0, sizeof(flags));
		dict_addattr(group_name, 0, PW_TYPE_STRING, -1, flags);
		dattr = dict_attrbyname(group_name);
		if (dattr == NULL){
			radlog(L_ERR, "rlm_redisn: Failed to create attribute %s",group_name);
			free(group_name);
			free(inst);	/* FIXME: detach */
			return -1;
		}

		if (inst->groupmemb_query && 
		    inst->groupmemb_query[0]) {
			DEBUG("rlm_redisn: Registering redisn_groupcmp for %s",group_name);
			paircompare_register(dattr->attr, PW_USER_NAME, redisn_groupcmp, inst);
		}

		free(group_name);
	}
	if (xlat_name){
		inst->xlat_name = strdup(xlat_name);
		xlat_register(xlat_name, (RAD_XLAT_FUNC)redisn_xlat, inst);
	}

	if (inst->num_redisn_socks > MAX_REDISN_SOCKS) {
		radlog(L_ERR, "rlm_redisn (%s): redisn_instantiate: number of redis_sockets cannot exceed MAX_REDISN_SOCKS, %d",
		       inst->xlat_name, MAX_REDISN_SOCKS);
		rlm_redisn_detach(inst);
		return -1;
	}

	radlog(L_INFO, "rlm_redisn (%s): Attempting to connect to servers %s",
	       inst->xlat_name, 
	       inst->redisn_servers);

	if (redisn_init_socketpool(inst) < 0) {
		rlm_redisn_detach(inst);
		return -1;
	}

	if (inst->groupmemb_query && 
	    inst->groupmemb_query[0]) {
		paircompare_register(PW_REDIS_GROUP, PW_USER_NAME, redisn_groupcmp, inst);
	}

	if (inst->do_clients){
		if (generate_redisn_clients(inst) == -1){
			radlog(L_ERR, "Failed to load clients from REDISN.");
			rlm_redisn_detach(inst);
			return -1;
		}
	}
	allowed_chars = inst->allowed_chars;

	*instance = inst;

	return RLM_MODULE_OK;
}


static rlm_rcode_t rlm_redisn_authorize(void *instance, REQUEST * request)
{
	VALUE_PAIR *check_tmp = NULL;
	VALUE_PAIR *reply_tmp = NULL;
	VALUE_PAIR *user_profile = NULL;
	int     found = 0;
	int	dofallthrough = 1;
	int	rows;
	REDISSOCK *redis_socket;
	REDIS_INST *inst = instance;
	char    querystr[MAX_QUERY_LEN];
	char	redisnusername[MAX_STRING_LEN];
	/*
	 * the profile username is used as the redisnusername during
	 * profile checking so that we don't overwrite the orignal
	 * redisnusername string
	 */
	char   profileusername[MAX_STRING_LEN];

	/*
	 * Set, escape, and check the user attr here
	 */
	if (redisn_set_user(inst, request, redisnusername, NULL) < 0)
		return RLM_MODULE_FAIL;


	/*
	 * reserve a socket
	 */
	redis_socket = redisn_get_socket(inst);
	if (redis_socket == NULL) {
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_REDIS_USER_NAME, 0, TAG_ANY);
		return RLM_MODULE_FAIL;
	}


	/*
	 *  After this point, ALL 'return's MUST release the REDISN socket!
	 */

	/*
	 * Alright, start by getting the specific entry for the user
	 */
	if (!radius_xlat(querystr, sizeof(querystr), inst->authorize_check_query, request, redisn_escape_func, inst)) {
		radlog_request(L_ERR, 0, request, "Error generating query; rejecting user");
		redisn_release_socket(inst, redis_socket);
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_REDIS_USER_NAME, 0, TAG_ANY);
		return RLM_MODULE_FAIL;
	}
	rows = redisn_getvpdata(inst, redis_socket, &check_tmp, querystr);
	if (rows < 0) {
		radlog_request(L_ERR, 0, request, "REDISN query error; rejecting user");
		redisn_release_socket(inst, redis_socket);
		/* Remove the username we (maybe) added above */
		pairdelete(&request->packet->vps, PW_REDIS_USER_NAME, 0, TAG_ANY);
		pairfree(&check_tmp);
		return RLM_MODULE_FAIL;
	} else if (rows > 0) {
		/*
		 *	Only do this if *some* check pairs were returned
		 */
		if (paircompare(request, request->packet->vps, check_tmp, &request->reply->vps) == 0) {
			found = 1;
			RDEBUG2("User found in radcheck table");

			if (inst->authorize_reply_query &&
			    *inst->authorize_reply_query) {

			/*
			 *	Now get the reply pairs since the paircompare matched
			 */
			if (!radius_xlat(querystr, sizeof(querystr), inst->authorize_reply_query, request, redisn_escape_func, inst)) {
				radlog_request(L_ERR, 0, request, "Error generating query; rejecting user");
				redisn_release_socket(inst, redis_socket);
				/* Remove the username we (maybe) added above */
				pairdelete(&request->packet->vps, PW_REDIS_USER_NAME, 0, TAG_ANY);
				pairfree(&check_tmp);
				return RLM_MODULE_FAIL;
			}
			if (redisn_getvpdata(inst, redis_socket, &reply_tmp, querystr) < 0) {
				radlog_request(L_ERR, 0, request, "REDISN query error; rejecting user");
				redisn_release_socket(inst, redis_socket);
				/* Remove the username we (maybe) added above */
				pairdelete(&request->packet->vps, PW_REDIS_USER_NAME, 0, TAG_ANY);
				pairfree(&check_tmp);
				pairfree(&reply_tmp);
				return RLM_MODULE_FAIL;
			}

			if (!inst->read_groups) {
				dofallthrough = fallthrough(reply_tmp);
				DEBUG("rlm_redisn (%s) %d: dofallthrough: %d",
				      inst->xlat_name,
				      __LINE__,dofallthrough);
			}
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
	DEBUG("rlm_redisn (%s) %d: dofallthrough: %d",
	      inst->xlat_name,
	      __LINE__,dofallthrough);
	if (dofallthrough) {
		rows = rlm_redisn_process_groups(inst, request, redis_socket, &dofallthrough);
		if (rows < 0) {
			radlog_request(L_ERR, 0, request, "Error processing groups; rejecting user");
			redisn_release_socket(inst, redis_socket);
			/* Remove the username we (maybe) added above */
			pairdelete(&request->packet->vps, PW_REDIS_USER_NAME, 0, TAG_ANY);
			return RLM_MODULE_FAIL;
		} else if (rows > 0) {
			found = 1;
		}
	}

	/*
	 *	repeat the above process with the default profile or User-Profile
	 */
	DEBUG("rlm_redisn (%s) %d: dofallthrough: %d",
	      inst->xlat_name,
	      __LINE__,dofallthrough);
	if (dofallthrough) {
		int profile_found = 0;
		/*
	 	* Check for a default_profile or for a User-Profile.
		*/
		user_profile = pairfind(request->config_items, PW_USER_PROFILE, 0, TAG_ANY);
		if (inst->default_profile[0] != 0 || user_profile != NULL){
			char *profile = inst->default_profile;

			if (user_profile != NULL)
				profile = user_profile->vp_strvalue;
			if (profile && strlen(profile)){
				RDEBUG("Checking profile %s", profile);
				if (redisn_set_user(inst, request, profileusername, profile) < 0) {
					radlog_request(L_ERR, 0, request, "Error setting profile; rejecting user");
					redisn_release_socket(inst, redis_socket);
					/* Remove the username we (maybe) added above */
					pairdelete(&request->packet->vps, PW_REDIS_USER_NAME, 0, TAG_ANY);
					return RLM_MODULE_FAIL;
				} else {
					profile_found = 1;
				}
			}
		}

		if (profile_found) {
			rows = rlm_redisn_process_groups(inst, request, redis_socket, &dofallthrough);
			DEBUG("rlm_redisn (%s) %d: dofallthrough: %d",
			      inst->xlat_name,
			      __LINE__,dofallthrough);
			if (rows < 0) {
				radlog_request(L_ERR, 0, request, "Error processing profile groups; rejecting user");
				redisn_release_socket(inst, redis_socket);
				/* Remove the username we (maybe) added above */
				pairdelete(&request->packet->vps, PW_REDIS_USER_NAME, 0, TAG_ANY);
				return RLM_MODULE_FAIL;
			} else if (rows > 0) {
				found = 1;
			}
		}
	}

	/* Remove the username we (maybe) added above */
	pairdelete(&request->packet->vps, PW_REDIS_USER_NAME, 0, TAG_ANY);
	redisn_release_socket(inst, redis_socket);

	if (!found) {
		RDEBUG("User %s not found", redisnusername);
		return RLM_MODULE_NOTFOUND;
	} else {
		return RLM_MODULE_OK;
	}
}

/*
 *	Accounting: save the account data to our redisn table
 */
static rlm_rcode_t rlm_redisn_accounting(void *instance, REQUEST * request) {

	REDISSOCK *redis_socket = NULL;
	VALUE_PAIR *pair;
	REDIS_INST *inst = instance;
	int	ret = RLM_MODULE_OK;
	int     acctstatustype = 0;
	char    logstr[MAX_QUERY_LEN];
	char	redisnusername[MAX_STRING_LEN];
	char**  queries=NULL;


	/*
	 * Find the Acct Status Type
	 */
	if ((pair = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE, 0, TAG_ANY)) != NULL) {
		acctstatustype = pair->vp_integer;
	} else {
		radius_xlat(logstr, sizeof(logstr), "packet has no accounting status type. [user '%{User-Name}', nas '%{NAS-IP-Address}']", request, NULL, inst);
		radlog_request(L_ERR, 0, request, "%s", logstr);
		return RLM_MODULE_INVALID;
	}

	switch (acctstatustype) {
			/*
			 * The Terminal server informed us that it was rebooted
			 * STOP all records from this NAS
			 */
		case PW_STATUS_ACCOUNTING_ON:
		  RDEBUG("Received Acct On packet");
		  queries=inst->accounting_on_queries;
		  break;
		case PW_STATUS_ACCOUNTING_OFF:
		  RDEBUG("Received Acct Off packet");
		  queries=inst->accounting_off_queries;
		  break;
		case PW_STATUS_START:
		  RDEBUG("Received Acct Start packet");
		  queries=inst->accounting_start_queries;
		  break;
		case PW_STATUS_STOP:
		  RDEBUG("Received Acct Stop packet");
#if 0 //#ifdef CISCO_ACCOUNTING_HACK
		  {
		    /*
		     * If stop but zero session length AND no previous
		     * session found, drop it as in invalid packet
		     * This is to fix CISCO's aaa from filling our
		     * table with bogus crap
		   */
		    int     acctsessiontime = 0;
		    if ((pair = pairfind(request->packet->vps, PW_ACCT_SESSION_TIME, 0, TAG_ANY)) != NULL)
		      acctsessiontime = pair->vp_integer;
		    
		    if (acctsessiontime <= 0) {
		      radius_xlat(logstr, sizeof(logstr), "stop packet with zero session length. [user '%{User-Name}', nas '%{NAS-IP-Address}']", request, NULL, inst);
		      radlog_request(L_DBG, 0, request, "%s", logstr);
		      redisn_release_socket(inst, redis_socket);
		      return RLM_MODULE_NOOP;
		    }
		  }
#endif

		  queries=inst->accounting_stop_queries;
		  break;
		case PW_STATUS_ALIVE:
		  RDEBUG("Received Acct Alive packet");
		  queries=inst->accounting_update_queries;
		  break;
		  /*
		   *	Anything else is ignored.
		   */
	        default:
		  RDEBUG("Unsupported Acct-Status-Type = %d",
			 acctstatustype);
		  return RLM_MODULE_NOOP;
		  break;
	}
	if (queries==NULL ||*queries==NULL)
	  ret=RLM_MODULE_NOOP;
	else
	  {
	    char    querystr[MAX_QUERY_LEN];
	    redis_socket = redisn_get_socket(inst);
	    if (redis_socket == NULL)
	      return(RLM_MODULE_FAIL);

	    redisn_set_user(inst, request, redisnusername, NULL);

	    while(*queries) {
	      char* query=*queries;		
	      memset(querystr, 0, MAX_QUERY_LEN);
	      radius_xlat(querystr, sizeof(querystr), query, request, redisn_escape_func, inst);
	      query_log(request, inst, querystr);
	      
	      if (rlm_redisn_query(inst, redis_socket, querystr)) {
		radlog_request(L_ERR, 0, request, "Accounting query failed: %s",
			       querystr);
		ret = RLM_MODULE_FAIL;
	      }

	      (inst->redisn_finish_query)(inst, redis_socket);
	      queries++;
	    }
	    redisn_release_socket(inst, redis_socket);
	  }

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

static rlm_rcode_t rlm_redisn_checksimul(void *instance, REQUEST * request) {
	REDISSOCK 	*redis_socket;
	REDIS_INST	*inst = instance;
	REDIS_ROW	row;
	char		querystr[MAX_QUERY_LEN];
	char		redisnusername[MAX_STRING_LEN];
	int		check = 0;
        uint32_t        ipno = 0;
        char            *call_num = NULL;
	VALUE_PAIR      *vp;
	int		ret;
	uint32_t	nas_addr = 0;
	int		nas_port = 0;

	/* If simul_count_query is not defined, we don't do any checking */
	if (!inst->simul_count_query ||
	    (inst->simul_count_query[0] == 0)) {
		return RLM_MODULE_NOOP;
	}

	if((request->username == NULL) || (request->username->length == 0)) {
		radlog_request(L_ERR, 0, request, "Zero Length username not permitted\n");
		return RLM_MODULE_INVALID;
	}


	if(redisn_set_user(inst, request, redisnusername, NULL) < 0)
		return RLM_MODULE_FAIL;

	radius_xlat(querystr, sizeof(querystr), inst->simul_count_query, request, redisn_escape_func, inst);

	/* initialize the redisn socket */
	redis_socket = redisn_get_socket(inst);
	if(redis_socket == NULL)
		return RLM_MODULE_FAIL;

	if(rlm_redisn_query(inst, redis_socket, querystr)) {
		radlog(L_ERR, "rlm_redisn (%s) redisn_checksimul: Database query failed", inst->xlat_name);
		redisn_release_socket(inst, redis_socket);
		return RLM_MODULE_FAIL;
	}

	ret = rlm_redisn_fetch_row(inst, redis_socket);

	if (ret != 0) {
		(inst->redisn_finish_query)(inst, redis_socket);
		redisn_release_socket(inst, redis_socket);
		return RLM_MODULE_FAIL;
	}

	row = redis_socket->row;
	if (row == NULL) {
		(inst->redisn_finish_query)(inst, redis_socket);
		redisn_release_socket(inst, redis_socket);
		return RLM_MODULE_FAIL;
	}

	request->simul_count = atoi(row[0]);
	(inst->redisn_finish_query)(inst, redis_socket);

	if(request->simul_count < request->simul_max) {
		redisn_release_socket(inst, redis_socket);
		return RLM_MODULE_OK;
	}

	/*
	 *	Looks like too many sessions, so let's start verifying
	 *	them, unless told to rely on count query only.
	 */
	if (!inst->simul_verify_query ||
	    (inst->simul_verify_query[0] == '\0')) {
		redisn_release_socket(inst, redis_socket);
		return RLM_MODULE_OK;
	}

	radius_xlat(querystr, sizeof(querystr), inst->simul_verify_query, request, redisn_escape_func, inst);
	if(rlm_redisn_query(inst, redis_socket, querystr)) {
		radlog_request(L_ERR, 0, request, "Database query error");
		redisn_release_socket(inst, redis_socket);
		return RLM_MODULE_FAIL;
	}

        /*
         *      Setup some stuff, like for MPP detection.
         */
	request->simul_count = 0;

        if ((vp = pairfind(request->packet->vps, PW_FRAMED_IP_ADDRESS, 0, TAG_ANY)) != NULL)
                ipno = vp->vp_ipaddr;
        if ((vp = pairfind(request->packet->vps, PW_CALLING_STATION_ID, 0, TAG_ANY)) != NULL)
                call_num = vp->vp_strvalue;


	while (rlm_redisn_fetch_row(inst, redis_socket) == 0) {
		row = redis_socket->row;
		if (row == NULL)
			break;
		if (!row[2]){
			(inst->redisn_finish_query)(inst, redis_socket);
			redisn_release_socket(inst, redis_socket);
			RDEBUG("Cannot zap stale entry. No username present in entry.", inst->xlat_name);
			return RLM_MODULE_FAIL;
		}
		if (!row[1]){
			(inst->redisn_finish_query)(inst, redis_socket);
			redisn_release_socket(inst, redis_socket);
			RDEBUG("Cannot zap stale entry. No session id in entry.", inst->xlat_name);
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
			if (inst->deletestalesessions == TRUE) {
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
			(inst->redisn_finish_query)(inst, redis_socket);
			redisn_release_socket(inst, redis_socket);
			radlog_request(L_ERR, 0, request, "Failed to check the terminal server for user '%s'.", row[2]);
			return RLM_MODULE_FAIL;
		}
	}

	(inst->redisn_finish_query)(inst, redis_socket);
	redisn_release_socket(inst, redis_socket);

	/*
	 *	The Auth module apparently looks at request->simul_count,
	 *	not the return value of this module when deciding to deny
	 *	a call for too many sessions.
	 */
	return RLM_MODULE_OK;
}

/*
 *	Execute postauth_query after authentication
 */
static rlm_rcode_t rlm_redisn_postauth(void *instance, REQUEST *request) {
	REDISSOCK 	*redis_socket = NULL;
	REDIS_INST	*inst = instance;
	char		querystr[MAX_QUERY_LEN];
	char		redisnusername[MAX_STRING_LEN];

	/* If postauth_query is not defined, we stop here */
	if (!inst->postauth_query ||
	    (inst->postauth_query[0] == '\0'))
		return RLM_MODULE_NOOP;

	if(redisn_set_user(inst, request, redisnusername, NULL) < 0)
		return RLM_MODULE_FAIL;

	/* Expand variables in the query */
	memset(querystr, 0, MAX_QUERY_LEN);
	radius_xlat(querystr, sizeof(querystr), inst->postauth_query,
		    request, redisn_escape_func, inst);
	query_log(request, inst, querystr);
	DEBUG2("rlm_redisn (%s) in redisn_postauth: query is %s",
	       inst->xlat_name, querystr);

	/* Initialize the redisn socket */
	redis_socket = redisn_get_socket(inst);
	if (redis_socket == NULL)
		return RLM_MODULE_FAIL;

	/* Process the query */
	if (rlm_redisn_query(inst, redis_socket, querystr)) {
		radlog(L_ERR, "rlm_redisn (%s) in redisn_postauth: Database query error - %s",
		       inst->xlat_name,
		       querystr);
		redisn_release_socket(inst, redis_socket);
		return RLM_MODULE_FAIL;
	}
	(inst->redisn_finish_query)(inst, redis_socket);

	redisn_release_socket(inst, redis_socket);
	return RLM_MODULE_OK;
}

/* globally exported name */
module_t rlm_redisn = {
	RLM_MODULE_INIT,
	"REDISN",
	RLM_TYPE_THREAD_SAFE,	/* type: reserved */
	rlm_redisn_instantiate,	/* instantiation */
	rlm_redisn_detach,		/* detach */
	{
		NULL,			/* authentication */
		rlm_redisn_authorize,	/* authorization */
		NULL,			/* preaccounting */
		rlm_redisn_accounting,	/* accounting */
		rlm_redisn_checksimul,	/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		rlm_redisn_postauth	/* post-auth */
	},
};
