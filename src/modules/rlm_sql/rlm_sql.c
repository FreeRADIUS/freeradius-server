/***************************************************************************
*  rlm_sql.c                          rlm_sql - FreeRADIUS SQL Module      *
*                                                                          *
*      Main SQL module file. Most ICRADIUS code is located in sql.c        *
*      $Id$
*                                                                          *
*                                     Mike Machado <mike@innercite.com>    *
***************************************************************************/
static const char rcsid[] = "$Id$";

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
#include "rlm_sql.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/***********************************************************************
 * start of main routines
 ***********************************************************************/

static int rlm_sql_init(int argc, char **argv) {

	if ((sql = malloc(sizeof(SQL))) == NULL) {
		log(L_ERR|L_CONS, "no memory");
		exit(1);
	}

	sql_init(0);
           
       return 0;
}

static int rlm_sql_detach(void) {

  return 0;
}


static int rlm_sql_authorize(REQUEST *request, VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs)
{
	int		nas_port = 0;
	VALUE_PAIR	*check_tmp = NULL;
	VALUE_PAIR	*reply_tmp = NULL;
	VALUE_PAIR	*tmp;
	int		found = 0;
	char		*name;
	SQLSOCK		*socket;
	
	name = request->username->strvalue;

       /*
        *      Check for valid input, zero length names not permitted
        */
       if (name[0] == 0) {
               log(L_ERR, "zero length username not permitted\n");
               return -1;
       }

	socket = sql_get_socket();

       /*
        *      Find the NAS port ID.
        */
       if ((tmp = pairfind(request->packet->vps, PW_NAS_PORT_ID)) != NULL)
               nas_port = tmp->lvalue;

       /*
        *      Find the entry for the user.
        */
       if ((found = sql_getvpdata(socket, sql->config->sql_authcheck_table, &check_tmp, name, PW_VP_USERDATA)) > 0) {
	       sql_getvpdata(socket, sql->config->sql_groupcheck_table, &check_tmp, name, PW_VP_GROUPDATA);
	       sql_getvpdata(socket, sql->config->sql_authreply_table, &reply_tmp, name, PW_VP_USERDATA);
	       sql_getvpdata(socket, sql->config->sql_groupreply_table, &reply_tmp, name, PW_VP_GROUPDATA);
       } else {
	       
	       int gcheck, greply;
	       gcheck = sql_getvpdata(socket, sql->config->sql_groupcheck_table, &check_tmp, "DEFAULT", PW_VP_GROUPDATA);
	       greply = sql_getvpdata(socket, sql->config->sql_groupreply_table, &reply_tmp, "DEFAULT", PW_VP_GROUPDATA);
	       if (gcheck && greply)
		       found = 1;
       }
       sql_release_socket(socket);
       
       if (!found) {
	       DEBUG2("User %s not found and DEFAULT not found", name);
	       return RLM_MODULE_OK;
       }
       
       if (paircmp(request->packet->vps, check_tmp, &reply_tmp) != 0) {
	       DEBUG2("Pairs do not match [%s]", name);
	       return RLM_MODULE_OK;
       }
       
       pairmove(reply_pairs, &reply_tmp);
       pairmove(check_pairs, &check_tmp);
       pairfree(reply_tmp);
       pairfree(check_tmp);
       
       
       /*
        *      Fix dynamic IP address if needed.
        */
       if ((tmp = pairfind(*reply_pairs, PW_ADD_PORT_TO_IP_ADDRESS)) != NULL){
               if (tmp->lvalue != 0) {
                       tmp = pairfind(*reply_pairs, PW_FRAMED_IP_ADDRESS);
                       if (tmp) {
                               /*
                                *      FIXME: This only works because IP
                                *      numbers are stored in host order
                                *      everywhere in this program.
                                */
                               tmp->lvalue += nas_port;
                       }
               }
               pairdelete(reply_pairs, PW_ADD_PORT_TO_IP_ADDRESS);
       }

	return RLM_MODULE_OK;
}

static int rlm_sql_authenticate(REQUEST *request) {
	
	VALUE_PAIR	*auth_pair;
	SQL_ROW		row;
	SQLSOCK		*socket;
	char		*querystr;
	char		escaped_user[AUTH_STRING_LEN*3];
	char		*user;
	const char	query[] = "SELECT Value FROM %s WHERE UserName = '%s' AND Attribute = 'Password'";
	
	user = request->username->strvalue;
	
	/*
	 *	Ensure that a password attribute exists.
	 */
	if ((request->password == NULL) ||
	    (request->password->length == 0) ||
	    (request->password->attribute != PW_PASSWORD)) {
		log(L_AUTH, "rlm_sql: Attribute \"Password\" is required for authentication.");
		return RLM_MODULE_REJECT;
	}
	
	sql_escape_string(escaped_user, user, strlen(user));
	
	/*
	 *	This should really be replaced with a static buffer...
	 */
	if ((querystr = malloc(strlen(escaped_user) +
			       strlen(sql->config->sql_authcheck_table) +
			       sizeof(query))) == NULL) {
                log(L_ERR|L_CONS, "no memory");
                exit(1);
        }
	
	sprintf(querystr, query, sql->config->sql_authcheck_table, escaped_user);
	socket = sql_get_socket();
	sql_select_query(socket, querystr);
	row = sql_fetch_row(socket);
	sql_finish_select_query(socket);
        free(querystr);
	
	if (strncmp(request->password->strvalue, row[0], request->password->length) != 0)
		return RLM_MODULE_REJECT;
	else
		return RLM_MODULE_OK;
}

/*
 *	Accounting: does nothing for now.
 */
static int rlm_sql_accounting(REQUEST *request) {

	return RLM_MODULE_OK;
}


/* globally exported name */
module_t rlm_sql = {
  "SQL",
  0,			/* type: reserved */
  rlm_sql_init,		/* initialization */
  rlm_sql_authorize,	/* authorization */
  rlm_sql_authenticate,	/* authentication */
  NULL,			/* preaccounting */
  rlm_sql_accounting,	/* accounting */
  rlm_sql_detach,	/* detach */
};
