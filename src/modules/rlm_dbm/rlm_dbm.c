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
 * @file rlm_dbm.c
 * @brief Authorize using ndbm database
 *
 * @copyright 2001 Koulik Andrei, Sandy Service
 * @copyright 2006 The FreeRADIUS server project
 */
#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#ifdef HAVE_NDBM_H
#include <ndbm.h>
#endif

#ifdef HAVE_GDBM_NDBM_H
#include <gdbm/ndbm.h>
#endif

#ifdef HAVE_GDBMNDBM_H
#include <gdbm-ndbm.h>
#endif

#include <fcntl.h>

#ifdef SANDY_MOD
#	include "sandymod.h"
#endif

#define MYDBM	DBM
#define get_user_content dbm_fetch

#define SM_JOIN_ATTR	1029

#ifdef SANDY_MOD
#	define SM_POOL_ATTR	510
#endif

typedef struct rlm_dbm_t {

#ifdef SANDY_MOD
	char	*dms_servers;
	char	*ducpd_servers;
#endif
	char	*userfile;
	int	findmod;
} rlm_dbm_t;

typedef struct user_entry {
	char * username;
	struct user_entry * next;
} SM_USER_ENTRY;


static const CONF_PARSER module_config[] = {
        { "usersfile",     PW_TYPE_STRING_PTR,offsetof(struct rlm_dbm_t,userfile),
		NULL, "/etc/uf" },
        { NULL, -1, 0, NULL, NULL }
};

static void sm_user_list_wipe (SM_USER_ENTRY **ue) {

	SM_USER_ENTRY * pue, *nue;

	if ( ! *ue ) return ;
	pue = *ue;

	while ( pue != NULL ) {
		nue = pue -> next;
		DEBUG2("Remove %s from user list", pue -> username);
		free(pue -> username);
		free(pue);
		pue = nue;
	}
	*ue = NULL;
}

/*
 * 	add username un to user list ue;
 * 	return 0 if user succefuly added
 * 	1 - if username already exists
 * 	-1 - error: no memmory
 */

static int sm_user_list_add(SM_USER_ENTRY **ue, const char *un) {

	while( *ue ) {
		if ( strcmp( (*ue) -> username, un) == 0 ) return 1;
		ue = & ((*ue) -> next);
	}
	*ue = malloc(sizeof(SM_USER_ENTRY));
	if ( !*ue ) return -1;
	(*ue)  -> username = strdup(un);
	DEBUG2("Add %s to user list", (*ue) -> username);
	(*ue)  -> next = NULL ;
	if ( ! (*ue) -> username ) {
		free(*ue);
		*ue = NULL;
		return -1;
	} else return 0;
}


enum {
   SMP_PATTERN,
   SMP_REPLY,
   SMP_ERROR
};


/******/

static int isfallthrough(VALUE_PAIR *vp) {
  VALUE_PAIR * tmp;

  tmp = pairfind(vp, PW_FALL_THROUGH, 0, TAG_ANY);
  return tmp ? tmp -> vp_integer : 1; /* if no  FALL_THROUGH - keep looking */
}

/* sm_parse_user
 *  find user, parse and return result
 * in-parameters:
 *  pdb	- ndbm handler
 *  username - user name from request
 *  request - pair originated from the nas
 *  mode - search mode SM_SM_ACCUM - accumulative search mode
 *  out-parameters:
 *  in-out:
 *  parsed_users - list of parsed user names for loop removal
 */

static int sm_parse_user(DBM *pdb, const char * username, REQUEST *req,
			 VALUE_PAIR * request, VALUE_PAIR **config,
			 VALUE_PAIR **reply, SM_USER_ENTRY **ulist)
{
   	datum 	k,d;
   	int		retcod, found = RLM_MODULE_NOTFOUND, res ;
   	VALUE_PAIR *vp = NULL,* tmp_config = NULL, *tmp_reply = NULL, *nu_reply = NULL;
   	VALUE_PAIR *join_attr;
   	char 	*ch,*beg;

   	int	parse_state = SMP_PATTERN;
	int     continue_search = 1;

   	/* check for loop */

   	DEBUG2("sm_parse_user.c: check for loops");

   	if ( (retcod = sm_user_list_add(ulist,username) ) ) {
   		if ( retcod < 0 ) radlog(L_ERR,"rlm_dbm: Couldn't allocate memory");
   			else radlog(L_ERR,"rlm_dbm: Invalid configuration: loop detected");
   		return RLM_MODULE_FAIL;
   	}

   	/* retrieve user content */
   	memcpy(&k.dptr, &username, sizeof(k.dptr));
   	k.dsize = strlen(username) + 1 ; /* username stored with '\0' */

   	d = dbm_fetch(pdb, k);
   	if ( d.dptr == NULL ) {
   		 DEBUG2("rlm_dbm: User <%s> not found in database\n",username);
   		 return RLM_MODULE_NOTFOUND;
   	}

   	ch = d.dptr;
   	ch [ d.dsize - 1 ] = '\0'; /* should be closed by 0 */

	DEBUG2("sm_parse_user: start parsing: user: %s", username);

   	/*  start parse content */
   	while ( parse_state != SMP_ERROR && *ch && continue_search ) {

   		beg = ch;

   		while( *ch && *ch != '\n') ch++ ;

		if ( *ch == '\n' ) { *ch = 0; ch++; }

		DEBUG2("parse buffer: <<%s>>\n",beg);

   		retcod = userparse(beg,&vp);
   		if ( retcod == T_OP_INVALID ) fr_perror("parse error ");

   	 	switch ( retcod ) {
   	 		case T_COMMA: break; /* continue parse the current list */
   	 		case T_EOL:	DEBUG2("rlm_dbm: recod parsed\n"); /* vp contains full pair list */
   	 				if ( parse_state == SMP_PATTERN ) { /* pattern line found */
   	 					DEBUG2("process pattern");
   	 					/* check pattern against request */
						if ( paircompare(req, request, vp, reply ) == 0 ) {
							DEBUG2("rlm_dbm: Pattern matched, look for request");
   	 						pairmove(&tmp_config, &vp);
   	 						pairfree(&vp);
   	 						parse_state = SMP_REPLY; /* look for reply */
   	 					} else  {
   	 						  /* skip reply */
   	 						DEBUG2("rlm_dbm: patern not matched, reply skiped");
   	 						pairfree(&vp);
   	 						while ( *ch && *ch !='\n' ) ch++;
   	 						if ( *ch == '\n' ) ch++;
   	 					}
   	 				} else { /* reply line found */
   	 					/* look for join-attribute */
   	 					DEBUG2("rlm_dbm: Reply found");
						join_attr = vp;
						while( (join_attr = pairfind(join_attr, SM_JOIN_ATTR, 0, TAG_ANY) ) != NULL ) {
   	 					 	DEBUG2("rlm_dbm: Proccess nested record: username %s",
   	 					 		(char *)join_attr->vp_strvalue);
   	 					 	/* res =  RLM_MODULE_NOTFOUND; */
   	 						res =  sm_parse_user(pdb, (char *)join_attr->vp_strvalue, req, request, &tmp_config,
   	 					 			&nu_reply, ulist);
							DEBUG("rlm_dbm: recived: %d\n",res);
							switch ( res ) {
								case RLM_MODULE_NOTFOUND:
								case RLM_MODULE_OK:
									break;
								default: /* seems error code */
									parse_state = SMP_ERROR;
									DEBUG2("rlm_dbm: Nested record error\n");
									break;
							}
							join_attr = join_attr -> next;
   	 					}
						pairdelete(&vp,SM_JOIN_ATTR, 0, TAG_ANY);
						if ( parse_state != SMP_ERROR ) {
							if ( ! isfallthrough(vp) ) {
							  continue_search = 0;
							  DEBUG2("rlm_dbm: Break search due Fall-Through = no");
							}
							pairmove(&vp,&nu_reply);
							pairfree(&nu_reply);
							pairmove(&tmp_reply,&vp);
							pairfree(&vp);
							parse_state = SMP_PATTERN;
							found = RLM_MODULE_OK;
						}
						pairfree(&vp);
						pairfree(&nu_reply);   	 				}
   	 				break;
   	 		default: 	/* we do not wait that !!!! */
   	 				parse_state = SMP_ERROR;
   	 				DEBUG2("rlm_dbm: Unknown token: %d\n",retcod);
   	 				break;
   	 	}

   	}
   	if ( parse_state == SMP_PATTERN  ) {
   		pairmove(config,&tmp_config);
		pairfree(&tmp_config);
   		pairmove(reply,&tmp_reply);
		pairfree(&tmp_reply);
    	} else {
   		pairfree(&tmp_config);
		pairfree(&tmp_reply);
		pairfree(&vp);
		DEBUG2("rlm_dbm: Bad final parse state: %d\n",parse_state);
   		found = RLM_MODULE_FAIL ;
   	}
   	pairfree(&vp);
	return found;
}

static int sm_postprocessor(VALUE_PAIR **reply UNUSED) {
	return 0;
}

static int rlm_dbm_instantiate(CONF_SECTION *conf, void **instance) {
	struct rlm_dbm_t *inst;

	inst = rad_malloc(sizeof(rlm_dbm_t));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

        if (cf_section_parse(conf, inst, module_config) < 0) {
                free(inst);
                return -1;
        }
	*instance = inst;
	return 0;
}
static rlm_rcode_t rlm_dbm_authorize(void *instance, REQUEST *request)
{
        VALUE_PAIR      *namepair;
        VALUE_PAIR      *request_pairs;
        VALUE_PAIR      *check_tmp = NULL;
        VALUE_PAIR      *reply_tmp = NULL;

        int             found = 0;
        const char      *name;
	SM_USER_ENTRY	*ulist = NULL;
	DBM		*pdb;

        struct rlm_dbm_t *inst = instance;

        VALUE_PAIR **check_pairs, **reply_pairs;

        request_pairs = request->packet->vps;
        check_pairs = &request->config_items;
        reply_pairs = &request->reply->vps;

        /*
         *      Grab the canonical user name.
         */
        namepair = request->username;
        name = namepair ? (char *) namepair->vp_strvalue : "NONE";

	DEBUG2("rlm_dbm: try open database file: %s\n",inst -> userfile);

	/* open database */
	if ( ( pdb = dbm_open(inst->userfile, O_RDONLY, 0600) ) != NULL ) {
		DEBUG("rlm_dbm: Call parse_user:\n");
		found = sm_parse_user(pdb, name, request, request_pairs, &check_tmp, &reply_tmp, &ulist);
	   	if ( found == RLM_MODULE_NOTFOUND ) {
		  sm_user_list_wipe(&ulist);
		  found = sm_parse_user(pdb, "DEFAULT", request, request_pairs, &check_tmp, &reply_tmp, &ulist);
		}
		dbm_close(pdb);
	} else {
		found = RLM_MODULE_FAIL;
		DEBUG2("rlm_dbm: Cannot open database file: %s\n",
		       strerror(errno));
	}

	if ( found == RLM_MODULE_OK ) {
		/* do preprocessor for final reply-pair tranformation */
		if ( !sm_postprocessor(&reply_tmp) ) {
			pairmove(reply_pairs, &reply_tmp);
			pairmove(check_pairs, &check_tmp);
		} else found = RLM_MODULE_FAIL;
	}
	sm_user_list_wipe(&ulist);
	pairfree(&reply_tmp);
	pairfree(&check_tmp);

	return found;
}

static int rlm_dbm_detach(void *instance)
{
	struct rlm_dbm_t *inst = instance;
	free(inst);
	return 0;
}


/* globally exported name */
module_t rlm_dbm = {
	RLM_MODULE_INIT,
        "dbm",
        0,                              /* type: reserved */
        rlm_dbm_instantiate,            /* instantiation */
        rlm_dbm_detach,                 /* detach */
        {
                NULL,                   /* authentication */
                rlm_dbm_authorize,      /* authorization */
                NULL,           	/* preaccounting */
                NULL,                   /* accounting */
                NULL,                    /* checksimul */
                NULL,			/* pre-proxy */
                NULL,			/* post-proxy */
                NULL			/* post-auth */
	},
};
