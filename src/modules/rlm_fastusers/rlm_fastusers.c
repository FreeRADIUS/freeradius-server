/*
 * rlm_fastusers.c	authorization: Find a user in the hashed "users" file.
 *		accounting:    Do nothing.  Auth module only.
 *
 */

#include	"autoconf.h"
#include "libradius.h"

/***********************************************************************
 * Copyright (C) 2000 The FreeRADIUS server project.
 *
 * This program is is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 if the
 *  License as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 ***********************************************************************/

#include	<sys/socket.h>
#include	<sys/time.h>
#include	<sys/stat.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<pwd.h>
#include	<grp.h>
#include	<ctype.h>
#include	<fcntl.h>
#include	<limits.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"radiusd.h"
#include	"modules.h"

struct fastuser_instance {
	char *compat_mode;
	int	 hash_reload;

	/* hash table */
	long hashsize;
	PAIR_LIST **hashtable;
	PAIR_LIST *defaults;
	int normal_defaults;

	char *usersfile;
	time_t next_reload;
};

/* Function declarations */
static int fallthrough(VALUE_PAIR *vp);
static int fastuser_buildhash(struct fastuser_instance *inst);
static int fastuser_getfile(struct fastuser_instance *inst, const char *filename, 
														PAIR_LIST **default_list, PAIR_LIST **hashtable);
static int fastuser_hash(const char *s, long hashtablesize);
static int fastuser_store(PAIR_LIST **hashtable, PAIR_LIST *entry, int idx);
static PAIR_LIST *fastuser_find(PAIR_LIST **hashtable, const char *user,
															long hashsize);

/*
 *	A temporary holding area for config values to be extracted
 *	into, before they are copied into the instance data
 */
static struct fastuser_instance config;

static CONF_PARSER module_config[] = {
	{ "usersfile",     PW_TYPE_STRING_PTR, &config.usersfile, "${raddbdir}/users_fast" },
	{ "hashsize",     PW_TYPE_INTEGER, &config.hashsize, "100000" },
	{ "compat",        PW_TYPE_STRING_PTR, &config.compat_mode, "cistron" },
	{ "hash_reload",     PW_TYPE_INTEGER, &config.hash_reload, "600" },
	{ NULL, -1, NULL, NULL }
};

/*
 * See if a VALUE_PAIR list contains Fall-Through = Yes
 */
static int fallthrough(VALUE_PAIR *vp)
{
	VALUE_PAIR *tmp;
	tmp = pairfind(vp, PW_FALL_THROUGH);
	return tmp ? tmp->lvalue : 0;
}

static int fastuser_buildhash(struct fastuser_instance *inst) {
	long memsize=0;
	int rcode, hashindex;
	PAIR_LIST **newhash=NULL, **oldhash=NULL;
	PAIR_LIST *newdefaults=NULL, *olddefaults=NULL, *cur=NULL;

	/* 
	 * Allocate space for hash table here
	 */
	memsize = sizeof(PAIR_LIST *) * inst->hashsize;
	if( (newhash = (PAIR_LIST **)malloc(memsize)) == NULL) {
		radlog(L_ERR, "rlm_fastusers:  Can't build hashtable, out of memory!");
		return -1;
	}
	memset((PAIR_LIST *)newhash, 0, memsize);

	rcode = fastuser_getfile(inst, inst->usersfile, &newdefaults, newhash);
	if (rcode != 0) {
		radlog(L_ERR|L_CONS, "rlm_fastusers:  Errors reading %s", inst->usersfile);
		return -1;
	}

	/*
	 * We need to do this now so that users auths
	 * aren't blocked while we free the old table
	 * below
	 */
	oldhash = inst->hashtable;
	inst->hashtable = newhash;
	olddefaults = inst->defaults;
	inst->defaults = newdefaults;

	/*
	 * When we get here, we assume the hash built properly.
	 * So we begin to tear down the old one
	 */
	if(oldhash) {
		for(hashindex=0; hashindex<inst->hashsize; hashindex++) {
			if(oldhash[hashindex]) {
				cur = oldhash[hashindex];
				pairlist_free(&cur);
			}
		} 
		free(oldhash);
		pairlist_free(&olddefaults);
	}
	return 0;	
}

static int fastuser_getfile(struct fastuser_instance *inst, const char *filename, 
														PAIR_LIST **default_list, PAIR_LIST **hashtable) {
	int rcode;
	PAIR_LIST *users = NULL;
	PAIR_LIST *entry=NULL, *next=NULL, *cur=NULL, *defaults=NULL, *lastdefault=NULL;
	int compat_mode = FALSE;
	VALUE_PAIR *vp=NULL;
	int hashindex = 0;
	long numdefaults = 0, numusers=0;

	rcode = pairlist_read(filename, &users, 1);
	if (rcode < 0) {
		return -1;
	}

	if (strcmp(inst->compat_mode, "cistron") == 0) {
		compat_mode = TRUE;
	}
        
	entry = users;
	while (entry) {
		if (compat_mode) {
			DEBUG("[%s]:%d Cistron compatibility checks for entry %s ...",
				filename, entry->lineno, entry->name);
		}

		/*
		 *	Look for improper use of '=' in the
		 *	check items.  They should be using
		 *	'==' for on-the-wire RADIUS attributes,
		 *	and probably ':=' for server
		 *	configuration items.
		 */
		for (vp = entry->check; vp != NULL; vp = vp->next) {
 			/*
			 *	Ignore attributes which are set
			 *	properly.
			 */
			if (vp->operator != T_OP_EQ) 
				continue;
				

			/*
			 *	If it's a vendor attribute,
			 *	or it's a wire protocol, 
			 *	ensure it has '=='.
			 */
			if (((vp->attribute & ~0xffff) != 0) ||
				(vp->attribute < 0x100)) {
				if (!compat_mode) {
					DEBUG("[%s]:%d WARNING! Changing '%s =' to '%s =='\n\tfor comparing RADIUS attribute in check item list for user %s",
					filename, entry->lineno, vp->name, vp->name, entry->name);
				} else {
					DEBUG("\tChanging '%s =' to '%s =='",
						vp->name, vp->name);
				}
				vp->operator = T_OP_CMP_EQ;
				continue;
			}
				
			/*
			 *	Cistron Compatibility mode.
			 *
			 *	Re-write selected attributes
			 *	to be '+=', instead of '='.
			 *
			 *	All others get set to '=='
			 */
			if (compat_mode) {
				/*
				 *	Non-wire attributes become +=
				 *
				 *	On the write attributes
				 *	become ==
				 */
				if ((vp->attribute >= 0x100) &&
					(vp->attribute <= 0xffff) &&
					(vp->attribute != PW_HINT) &&
					(vp->attribute != PW_HUNTGROUP_NAME)) {
					DEBUG("\tChanging '%s =' to '%s +='",
						vp->name, vp->name);
						vp->operator = T_OP_ADD;
				} else {
					DEBUG("\tChanging '%s =' to '%s =='",
						vp->name, vp->name);
					vp->operator = T_OP_CMP_EQ;
				}
			}
				
		} /* end of loop over check items */
                
                
		/*
		 *	Look for server configuration items
		 *	in the reply list.
		 *
		 *	It's a common enough mistake, that it's
		 *	worth doing.
		 */
		for (vp = entry->reply; vp != NULL; vp = vp->next) {
			/*
			 *	If it's NOT a vendor attribute,
			 *	and it's NOT a wire protocol
			 *	and we ignore Fall-Through,
			 *	then bitch about it, giving a
			 *	good warning message.
			 */
			if (!(vp->attribute & ~0xffff) &&
				(vp->attribute > 0xff) &&
				(vp->attribute > 1000)) {
				log_debug("[%s]:%d WARNING! Check item \"%s\"\n"
					"\tfound in reply item list for user \"%s\".\n"
					"\tThis attribute MUST go on the first line"
					" with the other check items", 
					filename, entry->lineno, vp->name,
					entry->name);
			}
		}

		/*
		 * Ok, we've done all the same BS as
		 * rlm_users, so here we tear apart the
		 * linked list, and store our users in
		 * the hashtable we've built instead
		 */

		/* Save what was next */
		next = entry->next;

		/* Save the DEFAULT entry specially */
		if(strcmp(entry->name, "DEFAULT")==0) {
			
			/* Save this as the last default we've seen */
			lastdefault = entry;
			numdefaults++;

			/* put it at the end of the list */
			if(defaults) {
				for(cur=defaults; cur->next; cur=cur->next);
				cur->next = entry;
				entry->next = NULL;
			} else {
				defaults = entry;
				defaults->next = NULL; 
			}

		} else {
			numusers++;

			/* Hash the username */
			hashindex = fastuser_hash(entry->name, inst->hashsize);

			/* Store the last default before this entry */
			entry->lastdefault = lastdefault;

			/* Store user in the hash */
			fastuser_store(hashtable, entry, hashindex);

		}
		/* Restore entry to next pair_list */
		entry = next;

	} /* while(entry) loop */

	*default_list = defaults;
	radlog(L_INFO, "rlm_fastusers:  Loaded %ld users and %ld defaults",
				numusers, numdefaults);

	return 0;
}

/* Hashes the username sent to it and returns index into hashtable */
int fastuser_hash(const char *s, long hashtablesize) {
     unsigned long hash = 0;

     while (*s != '\0') {
         hash = hash * 7907 + (unsigned char)*s++;
      }

     return (hash % hashtablesize);
}

/* Stores the username sent into the hashtable */
static int fastuser_store(PAIR_LIST **hashtable, PAIR_LIST *new, int idx) {

   /* store new record at beginning of list */
   new->next = hashtable[idx];
   hashtable[idx] = new;

   return 1;
}

/*
 * Looks up user in hashtable.  If user can't be found, returns 0.
 * Otherwise returns a pointer to the structure for the user
 */
static PAIR_LIST *fastuser_find(PAIR_LIST **hashtable, 
		const char *user, long hashsize)
{

   PAIR_LIST *cur;
   int idx;

   /* first hash the username and get the index into the hashtable */
   idx = fastuser_hash(user, hashsize);

   cur = hashtable[idx];

   while((cur != NULL) && (strcmp(cur->name, user))) {
      cur = cur->next;
   }

   if(cur) {
      DEBUG2("  fastusers:  user %s found in hashtable bucket %d", user, idx);
      return cur;
   }

   return (PAIR_LIST *)0;

}


/*
 *	(Re-)read the "users" file into memory.
 */
static int fastuser_instantiate(CONF_SECTION *conf, void **instance)
{
	struct fastuser_instance *inst=0;

	inst = malloc(sizeof *inst);
	if (!inst) {
		radlog(L_ERR|L_CONS, "Out of memory\n");
		return -1;
	}
	memset(inst, 0, sizeof(inst));

	if (cf_section_parse(conf, module_config) < 0) {
		free(inst);
		return -1;
	}

	inst->usersfile = config.usersfile;
	inst->hashsize = config.hashsize;
	inst->defaults = config.defaults;
	inst->compat_mode = config.compat_mode;
	inst->hash_reload = config.hash_reload;
	inst->next_reload = time(NULL) + inst->hash_reload;
	inst->hashtable = NULL;
	if(fastuser_buildhash(inst) < 0) {
		radlog(L_ERR, "rlm_fastusers:  error building user hash.  aborting");
		return -1;
	}

	config.usersfile = NULL;
	config.hashtable = NULL;
	config.defaults = NULL;
	config.compat_mode = NULL;

	*instance = inst;
	return 0;
}

/*
 *	Find the named user in the database.  Create the
 *	set of attribute-value pairs to check and reply with
 *	for this user from the database. The main code only
 *	needs to check the password, the rest is done here.
 */
static int fastuser_authorize(void *instance, REQUEST *request)
{

	VALUE_PAIR	*namepair;
	VALUE_PAIR	*request_pairs;
	VALUE_PAIR	*check_tmp;
	VALUE_PAIR	*reply_tmp;
	VALUE_PAIR 	**check_pairs;
	VALUE_PAIR	**reply_pairs;
	VALUE_PAIR	*check_save;
	PAIR_LIST		*user;
	PAIR_LIST		*curdefault;
	const char	*name;
	int			userfound=0;
	int			defaultfound=0;
	struct fastuser_instance *inst = instance;

	request_pairs = request->packet->vps;
	check_pairs = &request->config_items;
	reply_pairs = &request->reply->vps;

	/*
	 * Do we need to reload the cache?
	 * Really we should spawn a thread to do this
	 */
	if((inst->hash_reload) && (request->timestamp > inst->next_reload)) {
		inst->next_reload = request->timestamp + inst->hash_reload;
		radlog(L_INFO, "rlm_fastusers:  Reloading fastusers hash");
		if(fastuser_buildhash(inst) < 0) {
			radlog(L_ERR, "rlm_fastusers:  error building user hash.  aborting");
			exit(1);
		}
	}

 	/*
	 *	Grab the canonical user name.
	 */
	namepair = request->username;
	name = namepair ? (char *) namepair->strvalue : "NONE";

	/*
	 *	Find the entry for the user.
	 */
	user=fastuser_find(inst->hashtable, name, inst->hashsize);

	/*
	 * Usercollide means we have to compare check pairs
	 * _and_ the password
	 */
	if(mainconfig.do_usercollide) {
		/* Save the orginal config items */
		check_save = paircopy(request->config_items);

		while((user) && (!userfound) && (strcmp(user->name, name)==0)) {
			if(paircmp(request_pairs, user->check, reply_pairs) != 0) {
				user = user->next;
				continue;
			}
			DEBUG2("  fastusers(uc): Checking %s at %d", user->name, user->lineno);

			/* Copy this users check pairs to the request */
			check_tmp = paircopy(user->check);
			pairmove(check_pairs, &check_tmp);
			pairfree(&check_tmp); 

			/* Check the req to see if we matched */
			if(rad_check_password(request)==0) {
				DEBUG2("  fastusers: Matched %s at %d", user->name, user->lineno);
				userfound = 1;

			/* We didn't match here */
			} else {
				/* Restore check items */
				pairfree(&request->config_items); 
				request->config_items = paircopy(check_save);
				check_pairs = &request->config_items;
				user = user->next;
			}
		}

		/* Free our saved config items */
		pairfree(&check_save);
	} else {

		while((user) && (!userfound) && (strcmp(user->name, name)==0)) {
			if(paircmp(request_pairs, user->check, reply_pairs) == 0) {
				userfound = 1;
				DEBUG2("  fastusers: Matched %s at %d", user->name, user->lineno);
			} else {
				user = user->next;
			}	
		}
	}

	/* 
	 * If there's no lastdefault and we
	 * don't fallthrough, just copy the
	 * pairs for this user and return
	 */
	if((user) && (userfound) && 
		 (user->lastdefault == NULL) && 
		 (!fallthrough(user->reply))) {
		DEBUG2("rlm_fastusers:  not checking defaults");

		check_tmp = paircopy(user->check);
		pairmove(check_pairs, &check_tmp);
		pairfree(&check_tmp); 

		reply_tmp = paircopy(user->reply);
		pairmove(reply_pairs, &reply_tmp);
		pairfree(&reply_tmp);

		pairdelete(reply_pairs, PW_FALL_THROUGH);

		return RLM_MODULE_UPDATED;
	}

	/* 
	 * When we get here, we've either found 
	 * the user or not, but to preserve order
	 * we start at the top of the default
	 * list and work our way thru
	 * When we get to the user's 'lastdefault'
	 * we check to see if we should stop
	 * and return
	 */
	DEBUG2("rlm_fastusers:  checking defaults");
			
	curdefault = inst->defaults;
	while(curdefault) {
		if(paircmp(request_pairs, curdefault->check, reply_pairs) == 0) {
			DEBUG2("  fastusers: Matched %s at %d", 
							curdefault->name, curdefault->lineno);
			defaultfound = 1;

			check_tmp = paircopy(curdefault->check);
			pairmove(check_pairs, &check_tmp);
			pairfree(&check_tmp); 

			reply_tmp = paircopy(curdefault->reply);
			pairmove(reply_pairs, &reply_tmp);
			pairfree(&reply_tmp);
		}

		/* 
		 * There's no fallthru on this default which
		 * is *before* we find the user in the file, 
		 * so we know it's safe to quit here
		 */
		if (!fallthrough(curdefault->reply))
			break;

		/*
		 * If we found the user, we want to stop
		 * processing once we get to 'lastdefault'
		 * if there's no Fall-Through on the user
		 * entry
		 */
		if((userfound && (user) && (curdefault == user->lastdefault))) {
				DEBUG2("  fastusers:  found lastdefault at line %d",
						   curdefault->lineno);

				check_tmp = paircopy(user->check);
				pairmove(check_pairs, &check_tmp);
				pairfree(&check_tmp); 

				reply_tmp = paircopy(user->reply);
				pairmove(reply_pairs, &reply_tmp);
				pairfree(&reply_tmp);

			if(!fallthrough(user->reply))
				break;
		} 
		curdefault = curdefault->next;
	}

	if(userfound || defaultfound) {
		pairdelete(reply_pairs, PW_FALL_THROUGH);
		return RLM_MODULE_UPDATED;
	} else {
		DEBUG2("rlm_fastusers:  user not found");
		return RLM_MODULE_NOTFOUND;
	}
}

/*
 *	Authentication - unused.
 */
static int fastuser_authenticate(void *instance, REQUEST *request)
{
	instance = instance;
	request = request;
	return RLM_MODULE_OK;
}

/*
 *  Clean up.
 */
static int fastuser_detach(void *instance)
{
	struct fastuser_instance *inst = instance;
	int hashindex;
	PAIR_LIST *cur;

	/* Free hash table */
	for(hashindex=0; hashindex<inst->hashsize; hashindex++) {
		if(inst->hashtable[hashindex]) {
			cur = inst->hashtable[hashindex];
			pairlist_free(&cur);
		}
	} 

	free(inst->hashtable);
	pairlist_free(&inst->defaults);
	free(inst->usersfile);
	free(inst->compat_mode);
	free(inst);
  return 0;
}

/*
 *	This function is unused
 */
static int fastuser_preacct(void *instance, REQUEST *request)
{
	return RLM_MODULE_FAIL;
}

/*
 *	This function is unused
 */
static int fastuser_accounting(void *instance, REQUEST *request)
{
	return RLM_MODULE_FAIL;
}

/* globally exported name */
module_t rlm_fastusers = {
	"fastusers",
	0,				/* type: reserved */
	NULL,			/* initialization */
	fastuser_instantiate,		/* instantiation */
	fastuser_authorize, 		/* authorization */
	fastuser_authenticate,		/* authentication */
	fastuser_preacct,			/* preaccounting */
	fastuser_accounting,		/* accounting */
	NULL,									/* checksimul */
	fastuser_detach,			/* detach */
	NULL				/* destroy */
};

