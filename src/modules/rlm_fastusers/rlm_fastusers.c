/*
 * rlm_fastusers.c	authorization: Find a user in the hashed "users" file.
 *		accounting:    Do nothing.  Auth module only.
 *
 */

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<sys/stat.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<pwd.h>
#include	<grp.h>
#include	<time.h>
#include	<ctype.h>
#include	<fcntl.h>
#include	<unistd.h>
#include <limits.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"radiusd.h"
#include	"modules.h"

struct fastuser_instance {
	char *compat_mode;
	int	 normal_defaults;

	/* hash table */
	long hashsize;
	PAIR_LIST **hashtable;
	PAIR_LIST *users;
	PAIR_LIST *default_entry;

	char *usersfile;
};

/* Function declarations */
static int fastuser_getfile(const char *filename, PAIR_LIST **hashtable);
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
	{ "usersfile",     PW_TYPE_STRING_PTR, &config.usersfile, RADIUS_USERS },
	{ "hashsize",     PW_TYPE_INTEGER, &config.hashsize, "100000" },
	{ "compat",        PW_TYPE_STRING_PTR, &config.compat_mode, "cistron" },
	{ "normal_defaults", PW_TYPE_BOOLEAN, &config.normal_defaults, "yes" },
	{ NULL, -1, NULL, NULL }
};

static int fastuser_getfile(const char *filename, PAIR_LIST **hashtable)
{
	int rcode;
	PAIR_LIST *users = NULL;
	int compat_mode = FALSE;
	PAIR_LIST *entry, *next, *cur;
	VALUE_PAIR *vp;
	int hashindex = 0;
	int numdefaults = 0;

	rcode = pairlist_read(filename, &users, 1);
	if (rcode < 0) {
		return -1;
	}

	if (strcmp(config.compat_mode, "cistron") == 0) {
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
				numdefaults++;
				/* put it at the end of the list */
				if(config.default_entry) {
					for(cur=config.default_entry; cur->next; cur=cur->next);
					cur->next = entry;
					entry->next = NULL;
				} else {
					config.default_entry = entry;
					config.default_entry->next = NULL;
				}

		} else {

			/* Hash the username */
			hashindex = fastuser_hash(entry->name, config.hashsize);

			/* Store user in the hash */
			fastuser_store(hashtable, entry, hashindex);

			/* Restore entry to next pair_list */
		}
		entry = next;

	} /* while(entry) loop */

	if(!config.normal_defaults && (numdefaults>1)) {
		radlog(L_INFO, "Warning:  fastusers found multiple DEFAULT entries.  Using the first.");
	}

	/* 
	 * We *should* do this to help out clueless admins
	 * but it's documented, so it will confuse those who
	 * do read the docs if we do it here as well
	if(!config.normal_defaults) {
		pairdelete(&config.default_entry->check, PW_AUTHTYPE);
	}
	 */

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
	int rcode;
	long memsize=0;

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

	/* 
	 * Sue me.  The tradeoff for this extra variable
	 * is clean code below
	 */
	memsize = sizeof(PAIR_LIST *) * config.hashsize;
	/* 
	 * Allocate space for hash table here
	 */
	if( (inst->hashtable = (PAIR_LIST **)malloc(memsize)) == NULL) {
		radlog(L_ERR, "fastusers:  Can't build hashtable, out of memory!");
		return -1;
	}
	memset((PAIR_LIST *)inst->hashtable, 0, memsize);

	rcode = fastuser_getfile(config.usersfile, inst->hashtable);
	if (rcode != 0) {
		radlog(L_ERR|L_CONS, "Errors reading %s", config.usersfile);
		return -1;
	}

	inst->usersfile = config.usersfile;
	inst->hashsize = config.hashsize;
	inst->default_entry = config.default_entry;
	inst->compat_mode = config.compat_mode;
	inst->normal_defaults = config.normal_defaults;
	inst->users = NULL;

	config.usersfile = NULL;
	config.hashtable = NULL;
	config.default_entry = NULL;
	config.users = NULL;
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
	const char	*name;
	int			found=0;
	int			checkdefault = 0;
	struct fastuser_instance *inst = instance;

	request_pairs = request->packet->vps;
	check_pairs = &request->config_items;
	reply_pairs = &request->reply->vps;

 	/*
	 *	Grab the canonical user name.
	 */
	namepair = request->username;
	name = namepair ? (char *) namepair->strvalue : "NONE";

	/*
	 *	Find the entry for the user.
	 */
	if((user=fastuser_find(inst->hashtable, name, inst->hashsize))==NULL) {
		if(inst->normal_defaults) {
			checkdefault = 1;
		} else {
			return RLM_MODULE_NOTFOUND;
		}
	}

	/*
	 * Usercollide means we have to compare check pairs
	 * _and_ the password
	 */
	if(mainconfig.do_usercollide && !checkdefault) {
		/* Save the orginal config items */
		check_save = paircopy(request->config_items);

		while((user) && (!found) && (strcmp(user->name, name)==0)) {
			if(paircmp(request_pairs, user->check, reply_pairs) != 0) {
				user = user->next;
				continue;
			}
			DEBUG2("  fastusers(uc): Checking %s at %d", user->name, user->lineno);

			/* Copy this users check pairs to the request */
			check_tmp = paircopy(user->check);
			pairmove(check_pairs, &check_tmp);
			pairfree(check_tmp); 

			/* Check the req to see if we matched */
			if(rad_check_password(request)==0) {
				found = 1;

			/* We didn't match here */
			} else {
				/* Restore check items */
				pairfree(request->config_items); 
				request->config_items = paircopy(check_save);
				check_pairs = &request->config_items;
				user = user->next;
			}
		}

		/* Free our saved config items */
		pairfree(check_save);
	}

	/*
	 * No usercollide, just compare check pairs
	 */
	if(!mainconfig.do_usercollide && !checkdefault) {
		while((user) && (!found) && (strcmp(user->name, name)==0)) {
			if(paircmp(request_pairs, user->check, reply_pairs) == 0) {
				found = 1;
				DEBUG2("  fastusers: Matched %s at %d", user->name, user->lineno);
			} else {
				user = user->next;
			}	
		}
	}

	/* 
	 * When we get here, we've either found the user or not
	 * and we either do normal DEFAULTs or not.  
	 */
	
	/*
	 * We found the user & normal default 
	 * copy relevant pairs and return
	 */
	if(found && inst->normal_defaults) {
		check_tmp = paircopy(user->check);
		pairmove(check_pairs, &check_tmp);
		pairfree(check_tmp); 
		reply_tmp = paircopy(user->reply);
		pairmove(reply_pairs, &reply_tmp);
		pairfree(reply_tmp);
		return RLM_MODULE_UPDATED;
	}

	/*
	 * We didn't find the user, and we aren't supposed to
	 * check defaults.  So just report not found.
	 */
	if(!found && !inst->normal_defaults) {
		return RLM_MODULE_NOTFOUND;
	}

	/*
	 * We didn't find the user, but we should 
	 * check the defaults.  
	 */
	if(!found && inst->normal_defaults) {
		user = inst->default_entry;
		while((user) && (!found)) {
			if(paircmp(request_pairs, user->check, reply_pairs) == 0) {
				DEBUG2("  fastusers: Matched %s at %d", user->name, user->lineno);
				found = 1;
			} else {
				user = user->next;
			}
		}

		if(found) {
			check_tmp = paircopy(user->check);
			pairmove(check_pairs, &check_tmp);
			pairfree(check_tmp); 
			reply_tmp = paircopy(user->reply);
			pairmove(reply_pairs, &reply_tmp);
			pairfree(reply_tmp);
			return RLM_MODULE_UPDATED;

		} else {
			return RLM_MODULE_NOTFOUND;
		}
	}

	/*
	 * We found the user, and we don't use normal defaults.
	 * So copy the check and reply pairs from the default
	 * entry to the request
	 */
	if(found && !inst->normal_defaults) {

		/* We've already done this above if(mainconfig.do_usercollide) */
		if(!mainconfig.do_usercollide) {
			check_tmp = paircopy(user->check);
			pairmove(check_pairs, &check_tmp);
			pairfree(check_tmp); 
		}
		reply_tmp = paircopy(user->reply);
		pairmove(reply_pairs, &reply_tmp);
		pairfree(reply_tmp);

		/* 
		 * We also need to add the pairs from 
		 * inst->default_entry if the vp is
		 * not already present.
		 */
		
		if(inst->default_entry) {
			check_tmp = paircopy(inst->default_entry->check);
			reply_tmp = paircopy(inst->default_entry->reply);
			pairmove(reply_pairs, &reply_tmp);
			pairmove(check_pairs, &check_tmp);
			pairfree(reply_tmp);
			pairfree(check_tmp); 
		}

		return RLM_MODULE_UPDATED;
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
	pairlist_free(&inst->users);
	pairlist_free(&inst->default_entry);
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

