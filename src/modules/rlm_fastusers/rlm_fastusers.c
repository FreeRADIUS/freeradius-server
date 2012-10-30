/*
 * rlm_fastusers.c	authorization: Find a user in the hashed "users" file.
 *                	accounting:    Do nothing.  Auth module only.
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
 * Copyright 2000  Jeff Carneal <jeff@apex.net>
 */

#include        <freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>

#include	<sys/stat.h>

#include	<ctype.h>
#include	<fcntl.h>
#include	<limits.h>

struct fastuser_instance {
	char *compat_mode;
	int hash_reload;

	char *key;

	/* hash table */
	int hashsize;
	PAIR_LIST **hashtable;
	PAIR_LIST *defaults;
	PAIR_LIST *acctusers;
	int stats;

	char *usersfile;
	char *acctusersfile;
	time_t next_reload;
	time_t lastusersload;
	time_t lastacctusersload;
};

/* Function declarations */
static int fallthrough(VALUE_PAIR *vp);
static int fastuser_buildhash(struct fastuser_instance *inst);
static int fastuser_getfile(struct fastuser_instance *inst, const char *filename,
														PAIR_LIST **default_list, PAIR_LIST **pair_list,
														int isacctfile);
static int fastuser_hash(const char *s, int hashtablesize);
static int fastuser_store(PAIR_LIST **hashtable, PAIR_LIST *entry, int idx);
static PAIR_LIST *fastuser_find(REQUEST *request, PAIR_LIST *user,
																const char *username);
static void fastuser_tablestats(PAIR_LIST **hashtable, int size);

static const CONF_PARSER module_config[] = {
	{ "usersfile",     PW_TYPE_FILENAME,
	  offsetof(struct fastuser_instance,usersfile), NULL, "${raddbdir}/users_fast" },
	{ "acctusersfile",     PW_TYPE_FILENAME,
	  offsetof(struct fastuser_instance,acctusersfile), NULL, "${raddbdir}/acct_users" },
	{ "hashsize",     PW_TYPE_INTEGER,
	  offsetof(struct fastuser_instance,hashsize), NULL, "100000" },
	{ "stats",     PW_TYPE_BOOLEAN,
	  offsetof(struct fastuser_instance,stats), NULL, "no" },
	{ "compat",        PW_TYPE_STRING_PTR,
	  offsetof(struct fastuser_instance,compat_mode), NULL, "cistron" },
	{ "hash_reload",     PW_TYPE_INTEGER,
	  offsetof(struct fastuser_instance,hash_reload), NULL, "600" },
	{ "key",     PW_TYPE_STRING_PTR,
	  offsetof(struct fastuser_instance,key), NULL, NULL },
	{ NULL, -1, 0, NULL, NULL }
};

/*
 * See if a VALUE_PAIR list contains Fall-Through = Yes
 */
static int fallthrough(VALUE_PAIR *vp)
{
	VALUE_PAIR *tmp;
	tmp = pairfind(vp, PW_FALL_THROUGH, 0);
	return tmp ? tmp->vp_integer : 0;
}

/*
 *       returncheck - Check for Auth-Type = Reject and return appropriate
 *                     module return code if it is found.
 */
static int rad_check_return(VALUE_PAIR *list)
{
      VALUE_PAIR      *authtype;

      /*
       * We check for Auth-Type = Reject here
       */

      authtype = pairfind(list, PW_AUTHTYPE, 0);
      if((authtype) && authtype->vp_integer == PW_AUTHTYPE_REJECT)  {
              DEBUG2("rad_check_return:  Auth-Type is Reject");
              return RLM_MODULE_REJECT;
      }

      return RLM_MODULE_UPDATED;
}

static int fastuser_buildhash(struct fastuser_instance *inst) {
	int memsize=0;
	int rcode, hashindex;
	PAIR_LIST **newhash=NULL, **oldhash=NULL;
	PAIR_LIST *newdefaults=NULL, *newacctusers, *cur=NULL;
	PAIR_LIST *olddefaults=NULL, *oldacctusers=NULL;
	struct stat statbuf;
	int reloadusers = 1;
	int reloadacctusers = 1;

	/*
	 * Allocate space for hash table here
	 */
	memsize = sizeof(PAIR_LIST *) * inst->hashsize;

	newhash = (PAIR_LIST **) rad_malloc(memsize);

	memset((PAIR_LIST *)newhash, 0, memsize);

	/* Check acct_users last modification time */
	if ((stat(inst->acctusersfile, &statbuf) != -1)
	 && (statbuf.st_mtime <= inst->lastacctusersload)) {
		DEBUG2("rlm_fastusers:  File %s was unchanged. Not reloading.",
			inst->acctusersfile);
		reloadacctusers = 0;
		rcode = 0;
	}
	else
	/* Read acct_users */
	rcode = fastuser_getfile(inst, inst->acctusersfile, NULL, &newacctusers, 1);

	if (rcode != 0) {
		free(newhash);
		radlog(L_ERR|L_CONS, "rlm_fastusers:  Errors reading %s", inst->usersfile);
		return -1;
	}

	/* Check users last modification time */
	if ((stat(inst->usersfile, &statbuf) != -1)
	 && (statbuf.st_mtime <= inst->lastusersload)) {
		DEBUG2("rlm_fastusers:  File %s was unchanged. Not reloading.",
			inst->usersfile);
		reloadusers = 0;
		rcode = 0;
		/* This was allocated earlier but will remain unused */
		free(newhash);
		newhash = NULL;
	}
	else
	/* Read users */
	rcode = fastuser_getfile(inst, inst->usersfile, &newdefaults, newhash, 0);

	if (rcode != 0) {
		free(newhash);
		radlog(L_ERR|L_CONS, "rlm_fastusers:  Errors reading %s", inst->usersfile);
		return -1;
	}

	if (reloadusers) {
		/*
		 * We need to do this now so that users auths
		 * aren't blocked while we free the old table
		 * below
		 */
		inst->lastusersload = time(NULL);
		oldhash = inst->hashtable;
		inst->hashtable = newhash;
		olddefaults = inst->defaults;
		inst->defaults = newdefaults;

		/*
		 * When we get here, we assume the hash built properly.
		 * So we begin to tear down the old one
		 */
		if (oldhash) {
			for(hashindex=0; hashindex<inst->hashsize; hashindex++) {
				if(oldhash[hashindex]) {
					cur = oldhash[hashindex];
					pairlist_free(&cur);
				}
			}
			free(oldhash);
		}
		pairlist_free(&olddefaults);
	}
	if (reloadacctusers) {
		inst->lastacctusersload = time(NULL);
		oldacctusers = inst->acctusers;
		inst->acctusers = newacctusers;
		pairlist_free(&oldacctusers);
	}

	if(inst->stats)
		fastuser_tablestats(inst->hashtable, inst->hashsize);

	return 0;
}

static int fastuser_getfile(struct fastuser_instance *inst, const char *filename,
														PAIR_LIST **default_list, PAIR_LIST **pair_list,
														int isacctfile) {
	int rcode;
	PAIR_LIST *users = NULL;
	PAIR_LIST *entry=NULL, *next=NULL, *cur=NULL, *defaults=NULL, *lastdefault=NULL;
	int compat_mode = FALSE;
	VALUE_PAIR *vp=NULL;
	int hashindex = 0;
	int numdefaults = 0, numusers=0;

	radlog(L_INFO, " fastusers:  Reading %s", filename);
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
			if ((vp->vendor != 0) ||
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
		         if ((vp->vendor == 0) &&
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

		if(!isacctfile) {
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
				fastuser_store(pair_list, entry, hashindex);
			}
		}
		/* Restore entry to next pair_list */
		entry = next;

	} /* while(entry) loop */

	if(!isacctfile && (default_list)) {
		*default_list = defaults;
		radlog(L_INFO, "rlm_fastusers:  Loaded %d users and %d defaults",
					numusers, numdefaults);
	} else {
		*pair_list = users;
	}

	return 0;
}

/* Hashes the username sent to it and returns index into hashtable */
int fastuser_hash(const char *s, int hashtablesize) {
	unsigned int hash = 0;

	while (*s != '\0') {
		hash = hash * 7907 + (unsigned char)*s++;
	}

	return (hash % hashtablesize);
}

/* Stores the username sent into the hashtable */
static int fastuser_store(PAIR_LIST **hashtable, PAIR_LIST *new, int idx) {
	PAIR_LIST *cur;

	cur = hashtable[idx];
	/* store new record at end of list */
	if(cur) {
		while (cur->next != NULL)
			cur=cur->next;
		cur->next = new;
		new->next = NULL;
	} else {
		new->next = hashtable[idx];
		hashtable[idx] = new;
	}
	return 1;
}

/*
 * Looks up user in hashtable.  If user can't be found, returns 0.
 * Otherwise returns a pointer to the structure for the user
 */
static PAIR_LIST *fastuser_find(REQUEST *request, PAIR_LIST *user,
		                            const char *username)
{
	PAIR_LIST *cur=user;
	int userfound = 0;

	/*
	 * Now we have to make sure it's the right user by
	 * comparing the check pairs
	 */
	while((cur) && (!userfound)) {
		if((strcmp(cur->name, username)==0) &&
				paircompare(request, request->packet->vps, cur->check, &request->reply->vps) == 0) {
				userfound = 1;
				DEBUG2("  fastusers: Matched %s at %d", cur->name, cur->lineno);
		} else {
			cur = cur->next;
		}
	}

	if(cur) {
		return cur;
	}

	return (PAIR_LIST *)0;
}

/*
 * Generate and log statistics about our hash table
 */
static void fastuser_tablestats(PAIR_LIST **hashtable, int size) {
	int i, count;
	int countarray[256];
	int toomany=0;
	PAIR_LIST *cur;

	memset(countarray, 0, sizeof(countarray));

	for(i=0; i<size; i++) {
		count = 0;
		for(cur=hashtable[i]; cur; cur=cur->next) {
			count++;
		}
		if(count<256) {
			countarray[count]++;
		} else {
			toomany++;
		}
	}

	for(i=0; i<256; i++)
		if(countarray[i]) {
			radlog(L_INFO, "rlm_fastusers:  Hash buckets with %d users:  %d",
						i, countarray[i]);
		}

	if(toomany) {
		radlog(L_INFO, "rlm_fastusers:  Hash buckets with more than 256:  %d",
					toomany);
	}
}

/*
 *	(Re-)read the "users" file into memory.
 */
static int fastuser_instantiate(CONF_SECTION *conf, void **instance)
{
	struct fastuser_instance *inst=0;

	inst = rad_malloc(sizeof *inst);
	if (!inst)
		return -1;
	memset(inst, 0, sizeof(*inst));

	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}

	inst->next_reload = time(NULL) + inst->hash_reload;
	inst->hashtable = NULL;
	inst->lastusersload = 0;
	inst->lastacctusersload = 0;
	if(fastuser_buildhash(inst) < 0) {
		radlog(L_ERR, "rlm_fastusers:  error building user hash.  aborting");
		return -1;
	}

	/*
	 * Need code here to read acct_users file
	 */

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
	VALUE_PAIR	*check_tmp;
	VALUE_PAIR	*reply_tmp;
	PAIR_LIST		*user;
	PAIR_LIST		*curdefault;
	const char	*name;
	int			userfound=0;
	int			defaultfound=0;
	int			hashidx=0;
	struct fastuser_instance *inst = instance;
	char		buffer[256];

	/*
	 * Do we need to reload the cache?
	 * Really we should spawn a thread to do this
	 */
	if((inst->hash_reload) && (request->timestamp > inst->next_reload)) {
		inst->next_reload = request->timestamp + inst->hash_reload;
		radlog(L_INFO, "rlm_fastusers:  Reloading fastusers hash");
		if(fastuser_buildhash(inst) < 0) {
			radlog(L_ERR, "rlm_fastusers:  error building user hash.  aborting");
			return RLM_MODULE_FAIL;
		}
	}

	/*
	 *	Grab the canonical user name.
	 */
	if (!inst->key) {
		namepair = request->username;
		name = namepair ? (char *) namepair->vp_strvalue : "NONE";
	} else {
		int len;

		len = radius_xlat(buffer, sizeof(buffer), inst->key,
				  request, NULL, NULL);
		if (len) name = buffer;
		else name = "NONE";
	}

	/*
	 *	Find the entry for the user.
	 */
	hashidx = fastuser_hash(name, inst->hashsize);
	user = inst->hashtable[hashidx];
	if((user=fastuser_find(request, user, name))!=NULL) {
		userfound = 1;
	}

	/*
	 * If there's no lastdefault and we
	 * don't fallthrough, just copy the
	 * pairs for this user and return
	 */
	if((user) && (userfound) && (user->lastdefault == NULL)) {
		DEBUG2("rlm_fastusers:  user found before DEFAULT");

		check_tmp = paircopy(user->check);
		pairmove(&request->config_items, &check_tmp);
		pairfree(&check_tmp);

		reply_tmp = paircopy(user->reply);
		pairmove(&request->reply->vps, &reply_tmp);
		pairfree(&reply_tmp);

		if(!fallthrough(user->reply)) {
			pairdelete(&request->reply->vps, PW_FALL_THROUGH, 0, -1);
			return(rad_check_return(user->check));
		} else {
			user=user->next;
			user=fastuser_find(request, user, name);
		}
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
		if(paircompare(request, request->packet->vps, curdefault->check,
							&request->reply->vps) == 0) {
			DEBUG2("  fastusers: Matched %s at %d",
							curdefault->name, curdefault->lineno);
			defaultfound = 1;

			check_tmp = paircopy(curdefault->check);
			pairmove(&request->config_items, &check_tmp);
			pairfree(&check_tmp);

			reply_tmp = paircopy(curdefault->reply);
			pairmove(&request->reply->vps, &reply_tmp);
			pairfree(&reply_tmp);

			/*
			 * There's no fallthru on this default which
			 * is *before* we find the user in the file,
			 * so we know it's safe to quit here
			 */
			if (!fallthrough(curdefault->reply))
			  break;

		}

		/*
		 * If we found the user, we want to stop
		 * processing once we get to 'lastdefault'
		 * This way we can process this user's entry
		 * in the order it was found in the file
		 */
		while((userfound && (user) && (curdefault == user->lastdefault))) {
				DEBUG2("  fastusers:  found lastdefault at line %d",
						   curdefault->lineno);

			check_tmp = paircopy(user->check);
			pairmove(&request->config_items, &check_tmp);
			pairfree(&check_tmp);

			reply_tmp = paircopy(user->reply);
			pairmove(&request->reply->vps, &reply_tmp);
			pairfree(&reply_tmp);

			if(!fallthrough(user->reply)) {
				pairdelete(&request->reply->vps, PW_FALL_THROUGH, 0, -1);
				return(rad_check_return(user->check));
			}

			/*
			 * Find next occurence of THIS user in
			 * the users file
			 */
			user=user->next;
			user=fastuser_find(request, user, name);
		}

		curdefault = curdefault->next;
	}

	if(userfound || defaultfound) {
		pairdelete(&request->reply->vps, PW_FALL_THROUGH, 0, -1);
		return(rad_check_return(request->config_items));
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
 *	Pre-Accounting - read the acct_users file for check_items and
 *	config_items. Reply items are Not Recommended(TM) in acct_users,
 *	except for Fallthrough, which should work
 *
 *	This function is mostly a copy of file_authorize
 */
static int fastuser_preacct(void *instance, REQUEST *request)
{
	VALUE_PAIR	*namepair;
	const char	*name;
	VALUE_PAIR	*request_pairs;
	VALUE_PAIR	**config_pairs;
	VALUE_PAIR	*reply_pairs = NULL;
	VALUE_PAIR	*check_tmp;
	VALUE_PAIR	*reply_tmp;
	PAIR_LIST	*pl = NULL;
	int		found = 0;
	struct fastuser_instance *inst = instance;
	char		buffer[256];

	if (!inst->key) {
		namepair = request->username;
		name = namepair ? (char *) namepair->vp_strvalue : "NONE";
	} else {
		int len;

		len = radius_xlat(buffer, sizeof(buffer), inst->key,
				  request, NULL, NULL);
		if (len) name = buffer;
		else name = "NONE";
	}
	request_pairs = request->packet->vps;
	config_pairs = &request->config_items;

	/*
	 *	Find the entry for the user.
	 */
	for (pl = inst->acctusers; pl; pl = pl->next) {

		if (strcmp(name, pl->name) && strcmp(pl->name, "DEFAULT"))
			continue;

		if (paircompare(request, request_pairs, pl->check, &reply_pairs) == 0) {
			DEBUG2("  acct_users: Matched %s at %d",
			       pl->name, pl->lineno);
			found = 1;
			check_tmp = paircopy(pl->check);
			reply_tmp = paircopy(pl->reply);
			pairmove(&reply_pairs, &reply_tmp);
			pairmove(config_pairs, &check_tmp);
			pairfree(&reply_tmp);
			pairfree(&check_tmp); /* should be NULL */
			/*
			 *	Fallthrough?
			 */
			if (!fallthrough(pl->reply))
				break;
		}
	}

	/*
	 *	See if we succeeded.
	 */
	if (!found)
		return RLM_MODULE_NOOP; /* on to the next module */

	/*
	 *	FIXME: log a warning if there are any reply items other than
	 *	Fallthrough
	 */
	pairfree(&reply_pairs); /* Don't need these */

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
	pairlist_free(&inst->acctusers);
	return 0;
}

/*
 *	This function is unused
 */
static int fastuser_accounting(void *instance UNUSED, REQUEST *request UNUSED)
{
	/*
	 * FIXME: should re rather return RLM_MODULE_NOOP here?
	 */
	return RLM_MODULE_FAIL;
}

/* globally exported name */
module_t rlm_fastusers = {
	RLM_MODULE_INIT,
	"fastusers",
	0,				/* type: reserved */
	fastuser_instantiate,		/* instantiation */
	fastuser_detach,		/* detach */
	{
		fastuser_authenticate,	/* authentication */
		fastuser_authorize,	/* authorization */
		fastuser_preacct,	/* preaccounting */
		fastuser_accounting,	/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};

