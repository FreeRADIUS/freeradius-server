/*
 * rlm_files.c	authorization: Find a user in the "users" file.
 *		accounting:    Write the "detail" files.
 *
 * Version:	$Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	"radiusd.h"

#include	<sys/stat.h>

#include	<stdlib.h>
#include	<string.h>
#include	<netdb.h>
#include	<ctype.h>
#include	<fcntl.h>
#include        <limits.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"modules.h"

struct file_instance {
	char *compat_mode;

        /* autz */
        char *usersfile;
        PAIR_LIST *users;

        /* preacct */
        char *acctusersfile;
        PAIR_LIST *acctusers;
};

/*
 *     See if a VALUE_PAIR list contains Fall-Through = Yes
 */
static int fallthrough(VALUE_PAIR *vp)
{
	VALUE_PAIR *tmp;

	tmp = pairfind(vp, PW_FALL_THROUGH);

	return tmp ? tmp->lvalue : 0;
}

/*
 *	A temporary holding area for config values to be extracted
 *	into, before they are copied into the instance data
 */
static struct file_instance config;

static CONF_PARSER module_config[] = {
        { "usersfile",     PW_TYPE_STRING_PTR, &config.usersfile, "${raddbdir}/users" },
        { "acctusersfile", PW_TYPE_STRING_PTR, &config.acctusersfile, "${raddbdir}/acct_users" },
	{ "compat",        PW_TYPE_STRING_PTR, &config.compat_mode, "cistron" },
	{ NULL, -1, NULL, NULL }
};

static int getusersfile(const char *filename, PAIR_LIST **pair_list)
{
	int rcode;
        PAIR_LIST *users = NULL;

	rcode = pairlist_read(filename, &users, 1);
	if (rcode < 0) {
		return -1;
	}

        /*
         *	Walk through the 'users' file list, if we're debugging,
	 *	or if we're in compat_mode.
         */
        if ((debug_flag) ||
	    (strcmp(config.compat_mode, "cistron") == 0)) {
                PAIR_LIST *entry;
                VALUE_PAIR *vp;
		int compat_mode = FALSE;

		if (strcmp(config.compat_mode, "cistron") == 0) {
			compat_mode = TRUE;
		}
        
                entry = users;
                while (entry) {
			if (compat_mode) {
				DEBUG("[%s]:%d Cistron compatibility checks for entry %s ...",
				      filename, entry->lineno,
				      entry->name);
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
                                if (vp->operator != T_OP_EQ) {
                                        continue;
                                }

                                /*
                                 *	If it's a vendor attribute,
                                 *	or it's a wire protocol, 
                                 *	ensure it has '=='.
                                 */
                                if (((vp->attribute & ~0xffff) != 0) ||
                                    (vp->attribute < 0x100)) {
					if (!compat_mode) {
						DEBUG("[%s]:%d WARNING! Changing '%s =' to '%s =='\n\tfor comparing RADIUS attribute in check item list for user %s",
						      filename, entry->lineno,
						      vp->name, vp->name,
						      entry->name);
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
                
                        entry = entry->next;
                }
        
        }

	*pair_list = users;
        return 0;
}

/*
 *	(Re-)read the "users" file into memory.
 */
static int file_instantiate(CONF_SECTION *conf, void **instance)
{
        struct file_instance *inst;
	int rcode;

        inst = malloc(sizeof *inst);
        if (!inst) {
                radlog(L_ERR|L_CONS, "Out of memory\n");
                return -1;
        }

        if (cf_section_parse(conf, module_config) < 0) {
                free(inst);
                return -1;
        }

        inst->usersfile = config.usersfile;
        inst->acctusersfile = config.acctusersfile;
        config.usersfile = NULL;
        config.acctusersfile = NULL;

	rcode = getusersfile(inst->usersfile, &inst->users);
        if (rcode != 0) {
                radlog(L_ERR|L_CONS, "Errors reading %s", inst->usersfile);
                free(inst->usersfile);
                free(inst->acctusersfile);
                free(inst);
                return -1;
        }

	rcode = getusersfile(inst->acctusersfile, &inst->acctusers);
        if (rcode != 0) {
                radlog(L_ERR|L_CONS, "Errors reading %s", inst->acctusersfile);
                pairlist_free(&inst->users);
                free(inst->usersfile);
                free(inst->acctusersfile);
                free(inst);
                return -1;
        }

        *instance = inst;
        return 0;
}

/*
 *	Find the named user in the database.  Create the
 *	set of attribute-value pairs to check and reply with
 *	for this user from the database. The main code only
 *	needs to check the password, the rest is done here.
 */
static int file_authorize(void *instance, REQUEST *request)
{
	VALUE_PAIR	*namepair;
	VALUE_PAIR	*request_pairs;
	VALUE_PAIR	*check_tmp;
	VALUE_PAIR	*reply_tmp;
	PAIR_LIST	*pl;
	int		found = 0;
	const char	*name;
	struct file_instance *inst = instance;
	VALUE_PAIR **check_pairs, **reply_pairs;
	VALUE_PAIR *check_save;

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
	for(pl = inst->users; pl; pl = pl->next) {
		/*
		 *	If the current entry is NOT a default,
		 *	AND the name does NOT match the current entry,
		 *	then skip to the next entry.
		 */
		if ((strcmp(pl->name, "DEFAULT") != 0) &&
		    (strcmp(name, pl->name) != 0))  {
			continue;
		}

		/*
		 *	If the current request matches against the
		 *	check pairs, then add the reply pairs from the
		 *	entry to the current list of reply pairs.
		 */
		if ((paircmp(request_pairs, pl->check, reply_pairs) == 0)) {

			if((mainconfig.do_usercollide) && (strcmp(pl->name, "DEFAULT"))) {

				/* 
				 * We have to make sure the password
				 * matches as well
				 */
	
				/* Save the orginal config items */
				check_save = paircopy(request->config_items);
	
				/* Copy this users check pairs to the request */
				check_tmp = paircopy(pl->check);
				pairmove(check_pairs, &check_tmp);
				pairfree(&check_tmp);
	
				DEBUG2("  users: Checking %s at %d", pl->name, pl->lineno);
				/* Check the req to see if we matched */
				if (rad_check_password(request)==0) {
					DEBUG2("  users: Matched %s at %d", pl->name, pl->lineno);

					found = 1;

					/* Free our saved config items */
					pairfree(&check_save);

					/* 
					 * Already copied check items, so 
					 * just copy reply here
					 */
					reply_tmp = paircopy(pl->reply);
					pairmove(reply_pairs, &reply_tmp);
					pairfree(&reply_tmp);

				/* We didn't match here */
				} else {
					/* Restore check items */
					pairfree(&request->config_items);
					request->config_items = paircopy(check_save);
					check_pairs = &request->config_items;
					continue;
				}
	
			/* No usercollide */
			} else {
		
				DEBUG2("  users: Matched %s at %d", pl->name, pl->lineno);
				found = 1;
				check_tmp = paircopy(pl->check);
				reply_tmp = paircopy(pl->reply);
				pairmove(reply_pairs, &reply_tmp);
				pairmove(check_pairs, &check_tmp);
				pairfree(&reply_tmp);
				pairfree(&check_tmp); /* should be NULL */
			}
			/*
			 *	Fallthrough?
			 */
			if (!fallthrough(pl->reply))
				break;
		}
	}
	
	/*
	 *	See if we succeeded.  If we didn't find the user,
	 *	then exit from the module.
	 */
	if (!found)
		return RLM_MODULE_NOTFOUND;

	/*
	 *	Remove server internal parameters.
	 */
	pairdelete(reply_pairs, PW_FALL_THROUGH);

	return RLM_MODULE_OK;
}

/*
 *	Pre-Accounting - read the acct_users file for check_items and
 *	config_items. Reply items are Not Recommended(TM) in acct_users,
 *	except for Fallthrough, which should work
 *
 *	This function is mostly a copy of file_authorize
 */
static int file_preacct(void *instance, REQUEST *request)
{
	VALUE_PAIR	*namepair;
	const char	*name;
	VALUE_PAIR	*request_pairs;
	VALUE_PAIR	**config_pairs;
	VALUE_PAIR	*reply_pairs = NULL;
	VALUE_PAIR	*check_tmp;
	VALUE_PAIR	*reply_tmp;
	PAIR_LIST	*pl;
	int		found = 0;
	struct file_instance *inst = instance;

	namepair = request->username;
	name = namepair ? (char *) namepair->strvalue : "NONE";
	request_pairs = request->packet->vps;
	config_pairs = &request->config_items;
	
	/*
	 *	Find the entry for the user.
	 */
	for (pl = inst->acctusers; pl; pl = pl->next) {

		if (strcmp(name, pl->name) && strcmp(pl->name, "DEFAULT"))
			continue;

		if (paircmp(request_pairs, pl->check, &reply_pairs) == 0) {
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
 *	Clean up.
 */
static int file_detach(void *instance)
{
        struct file_instance *inst = instance;
        pairlist_free(&inst->users);
        pairlist_free(&inst->acctusers);
        free(inst->usersfile);
        free(inst->acctusersfile);
        free(inst);
	return 0;
}


/* globally exported name */
module_t rlm_files = {
	"files",
	0,				/* type: reserved */
	NULL,				/* initialization */
	file_instantiate,		/* instantiation */
	file_authorize, 		/* authorization */
	NULL,				/* authentication */
	file_preacct,			/* preaccounting */
	NULL,				/* accounting */
	NULL,				/* checksimul */
	file_detach,			/* detach */
	NULL				/* destroy */
};

