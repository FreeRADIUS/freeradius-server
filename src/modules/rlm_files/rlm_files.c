/*
 * rlm_files.c	authorization: Find a user in the "users" file.
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
 * Copyright 2002  The FreeRADIUS server project
 * Copyright 2000  Jeff Carneal <jeff@apex.net>
 */

static const char rcsid[] = "$Id$";

#include	<freeradius-devel/autoconf.h>

#include	<sys/stat.h>

#include	<stdlib.h>
#include	<string.h>
#include	<netdb.h>
#include	<ctype.h>
#include	<fcntl.h>
#include	<limits.h>

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>

struct file_instance {
	char *compat_mode;

	/* autz */
	char *usersfile;
	PAIR_LIST *users;

	/* preacct */
	char *acctusersfile;
	PAIR_LIST *acctusers;

	/* pre-proxy */
	char *preproxy_usersfile;
	PAIR_LIST *preproxy_users;

	/* authenticate */
	char *auth_usersfile;
	PAIR_LIST *auth_users;

	/* post-proxy */
	char *postproxy_usersfile;
	PAIR_LIST *postproxy_users;

	/* post-authenticate */
	char *postauth_usersfile;
	PAIR_LIST *postauth_users;
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

static const CONF_PARSER module_config[] = {
	{ "usersfile",	   PW_TYPE_FILENAME,
	  offsetof(struct file_instance,usersfile), NULL, NULL },
	{ "acctusersfile", PW_TYPE_FILENAME,
	  offsetof(struct file_instance,acctusersfile), NULL, NULL },
	{ "preproxy_usersfile", PW_TYPE_FILENAME,
	  offsetof(struct file_instance,preproxy_usersfile), NULL, NULL },
	{ "auth_usersfile", PW_TYPE_FILENAME,
	  offsetof(struct file_instance,auth_usersfile), NULL, NULL },
	{ "postproxy_usersfile", PW_TYPE_FILENAME,
	  offsetof(struct file_instance,postproxy_usersfile), NULL, NULL },
	{ "postauth_usersfile", PW_TYPE_FILENAME,
	  offsetof(struct file_instance,postauth_usersfile), NULL, NULL },
	{ "compat",	   PW_TYPE_STRING_PTR,
	  offsetof(struct file_instance,compat_mode), NULL, "cistron" },
	{ NULL, -1, 0, NULL, NULL }
};

static int getusersfile(const char *filename, PAIR_LIST **pair_list, char *compat_mode_str)
{
	int rcode;
	PAIR_LIST *users = NULL;

	if (!filename) {
		*pair_list = NULL;
		return 0;
	}

	rcode = pairlist_read(filename, &users, 1);
	if (rcode < 0) {
		return -1;
	}

	/*
	 *	Walk through the 'users' file list, if we're debugging,
	 *	or if we're in compat_mode.
	 */
	if ((debug_flag) ||
	    (strcmp(compat_mode_str, "cistron") == 0)) {
		PAIR_LIST *entry;
		VALUE_PAIR *vp;
		int compat_mode = FALSE;

		if (strcmp(compat_mode_str, "cistron") == 0) {
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
 *	Clean up.
 */
static int file_detach(void *instance)
{
	struct file_instance *inst = instance;
	pairlist_free(&inst->users);
	pairlist_free(&inst->acctusers);
	pairlist_free(&inst->preproxy_users);
	pairlist_free(&inst->auth_users);
	pairlist_free(&inst->postproxy_users);
	pairlist_free(&inst->postauth_users);
	free(inst->usersfile);
	free(inst->acctusersfile);
	free(inst->preproxy_usersfile);
	free(inst->auth_usersfile);
	free(inst->postproxy_usersfile);
	free(inst->postauth_usersfile);
	free(inst->compat_mode);
	free(inst);
	return 0;
}



/*
 *	(Re-)read the "users" file into memory.
 */
static int file_instantiate(CONF_SECTION *conf, void **instance)
{
	struct file_instance *inst;
	int rcode;

	inst = rad_malloc(sizeof *inst);
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}

	rcode = getusersfile(inst->usersfile, &inst->users, inst->compat_mode);
	if (rcode != 0) {
		radlog(L_ERR|L_CONS, "Errors reading %s", inst->usersfile);
		file_detach(inst);
		return -1;
	}

	rcode = getusersfile(inst->acctusersfile, &inst->acctusers, inst->compat_mode);
	if (rcode != 0) {
		radlog(L_ERR|L_CONS, "Errors reading %s", inst->acctusersfile);
		file_detach(inst);
		return -1;
	}

	/*
	 *  Get the pre-proxy stuff
	 */
	rcode = getusersfile(inst->preproxy_usersfile, &inst->preproxy_users, inst->compat_mode);
	if (rcode != 0) {
		radlog(L_ERR|L_CONS, "Errors reading %s", inst->preproxy_usersfile);
		file_detach(inst);
		return -1;
	}

	rcode = getusersfile(inst->auth_usersfile, &inst->auth_users, inst->compat_mode);
	if (rcode != 0) {
		radlog(L_ERR|L_CONS, "Errors reading %s", inst->auth_usersfile);
		file_detach(inst);
		return -1;
	}

	rcode = getusersfile(inst->postproxy_usersfile, &inst->postproxy_users, inst->compat_mode);
	if (rcode != 0) {
		radlog(L_ERR|L_CONS, "Errors reading %s", inst->postproxy_usersfile);
		file_detach(inst);
		return -1;
	}

	rcode = getusersfile(inst->postauth_usersfile, &inst->postauth_users, inst->compat_mode);
	if (rcode != 0) {
		radlog(L_ERR|L_CONS, "Errors reading %s", inst->postauth_usersfile);
		file_detach(inst);
		return -1;
	}

	*instance = inst;
	return 0;
}

/*
 *	Common code called by everything below.
 */
static int file_common(struct file_instance *inst, REQUEST *request,
		       const char *filename, const PAIR_LIST *list,
		       VALUE_PAIR *request_pairs, VALUE_PAIR **reply_pairs)
{
	VALUE_PAIR	*namepair;
	const char	*name;
	VALUE_PAIR	**config_pairs;
	VALUE_PAIR	*check_tmp;
	VALUE_PAIR	*reply_tmp;
	const PAIR_LIST	*pl;
	int		found = 0;

	inst = inst;		/* -Wunused fix later? */

	namepair = request->username;
	name = namepair ? (char *) namepair->vp_strvalue : "NONE";
	config_pairs = &request->config_items;

	if (!list) return RLM_MODULE_NOOP;

	/*
	 *	Find the entry for the user.
	 */
	for (pl = list; pl; pl = pl->next) {
		if (strcmp(name, pl->name) && strcmp(pl->name, "DEFAULT"))
			continue;

		if (paircompare(request, request_pairs, pl->check, reply_pairs) == 0) {
			DEBUG2("    %s: Matched entry %s at line %d",
			       filename, pl->name, pl->lineno);
			found = 1;
			check_tmp = paircopy(pl->check);
			reply_tmp = paircopy(pl->reply);
			pairxlatmove(request, reply_pairs, &reply_tmp);
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
	 *	Remove server internal parameters.
	 */
	pairdelete(reply_pairs, PW_FALL_THROUGH);

	/*
	 *	See if we succeeded.
	 */
	if (!found)
		return RLM_MODULE_NOOP; /* on to the next module */

	return RLM_MODULE_OK;

}


/*
 *	Find the named user in the database.  Create the
 *	set of attribute-value pairs to check and reply with
 *	for this user from the database. The main code only
 *	needs to check the password, the rest is done here.
 */
static int file_authorize(void *instance, REQUEST *request)
{
	struct file_instance *inst = instance;

	return file_common(inst, request, "users", inst->users,
			   request->packet->vps, &request->reply->vps);
}


/*
 *	Pre-Accounting - read the acct_users file for check_items and
 *	config_items. Reply items are Not Recommended(TM) in acct_users,
 *	except for Fallthrough, which should work
 */
static int file_preacct(void *instance, REQUEST *request)
{
	struct file_instance *inst = instance;

	return file_common(inst, request, "acct_users", inst->acctusers,
			   request->packet->vps, &request->reply->vps);
}

static int file_preproxy(void *instance, REQUEST *request)
{
	struct file_instance *inst = instance;

	return file_common(inst, request, "preproxy_users",
			   inst->preproxy_users,
			   request->packet->vps, &request->proxy->vps);
}

static int file_postproxy(void *instance, REQUEST *request)
{
	struct file_instance *inst = instance;

	return file_common(inst, request, "postproxy_users",
			   inst->postproxy_users,
			   request->proxy_reply->vps, &request->reply->vps);
}

static int file_authenticate(void *instance, REQUEST *request)
{
	struct file_instance *inst = instance;

	return file_common(inst, request, "auth_users",
			   inst->auth_users,
			   request->packet->vps, &request->reply->vps);
}

static int file_postauth(void *instance, REQUEST *request)
{
	struct file_instance *inst = instance;

	return file_common(inst, request, "postauth_users",
			   inst->postauth_users,
			   request->packet->vps, &request->reply->vps);
}


/* globally exported name */
module_t rlm_files = {
	RLM_MODULE_INIT,
	"files",
	0,				/* type: reserved */
	file_instantiate,		/* instantiation */
	file_detach,			/* detach */
	{
		file_authenticate,	/* authentication */
		file_authorize, 	/* authorization */
		file_preacct,		/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		file_preproxy,		/* pre-proxy */
		file_postproxy,		/* post-proxy */
		file_postauth		/* post-auth */
	},
};

