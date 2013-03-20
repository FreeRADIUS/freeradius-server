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
 * @file rlm_files.c
 * @brief Process simple 'users' policy files.
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Jeff Carneal <jeff@apex.net>
 */
#include	<freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>

#include	<ctype.h>
#include	<fcntl.h>
#include	<limits.h>

struct file_instance {
	char *compat_mode;

	char *key;

	/* autz */
	char *usersfile;
	fr_hash_table_t *users;


	/* authenticate */
	char *auth_usersfile;
	fr_hash_table_t *auth_users;

	/* preacct */
	char *acctusersfile;
	fr_hash_table_t *acctusers;

#ifdef WITH_PROXY
	/* pre-proxy */
	char *preproxy_usersfile;
	fr_hash_table_t *preproxy_users;

	/* post-proxy */
	char *postproxy_usersfile;
	fr_hash_table_t *postproxy_users;
#endif

	/* post-authenticate */
	char *postauth_usersfile;
	fr_hash_table_t *postauth_users;
};


/*
 *     See if a VALUE_PAIR list contains Fall-Through = Yes
 */
static int fallthrough(VALUE_PAIR *vp)
{
	VALUE_PAIR *tmp;
	tmp = pairfind(vp, PW_FALL_THROUGH, 0, TAG_ANY);

	return tmp ? tmp->vp_integer : 0;
}

static const CONF_PARSER module_config[] = {
	{ "usersfile",	   PW_TYPE_FILENAME,
	  offsetof(struct file_instance,usersfile), NULL, NULL },
	{ "acctusersfile", PW_TYPE_FILENAME,
	  offsetof(struct file_instance,acctusersfile), NULL, NULL },
#ifdef WITH_PROXY
	{ "preproxy_usersfile", PW_TYPE_FILENAME,
	  offsetof(struct file_instance,preproxy_usersfile), NULL, NULL },
	{ "postproxy_usersfile", PW_TYPE_FILENAME,
	  offsetof(struct file_instance,postproxy_usersfile), NULL, NULL },
#endif
	{ "auth_usersfile", PW_TYPE_FILENAME,
	  offsetof(struct file_instance,auth_usersfile), NULL, NULL },
	{ "postauth_usersfile", PW_TYPE_FILENAME,
	  offsetof(struct file_instance,postauth_usersfile), NULL, NULL },
	{ "compat",	   PW_TYPE_STRING_PTR,
	  offsetof(struct file_instance,compat_mode), NULL, "cistron" },
	{ "key",	   PW_TYPE_STRING_PTR,
	  offsetof(struct file_instance,key), NULL, NULL },
	{ NULL, -1, 0, NULL, NULL }
};


static uint32_t pairlist_hash(const void *data)
{
	return fr_hash_string(((const PAIR_LIST *)data)->name);
}

static int pairlist_cmp(const void *a, const void *b)
{
	return strcmp(((const PAIR_LIST *)a)->name,
		      ((const PAIR_LIST *)b)->name);
}

static void my_pairlist_free(void *data)
{
	PAIR_LIST *pl = data;

	pairlist_free(&pl);
}


static int getusersfile(const char *filename, fr_hash_table_t **pht,
			char *compat_mode_str)
{
	int rcode;
	PAIR_LIST *users = NULL;
	PAIR_LIST *entry, *next;
	fr_hash_table_t *ht, *tailht;
	int order = 0;

	if (!filename) {
		*pht = NULL;
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
				if (vp->op != T_OP_EQ) {
					continue;
				}

				/*
				 *	If it's a vendor attribute,
				 *	or it's a wire protocol,
				 *	ensure it has '=='.
				 */
				if ((vp->da->vendor != 0) ||
						(vp->da->attr < 0x100)) {
					if (!compat_mode) {
						DEBUGW("[%s]:%d Changing '%s =' to '%s =='\n\tfor comparing RADIUS attribute in check item list for user %s",
								filename, entry->lineno,
								vp->da->name, vp->da->name,
								entry->name);
					} else {
						DEBUG("\tChanging '%s =' to '%s =='",
								vp->da->name, vp->da->name);
					}
					vp->op = T_OP_CMP_EQ;
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
					if ((vp->da->attr >= 0x100) &&
							(vp->da->attr <= 0xffff) &&
							(vp->da->attr != PW_HINT) &&
							(vp->da->attr != PW_HUNTGROUP_NAME)) {
						DEBUG("\tChanging '%s =' to '%s +='",
								vp->da->name, vp->da->name);
						vp->op = T_OP_ADD;
					} else {
						DEBUG("\tChanging '%s =' to '%s =='",
								vp->da->name, vp->da->name);
						vp->op = T_OP_CMP_EQ;
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
				 if ((vp->da->vendor == 0) &&
					(vp->da->attr > 0xff) &&
					(vp->da->attr > 1000)) {
					log_debug("[%s]:%d WARNING! Check item \"%s\"\n"
							"\tfound in reply item list for user \"%s\".\n"
							"\tThis attribute MUST go on the first line"
							" with the other check items",
							filename, entry->lineno, vp->da->name,
							entry->name);
				}
			}

			entry = entry->next;
		}

	}

	ht = fr_hash_table_create(pairlist_hash, pairlist_cmp,
				    my_pairlist_free);
	if (!ht) {
		pairlist_free(&users);
		return -1;
	}

	tailht = fr_hash_table_create(pairlist_hash, pairlist_cmp,
					NULL);
	if (!tailht) {
		fr_hash_table_free(ht);
		pairlist_free(&users);
		return -1;
	}

	/*
	 *	Now that we've read it in, put the entries into a hash
	 *	for faster access.
	 */
	for (entry = users; entry != NULL; entry = next) {
		PAIR_LIST *tail;

		next = entry->next;
		entry->next = NULL;
		entry->order = order++;

		/*
		 *	Insert it into the hash table, and remember
		 *	the tail of the linked list.
		 */
		tail = fr_hash_table_finddata(tailht, entry);
		if (!tail) {
			/*
			 *	Insert it into the head & tail.
			 */
			if (!fr_hash_table_insert(ht, entry) ||
			    !fr_hash_table_insert(tailht, entry)) {
				pairlist_free(&next);
				fr_hash_table_free(ht);
				fr_hash_table_free(tailht);
				return -1;
			}
		} else {
			tail->next = entry;
			if (!fr_hash_table_replace(tailht, entry)) {
				pairlist_free(&next);
				fr_hash_table_free(ht);
				fr_hash_table_free(tailht);
				return -1;
			}
		}
	}

	fr_hash_table_free(tailht);
	*pht = ht;

	return 0;
}

/*
 *	Clean up.
 */
static int mod_detach(void *instance)
{
	struct file_instance *inst = instance;
	fr_hash_table_free(inst->users);
	fr_hash_table_free(inst->acctusers);
#ifdef WITH_PROXY
	fr_hash_table_free(inst->preproxy_users);
	fr_hash_table_free(inst->postproxy_users);
#endif
	fr_hash_table_free(inst->auth_users);
	fr_hash_table_free(inst->postauth_users);
	return 0;
}



/*
 *	(Re-)read the "users" file into memory.
 */
static int mod_instantiate(CONF_SECTION *conf, void **instance)
{
	struct file_instance *inst;
	int rcode;

	*instance = inst = talloc_zero(conf, struct file_instance);
	if (!inst) return -1;

	if (cf_section_parse(conf, inst, module_config) < 0) {
		return -1;
	}

	rcode = getusersfile(inst->usersfile, &inst->users, inst->compat_mode);
	if (rcode != 0) {
	  radlog(L_ERR, "Errors reading %s", inst->usersfile);
		mod_detach(inst);
		return -1;
	}

	rcode = getusersfile(inst->acctusersfile, &inst->acctusers, inst->compat_mode);
	if (rcode != 0) {
		radlog(L_ERR, "Errors reading %s", inst->acctusersfile);
		mod_detach(inst);
		return -1;
	}

#ifdef WITH_PROXY
	/*
	 *  Get the pre-proxy stuff
	 */
	rcode = getusersfile(inst->preproxy_usersfile, &inst->preproxy_users, inst->compat_mode);
	if (rcode != 0) {
		radlog(L_ERR, "Errors reading %s", inst->preproxy_usersfile);
		mod_detach(inst);
		return -1;
	}

	rcode = getusersfile(inst->postproxy_usersfile, &inst->postproxy_users, inst->compat_mode);
	if (rcode != 0) {
		radlog(L_ERR, "Errors reading %s", inst->postproxy_usersfile);
		mod_detach(inst);
		return -1;
	}
#endif

	rcode = getusersfile(inst->auth_usersfile, &inst->auth_users, inst->compat_mode);
	if (rcode != 0) {
		radlog(L_ERR, "Errors reading %s", inst->auth_usersfile);
		mod_detach(inst);
		return -1;
	}

	rcode = getusersfile(inst->postauth_usersfile, &inst->postauth_users, inst->compat_mode);
	if (rcode != 0) {
		radlog(L_ERR, "Errors reading %s", inst->postauth_usersfile);
		mod_detach(inst);
		return -1;
	}

	*instance = inst;
	return 0;
}

/*
 *	Common code called by everything below.
 */
static rlm_rcode_t file_common(struct file_instance *inst, REQUEST *request,
		       const char *filename, fr_hash_table_t *ht,
		       VALUE_PAIR *request_pairs, VALUE_PAIR **reply_pairs)
{
	const char	*name, *match;
	VALUE_PAIR	*check_tmp;
	VALUE_PAIR	*reply_tmp;
	const PAIR_LIST	*user_pl, *default_pl;
	int		found = 0;
	PAIR_LIST	my_pl;
	char		buffer[256];

	if (!inst->key) {
		VALUE_PAIR	*namepair;

		namepair = request->username;
		name = namepair ? (char *) namepair->vp_strvalue : "NONE";
	} else {
		int len;

		len = radius_xlat(buffer, sizeof(buffer), inst->key,
				  request, NULL, NULL);
		if (len) name = buffer;
		else name = "NONE";
	}

	if (!ht) return RLM_MODULE_NOOP;

	my_pl.name = name;
	user_pl = fr_hash_table_finddata(ht, &my_pl);
	my_pl.name = "DEFAULT";
	default_pl = fr_hash_table_finddata(ht, &my_pl);

	/*
	 *	Find the entry for the user.
	 */
	while (user_pl || default_pl) {
		const PAIR_LIST *pl;

		if (!default_pl && user_pl) {
			pl = user_pl;
			match = name;
			user_pl = user_pl->next;

		} else if (!user_pl && default_pl) {
			pl = default_pl;
			match = "DEFAULT";
			default_pl = default_pl->next;

		} else if (user_pl->order < default_pl->order) {
			pl = user_pl;
			match = name;
			user_pl = user_pl->next;

		} else {
			pl = default_pl;
			match = "DEFAULT";
			default_pl = default_pl->next;
		}

		if (paircompare(request, request_pairs, pl->check, reply_pairs) == 0) {
			RDEBUG2("%s: Matched entry %s at line %d",
			       filename, match, pl->lineno);
			found = 1;
			check_tmp = paircopy(request, pl->check);

			/* ctx may be reply or proxy */
			reply_tmp = paircopy(request, pl->reply);
			radius_xlat_move(request, reply_pairs, &reply_tmp);
			pairmove(request, &request->config_items, &check_tmp);
			pairfree(&reply_tmp);
			pairfree(&check_tmp);

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
	pairdelete(reply_pairs, PW_FALL_THROUGH, 0, TAG_ANY);

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
static rlm_rcode_t mod_authorize(void *instance, REQUEST *request)
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
static rlm_rcode_t mod_preacct(void *instance, REQUEST *request)
{
	struct file_instance *inst = instance;

	return file_common(inst, request, "acct_users", inst->acctusers,
			   request->packet->vps, &request->reply->vps);
}

#ifdef WITH_PROXY
static rlm_rcode_t file_preproxy(void *instance, REQUEST *request)
{
	struct file_instance *inst = instance;

	return file_common(inst, request, "preproxy_users",
			   inst->preproxy_users,
			   request->packet->vps, &request->proxy->vps);
}

static rlm_rcode_t file_postproxy(void *instance, REQUEST *request)
{
	struct file_instance *inst = instance;

	return file_common(inst, request, "postproxy_users",
			   inst->postproxy_users,
			   request->proxy_reply->vps, &request->reply->vps);
}
#endif

static rlm_rcode_t mod_authenticate(void *instance, REQUEST *request)
{
	struct file_instance *inst = instance;

	return file_common(inst, request, "auth_users",
			   inst->auth_users,
			   request->packet->vps, &request->reply->vps);
}

static rlm_rcode_t mod_post_auth(void *instance, REQUEST *request)
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
	RLM_TYPE_CHECK_CONFIG_SAFE | RLM_TYPE_HUP_SAFE,
	mod_instantiate,		/* instantiation */
	mod_detach,			/* detach */
	{
		mod_authenticate,	/* authentication */
		mod_authorize, 	/* authorization */
		mod_preacct,		/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
#ifdef WITH_PROXY
		file_preproxy,		/* pre-proxy */
		file_postproxy,		/* post-proxy */
#else
		NULL, NULL,
#endif
		mod_post_auth		/* post-auth */
	},
};

