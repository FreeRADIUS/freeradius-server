/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>

#include	<ctype.h>
#include	<fcntl.h>

typedef struct rlm_files_t {
	char const *compat_mode;

	char const *key;

	char const *filename;
	rbtree_t *common;

	/* autz */
	char const *usersfile;
	rbtree_t *users;


	/* authenticate */
	char const *auth_usersfile;
	rbtree_t *auth_users;

	/* preacct */
	char const *acctusersfile;
	rbtree_t *acctusers;

#ifdef WITH_PROXY
	/* pre-proxy */
	char const *preproxy_usersfile;
	rbtree_t *preproxy_users;

	/* post-proxy */
	char const *postproxy_usersfile;
	rbtree_t *postproxy_users;
#endif

	/* post-authenticate */
	char const *postauth_usersfile;
	rbtree_t *postauth_users;
} rlm_files_t;


/*
 *     See if a VALUE_PAIR list contains Fall-Through = Yes
 */
static int fall_through(VALUE_PAIR *vp)
{
	VALUE_PAIR *tmp;
	tmp = fr_pair_find_by_num(vp, PW_FALL_THROUGH, 0, TAG_ANY);

	return tmp ? tmp->vp_integer : 0;
}

static const CONF_PARSER module_config[] = {
	{ "filename", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_files_t, filename), NULL },
	{ "usersfile", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_files_t, usersfile), NULL },
	{ "acctusersfile", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_files_t, acctusersfile), NULL },
#ifdef WITH_PROXY
	{ "preproxy_usersfile", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_files_t, preproxy_usersfile), NULL },
	{ "postproxy_usersfile", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_files_t, postproxy_usersfile), NULL },
#endif
	{ "auth_usersfile", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_files_t, auth_usersfile), NULL },
	{ "postauth_usersfile", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_files_t, postauth_usersfile), NULL },
	{ "compat", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, rlm_files_t, compat_mode), NULL },
	{ "key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_files_t, key), NULL },
	CONF_PARSER_TERMINATOR
};


static int pairlist_cmp(void const *a, void const *b)
{
	return strcmp(((PAIR_LIST const *)a)->name,
		      ((PAIR_LIST const *)b)->name);
}

static int getusersfile(TALLOC_CTX *ctx, char const *filename, rbtree_t **ptree, char const *compat_mode_str)
{
	int rcode;
	PAIR_LIST *users = NULL;
	PAIR_LIST *entry, *next;
	PAIR_LIST *user_list, *default_list, **default_tail;
	rbtree_t *tree;

	if (!filename) {
		*ptree = NULL;
		return 0;
	}

	rcode = pairlist_read(ctx, filename, &users, 1);
	if (rcode < 0) {
		return -1;
	}

	/*
	 *	Walk through the 'users' file list, if we're debugging,
	 *	or if we're in compat_mode.
	 */
	if ((rad_debug_lvl) ||
	    (compat_mode_str && (strcmp(compat_mode_str, "cistron") == 0))) {
		VALUE_PAIR *vp;
		bool compat_mode = false;

		if (compat_mode_str && (strcmp(compat_mode_str, "cistron") == 0)) {
			compat_mode = true;
		}

		entry = users;
		while (entry) {
			vp_cursor_t cursor;
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
			for (vp = fr_cursor_init(&cursor, &entry->check); vp; vp = fr_cursor_next(&cursor)) {
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
						WARN("[%s]:%d Changing '%s =' to '%s =='\n\tfor comparing RADIUS attribute in check item list for user %s",
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
						DEBUG("\tChanging '%s =' to '%s +='", vp->da->name, vp->da->name);

						vp->op = T_OP_ADD;
					} else {
						DEBUG("\tChanging '%s =' to '%s =='", vp->da->name, vp->da->name);

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
			for (vp = fr_cursor_init(&cursor, &entry->reply); vp; vp = fr_cursor_next(&cursor)) {
				/*
				 *	If it's NOT a vendor attribute,
				 *	and it's NOT a wire protocol
				 *	and we ignore Fall-Through,
				 *	then bitch about it, giving a
				 *	good warning message.
				 */
				 if ((vp->da->vendor == 0) &&
					(vp->da->attr > 1000)) {
					WARN("[%s]:%d Check item \"%s\"\n"
					       "\tfound in reply item list for user \"%s\".\n"
					       "\tThis attribute MUST go on the first line"
					       " with the other check items", filename, entry->lineno, vp->da->name,
					       entry->name);
				}
			}

			entry = entry->next;
		}
	}

	tree = rbtree_create(ctx, pairlist_cmp, NULL, RBTREE_FLAG_NONE);
	if (!tree) {
		pairlist_free(&users);
		return -1;
	}

	default_list = NULL;
	default_tail = &default_list;

	/*
	 *	We've read the entries in linearly, but putting them
	 *	into an indexed data structure would be much faster.
	 *	Let's go fix that now.
	 */
	for (entry = users; entry != NULL; entry = next) {
		/*
		 *	Remove this entry from the input list.
		 */
		next = entry->next;
		entry->next = NULL;
		(void) talloc_steal(tree, entry);

		/*
		 *	DEFAULT entries get their own list.
		 */
		if (strcmp(entry->name, "DEFAULT") == 0) {
			if (!default_list) {
				default_list = entry;

				/*
				 *	Insert the first DEFAULT into the tree.
				 */
				if (!rbtree_insert(tree, entry)) {
				error:
					pairlist_free(&entry);
					pairlist_free(&next);
					rbtree_free(tree);
					return -1;
				}

			} else {
				/*
				 *	Tack this entry onto the tail
				 *	of the DEFAULT list.
				 */
				*default_tail = entry;
			}

			default_tail = &entry->next;
			continue;
		}

		/*
		 *	Not DEFAULT, must be a normal user.
		 */
		user_list = rbtree_finddata(tree, entry);
		if (!user_list) {
			/*
			 *	Insert the first one.
			 */
			if (!rbtree_insert(tree, entry)) goto error;
		} else {
			/*
			 *	Find the tail of this list, and add it
			 *	there.
			 */
			while (user_list->next) user_list = user_list->next;

			user_list->next = entry;
		}
	}

	*ptree = tree;

	return 0;
}



/*
 *	(Re-)read the "users" file into memory.
 */
static int mod_instantiate(UNUSED CONF_SECTION *conf, void *instance)
{
	rlm_files_t *inst = instance;

#undef READFILE
#define READFILE(_x, _y) do { if (getusersfile(inst, inst->_x, &inst->_y, inst->compat_mode) != 0) { ERROR("Failed reading %s", inst->_x); return -1;} } while (0)

	READFILE(filename, common);
	READFILE(usersfile, users);
	READFILE(acctusersfile, acctusers);

#ifdef WITH_PROXY
	READFILE(preproxy_usersfile, preproxy_users);
	READFILE(postproxy_usersfile, postproxy_users);
#endif

	READFILE(auth_usersfile, auth_users);
	READFILE(postauth_usersfile, postauth_users);

	return 0;
}

/*
 *	Common code called by everything below.
 */
static rlm_rcode_t file_common(rlm_files_t *inst, REQUEST *request, char const *filename, rbtree_t *tree,
			       RADIUS_PACKET *request_packet, RADIUS_PACKET *reply_packet)
{
	char const	*name, *match;
	VALUE_PAIR	*check_tmp;
	VALUE_PAIR	*reply_tmp;
	PAIR_LIST const *user_pl, *default_pl;
	bool		found = false;
	PAIR_LIST	my_pl;
	char		buffer[256];

	if (!inst->key) {
		VALUE_PAIR	*namepair;

		namepair = request->username;
		name = namepair ? namepair->vp_strvalue : "NONE";
	} else {
		int len;

		len = radius_xlat(buffer, sizeof(buffer), request, inst->key, NULL, NULL);
		if (len < 0) {
			return RLM_MODULE_FAIL;
		}

		name = len ? buffer : "NONE";
	}

	if (!tree) return RLM_MODULE_NOOP;

	my_pl.name = name;
	user_pl = rbtree_finddata(tree, &my_pl);
	my_pl.name = "DEFAULT";
	default_pl = rbtree_finddata(tree, &my_pl);

	/*
	 *	Find the entry for the user.
	 */
	while (user_pl || default_pl) {
		vp_cursor_t cursor;
		VALUE_PAIR *vp;
		PAIR_LIST const *pl;

		/*
		 *	Figure out which entry to match on.
		 */

		if (!default_pl && user_pl) {
			pl = user_pl;
			match = name;
			user_pl = user_pl->next;

		} else if (!user_pl && default_pl) {
			pl = default_pl;
			match = "DEFAULT";
			default_pl = default_pl->next;

		} else if (user_pl->lineno < default_pl->lineno) {
			pl = user_pl;
			match = name;
			user_pl = user_pl->next;

		} else {
			pl = default_pl;
			match = "DEFAULT";
			default_pl = default_pl->next;
		}

		check_tmp = fr_pair_list_copy(request, pl->check);
		for (vp = fr_cursor_init(&cursor, &check_tmp);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			if (radius_xlat_do(request, vp) < 0) {
				RWARN("Failed parsing expanded value for check item, skipping entry: %s", fr_strerror());
				fr_pair_list_free(&check_tmp);
				continue;
			}
		}

		if (paircompare(request, request_packet->vps, check_tmp, &reply_packet->vps) == 0) {
			RDEBUG2("%s: Matched entry %s at line %d", filename, match, pl->lineno);
			found = true;

			/* ctx may be reply or proxy */
			reply_tmp = fr_pair_list_copy(reply_packet, pl->reply);
			radius_pairmove(request, &reply_packet->vps, reply_tmp, true);
			fr_pair_list_move(request, &request->config, &check_tmp);
			fr_pair_list_free(&check_tmp);

			/*
			 *	Fallthrough?
			 */
			if (!fall_through(pl->reply))
				break;
		}
	}

	/*
	 *	Remove server internal parameters.
	 */
	fr_pair_delete_by_num(&reply_packet->vps, PW_FALL_THROUGH, 0, TAG_ANY);

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
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
{
	rlm_files_t *inst = instance;

	return file_common(inst, request, "users",
			   inst->users ? inst->users : inst->common,
			   request->packet, request->reply);
}


/*
 *	Pre-Accounting - read the acct_users file for check_items and
 *	config. Reply items are Not Recommended(TM) in acct_users,
 *	except for Fallthrough, which should work
 */
static rlm_rcode_t CC_HINT(nonnull) mod_preacct(void *instance, REQUEST *request)
{
	rlm_files_t *inst = instance;

	return file_common(inst, request, "acct_users",
			   inst->acctusers ? inst->acctusers : inst->common,
			   request->packet, request->reply);
}

#ifdef WITH_PROXY
static rlm_rcode_t CC_HINT(nonnull) mod_pre_proxy(void *instance, REQUEST *request)
{
	rlm_files_t *inst = instance;

	return file_common(inst, request, "preproxy_users",
			   inst->preproxy_users ? inst->preproxy_users : inst->common,
			   request->packet, request->proxy);
}

static rlm_rcode_t CC_HINT(nonnull) mod_post_proxy(void *instance, REQUEST *request)
{
	rlm_files_t *inst = instance;

	return file_common(inst, request, "postproxy_users",
			   inst->postproxy_users ? inst->postproxy_users : inst->common,
			   request->proxy_reply, request->reply);
}
#endif

static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
	rlm_files_t *inst = instance;

	return file_common(inst, request, "auth_users",
			   inst->auth_users ? inst->auth_users : inst->common,
			   request->packet, request->reply);
}

static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST *request)
{
	rlm_files_t *inst = instance;

	return file_common(inst, request, "postauth_users",
			   inst->postauth_users ? inst->postauth_users : inst->common,
			   request->packet, request->reply);
}


/* globally exported name */
extern module_t rlm_files;
module_t rlm_files = {
	.magic		= RLM_MODULE_INIT,
	.name		= "files",
	.type		= RLM_TYPE_HUP_SAFE,
	.inst_size	= sizeof(rlm_files_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PREACCT]		= mod_preacct,

#ifdef WITH_PROXY
		[MOD_PRE_PROXY]		= mod_pre_proxy,
		[MOD_POST_PROXY]	= mod_post_proxy,
#endif
		[MOD_POST_AUTH]		= mod_post_auth
	},
};

