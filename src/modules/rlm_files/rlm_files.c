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
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Jeff Carneal (jeff@apex.net)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/pairmove.h>
#include <freeradius-devel/server/users_file.h>

#include <ctype.h>
#include <fcntl.h>

typedef struct {
	tmpl_t *key;

	char const *filename;
	rbtree_t *common;

	/* autz */
	char const *usersfile;
	rbtree_t *users;


	/* authenticate */
	char const *auth_usersfile;
	rbtree_t *auth_users;

	/* preacct */
	char const *acct_usersfile;
	rbtree_t *acct_users;

	/* post-authenticate */
	char const *postauth_usersfile;
	rbtree_t *postauth_users;
} rlm_files_t;

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_files_dict[];
fr_dict_autoload_t rlm_files_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_fall_through;

extern fr_dict_attr_autoload_t rlm_files_dict_attr[];
fr_dict_attr_autoload_t rlm_files_dict_attr[] = {
	{ .out = &attr_fall_through, .name = "Fall-Through", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },

	{ NULL }
};


static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT, rlm_files_t, filename) },
	{ FR_CONF_OFFSET("usersfile", FR_TYPE_FILE_INPUT, rlm_files_t, usersfile) },
	{ FR_CONF_OFFSET("acctusersfile", FR_TYPE_FILE_INPUT, rlm_files_t, acct_usersfile) },
	{ FR_CONF_OFFSET("auth_usersfile", FR_TYPE_FILE_INPUT, rlm_files_t, auth_usersfile) },
	{ FR_CONF_OFFSET("postauth_usersfile", FR_TYPE_FILE_INPUT, rlm_files_t, postauth_usersfile) },
	{ FR_CONF_OFFSET("key", FR_TYPE_TMPL | FR_TYPE_NOT_EMPTY, rlm_files_t, key), .dflt = "%{%{Stripped-User-Name}:-%{User-Name}}", .quote = T_DOUBLE_QUOTED_STRING },
	CONF_PARSER_TERMINATOR
};


static int pairlist_cmp(void const *a, void const *b)
{
	return strcmp(((PAIR_LIST_LIST const *)a)->name, ((PAIR_LIST_LIST const *)b)->name);
}

static int getusersfile(TALLOC_CTX *ctx, char const *filename, rbtree_t **ptree)
{
	int rcode;
	PAIR_LIST_LIST users;
	PAIR_LIST_LIST search_list;	// Temporary list header used for matching in rbtree
	PAIR_LIST *entry, *next;
	PAIR_LIST_LIST *user_list, *default_list;
	rbtree_t *tree;

	if (!filename) {
		*ptree = NULL;
		return 0;
	}

	pairlist_list_init(&users);
	rcode = pairlist_read(ctx, dict_radius, filename, &users, 1);
	if (rcode < 0) {
		return -1;
	}

	/*
	 *	Walk through the 'users' file list
	 */
	entry = NULL;
	while ((entry = fr_dlist_next(&users.head, entry))) {
		map_t *map = NULL;
		fr_dict_attr_t const *da;
		/*
		 *	Look for improper use of '=' in the
		 *	check items.  They should be using
		 *	'==' for on-the-wire RADIUS attributes,
		 *	and probably ':=' for server
		 *	configuration items.
		 */
		while ((map = fr_dlist_next(&entry->check, map))) {
			if (!tmpl_is_attr(map->lhs)) {
				ERROR("%s[%d] Left side of check item %s is not an attribute",
				      entry->filename, entry->lineno, map->lhs->name);
				return -1;

			}
			da = tmpl_da(map->lhs);

			/*
			 *	Ignore attributes which are set
			 *	properly.
			 */
			if (map->op != T_OP_EQ) {
				continue;
			}

			/*
			 *	If it's a vendor attribute,
			 *	or it's a wire protocol,
			 *	ensure it has '=='.
			 */
			if ((fr_dict_vendor_num_by_da(da) != 0) ||
			    (da->attr < 0x100)) {
				WARN("%s[%d] Changing '%s =' to '%s =='\n\tfor comparing RADIUS attribute in check item list for user %s",
				     entry->filename, entry->lineno,
				     da->name, da->name,
				     entry->name);
				map->op = T_OP_CMP_EQ;
				continue;
			}
		} /* end of loop over check items */

		/*
		 *	Look for server configuration items
		 *	in the reply list.
		 *
		 *	It's a common enough mistake, that it's
		 *	worth doing.
		 */
		map = NULL;
		while ((map = fr_dlist_next(&entry->reply, map))) {
			if (!tmpl_is_attr(map->lhs)) {
				ERROR("%s[%d] Left side of reply item %s is not an attribute",
				      entry->filename, entry->lineno, map->rhs->name);
				return -1;
			}
			da = tmpl_da(map->lhs);

			/*
			 *	If it's NOT a vendor attribute,
			 *	and it's NOT a wire protocol
			 *	and we ignore Fall-Through,
			 *	then bitch about it, giving a
			 *	good warning message.
			 */
			if (fr_dict_attr_is_top_level(da) && (da->attr > 1000)) {
				WARN("%s[%d] Check item \"%s\"\n"
				     "\tfound in reply item list for user \"%s\".\n"
				     "\tThis attribute MUST go on the first line"
				     " with the other check items", entry->filename, entry->lineno, da->name,
				     entry->name);
			}

			/*
			 *	If we allow list qualifiers in
			 *	users_file.c, then this module also
			 *	needs to be updated.  Ensure via an
			 *	assertion that they do not get out of
			 *	sync.
			 */
			fr_assert(tmpl_list(map->lhs) == PAIR_LIST_REPLY);
		}
	}

	tree = rbtree_alloc(ctx, PAIR_LIST_LIST, node, pairlist_cmp, NULL, RBTREE_FLAG_NONE);
	if (!tree) {
		pairlist_free(&users);
		return -1;
	}

	default_list = NULL;

	/*
	 *	We've read the entries in linearly, but putting them
	 *	into an indexed data structure would be much faster.
	 *	Let's go fix that now.
	 */
	for (entry = fr_dlist_head(&users.head); entry != NULL; entry = next) {
		/*
		 *	Remove this entry from the input list.
		 */
		next = fr_dlist_next(&users.head, entry);
		fr_dlist_remove(&users.head, entry);

		/*
		 *	@todo - loop over entry->reply, calling
		 *	unlang_fixup_update() or unlang_fixup_filter()
		 *	to double-check the maps.
		 *
		 *	Those functions do normalization and sanity
		 *	checks which are needed if this module is
		 *	going to call an unlang function to *apply*
		 *	the maps.
		 */

		/*
		 *	DEFAULT entries get their own list.
		 */
		if (strcmp(entry->name, "DEFAULT") == 0) {
			if (!default_list) {
				default_list = talloc_zero(ctx, PAIR_LIST_LIST);
				pairlist_list_init(default_list);
				default_list->name = talloc_strdup(ctx, entry->name);

				/*
				 *	Insert the DEFAULT list into the tree.
				 */
				if (!rbtree_insert(tree, default_list)) {
				error:
					pairlist_free(&users);
					talloc_free(next);
					talloc_free(tree);
					return -1;
				}
			}

			/*
			 *	Append the entry to the DEFAULT list
			 */
			fr_dlist_insert_tail(&default_list->head, entry);
			continue;
		}

		/*
		 *	Not DEFAULT, must be a normal user. First look
		 *	for a matching list header already in the tree.
		 */
		search_list.name = entry->name;
		user_list = rbtree_finddata(tree, &search_list);
		if (!user_list) {
			user_list = talloc_zero(ctx, PAIR_LIST_LIST);
			pairlist_list_init(user_list);
			user_list->name = talloc_strdup(ctx, entry->name);
			/*
			 *	Insert the new list header.
			 */
			if (!rbtree_insert(tree, user_list)) goto error;
		}
		/*
		 *	Append the entry to the user list
		 */
		fr_dlist_insert_tail(&user_list->head, entry);
	}

	*ptree = tree;

	return 0;
}



/*
 *	(Re-)read the "users" file into memory.
 */
static int mod_instantiate(void *instance, UNUSED CONF_SECTION *conf)
{
	rlm_files_t *inst = instance;

#undef READFILE
#define READFILE(_x, _y) do { if (getusersfile(inst, inst->_x, &inst->_y) != 0) { ERROR("Failed reading %s", inst->_x); return -1;} } while (0)

	READFILE(filename, common);
	READFILE(usersfile, users);
	READFILE(acct_usersfile, acct_users);
	READFILE(auth_usersfile, auth_users);
	READFILE(postauth_usersfile, postauth_users);

	return 0;
}

/*
 *	Common code called by everything below.
 */
static unlang_action_t file_common(rlm_rcode_t *p_result, rlm_files_t const *inst,
				   request_t *request, char const *filename, rbtree_t *tree)
{
	char const		*name;
	PAIR_LIST_LIST const	*user_list, *default_list;
	PAIR_LIST const 	*user_pl, *default_pl;
	bool			found = false;
	PAIR_LIST_LIST		my_list;
	char			buffer[256];

	if (tmpl_expand(&name, buffer, sizeof(buffer), request, inst->key, NULL, NULL) < 0) {
		REDEBUG("Failed expanding key %s", inst->key->name);
		RETURN_MODULE_FAIL;
	}

	if (!tree) RETURN_MODULE_NOOP;

	my_list.name = name;
	user_list = rbtree_finddata(tree, &my_list);
	user_pl = (user_list) ? fr_dlist_head(&user_list->head) : NULL;
	my_list.name = "DEFAULT";
	default_list = rbtree_finddata(tree, &my_list);
	default_pl = (default_list) ? fr_dlist_head(&default_list->head) : NULL;

	/*
	 *	Find the entry for the user.
	 */
	while (user_pl || default_pl) {
		fr_pair_t *vp;
		map_t *map = NULL;
		PAIR_LIST const *pl;
		fr_pair_list_t list;
		bool fall_through = false;

		/*
		 *	Figure out which entry to match on.
		 */

		if (!default_pl && user_pl) {
			pl = user_pl;
			user_pl = fr_dlist_next(&user_list->head, user_pl);

		} else if (!user_pl && default_pl) {
			pl = default_pl;
			default_pl = fr_dlist_next(&default_list->head, default_pl);

		} else if (user_pl->order < default_pl->order) {
			pl = user_pl;
			user_pl = fr_dlist_next(&user_list->head, user_pl);

		} else {
			pl = default_pl;
			default_pl = fr_dlist_next(&default_list->head, default_pl);
		}

		fr_pair_list_init(&list);

		/*
		 *	Realize the map to a list of VPs
		 *
		 *	@todo convert the pl->check to fr_cond_t, and just use that!
		 */
		while ((map = fr_dlist_next(&pl->check, map))) {
			fr_pair_list_t tmp_list;
			fr_pair_list_init(&tmp_list);
			if (map_to_vp(request->control_ctx, &tmp_list, request, map, NULL) < 0) {
				fr_pair_list_free(&list);
				RPWARN("Failed parsing map for check item, skipping entry");
				break;
			}
			LIST_VERIFY(&tmp_list);

			fr_tmp_pair_list_move(&list, &tmp_list);
		}

		if (paircmp(request, &request->request_pairs, &list) != 0) {
			fr_pair_list_free(&list);
			continue;
		}

		RDEBUG2("Found match \"%s\" on line %d of %s", pl->name, pl->lineno, filename);
		found = true;
		fall_through = false;

		/*
		 *	Move the control items over, too.
		 */
		fr_pair_list_move(&request->control_pairs, &list);
		fr_pair_list_free(&list);

		/* ctx may be reply */
		if (!fr_dlist_empty(&pl->reply)) {
			map = NULL;
			while ((map = fr_dlist_next(&pl->reply, map))) {
				fr_pair_list_t tmp_list;
				fr_pair_list_init(&tmp_list);
				if (map->op == T_OP_CMP_FALSE) continue;

				if (map_to_vp(request->reply_ctx, &tmp_list, request, map, NULL) < 0) {
					RPWARN("Failed parsing map for reply item %s, skipping it", map->rhs->name);
					break;
				}

				/*
				 *	Check for Fall-Through in the
				 *	reply list.  If so, don't copy
				 *	the attribute over to the reply
				 */
				vp = fr_pair_list_head(&tmp_list);
				if (vp->da == attr_fall_through) {
					fall_through = vp->vp_bool;
					fr_pair_list_free(&tmp_list);
					continue;
				}

				radius_pairmove(request, &request->reply_pairs, &tmp_list, true);
			}
		}

		/*
		 *	Fallthrough?
		 */
		if (!fall_through) break;
	}

	/*
	 *	See if we succeeded.
	 */
	if (!found)
		RETURN_MODULE_NOOP; /* on to the next module */

	RETURN_MODULE_OK;

}


/*
 *	Find the named user in the database.  Create the
 *	set of attribute-value pairs to check and reply with
 *	for this user from the database. The main code only
 *	needs to check the password, the rest is done here.
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_files_t const *inst = talloc_get_type_abort_const(mctx->instance, rlm_files_t);

	return file_common(p_result, inst, request, inst->filename,
			   inst->users ? inst->users : inst->common);
}


/*
 *	Pre-Accounting - read the acct_users file for check_items and
 *	config. Reply items are Not Recommended(TM) in acct_users,
 *	except for Fallthrough, which should work
 */
static unlang_action_t CC_HINT(nonnull) mod_preacct(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_files_t const *inst = talloc_get_type_abort_const(mctx->instance, rlm_files_t);

	return file_common(p_result, inst, request, inst->acct_usersfile,
			   inst->acct_users ? inst->acct_users : inst->common);
}

static unlang_action_t CC_HINT(nonnull) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_files_t const *inst = talloc_get_type_abort_const(mctx->instance, rlm_files_t);

	return file_common(p_result, inst, request, inst->auth_usersfile,
			   inst->auth_users ? inst->auth_users : inst->common);
}

static unlang_action_t CC_HINT(nonnull) mod_post_auth(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_files_t const *inst = talloc_get_type_abort_const(mctx->instance, rlm_files_t);

	return file_common(p_result, inst, request, inst->postauth_usersfile,
			   inst->postauth_users ? inst->postauth_users : inst->common);
}


/* globally exported name */
extern module_t rlm_files;
module_t rlm_files = {
	.magic		= RLM_MODULE_INIT,
	.name		= "files",
	.inst_size	= sizeof(rlm_files_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PREACCT]		= mod_preacct,
		[MOD_POST_AUTH]		= mod_post_auth
	},
	.method_names = (module_method_names_t[]){
		/*
		 * Use mod_authorize for all DHCP processing - for consistent
		 * use of data in the file referenced by "filename"
		 */
		{ .name1 = "recv",	.name2 = "Discover",	.method = mod_authorize },
		{ .name1 = "recv",	.name2 = "Request",	.method = mod_authorize },
		{ .name1 = "recv",	.name2 = "Inform",	.method = mod_authorize },
		{ .name1 = "recv",	.name2 = "Release",	.method = mod_authorize },
		{ .name1 = "recv",	.name2 = "Decline",	.method = mod_authorize },

		MODULE_NAME_TERMINATOR
	}

};
