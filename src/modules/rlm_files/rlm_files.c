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
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/pairmove.h>
#include <freeradius-devel/server/users_file.h>
#include <freeradius-devel/util/htrie.h>

#include <ctype.h>
#include <fcntl.h>

typedef struct {
	tmpl_t *key;
	fr_type_t	key_data_type;

	char const *filename;
	fr_htrie_t *common;
	PAIR_LIST_LIST *common_def;

	/* autz */
	char const *usersfile;
	fr_htrie_t *users;
	PAIR_LIST_LIST *users_def;

	/* authenticate */
	char const *auth_usersfile;
	fr_htrie_t *auth_users;
	PAIR_LIST_LIST *auth_users_def;

	/* preacct */
	char const *acct_usersfile;
	fr_htrie_t *acct_users;
	PAIR_LIST_LIST *acct_users_def;

	/* post-authenticate */
	char const *postauth_usersfile;
	fr_htrie_t *postauth_users;
	PAIR_LIST_LIST *postauth_users_def;
} rlm_files_t;

typedef struct {
	fr_value_box_t	key;
} rlm_files_env_t;

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_files_dict[];
fr_dict_autoload_t rlm_files_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_fall_through;
static fr_dict_attr_t const *attr_next_shortest_prefix;

extern fr_dict_attr_autoload_t rlm_files_dict_attr[];
fr_dict_attr_autoload_t rlm_files_dict_attr[] = {
	{ .out = &attr_fall_through, .name = "Fall-Through", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ .out = &attr_next_shortest_prefix, .name = "Next-Shortest-Prefix", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },

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


static uint32_t pairlist_hash(void const *a)
{
	return fr_value_box_hash(((PAIR_LIST_LIST const *)a)->box);
}

static int8_t pairlist_cmp(void const *a, void const *b)
{
	int ret;

	ret = fr_value_box_cmp(((PAIR_LIST_LIST const *)a)->box, ((PAIR_LIST_LIST const *)b)->box);
	return CMP(ret, 0);
}

static int pairlist_to_key(uint8_t **out, size_t *outlen, void const *a)
{
	return fr_value_box_to_key(out, outlen, ((PAIR_LIST_LIST const *)a)->box);
}

static int getusersfile(TALLOC_CTX *ctx, char const *filename, fr_htrie_t **ptree, PAIR_LIST_LIST **pdefault, fr_type_t data_type)
{
	int rcode;
	PAIR_LIST_LIST users;
	PAIR_LIST_LIST search_list;	// Temporary list header used for matching in htrie
	PAIR_LIST *entry, *next;
	PAIR_LIST_LIST *user_list, *default_list;
	fr_htrie_t *tree;
	fr_htrie_type_t htype;
	fr_value_box_t *box;

	if (!filename) {
		*ptree = NULL;
		return 0;
	}

	pairlist_list_init(&users);
	rcode = pairlist_read(ctx, dict_radius, filename, &users, 1);
	if (rcode < 0) {
		return -1;
	}

	htype = fr_htrie_hint(data_type);

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
		while ((map = map_list_next(&entry->check, map))) {
			if (!tmpl_is_attr(map->lhs)) {
				ERROR("%s[%d] Left side of check item %s is not an attribute",
				      entry->filename, entry->lineno, map->lhs->name);
				return -1;
			}
			da = tmpl_attr_tail_da(map->lhs);

			/*
			 *	Disallow regexes for now.
			 */
			if ((map->op == T_OP_REG_EQ) || (map->op == T_OP_REG_NE)) {
				fr_assert(tmpl_is_regex(map->rhs));

			/*
			 *	Disallow inter-attribute comparisons.
			 */
			} else if (!tmpl_is_data(map->rhs)) {
				ERROR("%s[%d] Right side of check item %s is not a leaf value",
				      entry->filename, entry->lineno, map->lhs->name);
				return -1;
			}

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
				WARN("%s[%d] Changing '%s =' to '%s =='\n\tfor comparing RADIUS attribute in check item list for key %s",
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
		while ((map = map_list_next(&entry->reply, map))) {
			if (!tmpl_is_attr(map->lhs)) {
				ERROR("%s[%d] Left side of reply item %s is not an attribute",
				      entry->filename, entry->lineno, map->lhs->name);
				return -1;
			}
			da = tmpl_attr_tail_da(map->lhs);

			if ((htype != FR_HTRIE_TRIE) && (da == attr_next_shortest_prefix)) {
				ERROR("%s[%d] Cannot use %s when key is not an IP / IP prefix",
				      entry->filename, entry->lineno, da->name);
				return -1;
			}

			/*
			 *	If we allow list qualifiers in
			 *	users_file.c, then this module also
			 *	needs to be updated.  Ensure via an
			 *	assertion that they do not get out of
			 *	sync.
			 */
			fr_assert(tmpl_list(map->lhs) == request_attr_reply);
		}
	}

	tree = fr_htrie_alloc(ctx,  htype, pairlist_hash, pairlist_cmp, pairlist_to_key, NULL);
	if (!tree) {
		pairlist_free(&users);
		return -1;
	}

	default_list = NULL;
	box = fr_value_box_alloc(ctx, data_type, NULL);

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
				default_list->name = entry->name;

				/*
				 *	Don't insert the DEFAULT list
				 *	into the tree, instead make it
				 *	it's own list.
				 */
				*pdefault = default_list;
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
		search_list.box = box;

		/*
		 *	Has to be of the correct data type.
		 */
		if (fr_value_box_from_str(box, box, data_type, NULL,
					  entry->name, strlen(entry->name), NULL, false) < 0) {
			ERROR("%s[%d] Failed parsing key %s - %s",
			      entry->filename, entry->lineno, entry->name, fr_strerror());
			goto error;
		}

		/*
		 *	Find an exact match, especially for patricia tries.
		 */
		user_list = fr_htrie_match(tree, &search_list);
		if (!user_list) {
			user_list = talloc_zero(ctx, PAIR_LIST_LIST);
			pairlist_list_init(user_list);
			user_list->name = entry->name;
			user_list->box = fr_value_box_alloc(user_list, data_type, NULL);

			(void) fr_value_box_copy(user_list, user_list->box, box);

			/*
			 *	Insert the new list header.
			 */
			if (!fr_htrie_insert(tree, user_list)) {
				ERROR("%s[%d] Failed inserting key %s - %s",
				      entry->filename, entry->lineno, entry->name, fr_strerror());
				goto error;

			error:
				fr_value_box_clear_value(box);
				talloc_free(tree);
				return -1;
			}
		}
		fr_value_box_clear_value(box);

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
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_files_t *inst = talloc_get_type_abort(mctx->inst->data, rlm_files_t);

	inst->key_data_type = tmpl_expanded_type(inst->key);
	if (fr_htrie_hint(inst->key_data_type) == FR_HTRIE_INVALID) {
		cf_log_err(mctx->inst->conf, "Invalid data type '%s' for 'files' module.",
			   fr_type_to_str(inst->key_data_type));
		return -1;
	}

#undef READFILE
#define READFILE(_x, _y, _d) if (getusersfile(inst, inst->_x, &inst->_y, &inst->_d, inst->key_data_type) != 0) do { ERROR("Failed reading %s", inst->_x); return -1;} while (0)

	READFILE(filename, common, common_def);
	READFILE(usersfile, users, users_def);
	READFILE(acct_usersfile, acct_users, acct_users_def);
	READFILE(auth_usersfile, auth_users, auth_users_def);
	READFILE(postauth_usersfile, postauth_users, postauth_users_def);

	return 0;
}

static bool files_eval_map(request_t *request, map_t *map)
{
	fr_pair_t *vp;

	fr_assert(tmpl_is_attr(map->lhs));
	fr_assert(fr_comparison_op[map->op]);

	if (tmpl_find_vp(&vp, request, map->lhs) < 0) return false;

	/*
	 *	The RHS is a compiled regex, which we don't yet
	 *	support.  So just re-parse it at run time for
	 *	programmer laziness.
	 */
	if ((map->op == T_OP_REG_EQ) || (map->op == T_OP_REG_NE)) {
		return (fr_regex_cmp_op(map->op, &vp->data, fr_box_strvalue(map->rhs->name)) == 1);
	}

	fr_assert(tmpl_is_data(map->rhs));

	return (fr_value_box_cmp_op(map->op, &vp->data, tmpl_value(map->rhs)) == 1);
}


/*
 *	Common code called by everything below.
 */
static unlang_action_t file_common(rlm_rcode_t *p_result, UNUSED rlm_files_t const *inst, rlm_files_env_t *env,
				   request_t *request, fr_htrie_t *tree, PAIR_LIST_LIST *default_list)
{
	PAIR_LIST_LIST const	*user_list;
	PAIR_LIST const 	*user_pl, *default_pl;
	bool			found = false, trie = false;
	PAIR_LIST_LIST		my_list;
	uint8_t			key_buffer[16], *key;
	size_t			keylen = 0;

	if (!tree && !default_list) RETURN_MODULE_NOOP;

	RDEBUG2("Looking for key \"%pV\"", &env->key);

	if (tree) {
		my_list.name = NULL;
		my_list.box = &env->key;
		user_list = fr_htrie_find(tree, &my_list);

		trie = (tree->type == FR_HTRIE_TRIE);

		/*
		 *	Convert the value-box to a key for use in a trie.  The trie assumes that the key
		 *	starts at the high bit of the data, and that isn't always the case.  e.g. "bool" and
		 *	"integer" may be in host byte order, in which case we have to convert them to network
		 *	byte order.
		 */
		if (user_list && trie) {
			key = key_buffer;
			keylen = sizeof(key_buffer) * 8;

			(void) fr_value_box_to_key(&key, &keylen, &env->key);

			RDEBUG3("Keylen %ld", keylen);
			RHEXDUMP3(key, (keylen + 7) >> 3, "KEY ");
		}

		user_pl = user_list ? fr_dlist_head(&user_list->head) : NULL;
	} else {
		user_pl = NULL;
		user_list = NULL;
	}

redo:
	default_pl = default_list ? fr_dlist_head(&default_list->head) : NULL;

	/*
	 *	Find the entry for the user.
	 */
	while (user_pl || default_pl) {
		fr_pair_t *vp;
		map_t *map = NULL;
		PAIR_LIST const *pl;
		fr_pair_list_t list;
		bool fall_through, next_shortest_prefix;
		bool match = true;

		/*
		 *	Figure out which entry to match on.
		 */
		if (!default_pl && user_pl) {
			pl = user_pl;

			RDEBUG3("DEFAULT[] USER[%d]=%s", user_pl->lineno, user_pl->name);
			user_pl = fr_dlist_next(&user_list->head, user_pl);

		} else if (!user_pl && default_pl) {
			pl = default_pl;
			RDEBUG3("DEFAULT[%d]= USER[]=", default_pl->lineno);
			default_pl = fr_dlist_next(&default_list->head, default_pl);

		} else if (user_pl->order < default_pl->order) {
			pl = user_pl;

			RDEBUG3("DEFAULT[%d]= USER[%d]=%s (choosing user)", default_pl->lineno, user_pl->lineno, user_pl->name);
			user_pl = fr_dlist_next(&user_list->head, user_pl);

		} else {
			pl = default_pl;
			RDEBUG3("DEFAULT[%d]= USER[%d]=%s (choosing default)", default_pl->lineno, user_pl->lineno, user_pl->name);
			default_pl = fr_dlist_next(&default_list->head, default_pl);
		}

		fr_pair_list_init(&list);

		/*
		 *	Realize the map to a list of VPs
		 */
		while ((map = map_list_next(&pl->check, map))) {
			fr_pair_list_t tmp_list;

			RDEBUG3("    %s %s %s", map->lhs->name, fr_tokens[map->op], map->rhs->name);

			/*
			 *	Control items get realized to VPs, and
			 *	copied to a temporary list, which is
			 *	then copied to control if the entire
			 *	line matches.
			 */
			switch (map->op) {
			case T_OP_EQ:
			case T_OP_SET:
			case T_OP_ADD_EQ:
				fr_pair_list_init(&tmp_list);
				if (map_to_vp(request->control_ctx, &tmp_list, request, map, NULL) < 0) {
					fr_pair_list_free(&list);
					RPWARN("Failed parsing check item, skipping entry");
					match = false;
					break;
				}

				fr_pair_list_append(&list, &tmp_list);
				break;

				/*
				 *	Evaluate the map, including regexes.
				 */
			default:
				if (!files_eval_map(request, map)) {
					RDEBUG3("    failed match - %s", fr_strerror());
					match = false;
				}
				break;
			}

			if (!match) break;
		}

		if (!match) {
			fr_pair_list_free(&list);
			continue;
		}

		RDEBUG2("Found match \"%s\" on line %d of %s", pl->name, pl->lineno, pl->filename);
		found = true;
		fall_through = false;
		next_shortest_prefix = false;

		/*
		 *	Move the control items over, too.
		 */
		fr_pair_list_move_op(&request->control_pairs, &list, T_OP_ADD_EQ);

		/* ctx may be reply */
		if (!map_list_empty(&pl->reply)) {
			map = NULL;
			while ((map = map_list_next(&pl->reply, map))) {
				fr_pair_list_t tmp_list;
				fr_pair_list_init(&tmp_list);
				if (map->op == T_OP_CMP_FALSE) continue;

				if (map_to_vp(request->reply_ctx, &tmp_list, request, map, NULL) < 0) {
					RPWARN("Failed parsing map for reply item %s, skipping it", map->lhs->name);
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

				/*
				 *	And do the same checks for prefix tries.
				 */
				if (trie && (keylen > 0)) {
					vp = fr_pair_list_head(&tmp_list);
					if (vp->da == attr_next_shortest_prefix) {
						next_shortest_prefix = vp->vp_bool;
						fr_pair_list_free(&tmp_list);
						continue;
					}
				}

				radius_pairmove(request, &request->reply_pairs, &tmp_list);
			}
		}

		if (fall_through) {
			continue;
		}

		/*
		 *	We're not doing patricia tries.  Stop now.
		 */
		if (!trie) {
			break;
		}

		/*
		 *	We're doing patricia tries, but we've been
		 *	told to not walk back up the trie, OR we're at the top of the tree.  Stop.
		 */
		if (!next_shortest_prefix || (keylen == 0)) {
			break;
		}

		/*
		 *	Walk back up the trie looking for shorter prefixes.
		 *
		 *	Note that we've already found an entry, so we
		 *	MUST start with that prefix, otherwise we
		 *	would end up in an loop of finding the same
		 *	prefix over and over.
		 */
		if (keylen > user_list->box->vb_ip.prefix) keylen = user_list->box->vb_ip.prefix;

		do {
			keylen--;
			user_list = fr_trie_lookup_by_key(tree->store, key, keylen);
			if (!user_list) continue;

			user_pl = fr_dlist_head(&user_list->head);
			RDEBUG("Found matching shorter subnet %s at key length %ld", user_pl->name, keylen);
			goto redo;
		} while (keylen > 0);
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
	rlm_files_t const *inst = talloc_get_type_abort_const(mctx->inst->data, rlm_files_t);
	rlm_files_env_t *env_data = talloc_get_type_abort(mctx->env_data, rlm_files_env_t);

	return file_common(p_result, inst, env_data, request,
			   inst->users ? inst->users : inst->common,
			   inst->users ? inst->users_def : inst->common_def);
}


/*
 *	Pre-Accounting - read the acct_users file for check_items and
 *	config. Reply items are Not Recommended(TM) in acct_users,
 *	except for Fallthrough, which should work
 */
static unlang_action_t CC_HINT(nonnull) mod_preacct(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_files_t const *inst = talloc_get_type_abort_const(mctx->inst->data, rlm_files_t);
	rlm_files_env_t *env_data = talloc_get_type_abort(mctx->env_data, rlm_files_env_t);

	return file_common(p_result, inst, env_data, request,
			   inst->acct_users ? inst->acct_users : inst->common,
			   inst->acct_users ? inst->acct_users_def : inst->common_def);
}

static unlang_action_t CC_HINT(nonnull) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_files_t const *inst = talloc_get_type_abort_const(mctx->inst->data, rlm_files_t);
	rlm_files_env_t *env_data = talloc_get_type_abort(mctx->env_data, rlm_files_env_t);

	return file_common(p_result, inst, env_data, request,
			   inst->auth_users ? inst->auth_users : inst->common,
			   inst->auth_users ? inst->auth_users_def : inst->common_def);
}

static unlang_action_t CC_HINT(nonnull) mod_post_auth(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_files_t const *inst = talloc_get_type_abort_const(mctx->inst->data, rlm_files_t);
	rlm_files_env_t *env_data = talloc_get_type_abort(mctx->env_data, rlm_files_env_t);

	return file_common(p_result, inst, env_data, request,
			   inst->postauth_users ? inst->postauth_users : inst->common,
			   inst->postauth_users ? inst->postauth_users_def : inst->common_def);
}

/*
 *	@todo - Whilst this causes `key` to be evaluated on a per-call basis,
 *	it is still evaluated during module instantiation to determine the tree type in use
 *	so more restructuring is needed to make the module protocol agnostic.
 */
static const call_env_t call_env[] = {
	{ FR_CALL_ENV_OFFSET("key", FR_TYPE_VOID, rlm_files_env_t, key, "%{%{Stripped-User-Name}:-%{User-Name}}",
			     T_DOUBLE_QUOTED_STRING, true, false, false) },
	CALL_ENV_TERMINATOR
};

static const call_method_env_t method_env = {
	.inst_size = sizeof(rlm_files_env_t),
	.inst_type = "rlm_files_env_t",
	.env = call_env
};

/* globally exported name */
extern module_rlm_t rlm_files;
module_rlm_t rlm_files = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "files",
		.inst_size	= sizeof(rlm_files_t),
		.config		= module_config,
		.instantiate	= mod_instantiate
	},
	.method_names = (module_method_name_t[]){
		/*
		 *	Hack to support old configurations
		 */
		{ .name1 = "authorize",		.name2 = CF_IDENT_ANY,		.method = mod_authorize,
		  .method_env = &method_env	},

		{ .name1 = "recv",		.name2 = "accounting-request",	.method = mod_preacct,
		  .method_env = &method_env	},
		{ .name1 = "recv",		.name2 = CF_IDENT_ANY,		.method = mod_authorize,
		  .method_env = &method_env	},
		{ .name1 = "authenticate",	.name2 = CF_IDENT_ANY,		.method = mod_authenticate,
		  .method_env = &method_env	},
		{ .name1 = "send",		.name2 = CF_IDENT_ANY,		.method = mod_post_auth,
		  .method_env = &method_env	},
		MODULE_NAME_TERMINATOR
	}

};
