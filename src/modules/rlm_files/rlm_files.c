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
#include <freeradius-devel/unlang/call_env.h>
#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/transaction.h>

#include <ctype.h>
#include <fcntl.h>

typedef struct {
	char const	*filename;
	bool		v3_compat;
	fr_htrie_type_t	htype;
} rlm_files_t;

/**  Structure produced by custom call_env parser
 */
typedef struct {
	tmpl_t		*key_tmpl;	//!< tmpl used to evaluate lookup key.
	fr_htrie_t	*htrie;		//!< parsed files "user" data.
	PAIR_LIST_LIST	*def;		//!< parsed files DEFAULT data.
} rlm_files_data_t;

/**  Call_env structure
 */
typedef struct {
	rlm_files_data_t	*data;		//!< Data from parsed call_env.
	tmpl_t			*match_attr;	//!< Attribute to populate with matched key value.
	char const		*name;  	//!< Name of module instance - for debug output.
	fr_value_box_list_t	values;		//!< Where the expanded tmpl value will be written.
} rlm_files_env_t;

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_files_dict[];
fr_dict_autoload_t rlm_files_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_fall_through;
static fr_dict_attr_t const *attr_next_shortest_prefix;

extern fr_dict_attr_autoload_t rlm_files_dict_attr[];
fr_dict_attr_autoload_t rlm_files_dict_attr[] = {
	{ .out = &attr_fall_through, .name = "Fall-Through", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ .out = &attr_next_shortest_prefix, .name = "Next-Shortest-Prefix", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },

	DICT_AUTOLOAD_TERMINATOR
};

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_REQUIRED | CONF_FLAG_FILE_READABLE, rlm_files_t, filename) },
	{ FR_CONF_OFFSET("v3_compat", rlm_files_t, v3_compat) },
	{ FR_CONF_OFFSET("lookup_type", rlm_files_t, htype), .dflt = "auto",
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = fr_htrie_type_table, .len = &fr_htrie_type_table_len } },
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

static int getrecv_filename(TALLOC_CTX *ctx, rlm_files_t const *inst, fr_htrie_t **ptree, PAIR_LIST_LIST **pdefault,
			    fr_type_t data_type, fr_dict_attr_t const *key_enum, fr_dict_t const *dict)
{
	int			rcode;
	PAIR_LIST_LIST		users;
	PAIR_LIST_LIST		search_list;	// Temporary list header used for matching in htrie
	PAIR_LIST		*entry, *next;
	PAIR_LIST_LIST		*user_list, *default_list;
	fr_htrie_t		*tree;
	fr_htrie_type_t		htype;
	fr_value_box_t		*box;
	map_t			*reply_head;

	if (!inst->filename) {
		*ptree = NULL;
		return 0;
	}

	pairlist_list_init(&users);
	rcode = pairlist_read(ctx, dict, inst->filename, &users, inst->v3_compat);
	if (rcode < 0) {
		return -1;
	}

	if (inst->htype == FR_HTRIE_AUTO) {
		htype = fr_htrie_hint(data_type);
	} else {
		htype = inst->htype;
	}

	/*
	 *	Walk through the 'users' file list
	 */
	entry = NULL;
	while ((entry = fr_dlist_next(&users.head, entry))) {
		map_t *map = NULL;
		map_t *prev, *next_map;
		fr_dict_attr_t const *da;
		map_t *sub_head, *set_head;

		reply_head = NULL;

		/*
		 *	Do various sanity checks.
		 */
		while ((map = map_list_next(&entry->check, map))) {
			if (!tmpl_is_attr(map->lhs)) {
				ERROR("%s[%d] Left side of check item %s is not an attribute",
				      entry->filename, entry->lineno, map->lhs->name);
				return -1;
			}

			/*
			 *	Disallow regexes for now.
			 */
			if ((map->op == T_OP_REG_EQ) || (map->op == T_OP_REG_NE)) {
				fr_assert(tmpl_is_regex(map->rhs));
			}

			/*
			 *	Move assignment operations to the reply list.
			 */
			switch (map->op) {
			case T_OP_EQ:
			case T_OP_SET:
			case T_OP_ADD_EQ:
				prev = map_list_remove(&entry->check, map);
				map_list_insert_after(&entry->reply, reply_head, map);
				reply_head = map;
				map = prev;
				break;

			default:
				break;
			}
		} /* end of loop over check items */

		/*
		 *	Note that we also re-arrange any control items which are in the reply item list.
		 */
		sub_head = set_head = NULL;

		/*
		 *	Look for server configuration items
		 *	in the reply list.
		 *
		 *	It's a common enough mistake, that it's
		 *	worth doing.
		 */
		for (map = map_list_head(&entry->reply);
		     map != NULL;
		     map = next_map) {
			next_map = map_list_next(&entry->reply, map);
			if (!tmpl_is_attr(map->lhs)) {
				ERROR("%s[%d] Left side of reply item %s is not an attribute",
				      entry->filename, entry->lineno, map->lhs->name);
				return -1;
			}
			da = tmpl_attr_tail_da(map->lhs);

			if (fr_comparison_op[map->op] && (map->op != T_OP_LE) && (map->op != T_OP_GE)) {
				ERROR("%s[%d] Invalid operator reply item %s %s ...",
				      entry->filename, entry->lineno, map->lhs->name, fr_tokens[map->op]);
				return -1;
			}

			/*
			 *	Regex assignments aren't allowed.
			 *
			 *	Execs are being deprecated.
			 */
			if (tmpl_contains_regex(map->rhs) || tmpl_is_exec(map->rhs)) {
				ERROR("%s[%d] Invalid right-hand side of assignment for attribute %s",
				      entry->filename, entry->lineno, da->name);
				return -1;
			}

			if (da == attr_next_shortest_prefix) {
				if (htype != FR_HTRIE_TRIE) {
					ERROR("%s[%d] Cannot use %s when key is not an IP / IP prefix",
					      entry->filename, entry->lineno, da->name);
					return -1;
				}

				if (!tmpl_is_data(map->rhs) || (tmpl_value_type(map->rhs) != FR_TYPE_BOOL)) {
					ERROR("%s[%d] Value for %s must be static boolean",
					      entry->filename, entry->lineno, da->name);
					return -1;
				}

				entry->next_shortest_prefix = tmpl_value(map->rhs)->vb_bool;
				(void) map_list_remove(&entry->reply, map);
				continue;
			}

			/*
			 *	Check for Fall-Through in the reply list.  If so, delete it and set the flag
			 *	in the entry.
			 *
			 *	Note that we don't free "map", as the map functions usually make the "next"
			 *	map be talloc parented from the current one.  So freeing this one will likely
			 *	free all subsequent maps.
			 */
			if (da == attr_fall_through) {
				if (!tmpl_is_data(map->rhs) || (tmpl_value_type(map->rhs) != FR_TYPE_BOOL)) {
					ERROR("%s[%d] Value for %s must be static boolean",
					      entry->filename, entry->lineno, da->name);
					return -1;
				}

				entry->fall_through = tmpl_value(map->rhs)->vb_bool;
				(void) map_list_remove(&entry->reply, map);
				continue;
			}

			/*
			 *	Removals are applied before anything else.
			 */
			if (map->op == T_OP_SUB_EQ) {
				if (sub_head == map) continue;

				(void) map_list_remove(&entry->reply, map);
				map_list_insert_after(&entry->reply, sub_head, map);
				sub_head = map;
				continue;
			}

			/*
			 *	Over-rides are applied after deletions.
			 */
			if (map->op == T_OP_SET) {
				if (set_head == map) continue;

				if (!set_head) set_head = sub_head;

				(void) map_list_remove(&entry->reply, map);
				map_list_insert_after(&entry->reply, set_head, map);
				set_head = map;
				continue;
			}
		}
	}

	tree = fr_htrie_alloc(ctx, htype, pairlist_hash, pairlist_cmp, pairlist_to_key, NULL);
	if (!tree) {
		while ((entry = fr_dlist_pop_head(&users.head))) {
			talloc_free(entry);
		}
		return -1;
	}

	default_list = NULL;
	MEM(box = fr_value_box_alloc(ctx, data_type, NULL));

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
		if (fr_value_box_from_str(box, box, data_type, key_enum,
					  entry->name, strlen(entry->name), NULL) < 0) {
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

			if (unlikely(fr_value_box_copy(user_list, user_list->box, box) < 0)) {
				PERROR("%s[%d] Failed copying key %s",
				       entry->filename, entry->lineno, entry->name);
			}

			/*
			 *	Insert the new list header.
			 */
			if (!fr_htrie_insert(tree, user_list)) {
				PERROR("%s[%d] Failed inserting key %s",
				       entry->filename, entry->lineno, entry->name);
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

/** Lookup the expanded key value in files data.
 *
 */
static unlang_action_t CC_HINT(nonnull) mod_files_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_files_env_t		*env = talloc_get_type_abort(mctx->env_data, rlm_files_env_t);
	PAIR_LIST_LIST const	*user_list;
	PAIR_LIST const 	*user_pl, *default_pl;
	bool			found = false, trie = false;
	PAIR_LIST_LIST		my_list;
	uint8_t			key_buffer[16], *key = NULL;
	size_t			keylen = 0;
	fr_edit_list_t		*el, *child;
	fr_htrie_t		*tree = env->data->htrie;
	PAIR_LIST_LIST		*default_list = env->data->def;
	fr_value_box_t		*key_vb = fr_value_box_list_head(&env->values);

	if (!key_vb) {
		RERROR("Missing key value");
		RETURN_UNLANG_FAIL;
	}

	if (!tree && !default_list) {
		RETURN_UNLANG_NOOP;
	}

	RDEBUG2("%s - Looking for key \"%pV\"", env->name, key_vb);

	el = unlang_interpret_edit_list(request);
	MEM(child = fr_edit_list_alloc(request, 50, el));

	if (tree) {
		my_list.name = NULL;
		my_list.box = key_vb;
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

			(void) fr_value_box_to_key(&key, &keylen, key_vb);

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
		map_t *map = NULL;
		PAIR_LIST const *pl;
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

		/*
		 *	Run the check items.
		 */
		while ((map = map_list_next(&pl->check, map))) {
			int rcode;

			RDEBUG3("    %s %s %s", map->lhs->name, fr_tokens[map->op], map->rhs ? map->rhs->name : "{ ... }");

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
				fr_assert(0);
				goto fail;

				/*
				 *	Evaluate the map, including regexes.
				 */
			default:
				rcode = radius_legacy_map_cmp(request, map);
				if (rcode < 0) {
					RPWARN("Failed parsing map for check item %s, skipping it", map->lhs->name);
				fail:
					fr_edit_list_abort(child);
					RETURN_UNLANG_FAIL;
				}

				if (!rcode) {
					RDEBUG3("    failed match");
					match = false;
				}
				break;
			}

			if (!match) break;
		}

		if (!match) continue;

		RDEBUG2("%s - Found match \"%s\" on line %d of %s", env->name, pl->name, pl->lineno, pl->filename);
		found = true;

		/*
		 *	If match_attr is configured, populate the requested attribute with the
		 *	key value from the matching line.
		 */
		if (env->match_attr) {
			tmpl_t	match_rhs;
			map_t	match_map;

			match_map = (map_t) {
				.lhs = env->match_attr,
				.op = T_OP_SET,
				.rhs = &match_rhs
			};

			tmpl_init_shallow(&match_rhs, TMPL_TYPE_DATA, T_BARE_WORD, "", 0, NULL);
			fr_value_box_bstrndup_shallow(&match_map.rhs->data.literal, NULL, pl->name,
						      talloc_array_length(pl->name) - 1, false);
			if (map_to_request(request, &match_map, map_to_vp, NULL) < 0) {
				RWARN("Failed populating %s with key value %s", env->match_attr->name, pl->name);
			}
		}

		if (map_list_num_elements(&pl->reply) > 0) {
			RDEBUG2("%s - Preparing attribute updates:", env->name);
			/* ctx may be reply */
			RINDENT();
			if (radius_legacy_map_list_apply(request, &pl->reply, child) < 0) {
				RPWARN("Failed parsing reply item");
				REXDENT();
				goto fail;
			}
			REXDENT();
		}

		if (pl->fall_through) continue;

		/*
		 *	We're not doing patricia tries.  Stop now.
		 */
		if (!trie) break;

		/*
		 *	We're doing patricia tries, but we've been
		 *	told to not walk back up the trie, OR we're at the top of the tree.  Stop.
		 */
		if (!pl->next_shortest_prefix || (keylen == 0)) break;

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
			if (!user_list) {
				user_pl = NULL;
				continue;
			}

			user_pl = fr_dlist_head(&user_list->head);
			RDEBUG("%s - Found matching shorter subnet %s at key length %ld", env->name, user_pl->name, keylen);
			goto redo;
		} while (keylen > 0);
	}

	/*
	 *	See if we succeeded.
	 */
	if (!found) {
		fr_edit_list_abort(child);
		RETURN_UNLANG_NOOP;
	}

	fr_edit_list_commit(child);

	RETURN_UNLANG_OK;
}

/** Initiate a files data lookup
 *
 * The results of call_env parsing are a structure containing the
 * tmpl_t representing the key and the parsed files data, meaning tmpl
 * expansion does not happen by default.
 * First we push the tmpl onto the stack for evaluation, then the lookup
 * is done in mod_files_resume.
 */
static unlang_action_t CC_HINT(nonnull) mod_files(UNUSED unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_files_env_t		*env = talloc_get_type_abort(mctx->env_data, rlm_files_env_t);

	fr_value_box_list_init(&env->values);
	env->name = mctx->mi->name;

	return unlang_module_yield_to_tmpl(env, &env->values, request, env->data->key_tmpl,
					   NULL, mod_files_resume, NULL, 0, NULL);
}

/** Custom call_env parser for loading files data
 *
 */
static int files_call_env_parse(TALLOC_CTX *ctx, void *out, tmpl_rules_t const *t_rules, CONF_ITEM *ci,
				call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	rlm_files_t const		*inst = talloc_get_type_abort_const(cec->mi->data, rlm_files_t);
	CONF_PAIR const			*to_parse = cf_item_to_pair(ci);
	rlm_files_data_t		*files_data;
	fr_type_t			keytype;
	fr_dict_attr_t const		*key_enum = NULL;

	MEM(files_data = talloc_zero(ctx, rlm_files_data_t));

	if (tmpl_afrom_substr(ctx, &files_data->key_tmpl,
			      &FR_SBUFF_IN(cf_pair_value(to_parse), talloc_array_length(cf_pair_value(to_parse)) - 1),
			      cf_pair_value_quote(to_parse), value_parse_rules_quoted[cf_pair_value_quote(to_parse)],
			      t_rules) < 0) return -1;

	keytype = tmpl_expanded_type(files_data->key_tmpl);
	if (fr_htrie_hint(keytype) == FR_HTRIE_INVALID) {
		cf_log_err(ci, "Invalid data type '%s' for 'files' module", fr_type_to_str(keytype));
	error:
		talloc_free(files_data);
		return -1;
	}

	if (files_data->key_tmpl->type == TMPL_TYPE_ATTR) {
		key_enum = tmpl_attr_tail_da(files_data->key_tmpl);
	}

	if (getrecv_filename(files_data, inst, &files_data->htrie, &files_data->def,
			     keytype, key_enum, t_rules->attr.dict_def) < 0) goto error;

	*(void **)out = files_data;
	return 0;
}

static const call_env_method_t method_env = {
	FR_CALL_ENV_METHOD_OUT(rlm_files_env_t),
	.env = (call_env_parser_t[]){
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("key", FR_TYPE_VOID, CALL_ENV_FLAG_PARSE_ONLY, rlm_files_env_t, data),
				     .pair.dflt = "%{Stripped-User-Name || User-Name}", .pair.dflt_quote = T_DOUBLE_QUOTED_STRING,
				     .pair.func = files_call_env_parse },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("match_attr", FR_TYPE_VOID, CALL_ENV_FLAG_ATTRIBUTE, rlm_files_env_t, match_attr) },
		CALL_ENV_TERMINATOR
	},
};

/* globally exported name */
extern module_rlm_t rlm_files;
module_rlm_t rlm_files = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "files",
		.inst_size	= sizeof(rlm_files_t),
		.config		= module_config,
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = mod_files, .method_env = &method_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
