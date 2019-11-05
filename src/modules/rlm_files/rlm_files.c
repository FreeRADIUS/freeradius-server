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

typedef struct rlm_files_t {
	vp_tmpl_t *key;

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

/*
 *     See if a VALUE_PAIR list contains Fall-Through = Yes
 */
static int fall_through(VALUE_PAIR *vp)
{
	VALUE_PAIR *tmp;
	tmp = fr_pair_find_by_da(vp, attr_fall_through, TAG_ANY);

	return tmp ? tmp->vp_uint32 : 0;
}

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT, rlm_files_t, filename) },
	{ FR_CONF_OFFSET("usersfile", FR_TYPE_FILE_INPUT, rlm_files_t, usersfile) },
	{ FR_CONF_OFFSET("acctusersfile", FR_TYPE_FILE_INPUT, rlm_files_t, acct_usersfile) },
#ifdef WITH_PROXY
	{ FR_CONF_OFFSET("preproxy_usersfile", FR_TYPE_FILE_INPUT, rlm_files_t, preproxy_usersfile) },
	{ FR_CONF_OFFSET("postproxy_usersfile", FR_TYPE_FILE_INPUT, rlm_files_t, postproxy_usersfile) },
#endif
	{ FR_CONF_OFFSET("auth_usersfile", FR_TYPE_FILE_INPUT, rlm_files_t, auth_usersfile) },
	{ FR_CONF_OFFSET("postauth_usersfile", FR_TYPE_FILE_INPUT, rlm_files_t, postauth_usersfile) },
	{ FR_CONF_OFFSET("key", FR_TYPE_TMPL | FR_TYPE_NOT_EMPTY, rlm_files_t, key), .dflt = "%{%{Stripped-User-Name}:-%{User-Name}}", .quote = T_DOUBLE_QUOTED_STRING },
	CONF_PARSER_TERMINATOR
};


static int pairlist_cmp(void const *a, void const *b)
{
	return strcmp(((PAIR_LIST const *)a)->name, ((PAIR_LIST const *)b)->name);
}

static int getusersfile(TALLOC_CTX *ctx, char const *filename, rbtree_t **ptree)
{
	int rcode;
	VALUE_PAIR *vp;
	PAIR_LIST *users = NULL;
	PAIR_LIST *entry, *next;
	PAIR_LIST *user_list, *default_list, **default_tail;
	rbtree_t *tree;

	if (!filename) {
		*ptree = NULL;
		return 0;
	}

	rcode = pairlist_read(ctx, dict_radius, filename, &users, 1);
	if (rcode < 0) {
		return -1;
	}

	/*
	 *	Walk through the 'users' file list
	 */
	entry = users;
	while (entry) {
		fr_cursor_t cursor;

		/*
		 *	Look for improper use of '=' in the
		 *	check items.  They should be using
		 *	'==' for on-the-wire RADIUS attributes,
		 *	and probably ':=' for server
		 *	configuration items.
		 */
		for (vp = fr_cursor_init(&cursor, &entry->check);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
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
			if ((fr_dict_vendor_num_by_da(vp->da) != 0) ||
			    (vp->da->attr < 0x100)) {
				WARN("[%s]:%d Changing '%s =' to '%s =='\n\tfor comparing RADIUS attribute in check item list for user %s",
				     filename, entry->lineno,
				     vp->da->name, vp->da->name,
				     entry->name);
				vp->op = T_OP_CMP_EQ;
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
		for (vp = fr_cursor_init(&cursor, &entry->reply);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			/*
			 *	If it's NOT a vendor attribute,
			 *	and it's NOT a wire protocol
			 *	and we ignore Fall-Through,
			 *	then bitch about it, giving a
			 *	good warning message.
			 */
			 if (fr_dict_attr_is_top_level(vp->da) && (vp->da->attr > 1000)) {
				WARN("[%s]:%d Check item \"%s\"\n"
				       "\tfound in reply item list for user \"%s\".\n"
				       "\tThis attribute MUST go on the first line"
				       " with the other check items", filename, entry->lineno, vp->da->name,
				       entry->name);
			}
		}

		entry = entry->next;
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
					talloc_free(tree);
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
static int mod_instantiate(void *instance, UNUSED CONF_SECTION *conf)
{
	rlm_files_t *inst = instance;

#undef READFILE
#define READFILE(_x, _y) do { if (getusersfile(inst, inst->_x, &inst->_y) != 0) { ERROR("Failed reading %s", inst->_x); return -1;} } while (0)

	READFILE(filename, common);
	READFILE(usersfile, users);
	READFILE(acct_usersfile, acct_users);

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
static rlm_rcode_t file_common(rlm_files_t const *inst, REQUEST *request, char const *filename, rbtree_t *tree,
			       RADIUS_PACKET *request_packet, RADIUS_PACKET *reply_packet)
{
	char const	*name;
	VALUE_PAIR	*check_tmp = NULL;
	VALUE_PAIR	*reply_tmp = NULL;
	PAIR_LIST const *user_pl, *default_pl;
	bool		found = false;
	PAIR_LIST	my_pl;
	char		buffer[256];

	if (tmpl_expand(&name, buffer, sizeof(buffer), request, inst->key, NULL, NULL) < 0) {
		REDEBUG("Failed expanding key %s", inst->key->name);
		return RLM_MODULE_FAIL;
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
		fr_cursor_t cursor;
		VALUE_PAIR *vp;
		PAIR_LIST const *pl;

		/*
		 *	Figure out which entry to match on.
		 */

		if (!default_pl && user_pl) {
			pl = user_pl;
			user_pl = user_pl->next;

		} else if (!user_pl && default_pl) {
			pl = default_pl;
			default_pl = default_pl->next;

		} else if (user_pl->order < default_pl->order) {
			pl = user_pl;
			user_pl = user_pl->next;

		} else {
			pl = default_pl;
			default_pl = default_pl->next;
		}

		MEM(fr_pair_list_copy(request, &check_tmp, pl->check) >= 0);
		for (vp = fr_cursor_init(&cursor, &check_tmp);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			if (xlat_eval_pair(request, vp) < 0) {
				RWARN("Failed parsing expanded value for check item, skipping entry: %s", fr_strerror());
				fr_pair_list_free(&check_tmp);
				continue;
			}
		}

		if (paircmp(request, request_packet->vps, check_tmp, &reply_packet->vps) == 0) {
			RDEBUG2("Found match \"%s\" one line %d of %s", pl->name, pl->lineno, filename);
			found = true;

			/* ctx may be reply or proxy */
			MEM(fr_pair_list_copy(reply_packet, &reply_tmp, pl->reply) >= 0);

			radius_pairmove(request, &reply_packet->vps, reply_tmp, true);
			fr_pair_list_move(&request->control, &check_tmp);

			reply_tmp = NULL;	/* radius_pairmove() frees input attributes */
			fr_pair_list_free(&check_tmp);

			/*
			 *	Fallthrough?
			 */
			if (!fall_through(pl->reply)) break;
		}
	}

	/*
	 *	Remove server internal parameters.
	 */
	fr_pair_delete_by_da(&reply_packet->vps, attr_fall_through);

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
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_files_t const *inst = instance;

	return file_common(inst, request, inst->filename,
			   inst->users ? inst->users : inst->common,
			   request->packet, request->reply);
}


/*
 *	Pre-Accounting - read the acct_users file for check_items and
 *	config. Reply items are Not Recommended(TM) in acct_users,
 *	except for Fallthrough, which should work
 */
static rlm_rcode_t CC_HINT(nonnull) mod_preacct(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_files_t const *inst = instance;

	return file_common(inst, request, inst->acct_usersfile,
			   inst->acct_users ? inst->acct_users : inst->common,
			   request->packet, request->reply);
}

#ifdef WITH_PROXY
static rlm_rcode_t CC_HINT(nonnull) mod_pre_proxy(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_files_t const *inst = instance;

	return file_common(inst, request, inst->preproxy_usersfile,
			   inst->preproxy_users ? inst->preproxy_users : inst->common,
			   request->packet, request->proxy->packet);
}

static rlm_rcode_t CC_HINT(nonnull) mod_post_proxy(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_files_t const *inst = instance;

	return file_common(inst, request, inst->postproxy_usersfile,
			   inst->postproxy_users ? inst->postproxy_users : inst->common,
			   request->proxy->reply, request->reply);
}
#endif

static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_files_t const *inst = instance;

	return file_common(inst, request, inst->auth_usersfile,
			   inst->auth_users ? inst->auth_users : inst->common,
			   request->packet, request->reply);
}

static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_files_t const *inst = instance;

	return file_common(inst, request, inst->postauth_usersfile,
			   inst->postauth_users ? inst->postauth_users : inst->common,
			   request->packet, request->reply);
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

#ifdef WITH_PROXY
		[MOD_PRE_PROXY]		= mod_pre_proxy,
		[MOD_POST_PROXY]	= mod_post_proxy,
#endif
		[MOD_POST_AUTH]		= mod_post_auth
	},
};

