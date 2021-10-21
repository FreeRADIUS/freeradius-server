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
 * @file rlm_attr_filter.c
 * @brief Filter the contents of a list, allowing only certain attributes.
 *
 * @copyright (C) 2001,2006 The FreeRADIUS server project
 * @copyright (C) 2001 Chris Parker (cparker@starnetusa.net)
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_attr_filter (%s) - "
#define LOG_PREFIX_ARGS dl_module_instance_name_by_data(inst)

#include	<freeradius-devel/server/base.h>
#include	<freeradius-devel/server/module.h>
#include	<freeradius-devel/util/debug.h>
#include	<freeradius-devel/server/users_file.h>

#include	<sys/stat.h>

#include	<ctype.h>
#include	<fcntl.h>

/*
 *	Define a structure with the module configuration, so it can
 *	be used as the instance handle.
 */
typedef struct {
	char const	*filename;
	tmpl_t		*key;
	bool		relaxed;
	PAIR_LIST_LIST	attrs;
} rlm_attr_filter_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, rlm_attr_filter_t, filename) },
	{ FR_CONF_OFFSET("key", FR_TYPE_TMPL, rlm_attr_filter_t, key), .dflt = "&Realm", .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("relaxed", FR_TYPE_BOOL, rlm_attr_filter_t, relaxed), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_attr_filter_dict[];
fr_dict_autoload_t rlm_attr_filter_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_stripped_user_name;
static fr_dict_attr_t const *attr_fall_through;
static fr_dict_attr_t const *attr_relax_filter;

static fr_dict_attr_t const *attr_vendor_specific;

extern fr_dict_attr_autoload_t rlm_attr_filter_dict_attr[];
fr_dict_attr_autoload_t rlm_attr_filter_dict_attr[] = {
	{ .out = &attr_stripped_user_name, .name = "Stripped-User-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_fall_through, .name = "Fall-Through", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ .out = &attr_relax_filter, .name = "Relax-Filter", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },

	{ .out = &attr_vendor_specific, .name = "Vendor-Specific", .type = FR_TYPE_VSA, .dict = &dict_radius },
	{ NULL }
};

static void check_pair(request_t *request, fr_pair_t *check_item, fr_pair_t *reply_item, int *pass, int *fail)
{
	int compare;

	if (check_item->op == T_OP_SET) return;

	compare = fr_pair_cmp(check_item, reply_item);
	if (compare < 0) RPEDEBUG("Comparison failed");

	if (compare == 1) {
		++*(pass);
	} else {
		++*(fail);
	}

	RDEBUG3("%pP %s %pP", reply_item, compare == 1 ? "allowed by" : "disallowed by", check_item);

	return;
}

static int attr_filter_getfile(TALLOC_CTX *ctx, rlm_attr_filter_t *inst, char const *filename, PAIR_LIST_LIST *pair_list)
{
	int rcode;
	PAIR_LIST *entry = NULL;
	map_t *map;

	rcode = pairlist_read(ctx, dict_radius, filename, pair_list, 1);
	if (rcode < 0) {
		return -1;
	}

	/*
	 *	Walk through the 'attrs' file list.
	 */
	while ((entry = fr_dlist_next(&pair_list->head, entry))) {
		/*
		 *	We apply the rules in the reply items.
		 */
		if (!fr_dlist_empty(&entry->check)) {
			WARN("%s[%d] Check list is not empty for entry \"%s\".\n",
			     filename, entry->lineno, entry->name);
		}

		map = NULL;
		while ((map = fr_dlist_next(&entry->reply, map))) {
			fr_dict_attr_t const *da;

			if (!tmpl_is_attr(map->lhs)) {
				ERROR("%s[%d] Left side of filter %s is not an attribute",
				      filename, entry->lineno, map->lhs->name);
				return -1;
			}
			da = tmpl_da(map->lhs);

			/*
			 * If it's NOT a vendor attribute,
			 * and it's NOT a wire protocol
			 * and we ignore Fall-Through,
			 * then bitch about it, giving a good warning message.
			 */
			if (fr_dict_attr_is_top_level(da) && (da->attr > 1000)) {
				WARN("%s[%d] Check item \"%s\" was found in filter list for entry \"%s\".\n",
				     filename, entry->lineno, da->name, entry->name);
			}

			/*
			 *	Make sure that bad things don't happen.
			 */
			if (!map->rhs) {
				ERROR("%s[%d] Right side of filter %s is a nested attribute - this is not (yet) supported",
				      filename, entry->lineno, map->lhs->name);
				return -1;
			}
		}
	}

	return 0;
}


/*
 *	(Re-)read the "attrs" file into memory.
 */
static int mod_instantiate(void *instance, UNUSED CONF_SECTION *conf)
{
	rlm_attr_filter_t *inst = instance;
	int rcode;
	pairlist_list_init(&inst->attrs);

	rcode = attr_filter_getfile(inst, inst, inst->filename, &inst->attrs);
	if (rcode != 0) {
		ERROR("Errors reading %s", inst->filename);

		return -1;
	}

	return 0;
}


/*
 *	Common attr_filter checks
 */
static unlang_action_t CC_HINT(nonnull(1,2)) attr_filter_common(rlm_rcode_t *p_result,
								void const *instance, request_t *request,
								fr_radius_packet_t *packet, fr_pair_list_t *list)
{
	rlm_attr_filter_t const *inst = talloc_get_type_abort_const(instance, rlm_attr_filter_t);
	fr_pair_list_t	output;
	PAIR_LIST	*pl = NULL;
	int		found = 0;
	int		pass, fail = 0;
	char const	*keyname = NULL;
	char		buffer[256];
	ssize_t		slen;

	if (!packet) {
		RETURN_MODULE_NOOP;
	}

	slen = tmpl_expand(&keyname, buffer, sizeof(buffer), request, inst->key, NULL, NULL);
	if (slen < 0) {
		RETURN_MODULE_FAIL;
	}
	if ((keyname == buffer) && is_truncated((size_t)slen, sizeof(buffer))) {
		REDEBUG("Key too long, expected < " STRINGIFY(sizeof(buffer)) " bytes, got %zi bytes", slen);
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Head of the output list
	 */
	fr_pair_list_init(&output);

	/*
	 *      Find the attr_filter profile entry for the entry.
	 */
	while ((pl = fr_dlist_next(&inst->attrs.head, pl))) {
		int fall_through = 0;
		int relax_filter = inst->relaxed;
		map_t *map = NULL;
		fr_pair_list_t tmp_list;
		fr_pair_t *check_item, *input_item;
		fr_pair_list_t check_list;

		fr_pair_list_init(&tmp_list);
		/*
		 *  If the current entry is NOT a default,
		 *  AND the realm does NOT match the current entry,
		 *  then skip to the next entry.
		 */
		if ((strcmp(pl->name, "DEFAULT") != 0) &&
		    (strcmp(keyname, pl->name) != 0))  {
			continue;
		}

		RDEBUG2("Matched entry %s at line %d", pl->name, pl->lineno);
		found = 1;

		fr_pair_list_init(&check_list);

		while ((map = fr_dlist_next(&pl->reply, map))) {
			if (map_to_vp(packet, &tmp_list, request, map, NULL) < 0) {
				RPWARN("Failed parsing map %s for check item, skipping it", map->lhs->name);
				continue;
			}

			check_item = fr_pair_list_head(&tmp_list);
		     	if (check_item->da == attr_fall_through) {
				if (check_item->vp_uint32 == 1) {
					fall_through = 1;
					fr_pair_list_free(&tmp_list);
					continue;
				}
		     	} else if (check_item->da == attr_relax_filter) {
				relax_filter = check_item->vp_uint32;
		     	}

			/*
			 *	Remove pair from temporary list ready to
			 *	add to the correct destination
			 */
			fr_pair_remove(&tmp_list, check_item);

			/*
			 *    If it is a SET operator, add the attribute to
			 *    the output list without checking it.
			 */
			if (check_item->op == T_OP_SET ) {
				fr_pair_append(&output, check_item);
				continue;
			}

			/*
			 *	Append the realized VP to the check list.
			 */
			fr_pair_append(&check_list, check_item);
		}

		/*
		 *	Iterate through the input items, comparing
		 *	each item to every rule, then moving it to the
		 *	output list only if it matches all rules
		 *	for that attribute.  IE, Idle-Timeout is moved
		 *	only if it matches all rules that describe an
		 *	Idle-Timeout.
		 */
		for (input_item = fr_pair_list_head(list);
		     input_item;
		     input_item = fr_pair_list_next(list, input_item)) {
			pass = fail = 0; /* reset the pass,fail vars for each reply item */

			/*
			 *  Reset the check_item pointer to beginning of the list
			 */
			for (check_item = fr_pair_list_head(&check_list);
			     check_item;
			     check_item = fr_pair_list_next(&check_list, check_item)) {
				/*
				 *  Vendor-Specific is special, and matches any VSA if the
				 *  comparison is always true.
				 */
				if ((check_item->da == attr_vendor_specific) &&
				    (fr_dict_vendor_num_by_da(input_item->da) != 0) &&
				    (check_item->op == T_OP_CMP_TRUE)) {
					pass++;
					continue;
				}

				if (input_item->da == check_item->da) {
					check_pair(request, check_item, input_item, &pass, &fail);
				}
			}

			RDEBUG3("Attribute \"%s\" allowed by %i rules, disallowed by %i rules",
				input_item->da->name, pass, fail);
			/*
			 *  Only move attribute if it passed all rules, or if the config says we
			 *  should copy unmatched attributes ('relaxed' mode).
			 */
			if (fail == 0 && (pass > 0 || relax_filter)) {
				fr_pair_t *prev = fr_pair_list_prev(list, input_item);

				if (!pass) {
					RDEBUG3("Attribute \"%s\" allowed by relaxed mode", input_item->da->name);
				}
				fr_pair_remove(list, input_item);
				fr_assert(input_item != NULL);
				fr_pair_append(&output, input_item);
				input_item = prev; /* Set input_item to previous in the list for outer loop */
			}
		}

		/* If we shouldn't fall through, break */
		if (!fall_through) {
			break;
		}
	}

	/*
	 *	No entry matched.  We didn't do anything.
	 */
	if (!found) {
		fr_assert(fr_pair_list_empty(&output));
		RETURN_MODULE_NOOP;
	}

	/*
	 *	Replace the existing request list with our filtered one
	 */
	fr_pair_list_free(list);
	fr_pair_list_append(list, &output);

	RETURN_MODULE_UPDATED;
}

#define RLM_AF_FUNC(_x, _y, _z) static unlang_action_t CC_HINT(nonnull) mod_##_x(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request) \
	{ \
		return attr_filter_common(p_result, mctx->instance, request, request->_y, &request->_z##_pairs); \
	}

RLM_AF_FUNC(authorize, packet, request)
RLM_AF_FUNC(post_auth, reply, reply)

RLM_AF_FUNC(preacct, packet, request)
RLM_AF_FUNC(accounting, reply, reply)

/* globally exported name */
extern module_t rlm_attr_filter;
module_t rlm_attr_filter = {
	.magic		= RLM_MODULE_INIT,
	.name		= "attr_filter",
	.inst_size	= sizeof(rlm_attr_filter_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_POST_AUTH]		= mod_post_auth,
	},
};

