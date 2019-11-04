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
 * @file rlm_json.c
 * @brief Parses JSON responses
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 Network RADIUS SARL (legal@networkradius.com)
 * @copyright 2015 The FreeRADIUS Server Project
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/json/base.h>

#include <ctype.h>

#ifndef HAVE_JSON
#  error "rlm_json should not be built unless json-c is available"
#endif

/** Forms a linked list of jpath head node pointers (a list of jpaths)
 */
typedef struct rlm_json_jpath_cache rlm_json_jpath_cache_t;
struct rlm_json_jpath_cache {
	fr_jpath_node_t		*jpath;		//!< First node in jpath expression.
	rlm_json_jpath_cache_t	*next;		//!< Next jpath cache entry.
};

typedef struct {
	fr_jpath_node_t const	*jpath;
	json_object		*root;
} rlm_json_jpath_to_eval_t;

static ssize_t jsonquote_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			      UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			      REQUEST *request, char const *fmt)
{
	size_t len;
	char *tmp;

	tmp = fr_json_from_string(request, fmt, false);

	/* Indicate truncation */
	if (!tmp) return outlen + 1;
	len = strlen(tmp);
	if (len >= outlen) return outlen + 1;

	*out = tmp;

	return len;
}

/** Determine if a jpath expression is valid
 *
 * @param ctx to allocate expansion buffer in.
 * @param mod_inst data.
 * @param xlat_inst data.
 * @param out Where to write the output (in the format @verbatim<bytes parsed>[:error]@endverbatim).
 * @param outlen How big out is.
 * @param request The current request.
 * @param fmt jpath expression to parse.
 * @return number of bytes written to out.
 */
static ssize_t jpath_validate_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			    	   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				   REQUEST *request, char const *fmt)
{
	fr_jpath_node_t *head;
	ssize_t slen, ret;
	char *jpath_str;

	slen = fr_jpath_parse(request, &head, fmt, strlen(fmt));
	if (slen <= 0) {
		rad_assert(head == NULL);
		return snprintf(*out, outlen, "%zd:%s", -(slen), fr_strerror());
	}
	rad_assert(talloc_get_type_abort(head, fr_jpath_node_t));

	jpath_str = fr_jpath_asprint(request, head);
	ret = snprintf(*out, outlen, "%zu:%s", (size_t) slen, jpath_str);
	talloc_free(head);
	talloc_free(jpath_str);

	return ret;
}

/** Pre-parse and validate literal jpath expressions for maps
 *
 * @param[in] cs	#CONF_SECTION that defined the map instance.
 * @param[in] mod_inst	module instance (unused).
 * @param[in] proc_inst	the cache structure to fill.
 * @param[in] src	Where to get the JSON data from.
 * @param[in] maps	set of maps to translate to jpaths.
 * @return
 *	- 0 on success.
 * 	- -1 on failure.
 */
static int mod_map_proc_instantiate(CONF_SECTION *cs, UNUSED void *mod_inst, void *proc_inst,
				    vp_tmpl_t const *src, vp_map_t const *maps)
{
	rlm_json_jpath_cache_t	*cache_inst = proc_inst;
	vp_map_t const		*map;
	ssize_t			slen;
	rlm_json_jpath_cache_t	*cache = cache_inst, **tail = &cache->next;

	if (!src) {
		cf_log_err(cs, "Missing JSON source");

		return -1;
	}

	for (map = maps; map; map = map->next) {
		CONF_PAIR	*cp = cf_item_to_pair(map->ci);
		char const	*p;

#ifndef HAVE_JSON_OBJECT_GET_INT64
		if (tmpl_is_attr(map->lhs) && (map->lhs->tmpl_da->type == FR_TYPE_UINT64)) {
			cf_log_err(cp, "64bit integers are not supported by linked json-c.  "
				      "Upgrade to json-c >= 0.10 to use this feature");
			return -1;
		}
#endif

		switch (map->rhs->type) {
		case TMPL_TYPE_UNPARSED:
			p = map->rhs->name;
			slen = fr_jpath_parse(cache, &cache->jpath, p, map->rhs->len);
			if (slen <= 0) {
				char		*spaces, *text;

			error:
				fr_canonicalize_error(cache, &spaces, &text, slen, fr_strerror());

				cf_log_err(cp, "Syntax error");
				cf_log_err(cp, "%s", p);
				cf_log_err(cp, "%s^ %s", spaces, text);

				talloc_free(spaces);
				talloc_free(text);
				return -1;
			}
			break;

		case TMPL_TYPE_DATA:
			if (map->rhs->tmpl_value_type != FR_TYPE_STRING) {
				cf_log_err(cp, "Right side of map must be a string");
				return -1;
			}
			p = map->rhs->tmpl_value.vb_strvalue;
			slen = fr_jpath_parse(cache, &cache->jpath, p, map->rhs->tmpl_value_length);
			if (slen <= 0) goto error;
			break;

		default:
			continue;
		}

		/*
		 *	Slightly weird... This is here because our first
		 *	list member was pre-allocated and passed to the
		 *	instantiation callback.
		 */
		if (map->next) {
			*tail = cache = talloc_zero(cache, rlm_json_jpath_cache_t);
			tail = &cache->next;
		}
	}

	return 0;
}

/** Converts a string value into a #VALUE_PAIR
 *
 * @param[in,out] ctx to allocate #VALUE_PAIR (s).
 * @param[out] out where to write the resulting #VALUE_PAIR.
 * @param[in] request The current request.
 * @param[in] map to process.
 * @param[in] uctx The json tree/jpath expression to evaluate.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _json_map_proc_get_value(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request,
				    vp_map_t const *map, void *uctx)
{
	VALUE_PAIR			*vp;
	fr_cursor_t			cursor;
	rlm_json_jpath_to_eval_t	*to_eval = uctx;
	fr_value_box_t			*head, *value;
	int				ret;

	*out = NULL;

	ret = fr_jpath_evaluate_leaf(request, &head, map->lhs->tmpl_da->type, map->lhs->tmpl_da,
			     	     to_eval->root, to_eval->jpath);
	if (ret < 0) {
		RPEDEBUG("Failed evaluating jpath");
		return -1;
	}
	if (ret == 0) return 0;
	rad_assert(head);

	for (fr_cursor_init(&cursor, out), value = head;
	     value;
	     fr_cursor_append(&cursor, vp), value = value->next) {
		MEM(vp = fr_pair_afrom_da(ctx, map->lhs->tmpl_da));
		vp->op = map->op;

		if (fr_value_box_steal(vp, &vp->data, value) < 0) {
			RPEDEBUG("Copying data to attribute failed");
			talloc_free(vp);
			talloc_free(*out);
			return -1;
		}
	}
	return 0;
}

/** Parses a JSON string, and executes jpath queries against it to map values to attributes
 *
 * @param mod_inst	unused.
 * @param proc_inst	cached jpath sequences.
 * @param request	The current request.
 * @param json		JSON string to parse.
 * @param maps		Head of the map list.
 * @return
 *	- #RLM_MODULE_NOOP no rows were returned or columns matched.
 *	- #RLM_MODULE_UPDATED if one or more #VALUE_PAIR were added to the #REQUEST.
 *	- #RLM_MODULE_FAIL if a fault occurred.
 */
static rlm_rcode_t mod_map_proc(UNUSED void *mod_inst, void *proc_inst, REQUEST *request,
			      	fr_value_box_t **json, vp_map_t const *maps)
{
	rlm_rcode_t			rcode = RLM_MODULE_UPDATED;
	struct json_tokener		*tok;

	rlm_json_jpath_cache_t		*cache = proc_inst;
	vp_map_t const			*map;

	rlm_json_jpath_to_eval_t	to_eval;

	char const			*json_str = NULL;

	if (!*json) {
		REDEBUG("JSON map input cannot be (null)");
		return RLM_MODULE_FAIL;
	}

	if (fr_value_box_list_concat(request, *json, json, FR_TYPE_STRING, true) < 0) {
		REDEBUG("Failed concatenating input");
		return RLM_MODULE_FAIL;
	}
	json_str = (*json)->vb_strvalue;

	if ((talloc_array_length(json_str) - 1) == 0) {
		REDEBUG("JSON map input length must be > 0");
		return RLM_MODULE_FAIL;
	}

	tok = json_tokener_new();
	to_eval.root = json_tokener_parse_ex(tok, json_str, (int)(talloc_array_length(json_str) - 1));
	if (!to_eval.root) {
		REMARKER(json_str, tok->char_offset, "%s", json_tokener_error_desc(json_tokener_get_error(tok)));
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	for (map = maps; map; map = map->next) {
		switch (map->rhs->type) {
		/*
		 *	Cached types
		 */
		case TMPL_TYPE_UNPARSED:
		case TMPL_TYPE_DATA:
			to_eval.jpath = cache->jpath;

			if (map_to_request(request, map, _json_map_proc_get_value, &to_eval) < 0) {
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
			cache = cache->next;
			break;

		/*
		 *	Dynamic types
		 */
		default:
		{
			ssize_t		slen;
			fr_jpath_node_t	*node;
			char		*to_parse;

			if (tmpl_aexpand(request, &to_parse, request, map->rhs, fr_jpath_escape_func, NULL) < 0) {
				RPERROR("Failed getting jpath data");
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
			slen = fr_jpath_parse(request, &node, to_parse, talloc_array_length(to_parse) - 1);
			if (slen <= 0) {
				REMARKER(to_parse, -(slen), "%s", fr_strerror());
				talloc_free(to_parse);
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
			to_eval.jpath = node;

			if (map_to_request(request, map, _json_map_proc_get_value, &to_eval) < 0) {
				talloc_free(node);
				talloc_free(to_parse);
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
			talloc_free(node);
		}
			break;
		}
	}


finish:
	json_object_put(to_eval.root);
	json_tokener_free(tok);

	return rcode;
}

static int mod_bootstrap(void *instance, UNUSED CONF_SECTION *conf)
{
	xlat_register(instance, "jsonquote", jsonquote_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);
	xlat_register(instance, "jpathvalidate", jpath_validate_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);

	if (map_proc_register(instance, "json", mod_map_proc,
			      mod_map_proc_instantiate, sizeof(rlm_json_jpath_cache_t)) < 0) return -1;
	return 0;
}

static int mod_load(void)
{
	fr_json_version_print();

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_json;
module_t rlm_json = {
	.magic		= RLM_MODULE_INIT,
	.name		= "json",
	.type		= RLM_TYPE_THREAD_SAFE,
	.onload		= mod_load,
	.bootstrap	= mod_bootstrap,
};
