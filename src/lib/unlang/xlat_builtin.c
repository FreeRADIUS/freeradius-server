/*
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
 */

/**
 * $Id$
 *
 * @file xlat_builtin.c
 * @brief String expansion ("translation").  Baked in expansions.
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

/**
 * @defgroup xlat_functions xlat expansion functions
 */

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/server/regex.h>
#include <freeradius-devel/unlang/xlat_priv.h>

#include <freeradius-devel/util/base64.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/hex.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/util/value.h>

#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/evp.h>
#endif

#ifdef HAVE_REGEX_PCRE2
#  include <pcre2.h>
#endif

#include <ctype.h>

static rbtree_t *xlat_root = NULL;

static char const hextab[] = "0123456789abcdef";

static fr_sbuff_parse_rules_t const xlat_arg_parse_rules = {
	.terminals = &FR_SBUFF_TERM(" ")
};


/** Return a VP from the specified request.
 *
 * @note DEPRECATED, TO NOT USE.  @see xlat_fmt_to_cursor instead.
 *
 * @param out where to write the pointer to the resolved VP. Will be NULL if the attribute couldn't
 *	be resolved.
 * @param request current request.
 * @param name attribute name including qualifiers.
 * @return
 *	- -4 if either the attribute or qualifier were invalid.
 *	- The same error codes as #tmpl_find_vp for other error conditions.
 */
int xlat_fmt_get_vp(fr_pair_t **out, request_t *request, char const *name)
{
	int ret;
	tmpl_t *vpt;

	*out = NULL;

	if (tmpl_afrom_attr_str(request, NULL, &vpt, name,
				&(tmpl_rules_t){
					.dict_def = request->dict,
					.prefix = TMPL_ATTR_REF_PREFIX_AUTO
				}) <= 0) return -4;

	ret = tmpl_find_vp(out, request, vpt);
	talloc_free(vpt);

	return ret;
}


/** Copy VP(s) from the specified request.
 *
 * @note DEPRECATED, TO NOT USE.  @see xlat_fmt_to_cursor instead.
 *
 * @param ctx to alloc new fr_pair_ts in.
 * @param out where to write the pointer to the copied VP. Will be NULL if the attribute couldn't be
 *	resolved.
 * @param request current request.
 * @param name attribute name including qualifiers.
 * @return
 *	- -4 if either the attribute or qualifier were invalid.
 *	- The same error codes as #tmpl_find_vp for other error conditions.
 */
int xlat_fmt_copy_vp(TALLOC_CTX *ctx, fr_pair_t **out, request_t *request, char const *name)
{
	int ret;
	tmpl_t *vpt;

	*out = NULL;

	if (tmpl_afrom_attr_str(request, NULL,
				&vpt, name, &(tmpl_rules_t){ .dict_def = request->dict }) <= 0) return -4;

	ret = tmpl_copy_pairs(ctx, out, request, vpt);
	talloc_free(vpt);

	return ret;
}


/** Convenience function to convert a string attribute reference to a cursor
 *
 * This is intended to be used by xlat functions which need to iterate over
 * an attribute reference provided as a format string or as a boxed value.
 *
 * We can't add attribute reference support to the xlat parser
 * as the inputs and outputs of xlat functions are all boxed values and
 * couldn't represent a fr_pair_t.
 *
 * @param[in] ctx	To allocate new cursor in.
 * @param[out] out	Where to write heap allocated cursor.  Must be freed
 *			once it's done with.  The heap based cursor is to
 *			simplify memory management, as all tmpls are heap
 *			allocated, and we need to bind the lifetime of the
 *			tmpl and tmpl cursor together.
 * @param[in] tainted	May be NULL.  Set to true if one or more of the pairs
 *			in the cursor's scope have the tainted flag high.
 * @param[in] request	The current request.
 * @param[in] fmt	string.  Leading whitespace will be ignored.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_fmt_to_cursor(TALLOC_CTX *ctx, fr_cursor_t **out,
		       bool *tainted, request_t *request, char const *fmt)
{
	tmpl_t			*vpt;
	fr_pair_t		*vp;
	fr_cursor_t		*cursor;
	tmpl_cursor_ctx_t	cc;

	fr_skip_whitespace(fmt);	/* Not binary safe, but attr refs should only contain printable chars */

	if (tmpl_afrom_attr_str(NULL, NULL, &vpt, fmt,
				&(tmpl_rules_t){
					.dict_def = request->dict,
					.prefix = TMPL_ATTR_REF_PREFIX_AUTO
				}) <= 0) {
		RPEDEBUG("Failed parsing attribute reference");
		return -1;
	}

	MEM(cursor = talloc(ctx, fr_cursor_t));
	talloc_steal(cursor, vpt);
	vp = tmpl_cursor_init(NULL, NULL, &cc, cursor, request, vpt);
	tmpl_cursor_clear(&cc);
	*out = cursor;

	if (!tainted) return 0;

	*tainted = false;	/* Needed for the rest of the code */

	if (!vp) return 0;

	do {
		if (vp->vp_tainted) {
			*tainted = true;
			break;
		}
	} while ((vp = fr_cursor_next(cursor)));

	fr_cursor_head(cursor);	/* Reset */

	return 0;
}


/*
 *	Compare two xlat_t structs, based ONLY on the module name.
 */
static int xlat_cmp(void const *one, void const *two)
{
	xlat_t const *a = one, *b = two;
	size_t a_len, b_len;
	int ret;

	a_len = strlen(a->name);
	b_len = strlen(b->name);

	ret = (a_len > b_len) - (a_len < b_len);
	if (ret != 0) return ret;

	return memcmp(a->name, b->name, a_len);
}


/*
 *	find the appropriate registered xlat function.
 */
xlat_t *xlat_func_find(char const *in, ssize_t inlen)
{
	char buffer[256];

	if (!xlat_root) return NULL;

	if (inlen < 0) {
		return rbtree_finddata(xlat_root, &(xlat_t){ .name = in });
	}

	if ((size_t) inlen >= sizeof(buffer)) return NULL;

	memcpy(buffer, in, inlen);
	buffer[inlen] = '\0';

	return rbtree_finddata(xlat_root, &(xlat_t){ .name = buffer });
}


/** Remove an xlat function from the function tree
 *
 * @param[in] xlat	to free.
 * @return 0
 */
static int _xlat_func_talloc_free(xlat_t *xlat)
{
	if (!xlat_root) return 0;

	rbtree_deletebydata(xlat_root, xlat);
	if (rbtree_num_elements(xlat_root) == 0) TALLOC_FREE(xlat_root);

	return 0;
}


/** Callback for the rbtree to clear out any xlats still registered
 *
 */
static void _xlat_func_tree_free(void *xlat)
{
	talloc_free(xlat);
}


/** Register an old style xlat function
 *
 * @note No new legacy xlat functions should be added to the server.
 *       Each one added creates additional work later for a member
 *	 of the development team to fix the function to conform to
 *	 the new API.
 *
 * @param[in] mod_inst		Instance of module that's registering the xlat function.
 * @param[in] name		xlat name.
 * @param[in] func		xlat function to be called.
 * @param[in] escape		function to sanitize any sub expansions passed to the xlat function.
 * @param[in] instantiate	function to pre-parse any xlat specific data.
 * @param[in] inst_size		sizeof() this xlat's instance data.
 * @param[in] buf_len		Size of the output buffer to allocate when calling the function.
 *				May be 0 if the function allocates its own buffer.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_register_legacy(void *mod_inst, char const *name,
			 xlat_func_legacy_t func, xlat_escape_legacy_t escape,
			 xlat_instantiate_t instantiate, size_t inst_size,
			 size_t buf_len)
{
	xlat_t	*c;
	bool	is_new = false;

	if (!xlat_root && (xlat_init() < 0)) return -1;;

	if (!name || !*name) {
		ERROR("%s: Invalid xlat name", __FUNCTION__);
		return -1;
	}

	/*
	 *	If it already exists, replace the instance.
	 */
	c = rbtree_finddata(xlat_root, &(xlat_t){ .name = name });
	if (c) {
		if (c->internal) {
			ERROR("%s: Cannot re-define internal expansion %s", __FUNCTION__, name);
			return -1;
		}
	/*
	 *	Doesn't exist.  Create it.
	 */
	} else {
		c = talloc_zero(xlat_root, xlat_t);
		c->name = talloc_typed_strdup(c, name);
		talloc_set_destructor(c, _xlat_func_talloc_free);
		is_new = true;
	}

	c->func.sync = func;
	c->type = XLAT_FUNC_LEGACY;
	c->buf_len = buf_len;
	c->escape = escape;
	c->mod_inst = mod_inst;
	c->instantiate = instantiate;
	c->inst_size = inst_size;
	c->needs_async = false;

	DEBUG3("%s: %s", __FUNCTION__, c->name);

	if (is_new && !rbtree_insert(xlat_root, c)) {
		ERROR("Failed inserting xlat registration for %s",
		      c->name);
		talloc_free(c);
		return -1;
	}

	return 0;
}


/** Register an xlat function
 *
 * @param[in] ctx		Used to automate deregistration of the xlat fnction.
 * @param[in] name		of the xlat.
 * @param[in] func		to register.
 * @param[in] needs_async	Requires asynchronous evaluation.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
xlat_t const *xlat_register(TALLOC_CTX *ctx, char const *name, xlat_func_t func, bool needs_async)
{
	xlat_t	*c;

	if (!xlat_root) xlat_init();

	if (!name || !*name) {
		ERROR("%s: Invalid xlat name", __FUNCTION__);
		return NULL;
	}

	/*
	 *	If it already exists, replace the instance.
	 */
	c = rbtree_finddata(xlat_root, &(xlat_t){ .name = name });
	if (c) {
		if (c->internal) {
			ERROR("%s: Cannot re-define internal expansion %s", __FUNCTION__, name);
			return NULL;
		}

		if ((c->type != XLAT_FUNC_NORMAL) || (c->needs_async != needs_async)) {
			ERROR("%s: Cannot change async capability of %s", __FUNCTION__, name);
			return NULL;
		}

		if (c->func.async != func) {
			ERROR("%s: Cannot change callback function for %s", __FUNCTION__, name);
			return NULL;
		}

		return c;
	}

	/*
	 *	Doesn't exist.  Create it.
	 */
	c = talloc_zero(ctx, xlat_t);
	c->name = talloc_typed_strdup(c, name);
	talloc_set_destructor(c, _xlat_func_talloc_free);

	c->func.async = func;
	c->type = XLAT_FUNC_NORMAL;
	c->needs_async = needs_async;	/* this function may yield */

	DEBUG3("%s: %s", __FUNCTION__, c->name);

	if (!rbtree_insert(xlat_root, c)) {
		ERROR("%s: Failed inserting xlat registration for %s", __FUNCTION__, c->name);
		talloc_free(c);
		return NULL;
	}

	return c;
}


/** Mark an xlat function as internal
 *
 * @param[in] name of function to find.
 * @return
 *	- -1 on failure (function doesn't exist).
 *	- 0 on success.
 */
int xlat_internal(char const *name)
{
	xlat_t *c;

	c = xlat_func_find(name, -1);
	if (!c) return -1;

	c->internal = true;

	return 0;
}


/** Set global instantiation/detach callbacks
 *
 * All functions registered must be needs_async.
 *
 * @param[in] xlat		to set instantiation callbacks for.
 * @param[in] instantiate	Instantiation function. Called whenever a xlat is
 *				compiled.
 * @param[in] inst_type		Name of the instance structure.
 * @param[in] inst_size		The size of the instance struct.
 *				Pre-allocated for use by the instantiate function.
 *				If 0, no memory will be allocated.
 * @param[in] detach		Called when an xlat_exp_t is freed.
 * @param[in] uctx		Passed to the instantiation function.
 */
void _xlat_async_instantiate_set(xlat_t const *xlat,
				 xlat_instantiate_t instantiate, char const *inst_type, size_t inst_size,
				 xlat_detach_t detach,
				 void *uctx)
{
	xlat_t *c;

	memcpy(&c, &xlat, sizeof(c));

	c->instantiate = instantiate;
	c->inst_type = inst_type;
	c->inst_size = inst_size;
	c->detach = detach;
	c->uctx = uctx;
}


/** Register an async xlat
 *
 * All functions registered must be needs_async.
 *
 * @param[in] xlat			to set instantiation callbacks for.
 * @param[in] thread_instantiate	Instantiation function. Called for every compiled xlat
 *					every time a thread is started.
 * @param[in] thread_inst_type		Name of the thread instance structure.
 * @param[in] thread_inst_size		The size of the thread instance struct.
 *					Pre-allocated for use by the instantiate function.
 *					If 0, no memory will be allocated.
 * @param[in] thread_detach		Called when the thread is freed.
 * @param[in] uctx			Passed to the thread instantiate function.
 */
void _xlat_async_thread_instantiate_set(xlat_t const *xlat,
					xlat_thread_instantiate_t thread_instantiate,
				        char const *thread_inst_type, size_t thread_inst_size,
				        xlat_thread_detach_t thread_detach,
				        void *uctx)
{
	xlat_t *c;

	memcpy(&c, &xlat, sizeof(c));

	c->thread_instantiate = thread_instantiate;
	c->thread_inst_type = thread_inst_type;
	c->thread_inst_size = thread_inst_size;
	c->thread_detach = thread_detach;
	c->thread_uctx = uctx;
}


/** Unregister an xlat function
 *
 * We can only have one function to call per name, so the passing of "func"
 * here is extraneous.
 *
 * @param[in] name xlat to unregister.
 */
void xlat_unregister(char const *name)
{
	xlat_t	*c;

	if (!name || !xlat_root) return;

	c = rbtree_finddata(xlat_root, &(xlat_t){ .name = name });
	if (!c) return;

	(void) talloc_get_type_abort(c, xlat_t);

	talloc_free(c);	/* Should also remove from tree */
}


static int _xlat_unregister_callback(void *data, void *mod_inst)
{
	xlat_t *c = (xlat_t *) data;

	if (c->mod_inst != mod_inst) return 0; /* keep walking */

	return 2;		/* delete it */
}


void xlat_unregister_module(void *instance)
{
	if (!xlat_root) return;	/* All xlats have already been freed */

	rbtree_walk(xlat_root, RBTREE_DELETE_ORDER, _xlat_unregister_callback, instance);
}


/*
 *	Internal redundant handler for xlats
 */
typedef enum xlat_redundant_type_t {
	XLAT_REDUNDANT_INVALID = 0,
	XLAT_REDUNDANT,
	XLAT_LOAD_BALANCE,
	XLAT_REDUNDANT_LOAD_BALANCE,
} xlat_redundant_type_t;

typedef struct {
	xlat_redundant_type_t		type;
	uint32_t			count;
	CONF_SECTION const		*cs;
} xlat_redundant_t;


/** xlat "redundant" processing
 *
 * Processes xlat calls for modules defined in "redundant"
 * sub-sections of the instantiate configuration.
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_redundant(TALLOC_CTX *ctx, char **out, NDEBUG_UNUSED size_t outlen,
			      void const *mod_inst, UNUSED void const *xlat_inst,
			      request_t *request, char const *fmt)
{
	xlat_redundant_t const *xr = mod_inst;
	CONF_ITEM *ci;
	char const *name;
	xlat_t *xlat;

	fr_assert((*out == NULL) && (outlen == 0));	/* Caller must not have allocated buf */
	fr_assert(xr->type == XLAT_REDUNDANT);

	/*
	 *	Pick the first xlat which succeeds
	 */
	for (ci = cf_item_next(xr->cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(xr->cs, ci)) {
		ssize_t ret;

		if (!cf_item_is_pair(ci)) continue;

		name = cf_pair_attr(cf_item_to_pair(ci));
		fr_assert(name != NULL);

		xlat = xlat_func_find(name, -1);
		if (!xlat) continue;

		if (xlat->buf_len > 0) {
			*out = talloc_array(ctx, char, xlat->buf_len);
			**out = '\0';	/* Be sure the string is \0 terminated */
		} else {
			*out = NULL;
		}

		ret = xlat->func.sync(ctx, out, xlat->buf_len, xlat->mod_inst, NULL, request, fmt);
		if (ret <= 0) {
			TALLOC_FREE(*out);
			continue;
		}
		return ret;
	}

	/*
	 *	Everything failed.  Oh well.
	 */
	*out = NULL;
	return 0;
}


/** xlat "load-balance" processing
 *
 * Processes xlat calls for modules defined in "load-balance"
 * sub-sections of the instantiate configuration.
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_load_balance(TALLOC_CTX *ctx, char **out, NDEBUG_UNUSED size_t outlen,
				 void const *mod_inst, UNUSED void const *xlat_inst,
				 request_t *request, char const *fmt)
{
	uint32_t count = 0;
	xlat_redundant_t const *xr = mod_inst;
	CONF_ITEM *ci;
	CONF_ITEM *found = NULL;
	char const *name;
	xlat_t *xlat;

	fr_assert((*out == NULL) && (outlen == 0));	/* Caller must not have allocated buf */

	/*
	 *	Choose a child at random.
	 */
	for (ci = cf_item_next(xr->cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(xr->cs, ci)) {
		if (!cf_item_is_pair(ci)) continue;
		count++;

		/*
		 *	Replace the previously found one with a random
		 *	new one.
		 */
		if ((count * (fr_rand() & 0xffff)) < (uint32_t) 0x10000) {
			found = ci;
		}
	}

	/*
	 *	Plain load balancing: do one child, and only one child.
	 */
	if (xr->type == XLAT_LOAD_BALANCE) {
		ssize_t slen;
		name = cf_pair_attr(cf_item_to_pair(found));
		fr_assert(name != NULL);

		xlat = xlat_func_find(name, -1);
		if (!xlat) return -1;

		if (xlat->buf_len > 0) {
			*out = talloc_array(ctx, char, xlat->buf_len);
			**out = '\0';	/* Be sure the string is \0 terminated */
		} else {
			*out = NULL;
		}
		slen = xlat->func.sync(ctx, out, xlat->buf_len, xlat->mod_inst, NULL, request, fmt);
		if (slen <= 0) TALLOC_FREE(*out);

		return slen;
	}

	fr_assert(xr->type == XLAT_REDUNDANT_LOAD_BALANCE);

	/*
	 *	Try the random one we found.  If it fails, keep going
	 *	through the rest of the children.
	 */
	ci = found;
	do {
		name = cf_pair_attr(cf_item_to_pair(ci));
		fr_assert(name != NULL);

		xlat = xlat_func_find(name, -1);
		if (xlat) {
			ssize_t ret;

			if (xlat->buf_len > 0) {
				*out = talloc_array(ctx, char, xlat->buf_len);
				**out = '\0';	/* Be sure the string is \0 terminated */
			} else {
				*out = NULL;
			}
			ret = xlat->func.sync(ctx, out, xlat->buf_len, xlat->mod_inst, NULL, request, fmt);
			if (ret > 0) return ret;
			TALLOC_FREE(*out);
		}

		/*
		 *	Go to the next one, wrapping around at the end.
		 */
		ci = cf_item_next(xr->cs, ci);
		if (!ci) ci = cf_item_next(xr->cs, NULL);
	} while (ci != found);

	return -1;
}


/** Registers a redundant xlat
 *
 * These xlats wrap the xlat methods of the modules in a redundant section,
 * emulating the behaviour of a redundant section, but over xlats.
 *
 * @todo - make xlat_register_legacy() take ASYNC / SYNC / UNKNOWN.  We may
 * need "unknown" here in order to properly handle the children, which
 * we don't know are async-safe or not.  For now, it's best to assume
 * that all xlat's in a redundant block are module calls, and are not async-safe
 *
 * @return
 *	- 0 on success.
 *	- -1 on error.
 *	- 1 if the modules in the section do not have an xlat method.
 */
int xlat_register_legacy_redundant(CONF_SECTION *cs)
{
	char const *name1, *name2;
	xlat_redundant_t *xr;

	name1 = cf_section_name1(cs);
	name2 = cf_section_name2(cs);

	if (xlat_func_find(name2, -1)) {
		cf_log_err(cs, "An expansion is already registered for this name");
		return -1;
	}

	MEM(xr = talloc_zero(cs, xlat_redundant_t));

	if (strcmp(name1, "redundant") == 0) {
		xr->type = XLAT_REDUNDANT;
	} else if (strcmp(name1, "redundant-load-balance") == 0) {
		xr->type = XLAT_REDUNDANT_LOAD_BALANCE;
	} else if (strcmp(name1, "load-balance") == 0) {
		xr->type = XLAT_LOAD_BALANCE;
	} else {
		fr_assert(0);
	}

	xr->cs = cs;

	/*
	 *	Get the number of children for load balancing.
	 */
	if (xr->type == XLAT_REDUNDANT) {
		if (xlat_register_legacy(xr, name2, xlat_redundant, NULL, NULL, 0, 0) < 0) {
			ERROR("Registering xlat for redundant section failed");
			talloc_free(xr);
			return -1;
		}

	} else {
		CONF_ITEM *ci = NULL;

		while ((ci = cf_item_next(cs, ci))) {
			char const *attr;

			if (!cf_item_is_pair(ci)) continue;

			attr = cf_pair_attr(cf_item_to_pair(ci));

			/*
			 *	This is ok, it just means the module
			 *	doesn't have an xlat method.
			 */
			if (!xlat_func_find(attr, -1)) {
				talloc_free(xr);
				return 1;
			}

			xr->count++;
		}

		if (xlat_register_legacy(xr, name2, xlat_load_balance, NULL, NULL, 0, 0) < 0) {
			ERROR("Registering xlat for load-balance section failed");
			talloc_free(xr);
			return -1;
		}
	}

	return 0;
}



/*
 *	Regular xlat functions
 */


/** Dynamically change the debugging level for the current request
 *
 * Example:
@verbatim
"%{debug:3}"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_func_debug(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			       UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			       request_t *request, char const *fmt)
{
	int level = 0;

	/*
	 *  Expand to previous (or current) level
	 */
	snprintf(*out, outlen, "%d", request->log.lvl);

	/*
	 *  Assume we just want to get the current value and NOT set it to 0
	 */
	if (!*fmt)
		goto done;

	level = atoi(fmt);
	if (level == 0) {
		request->log.lvl = RAD_REQUEST_LVL_NONE;
	} else {
		if (level > L_DBG_LVL_MAX) level = L_DBG_LVL_MAX;
		request->log.lvl = level;
	}

done:
	return strlen(*out);
}


/** Print out attribute info
 *
 * Prints out all instances of a current attribute, or all attributes in a list.
 *
 * At higher debugging levels, also prints out alternative decodings of the same
 * value. This is helpful to determine types for unknown attributes of long
 * passed vendors, or just crazy/broken NAS.
 *
 * This expands to a zero length string.
 *
 * Example:
@verbatim
"%{debug_attr:&request[*]}"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_func_debug_attr(UNUSED TALLOC_CTX *ctx, UNUSED char **out, UNUSED size_t outlen,
				    UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				    request_t *request, char const *fmt)
{
	fr_pair_t		*vp;
	fr_cursor_t		cursor;
	tmpl_cursor_ctx_t	cc;
	tmpl_t			*vpt;

	if (!RDEBUG_ENABLED2) return 0;	/* NOOP if debugging isn't enabled */

	fr_skip_whitespace(fmt);

	if (tmpl_afrom_attr_str(request, NULL, &vpt, fmt,
				&(tmpl_rules_t){
					.dict_def = request->dict,
					.prefix = TMPL_ATTR_REF_PREFIX_AUTO
				}) <= 0) {
		RPEDEBUG("Invalid input");
		return -1;
	}

	RIDEBUG("Attributes matching \"%s\"", fmt);

	RINDENT();
	for (vp = tmpl_cursor_init(NULL, NULL, &cc, &cursor, request, vpt);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		fr_dict_vendor_t const		*vendor;
		fr_table_num_ordered_t const	*type;
		size_t				i;

		switch (vp->da->type) {
		case FR_TYPE_STRUCTURAL:
			if (!vp->vp_group) {
				RIDEBUG2("&%s.%s %s {}",
					 fr_table_str_by_value(pair_list_table, tmpl_list(vpt), "<INVALID>"),
					 vp->da->name,
					 fr_table_str_by_value(fr_tokens_table, vp->op, "<INVALID>"));
			} else {
				RIDEBUG2("&%s.%s %s {...}", /* @todo */
					 fr_table_str_by_value(pair_list_table, tmpl_list(vpt), "<INVALID>"),
					 vp->da->name,
					 fr_table_str_by_value(fr_tokens_table, vp->op, "<INVALID>"));
			}
			break;

		default:
			RIDEBUG2("&%s.%s %s %pV",
				 fr_table_str_by_value(pair_list_table, tmpl_list(vpt), "<INVALID>"),
				 vp->da->name,
				 fr_table_str_by_value(fr_tokens_table, vp->op, "<INVALID>"),
				 &vp->data);
		}

		if (!RDEBUG_ENABLED3) continue;

		RIDEBUG3("da         : %p", vp->da);
		RIDEBUG3("is_raw     : %pV", fr_box_bool(vp->da->flags.is_raw));
		RIDEBUG3("is_unknown : %pV", fr_box_bool(vp->da->flags.is_unknown));

		if (RDEBUG_ENABLED3) {
			RIDEBUG3("parent     : %s (%p)", vp->da->parent->name, vp->da->parent);
		} else {
			RIDEBUG2("parent     : %s", vp->da->parent->name);
		}
		RIDEBUG3("attr       : %u", vp->da->attr);
		vendor = fr_dict_vendor_by_da(vp->da);
		if (vendor) RIDEBUG2("vendor     : %i (%s)", vendor->pen, vendor->name);
		RIDEBUG3("type       : %s", fr_table_str_by_value(fr_value_box_type_table, vp->vp_type, "<INVALID>"));

		switch (vp->vp_type) {
		case FR_TYPE_VARIABLE_SIZE:
			RIDEBUG3("length     : %zu", vp->vp_length);
			break;

		default:
			break;
		}

		if (!RDEBUG_ENABLED4) continue;

		for (i = 0; i < fr_value_box_type_table_len; i++) {
			int pad;

			fr_value_box_t *dst = NULL;

			type = &fr_value_box_type_table[i];

			if ((fr_type_t) type->value == vp->vp_type) goto next_type;

			switch (type->value) {
			case FR_TYPE_NON_VALUES:	/* Skip everything that's not a value */
				goto next_type;

			default:
				break;
			}

			dst = fr_value_box_alloc_null(vp);
			/* We expect some to fail */
			if (fr_value_box_cast(dst, dst, type->value, NULL, &vp->data) < 0) {
				goto next_type;
			}

			if ((pad = (11 - type->name.len)) < 0) pad = 0;

			RINDENT();
			RDEBUG4("as %s%*s: %pV", type->name.str, pad, " ", dst);
			REXDENT();

		next_type:
			talloc_free(dst);
		}
	}
	tmpl_cursor_clear(&cc);
	REXDENT();

	talloc_free(vpt);

	return 0;
}


/** Split an attribute into multiple new attributes based on a delimiter
 *
 * @todo should support multibyte delimiter for string types.
 *
@verbatim
%{explode:&ref <delim>}
@endverbatim
 *
 * Example:
@verbatim
update request {
	&Tmp-String-1 := "a,b,c"
}
if ("%{explode:&Tmp-String-1 ,}" != 3) {
	reject
}
@endverbatim
 * Replaces Tmp-String-1 with three new attributes:
@verbatim
&Tmp-String-1 = "a"
&Tmp-String-1 = "b"
&Tmp-String-1 = "c"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_func_explode(TALLOC_CTX *ctx, char **out, size_t outlen,
				 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				 request_t *request, char const *fmt)
{
	tmpl_t			*vpt = NULL;
	fr_pair_t		*vp;
	fr_cursor_t		cursor, to_merge;
	tmpl_cursor_ctx_t	cc;
	fr_pair_list_t		head;
	ssize_t			slen;
	int			count = 0;
	char const		*p = fmt;
	char			delim;

	fr_pair_list_init(&head);
	/*
	 *  Trim whitespace
	 */
	fr_skip_whitespace(p);

	slen = tmpl_afrom_attr_substr(ctx, NULL, &vpt,
				      &FR_SBUFF_IN(p, strlen(p)),
				      &xlat_arg_parse_rules,
				      &(tmpl_rules_t){ .dict_def = request->dict });
	if (slen <= 0) {
		RPEDEBUG("Invalid input");
		return -1;
	}

	p += slen;

	if (*p++ != ' ') {
	arg_error:
		talloc_free(vpt);
		REDEBUG("explode needs exactly two arguments: &ref <delim>");
		return -1;
	}

	if (*p == '\0' || p[1]) goto arg_error;

	delim = *p;

	fr_cursor_init(&to_merge, &head);

	vp = tmpl_cursor_init(NULL, NULL, &cc, &cursor, request, vpt);
	while (vp) {
		fr_pair_t *nvp;
		char const *end;
		char const *q;

		/*
		 *	This can theoretically operate on lists too
		 *	so we need to check the type of each attribute.
		 */
		switch (vp->vp_type) {
		case FR_TYPE_OCTETS:
		case FR_TYPE_STRING:
			break;

		default:
			goto next;
		}

		p = vp->vp_ptr;
		end = p + vp->vp_length;
		while (p < end) {
			q = memchr(p, delim, end - p);
			if (!q) {
				/* Delimiter not present in attribute */
				if (p == vp->vp_ptr) goto next;
				q = end;
			}

			/* Skip zero length */
			if (q == p) {
				p = q + 1;
				continue;
			}

			MEM(nvp = fr_pair_afrom_da(talloc_parent(vp), vp->da));
			switch (vp->vp_type) {
			case FR_TYPE_OCTETS:
				MEM(fr_pair_value_memdup(nvp, (uint8_t const *)p, q - p, vp->vp_tainted) == 0);
				break;

			case FR_TYPE_STRING:
				MEM(fr_pair_value_bstrndup(nvp, p, q - p, vp->vp_tainted) == 0);
				break;

			default:
				fr_assert(0);
			}

			fr_cursor_append(&to_merge, nvp);

			p = q + 1;	/* next */

			count++;
		}

		/*
		 *	Remove the unexploded version
		 */
		vp = fr_cursor_remove(&cursor);
		talloc_free(vp);
		/*
		 *	Remove sets cursor->current to
		 *	the next iter value.
		 */
		vp = fr_cursor_current(&cursor);
		continue;

	next:
		vp = fr_cursor_next(&cursor);
	}
	tmpl_cursor_clear(&cc);

	fr_cursor_head(&to_merge);
	fr_cursor_merge(&cursor, &to_merge);
	talloc_free(vpt);

	return snprintf(*out, outlen, "%i", count);
}


/** Print data as integer, not as VALUE.
 *
 * Example:
@verbatim
update request {
	&Tmp-IP-Address-0 := "127.0.0.5"
}
"%{integer:&Tmp-IP-Address-0}" == 2130706437
@endverbatim
 * @ingroup xlat_functions
 */
static ssize_t xlat_func_integer(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				 request_t *request, char const *fmt)
{
	fr_pair_t	*vp;

	uint64_t	int64 = 0;	/* Needs to be initialised to zero */
	uint32_t	int32 = 0;	/* Needs to be initialised to zero */

	fr_skip_whitespace(fmt);

	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) return 0;

	switch (vp->vp_type) {
	case FR_TYPE_DATE:
	case FR_TYPE_STRING:
	{
		fr_value_box_t vb;

		if (fr_value_box_cast(NULL, &vb, FR_TYPE_UINT64, NULL, &vp->data) < 0) {
			RPEDEBUG("Invalid input for printing as an integer");
			return -1;
		}

		return snprintf(*out, outlen, "%" PRIu64, vb.vb_uint64);
	}

	case FR_TYPE_OCTETS:
		if (vp->vp_length > 8) {
			break;
		}

		if (vp->vp_length > 4) {
			memcpy(&int64, vp->vp_octets, vp->vp_length);
			return snprintf(*out, outlen, "%" PRIu64, htonll(int64));
		}

		memcpy(&int32, vp->vp_octets, vp->vp_length);
		return snprintf(*out, outlen, "%i", htonl(int32));

	case FR_TYPE_UINT64:
		return snprintf(*out, outlen, "%" PRIu64, vp->vp_uint64);

	/*
	 *	IP addresses are treated specially, as parsing functions assume the value
	 *	is bigendian and will convert it for us.
	 */
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:	/* Same addr field */
		return snprintf(*out, outlen, "%u", ntohl(vp->vp_ipv4addr));

	case FR_TYPE_UINT32:
		return snprintf(*out, outlen, "%u", vp->vp_uint32);

	case FR_TYPE_UINT8:
		return snprintf(*out, outlen, "%u", (unsigned int) vp->vp_uint8);

	case FR_TYPE_UINT16:
		return snprintf(*out, outlen, "%u", (unsigned int) vp->vp_uint16);

	/*
	 *	Ethernet is weird... It's network related, so it
	 *	should be bigendian.
	 */
	case FR_TYPE_ETHERNET:
		int64 = vp->vp_ether[0];
		int64 <<= 8;
		int64 |= vp->vp_ether[1];
		int64 <<= 8;
		int64 |= vp->vp_ether[2];
		int64 <<= 8;
		int64 |= vp->vp_ether[3];
		int64 <<= 8;
		int64 |= vp->vp_ether[4];
		int64 <<= 8;
		int64 |= vp->vp_ether[5];
		return snprintf(*out, outlen, "%" PRIu64, int64);

	case FR_TYPE_INT32:
		return snprintf(*out, outlen, "%i", vp->vp_int32);

	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
		return fr_snprint_uint128(*out, outlen, ntohlll(*(uint128_t const *) &vp->vp_ipv6addr));

	default:
		break;
	}

	REDEBUG("Type '%s' cannot be converted to integer", fr_table_str_by_value(fr_value_box_type_table, vp->vp_type, "???"));

	return -1;
}


/** Parse the 3 arguments to lpad / rpad.
 *
 * Parses a fmt string with the components @verbatim <tmpl> <pad_len> <pad_char>@endverbatim
 *
 * @param[out] vpt_p		Template to retrieve value to pad.
 * @param[out] pad_len_p	Length the string needs to be padded to.
 * @param[out] pad_char_p	Char to use for padding.
 * @param[in] request		The current request.
 * @param[in] fmt		string to parse.
 *
 * @return
 *	- <= 0 the negative offset the parse error ocurred at.
 *	- >0 how many bytes of fmt were parsed.
 */
static ssize_t parse_pad(tmpl_t **vpt_p, size_t *pad_len_p, char *pad_char_p, request_t *request, char const *fmt)
{
	ssize_t			slen;
	unsigned long		pad_len;
	char const		*p;
	char			*end;
	tmpl_t			*vpt;


	*pad_char_p = ' ';		/* the default */

	*vpt_p = NULL;

	p = fmt;
	fr_skip_whitespace(p);

	if (*p != '&') {
		REDEBUG("First argument must be an attribute reference");
		return 0;
	}

	slen = tmpl_afrom_attr_substr(request, NULL, &vpt,
				      &FR_SBUFF_IN(p, strlen(p)),
				      &xlat_arg_parse_rules,
				      &(tmpl_rules_t){ .dict_def = request->dict });
	if (slen <= 0) {
		RPEDEBUG("Failed parsing input string");
		return slen;
	}

	p = fmt + slen;

	fr_skip_whitespace(p);

	pad_len = strtoul(p, &end, 10);
	if ((pad_len == ULONG_MAX) || (pad_len > 8192)) {
		talloc_free(vpt);
		REDEBUG("Invalid pad_len found at: %s", p);
		return fmt - p;
	}

	p += (end - p);

	/*
	 *	The pad_char_p character is optional.
	 *
	 *	But we must have a space after the previous number,
	 *	and we must have only ONE pad_char_p character.
	 */
	if (*p) {
		if (!isspace(*p)) {
			talloc_free(vpt);
			REDEBUG("Invalid text found at: %s", p);
			return fmt - p;
		}

		fr_skip_whitespace(p);

		if (p[1] != '\0') {
			talloc_free(vpt);
			REDEBUG("Invalid text found at: %s", p);
			return fmt - p;
		}

		*pad_char_p = *p++;
	}

	*vpt_p = vpt;
	*pad_len_p = pad_len;

	return p - fmt;
}


/** Left pad a string
 *
@verbatim
%{lpad:&Attribute-Name <length> <char>}
@endverbatim
 *
 * Example: (User-Name = "foo")
@verbatim
"%{lpad:&User-Name 5 x}" == "xxfoo"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_func_lpad(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
			      UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			      request_t *request, char const *fmt)
{
	char		fill;
	size_t		pad;
	ssize_t		len;
	tmpl_t	*vpt;
	char		*to_pad = NULL;

	if (parse_pad(&vpt, &pad, &fill, request, fmt) <= 0) return 0;

	if (!fr_cond_assert(vpt)) return 0;

	/*
	 *	Print the attribute (left justified).  If it's too
	 *	big, we're done.
	 */
	len = tmpl_aexpand(ctx, &to_pad, request, vpt, NULL, NULL);
	if (len <= 0) return -1;

	/*
	 *	Already big enough, no padding required...
	 */
	if ((size_t) len >= pad) {
		*out = to_pad;
		return pad;
	}

	/*
	 *	Realloc is actually pretty cheap in most cases...
	 */
	MEM(to_pad = talloc_realloc(ctx, to_pad, char, pad + 1));

	/*
	 *	We have to shift the string to the right, and pad with
	 *	"fill" characters.
	 */
	memmove(to_pad + (pad - len), to_pad, len + 1);
	memset(to_pad, fill, pad - len);

	*out = to_pad;

	return pad;
}


/** Processes fmt as a map string and applies it to the current request
 *
 * e.g.
@verbatim
%{map:&User-Name := 'foo'}
@endverbatim
 *
 * Allows sets of modifications to be cached and then applied.
 * Useful for processing generic attributes from LDAP.
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_func_map(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			     UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			     request_t *request, char const *fmt)
{
	map_t	*map = NULL;
	int		ret;

	tmpl_rules_t	attr_rules = {
		.dict_def = request->dict,
		.prefix = TMPL_ATTR_REF_PREFIX_AUTO
	};

	if (map_afrom_attr_str(request, &map, fmt, &attr_rules, &attr_rules) < 0) {
		RPEDEBUG("Failed parsing \"%s\" as map", fmt);
		return -1;
	}

	switch (map->lhs->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_XLAT:
		break;

	default:
		REDEBUG("Unexpected type %s in left hand side of expression",
			fr_table_str_by_value(tmpl_type_table, map->lhs->type, "<INVALID>"));
		return strlcpy(*out, "0", outlen);
	}

	switch (map->rhs->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_EXEC:
	case TMPL_TYPE_DATA:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:
	case TMPL_TYPE_UNRESOLVED:
	case TMPL_TYPE_XLAT:
		break;

	default:
		REDEBUG("Unexpected type %s in right hand side of expression",
			fr_table_str_by_value(tmpl_type_table, map->rhs->type, "<INVALID>"));
		return strlcpy(*out, "0", outlen);
	}

	RINDENT();
	ret = map_to_request(request, map, map_to_vp, NULL);
	REXDENT();
	talloc_free(map);
	if (ret < 0) return strlcpy(*out, "0", outlen);

	return strlcpy(*out, "1", outlen);
}


/** Calculate number of seconds until the next n hour(s), day(s), week(s), year(s).
 *
 * For example, if it were 16:18 %{nexttime:1h} would expand to 2520.
 *
 * The envisaged usage for this function is to limit sessions so that they don't
 * cross billing periods. The output of the xlat should be combined with %{rand:} to create
 * some jitter, unless the desired effect is every subscriber on the network
 * re-authenticating at the same time.
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_func_next_time(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				   request_t *request, char const *fmt)
{
	long		num;

	char const	*p;
	char		*q;
	time_t		now;
	struct tm	*local, local_buff;

	now = time(NULL);
	local = localtime_r(&now, &local_buff);

	p = fmt;

	num = strtoul(p, &q, 10);
	if (!q || *q == '\0') {
		REDEBUG("nexttime: <int> must be followed by period specifier (h|d|w|m|y)");
		return -1;
	}

	if (p == q) {
		num = 1;
	} else {
		p += q - p;
	}

	local->tm_sec = 0;
	local->tm_min = 0;

	switch (*p) {
	case 'h':
		local->tm_hour += num;
		break;

	case 'd':
		local->tm_hour = 0;
		local->tm_mday += num;
		break;

	case 'w':
		local->tm_hour = 0;
		local->tm_mday += (7 - local->tm_wday) + (7 * (num-1));
		break;

	case 'm':
		local->tm_hour = 0;
		local->tm_mday = 1;
		local->tm_mon += num;
		break;

	case 'y':
		local->tm_hour = 0;
		local->tm_mday = 1;
		local->tm_mon = 0;
		local->tm_year += num;
		break;

	default:
		REDEBUG("nexttime: Invalid period specifier '%c', must be h|d|w|m|y", *p);
		return -1;
	}

	return snprintf(*out, outlen, "%" PRIu64, (uint64_t)(mktime(local) - now));
}


/** Right pad a string
 *
@verbatim
%{rpad:&Attribute-Name <length> <char>}
@endverbatim
 *
 * Example: (User-Name = "foo")
@verbatim
"%{rpad:&User-Name 5 x}" == "fooxx"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_func_rpad(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
			      UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			      request_t *request, char const *fmt)
{
	char		fill;
	size_t		pad;
	ssize_t		len;
	tmpl_t	*vpt;
	char		*to_pad = NULL;

	fr_assert(!*out);

	if (parse_pad(&vpt, &pad, &fill, request, fmt) <= 0) return 0;

	if (!fr_cond_assert(vpt)) return 0;

	/*
	 *	Print the attribute (left justified).  If it's too
	 *	big, we're done.
	 */
	len = tmpl_aexpand(ctx, &to_pad, request, vpt, NULL, NULL);
	if (len <= 0) return 0;

	if ((size_t) len >= pad) {
		*out = to_pad;
		return pad;
	}

	MEM(to_pad = talloc_realloc(ctx, to_pad, char, pad + 1));

	/*
	 *	We have to pad with "fill" characters.
	 */
	memset(to_pad + len, fill, pad - len);
	to_pad[pad] = '\0';

	*out = to_pad;

	return pad;
}


/** xlat expand string attribute value
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_func_xlat(TALLOC_CTX *ctx, char **out, size_t outlen,
			      UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			      request_t *request, char const *fmt)
{
	ssize_t		slen;
	fr_pair_t	*vp;

	fr_skip_whitespace(fmt);

	if (outlen < 3) {
	nothing:
		return 0;
	}

	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) goto nothing;

	RDEBUG2("EXPAND %s", fmt);
	RINDENT();

	/*
	 *	If it's a string, expand it again
	 */
	if (vp->vp_type == FR_TYPE_STRING) {
		slen = xlat_eval(*out, outlen, request, vp->vp_strvalue, NULL, NULL);
		if (slen <= 0) return slen;
	/*
	 *	If it's not a string, treat it as a literal
	 */
	} else {
		slen = fr_value_box_aprint(ctx, out, &vp->data, NULL);
		if (!*out) return -1;
	}

	REXDENT();
	RDEBUG2("--> %s", *out);

	return slen;
}



/*
 *	Async xlat functions
 */


/** Encode string or attribute as base64
 *
 * Example:
@verbatim
"%{base64:foo}" == "Zm9v"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_base64_encode(TALLOC_CTX *ctx, fr_cursor_t *out,
					     request_t *request, UNUSED void const *xlat_inst,
					     UNUSED void *xlat_thread_inst,
					     fr_value_box_t **in)
{
	size_t		alen;
	ssize_t		elen;
	char		*buff;
	fr_value_box_t	*vb;

	/*
	 *	If there's no input, there's no output
	 */
	if (!in) return XLAT_ACTION_DONE;

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	alen = FR_BASE64_ENC_LENGTH((*in)->vb_length);

	MEM(vb = fr_value_box_alloc_null(ctx));
	if (fr_value_box_bstr_alloc(vb, &buff, vb, NULL, alen, false) < 0) {
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	elen = fr_base64_encode(buff, alen + 1, (*in)->vb_octets, (*in)->vb_length);
	if (elen < 0) {
		RPEDEBUG("Base64 encoding failed");
		talloc_free(buff);
		return XLAT_ACTION_FAIL;
	}

	fr_assert((size_t)elen <= alen);
	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Decode base64 string
 *
 * Example:
@verbatim
"%{base64decode:Zm9v}" == "foo"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_base64_decode(TALLOC_CTX *ctx, fr_cursor_t *out,
					     request_t *request, UNUSED void const *xlat_inst,
					     UNUSED void *xlat_thread_inst,
					     fr_value_box_t **in)
{
	size_t		alen;
	ssize_t		declen;
	uint8_t		*decbuf;
	fr_value_box_t	*vb;

	/*
	 *	If there's no input, there's no output
	 */
	if (!in) return XLAT_ACTION_DONE;

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	alen = FR_BASE64_DEC_LENGTH((*in)->vb_length);

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_mem_alloc(vb, &decbuf, vb, NULL, alen, (*in)->tainted) == 0);
	declen = fr_base64_decode(decbuf, alen, (*in)->vb_strvalue, (*in)->vb_length);
	if (declen < 0) {
		talloc_free(vb);
		REDEBUG("Base64 string invalid");
		return XLAT_ACTION_FAIL;
	}
	MEM(fr_value_box_mem_realloc(vb, NULL, vb, declen) == 0);
	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Convert hex string to binary
 *
 * Example:
@verbatim
"%{bin:666f6f626172}" == "foobar"
@endverbatim
 *
 * @see #xlat_func_hex
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_bin(TALLOC_CTX *ctx, fr_cursor_t *out,
				   request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				   fr_value_box_t **in)
{
	fr_value_box_t		*result;
	char			*buff = NULL, *p, *end;
	uint8_t			*bin;
	size_t			len, outlen;
	fr_sbuff_parse_error_t	err;

	/*
	 *	If there's no input, there's no output
	 */
	if (!*in) return XLAT_ACTION_DONE;

	buff = fr_value_box_list_aprint(NULL, *in, NULL, NULL);
	if (!buff) return XLAT_ACTION_FAIL;

	len = talloc_array_length(buff) - 1;
	if ((len > 1) && (len & 0x01)) {
		REDEBUG("Input data length must be >1 and even, got %zu", len);
		talloc_free(buff);
		return XLAT_ACTION_FAIL;
	}

	p = buff;
	end = p + len;

	/*
	 *	Zero length octets string
	 */
	if ((p[0] == '0') && (p[1] == 'x')) p += 2;
	if (p == end) goto finish;

	outlen = len / 2;

	MEM(result = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_mem_alloc(result, &bin, result, NULL, outlen, fr_value_box_list_tainted(*in)) == 0);
	fr_hex2bin(&err, &FR_DBUFF_TMP(bin, outlen), &FR_SBUFF_IN(p, end - p), true);
	if (err) {
		REDEBUG2("Invalid hex string");
		talloc_free(result);
		return XLAT_ACTION_FAIL;
	}

	fr_cursor_append(out, result);

finish:
	talloc_free(buff);
	return XLAT_ACTION_DONE;
}


/** Concatenate values of given attributes using separator
 *
 * First char of xlat is the separator, followed by attributes
 *
 * Example:
@verbatim
"%{concat:, %{User-Name}%{Calling-Station-Id}" == "bob, aa:bb:cc:dd:ee:ff"
"%{concat:, %{request[*]}" == "<attr1value>, <attr2value>, <attr3value>, ..."
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_concat(TALLOC_CTX *ctx, fr_cursor_t *out,
				      request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				      fr_value_box_t **in)
{
	fr_value_box_t	*result;
	fr_value_box_t	*separator;
	char		*buff;
	char const	*sep;

	/*
	 *	If there's no input, there's no output
	 */
	if (!in) return XLAT_ACTION_DONE;

	/*
	 * Separator is first value box
	 */
	separator = *in;

	if (!separator) {
		REDEBUG("Missing separator for concat xlat");
		return XLAT_ACTION_FAIL;
	}

	sep = separator->vb_strvalue;

	result = fr_value_box_alloc_null(ctx);
	if (!result) {
	error:
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	buff = fr_value_box_list_aprint(result, (*in)->next, sep, NULL);
	if (!buff) goto error;

	fr_value_box_bstrdup_buffer_shallow(NULL, result, NULL, buff, fr_value_box_list_tainted((*in)->next));

	fr_cursor_append(out, result);

	return XLAT_ACTION_DONE;
}


/** Print data as hex, not as VALUE.
 *
 * Example:
@verbatim
"%{hex:foobar}" == "666f6f626172"
@endverbatim
 *
 * @see #xlat_func_bin
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_hex(TALLOC_CTX *ctx, fr_cursor_t *out,
				   request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				   fr_value_box_t **in)
{
	char *p;
	fr_value_box_t* vb;

	/*
	 *	If there's no input, there's no output
	 */
	if (!*in) return XLAT_ACTION_DONE;

	/*
	 *	Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false));
	vb->vb_length = ((*in)->vb_length * 2);
	vb->vb_strvalue = p = talloc_zero_array(vb, char, vb->vb_length + 1);
	fr_bin2hex(&FR_SBUFF_OUT(p, talloc_array_length(p)), &FR_DBUFF_TMP((*in)->vb_octets, (*in)->vb_length), SIZE_MAX);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


typedef enum {
	HMAC_MD5,
	HMAC_SHA1
} hmac_type;

static xlat_action_t xlat_hmac(TALLOC_CTX *ctx, fr_cursor_t *out,
				request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				fr_value_box_t **in, uint8_t *digest, int digest_len, hmac_type type)
{
	uint8_t const	*data_p, *key_p;
	size_t		data_len, key_len;
	fr_value_box_t	*vb, *vb_data, *vb_sep, *vb_key;

	if (!in) return XLAT_ACTION_FAIL;

	vb_data = fr_value_box_list_get(*in, 0);
	vb_sep = fr_value_box_list_get(*in, 1);
	vb_key = fr_value_box_list_get(*in, 2);

	if (!vb_data || !vb_sep || !vb_key ||
            vb_sep->vb_length != 1 ||
            vb_sep->vb_strvalue[0] != ' ') {
		REDEBUG("HMAC requires exactly two arguments (%%{data} %%{key})");
		return XLAT_ACTION_FAIL;
	}

	data_p = vb_data->vb_octets;
	data_len = vb_data->vb_length;

	key_p = vb_key->vb_octets;
	key_len = vb_key->vb_length;

	if (type == HMAC_MD5) {
		fr_hmac_md5(digest, data_p, data_len, key_p, key_len);
	} else if (type == HMAC_SHA1) {
		fr_hmac_sha1(digest, data_p, data_len, key_p, key_len);
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, digest_len, false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Generate the HMAC-MD5 of a string or attribute
 *
 * Example:
@verbatim
"%{hmacmd5:%{string:foo} %{string:bar}}" == "0x31b6db9e5eb4addb42f1a6ca07367adc"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_hmac_md5(TALLOC_CTX *ctx, fr_cursor_t *out,
					request_t *request, void const *xlat_inst, void *xlat_thread_inst,
					fr_value_box_t **in)
{
	uint8_t		digest[MD5_DIGEST_LENGTH];
	return xlat_hmac(ctx, out, request, xlat_inst, xlat_thread_inst, in, digest, MD5_DIGEST_LENGTH, HMAC_MD5);
}


/** Generate the HMAC-SHA1 of a string or attribute
 *
 * Example:
@verbatim
"%{hmacsha1:%{string:foo} %{string:bar}}" == "0x85d155c55ed286a300bd1cf124de08d87e914f3a"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_hmac_sha1(TALLOC_CTX *ctx, fr_cursor_t *out,
					 request_t *request, void const *xlat_inst, void *xlat_thread_inst,
					 fr_value_box_t **in)
{
	uint8_t		digest[SHA1_DIGEST_LENGTH];
	return xlat_hmac(ctx, out, request, xlat_inst, xlat_thread_inst, in, digest, SHA1_DIGEST_LENGTH, HMAC_SHA1);
}


/** Return the on-the-wire size of the boxes in bytes
 *
 * Example:
@verbatim
"%{length:foobar}" == 6
"%{length:%{bin:0102030005060708}}" == 8
@endverbatim
 *
 * @see #xlat_func_strlen
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_length(TALLOC_CTX *ctx, fr_cursor_t *out,
				      UNUSED request_t *request, UNUSED void const *xlat_inst,
				      UNUSED void *xlat_thread_inst, fr_value_box_t **in)

{
	fr_value_box_t	*vb;
	fr_cursor_t	cursor;

	for (vb = fr_cursor_talloc_init(&cursor, in, fr_value_box_t);
	     vb;
	     vb = fr_cursor_next(&cursor)) {
		fr_value_box_t *my;

		MEM(my = fr_value_box_alloc(ctx, FR_TYPE_SIZE, NULL, false));
		my->vb_size = fr_value_box_network_length(vb);
		fr_cursor_append(out, my);
	}

	return XLAT_ACTION_DONE;
}


/** Calculate the MD4 hash of a string or attribute.
 *
 * Example:
@verbatim
"%{md4:foo}" == "0ac6700c491d70fb8650940b1ca1e4b2"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_md4(TALLOC_CTX *ctx, fr_cursor_t *out,
				   request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				   fr_value_box_t **in)
{
	uint8_t		digest[MD5_DIGEST_LENGTH];
	fr_value_box_t	*vb;

	/*
	 * Concatenate all input if there is some
	 */
	if (*in && fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	if (*in) {
		fr_md4_calc(digest, (*in)->vb_octets, (*in)->vb_length);
	} else {
		/* Digest of empty string */
		fr_md4_calc(digest, NULL, 0);
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, sizeof(digest), false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Calculate the MD5 hash of a string or attribute.
 *
 * Example:
@verbatim
"%{md5:foo}" == "acbd18db4cc2f85cedef654fccc4a4d8"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_md5(TALLOC_CTX *ctx, fr_cursor_t *out,
				   request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				   fr_value_box_t **in)
{
	uint8_t		digest[MD5_DIGEST_LENGTH];
	fr_value_box_t	*vb;

	/*
	 *	Concatenate all input if there is some
	 */
	if (*in && fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	if (*in) {
		fr_md5_calc(digest, (*in)->vb_octets, (*in)->vb_length);
	} else {
		/* Digest of empty string */
		fr_md5_calc(digest, NULL, 0);
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, sizeof(digest), false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Prints the name of the current module processing the request
 *
 * For example will expand to "echo" (not "exec") in
@verbatim
exec echo {
  ...
  program = "/bin/echo %{module:}"
  ...
}
@endverbatim
 *
 * Example:
@verbatim
"%{module:}" == "" (outside a module)
"%{module:}" == "ldap" (in the ldap module)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_module(TALLOC_CTX *ctx, fr_cursor_t *out,
				      request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				      UNUSED fr_value_box_t **in)
{
	fr_value_box_t	*vb = NULL;

	/*
	 *	Don't do anything if we're outside of a module
	 */
	if (!request->module || !*request->module) return XLAT_ACTION_DONE;

	MEM(vb = fr_value_box_alloc_null(ctx));
	if (fr_value_box_strdup(vb, vb, NULL, request->module, false) < 0) {
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Pack multiple things together
 *
 * Example:
@verbatim
"%{pack:%{Attr-Foo}%{Attr-bar}" == packed hex values of the attributes
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_pack(TALLOC_CTX *ctx, fr_cursor_t *out,
				   request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				   fr_value_box_t **in)
{
	fr_value_box_t	*vb, *in_vb;
	fr_cursor_t	cursor;

	if (!*in) {
		REDEBUG("Missing input boxes");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_OCTETS, NULL, false));

	/*
	 *	Loop over the input boxes, packing them together.
	 */
	for (in_vb = fr_cursor_init(&cursor, in);
	     in_vb;
	     in_vb = fr_cursor_next(&cursor)) {
		fr_value_box_t *cast, box;

		if (in_vb->type != FR_TYPE_OCTETS) {
			if (fr_value_box_cast(ctx, &box, FR_TYPE_OCTETS, NULL, in_vb) < 0) {
			error:
				talloc_free(vb);
				RPEDEBUG("Failed packing value");
				return XLAT_ACTION_FAIL;
			}
			cast = &box;
		} else {
			cast = in_vb;
		}

		if (vb->vb_length == 0) {
			(void) fr_value_box_memdup(vb, vb, NULL, cast->vb_octets, cast->vb_length, cast->tainted);

		} else if (fr_value_box_mem_append(ctx, vb, cast->vb_octets, cast->vb_length, cast->tainted) < 0) {
			goto error;
		}

		fr_assert(vb->vb_octets != NULL);
	}

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Encode attributes as a series of string attribute/value pairs
 *
 * This is intended to serialize one or more attributes as a comma
 * delimited string.
 *
 * Example:
@verbatim
"%{pairs:request[*]}" == "User-Name = 'foo'User-Password = 'bar'"
"%{concat:, %{pairs:request[*]}}" == "User-Name = 'foo', User-Password = 'bar'"
@endverbatim
 *
 * @see #xlat_func_concat
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_pairs(TALLOC_CTX *ctx, fr_cursor_t *out,
				     request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				     fr_value_box_t **in)
{
	tmpl_t			*vpt = NULL;
	fr_cursor_t		cursor;
	tmpl_cursor_ctx_t	cc;
	fr_value_box_t		*vb;

	/*
	 *	If there's no input, there's no output
	 */
	if (!in) return XLAT_ACTION_DONE;

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	fr_pair_t *vp;

	if (tmpl_afrom_attr_str(ctx, NULL, &vpt, (*in)->vb_strvalue,
				&(tmpl_rules_t){
					.dict_def = request->dict,
					.prefix = TMPL_ATTR_REF_PREFIX_AUTO
				}) <= 0) {
		RPEDEBUG("Invalid input");
		return XLAT_ACTION_FAIL;
	}

	for (vp = tmpl_cursor_init(NULL, NULL, &cc, &cursor, request, vpt);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		fr_token_t op = vp->op;
		char *buff;

		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false));

		vp->op = T_OP_EQ;
		fr_pair_aprint(vb, &buff, NULL, vp);
		vp->op = op;

		vb->vb_strvalue = buff;
		vb->vb_length = talloc_array_length(buff) - 1;

		fr_cursor_append(out, vb);
	}
	tmpl_cursor_clear(&cc);
	talloc_free(vpt);

	return XLAT_ACTION_DONE;
}


/** Generate a random integer value
 *
 * For "N = %{rand:MAX}", 0 <= N < MAX
 *
 * Example:
@verbatim
"%{rand:100}" == 42
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_rand(TALLOC_CTX *ctx, fr_cursor_t *out,
				    request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				    fr_value_box_t **in)
{
	int64_t		result;
	fr_value_box_t*	vb;

	/* Make sure input can be converted to an unsigned 32 bit integer */
	if (fr_value_box_cast_in_place(ctx, (*in), FR_TYPE_UINT32, NULL) < 0) {
		RPEDEBUG("Failed converting input to uint32");
		return XLAT_ACTION_FAIL;
	}

	result = (*in)->vb_uint32;

	/* Make sure it isn't too big */
	if (result > (1 << 30)) result = (1 << 30);

	result *= fr_rand();	/* 0..2^32-1 */
	result >>= 32;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL, false));
	vb->vb_uint64 = result;

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Generate a string of random chars
 *
 * Build strings of random chars, useful for generating tokens and passcodes
 * Format similar to String::Random.
 *
 * Format characters may include the following, and may be
 * preceeded by a repetition count:
 * - "c"	lowercase letters
 * - "C" 	uppercase letters
 * - "n" 	numbers
 * - "a" 	alphanumeric
 * - "!" 	punctuation
 * - "." 	alphanumeric + punctuation
 * - "s" 	alphanumeric + "./"
 * - "o" 	characters suitable for OTP (easily confused removed)
 * - "b" 	binary data
 *
 * Example:
@verbatim
"%{randstr:CCCC!!cccnnn}" == "IPFL>{saf874"
"%{randstr:42o}" == "yHdupUwVbdHprKCJRYfGbaWzVwJwUXG9zPabdGAhM9"
"%{hex:%{randstr:bbbb}}" == "a9ce04f3"
"%{hex:%{randstr:8b}}" == "fe165529f9f66839"
@endverbatim
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_randstr(TALLOC_CTX *ctx, fr_cursor_t *out,
				       request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				       fr_value_box_t **in)
{
	/*
	 *	Lookup tables for randstr char classes
	 */
	static char	randstr_punc[] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
	static char	randstr_salt[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmopqrstuvwxyz/.";

	/*
	 *	Characters humans rarely confuse. Reduces char set considerably
	 *	should only be used for things such as one time passwords.
	 */
	static char	randstr_otp[] = "469ACGHJKLMNPQRUVWXYabdfhijkprstuvwxyz";

	char const	*p, *start, *end;
	char		*endptr;
	char		*buff_p;
	unsigned int	result;
	unsigned int	reps;
	size_t		outlen = 0;
	fr_value_box_t*	vb;

	/** Max repetitions of a single character class
	 *
	 */
#define REPETITION_MAX 1024

	/*
	 *	Nothing to do if input is empty
	 */
	if (!(*in)) return XLAT_ACTION_DONE;

	/*
	 *	Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	start = p = (*in)->vb_strvalue;
	end = p + (*in)->vb_length;

	/*
	 *	Calculate size of output
	 */
	while (p < end) {
		/*
		 *	Repetition modifiers.
		 *
		 *	We limit it to REPETITION_MAX, because we don't want
		 *	utter stupidity.
		 */
		if (isdigit((int) *p)) {
			reps = strtol(p, &endptr, 10);
			if (reps > REPETITION_MAX) reps = REPETITION_MAX;
			outlen += reps;
			p = endptr;
		} else {
			outlen++;
		}
		p++;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_bstr_alloc(vb, &buff_p, vb, NULL, outlen, false) == 0);

	/* Reset p to start position */
	p = start;

	while (p < end) {
		size_t i;

		if (isdigit((int) *p)) {
			reps = strtol(p, &endptr, 10);
			if (reps > REPETITION_MAX) {
				reps = REPETITION_MAX;
				RMARKER(L_WARN, L_DBG_LVL_2, start, start - p,
					"Forcing repetition to %u", (unsigned int)REPETITION_MAX);
			}
			p = endptr;
		} else {
			reps = 1;
		}

		for (i = 0; i < reps; i++) {
			result = fr_rand();
			switch (*p) {
			/*
			 *  Lowercase letters
			 */
			case 'c':
				*buff_p++ = 'a' + (result % 26);
				break;

			/*
			 *  Uppercase letters
			 */
			case 'C':
				*buff_p++ = 'A' + (result % 26);
				break;

			/*
			 *  Numbers
			 */
			case 'n':
				*buff_p++ = '0' + (result % 10);
				break;

			/*
			 *  Alpha numeric
			 */
			case 'a':
				*buff_p++ = randstr_salt[result % (sizeof(randstr_salt) - 3)];
				break;

			/*
			 *  Punctuation
			 */
			case '!':
				*buff_p++ = randstr_punc[result % (sizeof(randstr_punc) - 1)];
				break;

			/*
			 *  Alpha numeric + punctuation
			 */
			case '.':
				*buff_p++ = '!' + (result % 95);
				break;

			/*
			 *  Alpha numeric + salt chars './'
			 */
			case 's':
				*buff_p++ = randstr_salt[result % (sizeof(randstr_salt) - 1)];
				break;

			/*
			 *  Chars suitable for One Time Password tokens.
			 *  Alpha numeric with easily confused char pairs removed.
			 */
			case 'o':
				*buff_p++ = randstr_otp[result % (sizeof(randstr_otp) - 1)];
				break;

			/*
			 *	Binary data - Copy between 1-4 bytes at a time
			 */
			case 'b':
			{
				size_t copy = (reps - i) > sizeof(result) ? sizeof(result) : reps - i;

				memcpy(buff_p, (uint8_t *)&result, copy);
				buff_p += copy;
				i += (copy - 1);	/* Loop +1 */
			}
				break;

			default:
				REDEBUG("Invalid character class '%c'", *p);
				talloc_free(vb);

				return XLAT_ACTION_FAIL;
			}
		}

		p++;
	}

	*buff_p++ = '\0';

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

#if defined(HAVE_REGEX_PCRE) || defined(HAVE_REGEX_PCRE2)
/** Get named subcapture value from previous regex
 *
 * Example:
@verbatim
if ("foo" =~ /^(?<name>.*)/) {
        noop
}
"%{regex:name}" == "foo"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_regex(TALLOC_CTX *ctx, fr_cursor_t *out,
				     request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				     fr_value_box_t **in)
{
	/*
	 *	Return the complete capture if no other capture is specified
	 */
	if (!(*in)) {
		fr_value_box_t	*vb;
		char		*p;

		MEM(vb = fr_value_box_alloc_null(ctx));
		if (regex_request_to_sub(vb, &p, request, 0) < 0) {
			REDEBUG2("No previous regex capture");
			talloc_free(vb);
			return XLAT_ACTION_FAIL;
		}

		fr_assert(p);
		fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, p, false);
		fr_cursor_append(out, vb);

		return XLAT_ACTION_DONE;
	}

	switch ((*in)->type) {
	/*
	 *	If the input is an integer value then get an
	 *	arbitrary subcapture index.
	 */
	case FR_TYPE_NUMERIC:
	{
		fr_value_box_t	idx;
		fr_value_box_t	*vb;
		char		*p;

		if ((*in)->next) {
			REDEBUG("Only one subcapture argument allowed");
			return XLAT_ACTION_FAIL;
		}

		if (fr_value_box_cast(NULL, &idx, FR_TYPE_UINT32, NULL, *in) < 0) {
			RPEDEBUG("Bad subcapture index");
			return XLAT_ACTION_FAIL;
		}

		MEM(vb = fr_value_box_alloc_null(ctx));
		if (regex_request_to_sub(vb, &p, request, idx.vb_uint32) < 0) {
			REDEBUG2("No previous numbered regex capture group");
			talloc_free(vb);
			return XLAT_ACTION_FAIL;
		}
		fr_assert(p);
		fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, p, false);
		fr_cursor_append(out, vb);

		return XLAT_ACTION_DONE;
	}

	default:
	{
		fr_value_box_t	*vb;
		char		*p;

		/*
		 *	Concatenate all input
		 */
		if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
			RPEDEBUG("Failed concatenating input");
			return XLAT_ACTION_FAIL;
		}

		MEM(vb = fr_value_box_alloc_null(ctx));
		if (regex_request_to_sub_named(vb, &p, request, (*in)->vb_strvalue) < 0) {
			REDEBUG2("No previous named regex capture group");
			talloc_free(vb);
			return XLAT_ACTION_FAIL;
		}

		fr_assert(p);
		fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, p, false);
		fr_cursor_append(out, vb);

		return XLAT_ACTION_DONE;
	}
	}
}
#endif

/** Calculate the SHA1 hash of a string or attribute.
 *
 * Example:
@verbatim
"%{sha1:foo}" == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_sha1(TALLOC_CTX *ctx, fr_cursor_t *out,
				    request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				    fr_value_box_t **in)
{
	uint8_t		digest[SHA1_DIGEST_LENGTH];
	fr_sha1_ctx	sha1_ctx;
	fr_value_box_t	*vb;

	/*
	 * Concatenate all input if there is some
	 */
	if (*in && fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	fr_sha1_init(&sha1_ctx);
	if (*in) {
		fr_sha1_update(&sha1_ctx, (*in)->vb_octets, (*in)->vb_length);
	} else {
		/* sha1 of empty string */
		fr_sha1_update(&sha1_ctx, NULL, 0);
	}
	fr_sha1_final(digest, &sha1_ctx);

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, sizeof(digest), false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Calculate any digest supported by OpenSSL EVP_MD
 *
 * Example:
@verbatim
"%{sha2_256:foo}" == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
@endverbatim
 *
 * @ingroup xlat_functions
 */
#ifdef HAVE_OPENSSL_EVP_H
static xlat_action_t xlat_evp_md(TALLOC_CTX *ctx, fr_cursor_t *out,
			         request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
			         fr_value_box_t **in, EVP_MD const *md)
{
	uint8_t		digest[EVP_MAX_MD_SIZE];
	unsigned int	digestlen;
	EVP_MD_CTX	*md_ctx;
	fr_value_box_t	*vb;

	/*
	 * Concatenate all input if there is some
	 */
	if (*in && fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	md_ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(md_ctx, md, NULL);
	if (*in) {
		EVP_DigestUpdate(md_ctx, (*in)->vb_octets, (*in)->vb_length);
	} else {
		EVP_DigestUpdate(md_ctx, NULL, 0);
	}
	EVP_DigestFinal_ex(md_ctx, digest, &digestlen);
	EVP_MD_CTX_destroy(md_ctx);

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, digestlen, false);

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

#  define EVP_MD_XLAT(_md, _md_func) \
static xlat_action_t xlat_func_##_md(TALLOC_CTX *ctx, fr_cursor_t *out,\
				      request_t *request, void const *xlat_inst, void *xlat_thread_inst,\
				      fr_value_box_t **in)\
{\
	return xlat_evp_md(ctx, out, request, xlat_inst, xlat_thread_inst, in, EVP_##_md_func());\
}

EVP_MD_XLAT(sha2_224, sha224)
EVP_MD_XLAT(sha2_256, sha256)
EVP_MD_XLAT(sha2_384, sha384)
EVP_MD_XLAT(sha2_512, sha512)

#  if OPENSSL_VERSION_NUMBER >= 0x10100000L
EVP_MD_XLAT(blake2s_256, blake2s256)
EVP_MD_XLAT(blake2b_512, blake2b512)
#  endif

#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
EVP_MD_XLAT(sha3_224, sha3_224)
EVP_MD_XLAT(sha3_256, sha3_256)
EVP_MD_XLAT(sha3_384, sha3_384)
EVP_MD_XLAT(sha3_512, sha3_512)
#  endif
#endif


/** Print data as string, if possible.
 *
 * Concat and cast one or more input boxes to a single output box string.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_string(TALLOC_CTX *ctx, fr_cursor_t *out,
				      request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				      fr_value_box_t **in)
{
	if (!*in) return XLAT_ACTION_DONE;

	/*
	 * Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");

		return XLAT_ACTION_FAIL;
	}

	fr_cursor_append(out, *in);
	*in = NULL;	/* Let the caller know this was consumed */

	return XLAT_ACTION_DONE;
}


/** Print length of given string
 *
 * Example:
@verbatim
"%{strlen:foo}" == 3
@endverbatim
 *
 * @see #xlat_func_length
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_strlen(TALLOC_CTX *ctx, fr_cursor_t *out,
				      request_t *request, UNUSED void const *xlat_inst,
				      UNUSED void *xlat_thread_inst, fr_value_box_t **in)
{
	fr_value_box_t	*vb;

	if (!*in) {
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_SIZE, NULL, false));
		vb->vb_size = 0;
		fr_cursor_append(out, vb);
		return XLAT_ACTION_DONE;
	}

	/*
	 *	Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_SIZE, NULL, false));
	vb->vb_size = strlen((*in)->vb_strvalue);
	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


#ifdef HAVE_REGEX_PCRE2
/** Perform regex substitution TODO CHECK
 *
 * Called when %{sub:} pattern begins with "/"
 *
@verbatim
%{sub:/<regex>/[flags] <replace> <subject>}
@endverbatim
 *
 * Example: (User-Name = "foo")
@verbatim
"%{sub:/oo.*$/ un %{User-Name}}" == "fun"
@endverbatim
 *
 * @see #xlat_func_sub
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_sub_regex(TALLOC_CTX *ctx, fr_cursor_t *out,
					 request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
					 fr_value_box_t **in)
{
	char const		*p, *q, *end;
	char const		*regex, *rep, *subject;
	char			*buff;
	size_t			regex_len, rep_len, subject_len;
	ssize_t			slen;
	regex_t			*pattern;
	fr_regex_flags_t	flags;
	fr_value_box_t		*vb;


	/*
	 *	If there's no input, there's no output
	 */
	if (!*in) {
		REDEBUG("No input arguments");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	p = (*in)->vb_strvalue;
	end = p + (*in)->vb_length;

	if (p == end) {
		REDEBUG("Regex must not be empty");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Parse '/<regex>/'
	 */
	if (*p != '/') {
		REDEBUG("Regex must start with '/'");
		return XLAT_ACTION_FAIL;
	}
	p++;

	regex = p;

	q = memchr(p, '/', end - p);
	if (!q) {
		REDEBUG("No terminating '/' found for regex");
		return XLAT_ACTION_FAIL;
	}
	regex_len = q - p;

	p = q + 1;

	/*
	 *	Parse '[flags]'
	 */
	q = memchr(p, ' ', end - p);
	if (!q) {
		REDEBUG("Missing replacement");
		return XLAT_ACTION_FAIL;
	}

	memset(&flags, 0, sizeof(flags));

	slen = regex_flags_parse(NULL, &flags, &FR_SBUFF_IN(p, q), NULL, true);
	if (slen < 0) {
		RPEDEBUG("Failed parsing regex flags");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Parse ' <replace>'
	 */
	p += slen;

	fr_assert(*p == ' ');

	p++;	/* Skip space */
	rep = p;

	/*
	 *	Parse ' <subject>'
	 */
	q = memchr(p, ' ', end - p);
	if (!q) {
		REDEBUG("Missing subject");
		return XLAT_ACTION_FAIL;
	}
	rep_len = q - p;

	p = q + 1;

	subject = p;
	subject_len = end - p;

	/*
	 *	Process the substitution
	 */
	if (regex_compile(NULL, &pattern, regex, regex_len, &flags, false, true) <= 0) {
		RPEDEBUG("Failed compiling regex");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	if (regex_substitute(vb, &buff, 0, pattern, &flags,
			     subject, subject_len, rep, rep_len, NULL) < 0) {
		RPEDEBUG("Failed performing substitution");
		talloc_free(vb);
		talloc_free(pattern);
		return XLAT_ACTION_FAIL;
	}
	fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, buff, (*in)->tainted);

	fr_cursor_append(out, vb);

	talloc_free(pattern);

	return XLAT_ACTION_DONE;
}
#endif


/** Perform regex substitution
 *
@verbatim
%{sub:<pattern> <replace> <subject>}
@endverbatim
 *
 * Example: (User-Name = "foobar")
@verbatim
"%{sub:oo un %{User-Name}}" == "funbar"
@endverbatim
 *
 * @see xlat_func_sub_regex
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_sub(TALLOC_CTX *ctx, fr_cursor_t *out,
				   request_t *request,
#ifdef HAVE_REGEX_PCRE2
				   void const *xlat_inst, void *xlat_thread_inst,
#else
				   UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
#endif
				   fr_value_box_t **in)
{
	char const		*p, *q, *end;
	char			*vb_str;

	char const		*pattern, *rep;
	size_t			pattern_len, rep_len;

	fr_value_box_t		*vb;

	/*
	 *	If there's no input, there's no output
	 */
	if (!*in) {
		REDEBUG("No input arguments");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	p = (*in)->vb_strvalue;
	end = p + (*in)->vb_length;

	if (p == end) {
		REDEBUG("Substitution arguments must not be empty");
		return XLAT_ACTION_FAIL;
	}

	if (*p == '/') {
#ifdef HAVE_REGEX_PCRE2
		return xlat_func_sub_regex(ctx, out, request, xlat_inst, xlat_thread_inst, in);
#else
		REDEBUG("regex based substitutions require libpcre2.  "
			"Check ${features.regex-pcre2} to determine support");
		return XLAT_ACTION_FAIL;
#endif
	}

	/*
	 *	Parse '<pattern> '
	 */
	q = memchr(p, ' ', end - p);
	if (!q || (q == p)) {
		REDEBUG("Missing pattern");
		return XLAT_ACTION_FAIL;
	}

	pattern = p;
	pattern_len = q - p;
	p = q + 1;

	/*
	 *	Parse '<replacement> '
	 */
	q = memchr(p, ' ', end - p);
	if (!q) {
		REDEBUG("Missing subject");
		return XLAT_ACTION_FAIL;
	}
	rep = p;
	rep_len = q - p;
	p = q + 1;

	/*
	 *	Parse '<subject>'
	 */
	MEM(vb = fr_value_box_alloc_null(ctx));
	vb_str = talloc_bstrndup(vb, "", 0);

	while (p < end) {
		q = memmem(p, end - p, pattern, pattern_len);
		if (!q) {
			MEM(vb_str = talloc_bstr_append(vb, vb_str, p, end - p));
			break;
		}

		if (q > p) MEM(vb_str = talloc_bstr_append(vb, vb_str, p, q - p));
		if (rep_len) MEM(vb_str = talloc_bstr_append(vb, vb_str, rep, rep_len));
		p = q + pattern_len;
	}

	if (fr_value_box_bstrdup_buffer_shallow(vb, vb, NULL, vb_str, (*in)->vb_strvalue) < 0) {
		RPEDEBUG("Failed creating output box");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_assert(vb && (vb->type != FR_TYPE_INVALID));
	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Change case of a string
 *
 * If upper is true, change to uppercase, otherwise, change to lowercase
 */
static xlat_action_t xlat_change_case(TALLOC_CTX *ctx, fr_cursor_t *out,
				       request_t *request, fr_value_box_t **in, bool upper)
{
	char		*buff_p;
	char const	*p, *end;
	fr_value_box_t	*vb;

	/*
	 *	If there's no input, there's no output
	 */
	if (!*in) return XLAT_ACTION_DONE;

	/*
	 * Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	p = (*in)->vb_strvalue;
	end = p + (*in)->vb_length;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL, false));
	MEM(fr_value_box_bstr_alloc(vb, &buff_p, vb, NULL, (*in)->vb_length, (*in)->tainted) == 0);

	while (p < end) {
		*(buff_p++) = upper ? toupper ((int) *(p++)) : tolower((int) *(p++));
	}

	*buff_p = '\0';

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Convert a string to lowercase
 *
 * Example:
@verbatim
"%{tolower:Bar}" == "bar"
@endverbatim
 *
 * Probably only works for ASCII
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_tolower(TALLOC_CTX *ctx, fr_cursor_t *out,
				       request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				       fr_value_box_t **in)
{
	return xlat_change_case(ctx, out, request, in, false);
}


/** Convert a string to uppercase
 *
 * Example:
@verbatim
"%{toupper:Foo}" == "FOO"
@endverbatim
 *
 * Probably only works for ASCII
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_toupper(TALLOC_CTX *ctx, fr_cursor_t *out,
				       request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				       fr_value_box_t **in)
{
	return xlat_change_case(ctx, out, request, in, true);
}


/** URLencode special characters
 *
 * Example:
@verbatim
"%{urlquote:http://example.org/}" == "http%3A%47%47example.org%47"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_urlquote(TALLOC_CTX *ctx, fr_cursor_t *out,
					request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
					fr_value_box_t **in)
{
	char const	*p, *end;
	char		*buff_p;
	size_t		outlen = 0;
	fr_value_box_t	*vb;

	/*
	 * Nothing to do if input is empty
	 */
	if (!(*in)) return XLAT_ACTION_DONE;

	/*
	 * Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	p = (*in)->vb_strvalue;
	end = p + (*in)->vb_length;

	/*
	 * Calculate size of output
	 */
	while (p < end) {
		if (isalnum(*p) ||
		    *p == '-' ||
		    *p == '_' ||
		    *p == '.' ||
		    *p == '~') {
			outlen++;
		} else {
			outlen += 3;
		}
		p++;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_bstr_alloc(vb, &buff_p, vb, NULL, outlen, false) == 0);

	/* Reset p to start position */
	p = (*in)->vb_strvalue;

	while (p < end) {
		if (isalnum(*p)) {
			*buff_p++ = *p++;
			continue;
		}

		switch (*p) {
		case '-':
		case '_':
		case '.':
		case '~':
			*buff_p++ = *p++;
			break;

		default:
			/* MUST be upper case hex to be compliant */
			snprintf(buff_p, 4, "%%%02X", (uint8_t) *p++); /* %XX */

			buff_p += 3;
		}
	}

	*buff_p = '\0';

	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** URLdecode special characters
 *
 * @note Remember to escape % with %% in strings, else xlat will try to parse it.
 *
 * Example:
@verbatim
"%{urlunquote:http%%3A%%47%%47example.org%%47}" == "http://example.org/"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_urlunquote(TALLOC_CTX *ctx, fr_cursor_t *out,
					  request_t *request, UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
					  fr_value_box_t **in)
{
	char const	*p, *end;
	char		*buff_p;
	char		*c1, *c2;
	size_t		outlen = 0;
	fr_value_box_t	*vb;

	/*
	 * Nothing to do if input is empty
	 */
	if (!*in) return XLAT_ACTION_DONE;

	/*
	 * Concatenate all input
	 */
	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	p = (*in)->vb_strvalue;
	end = p + (*in)->vb_length;

	/*
	 * Calculate size of output
	 */
	while (p < end) {
		if (*p == '%') {
			p += 3;
		} else {
			p++;
		}
		outlen++;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_bstr_alloc(vb, &buff_p, vb, NULL, outlen, false) == 0);

	/* Reset p to start position */
	p = (*in)->vb_strvalue;

	while (p < end) {
		if (*p != '%') {
			*buff_p++ = *p++;
			continue;
		}
		/* Is a % char */

		/* Don't need \0 check, as it won't be in the hextab */
		if (!(c1 = memchr(hextab, tolower(*++p), 16)) ||
		    !(c2 = memchr(hextab, tolower(*++p), 16))) {
			REMARKER((*in)->vb_strvalue, p - (*in)->vb_strvalue, "Non-hex char in %% sequence");
			talloc_free(vb);

			return XLAT_ACTION_FAIL;
		}
		p++;
		*buff_p++ = ((c1 - hextab) << 4) + (c2 - hextab);
	}

	*buff_p = '\0';
	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}



/** Global initialisation for xlat
 *
 * @note Free memory with #xlat_free
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int xlat_init(void)
{
	if (xlat_root) return 0;

	/*
	 *	Lookup attributes used by virtual xlat expansions.
	 */
	if (xlat_eval_init() < 0) return -1;

	/*
	 *	Registers async xlat operations in the `unlang` interpreter.
	 */
	unlang_xlat_init();

	/*
	 *	Create the function tree
	 */
	xlat_root = rbtree_talloc_alloc(NULL, xlat_cmp, xlat_t, _xlat_func_tree_free, RBTREE_FLAG_REPLACE);
	if (!xlat_root) {
		ERROR("%s: Failed to create tree", __FUNCTION__);
		return -1;
	}

#define XLAT_REGISTER(_x) xlat_register_legacy(NULL, STRINGIFY(_x), xlat_func_ ## _x, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN); \
	xlat_internal(STRINGIFY(_x));

	xlat_register_legacy(NULL, "debug", xlat_func_debug, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN);
	xlat_internal("debug");
	XLAT_REGISTER(debug_attr);
	xlat_register_legacy(NULL, "explode", xlat_func_explode, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN);
	XLAT_REGISTER(integer);
	xlat_register_legacy(NULL, "lpad", xlat_func_lpad, NULL, NULL, 0, 0);
	XLAT_REGISTER(map);
	xlat_register_legacy(NULL, "nexttime", xlat_func_next_time, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN);
	xlat_register_legacy(NULL, "rpad", xlat_func_rpad, NULL, NULL, 0, 0);
	xlat_register_legacy(NULL, "trigger", trigger_xlat, NULL, NULL, 0, 0);	/* On behalf of trigger.c */
	XLAT_REGISTER(xlat);


	xlat_register(NULL, "base64", xlat_func_base64_encode, false);
	xlat_register(NULL, "base64decode", xlat_func_base64_decode, false);
	xlat_register(NULL, "bin", xlat_func_bin, false);
	xlat_register(NULL, "concat", xlat_func_concat, false);
	xlat_register(NULL, "hex", xlat_func_hex, false);
	xlat_register(NULL, "hmacmd5", xlat_func_hmac_md5, false);
	xlat_register(NULL, "hmacsha1", xlat_func_hmac_sha1, false);
	xlat_register(NULL, "length", xlat_func_length, false);
	xlat_register(NULL, "md4", xlat_func_md4, false);
	xlat_register(NULL, "md5", xlat_func_md5, false);
	xlat_register(NULL, "module", xlat_func_module, false);
	xlat_register(NULL, "pack", xlat_func_pack, false);
	xlat_register(NULL, "pairs", xlat_func_pairs, false);
	xlat_register(NULL, "rand", xlat_func_rand, false);
	xlat_register(NULL, "randstr", xlat_func_randstr, false);
#if defined(HAVE_REGEX_PCRE) || defined(HAVE_REGEX_PCRE2)
	xlat_register(NULL, "regex", xlat_func_regex, false);
#endif
	xlat_register(NULL, "sha1", xlat_func_sha1, false);

#ifdef HAVE_OPENSSL_EVP_H
	xlat_register(NULL, "sha2_224", xlat_func_sha2_224, false);
	xlat_register(NULL, "sha2_256", xlat_func_sha2_256, false);
	xlat_register(NULL, "sha2_384", xlat_func_sha2_384, false);
	xlat_register(NULL, "sha2_512", xlat_func_sha2_512, false);

#  if OPENSSL_VERSION_NUMBER >= 0x10100000L
	xlat_register(NULL, "blake2s_256", xlat_func_blake2s_256, false);
	xlat_register(NULL, "blake2b_512", xlat_func_blake2b_512, false);
#  endif

#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
	xlat_register(NULL, "sha3_224", xlat_func_sha3_224, false);
	xlat_register(NULL, "sha3_256", xlat_func_sha3_256, false);
	xlat_register(NULL, "sha3_384", xlat_func_sha3_384, false);
	xlat_register(NULL, "sha3_512", xlat_func_sha3_512, false);
#  endif
#endif

	xlat_register(NULL, "string", xlat_func_string, false);
	xlat_register(NULL, "strlen", xlat_func_strlen, false);
	xlat_register(NULL, "sub", xlat_func_sub, false);
	xlat_register(NULL, "tolower", xlat_func_tolower, false);
	xlat_register(NULL, "toupper", xlat_func_toupper, false);
	xlat_register(NULL, "urlquote", xlat_func_urlquote, false);
	xlat_register(NULL, "urlunquote", xlat_func_urlunquote, false);

	return 0;
}


/** De-register all xlat functions we created
 *
 */
void xlat_free(void)
{
	rbtree_t *xr = xlat_root;		/* Make sure the tree can't be freed multiple times */

	if (!xr) return;

	xlat_root = NULL;
	talloc_free(xr);

	xlat_eval_free();
}
