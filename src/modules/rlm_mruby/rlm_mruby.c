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
 * @file rlm_mruby.c
 * @brief Translates requests between the server an an mruby interpreter.
 *
 * @copyright 2016 Herwin Weststrate (freeradius@herwinw.nl)
 * @copyright 2016 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/pairmove.h>
#include <freeradius-devel/server/rad_assert.h>

#include "rlm_mruby.h"

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct {
	char const *filename;
	char const *module_name;

	mrb_state *mrb;

	struct RClass *mruby_module;
	struct RClass *mruby_request;
	mrb_value mrubyconf_hash;
} rlm_mruby_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, rlm_mruby_t, filename) },
	{ FR_CONF_OFFSET("module", FR_TYPE_STRING, rlm_mruby_t, module_name), .dflt = "Radiusd" },
	CONF_PARSER_TERMINATOR
};

static mrb_value mruby_log(mrb_state *mrb, UNUSED mrb_value self)
{
	mrb_int level;
	char *msg = NULL;

	mrb_get_args(mrb, "iz", &level, &msg);
	fr_log(&default_log, level, __FILE__, __LINE__, "rlm_ruby: %s", msg);

	return mrb_nil_value();
}

static void mruby_parse_config(mrb_state *mrb, CONF_SECTION *cs, int lvl, mrb_value hash)
{
	int indent_section = (lvl + 1) * 4;
	int indent_item = (lvl + 2) * 4;
	CONF_ITEM *ci = NULL;

	if (!cs) return;

	DEBUG("%*s%s {", indent_section, " ", cf_section_name1(cs));

	while ((ci = cf_item_next(cs, ci))) {
		if (cf_item_is_section(ci)) {
			CONF_SECTION *sub_cs = cf_item_to_section(ci);
			char const *key = cf_section_name1(sub_cs);
			mrb_value sub_hash, mrubyKey;

			if (!key) continue;

			mrubyKey = mrb_str_new_cstr(mrb, key);

			if (!mrb_nil_p(mrb_hash_get(mrb, hash, mrubyKey))) {
				WARN("rlm_mruby: Ignoring duplicate config section '%s'", key);
				continue;
			}

			sub_hash = mrb_hash_new(mrb);
			mrb_hash_set(mrb, hash, mrubyKey, sub_hash);

			mruby_parse_config(mrb, sub_cs, lvl + 1, sub_hash);
		} else if (cf_item_is_pair(ci)) {
			CONF_PAIR *cp = cf_item_to_pair(ci);
			const char *key = cf_pair_attr(cp);
			const char *value = cf_pair_value(cp);
			mrb_value mrubyKey, mrubyValue;

			if (!key || !value) continue;

			mrubyKey = mrb_str_new_cstr(mrb, key);
			mrubyValue = mrb_str_new_cstr(mrb, value);

			if (!mrb_nil_p(mrb_hash_get(mrb, hash, mrubyKey))) {
				WARN("rlm_mruby: Ignoring duplicate config item '%s'", key);
				continue;
			}

			mrb_hash_set(mrb, hash, mrubyKey, mrubyValue);

			DEBUG("%*s%s = %s", indent_item, " ", key, value);
		}
	}

	DEBUG("%*s}", indent_section, " ");
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_mruby_t *inst = instance;
	mrb_state *mrb;
	CONF_SECTION *cs;
	FILE *f;
	mrb_value status;

	mrb = inst->mrb = mrb_open();
	if (!mrb) {
		ERROR("mruby initialization failed");
		return -1;
	}

	/* Define the freeradius module */
	DEBUG("Creating module %s", inst->module_name);
	inst->mruby_module = mrb_define_module(mrb, inst->module_name);
	if (!inst->mruby_module) {
		ERROR("Creating module %s failed", inst->module_name);
		return -1;
	}

	/* Define the log method */
	mrb_define_class_method(mrb, inst->mruby_module, "log", mruby_log, MRB_ARGS_REQ(2));

#define A(x) mrb_define_const(mrb, inst->mruby_module, #x, mrb_fixnum_value(x));
	/* Define the logging constants */
	A(L_DBG);
	A(L_WARN);
	A(L_INFO);
	A(L_ERR);
	A(L_WARN);
	A(L_DBG_WARN);
	A(L_DBG_ERR);
	A(L_DBG_WARN_REQ);
	A(L_DBG_ERR_REQ);

	/* Define the return value constants */
	A(RLM_MODULE_REJECT)
	A(RLM_MODULE_FAIL)
	A(RLM_MODULE_OK)
	A(RLM_MODULE_HANDLED)
	A(RLM_MODULE_INVALID)
	A(RLM_MODULE_DISALLOW)
	A(RLM_MODULE_NOTFOUND)
	A(RLM_MODULE_NOOP)
	A(RLM_MODULE_UPDATED)
	A(RLM_MODULE_NUMCODES)
#undef A

	/* Convert a FreeRADIUS config structure into a mruby hash */
	inst->mrubyconf_hash = mrb_hash_new(mrb);
	cs = cf_section_find(conf, "config", NULL);
	if (cs) mruby_parse_config(mrb, cs, 0, inst->mrubyconf_hash);

	/* Define the Request class */
	inst->mruby_request = mruby_request_class(mrb, inst->mruby_module);

	DEBUG("Loading file %s...", inst->filename);
	f = fopen(inst->filename, "r");
	if (!f) {
		ERROR("Opening file failed");
		return -1;
	}

	status = mrb_load_file(mrb, f);
	if (mrb_undef_p(status)) {
		ERROR("Parsing file failed");
		return -1;
	}
	fclose(f);

	status = mrb_funcall(mrb, mrb_obj_value(inst->mruby_module), "instantiate", 0);
	if (mrb_undef_p(status)) {
		ERROR("Running instantiate failed");
		return -1;
	}

	return 0;
}

static int mruby_vps_to_array(REQUEST *request, mrb_value *out, mrb_state *mrb, VALUE_PAIR **vps)
{
	mrb_value	res;
	VALUE_PAIR	*vp;
	fr_cursor_t	cursor;

	res = mrb_ary_new(mrb);
	for (vp = fr_cursor_init(&cursor, vps); vp; vp = fr_cursor_next(&cursor)) {
		mrb_value	tmp, key, val, to_cast;
		char		*str;

		tmp = mrb_ary_new_capa(mrb, 2);
		if (vp->da->flags.has_tag) {
			str = talloc_typed_asprintf(request, "%s:%d", vp->da->name, vp->tag);
			key = mrb_str_new(mrb, str, talloc_array_length(str) - 1);
			talloc_free(str);
		} else {
			key = mrb_str_new(mrb, vp->da->name, strlen(vp->da->name));
		}

		/*
		 *	The only way to create floats, doubles, bools etc,
		 *	is to feed mruby the string representation and have
		 *	it convert to its internal types.
		 */
		switch (vp->vp_type) {
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			to_cast = mrb_str_new(mrb, vp->vp_ptr, vp->vp_length);
			break;

		case FR_TYPE_BOOL:
#ifndef NDEBUG
			to_cast = mrb_nil_value();	/* Not needed but clang flags it */
#endif
			break;

		default:
		{
			char *in;

			in = fr_value_box_asprint(request, &vp->data, '\0');
			to_cast = mrb_str_new(mrb, in, talloc_array_length(in) - 1);
			talloc_free(in);
		}
			break;
		}

		switch (vp->vp_type) {
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_IPV4_PREFIX:
		case FR_TYPE_IPV6_ADDR:
		case FR_TYPE_IPV6_PREFIX:
		case FR_TYPE_IFID:
		case FR_TYPE_ETHERNET:
		case FR_TYPE_ABINARY:
			val = to_cast;		/* No conversions required */
			break;

		case FR_TYPE_BOOL:
			val = vp->vp_bool ? mrb_obj_value(mrb->true_class) : mrb_obj_value(mrb->false_class);
			break;

		case FR_TYPE_UINT8:
		case FR_TYPE_UINT16:
		case FR_TYPE_UINT32:
		case FR_TYPE_UINT64:
		case FR_TYPE_INT8:
		case FR_TYPE_INT16:
		case FR_TYPE_INT32:
		case FR_TYPE_INT64:
		case FR_TYPE_DATE:
		case FR_TYPE_TIME_DELTA:
		case FR_TYPE_SIZE:
			val = mrb_convert_type(mrb, to_cast, MRB_TT_FIXNUM, "Fixnum", "to_int");
			break;

		case FR_TYPE_FLOAT32:
		case FR_TYPE_FLOAT64:
			val = mrb_convert_type(mrb, to_cast, MRB_TT_FLOAT, "Float", "to_f");
			break;

		case FR_TYPE_NON_VALUES:
			rad_assert(0);
			return -1;
		}

		mrb_ary_push(mrb, tmp, key);
		mrb_ary_push(mrb, tmp, val);
		mrb_ary_push(mrb, res, tmp);

		*out = res;
	}

	return 0;
}

static void add_vp_tuple(TALLOC_CTX *ctx, REQUEST *request, VALUE_PAIR **vps, mrb_state *mrb, mrb_value value, char const *function_name)
{
	int i;

	for (i = 0; i < RARRAY_LEN(value); i++) {
		mrb_value	tuple = mrb_ary_entry(value, i);
		mrb_value	key, val;
		char const	*ckey, *cval;
		VALUE_PAIR	*vp;
		vp_tmpl_t	*dst;
		FR_TOKEN	op = T_OP_EQ;

		/* This tuple should be an array of length 2 */
		if (mrb_type(tuple) != MRB_TT_ARRAY) {
			REDEBUG("add_vp_tuple, %s: non-array passed at index %i", function_name, i);
			continue;
		}

		if (RARRAY_LEN(tuple) != 2 && RARRAY_LEN(tuple) != 3) {
			REDEBUG("add_vp_tuple, %s: array with incorrect length passed at index "
				"%i, expected 2 or 3, got %"PRId64, function_name, i, RARRAY_LEN(tuple));
			continue;
		}

		key = mrb_ary_entry(tuple, 0);
		val = mrb_ary_entry(tuple, -1);
		if (mrb_type(key) != MRB_TT_STRING) {
			REDEBUG("add_vp_tuple, %s: tuple element %i must have a string as first element", function_name, i);
			continue;
		}

		ckey = mrb_str_to_cstr(mrb, key);
		cval = mrb_str_to_cstr(mrb, mrb_obj_as_string(mrb, val));
		if (ckey == NULL || cval == NULL) {
			REDEBUG("%s: string conv failed", function_name);
			continue;
		}


		if (RARRAY_LEN(tuple) == 3) {
			if (mrb_type(mrb_ary_entry(tuple, 1)) != MRB_TT_STRING) {
				REDEBUG("Invalid type for operator, expected string, falling back to =");
			} else {
				char const *cop = mrb_str_to_cstr(mrb, mrb_ary_entry(tuple, 1));
				if (!(op = fr_table_value_by_str(fr_tokens_table, cop, 0))) {
					REDEBUG("Invalid operator: %s, falling back to =", cop);
					op = T_OP_EQ;
				}
			}
		}
		DEBUG("%s: %s %s %s", function_name, ckey, fr_table_str_by_value(fr_tokens_table, op, "="), cval);

		if (tmpl_afrom_attr_str(request, NULL, &dst, ckey,
					&(vp_tmpl_rules_t){
						.dict_def = request->dict,
						.list_def = PAIR_LIST_REPLY
					}) <= 0) {
			ERROR("Failed to find attribute %s", ckey);
			continue;
		}

		if (radius_request(&request, dst->tmpl_request) < 0) {
			ERROR("Attribute name %s refers to outer request but not in a tunnel, skipping...", ckey);
			talloc_free(dst);
			continue;
		}

		MEM(vp = fr_pair_afrom_da(ctx, dst->tmpl_da));
		talloc_free(dst);

		vp->op = op;
		if (fr_pair_value_from_str(vp, cval, -1, '\0', false) < 0) {
			REDEBUG("%s: %s %s %s failed", function_name, ckey, fr_table_str_by_value(fr_tokens_table, op, "="), cval);
		} else {
			DEBUG("%s: %s %s %s OK", function_name, ckey, fr_table_str_by_value(fr_tokens_table, op, "="), cval);
		}

		radius_pairmove(request, vps, vp, false);
	}
}

static inline int mruby_set_vps(REQUEST *request, mrb_state *mrb, mrb_value mruby_request,
				char const *list_name, VALUE_PAIR **vps)
{
	mrb_value res;

	memset(&res, 0, sizeof(res));	/* clang scan */

	if (mruby_vps_to_array(request, &res, mrb, vps) < 0) return -1;

	mrb_iv_set(mrb, mruby_request, mrb_intern_cstr(mrb, list_name), res);

	return 0;
}

static rlm_rcode_t CC_HINT(nonnull) do_mruby(REQUEST *request, rlm_mruby_t const *inst, char const *function_name)
{
	mrb_state *mrb = inst->mrb;
	mrb_value mruby_request, mruby_result;

	mruby_request = mrb_obj_new(mrb, inst->mruby_request, 0, NULL);
	mrb_iv_set(mrb, mruby_request, mrb_intern_cstr(mrb, "@frconfig"), inst->mrubyconf_hash);
	mruby_set_vps(request, mrb, mruby_request, "@request", &request->packet->vps);
	mruby_set_vps(request, mrb, mruby_request, "@reply", &request->reply->vps);
	mruby_set_vps(request, mrb, mruby_request, "@control", &request->control);
	mruby_set_vps(request, mrb, mruby_request, "@session_state", &request->state);
#ifdef WITH_PROXY
	if (request->proxy) {
		mruby_set_vps(request, mrb, mruby_request, "@proxy_request", &request->proxy->packet->vps);
		mruby_set_vps(request, mrb, mruby_request, "@proxy_reply", &request->proxy->reply->vps);
	}
#endif

DIAG_OFF(class-varargs)
	mruby_result = mrb_funcall(mrb, mrb_obj_value(inst->mruby_module), function_name, 1, mruby_request);
DIAG_ON(class-varargs)

	/* Two options for the return value:
	 * - a fixnum: convert to rlm_rcode_t, and return that
	 * - an array: this should have exactly three items in it. The first one
	 *             should be a fixnum, this will once again be converted to
	 *             rlm_rcode_t and eventually returned. The other two items
	 *             should be arrays. The items of the first array should be
	 *             merged into reply, the second array into control.
	 */
	switch (mrb_type(mruby_result)) {
		/* If it is a Fixnum: return that value */
		case MRB_TT_FIXNUM:
			return (rlm_rcode_t)mrb_int(mrb, mruby_result);

		case MRB_TT_ARRAY:
			/* Must have exactly three items */
			if (RARRAY_LEN(mruby_result) != 3) {
				ERROR("Expected array to have exactly three values, got %" PRId64 " instead", RARRAY_LEN(mruby_result));
				return RLM_MODULE_FAIL;
			}

			/* First item must be a Fixnum, this will be the return type */
			if (mrb_type(mrb_ary_entry(mruby_result, 0)) != MRB_TT_FIXNUM) {
				ERROR("Expected first array element to be a Fixnum, got %s instead", RSTRING_PTR(mrb_obj_as_string(mrb, mrb_ary_entry(mruby_result, 0))));
				return RLM_MODULE_FAIL;
			}

			/* Second and third items must be Arrays, these will be the updates for reply and control */
			if (mrb_type(mrb_ary_entry(mruby_result, 1)) != MRB_TT_ARRAY) {
				ERROR("Expected second array element to be an Array, got %s instead", RSTRING_PTR(mrb_obj_as_string(mrb, mrb_ary_entry(mruby_result, 1))));
				return  RLM_MODULE_FAIL;
			} else if (mrb_type(mrb_ary_entry(mruby_result, 2)) != MRB_TT_ARRAY) {
				ERROR("Expected third array element to be an Array, got %s instead", RSTRING_PTR(mrb_obj_as_string(mrb, mrb_ary_entry(mruby_result, 2))));
				return RLM_MODULE_FAIL;
			}

			add_vp_tuple(request->reply, request, &request->reply->vps, mrb, mrb_ary_entry(mruby_result, 1), function_name);
			add_vp_tuple(request, request, &request->control, mrb, mrb_ary_entry(mruby_result, 2), function_name);
			return (rlm_rcode_t)mrb_int(mrb, mrb_ary_entry(mruby_result, 0));

		default:
			/* Invalid return type */
			ERROR("Expected return to be a Fixnum or an Array, got %s instead", RSTRING_PTR(mrb_obj_as_string(mrb, mruby_result)));
			return RLM_MODULE_FAIL;
	}
}


#define RLM_MRUBY_FUNC(foo) static rlm_rcode_t CC_HINT(nonnull) mod_##foo(void *instance, UNUSED void *thread, REQUEST *request) \
	{ \
		return do_mruby(request,	\
			       (rlm_mruby_t const *)instance, \
			       #foo); \
	}

RLM_MRUBY_FUNC(authorize)
RLM_MRUBY_FUNC(authenticate)
RLM_MRUBY_FUNC(post_auth)
#ifdef WITH_ACCOUNTING
RLM_MRUBY_FUNC(preacct)
RLM_MRUBY_FUNC(accounting)
#endif
#ifdef WITH_PROXY
RLM_MRUBY_FUNC(pre_proxy)
RLM_MRUBY_FUNC(post_proxy)
#endif
#ifdef WITH_COA
RLM_MRUBY_FUNC(recv_coa)
RLM_MRUBY_FUNC(send_coa)
#endif


/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int mod_detach(void *instance)
{
	rlm_mruby_t *inst = instance;

	mrb_close(inst->mrb);

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
extern module_t rlm_mruby;
module_t rlm_mruby = {
	.magic		= RLM_MODULE_INIT,
	.name		= "mruby",
	.type		= RLM_TYPE_THREAD_UNSAFE, /* Not sure */
	.inst_size	= sizeof(rlm_mruby_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_POST_AUTH]		= mod_post_auth,
#ifdef WITH_ACCOUNTING
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
#endif
#ifdef WITH_PROXY
		[MOD_PRE_PROXY]		= mod_pre_proxy,
		[MOD_POST_PROXY]	= mod_post_proxy,
#endif
#ifdef WITH_COA
		[MOD_RECV_COA]		= mod_recv_coa,
		[MOD_SEND_COA]		= mod_send_coa,
#endif
	},
};
