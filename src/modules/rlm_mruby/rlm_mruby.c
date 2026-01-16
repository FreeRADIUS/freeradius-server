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
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/debug.h>

#include "rlm_mruby.h"

typedef struct {
	char const	*function_name;	//!< Name of the function being called
	char		*name1;		//!< Section name1 where this is called
	char		*name2;		//!< Section name2 where this is called
	fr_rb_node_t	node;		//!< Node in tree of function calls.
} mruby_func_def_t;

typedef struct {
	mruby_func_def_t	*func;
} mruby_call_env_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_FILE_READABLE | CONF_FLAG_REQUIRED, rlm_mruby_t, filename) },
	{ FR_CONF_OFFSET("module", rlm_mruby_t, module_name), .dflt = "FreeRADIUS" },
	CONF_PARSER_TERMINATOR
};

/** How to compare two Ruby function calls
 *
 */
static int8_t mruby_func_def_cmp(void const *one, void const *two)
{
	mruby_func_def_t const *a = one, *b = two;
	int ret;

	ret = strcmp(a->name1, b->name1);
	if (ret != 0) return CMP(ret, 0);
	if (!a->name2 && !b->name2) return 0;
	if (!a->name2 || !b->name2) return a->name2 ? 1 : -1;
	ret = strcmp(a->name2, b->name2);
	return CMP(ret, 0);
}

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
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_mruby_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_mruby_t);
	fr_rb_iter_inorder_t	iter;
	mruby_func_def_t	*func = NULL;
	mrb_state		*mrb;
	CONF_SECTION		*cs;
	FILE			*f;
	mrb_value		status;
	char			*pair_name;
	CONF_PAIR		*cp;
	mrb_value		func_sym;

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
	cs = cf_section_find(mctx->mi->conf, "config", NULL);
	if (cs) mruby_parse_config(mrb, cs, 0, inst->mrubyconf_hash);

	/* Define the Request class */
	inst->mruby_request = mruby_request_class(mrb, inst->mruby_module);

	inst->mruby_pair_list = mruby_pair_list_class(mrb, inst->mruby_module);
	inst->mruby_pair = mruby_pair_class(mrb, inst->mruby_module);

	inst->mruby_ptr = mrb_define_class_under(mrb, inst->mruby_module, "Ptr", mrb->object_class);
	MRB_SET_INSTANCE_TT(inst->mruby_ptr, MRB_TT_DATA);

	DEBUG("Loading file %s...", inst->filename);
	f = fopen(inst->filename, "r");
	if (!f) {
		ERROR("Opening file failed");
		return -1;
	}

	status = mrb_load_file(mrb, f);
	fclose(f);
	if (mrb_undef_p(status)) {
		ERROR("Parsing file failed");
		return -1;
	}

	if (!inst->funcs_init) fr_rb_inline_init(&inst->funcs, mruby_func_def_t, node, mruby_func_def_cmp, NULL);

	for (func = fr_rb_iter_init_inorder(&inst->funcs, &iter);
	     func != NULL;
	     func = fr_rb_iter_next_inorder(&inst->funcs, &iter)) {
		/*
		 *	Check for func_<name1>_<name2> or func_<name1> config pairs.
		 */
		if (func->name2) {
			pair_name = talloc_asprintf(func, "func_%s_%s", func->name1, func->name2);
			cp = cf_pair_find(mctx->mi->conf, pair_name);
			talloc_free(pair_name);
			if (cp) goto found_func;
		}
		pair_name = talloc_asprintf(func, "func_%s", func->name1);
		cp = cf_pair_find(mctx->mi->conf, pair_name);
		talloc_free(pair_name);
	found_func:
		if (cp){
			func->function_name = cf_pair_value(cp);
			func_sym = mrb_check_intern_cstr(mrb, func->function_name);
			if (mrb_nil_p(func_sym)) {
				cf_log_err(cp, "mruby function %s does not exist", func->function_name);
				return -1;
			}
		/*
		 *	If no pair was found, then use <name1>_<name2> or <name1> as the function to call.
		 */
		} else if (func->name2) {
			func->function_name = talloc_asprintf(func, "%s_%s", func->name1, func->name2);
			func_sym = mrb_check_intern_cstr(mrb, func->function_name);
			if (mrb_nil_p(func_sym)) {
				talloc_const_free(func->function_name);
				goto name1_only;
			}
		} else {
		name1_only:
			func->function_name = func->name1;
			func_sym = mrb_check_intern_cstr(mrb, func->function_name);
			if (mrb_nil_p(func_sym)) {
				cf_log_err(cp, "mruby function %s does not exist", func->function_name);
				return -1;
			}
		}
	}

	if (mrb_nil_p(mrb_check_intern_cstr(mrb, "instantiate"))) return 0;

	status = mrb_funcall(mrb, mrb_obj_value(inst->mruby_module), "instantiate", 0);
	if (mrb_undef_p(status)) {
		ERROR("Running instantiate failed");
		return -1;
	}

	return 0;
}

static unlang_action_t CC_HINT(nonnull) mod_mruby(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_mruby_t const	*inst = talloc_get_type_abort(mctx->mi->data, rlm_mruby_t);
	mruby_call_env_t	*func = talloc_get_type_abort(mctx->env_data, mruby_call_env_t);
	mrb_state		*mrb = inst->mrb;
	mrb_value		mruby_packet, mruby_result, mruby_request, mruby_reply, mruby_control, mruby_session_state;
	mrb_value		args[5];

	mruby_packet = mrb_obj_new(mrb, inst->mruby_request, 0, NULL);
	mrb_iv_set(mrb, mruby_packet, mrb_intern_cstr(mrb, "@frconfig"), inst->mrubyconf_hash);

	args[0] = mruby_inst_object(mrb, inst->mruby_ptr, inst);
	args[1] = mruby_request_object(mrb, inst->mruby_ptr, request);
	args[2] = mruby_dict_attr_object(mrb, inst->mruby_ptr, fr_dict_root(request->proto_dict));
	args[3] = mrb_int_value(mrb, 0);
	args[4] = mruby_value_pair_object(mrb, inst->mruby_ptr, fr_pair_list_parent(&request->request_pairs));
	mruby_request = mrb_obj_new(mrb, inst->mruby_pair_list, 5, args);
	mrb_iv_set(mrb, mruby_packet, mrb_intern_cstr(mrb, "@request"), mruby_request);

	args[4] = mruby_value_pair_object(mrb, inst->mruby_ptr, fr_pair_list_parent(&request->reply_pairs));
	mruby_reply = mrb_obj_new(mrb, inst->mruby_pair_list, 5, args);
	mrb_iv_set(mrb, mruby_packet, mrb_intern_cstr(mrb, "@reply"), mruby_reply);

	args[4] = mruby_value_pair_object(mrb, inst->mruby_ptr, fr_pair_list_parent(&request->control_pairs));
	mruby_control = mrb_obj_new(mrb, inst->mruby_pair_list, 5, args);
	mrb_iv_set(mrb, mruby_packet, mrb_intern_cstr(mrb, "@control"), mruby_control);

	args[4] = mruby_value_pair_object(mrb, inst->mruby_ptr, fr_pair_list_parent(&request->session_state_pairs));
	mruby_session_state = mrb_obj_new(mrb, inst->mruby_pair_list, 5, args);
	mrb_iv_set(mrb, mruby_packet, mrb_intern_cstr(mrb, "@session_state"), mruby_session_state);

	RDEBUG2("Calling %s", func->func->function_name);
DIAG_OFF(DIAG_UNKNOWN_PRAGMAS)
DIAG_OFF(class-varargs)
	mruby_result = mrb_funcall(mrb, mrb_obj_value(inst->mruby_module), func->func->function_name, 1, mruby_packet);
DIAG_ON(class-varargs)
DIAG_ON(DIAG_UNKNOWN_PRAGMAS)

	/*
	 *	The return should be a fixnum, which is converted to rlm_rcode_t
	 */
	if (mrb_type(mruby_result) == MRB_TT_FIXNUM) RETURN_UNLANG_RCODE((rlm_rcode_t)mrb_int(mrb, mruby_result));

	/* Invalid return type */
	RERROR("Expected return to be a Fixnum, got %s instead", RSTRING_PTR(mrb_obj_as_string(mrb, mruby_result)));
	RETURN_UNLANG_FAIL;
}

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_mruby_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_mruby_t);

	mrb_close(inst->mrb);

	return 0;
}

/*
 *	Restrict automatic Ruby function names to lowercase characters, numbers and underscore
 *	meaning that a module call in `recv Access-Request` will look for `recv_access_request`
 */
static void mruby_func_name_safe(char *name) {
	char	*p;
	size_t	i;

	p = name;
	for (i = 0; i < talloc_array_length(name); i++) {
		*p = tolower(*p);
		if (!strchr("abcdefghijklmnopqrstuvwxyz1234567890", *p)) *p = '_';
		p++;
	}
}

static int mruby_func_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *out, UNUSED tmpl_rules_t const *t_rules,
			    UNUSED CONF_ITEM *ci, call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	rlm_mruby_t		*inst = talloc_get_type_abort(cec->mi->data, rlm_mruby_t);
	call_env_parsed_t	*parsed;
	mruby_func_def_t	*func;
	void			*found;

	if (!inst->funcs_init) {
		fr_rb_inline_init(&inst->funcs, mruby_func_def_t, node, mruby_func_def_cmp, NULL);
		inst->funcs_init = true;
	}

	MEM(parsed = call_env_parsed_add(ctx, out,
					 &(call_env_parser_t){
						.name = "func",
						.flags = CALL_ENV_FLAG_PARSE_ONLY,
						.pair = {
							.parsed = {
								.offset = rule->pair.offset,
								.type = CALL_ENV_PARSE_TYPE_VOID
							}
						}
					}));

	MEM(func = talloc_zero(inst, mruby_func_def_t));
	func->name1 = talloc_strdup(func, cec->asked->name1);
	mruby_func_name_safe(func->name1);
	if (cec->asked->name2) {
		func->name2 = talloc_strdup(func, cec->asked->name2);
		mruby_func_name_safe(func->name2);
	}
	if (fr_rb_find_or_insert(&found, &inst->funcs, func) < 0) {
		talloc_free(func);
		return -1;
	}

	/*
	*	If the function call is already in the tree, use that entry.
	*/
	if (found) {
		talloc_free(func);
		call_env_parsed_set_data(parsed, found);
	} else {
		call_env_parsed_set_data(parsed, func);
	}
	return 0;
}

static const call_env_method_t mruby_method_env = {
	FR_CALL_ENV_METHOD_OUT(mruby_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_SUBSECTION_FUNC(CF_IDENT_ANY, CF_IDENT_ANY, CALL_ENV_FLAG_PARSE_MISSING, mruby_func_parse) },
		CALL_ENV_TERMINATOR
	}
};

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_mruby;
module_rlm_t rlm_mruby = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "mruby",
		.flags		= MODULE_TYPE_THREAD_UNSAFE, /* Not sure */
		.inst_size	= sizeof(rlm_mruby_t),
		.config		= module_config,
		.instantiate	= mod_instantiate,
		.detach		= mod_detach,
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = mod_mruby, .method_env = &mruby_method_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
