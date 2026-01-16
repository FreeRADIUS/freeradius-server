/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
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
 * @file rlm_lua.c
 * @brief Translates requests between the server an a Lua interpreter.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

#define LOG_PREFIX mctx->mi->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/module_rlm.h>

#include "lua.h"
/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_FILE_READABLE | CONF_FLAG_REQUIRED, rlm_lua_t, module), NULL},
	{ FR_CONF_OFFSET("func_instantiate", rlm_lua_t, func_instantiate), NULL},
	{ FR_CONF_OFFSET("func_detach", rlm_lua_t, func_detach), NULL},
	{ FR_CONF_OFFSET("func_xlat", rlm_lua_t, func_xlat), NULL},

	CONF_PARSER_TERMINATOR
};

typedef struct {
	char const	*function_name;	//!< Name of the function being called
	char		*name1;		//!< Section name1 where this is called
	char		*name2;		//!< Section name2 where this is called
	fr_rb_node_t	node;		//!< Node in tree of function calls.
} lua_func_def_t;

typedef struct {
	lua_func_def_t	*func;
} lua_call_env_t;

/** How to compare two Lua function calls
 *
 */
static int8_t lua_func_def_cmp(void const *one, void const *two)
{
	lua_func_def_t const *a = one, *b = two;
	int ret;

	ret = strcmp(a->name1, b->name1);
	if (ret != 0) return CMP(ret, 0);
	if (!a->name2 && !b->name2) return 0;
	if (!a->name2 || !b->name2) return a->name2 ? 1 : -1;
	ret = strcmp(a->name2, b->name2);
	return CMP(ret, 0);
}

static unlang_action_t mod_lua(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	lua_call_env_t	*func = talloc_get_type_abort(mctx->env_data, lua_call_env_t);
	return fr_lua_run(p_result, mctx, request, func->func->function_name);
}

/** Free any thread specific interpreters
 *
 */
static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_lua_thread_t *t = talloc_get_type_abort(mctx->thread, rlm_lua_thread_t);

	/*
	 *	May be NULL if fr_lua_init failed
	 */
	if (t->interpreter) lua_close(t->interpreter);

	return 0;
}

/** Create thread-specific connections and buffers
 *
 * @param[in] mctx	specific data (where we write the interpreter).
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_lua_thread_t *t = talloc_get_type_abort(mctx->thread, rlm_lua_thread_t);

	if (fr_lua_init(&t->interpreter, (module_inst_ctx_t const *)mctx) < 0) return -1;

	return 0;
}

/** Close the global interpreter
 *
 */
static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_lua_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_lua_t);
	unlang_result_t result;

	/*
	 *	May be NULL if fr_lua_init failed
	 */
	if (inst->interpreter) {
		if (inst->func_detach) {
			fr_lua_run(&result,
				   MODULE_CTX(mctx->mi,
					      &(rlm_lua_thread_t){
							.interpreter = inst->interpreter
					      },
					      NULL, NULL),
				   NULL, inst->func_detach);
		}
		lua_close(inst->interpreter);
	}

	return 0;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_lua_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_lua_t);
	lua_func_def_t		*func = NULL;
	fr_rb_iter_inorder_t	iter;
	CONF_PAIR		*cp;
	char			*pair_name;
	unlang_result_t		result;

	/*
	 *	Get an instance global interpreter to use with various things...
	 */
	if (fr_lua_init(&inst->interpreter, mctx) < 0) return -1;
	inst->jit = fr_lua_isjit(inst->interpreter);
	if (!inst->jit) WARN("Using standard Lua interpreter, performance will be suboptimal");

	DEBUG("Using %s interpreter", fr_lua_version(inst->interpreter));

	/*
	 *	The call_env parser has found all the places the module is called
	 *	Check for config options which set the subroutine name, falling back to
	 *	automatic subroutine names based on section name.
	 */
	if (!inst->funcs_init) fr_rb_inline_init(&inst->funcs, lua_func_def_t, node, lua_func_def_cmp, NULL);

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
			if (fr_lua_check_func(mctx, inst->interpreter, func->function_name) < 0) {
				cf_log_err(cp, "Lua function %s does not exist", func->function_name);
				return -1;
			}
		/*
		 *	If no pair was found, then use <name1>_<name2> or <name1> as the function to call.
		 */
		} else if (func->name2) {
			func->function_name = talloc_asprintf(func, "%s_%s", func->name1, func->name2);
			if (fr_lua_check_func(mctx, inst->interpreter, func->function_name) < 0) {
				talloc_const_free(func->function_name);
				goto name1_only;
			}
		} else {
		name1_only:
			func->function_name = func->name1;
			if (fr_lua_check_func(mctx, inst->interpreter, func->function_name) < 0) {
				cf_log_err(cp, "Lua function %s does not exist", func->function_name);
				return -1;
			}
		}
	}

	if (inst->func_instantiate) {
		fr_lua_run(&result,
			   MODULE_CTX(mctx->mi,
			   	      &(rlm_lua_thread_t){
						.interpreter = inst->interpreter
				      },
				      NULL, NULL),
			   NULL, inst->func_instantiate);
	}

	return 0;
}

/*
 *	Restrict automatic Lua function names to lowercase characters, numbers and underscore
 *	meaning that a module call in `recv Access-Request` will look for `recv_access_request`
 */
static void lua_func_name_safe(char *name) {
	char	*p;
	size_t	i;

	p = name;
	for (i = 0; i < talloc_array_length(name); i++) {
		*p = tolower(*p);
		if (!strchr("abcdefghijklmnopqrstuvwxyz1234567890", *p)) *p = '_';
		p++;
	}
}

static int lua_func_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *out, UNUSED tmpl_rules_t const *t_rules,
			  UNUSED CONF_ITEM *ci, call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	rlm_lua_t		*inst = talloc_get_type_abort(cec->mi->data, rlm_lua_t);
	call_env_parsed_t	*parsed;
	lua_func_def_t		*func;
	void			*found;

	if (!inst->funcs_init) {
		fr_rb_inline_init(&inst->funcs, lua_func_def_t, node, lua_func_def_cmp, NULL);
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

	MEM(func = talloc_zero(inst, lua_func_def_t));
	func->name1 = talloc_strdup(func, cec->asked->name1);
	lua_func_name_safe(func->name1);
	if (cec->asked->name2) {
		func->name2 = talloc_strdup(func, cec->asked->name2);
		lua_func_name_safe(func->name2);
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

static const call_env_method_t lua_method_env = {
	FR_CALL_ENV_METHOD_OUT(lua_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_SUBSECTION_FUNC(CF_IDENT_ANY, CF_IDENT_ANY, CALL_ENV_FLAG_PARSE_MISSING, lua_func_parse) },
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
extern module_rlm_t rlm_lua;
module_rlm_t rlm_lua = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "lua",
		.inst_size		= sizeof(rlm_lua_t),

		.thread_inst_size	= sizeof(rlm_lua_thread_t),

		.config			= module_config,
		.instantiate		= mod_instantiate,
		.thread_instantiate	= mod_thread_instantiate,

		.detach			= mod_detach,
		.thread_detach		= mod_thread_detach
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = mod_lua, .method_env = &lua_method_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
