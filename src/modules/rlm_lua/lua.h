/*
 *   This program is free software; you can redistribute it and/or modify
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
 *
 * @file lua.h
 * @brief Library function signatures for lua module.
 */
RCSIDH(lua_h, "$Id$")

/*
 *	If were using luajit, luajit.h will define a few more constants and
 *	then include lua.h. Lua 5.1 and LuaJIT 2.0 are API compatible.
 */
#ifdef HAVE_LUAJIT_H
#  include <luajit.h>
#else
#  include <lua.h>
#endif
#include <lauxlib.h>
#include <freeradius-devel/server/base.h>

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct {
	lua_State	*interpreter;		//!< Interpreter used for single threaded mode, and environment tests.
	bool 		threads;		//!< Whether to create new interpreters on a per-instance/per-thread
						//!< basis, or use a single mutex protected interpreter.

	bool 		jit;			//!< Whether the linked interpreter is Lua 5.1 or LuaJIT.
	const char 	*module;		//!< Full path to lua script to load and execute.

	const char	*func_instantiate;	//!< Name of function to run on instantiation.
	const char	*func_detach;		//!< Name of function to run on detach.

	const char	*func_xlat;		//!< Name of function to be called for string expansions.

	fr_rb_tree_t	funcs;			//!< Tree of function calls found by call_env parser.
	bool		funcs_init;		//!< Has the tree been initialised.
} rlm_lua_t;

typedef struct {
	lua_State	*interpreter;		//!< Thread specific interpreter.
} rlm_lua_thread_t;

/* lua.c */
int		fr_lua_init(lua_State **out, module_inst_ctx_t const *mctx);
unlang_action_t fr_lua_run(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request, char const *funcname);
bool		fr_lua_isjit(lua_State *L);
char const	*fr_lua_version(lua_State *L);
int		fr_lua_check_func(module_inst_ctx_t const *mctx, lua_State *L, char const *name);

/* util.c */
void		fr_lua_util_jit_log_debug(char const *msg);
void		fr_lua_util_jit_log_info(char const *msg);
void		fr_lua_util_jit_log_warn(char const *msg);
void		fr_lua_util_jit_log_error(char const *msg);

int		fr_lua_util_jit_log_register(lua_State *L);
int		fr_lua_util_log_register(lua_State *L);
void		fr_lua_util_set_mctx(module_ctx_t const *mctx);
module_ctx_t const *fr_lua_util_get_mctx(void);
void		fr_lua_util_set_request(request_t *request);
request_t		*fr_lua_util_get_request(void);
void		fr_lua_util_fr_register(lua_State *L);
