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
 * @file aux.c
 * @brief Helper Lua land functions.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 *
 * @copyright 2013 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_lua (%s) - "
#define LOG_PREFIX_ARGS inst->xlat_name

#include <freeradius-devel/server/base.h>

#include "config.h"
#include "lua.h"

#include <lauxlib.h>
#include <lualib.h>

static _Thread_local REQUEST *rlm_lua_request;
static _Thread_local rlm_lua_t const *rlm_lua_inst;

/** Lua function to output debug messages
 *
 * Lua arguments are one or more strings. Each successive argument will be printed on a new line.
 *
 * @param L Lua interpreter.
 * @return 0 (no arguments)
 */
static int _aux_log_debug(lua_State *L)
{
	rlm_lua_t const		*inst = rlm_lua_inst;
	REQUEST			*request = rlm_lua_request;
	int			idx;

	while ((idx = lua_gettop(L))) {
		char const *msg = lua_tostring(L, idx);
		lua_pop(L, 1);
		if (!msg) continue;

		ROPTIONAL(RDEBUG2, DEBUG2, "%s", msg);
	}

	return 0;
}

/** Lua function to output informational messages
 *
 * Lua arguments are one or more strings. Each successive argument will be printed on a new line.
 *
 * @param L Lua interpreter.
 * @return 0 (no arguments)
 */
static int _aux_log_info(lua_State *L)
{
	rlm_lua_t const		*inst = rlm_lua_inst;
	REQUEST			*request = rlm_lua_request;
	int 			idx;

	while ((idx = lua_gettop(L))) {
		char const *msg = lua_tostring(L, idx);
		lua_pop(L, 1);
		if (!msg) continue;

		ROPTIONAL(RINFO, INFO, "%s", msg);
	}

	return 0;
}


/** Lua function to output warning messages
 *
 * Lua arguments are one or more strings. Each successive argument will be printed on a new line.
 *
 * @param L Lua interpreter.
 * @return 0 (no arguments)
 */
static int _aux_log_warn(lua_State *L)
{
	rlm_lua_t const		*inst = rlm_lua_inst;
	REQUEST			*request = rlm_lua_request;
	int			idx;

	while ((idx = lua_gettop(L))) {
		char const *msg = lua_tostring(L, idx);
		lua_pop(L, 1);
		if (!msg) continue;

		ROPTIONAL(RWARN, WARN, "%s", msg);
	}

	return 0;
}

/** Lua function to output error messages.
 *
 * Lua arguments are one or more strings. Each successive argument will be printed on a new line.
 *
 * @param L Lua interpreter.
 * @return 0 (no arguments)
 */
static int _aux_log_error(lua_State *L)
{
	rlm_lua_t const		*inst = rlm_lua_inst;
	REQUEST			*request = rlm_lua_request;
	int			idx;

	while ((idx = lua_gettop(L))) {
		char const *msg = lua_tostring(L, idx);
		lua_pop(L, 1);
		if (!msg) continue;

		ROPTIONAL(RERROR, ERROR, "%s", msg);
	}

	return 0;
}

/** Insert cdefs into the lua environment
 *
 * For LuaJIT using the FFI is significantly faster than the Lua interface.
 * Help people wishing to use the FFI by inserting cdefs for standard functions.
 *
 * @param inst Current instance of the rlm_lua module.
 * @param L Lua interpreter.
 * @return 0 (no arguments).
 */
int fr_lua_aux_jit_funcs_register(rlm_lua_t const *inst, lua_State *L)
{
	if (luaL_dostring(L,"\
		ffi = require(\"ffi\")\
		ffi.cdef [[\
			typedef enum log_type {\
				L_INFO = 3,\
				L_ERR = 4,\
				L_WARN = 5,\
				L_DBG = 16,\
				L_DBG_WARN = 17,\
				L_DBG_ERR = 18,\
				L_DBG_WARN_REQ = 20,\
				L_DBG_ERR_REQ = 21\
			} fr_log_type_t;\
			int fr_log(fr_log_type_t lvl, char const *fmt, ...);\
			]]\
		fr_srv = ffi.load(\"freeradius-server\")\
		fr_lua = ffi.load(\"freeradius-lua\")\
		fr.debug = function(msg)\
		   fr_srv.fr_log(16, \"%s\", msg)\
		end\
		fr.info = function(msg)\
		   fr_srv.fr_log(3, \"%s\", msg)\
		end\
		fr.warn = function(msg)\
		   fr_srv.fr_log(5, \"%s\", msg)\
		end\
		fr.error = function(msg)\
		   fr_srv.fr_log(4, \"%s\", msg)\
		end\
		") != 0) {
		ERROR("Failed setting up FFI: %s",
		      lua_gettop(L) ? lua_tostring(L, -1) : "Unknown error");
		return -1;
	}

	return 0;
}

/** Register auxiliary functions in the lua environment
 *
 * @param inst Current instance of the rlm_lua module.
 * @param L Lua interpreter.
 * @return 0 (no arguments).
 */
int fr_lua_aux_funcs_register(UNUSED rlm_lua_t const *inst, lua_State *L)
{
	lua_newtable(L);
	lua_pushcfunction(L, _aux_log_debug);
	lua_setfield(L, -2, "debug");

	lua_pushcfunction(L, _aux_log_info);
	lua_setfield(L, -2, "info");

	lua_pushcfunction(L, _aux_log_warn);
	lua_setfield(L, -2, "warn");

	lua_pushcfunction(L, _aux_log_error);
	lua_setfield(L, -2, "error");
	lua_setglobal(L, "fr");

	return 0;
}

/** Set the thread local instance
 *
 * @param[in] inst	all helper and C functions callable from Lua should use.
 */
void fr_lua_aux_set_inst(rlm_lua_t const *inst)
{
	rlm_lua_inst = inst;
}

/** Get the thread local instance
 *
 * @return inst all helper and C functions callable from Lua should use.
 */
rlm_lua_t const *fr_lua_aux_get_inst(void)
{
	return rlm_lua_inst;
}

/** Set the thread local request
 *
 * @param[in] request	all helper and C functions callable from Lua should use.
 */
void fr_lua_aux_set_request(REQUEST *request)
{
	rlm_lua_request = request;
}

/** Get the thread local request
 *
 * @return request all helper and C functions callable from Lua should use.
 */
REQUEST *fr_lua_aux_get_request(void)
{
	return rlm_lua_request;
}

