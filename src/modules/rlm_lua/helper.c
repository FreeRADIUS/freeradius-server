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
 * @file helper.c
 * @brief Helper Lua land functions.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 *
 * @copyright 2013 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>

#include "config.h"
#include "lua.h"

#include <lauxlib.h>
#include <lualib.h>

/** Lua function to output debug messages
 *
 * Lua arguments are one or more strings. Each successive argument will be printed on a new line.
 *
 * @param L Lua interpreter.
 * @return 0 (no arguments)
 */
static int _aux_log_debug(lua_State *L)
{
	int idx;

	while ((idx = lua_gettop(L))) {
		char const *msg = lua_tostring(L, idx);
		lua_pop(L, 1);
		if (!msg) continue;

		DEBUG("%s", msg);
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
	int idx;

	while ((idx = lua_gettop(L))) {
		char const *msg = lua_tostring(L, idx);
		lua_pop(L, 1);
		if (!msg) continue;

		INFO("%s", msg);
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
	int idx;

	while ((idx = lua_gettop(L))) {
		char const *msg = lua_tostring(L, idx);
		lua_pop(L, 1);
		if (!msg) continue;

		WARN("%s", msg);
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
	int idx;

	while ((idx = lua_gettop(L))) {
		char const *message = lua_tostring(L, idx);
		ERROR("%i: %s", idx, message);
		lua_pop(L, 1);
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
int aux_jit_funcs_register(rlm_lua_t const *inst, lua_State *L)
{
	if (luaL_dostring(L,"\
		ffi = require(\"ffi\")\
		ffi.cdef [[\
			typedef enum log_type {\
				L_AUTH = 2,\
				l_log_info = 3,\
				L_ERR = 4,\
				L_WARN = 5,\
				L_PROXY	= 6,\
				L_ACCT = 7,\
				L_DBG = 16,\
				L_DBG_WARN = 17,\
				L_DBG_ERR = 18,\
				L_DBG_WARN2 = 19,\
				L_DBG_ERR2 = 20\
			} fr_log_type_t;\
			int fr_log(fr_log_type_t lvl, char const *fmt, ...);\
			]]\
		fr_srv = ffi.load(\"freeradius-server\")\
		fr = ffi.load(\"freeradius-lua\")\
		debug = function(msg)\
		   fr_srv.fr_log(16, \"%s\", msg)\
		end\
		info = function(msg)\
		   fr_srv.fr_log(3, \"%s\", msg)\
		end\
		warn = function(msg)\
		   fr_srv.fr_log(5, \"%s\", msg)\
		end\
		error = function(msg)\
		   fr_srv.fr_log(4, \"%s\", msg)\
		end\
		") != 0) {
		ERROR("rlm_lua (%s): Failed setting up FFI: %s", inst->xlat_name,
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
int aux_funcs_register(UNUSED rlm_lua_t const *inst, lua_State *L)
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
