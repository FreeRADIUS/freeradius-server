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
 * @file rlm_lua/util.c
 * @brief Helper Lua land functions.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
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

static _Thread_local request_t *fr_lua_request;
static _Thread_local rlm_lua_t const *fr_lua_inst;

void fr_lua_util_fr_register(lua_State *L)
{
	/* fr.{} */
	lua_newtable(L);
	lua_setglobal(L, "fr");
	lua_settop(L, 0);
}

/** Lua function to output debug messages
 *
 * Lua arguments are one or more strings. Each successive argument will be printed on a new line.
 *
 * @param L Lua interpreter.
 * @return 0 (no arguments)
 */
static int _util_log_debug(lua_State *L)
{
	rlm_lua_t const		*inst = fr_lua_inst;
	request_t			*request = fr_lua_request;
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
static int _util_log_info(lua_State *L)
{
	rlm_lua_t const		*inst = fr_lua_inst;
	request_t			*request = fr_lua_request;
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
static int _util_log_warn(lua_State *L)
{
	rlm_lua_t const		*inst = fr_lua_inst;
	request_t			*request = fr_lua_request;
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
static int _util_log_error(lua_State *L)
{
	rlm_lua_t const		*inst = fr_lua_inst;
	request_t			*request = fr_lua_request;
	int			idx;

	while ((idx = lua_gettop(L))) {
		char const *msg = lua_tostring(L, idx);
		lua_pop(L, 1);
		if (!msg) continue;

		ROPTIONAL(RERROR, ERROR, "%s", msg);
	}

	return 0;
}

static int _util_log_newindex(UNUSED lua_State *L)
{
	request_t	*request = fr_lua_util_get_request();

	RWDEBUG("fr.log.$func() is read-only");

	return 1;
}

/** Emit a debug log message
 *
 * @param msg	to be printed.
 */
void fr_lua_util_jit_log_debug(char const *msg)
{
	rlm_lua_t const		*inst = fr_lua_inst;
	request_t			*request = fr_lua_request;

	ROPTIONAL(RDEBUG2, DEBUG2, "%s", msg);
}

/** Emit an info log message
 *
 * @param msg	to be printed.
 */
void fr_lua_util_jit_log_info(char const *msg)
{
	rlm_lua_t const		*inst = fr_lua_inst;
	request_t			*request = fr_lua_request;

	ROPTIONAL(RINFO, INFO, "%s", msg);
}

/** Emit a warning log message
 *
 * @param msg	to be printed.
 */
void fr_lua_util_jit_log_warn(char const *msg)
{
	rlm_lua_t const		*inst = fr_lua_inst;
	request_t			*request = fr_lua_request;

	ROPTIONAL(RWARN, WARN, "%s", msg);
}

/** Emit a error log message
 *
 * @param msg	to be printed.
 */
void fr_lua_util_jit_log_error(char const *msg)
{
	rlm_lua_t const		*inst = fr_lua_inst;
	request_t			*request = fr_lua_request;

	ROPTIONAL(RERROR, ERROR, "%s", msg);
}

/** Insert cdefs into the lua environment
 *
 * For LuaJIT using the FFI is significantly faster than the Lua interface.
 * Help people wishing to use the FFI by inserting cdefs for standard functions.
 *
 * @param inst Current instance of the fr_lua module.
 * @param L Lua interpreter.
 * @return 0 (no arguments).
 */
int fr_lua_util_jit_log_register(rlm_lua_t const *inst, lua_State *L)
{
	char const *search_path;
	char *lua_str;
	int ret;

	search_path = dl_module_search_path();
	lua_str = talloc_asprintf(NULL, "\
		ffi = require(\"ffi\")\
		ffi.cdef [[\
			void fr_lua_util_jit_log_debug(char const *msg);\
			void fr_lua_util_jit_log_info(char const *msg);\
			void fr_lua_util_jit_log_warn(char const *msg);\
			void fr_lua_util_jit_log_error(char const *msg);\
		]]\
		fr_lua = ffi.load(\"%s%clibfreeradius-lua%s\")\
		_fr_log = {}\
		_fr_log.debug = function(msg)\
			fr_lua.fr_lua_util_jit_log_debug(msg)\
		end\
		_fr_log.info = function(msg)\
			fr_lua.fr_lua_util_jit_log_info(msg)\
		end\
		_fr_log.warn = function(msg)\
			fr_lua.fr_lua_util_jit_log_warn(msg)\
		end\
		_fr_log.error = function(msg)\
			fr_lua.fr_lua_util_jit_log_error(msg)\
		end\
		function _ro_log(table) \
			return setmetatable({}, { \
				__index = table,\
				__newindex = function(table, key, value)\
					_fr_log.warn(\"fr.log.$func() is read-only\")\
				end, \
				__metatable = false \
			}); \
		end\
		fr.log = _ro_log(_fr_log)\
		", search_path, FR_DIR_SEP, DL_EXTENSION);
	ret = luaL_dostring(L, lua_str);
	talloc_free(lua_str);
	if (ret != 0) {
		ERROR("Failed setting up FFI: %s",
		      lua_gettop(L) ? lua_tostring(L, -1) : "Unknown error");

		return -1;
	}

	return 0;
}

/** Register utililiary functions in the lua environment
 *
 * @param inst Current instance of the fr_lua module.
 * @param L Lua interpreter.
 * @return 0 (no arguments).
 */
int fr_lua_util_log_register(UNUSED rlm_lua_t const *inst, lua_State *L)
{
	/* fr.{} */
	lua_getglobal(L, "fr");
	luaL_checktype(L, -1, LUA_TTABLE);

	/* fr.log.{} */
	lua_newtable(L);
	{
		lua_newtable(L); //__metatable
		{
			lua_pushvalue(L, -1);
			lua_setfield(L, -2, "__index");

			lua_pushcfunction(L, _util_log_newindex);
			lua_setfield(L, -2, "__newindex");
		}

		lua_pushcfunction(L, _util_log_debug);
		lua_setfield(L, -2, "debug");

		lua_pushcfunction(L, _util_log_info);
		lua_setfield(L, -2, "info");

		lua_pushcfunction(L, _util_log_warn);
		lua_setfield(L, -2, "warn");

		lua_pushcfunction(L, _util_log_error);
		lua_setfield(L, -2, "error");
	}

	lua_setmetatable(L, -2);
	lua_setfield(L, -2, "log");

	return 0;
}

/** Set the thread local instance
 *
 * @param[in] inst	all helper and C functions callable from Lua should use.
 */
void fr_lua_util_set_inst(rlm_lua_t const *inst)
{
	fr_lua_inst = inst;
}

/** Get the thread local instance
 *
 * @return inst all helper and C functions callable from Lua should use.
 */
rlm_lua_t const *fr_lua_util_get_inst(void)
{
	return fr_lua_inst;
}

/** Set the thread local request
 *
 * @param[in] request	all helper and C functions callable from Lua should use.
 */
void fr_lua_util_set_request(request_t *request)
{
	fr_lua_request = request;
}

/** Get the thread local request
 *
 * @return request all helper and C functions callable from Lua should use.
 */
request_t *fr_lua_util_get_request(void)
{
	return fr_lua_request;
}

