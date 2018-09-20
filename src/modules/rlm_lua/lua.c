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
 * @file lua.c
 * @brief Library functions for the lua module.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @author Artur Malinowski <artur@wow.com>
 *
 * @copyright 2015 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>

#include "config.h"
#include "lua.h"

#include <lauxlib.h>
#include <lualib.h>

#define RLM_LUA_STACK_SET()	int _rlm_lua_stack_state = lua_gettop(L)
#define RLM_LUA_STACK_RESET()	lua_settop(L, _rlm_lua_stack_state)

static _Thread_local REQUEST *rlm_lua_request;

/** Convert VALUE_PAIRs to Lua values
 *
 * Pushes a Lua representation of an attribute value onto the stack.
 *
 * @param L Lua interpreter.
 * @param vp to convert.
 * @return 0 on success, -1 on failure.
 */
static int rlm_lua_marshall(lua_State *L, VALUE_PAIR const *vp)
{
	char buffer[1024];

	if (!vp) return -1;

	switch (vp->vp_type) {
	case FR_TYPE_ETHERNET:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_IFID:
	case FR_TYPE_TIMEVAL:
	case FR_TYPE_ABINARY:
		fr_pair_value_snprint(buffer, sizeof(buffer), vp, '\0');
		lua_pushstring(L, buffer);
		break;

	case FR_TYPE_STRING:
		lua_pushlstring(L, vp->vp_strvalue, vp->vp_length);
		break;

	case FR_TYPE_OCTETS:
		lua_pushlstring(L, (char const *)vp->vp_octets, vp->vp_length); /* lstring variant is embedded NULL safe */
		break;

	case FR_TYPE_BOOL:
		lua_pushinteger(L, vp->vp_bool ? 1 : 0);
		break;

	case FR_TYPE_UINT8:
		lua_pushinteger(L, vp->vp_uint8);
		break;

	case FR_TYPE_UINT16:
		lua_pushinteger(L, vp->vp_uint16);
		break;

	case FR_TYPE_UINT32:
		lua_pushinteger(L, vp->vp_uint32);
		break;

	case FR_TYPE_UINT64:
		lua_pushinteger(L, vp->vp_uint64);
		break;

	case FR_TYPE_INT8:
		lua_pushinteger(L, vp->vp_int8);
		break;

	case FR_TYPE_INT16:
		lua_pushinteger(L, vp->vp_int16);
		break;

	case FR_TYPE_INT32:
		lua_pushinteger(L, vp->vp_int32);
		break;

	case FR_TYPE_INT64:
		lua_pushinteger(L, vp->vp_int64);
		break;

	case FR_TYPE_DATE:
		lua_pushinteger(L, vp->vp_date);
		break;

	case FR_TYPE_DATE_MILLISECONDS:
		lua_pushinteger(L, vp->vp_date_milliseconds);
		break;

	case FR_TYPE_DATE_MICROSECONDS:
		lua_pushinteger(L, vp->vp_date_microseconds);
		break;

	case FR_TYPE_DATE_NANOSECONDS:
		lua_pushinteger(L, vp->vp_date_nanoseconds);
		break;

	case FR_TYPE_FLOAT32:
		lua_pushnumber(L, (double) vp->vp_float32);
		break;

	case FR_TYPE_FLOAT64:
		lua_pushnumber(L, vp->vp_float64);
		break;

	case FR_TYPE_SIZE:
		lua_pushnumber(L, vp->vp_size);
		break;

	case FR_TYPE_NON_VALUES:
		ERROR("Cannot convert %s to Lua type", fr_int2str(fr_value_box_type_names, vp->vp_type, "<INVALID>"));
		return -1;
	}
	return 0;
}

/** Convert Lua values to VALUE_PAIRs
 *
 * Convert Lua values back to VALUE_PAIRs. How the Lua value is converted is dependent
 * on the type of the DA.
 *
 * @param out Where to write a pointer to the new VALUE_PAIR.
 * @param request the current request.
 * @param L Lua interpreter.
 * @param da specifying the type of attribute to create.
 * @return 0 on success, -1 on failure.
 */
static int rlm_lua_unmarshall(VALUE_PAIR **out, REQUEST *request, lua_State *L, fr_dict_attr_t const *da)
{
	VALUE_PAIR *vp;

	MEM(vp = fr_pair_afrom_da(request, da));
	switch (lua_type(L, -1)) {
	case LUA_TNUMBER:
		switch (vp->vp_type) {
		case FR_TYPE_STRING:
		{
			char *p;
			p = talloc_typed_asprintf(vp, "%f", lua_tonumber(L, -1));
			fr_pair_value_strsteal(vp, p);
			break;
		}

		case FR_TYPE_IPV4_ADDR:
		case FR_TYPE_COMBO_IP_ADDR:
			vp->vp_ipv4addr = (uint32_t) lua_tointeger(L, -1);
			break;

		case FR_TYPE_OCTETS:
		{
			lua_Number number = lua_tonumber(L, -1);
			fr_pair_value_memcpy(vp, (uint8_t*) &number, sizeof(number));
		}
			break;

		/*
		 *	FIXME: Check to see if values overflow
		 */
		case FR_TYPE_UINT8:
			vp->vp_uint8 = (uint8_t) lua_tointeger(L, -1);
			break;

		case FR_TYPE_UINT16:
			vp->vp_uint16 = (uint16_t) lua_tointeger(L, -1);
			break;

		case FR_TYPE_UINT32:
			vp->vp_uint32 = (uint32_t) lua_tointeger(L, -1);
			break;

		case FR_TYPE_UINT64:
			vp->vp_uint64 = (uint64_t) lua_tointeger(L, -1);
			break;

		case FR_TYPE_INT8:
			vp->vp_int8 = (int8_t) lua_tointeger(L, -1);
			break;

		case FR_TYPE_INT16:
			vp->vp_int16 = (int16_t) lua_tointeger(L, -1);
			break;

		case FR_TYPE_INT32:
			vp->vp_int32 = (int32_t) lua_tointeger(L, -1);
			break;

		case FR_TYPE_INT64:
			vp->vp_int64 = (int64_t) lua_tointeger(L, -1);
			break;

		case FR_TYPE_FLOAT32:
			vp->vp_float32 = (float) lua_tonumber(L, -1);
			break;

		case FR_TYPE_FLOAT64:
			vp->vp_float64 = (double) lua_tonumber(L, -1);
			break;

		case FR_TYPE_DATE:
			vp->vp_date = (uint32_t) lua_tointeger(L, -1);
			break;

		case FR_TYPE_DATE_MILLISECONDS:
			vp->vp_date_milliseconds = (uint64_t) lua_tointeger(L, -1);
			break;

		case FR_TYPE_DATE_MICROSECONDS:
			vp->vp_date_microseconds = (uint64_t) lua_tointeger(L, -1);
			break;

		case FR_TYPE_DATE_NANOSECONDS:
			vp->vp_date_nanoseconds = (uint64_t) lua_tointeger(L, -1);
			break;

		default:
			REDEBUG("Invalid attribute type");
			return -1;
		}
		break;

	case LUA_TSTRING:
		/*
		 *	Special case for binary data. Lua strings can be used to represent
		 *	both printable strings and binary data. They do not treat NULLs or
		 *	any other unprintable chars any different from those in a plaintext
		 *	string.
		 */
		if (da->type == FR_TYPE_OCTETS) {
			uint8_t const *p;
			size_t len;

			p = (uint8_t const *) lua_tolstring(L, -1, &len);
			if (!p) {
				RDEBUG("Unmarshalling failed: Lua bstring was NULL");
				return -1;
			}
			fr_pair_value_memcpy(vp, p, len);
		/*
		 *	We don't have any special types in Lua for things likes IP addresses
		 *	or dates, so everything gets converted to a string, then back to
		 *	it's original binary form by pairparsevalue.
		 */
		} else {
			char const *p;
			p = lua_tostring(L, -1);
			if (!p) {
				REDEBUG("Unmarshalling failed: Lua string was NULL");
				return -1;
			}
			if (fr_pair_value_from_str(vp, p, strlen(p), '\0', false) < 0) {
				RPEDEBUG("Unmarshalling failed");
				return -1;
			}
		}
		break;

	case LUA_TLIGHTUSERDATA:
	case LUA_TUSERDATA:
	{
		size_t len;
		uint8_t *p;

		len = lua_objlen(L, -1);
		if (len == 0) {
			REDEBUG("Unmarshalling failed: Can't determine length of user data");
			return -1;
		}
		p = lua_touserdata(L, -1);
		if (!p) {
			REDEBUG("Unmarshalling failed: User data was NULL");
		}
		fr_pair_value_memcpy(vp, p, len);
	}
		break;

	default:
	{
		int type = lua_type(L, -1);
		REDEBUG("Unmarshalling failed: Unknown type %s (%i)", lua_typename(L, type), type);

		return -1;
	}
	}

	*out = vp;
	return 0;
}

/** Get an instance of an attribute
 *
 * @note Should only be present in the Lua environment as a closure.
 * @note Takes one upvalue - the fr_dict_attr_t to search for as light user data.
 * @note Is called as an __index metamethod, so takes the table (can be ignored) and the field (an integer index value)
 *
 * @param L Lua interpreter.
 * @return 0 (no results) on success, 1 on success with the VALUE_PAIR value on the stack.
 */
static int _lua_pair_get(lua_State *L)
{
	fr_cursor_t cursor;
	fr_dict_attr_t const	*da;
	VALUE_PAIR		*vp = NULL;
	int			index;
	REQUEST			*request = rlm_lua_request;

	rad_assert(lua_islightuserdata(L, lua_upvalueindex(1)));

	da = lua_touserdata(L, lua_upvalueindex(1));
	rad_assert(da);

	/*
	 *	@fixme Packet list should be light user data too at some point
	 */
	fr_cursor_iter_by_da_init(&cursor, &request->packet->vps, da);

	for (index = (int) lua_tointeger(L, -1); index >= 0; index--) {
		vp = fr_cursor_next(&cursor);
		if (!vp) return 0;
	}

	if (rlm_lua_marshall(L, vp) < 0) return -1;

	return 1;
}

/** Set an instance of an attribute
 *
 * @note Should only be present in the Lua environment as a closure.
 * @note Takes one upvalue - the fr_dict_attr_t to search for as light user data.
 * @note Is called as an __newindex metamethod, so takes the table (can be ignored), the field (an integer index value)
 *	 and the new value.
 *
 * @param L Lua interpreter.
 * @return 0 on success, -1 on failure.
 */
static int _lua_pair_set(lua_State *L)
{
	fr_cursor_t cursor;
	fr_dict_attr_t const *da;
	VALUE_PAIR *vp = NULL, *new;
	int index;
	bool delete = false;
	REQUEST *request = rlm_lua_request;

	/*
	 *	This function should only be called as a closure.
	 *	As we control the upvalues, we should assert on errors.
	 */

	rad_assert(lua_islightuserdata(L, lua_upvalueindex(1)));

	da = lua_touserdata(L, lua_upvalueindex(1));
	rad_assert(da);

	delete = lua_isnil(L, -1);

	/*
	 *	@fixme Packet list should be light user data too at some point
	 */
	fr_cursor_iter_by_da_init(&cursor, &request->packet->vps, da);

	for (index = (int) lua_tointeger(L, -2); index >= 0; index--) {
		vp = fr_cursor_next(&cursor);
		if (vp) break;
	}

	/*
	 *	If the value of the Lua stack was nil, we delete the
	 *	attribute the cursor is currently positioned at.
	 */
	if (delete) {
		fr_cursor_remove(&cursor);
		return 0;
	}

	if (rlm_lua_unmarshall(&new, request, L, da) < 0) {
		return -1;
	}

	/*
	 *	If there was already a VP at that index we replace it
	 *	else we add a new VP to the list.
	 */
	if (vp) {
		fr_cursor_replace(&cursor, new);
	} else {
		fr_cursor_append(&cursor, new);
	}

	return 0;
}

static int _lua_pair_iterator(lua_State *L)
{
	fr_cursor_t *cursor;
	VALUE_PAIR *vp;

	/*
	 *	This function should only be called as a closure.
	 *	As we control the upvalues, we should assert on errors.
	 */

	rad_assert(lua_isuserdata(L, lua_upvalueindex(1)));

	cursor = lua_touserdata(L, lua_upvalueindex(1));
	rad_assert(cursor);

	/* Packet list should be light user data too at some point... */
	vp = fr_cursor_next(cursor);
	if (!vp) {
		lua_pushnil(L);
		return 1;
	}

	if (rlm_lua_marshall(L, vp) < 0) {
		return -1;
	}

	return 1;
}

static int _lua_pair_iterator_init(lua_State *L)
{
	fr_cursor_t *cursor;
	fr_dict_attr_t const *da;
	REQUEST *request = rlm_lua_request;

	/*
	 *	This function should only be called as a closure.
	 *	As we control the upvalues, we should assert on errors.
	 */
	rad_assert(lua_isuserdata(L, lua_upvalueindex(2)));

	da = lua_touserdata(L, lua_upvalueindex(2));
	rad_assert(da);

	cursor = (fr_cursor_t*) lua_newuserdata(L, sizeof(fr_cursor_t));
	if (!cursor) {
		REDEBUG("Failed allocating user data to hold cursor");
		return -1;
	}
	fr_cursor_iter_by_da_init(cursor, &request->packet->vps, da);	/* @FIXME: Shouldn't use list head */

	lua_pushcclosure(L, _lua_pair_iterator, 1);

	return 1;
}

static int _lua_list_iterator(lua_State *L)
{
	fr_cursor_t *cursor;
	VALUE_PAIR *vp;

	rad_assert(lua_isuserdata(L, lua_upvalueindex(1)));

	cursor = lua_touserdata(L, lua_upvalueindex(1));
	rad_assert(cursor);

	/* Packet list should be light user data too at some point... */
	vp = fr_cursor_current(cursor);
	if(!vp) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushstring(L, vp->da->name);

	if (rlm_lua_marshall(L, vp) < 0) {
		return -1;
	}

	fr_cursor_next(cursor);

	return 2;
}

/** Initialise a new top level list iterator
 *
 */
static int _lua_list_iterator_init(lua_State *L)
{
	fr_cursor_t *cursor;
	REQUEST *request = rlm_lua_request;

	cursor = (fr_cursor_t*) lua_newuserdata(L, sizeof(fr_cursor_t));
	if (!cursor) {
		REDEBUG("Failed allocating user data to hold cursor");
		return -1;
	}
	fr_cursor_init(cursor, &request->packet->vps);	/* @FIXME: Shouldn't use list head */

	lua_pushlightuserdata(L, cursor);
	lua_pushcclosure(L, _lua_list_iterator, 1);

	return 1;
}


/** Initialise and return a new accessor table
 *
 *
 */
static int _lua_pair_accessor_init(lua_State *L)
{
	char const *attr;
	fr_dict_attr_t const *da;
	fr_dict_attr_t *up;
	REQUEST *request = rlm_lua_request;

	attr = lua_tostring(L, -1);
	if (!attr) {
		REDEBUG("Failed retrieving field name \"%s\"", attr);
		return -1;
	}

	da = fr_dict_attr_by_name(request->dict, attr);
	if (!da) {
		REDEBUG("Unknown or invalid attribute name \"%s\"", attr);
		return -1;
	}
	memcpy(&up, &da, sizeof(up));

	/*
	 *	Add the pairs method to the main table, this allows
	 *	easy iteration over multiple values of the same
	 *	attribute.
	 *
	 *	for v in request[User-Name].pairs() do
	 */
	lua_newtable(L);
	lua_pushlightuserdata(L, request->packet->vps);
	lua_pushlightuserdata(L, up);
	lua_pushcclosure(L, _lua_pair_iterator_init, 2);
	lua_setfield(L, -2, "pairs");

	/*
	 *	Metatable methods for getting and setting
	 */
	lua_newtable(L);
	lua_pushlightuserdata(L, up);
	lua_pushcclosure(L, _lua_pair_get, 1);
	lua_setfield(L, -2, "__index");

	lua_pushlightuserdata(L, up);
	lua_pushcclosure(L, _lua_pair_set, 1);
	lua_setfield(L, -2, "__newindex");

	lua_setmetatable(L, -2);
	lua_settable(L, -3);		/* Cache the attribute manipulation object */
	lua_getfield(L, -1, attr);	/* and return it */

	return 1;
}

/** Check whether the Lua interpreter were actually linked to is LuaJIT
 *
 * @param L Lua interpreter.
 * @return true if were running with LuaJIT else false.
 */
bool rlm_lua_isjit(lua_State *L)
{
	bool ret = false;
	RLM_LUA_STACK_SET();
	lua_getglobal(L, "jit");
	if (lua_isnil(L, -1)) {
		goto done;
	}
	ret = true;
done:
	RLM_LUA_STACK_RESET();
	return ret;
}

char const *rlm_lua_version(lua_State *L)
{
	char const *version;

	RLM_LUA_STACK_SET();
	lua_getglobal(L, "jit");
	if (!lua_isnil(L, -1)) {
		lua_getfield(L, -1, "version");	/* Version field in jit table */
	} else {
		lua_getglobal(L, "_VERSION");	/* Version global */
	}

	if (lua_isnil(L, -1) || !(version = lua_tostring(L, -1))) {
		return "unknown version";
	}
	RLM_LUA_STACK_RESET();

	return version;
}

/** Check if a given function was loaded into an index in the global table
 *
 * Also check what was loaded there is a function and that it accepts the correct arguments.
 *
 * @param inst Current instance of rlm_lua
 * @param L the lua state
 * @param name of function to check.
 * @returns 0 on success (function is present and correct), or -1 on failure.
 */
static int rlm_lua_check_func(rlm_lua_t const *inst, lua_State *L, char const *name)
{
	int ret;
	int type;
	RLM_LUA_STACK_SET();

	if (name == NULL) return 0;

	lua_getglobal(L, name);

	/*
	 *	Check the global is a function.
	 */
	type = lua_type(L, -1);
	switch (type) {
	case LUA_TFUNCTION:
		break;

	case LUA_TNIL:
		ERROR("rlm_lua (%s): Function \"%s\" not found ", inst->xlat_name, name);
		ret = -1;
		goto done;

	default:
		ERROR("rlm_lua (%s): Value found at index \"%s\" is not a function (is a %s)",
		      inst->xlat_name, name, lua_typename(L, type));
		ret = -1;
		goto done;
	}
	ret = 0;
done:
	RLM_LUA_STACK_RESET();
	return ret;
}

/** Initialise a new Lua/LuaJIT interpreter
 *
 * Creates a new lua_State and verifies all required functions have been loaded correctly.
 *
 * @param out Where to write a pointer to the new state.
 * @param instance Current instance of rlm_lua, a talloc marker context will be inserted into the context of instance
 *	to ensure the interpreter is freed when instance data is freed.
 * @return 0 on success else -1.
 */
int rlm_lua_init(lua_State **out, rlm_lua_t const *instance)
{
	rlm_lua_t const *inst = instance;
	lua_State *L;

	L = luaL_newstate();
	if (!L) {
		ERROR("rlm_lua (%s): Failed initialising Lua state", inst->xlat_name);
		return -1;
	}

	luaL_openlibs(L);

	/*
	 *	Load the Lua file into our environment.
	 */
	if (luaL_loadfile(L, inst->module) != 0) {
		ERROR("rlm_lua (%s): Failed loading file: %s", inst->xlat_name,
		      lua_gettop(L) ? lua_tostring(L, -1) : "Unknown error");

		goto error;
	}

	if (lua_pcall(L, 0, LUA_MULTRET, 0) != 0) {
		ERROR("rlm_lua (%s): Failed executing script: %s", inst->xlat_name,
		      lua_gettop(L) ? lua_tostring(L, -1) : "Unknown error");

		goto error;
	}

	if (inst->jit) {
		DEBUG4("rlm_lua (%s): Initialised new LuaJIT interpreter %p", inst->xlat_name, L);
		aux_jit_funcs_register(inst, L);
	} else {
		DEBUG4("rlm_lua (%s): Initialised new Lua interpreter %p", inst->xlat_name, L);
		aux_funcs_register(inst, L);
	}

	/*
	 *	Verify all the functions were provided.
	 */
	if (rlm_lua_check_func(inst, L, inst->func_authorize)
	    || rlm_lua_check_func(inst, L, inst->func_authenticate)
#ifdef WITH_ACCOUNTING
	    || rlm_lua_check_func(inst, L, inst->func_preacct)
	    || rlm_lua_check_func(inst, L, inst->func_accounting)
#endif
	    || rlm_lua_check_func(inst, L, inst->func_checksimul)
#ifdef WITH_PROXY
	    || rlm_lua_check_func(inst, L, inst->func_pre_proxy)
	    || rlm_lua_check_func(inst, L, inst->func_post_proxy)
#endif
	    || rlm_lua_check_func(inst, L, inst->func_post_auth)
#ifdef WITH_COA
	    || rlm_lua_check_func(inst, L, inst->func_recv_coa)
	    || rlm_lua_check_func(inst, L, inst->func_send_coa)
#endif
	    || rlm_lua_check_func(inst, L, inst->func_detach)
	    || rlm_lua_check_func(inst, L, inst->func_xlat)) {
	 	goto error;
	}

	*out = L;
	return 0;

error:
	*out = NULL;

	lua_close(L);
	return -1;
}

/** Resolve a path string to a field value in Lua
 *
 * Parses a string in the format FIELD1 or FIELD1.FIELD2, adding all tables
 * it traverses to the stack.
 *
 * All paths are assumed to start at a global, so the first field
 * will be looked up in the global table.
 *
 */
static int rlm_lua_get_field(lua_State *L, REQUEST *request, char const *field)
{
	char buffer[512];
	char const *p = field, *q;

	while ((q = strchr(field, '.'))) {
		if ((size_t) (p - q) >= sizeof(buffer)) {
			RDEBUG("Field name too long, maximum is %zu", sizeof(buffer));
			return -1;
		}

		strlcpy(buffer, p, p - q);
		if (!(p - buffer)) {
			lua_getglobal(L, buffer);
		} else {
			lua_getfield(L, -1, buffer);
		}
		if (lua_isnil(L, -1)) {
			RDEBUG("Field '%s' does not exist", p);
			return -1;
		}
	}

	return 0;
}

#ifdef HAVE_PTHREAD_H
#define rlm_lua_release_interp(_x)  if (!_x->threads) pthread_mutex_unlock(_x->mutex)
#else
#define rlm_lua_release_interp(_x)
#endif

int do_lua(rlm_lua_t const *inst, rlm_lua_thread_t *thread, REQUEST *request, char const *funcname)
{
	fr_cursor_t cursor;
	lua_State *L = thread->interpreter;

	rlm_lua_request = request;

	RDEBUG2("Calling %s() in interpreter %p", funcname, L);

	fr_pair_list_sort(&request->packet->vps, fr_pair_cmp_by_da_tag);
	fr_cursor_init(&cursor, &request->packet->vps);

	/*
	 *	Setup the environment
	 */
	lua_newtable(L);		/* Attribute list table */
	lua_pushlightuserdata(L, &cursor);
	lua_pushcclosure(L, _lua_list_iterator_init, 1);
	lua_setfield(L, -2, "pairs");
	lua_newtable(L);		/* Attribute list meta-table */
	lua_pushinteger(L, PAIR_LIST_REQUEST);
	lua_pushcclosure(L, _lua_pair_accessor_init, 1);
	lua_setfield(L, -2, "__index");

//	lua_pushcfunction(L, new_index);
//	lua_setfield(L, -2, "__newindex");

	lua_setmetatable(L, -2);
	lua_setglobal(L, "request");

	/*
	 *	Get the function were going to be calling
	 */
	if (rlm_lua_get_field(L, request, funcname) < 0) {
		goto error;
	}

	if (!lua_isfunction(L, -1)) {
		int type = lua_type(L, -1);
		REDEBUG("'%s' is not a function, is a %s (%i)", funcname, lua_typename(L, type), type);
		goto error;
	}

	if (lua_pcall(L, 0, 0, 0) != 0) {
		char const *msg = lua_tostring(L, -1);
		REDEBUG("Call to %s failed: %s", funcname, msg ? msg : "unknown error");
		goto error;
	}

	rlm_lua_release_interp(inst);
	return 0;

error:
	rlm_lua_release_interp(inst);
	return -1;
}
