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
	char buff[1024];

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
		fr_pair_value_snprint(buff, sizeof(buff), vp, '\0');
		lua_pushstring(L, buff);
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
		ERROR("Cannot convert %s to Lua type", fr_int2str(fr_value_box_type_table, vp->vp_type, "<INVALID>"));
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
	{
		fr_value_box_t	vb;

		/*
		 *	lua_tonumber actually returns ptrdiff_t
		 *	so we need to check if our input box
		 *	type is the same width or greater.
		 */
		static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_int64) >= sizeof(ptrdiff_t),
			      "fr_value_box_t field smaller than return from lua_tointeger");

		static_assert(SIZEOF_MEMBER(fr_value_box_t, vb_float64) >= sizeof(double),
			      "fr_value_box_t field smaller than return from lua_tonumber");

		switch (vp->da->type) {
		/*
		 *	Preserve decimal precision.
		 *
		 *	Our FR_TYPE_FLOAT64 is a double, which is apparently
		 *	what lua_tonumber returns on most platforms.
		 */
		case FR_TYPE_FLOAT32:
		case FR_TYPE_FLOAT64:
			fr_value_box_init(&vb, FR_TYPE_FLOAT64, NULL, true);
			vb.vb_float64 = lua_tonumber(L, -1);
			break;

		default:
			fr_value_box_init(&vb, FR_TYPE_INT64, NULL, true);
			vb.vb_int64 = lua_tointeger(L, -1);
			break;
		}


		if (fr_value_box_cast(vp, &vp->data, vp->da->type, vp->da, &vb) < 0) {
			RPEDEBUG("Failed unmarshalling Lua number for \"%s\"", vp->da->name);
			return -1;
		}
	}
		break;

	case LUA_TSTRING:
	{
		fr_value_box_t	vb;
		char const	*p;
		size_t		len;

		p = (char const *)lua_tolstring(L, -1, &len);
		if (!p) {
			REDEBUG("Unmarshalling failed, Lua bstring was NULL");
			return -1;
		}

		fr_value_box_bstrndup_shallow(&vb, NULL, p, len, true);

		if (fr_value_box_cast(vp, &vp->data, vp->da->type, vp->da, &vb) < 0) {
			RPEDEBUG("Failed unmarshalling Lua string for \"%s\"", vp->da->name);
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
			REDEBUG("Unmarshalling failed, can't determine length of user data");
			return -1;
		}
		p = lua_touserdata(L, -1);
		if (!p) {
			REDEBUG("Unmarshalling failed, user data was NULL");
		}
		fr_pair_value_memcpy(vp, p, len);
	}
		break;

	default:
	{
		int type = lua_type(L, -1);
		REDEBUG("Unmarshalling failed, unsupported Lua type %s (%i)", lua_typename(L, type), type);

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

/*
 * 	Initialise the table "fr." with all valid return codes.
 */
static int _lua_rcode_table_newindex(UNUSED lua_State *L)
{
	REQUEST *request = rlm_lua_request;

	RWDEBUG("You can't modify the table 'fr.*' (read-only)");

	return 1;
}

static int _lua_rcode_table_index(lua_State *L)
{
	char const *key = lua_tostring(L, -1);
	int ret;

	ret = fr_str2int(mod_rcode_table, key, -1);
	if (ret != -1) {
		lua_pushinteger(L, ret);
		return 1;
	}

	lua_pushfstring(L, "The fr.%s is not found", key);
	return -1;
}

static void rlm_lua_rcode_table_init(lua_State *L, char const *name)
{
	lua_newtable(L);
	luaL_newmetatable(L, name);

	lua_pushcfunction(L, _lua_rcode_table_index);
	lua_setfield(L, -2, "__index");

	lua_pushcfunction(L, _lua_rcode_table_newindex);
	lua_setfield(L, -2, "__newindex");

	lua_setmetatable(L, -2);
	lua_setglobal(L, name);
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
	if (lua_isnil(L, -1)) goto done;

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

	error:
		*out = NULL;

		lua_close(L);
		return -1;
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
}

/** Resolve a path string to a field value in Lua
 *
 * Parses a string in the format
 * @verbatim obj0[.obj1][.objN] @endverbatim, adding all tables it traverses
 * to the stack.
 *
 * All paths are assumed to start at a global, so the first field
 * will be looked up in the global table.
 *
 */
static int rlm_lua_get_field(lua_State *L, REQUEST *request, char const *field)
{
	char buff[512];
	char const *p = field, *q;

	q = strchr(p, '.');
	if (!q) {	/* No field, just global */
		lua_getglobal(L, p);
		if (lua_isnil(L, -1)) {
		does_not_exist:
			REMARKER(field, p - field, "Field does not exist");
			return -1;
		}
		return 0;
	}

	if ((size_t) (q - p) >= sizeof(buff)) {
	too_long:
		REDEBUG("Field name too long, expected < %zu, got %zu", q - p, sizeof(buff));
		return -1;
	}

	strlcpy(buff, p, (q - p) + 1);
	lua_getglobal(L, buff);
	if (lua_isnil(L, -1)) goto does_not_exist;
	p = q + 1;	/* Skip the '.' */

	while ((q = strchr(p, '.'))) {
		if ((size_t) (q - p) >= sizeof(buff)) goto too_long;

		strlcpy(buff, p, (q - p) + 1);
		lua_getfield(L, -1, buff);
		if (lua_isnil(L, -1)) goto does_not_exist;
		p = q + 1;
	}

	lua_getfield(L, -1, p);
	if (lua_isnil(L, -1)) goto does_not_exist;

	return 0;
}

int do_lua(rlm_lua_thread_t *thread, REQUEST *request, char const *funcname)
{
	fr_cursor_t cursor;
	lua_State *L = thread->interpreter;
	int ret = RLM_MODULE_OK;
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
	 *	Setup the "fr" global table. with all RLM_MODULE_* values. e.g: "fr.reject", "fr.ok", ...
	 */
	rlm_lua_rcode_table_init(L, "fr");

	/*
	 *	Get the function were going to be calling
	 */
	if (rlm_lua_get_field(L, request, funcname) < 0) {
error:
		return RLM_MODULE_FAIL;
	}

	if (!lua_isfunction(L, -1)) {
		int type = lua_type(L, -1);
		REDEBUG("'%s' is not a function, is a %s (%i)", funcname, lua_typename(L, type), type);
		goto error;
	}

	if (lua_pcall(L, 0, 1, 0) != 0) {
		char const *msg = lua_tostring(L, -1);
		REDEBUG("Call to %s failed: %s", funcname, msg ? msg : "unknown error");
		goto error;
	}

	/*
	 *	functions without return or returning none/nil will be RLM_MODULE_OK
	 */
	if (!lua_isnoneornil(L, -1)) {
		/*
		 *	e.g: return 2, return "2", return fr.handled, fr.fail, ...
		 */
		if (lua_isnumber(L, -1)) {
			ret = lua_tointeger(L, -1);
			if (fr_int2str(mod_rcode_table, ret, NULL) != NULL) goto done;
		}

		/*
		 *	e.g: return "handled", "ok", "fail", ...
		 */
		if (lua_isstring(L, -1)) {
			ret = fr_str2int(mod_rcode_table, lua_tostring(L, -1), -1);
			if (ret != -1) goto done;
		}

		REDEBUG("Lua function %s() returned invalid rcode \"%s\"", funcname, lua_tostring(L, -1));
		goto error;
	}

done:
	return ret;
}
