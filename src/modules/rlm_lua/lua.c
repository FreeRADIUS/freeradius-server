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
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @author Artur Malinowski (artur@wow.com)
 *
 * @copyright 2015 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

#define LOG_PREFIX mctx->mi->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include "config.h"
#include "lua.h"

#include <float.h>
#include <lauxlib.h>
#include <lualib.h>

#define RLM_LUA_STACK_SET()	int _fr_lua_stack_state = lua_gettop(L)
#define RLM_LUA_STACK_RESET()	lua_settop(L, _fr_lua_stack_state)

typedef struct fr_lua_pair_s fr_lua_pair_t;
struct fr_lua_pair_s {
	fr_dict_attr_t const	*da;
	fr_pair_t		*vp;
	unsigned int		idx;
	fr_lua_pair_t		*parent;
};

static void _lua_pair_init(lua_State *L, fr_pair_t *vp, fr_dict_attr_t const *da, unsigned int idx, fr_lua_pair_t *parent);

DIAG_OFF(type-limits)
/** Convert fr_pair_ts to Lua values
 *
 * Pushes a Lua representation of an attribute value onto the stack.
 *
 * @param[in] request	The current request.
 * @param[in] L		Lua interpreter.
 * @param[in] vp	to convert.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int fr_lua_marshall(request_t *request, lua_State *L, fr_pair_t const *vp)
{
	if (!vp) return -1;

#if PTRDIFF_MAX < INT64_MAX
#define IN_RANGE_INTEGER_SIGNED(_x) \
	do { \
		if ((((int64_t)(_x)) < PTRDIFF_MIN) || (((int64_t)(_x)) > PTRDIFF_MAX)) { \
			REDEBUG("Value (%" PRId64 ") cannot be represented as Lua integer.  Must be between %td-%td", \
				(int64_t)(_x), (ptrdiff_t)PTRDIFF_MIN, (ptrdiff_t)PTRDIFF_MAX); \
			return -1; \
		} \
	} while (0)

#define IN_RANGE_INTEGER_UNSIGNED(_x) \
	do { \
		if (((uint64_t)(_x)) > PTRDIFF_MAX) { \
			REDEBUG("Value (%" PRIu64 ") cannot be represented as Lua integer.  Must be between 0-%td", \
				(uint64_t)(_x), (ptrdiff_t)PTRDIFF_MAX); \
			return -1; \
		} \
	} while (0)
#else
#define IN_RANGE_INTEGER_SIGNED(_x) \
        do { \
        } while (0)

#define IN_RANGE_INTEGER_UNSIGNED(_x) \
        do { \
        } while (0)
#endif

#define IN_RANGE_FLOAT_SIGNED(_x) \
	do { \
		if ((((double)(_x)) < DBL_MIN) || (((double)(_x)) > DBL_MAX)) { \
			REDEBUG("Value (%f) cannot be represented as Lua number.  Must be between %f-%f", \
				(double)(_x), DBL_MIN, DBL_MAX); \
			return -1; \
		} \
	} while (0)

	switch (vp->vp_type) {
	case FR_TYPE_ETHERNET:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
	case FR_TYPE_IFID:
	case FR_TYPE_TIME_DELTA:
	{
		char	buff[128];
		ssize_t	slen;

		slen = fr_pair_print_value_quoted(&FR_SBUFF_OUT(buff, sizeof(buff)), vp, T_BARE_WORD);
		if (slen < 0) {
			REDEBUG("Cannot convert %s to Lua type, insufficient buffer space",
				fr_type_to_str(vp->vp_type));
			return -1;
		}

		lua_pushlstring(L, buff, (size_t)slen);
	}
		break;

	case FR_TYPE_STRING:
		lua_pushlstring(L, vp->vp_strvalue, vp->vp_length);
		break;

	case FR_TYPE_OCTETS:
		lua_pushlstring(L, (char const *)vp->vp_octets, vp->vp_length); /* lstring variant is embedded NULL safe */
		break;

	case FR_TYPE_BOOL:
		lua_pushinteger(L, (lua_Integer)(vp->vp_bool ? 1 : 0));
		break;

	case FR_TYPE_UINT8:
		lua_pushinteger(L, (lua_Integer)vp->vp_uint8);
		break;

	case FR_TYPE_UINT16:
		lua_pushinteger(L, (lua_Integer)vp->vp_uint16);
		break;

	case FR_TYPE_UINT32:
		lua_pushinteger(L, (lua_Integer)vp->vp_uint32);
		break;

	case FR_TYPE_UINT64:
		IN_RANGE_INTEGER_UNSIGNED(vp->vp_uint64);
		lua_pushinteger(L, (lua_Integer)vp->vp_uint64);
		break;

	case FR_TYPE_INT8:
		lua_pushinteger(L, (lua_Integer)vp->vp_int8);
		break;

	case FR_TYPE_INT16:
		lua_pushinteger(L, (lua_Integer)vp->vp_int16);
		break;

	case FR_TYPE_INT32:
		lua_pushinteger(L, (lua_Integer)vp->vp_int32);
		break;

	case FR_TYPE_INT64:
		IN_RANGE_INTEGER_SIGNED(vp->vp_int64);
		lua_pushinteger(L, (lua_Integer)vp->vp_int64);
		break;

	case FR_TYPE_DATE:
		lua_pushinteger(L, (lua_Integer) fr_unix_time_to_sec(vp->vp_date));
		break;

	case FR_TYPE_FLOAT32:
		IN_RANGE_FLOAT_SIGNED(vp->vp_float32);
		lua_pushnumber(L, (lua_Number)vp->vp_float32);
		break;

	case FR_TYPE_FLOAT64:
		IN_RANGE_FLOAT_SIGNED(vp->vp_float64);
		lua_pushnumber(L, (lua_Number)vp->vp_float64);
		break;

	case FR_TYPE_SIZE:
		IN_RANGE_INTEGER_UNSIGNED(vp->vp_size);
		lua_pushinteger(L, (lua_Integer)vp->vp_size);
		break;

	case FR_TYPE_NON_LEAF:
		REDEBUG("Cannot convert %s to Lua type", fr_type_to_str(vp->vp_type));
		return -1;
	}
	return 0;
}
DIAG_ON(type-limits)

/** Use Lua values to populate a fr_value_box_t
 *
 * Convert Lua values to fr_value_box_t.  How the Lua value is converted is dependent
 * on the type of the box.
 *
 * @param[in] ctx	To allocate new fr_pair_t in.
 * @param[out] out_vb	Value box to populate.
 * @param[in] request	the current request.
 * @param[in] L		Lua interpreter.
 * @param[in] da	specifying the type of attribute the box represent.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int fr_lua_unmarshall(TALLOC_CTX *ctx, fr_value_box_t *out_vb, request_t *request,
			     lua_State *L, fr_dict_attr_t const *da)
{
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

		switch (da->type) {
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


		if (fr_value_box_cast(ctx, out_vb, da->type, da, &vb) < 0) {
			RPEDEBUG("Failed unmarshalling Lua number for \"%s\"", da->name);
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

		if (fr_value_box_cast(ctx, out_vb, da->type, da, &vb) < 0) {
			RPEDEBUG("Failed unmarshalling Lua string for \"%s\"", da->name);
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
		fr_value_box_memdup(ctx, out_vb, da, p, len, true);
	}
		break;

	default:
	{
		int type = lua_type(L, -1);
		REDEBUG("Unmarshalling failed, unsupported Lua type %s (%i)", lua_typename(L, type), type);

		return -1;
	}
	}

	return 0;
}

/** Build parent structural pairs needed when a leaf node is set
 *
 */
static int fr_lua_pair_parent_build(request_t *request, fr_lua_pair_t *pair_data)
{
	if (!pair_data->parent->vp) {
		if (fr_lua_pair_parent_build(request, pair_data->parent) < 0) return -1;
	}
	if (pair_data->idx > 1) {
		unsigned int count = fr_pair_count_by_da(&pair_data->parent->vp->vp_group, pair_data->da);
		if (count < (pair_data->idx - 1)) {
			RERROR("Attempt to set instance %d when only %d exist", pair_data->idx, count);
			return -1;
		}
	}

	if (fr_pair_append_by_da(pair_data->parent->vp, &pair_data->vp,
				 &pair_data->parent->vp->vp_group, pair_data->da) < 0) return -1;
	return 0;
}

/** Set an instance of an attribute
 *
 * @note Should only be present in the Lua environment as a closure.
 * @note Takes one upvalue - the fr_lua_pair_t representing this pair as user data.
 * @note Is called as an __newindex metamethod, so takes the table (can be ignored),
 *	 the field (an integer index value) and the new value.
 *
 * @param[in] L Lua state.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _lua_pair_setter(lua_State *L)
{
	request_t		*request = fr_lua_util_get_request();
	fr_lua_pair_t		*pair_data, *parent;
	fr_dict_attr_t const	*da;
	fr_pair_t		*vp;
	lua_Integer		index;

	if (!lua_isnumber(L, -2)) {
		RERROR("Attempt to %s attribute \"%s\" table.", lua_isnil(L, -1) ? "delete" : "set value on", lua_tostring(L, -2));
		RWARN("Values should be manipulated using <list>['<attr>'][idx] = <value> where idx is the attribute instance (starting at 1)");
		return -1;
	}

	index = lua_tointeger(L, -2);
	if (index < 1) {
		RERROR("Invalid attribute index %ld", index);
		return -1;
	}

	pair_data = lua_touserdata(L, lua_upvalueindex(1));
	da = pair_data->da;

	if (!fr_type_is_leaf(da->type)) {
		RERROR("Values cannot be assigned to structural attribute \"%s\"", da->name);
		return -1;
	}
	parent = pair_data->parent;

	/*
	 *	If the value of the Lua stack was nil, we delete the attribute if it exists.
	 */
	if (lua_isnil(L, -1)) {
		if (!pair_data->parent->vp) return 0;
		vp = fr_pair_find_by_da_idx(&parent->vp->vp_group, da, index - 1);
		if (!vp) return 0;
		if (pair_data->vp == vp) pair_data->vp = NULL;
		fr_pair_delete(&parent->vp->vp_group, vp);
		return 0;
	}

	if (!parent->vp) {
		if (fr_lua_pair_parent_build(request, parent) < 0) return -1;
	}

	vp = fr_pair_find_by_da_idx(&parent->vp->vp_group, da, index - 1);

	/*
	 *	Asked to add a pair we don't have - check we're not being asked
	 *	to add a gap.
	 */
	if (!vp && (index > 1)) {
		unsigned int count = fr_pair_count_by_da(&parent->vp->vp_group, da);
		if (count < (index - 1)) {
			RERROR("Attempt to set instance %ld when only %d exist", index, count);
			return -1;
		}
	}

	if (!vp) {
		if (fr_pair_append_by_da(parent->vp, &vp, &parent->vp->vp_group, da) < 0) {
			RERROR("Failed to create attribute %s", da->name);
			return -1;
		}
	}
	if (fr_lua_unmarshall(vp, &vp->data, request, L, da) < 0) return -1;

	return 0;
}

/** Iterate over instances of a leaf attribute
 *
 * Each call returns with the value of the next instance of the attribute
 * on the Lua stack, or nil, when there are no more instances.
 *
 */
static int _lua_pair_iterator(lua_State *L)
{
	request_t	*request = fr_lua_util_get_request();
	fr_dcursor_t	*cursor;
	fr_pair_t	*vp;

	fr_assert(lua_isuserdata(L, lua_upvalueindex(1)));

	cursor = lua_touserdata(L, lua_upvalueindex(1));
	fr_assert(cursor);

	vp = fr_dcursor_current(cursor);
	if (!vp) {
		lua_pushnil(L);
		return 1;
	}

	if (fr_lua_marshall(request, L, vp) < 0) return -1;

	fr_dcursor_next(cursor);
	return 1;
}

/** Initiate an iterator to return all the values of a given attribute
 *
 */
static int _lua_pair_iterator_init(lua_State *L)
{
	request_t	*request = fr_lua_util_get_request();
	fr_dcursor_t	*cursor;
	fr_lua_pair_t	*pair_data;

	fr_assert(lua_isuserdata(L, lua_upvalueindex(1)));
	pair_data = lua_touserdata(L, lua_upvalueindex(1));
	fr_assert(pair_data);

	cursor = (fr_dcursor_t*) lua_newuserdata(L, sizeof(fr_dcursor_t));
	if (!cursor) {
		REDEBUG("Failed allocating user data to hold cursor");
		return -1;
	}
	fr_pair_dcursor_by_da_init(cursor, &pair_data->parent->vp->vp_group, pair_data->da);

	lua_pushcclosure(L, _lua_pair_iterator, 1);

	return 1;
}

/** Iterate over attributes in a list
 *
 * Each call returns with two values on the Lua stack
 *  - the name of the next attribute
 *  - the value of the next attribute, or an array of child attribute names
 *
 * or, nil is pushed to the stack when there are no more attributes in the list.
 */
static int _lua_list_iterator(lua_State *L)
{
	request_t	*request = fr_lua_util_get_request();
	fr_dcursor_t	*cursor;
	fr_pair_t	*vp;

	fr_assert(lua_isuserdata(L, lua_upvalueindex(1)));

	cursor = lua_touserdata(L, lua_upvalueindex(1));
	fr_assert(cursor);

	vp = fr_dcursor_current(cursor);
	if(!vp) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushstring(L, vp->da->name);

	/*
	 *	For structural attributes return an array of the child names
	 */
	if (fr_type_is_structural(vp->da->type)) {
		fr_pair_t	*child = NULL;
		unsigned int	i = 1;

		lua_createtable(L, fr_pair_list_num_elements(&vp->vp_group), 0);
		while ((child = fr_pair_list_next(&vp->vp_group, child))) {
			lua_pushstring(L, child->da->name);
			lua_rawseti(L, -2, i++);
		}
	} else {
		if (fr_lua_marshall(request, L, vp) < 0) return -1;
	}

	fr_dcursor_next(cursor);

	return 2;
}

/** Initialise a new structural iterator
 *
 */
static int _lua_list_iterator_init(lua_State *L)
{
	request_t	*request = fr_lua_util_get_request();
	fr_dcursor_t	*cursor;
	fr_lua_pair_t	*pair_data;

	fr_assert(lua_isuserdata(L, lua_upvalueindex(1)));
	pair_data = lua_touserdata(L, lua_upvalueindex(1));
	if (!pair_data->vp) return 0;

	cursor = (fr_dcursor_t*) lua_newuserdata(L, sizeof(fr_dcursor_t));
	if (!cursor) {
		REDEBUG("Failed allocating user data to hold cursor");
		return -1;
	}
	fr_pair_dcursor_init(cursor, &pair_data->vp->vp_group);

	lua_pushcclosure(L, _lua_list_iterator, 1);

	return 1;
}

/** Get an attribute or an instance of an attribute
 *
 * When called with a numeric index, it is the instance of the attribute
 * which is being requested.
 * Otherwise, the index is an attribute name.
 *
 * @note Should only be present in the Lua environment as a closure.
 * @note Takes one upvalue - the fr_lua_pair_t representing either this
 *	 attribute in the case it is an index being requested, or the
 *	 parent in the case an attribute is being requested.
 * @note Is called as an __index metamethod, so takes the table (can be ignored)
 *	 and the field (integer index for instance or string for attribute)
 *
 * @param[in] L Lua interpreter.
 * @return
 *	- -1 on failure.
 *	- 0 (no results) on success.
 *	- 1 on success with:
 *	  - the fr_pair_t value on the stack for leaf values.
 *	  - a lua table for structural items.
 */
static int _lua_pair_accessor(lua_State *L)
{
	request_t	*request = fr_lua_util_get_request();
	fr_lua_pair_t	*pair_data;
	fr_pair_t	*vp = NULL;

	fr_assert(lua_isuserdata(L, lua_upvalueindex(1)));

	pair_data = (fr_lua_pair_t *)lua_touserdata(L, lua_upvalueindex(1));

	if (lua_isnumber(L, -1)) {
		lua_Integer	index = lua_tointeger(L, -1);

		if (index < 1) {
			RERROR("Invalid attribute index %ld", index);
			return -1;
		}

		if (!pair_data->parent || !pair_data->parent->vp) return 0;

		if (index == 1 && pair_data->vp) {
			vp = pair_data->vp;
		} else {
			// Lua array indexes are 1 based, not 0 based.
			vp = fr_pair_find_by_da_idx(&pair_data->parent->vp->vp_group, pair_data->da, index - 1);
			if (index == 1) pair_data->vp = vp;
		}
		/*
		 *	Retrieving an instance of a leaf gives the actual attribute
		 *	value (if it exists)
		 */
		if (fr_type_is_leaf(pair_data->da->type)) {
			if (!vp) return 0;
			if (fr_lua_marshall(request, L, vp) < 0) return -1;
			return 1;
		}

		fr_assert(fr_type_is_structural(pair_data->da->type));

		/*
		 *	Retrieving a structural attribute returns a new table.
		 */
		lua_newtable(L);
		_lua_pair_init(L, vp, pair_data->da, index, pair_data->parent);

	} else {
		fr_dict_attr_t const	*da;
		char const		*attr = lua_tostring(L, -1);

		if (!attr) {
			RERROR("Failed retrieving field name from lua stack");
			return -1;
		}

		da = fr_dict_attr_by_name(NULL, pair_data->da, attr);

		/*
		 *	Allow fallback to internal attributes if the parent is a group or dictionary root.
		 */
		if (!da && (fr_type_is_group(pair_data->da->type) || pair_data->da->flags.is_root)) {
			da = fr_dict_attr_by_name(NULL, fr_dict_root(fr_dict_internal()), attr);
		}

		if (!da) {
			RERROR("Unknown or invalid attribute name \"%s\"", attr);
			return -1;
		}

		if (pair_data->vp) vp = fr_pair_find_by_da(&pair_data->vp->vp_group, NULL, da);
		_lua_pair_init(L, vp, da, 1, pair_data);

		lua_rawset(L, -3);		/* Cache the attribute manipulation object */
		lua_getfield(L, -1, attr);	/* and return it */
	}

	return 1;
}

/** Check whether the Lua interpreter were actually linked to is LuaJIT
 *
 * @param L Lua interpreter.
 * @return true if were running with LuaJIT else false.
 */
bool fr_lua_isjit(lua_State *L)
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

char const *fr_lua_version(lua_State *L)
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
 * @param[in] mctx 		module instantiation data.
 * @param[in] L			the lua state.
 * @param[in] name		of function to check.
 * @returns 0 on success (function is present and correct), or -1 on failure.
 */
int fr_lua_check_func(module_inst_ctx_t const *mctx, lua_State *L, char const *name)
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
		ERROR("Function \"%s\" not found ", name);
		ret = -1;
		goto done;

	default:
		ERROR("Value found at index \"%s\" is not a function (is a %s)", name, lua_typename(L, type));
		ret = -1;
		goto done;
	}
	ret = 0;
done:
	RLM_LUA_STACK_RESET();
	return ret;
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
static int fr_lua_get_field(module_ctx_t const *mctx, lua_State *L, request_t *request, char const *field)
{
	char buff[512];
	char const *p = field, *q;

	q = strchr(p, '.');
	if (!q) {	/* No field, just global */
		lua_getglobal(L, p);
		if (lua_isnil(L, -1)) {
		does_not_exist:
			if (request) {
				REMARKER(field, p - field, "Field does not exist");
			} else {
				EMARKER(field, p - field, "Field does not exist");
			}
			return -1;
		}
		return 0;
	}

	if ((size_t) (q - p) >= sizeof(buff)) {
	too_long:
		ROPTIONAL(REDEBUG, ERROR, "Field name too long, expected < %zu, got %zu", q - p, sizeof(buff));
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

/** Initialise a table representing a pair
 *
 * After calling this function, a new table will be on the lua stack which represents the pair.
 *
 * The pair may not exist - e.g. when setting a new nested attribute, parent pairs may not
 * have been created yet.  In that case, this holds the da and index of the instance which
 * will be created when the leaf is assigned a value.
 *
 * @param[in] L		the lua state
 * @param[in] vp	the actual pair instance being represented, if it already exists
 * @param[in] da	dictionary attribute for this pair
 * @param[in] idx	index of the attribute instance (starting at 1)
 * @param[in] parent	lua userdata for the parent of this attribute.
 */
static void _lua_pair_init(lua_State *L, fr_pair_t *vp, fr_dict_attr_t const *da, unsigned int idx, fr_lua_pair_t *parent)
{
	fr_lua_pair_t	*pair_data;

	lua_newtable(L);

	/*
	 *	The userdata associated with the meta functions
	 *	__index and __newindex, and the .pairs() field.
	 */
	pair_data = lua_newuserdata(L, sizeof(fr_lua_pair_t));
	*pair_data = (fr_lua_pair_t) {
		.da = da,
		.idx = idx,
		.vp = vp,
		.parent = parent
	};
	if (fr_type_is_structural(da->type)) {
		lua_pushcclosure(L, _lua_list_iterator_init, 1);
	} else {
		lua_pushcclosure(L, _lua_pair_iterator_init, 1);
	}
	lua_setfield(L, -2, "pairs");

	lua_newtable(L);	/* Metatable for index functions*/

	lua_pushlightuserdata(L, pair_data);
	lua_pushcclosure(L, _lua_pair_accessor, 1);
	lua_setfield(L, -2, "__index");

	lua_pushlightuserdata(L, pair_data);
	lua_pushcclosure(L, _lua_pair_setter, 1);
	lua_setfield(L, -2, "__newindex");
	lua_setmetatable(L, -2);
}

static void _lua_fr_request_register(lua_State *L, request_t *request)
{
	/* fr = {} */
	lua_getglobal(L, "fr");
	luaL_checktype(L, -1, LUA_TTABLE);

	/* fr = { request {} } */
	lua_pushstring(L, "request");
	_lua_pair_init(L, fr_pair_list_parent(&request->request_pairs), fr_dict_root(request->proto_dict), 1, NULL);
	lua_rawset(L, -3);

	lua_pushstring(L, "reply");
	_lua_pair_init(L, fr_pair_list_parent(&request->reply_pairs), fr_dict_root(request->proto_dict), 1, NULL);
	lua_rawset(L, -3);

	lua_pushstring(L, "control");
	_lua_pair_init(L, fr_pair_list_parent(&request->control_pairs), fr_dict_root(request->proto_dict), 1, NULL);
	lua_rawset(L, -3);

	lua_pushstring(L, "session-state");
	_lua_pair_init(L, fr_pair_list_parent(&request->session_state_pairs), fr_dict_root(request->proto_dict), 1, NULL);
	lua_rawset(L, -3);
}

unlang_action_t fr_lua_run(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request, char const *funcname)
{
	rlm_lua_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_lua_thread_t);
	lua_State		*L = thread->interpreter;
	rlm_rcode_t		rcode = RLM_MODULE_OK;

	fr_lua_util_set_mctx(mctx);
	fr_lua_util_set_request(request);

	ROPTIONAL(RDEBUG2, DEBUG2, "Calling %s() in interpreter %p", funcname, L);

	if (request) _lua_fr_request_register(L, request);

	/*
	 *	Get the function were going to be calling
	 */
	if (fr_lua_get_field(mctx, L, request, funcname) < 0) {
error:
		fr_lua_util_set_mctx(NULL);
		fr_lua_util_set_request(NULL);

		RETURN_MODULE_FAIL;
	}

	if (!lua_isfunction(L, -1)) {
		int type = lua_type(L, -1);

		ROPTIONAL(RDEBUG2, DEBUG2, "'%s' is not a function, is a %s (%i)", funcname, lua_typename(L, type), type);
		goto error;
	}

	if (lua_pcall(L, 0, 1, 0) != 0) {
		char const *msg = lua_tostring(L, -1);

		ROPTIONAL(RDEBUG2, DEBUG2, "Call to %s failed: %s", funcname, msg ? msg : "unknown error");
		goto error;
	}

	/*
	 *	functions without rcodeurn or rcodeurning none/nil will be RLM_MODULE_OK
	 */
	if (!lua_isnoneornil(L, -1)) {
		/*
		 *	e.g: rcodeurn 2, rcodeurn "2", rcodeurn fr.handled, fr.fail, ...
		 */
		if (lua_isnumber(L, -1)) {
			rcode = lua_tointeger(L, -1);
			if (fr_table_str_by_value(rcode_table, rcode, NULL) != NULL) goto done;
		}

		/*
		 *	e.g: rcodeurn "handled", "ok", "fail", ...
		 */
		if (lua_isstring(L, -1)) {
			rcode = fr_table_value_by_str(rcode_table, lua_tostring(L, -1), -1);
			if ((int)rcode != -1) goto done;
		}

		ROPTIONAL(RDEBUG2, DEBUG2, "Lua function %s() rcodeurned invalid rcode \"%s\"", funcname, lua_tostring(L, -1));
		goto error;
	}

done:
	fr_lua_util_set_mctx(NULL);
	fr_lua_util_set_request(NULL);

	RETURN_MODULE_RCODE(rcode);
}

/*
 * 	Initialise the table "fr." with all valid return codes.
 */
static int _lua_rcode_table_newindex(UNUSED lua_State *L)
{
	request_t	*request = fr_lua_util_get_request();

	RWDEBUG("You can't modify the table 'fr.rcode.{}' (read-only)");

	return 1;
}

static int _lua_rcode_table_index(lua_State *L)
{
	char const *key = lua_tostring(L, -1);
	int ret;

	ret = fr_table_value_by_str(rcode_table, key, -1);
	if (ret != -1) {
		lua_pushinteger(L, ret);
		return 1;
	}

	lua_pushfstring(L, "The fr.rcode.%s is not found", key);
	return -1;
}

/*
 *	As can be seen in http://luajit.org/extensions.html, the pairs() is disabled by default.
 *	ps: We add pairs() method just to inform the user that it does not work.
 */
static int _lua_rcode_table_pairs(lua_State *L)
{
	lua_pushfstring(L, "The pairs(fr.rcode) is not available. Access directly! e.g: 'fr.rcode.reject'");
	return -1;
}

static void fr_lua_rcode_register(lua_State *L, char const *name)
{
	const luaL_Reg metatable[] = {
		{ "__index",    _lua_rcode_table_index },
		{ "__newindex", _lua_rcode_table_newindex },
		{ "__pairs",    _lua_rcode_table_pairs },
#ifdef HAVE_LUAJIT_H
		{ "pairs",      _lua_rcode_table_pairs },
#endif
		{ NULL, NULL }
	};

	/* fr = {} */
	lua_getglobal(L, "fr");
	luaL_checktype(L, -1, LUA_TTABLE);

	/* fr = { rcode = {} } */
	lua_newtable(L);
	{
		luaL_register(L, name, metatable);
		lua_setmetatable(L, -2);
		lua_setfield(L, -2, name);
	}
}

/** Initialise a new Lua/LuaJIT interpreter
 *
 * Creates a new lua_State and verifies all required functions have been loaded correctly.
 *
 * @param[in] out	Where to write a pointer to the new state.
 * @param[in] mctx	configuration data for the
 * @return 0 on success else -1.
 */
int fr_lua_init(lua_State **out, module_inst_ctx_t const *mctx)
{
	rlm_lua_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_lua_t);
	lua_State		*L;

	fr_lua_util_set_mctx(MODULE_CTX_FROM_INST(mctx));

	L = luaL_newstate();
	if (!L) {
		ERROR("Failed initialising Lua state");
		return -1;
	}

	luaL_openlibs(L);

	/*
	 *	Load the Lua file into our environment.
	 */
	if (luaL_loadfile(L, inst->module) != 0) {
		ERROR("Failed loading file: %s", lua_gettop(L) ? lua_tostring(L, -1) : "Unknown error");

	error:
		*out = NULL;
		fr_lua_util_set_mctx(NULL);
		lua_close(L);
		return -1;
	}

	if (lua_pcall(L, 0, LUA_MULTRET, 0) != 0) {
		ERROR("Failed executing script: %s", lua_gettop(L) ? lua_tostring(L, -1) : "Unknown error");

		goto error;
	}

	/*
	 * 	Setup "fr.{}"
	 */
	fr_lua_util_fr_register(L);

	/*
	 *	Setup "fr.log.{}"
	 */
	if (inst->jit) {
		DEBUG4("Initialised new LuaJIT interpreter %p", L);
		if (fr_lua_util_jit_log_register(L) < 0) goto error;
	} else {
		DEBUG4("Initialised new Lua interpreter %p", L);
		if (fr_lua_util_log_register(L) < 0) goto error;
	}

	/*
	 *	Setup the "fr.rcode.{}"  with all RLM_MODULE_*
	 * 	e.g: "fr.rcode.reject", "fr.rcode.ok", ...
	 */
	fr_lua_rcode_register(L, "rcode");

	/*
	 *	Verify all the functions were provided.
	 */
	if (fr_lua_check_func(mctx, L, inst->func_instantiate)
	    || fr_lua_check_func(mctx, L, inst->func_detach)
	    || fr_lua_check_func(mctx, L, inst->func_xlat)) {
	 	goto error;
	}

	*out = L;
	return 0;
}
