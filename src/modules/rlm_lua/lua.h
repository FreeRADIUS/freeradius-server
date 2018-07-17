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

#ifndef HAVE_PTHREAD_H
#define pthread_mutex_lock(_x)
#define pthread_mutex_unlock(_x)
#endif

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_lua {
	lua_State	*interpreter;		//!< Interpreter used for single threaded mode, and environment tests.
	bool 		threads;		//!< Whether to create new interpreters on a per-instance/per-thread
						//!< basis, or use a single mutex protected interpreter.

#ifdef HAVE_PTHREAD_H
	pthread_key_t	key;			//!< Key to access the thread local and instance specific interpreter.
	pthread_mutex_t	*mutex;			//!< Mutex used to protect interpreter, when running with a single
						//!< interpreter (threads = no).
#endif
	bool 		jit;			//!< Whether the linked interpreter is Lua 5.1 or LuaJIT.
	const char	*xlat_name;		//!< Name of this instance.
	const char 	*module;		//!< Full path to lua script to load and execute.

	const char	*func_instantiate;	//!< Name of function to run on instantiation.
	const char	*func_detach;		//!< Name of function to run on detach.

	const char	*func_authorize;	//!< Name of function to run on authorization.
	const char	*func_authenticate;	//!< Name of function to run on authentication.
#ifdef WITH_ACCOUNTING
	const char	*func_preacct;		//!< Name of function to run on preacct.
	const char	*func_accounting;	//!< Name of function to run on accounting.
#endif
	const char	*func_checksimul;	//!< Name of function to check for simultaneous use.
#ifdef WITH_PROXY
	const char	*func_pre_proxy;	//!< Name of function to run before proxying.
	const char	*func_post_proxy;	//!< Name of function to run after proxying.
#endif
	const char	*func_post_auth;	//!< Name of function to run after authentication.
#ifdef WITH_COA
	const char	*func_recv_coa;		//!< Name of function to run when receiving a CoA request.
	const char	*func_send_coa;		//!< Name of function to run when sending a CoA response.
#endif
	const char	*func_xlat;		//!< Name of function to be called for string expansions.
} rlm_lua_t;

/* lua.c */
int rlm_lua_init(lua_State **out, rlm_lua_t const *instance);
int do_lua(rlm_lua_t const *inst, REQUEST *request, char const *funcname);
bool rlm_lua_isjit(lua_State *L);
char const *rlm_lua_version(lua_State *L);

/* aux.c */
int aux_jit_funcs_register(rlm_lua_t const *inst, lua_State *L);
int aux_funcs_register(rlm_lua_t const *inst, lua_State *L);
