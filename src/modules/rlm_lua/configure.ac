AC_PREREQ([2.53])
AC_INIT(rlm_lua.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_lua])
m4_include([m4/ax_lua.m4])

AC_ARG_WITH([]modname,
[AS_HELP_STRING([--without-[]modname],[build without module])]
)

if test x$with_[]modname != xno; then
	AC_PROG_CC
	AC_PROG_CPP

	dnl extra argument: --with-lua-include-dir=DIR
	AC_ARG_WITH(lua-include-dir,
		[AS_HELP_STRING([--with-lua-include-dir=DIR],
		[Directory where the lua includes may be found])],
		[case "$withval" in
		    no)
			AC_MSG_ERROR(Need lua-include-dir)
		    ;;
		    yes)
		    ;;
		    *)
		        lua_include_dir="$withval"
		    ;;
		esac])

	if test "x$lua_include_dir" != "x"; then
		LUA_INCLUDE="-I$lua_include_dir"
	fi

	dnl extra argument: --with-lua-lib-dir=DIR
	AC_ARG_WITH(lua-lib-dir,
	[AS_HELP_STRING([--with-lua-lib-dir=DIR],
		[Directory where the lua libraries may be found])],
		[case "$withval" in
		    no)
			AC_MSG_ERROR(Need lua-lib-dir)
			;;
		    yes)
			;;
		    *)
			lua_lib_dir="$withval"
			;;
		esac])

	if test "x$lua_lib_dir" != "x"; then
		LDFLAGS="-L$lua_lib_dir"
	fi

	dnl #
	dnl # This is the version of Lua we expect to be returned by the Lua headers/Lua libs
	dnl #
	LUA_COMPAT_VERSION=5.1

	dnl #
	dnl # First look in the directory structure for LuaJIT 2.0
	dnl #
	LUA_VERSION=jit-2.0
	AX_LUA_HEADERS
	dnl #
	dnl # ... then fall back to standard Lua if we can't find LuaJIT
	dnl #
	if test "x$ac_cv_header_lua_h" = "xno"; then
		LUA_VERSION=5.2
		AX_LUA_HEADERS
	fi

	if test "x$ac_cv_header_lua_h" = "xno"; then
		fail="lua.h"
	else
		if test "x$ax_header_version_match" = "xno"; then
			fail="lua.h version"
		else
			AC_CACHE_CHECK([ldflags], [_cv_lua_ldflags],
			[
			if test "x$ac_cv_header_luajit_h" = "xno"; then
				AC_MSG_NOTICE([Falling back to Lua 5.2, for optimal performance rebuild with LuaJIT 2.x.x])
			else
				AC_MSG_NOTICE([Found LuaJIT headers, module will perform optimally])
				LUA_VERSION=jit-5.1
			fi

			AX_LUA_LIBS
			if test "x$_ax_found_lua_libs" = 'xno' && test "x$lua_lib_dir" = "x"; then
				AS_UNSET([ac_cv_search_dlopen])
				AS_UNSET([ac_cv_search_exp])
				AS_UNSET([ac_cv_search_lua_load])

				LDFLAGS="-L/usr/local/lib/"
				AX_LUA_LIBS
			fi

			if test "x$_ax_found_lua_libs" != 'xyes'; then
				fail="Lua libs"
			fi
			_cv_lua_ldflags="$LUA_LIB $LDFLAGS"
			])
		fi
	fi

	lua_cflags="$LUA_INCLUDE"
	lua_ldflags="$_cv_lua_ldflags"

	if test "x$_ax_found_lua_libs" = 'xyes'; then
		AC_MSG_NOTICE([Lua Library:])
		AC_MSG_NOTICE([  Using Lua version.......... : $ax_cv_lua_version])
		AC_MSG_NOTICE([  Using Lua header version... : $ax_cv_lua_header_version])
		AC_MSG_NOTICE([  Using Lua headers.......... : $lua_cflags])
		AC_MSG_NOTICE([  Using Lua lib.............. : $lua_ldflags])
	fi


	targetname=modname     # keep this!  Don't change!
else
	targetname=            # keep this!  Don't change!
	echo \*\*\* module modname is disabled.  # keep this!  Don't change!
fi

dnl  Don't change this section.
if test x"$fail" != x""; then
	if test x"${enable_strict_dependencies}" = x"yes"; then
		AC_MSG_ERROR([set --without-]modname[ to disable it explicitly.])
	else
		AC_MSG_WARN([silently not building ]modname[.])
		AC_MSG_WARN([FAILURE: ]modname[ requires: $fail.]);
		targetname=""
	fi
fi

AC_SUBST(lua_cflags)
AC_SUBST(lua_ldflags)


AC_SUBST(targetname)  # keep this!  Don't change!
AC_CONFIG_HEADER(config.h)
AC_OUTPUT([all.mk rlm_lua.mk libfreeradius-lua.mk])  # keep this!  Don't change!

