AC_PREREQ([2.53])
AC_INIT(rlm_lua.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_lua])
m4_include([m4/ax_lua.m4])

if test x$with_[]modname != xno; then
	AC_PROG_CC
	AC_PROG_CPP
	AC_PROG_SED

	LUA_VERSION="5.2"

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
		LUA_LIB="-L$lua_lib_dir -llua${LUA_VERSION}"
	fi

	dnl
	dnl Not specified? then use the m4/ax_lua
	dnl
	if test "x$LUA_LIB" = "x" -a "x$LUA_INCLUDE" = "x"; then
		_LUA_VERSIONS="jit-2.1 5.3 5.2 5.1"

		for _v in ${_LUA_VERSIONS}; do
			AS_UNSET([ac_cv_search_dlopen])
			AS_UNSET([ac_cv_search_exp])
			AS_UNSET([ac_cv_search_lua_load])

			echo "Looking for Lua $_v"
			LUA_VERSION="$_v"

			AX_PROG_LUA
			AX_LUA_LIBS(have_lua_libs="yes", have_lua_libs="no")
			AX_LUA_HEADERS(have_lua_headers="yes", have_lua_headers="no")
		
			if test "x$have_lua_libs" = "xyes" -a "x$have_lua_headers" = "xyes"; then
				LUA_INCLUDE="$ac_cv_lua_include -DLUA_COMPAT_ALL"
				LUA_LIB="$ac_cv_search_lua_load"

				# luajit has different lib name.
				if test "x$ac_cv_header_luajit_h" = "xyes"; then
					LUA_LIB="-lluajit-${ax_cv_lua_header_version}"
				fi

				break
			fi
		done
	fi

	lua_cflags="$LUA_INCLUDE"
	lua_ldflags="$LUA_LIB"

	if test x"$lua_cflags" = "x" -o "x$lua_ldflags" = "x"; then
		AC_MSG_ERROR([We did not found Lua $LUA_VERSION support])
	fi

	echo
	echo "Lua Library:"
	echo "   Using Lua version.......... : $LUA_VERSION"
	echo "   Using Lua headers.......... : $lua_cflags"
	echo "   Using Lua lib.............. : $lua_ldflags"
	echo

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
