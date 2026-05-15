AC_PREREQ([2.53])
AC_INIT(rlm_dotnet.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_dotnet])

AC_PROG_CC
AC_PROG_CPP

AC_ARG_WITH([]modname,
[  --with-[]modname              build []modname. (default=yes)])

dnl Optional paths for .NET SDK nethost (headers + libnethost.so).
dotnet_include_dir=
AC_ARG_WITH(dotnet-include-dir,
	[AS_HELP_STRING([--with-dotnet-include-dir=DIR],
		[Directory containing nethost.h (e.g. .../runtimes/linux-x64/native)])],
	[ case "$withval" in
	    no) AC_MSG_ERROR(Need dotnet-include-dir) ;;
	    yes) ;;
	    *) dotnet_include_dir="$withval" ;;
	  esac ])

dotnet_lib_dir=
AC_ARG_WITH(dotnet-lib-dir,
	[AS_HELP_STRING([--with-dotnet-lib-dir=DIR],
		[Directory containing libnethost.so])],
	[ case "$withval" in
	    no) AC_MSG_ERROR(Need dotnet-lib-dir) ;;
	    yes) ;;
	    *) dotnet_lib_dir="$withval" ;;
	  esac ])

if test x$with_[]modname != xno; then
	smart_try_dir=$dotnet_include_dir
	FR_SMART_CHECK_INCLUDE(nethost.h)
	if test "$ac_cv_header_nethost_h" != "yes"; then
		fail="$fail nethost.h"
	fi

	smart_try_dir=$dotnet_lib_dir
	FR_SMART_CHECK_LIB(nethost, get_hostfxr_path)
	if test "x$ac_cv_lib_nethost_get_hostfxr_path" != "xyes"; then
		fail="$fail libnethost"
	fi

	targetname=modname
else
	targetname=
	echo \*\*\* module modname is disabled.
fi

if test x"$fail" != x""; then
	if test x"${enable_strict_dependencies}" = "xyes"; then
		AC_MSG_ERROR([set --without-]modname[ to disable it explicitly.])
	else
		AC_MSG_WARN([silently not building ]modname[.])
		AC_MSG_WARN([FAILURE: ]modname[ requires: $fail.]);
		targetname=""
	fi
fi

mod_ldflags="${SMART_LIBS} -ldl -lpthread"
mod_cflags="${SMART_CPPFLAGS}"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_CONFIG_HEADER(config.h)

AC_SUBST(targetname)
AC_OUTPUT(all.mk)
