AC_INIT(rlm_mschap.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_mschap])

if test x$with_[]modname != xno; then

    AC_PROG_CC
    AC_PROG_CPP

    dnl ############################################################
    dnl # Check for command line options
    dnl ############################################################

    dnl extra argument: --with-winbind-include-dir=DIR
    winbind_include_dir=
    AC_ARG_WITH(winbind-include-dir,
	[AS_HELP_STRING([--with-winbind-include-dir=DIR],
		[Directory where the winbind includes may be found])],
	[case "$withval" in
	    no)
		AC_MSG_ERROR(Need winbind-include-dir)
		;;
	    yes)
		;;
	    *)
		winbind_include_dir="$withval"
		;;
	esac])

    dnl extra argument: --with-winbind-lib-dir=DIR
    winbind_lib_dir=
    AC_ARG_WITH(winbind-lib-dir,
	[AS_HELP_STRING([--with-winbind-lib-dir=DIR],
		[Directory where the winbind libraries may be found])],
	[case "$withval" in
	    no)
		AC_MSG_ERROR(Need winbind-lib-dir)
		;;
	    yes)
		;;
	    *)
		winbind_lib_dir="$withval"
		;;
	esac])

    dnl extra argument: --with-winbind-dir=DIR
    AC_ARG_WITH(winbind-dir,
	[AS_HELP_STRING([--with-winbind-dir=DIR],
		[Base directory where winbind is installed])],
	[case "$withval" in
	    no)
		AC_MSG_ERROR(Need winbind-dir)
		;;
	    yes)
		;;
	    *)
		winbind_lib_dir="$withval/lib"
		winbind_include_dir="$withval/include"
		;;
	esac])


    dnl ############################################################
    dnl # Check for header files
    dnl ############################################################

    mschap_sources=
    FR_SMART_CHECK_INCLUDE(membership.h)
    if test "x$ac_cv_header_membership_h" = "xyes"; then
        AC_DEFINE([HAVE_MEMBERSHIP_H],[1],[Build with Apple Open Directory support])
        mschap_sources="$mschap_sources opendir.c"
        mod_ldflags="-framework DirectoryService"
    fi

    smart_try_dir="$winbind_include_dir /usr/include/samba-4.0"
    FR_SMART_CHECK_INCLUDE(wbclient.h, [#include <stdint.h>
					#include <stdbool.h>])
    if test "x$ac_cv_header_wbclient_h" != "xyes"; then
        AC_MSG_WARN([wbclient.h not found. Use --with-winbind-include-dir=<path>.])
        AC_MSG_WARN([silently building without support for direct authentication via winbind. requires: libwbclient])
    fi

    FR_SMART_CHECK_INCLUDE(core/ntstatus.h, [#include <stdint.h>
					     #include <stdbool.h>])
    if test "x$ac_cv_header_core_ntstatus_h" != "xyes"; then
        AC_MSG_WARN([core/ntstatus.h not found. Use --with-winbind-include-dir=<path>.])
        AC_MSG_WARN([silently building without support for direct authentication via winbind. requires: libwbclient])
    fi

    dnl ############################################################
    dnl # Check for libraries
    dnl ############################################################

    if test "x$ac_cv_header_wbclient_h" = "xyes" && \
       test "x$ac_cv_header_core_ntstatus_h" = "xyes"; then

      smart_try_dir="$winbind_lib_dir"
      FR_SMART_CHECK_LIB(wbclient, wbcCtxAuthenticateUserEx)
      if test "x$ac_cv_lib_wbclient_wbcCtxAuthenticateUserEx" != "xyes"; then
        AC_MSG_WARN([winbind libraries not found. Use --with-winbind-lib-dir=<path>.])
        AC_MSG_WARN([Samba must be version 4.2.1 or higher to use this feature.])
      else
        mschap_sources="$mschap_sources auth_wbclient.c"
        AC_DEFINE([WITH_AUTH_WINBIND],[1],[Build with direct winbind auth support])
      fi
    fi

    targetname=modname
else
    targetname=
    echo \*\*\* module modname is disabled.
fi

if test x"$fail" != x""; then
	if test x"${enable_strict_dependencies}" = x"yes"; then
		AC_MSG_ERROR([set --without-]modname[ to disable it explicitly.])
	else
		AC_MSG_WARN([silently not building ]modname[.])
		AC_MSG_WARN([FAILURE: ]modname[ requires: $fail.]);
		targetname=""
	fi
fi

mod_ldflags="$mod_ldflags $SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"
AC_SUBST(mschap_sources)
AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)
AC_SUBST(targetname)

AC_CONFIG_HEADER(config.h)
AC_OUTPUT(rlm_mschap.mk)

