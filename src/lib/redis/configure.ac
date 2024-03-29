AC_PREREQ([2.71])
AC_INIT
AC_CONFIG_SRCDIR([redis.c])
AC_REVISION($Revision$)
FR_INIT_LIBRARY([libfreeradius-redis], [redis support])

SMART_LIBS=
SMART_CLFAGS=

FR_LIBRARY_START_TESTS

    dnl ############################################################
    dnl # Check for command line options
    dnl ############################################################

    dnl extra argument: --with-redis-include-dir=DIR
    redis_include_dir=
    AC_ARG_WITH(redis-include-dir,
	[AS_HELP_STRING([--with-redis-include-dir=DIR],
		[Directory where the redis includes may be found])],
	[case "$withval" in
	    no)
		AC_MSG_ERROR(Need redis-include-dir)
		;;
	    yes)
		;;
	    *)
		redis_include_dir="$withval"
		;;
	esac])

    dnl extra argument: --with-redis-lib-dir=DIR
    redis_lib_dir=
    AC_ARG_WITH(redis-lib-dir,
	[AS_HELP_STRING([--with-redis-lib-dir=DIR],
		[Directory where the redis libraries may be found])],
	[case "$withval" in
	    no)
		AC_MSG_ERROR(Need redis-lib-dir)
		;;
	    yes)
		;;
	    *)
		redis_lib_dir="$withval"
		;;
	esac])

    dnl extra argument: --with-redis-dir=DIR
    AC_ARG_WITH(redis-dir,
	[AS_HELP_STRING([--with-redis-dir=DIR],
		[Base directory where redis is installed])],
	[case "$withval" in
	    no)
		AC_MSG_ERROR(Need redis-dir)
		;;
	    yes)
		;;
	    *)
		redis_lib_dir="$withval/lib"
		redis_include_dir="$withval/include"
		;;
	esac])

    dnl ############################################################
    dnl # Check for programs
    dnl ############################################################

    AC_PROG_CC

    dnl #############################################################
    dnl # Library/include paths
    dnl #############################################################
    AX_WITH_LIB_ARGS_OPT([openssl],[yes])

    dnl ############################################################
    dnl # Check for header files
    dnl ############################################################

    smart_try_dir="${redis_include_dir}"
    FR_SMART_CHECK_INCLUDE([hiredis/hiredis.h])
    if test "x$ac_cv_header_hiredis_hiredis_h" != "xyes"; then
      AC_MSG_WARN([hiredis headers not found. Use --with-redis-include-dir=<path>.])
      fail="$fail hiredis.h"
    fi

    dnl ############################################################
    dnl # Check for libraries
    dnl ############################################################

    smart_try_dir="$redis_lib_dir"
    FR_SMART_CHECK_LIB(hiredis, redisConnect)
    if test "x$ac_cv_lib_hiredis_redisConnect" != "xyes"
    then
      AC_MSG_WARN([hiredis libraries not found. Use --with-redis-lib-dir=<path>.])
      fail="$fail libhiredis"
    fi

    smart_try_dir="$openssl_lib_dir"
    FR_SMART_CHECK_LIB(hiredis_ssl, redisCreateSSLContext)
    if test "x$ac_cv_lib_hiredis_ssl_redisCreateSSLContext" == "xyes"
    then
      AC_DEFINE([HAVE_REDIS_SSL],[1],[Build with SSL support])
    fi
FR_LIBRARY_END_TESTS

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
