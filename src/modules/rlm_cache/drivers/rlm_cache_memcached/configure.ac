AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_cache_memcached.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_cache_memcached])

FR_MODULE_START_TESTS

AC_PROG_CC
AC_PROG_CPP

dnl ############################################################
dnl # Check for libmemcached
dnl ############################################################

dnl extra argument: --with-libmemcached-include-dir=DIR
libmemcached_include_dir=
AC_ARG_WITH(libmemcached-include-dir,
	[AS_HELP_STRING([--with-libmemcached-include-dir=DIR],
	[Directory where the libmemcached includes may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need libmemcached-include-dir)
		;;
	yes)
		;;
	*)
		libmemcached_include_dir="$withval"
		;;
	esac])

dnl extra argument: --with-libmemcached-lib-dir=DIR
libmemcached_lib_dir=
AC_ARG_WITH(libmemcached-lib-dir,
[AS_HELP_STRING([--with-libmemcached-lib-dir=DIR],
	[Directory where the libmemcached libraries may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need libmemcached-lib-dir)
		;;
	yes)
		;;
	*)
		libmemcached_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-libmemcached-dir=DIR
AC_ARG_WITH(libmemcached-dir,
[AS_HELP_STRING([--with-libmemcached-dir=DIR],
	[Base directory where libmemcached is installed])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need libmemcached-dir)
		;;
	yes)
		;;
	*)
		libmemcached_lib_dir="$withval/lib"
		libmemcached_include_dir="$withval/include"
		;;
	esac])


dnl ############################################################
dnl # Check for libmemcached header files
dnl ############################################################

smart_try_dir="$libmemcached_include_dir"
FR_SMART_CHECK_INCLUDE([libmemcached/memcached.h])
if test "x$ac_cv_header_libmemcached_memcached_h" != "xyes"; then
	AC_MSG_WARN([libmemcached headers not found. Use --with-libmemcached-include-dir=<path>.])
	FR_MODULE_FAIL([memcached.h])
fi

dnl ############################################################
dnl # Check for libmemcached libraries
dnl ############################################################

dnl # Check if libpthread is available. Should add -lpthread
dnl # to CFLAGS when checking for memcached.
FR_SMART_CHECK_LIB([pthread], [pthread_once])

smart_try_dir="$libmemcached_lib_dir"
dnl # Use a libmemcached specific function which is only
dnl # available in newer versions.
FR_SMART_CHECK_LIB([memcached], [memcached])
if test "x$ac_cv_lib_memcached_memcached" != "xyes"
then
	AC_MSG_WARN([libmemcached libraries not found. Use --with-libmemcached-lib-dir=<path>.])
	FR_MODULE_FAIL([libmemcached])
else
	AC_CHECK_FUNCS(\
		memcached \
		memcached_free \
		memcached_get \
		memcached_set \
		memcached_delete \
		libmemcached_check_configuration \
	,[], [
		FR_MODULE_FAIL([memached functions])
	])
fi


FR_MODULE_END_TESTS

mod_ldflags="$LIBCURL $SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
