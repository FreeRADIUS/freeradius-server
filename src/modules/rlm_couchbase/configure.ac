AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_couchbase.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_couchbase], [couchbase database support])

FR_MODULE_START_TESTS

AC_PROG_CC
AC_PROG_CPP

dnl ############################################################
dnl # Check for libcouchbase
dnl ############################################################

dnl extra argument: --with-libcouchbase-include-dir=DIR
libcouchbase_include_dir=
AC_ARG_WITH(libcouchbase-include-dir,
	[AS_HELP_STRING([--with-libcouchbase-include-dir=DIR],
	[Directory where the libcouchbase includes may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need libcouchbase-include-dir)
		;;
	yes)
		;;
	*)
		libcouchbase_include_dir="$withval"
		;;
	esac])

dnl extra argument: --with-libcouchbase-lib-dir=DIR
libcouchbase_lib_dir=
AC_ARG_WITH(libcouchbase-lib-dir,
[AS_HELP_STRING([--with-libcouchbase-lib-dir=DIR],
	[Directory where the libcouchbase libraries may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need libcouchbase-lib-dir)
		;;
	yes)
		;;
	*)
		libcouchbase_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-libcouchbase-dir=DIR
AC_ARG_WITH(libcouchbase-dir,
[AS_HELP_STRING([--with-libcouchbase-dir=DIR],
	[Base directory where libcouchbase is installed])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need libcouchbase-dir)
		;;
	yes)
		;;
	*)
		libcouchbase_lib_dir="$withval/lib"
		libcouchbase_include_dir="$withval/include"
		;;
	esac])

dnl ############################################################
dnl # Check for libcouchbase header files
dnl ############################################################

smart_try_dir="$libcouchbase_include_dir"
FR_SMART_CHECK_INCLUDE([libcouchbase/couchbase.h])
if test "x$ac_cv_header_libcouchbase_couchbase_h" != "xyes"; then
	AC_MSG_WARN([libcouchbase headers not found. Use --with-libcouchbase-include-dir=<path>.])
        FR_MODULE_FAIL([couchbase.h])
fi

dnl ############################################################
dnl # Check for libcouchbase libraries
dnl ############################################################

smart_try_dir="$libcouchbase_lib_dir"
FR_SMART_CHECK_LIB([couchbase], [lcb_get_version])
if test "x$ac_cv_lib_couchbase_lcb_get_version" != "xyes"; then
	AC_MSG_WARN([libcouchbase libraries not found. Use --with-libcouchbase-lib-dir=<path>.])
        FR_MODULE_FAIL([libcouchbase])
fi

FR_MODULE_END_TESTS

mod_ldflags="${SMART_LIBS}"
mod_cflags="${SMART_CPPFLAGS}"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
