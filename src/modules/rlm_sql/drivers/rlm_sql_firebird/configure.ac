AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_sql_firebird.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_sql_firebird])

SMART_LIBS=
SMART_CLFAGS=

FR_MODULE_START_TESTS

dnl extra argument: --with-firebird-include-dir
firebird_include_dir=
AC_ARG_WITH(firebird-include-dir,
	[AS_HELP_STRING([--with-firebird-include-dir=DIR],
		[Directory where the firebird includes may be found])],
	[case "$withval" in
		no)
		AC_MSG_ERROR(Need firebird-include-dir)
		;;
	yes)
		;;
	*)
		firebird_include_dir="$withval"
		;;
	esac])

dnl extra argument: --with-firebird-lib-dir
firebird_lib_dir=
AC_ARG_WITH(firebird-lib-dir,
	[AS_HELP_STRING([--with-firebird-lib-dir=DIR],
		[Directory where the firebird libraries may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need firebird-lib-dir)
		;;
	yes)
		;;
	*)
		firebird_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-firebird-dir
AC_ARG_WITH(firebird-dir,
	[AS_HELP_STRING([--with-firebird-dir=DIR],
		[Base directory where firebird is installed])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need firebird-dir)
		;;
	yes)
		;;
	*)
		firebird_lib_dir="$withval/lib"
		firebird_include_dir="$withval/include"
		;;
	esac])

dnl Check for isc_attach_database in -lfbclient
smart_try_dir="$firebird_lib_dir /usr/lib/firebird2/lib /usr/local/firebird/lib"
FR_SMART_CHECK_LIB(fbclient, isc_attach_database)
if test "x$ac_cv_lib_fbclient_isc_attach_database" != xyes; then
	FR_MODULE_FAIL([libfbclient])
fi

dnl Check for ibase.h
smart_try_dir="$firebird_include_dir /usr/lib/firebird2/include /usr/local/firebird/include"
FR_SMART_CHECK_INCLUDE(ibase.h)
if test "x$ac_cv_header_ibase_h" != xyes; then
	FR_MODULE_FAIL([ibase.h])
fi

FR_MODULE_END_TESTS

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
