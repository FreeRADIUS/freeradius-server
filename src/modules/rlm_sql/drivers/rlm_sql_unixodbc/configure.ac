AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_sql_unixodbc.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_sql_unixodbc])

SMART_LIBS=
SMART_CLFAGS=

FR_MODULE_START_TESTS

dnl extra argument: --with-unixodbc-include-dir
unixodbc_include_dir=
AC_ARG_WITH(unixodbc-include-dir,
	[AS_HELP_STRING([--with-unixodbc-include-dir=DIR],
		[Directory where the unixODBC includes may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need unixodbc-include-dir)
		;;
	yes)
		;;
	*)
		unixodbc_include_dir="$withval"
		;;
	esac])

dnl extra argument: --with-unixodbc-lib-dir
unixodbc_lib_dir=
AC_ARG_WITH(unixodbc-lib-dir,
	[AS_HELP_STRING([--with-unixodbc-lib-dir=DIR],
		[Directory where the unixODBC libraries may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need unixodbc-lib-dir)
		;;
	yes)
		;;
	*)
		unixodbc_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-unixodbc-dir
AC_ARG_WITH(unixodbc-dir,
	[AS_HELP_STRING([--with-unixodbc-dir=DIR],
		[Base directory where unixODBC is installed])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need unixodbc-dir)
		;;
	yes)
		;;
	*)
		unixodbc_lib_dir="$withval/lib"
		unixodbc_include_dir="$withval/include"
		;;
	esac])

dnl Check for SQLConnect in -lodbc
smart_try_dir="$unixodbc_lib_dir /usr/local/unixodbc/lib"
FR_SMART_CHECK_LIB(odbc, SQLConnect)
if test "x$ac_cv_lib_odbc_SQLConnect" != xyes; then
	FR_MODULE_FAIL([libodbc])
fi

dnl Check for sql.h
smart_try_dir="$unixodbc_include_dir /usr/local/unixodbc/include"
FR_SMART_CHECK_INCLUDE(sql.h)
if test "x$ac_cv_header_sql_h" != xyes; then
	FR_MODULE_FAIL([sql.h])
fi

FR_MODULE_END_TESTS

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
