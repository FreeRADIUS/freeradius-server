AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_sql_sqlite.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_sql_sqlite])

SMART_LIBS=
SMART_CLFAGS=

FR_MODULE_START_TESTS

dnl ############################################################
dnl # Check for command line options
dnl ############################################################

dnl extra argument: --with-sqlite-include-dir=DIR
sqlite_include_dir=
AC_ARG_WITH(sqlite-include-dir,
	[AS_HELP_STRING([--with-sqlite-include-dir=DIR],
		[Directory where the sqlite includes may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need sqlite-include-dir)
		;;
	yes)
		;;
	*)
		sqlite_include_dir="$withval"
		;;
	esac])

dnl extra argument: --with-sqlite-lib-dir=DIR
sqlite_lib_dir=
AC_ARG_WITH(sqlite-lib-dir,
	[AS_HELP_STRING([--with-sqlite-lib-dir=DIR],
		[Directory where the sqlite libraries may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need sqlite-lib-dir)
		;;
	yes)
		;;
	*)
		sqlite_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-sqlite-dir=DIR
AC_ARG_WITH(sqlite-dir,
	[AS_HELP_STRING([--with-sqlite-dir=DIR],
		[Base directory where sqlite is installed])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need sqlite-dir)
		;;
	yes)
		;;
	*)
		sqlite_lib_dir="$withval/lib"
		sqlite_include_dir="$withval/include"
		;;
	esac])

dnl ############################################################
dnl # Check for programs
dnl ############################################################

AC_PROG_CC

dnl ############################################################
dnl # Check for libraries
dnl ############################################################

dnl try to link to libsqlite3
smart_try_dir="$sqlite_lib_dir"
FR_SMART_CHECK_LIB(sqlite3, sqlite3_open)
dnl # Ensure we use the library we just found the rest of the checks
LDFLAGS="${LDFLAGS} ${SMART_LIBS}"
if test "x$ac_cv_lib_sqlite3_sqlite3_open" != "xyes"
then
	AC_MSG_WARN([Sqlite libraries not found. Use --with-sqlite-lib-dir=<path>.])
	FR_MODULE_FAIL([libsqlite3])
else
	dnl # Add any v2 variants here
	AC_CHECK_FUNCS(\
		sqlite3_prepare_v2 \
		sqlite3_open_v2 \
		sqlite3_create_function_v2 \
		sqlite3_errstr \
		sqlite3_extended_result_codes \
	)
fi

dnl ############################################################
dnl # Check for header files
dnl ############################################################

smart_try_dir="$sqlite_include_dir"
FR_SMART_CHECK_INCLUDE(sqlite3.h)
if test "x$ac_cv_header_sqlite3_h" != "xyes"; then
	AC_MSG_WARN([Sqlite headers not found. Use --with-sqlite-include-dir=<path>.])
	FR_MODULE_FAIL([sqlite.h])
fi
CFLAGS="$SMART_CPPFLAGS"
AC_CHECK_TYPES([sqlite3_int64], [], [], [[#include <sqlite3.h>]])

FR_MODULE_END_TESTS

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
