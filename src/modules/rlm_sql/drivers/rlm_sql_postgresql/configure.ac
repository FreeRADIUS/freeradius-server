AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_sql_postgresql.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_sql_postgresql])

SMART_LIBS=
SMART_CLFAGS=

FR_MODULE_START_TESTS

AC_PROG_CC

dnl extra argument: --with-rlm-sql-postgresql-lib-dir
rlm_sql_postgresql_lib_dir=
AC_ARG_WITH(rlm-sql-postgresql-lib-dir,
	[AS_HELP_STRING([-with-rlm-sql-postgresql-lib-dir=DIR],
		[Directory for PostgreSQL library files])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need rlm-sql-postgresql-lib-dir)
		;;
	yes)
		;;
	*)
		rlm_sql_postgresql_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-rlm-sql-postgresql-include-dir
rlm_sql_postgresql_include_dir=
AC_ARG_WITH(rlm-sql-postgresql-include-dir,
	[AS_HELP_STRING([-with-rlm-sql-postgresql-include-dir=DIR],
		[Directory for PostgreSQL include files])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need rlm-sql-postgresql-include-dir)
		;;
	yes)
		;;
	*)
		rlm_sql_postgresql_include_dir="$withval"
		;;
	esac])

smart_try_dir="$rlm_sql_postgresql_include_dir /usr/include/postgresql /usr/local/pgsql/include /usr/include/pgsql"
FR_SMART_CHECK_INCLUDE(libpq-fe.h)
if test "x$ac_cv_header_libpqmfe_h" != "xyes"; then
	FR_MODULE_FAIL([libpq-fe.h])
else
	CPPFLAGS="$SMART_CPPFLAGS"
	AC_MSG_CHECKING([for PGRES_SINGLE_TUPLE])
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM([#include <libpq-fe.h>], [[
			if (PGRES_SINGLE_TUPLE) return 0;
			return 1;
		]])],
		[
			AC_DEFINE([HAVE_PGRES_SINGLE_TUPLE], [1],
				[Whether the PGRES_SINGLE_TUPLE constant is defined])
			AC_MSG_RESULT(yes)
		],
		[
			AC_MSG_RESULT(no)
		])

	AC_MSG_CHECKING([for PGRES_COPY_BOTH])
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM([#include <libpq-fe.h>], [[
			if (PGRES_COPY_BOTH) return 0;
			return 1;
		]])],
		[
			AC_DEFINE([HAVE_PGRES_COPY_BOTH], [1],
				[Whether the PGRES_COPY_BOTH constant is defined])
			AC_MSG_RESULT(yes)
		],
		[
			AC_MSG_RESULT(no)
		])

	AC_MSG_CHECKING([for PGRES_PIPELINE_SYNC])
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM([#include <libpq-fe.h>], [[
			if (PGRES_PIPELINE_SYNC) return 0;
			return 1;
		]])],
		[
			AC_DEFINE([HAVE_PGRES_PIPELINE_SYNC], [1],
				[Whether the PGRES_PIPELINE_SYNC constant is defined])
			AC_MSG_RESULT(yes)
		],
		[
			AC_MSG_RESULT(no)
		])
fi

smart_try_dir="$rlm_sql_postgresql_lib_dir /usr/lib /usr/local/pgsql/lib"
FR_SMART_CHECK_LIB(pq, PQconnectdb)
if test "x$ac_cv_lib_pq_PQconnectdb" != "xyes"; then
	FR_MODULE_FAIL([libpq])
fi

AC_CHECK_FUNCS(\
	PQinitOpenSSL \
	PQinitSSL \
)

FR_MODULE_END_TESTS

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
