AC_INIT(rlm_sql_postgresql.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_sql_postgresql])

fail=
SMART_LIBS=
SMART_CLFAGS=
if test x$with_[]modname != xno; then

	AC_PROG_CC

	dnl extra argument: --with-rlm-sql-postgresql-lib-dir
	rlm_sql_postgresql_lib_dir=
	AC_ARG_WITH(rlm-sql-postgresql-lib-dir,
	[  --with-rlm-sql-postgresql-lib-dir=DIR       Directory for PostgreSQL library files []],
	[ case "$withval" in
	    no)
		AC_MSG_ERROR(Need rlm-sql-postgresql-lib-dir)
		;;
	    yes)
		;;
	    *)
		rlm_sql_postgresql_lib_dir="$withval"
		;;
	  esac ]
	)

	dnl extra argument: --with-rlm-sql-postgresql-include-dir
	rlm_sql_postgresql_include_dir=
	AC_ARG_WITH(rlm-sql-postgresql-include-dir,
	[  --with-rlm-sql-postgresql-include-dir=DIR   Directory for PostgreSQL include files []],
	[ case "$withval" in
	    no)
		AC_MSG_ERROR(Need rlm-sql-postgresql-include-dir)
		;;
	    yes)
		;;
	    *)
		rlm_sql_postgresql_include_dir="$withval"
		;;
	  esac ]
	)

	smart_try_dir="$rlm_sql_postgresql_include_dir /usr/include/postgresql /usr/local/pgsql/include /usr/include/pgsql"
	FR_SMART_CHECK_INCLUDE(libpq-fe.h)
	if test "x$ac_cv_header_libpqmfe_h" != "xyes"; then
		fail="$fail libpq-fe.h"
	else
		CPPFLAGS="$SMART_CPPFLAGS"
		AC_MSG_CHECKING([for PGRES_SINGLE_TUPLE])
		AC_COMPILE_IFELSE(
		  [AC_LANG_PROGRAM([#include <libpq-fe.h>], [[
		    if (PGRES_SINGLE_TUPLE) return 0;
		    return 1;
		  ]])],
		  [
		    AC_DEFINE([HAVE_PGRES_SINGLE_TUPLE], [1], [Whether the PGRES_SINGLE_TUPLE constant is defined])
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
		    AC_DEFINE([HAVE_PGRES_COPY_BOTH], [1], [Whether the PGRES_COPY_BOTH constant is defined])
		    AC_MSG_RESULT(yes)
		  ],
		  [
		    AC_MSG_RESULT(no)
		  ])
	fi

	smart_try_dir="$rlm_sql_postgresql_lib_dir /usr/lib /usr/local/pgsql/lib"
	FR_SMART_CHECK_LIB(pq, PQconnectdb)
	if test "x$ac_cv_lib_pq_PQconnectdb" != "xyes"; then
		fail="$fail libpq"
	fi
	AC_CHECK_FUNCS(\
		PQinitOpenSSL \
		PQinitSSL \
	)
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
		AC_MSG_WARN([FAILURE: ]modname[ requires: $fail.])
		if test x"$headersuggestion" != x; then
			AC_MSG_WARN([$headersuggestion])
		fi
		if test x"$libsuggestion" != x; then
			AC_MSG_WARN([$libsuggestion])
		fi
		targetname=""
	fi
fi

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"
AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)
AC_SUBST(targetname)
AC_CONFIG_HEADER(config.h)
AC_OUTPUT(all.mk)
