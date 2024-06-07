AC_PREREQ([2.71])
AC_INIT
AC_CONFIG_SRCDIR([rlm_sql_mysql.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_sql_mysql], [MySQL and MariaDB database support])

SMART_LIBS=
SMART_CLFAGS=

FR_MODULE_START_TESTS

dnl ############################################################
dnl # Check for command line options
dnl ############################################################

dnl extra argument: --with-mysql-include-dir=DIR
mysql_include_dir=
AC_ARG_WITH(mysql-include-dir,
[AS_HELP_STRING([--with-mysql-include-dir=DIR],
	[Directory where the mysql includes may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need mysql-include-dir)
		;;
	yes)
		;;
	*)
		mysql_include_dir="$withval"
		;;
	esac])

dnl extra argument: --with-mysql-lib-dir=DIR
mysql_lib_dir=
AC_ARG_WITH(mysql-lib-dir,
[AS_HELP_STRING([--with-mysql-lib-dir=DIR],
	[Directory where the mysql libraries may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need mysql-lib-dir)
		;;
	yes)
		;;
	*)
		mysql_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-mysql-dir=DIR
AC_ARG_WITH(mysql-dir,
[AS_HELP_STRING([--with-mysql-dir=DIR],
	[Base directory where mysql is installed])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need mysql-dir)
		;;
	yes)
		;;
	*)
		mysql_lib_dir="$withval/lib"
		mysql_include_dir="$withval/include"
		;;
	esac])

dnl extra argument: --with-threads
mysql_with_threads=yes
AC_ARG_WITH(threads,
[AS_HELP_STRING([--with-threads],
	[use threads, if available. (default=yes)])],
	[case "$withval" in
	no)
		mysql_with_threads=no
		;;
	*)
		;;
	esac])

dnl ############################################################
dnl # Check for programs
dnl ############################################################

AC_PROG_CC
AC_CHECK_PROGS(MYSQL_CONFIG, [ mariadb_config ])

dnl ############################################################
dnl # Check for libraries
dnl ############################################################

dnl # Use linker arguments from mysql_config if available, then fallback
dnl # to hunting around if we can't find the client library.
if test "x$MYSQL_CONFIG" != "x"; then
	mysql_libs="$(${MYSQL_CONFIG} --libs_r)"
	old_LIBS="$LIBS"
	LIBS="$mysql_libs $LIBS"

	dnl # First check for libmysqlclient_r
	AC_MSG_CHECKING([for mysql_get_socket in -lmysqlclient_r (using ${MYSQL_CONFIG})])
	AC_TRY_LINK_FUNC([mysql_get_socket], [have_libmysqlclient_r=yes])

	LIBS="$old_LIBS"
	if test "x$have_libmysqlclient_r" = "xyes"; then
		AC_MSG_RESULT(yes)

		have_a_libmysqlclient='yes'
		SMART_LIBS="$mysql_libs $SMART_LIBS"
	else
		AC_MSG_RESULT(no)
	fi

	dnl # If that's not available check for libmysqlclient
	if test "x$have_a_libmysqlclient" != "xyes"; then
		mysql_libs="$(${MYSQL_CONFIG} --libs)"
		old_LIBS="$LIBS"
		LIBS="$mysql_libs $LIBS"

		AC_MSG_CHECKING([for mysql_get_socket in -lmysqlclient (using ${MYSQL_CONFIG})])
		AC_TRY_LINK_FUNC([mysql_get_socket], [have_libmysqlclient=yes])

		LIBS="$old_LIBS"
		if test "x$have_libmysqlclient" = "xyes"; then
			AC_MSG_RESULT(yes)

			have_a_libmysqlclient=yes
			SMART_LIBS="$mysql_libs $SMART_LIBS"
		else
			AC_MSG_RESULT(no)
		fi
	fi
fi

dnl # Check for libmariadb
if test "x$have_a_libmysqlclient" != "xyes"; then
	smart_try_dir="$mysql_lib_dir /usr/lib /usr/lib/mariadb /usr/local/lib/mariadb /usr/local/mariadb/lib/mariadb"
	FR_SMART_CHECK_LIB(mariadb, mysql_get_socket, [mysql-client])
	if test "x$ac_cv_lib_mysqlclient_mysql_get_socket" = "xyes"; then
		have_a_libmysqlclient='yes'
	fi
fi

if test "x$have_a_libmysqlclient" != "xyes"; then
	AC_MSG_WARN([MariaDB libraries not found. Use --with-mysql-lib-dir=<path>.])
	FR_MODULE_FAIL([libmariadb])
fi

dnl ############################################################
dnl # Check for header files
dnl ############################################################
if test "x$MYSQL_CONFIG" != "x"; then
	mod_cflags="$(${MYSQL_CONFIG} --cflags)"
	old_CFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS $mod_cflags"
	AC_MSG_CHECKING([for mysql.h (using ${MYSQL_CONFIG} --cflags)])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <mysql.h>]], [[int a = 1;]])],[have_mysql_h=yes],[])
	if test "x$have_mysql_h" = "xyes"; then
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_MYSQL_H, [], [Define if you have <mysql.h>])
		SMART_CPPFLAGS="$SMART_CPPFLAGS $mod_cflags"
	else
		AC_MSG_RESULT(no)

		mod_cflags="$(${MYSQL_CONFIG} --include)"
		CFLAGS="$old_CFLAGS $mod_cflags"
		AC_MSG_CHECKING([for mysql.h (using mysql_config --include)])
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <mysql.h>]], [[int a = 1;]])],[have_mysql_h=yes],[])
		if test "x$have_mysql_h" = "xyes"; then
			AC_MSG_RESULT(yes)
			AC_DEFINE(HAVE_MYSQL_H, [], [Define if you have <mysql.h>])
			SMART_CPPFLAGS="$SMART_CPPFLAGS $mod_cflags"
		else
			AC_MSG_RESULT(no)
		fi
	fi
	CFLAGS="$old_CFLAGS"
fi

if test "x$have_mysql_h" != "xyes"; then
	smart_try_dir="$mysql_include_dir /usr/local/include /usr/local/mysql/include /usr/local/mariadb/include"
	FR_SMART_CHECK_INCLUDE(mysql/mysql.h,,[mysql-client])
	if test "x$ac_cv_header_mysql_mysql_h" = "xyes"; then
		AC_DEFINE(HAVE_MYSQL_MYSQL_H, [], [Define if you have <mysql/mysql.h>])
	else
		AC_MSG_WARN([MariaDB headers not found. Use --with-mysql-include-dir=<path>.])
		FR_MODULE_FAIL([mysql.h])
	fi
fi

FR_MODULE_END_TESTS

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
