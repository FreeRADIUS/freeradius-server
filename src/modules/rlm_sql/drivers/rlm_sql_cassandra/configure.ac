AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_sql_cassandra.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_sql_cassandra], [Cassandra database support])

SMART_LIBS=
SMART_CLFAGS=

FR_MODULE_START_TESTS

dnl ############################################################
dnl # Check for command line options
dnl ############################################################

dnl extra argument: --with-cassandra-include-dir=DIR
cassandra_include_dir=
AC_ARG_WITH(cassandra-include-dir,
	[AS_HELP_STRING([--with-cassandra-include-dir=DIR],
		[Directory where the cassandra includes may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need cassandra-include-dir)
		;;
	yes)
		;;
	*)
		cassandra_include_dir="$withval"
		;;
	esac])

dnl extra argument: --with-cassandra-lib-dir=DIR
cassandra_lib_dir=
AC_ARG_WITH(cassandra-lib-dir,
	[AS_HELP_STRING([--with-cassandra-lib-dir=DIR],
		[Directory where the cassandra libraries may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need cassandra-lib-dir)
		;;
	yes)
		;;
	*)
		cassandra_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-cassandra-dir=DIR
AC_ARG_WITH(cassandra-dir,
	[AS_HELP_STRING([--with-cassandra-dir=DIR],
		[Base directory where cassandra is installed])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need cassandra-dir)
		;;
	yes)
		;;
	*)
		cassandra_lib_dir="$withval/lib"
		cassandra_include_dir="$withval/include"
		;;
	esac])

dnl ############################################################
dnl # Check for programs
dnl ############################################################

AC_PROG_CC

dnl ############################################################
dnl # Check for libraries
dnl ############################################################

dnl # try to link to libcassandra
smart_try_dir="$cassandra_lib_dir"
FR_SMART_CHECK_LIB(cassandra, cass_statement_new_n)
dnl # Ensure we use the library we just found the rest of the checks
LDFLAGS="$SMART_LIBS"
if test "x$ac_cv_lib_cassandra_cass_statement_new_n" != "xyes"
then
	AC_MSG_WARN([Cassandra libraries not found. Use --with-cassandra-lib-dir=<path>.])
	FR_MODULE_FAIL([libcassandra (>= 2.0)])
fi

dnl ############################################################
dnl # Check for header files
dnl ############################################################

smart_try_dir="$cassandra_include_dir"
FR_SMART_CHECK_INCLUDE(cassandra.h)
if test "x$ac_cv_header_cassandra_h" != "xyes"; then
	AC_MSG_WARN([Cassandra headers not found. Use --with-cassandra-include-dir=<path>.])
	FR_MODULE_FAIL([cassandra.h])
fi
CFLAGS="$SMART_CPPFLAGS"

FR_MODULE_END_TESTS

FR_MODULE_TEST_FAIL_DO([
	AC_MSG_WARN([available from https://github.com/datastax/cpp-driver]);
])

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
