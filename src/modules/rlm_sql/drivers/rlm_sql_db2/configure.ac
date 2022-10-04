AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_sql_db2.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_sql_db2])

SMART_LIBS=
SMART_CLFAGS=

FR_MODULE_START_TESTS

dnl extra argument: --with-ibmdb2-include-dir
ibmdb2_include_dir=
AC_ARG_WITH(ibmdb2-include-dir,
	[AS_HELP_STRING([--with-ibmdb2-include-dir=DIR],
		[Directory where the IBM-DB2 includes may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need ibmdb2-include-dir)
		;;
	yes)
		;;
	*)
		ibmdb2_include_dir="$withval"
		;;
	esac])

dnl extra argument: --with-ibmdb2-lib-dir
ibmdb2_lib_dir=
AC_ARG_WITH(ibmdb2-lib-dir,
	[AS_HELP_STRING([--with-ibmdb2-lib-dir=DIR],
		[Directory where the IBM-DB2 libraries may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need ibmdb2-lib-dir)
		;;
	yes)
		;;
	*)
		ibmdb2_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-ibmdb2-dir
AC_ARG_WITH(ibmdb2-dir,
	[AS_HELP_STRING([--with-ibmdb2-dir=DIR],
		[Base directory where IBM-DB2 is installed])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need ibmdb2-dir)
		;;
	yes)
		;;
	*)
		ibmdb2_lib_dir="$withval/lib"
		ibmdb2_include_dir="$withval/include"
		;;
	esac])

dnl Check for SQLConnect in -ldb2
smart_try_dir="$ibmdb2_lib_dir /usr/local/db2/lib /usr/IBMdb2/V7.1/lib"
FR_SMART_CHECK_LIB(db2, SQLConnect)
if test "x$ac_cv_lib_db2_SQLConnect" != xyes; then
	FR_MODULE_FAIL([libdb2])
fi

dnl Check for sqlcli.h
smart_try_dir="$ibmdb2_include_dir /usr/local/db2/include /usr/IBMdb2/V7.1/include"
FR_SMART_CHECK_INCLUDE(sqlcli.h)
if test "x$ac_cv_header_sqlcli_h" != xyes; then
	FR_MODULE_FAIL([sqlcli.h])
fi

FR_MODULE_END_TESTS

sql_ibmdb2_ldflags="$SMART_LIBS"
sql_ibmdb2_cflags="$SMART_CPPFLAGS"

AC_SUBST(sql_ibmdb2_ldflags)
AC_SUBST(sql_ibmdb2_cflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
