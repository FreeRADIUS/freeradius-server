AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_securid.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_securid])

SMART_LIBS=
SMART_CLFAGS=

FR_MODULE_START_TESTS

dnl ############################################################
dnl # Check for command line options
dnl ############################################################

dnl extra argument: --with-rlm-securid-include-dir=DIR
securid_include_dir=
AC_ARG_WITH(rlm-securid-include-dir,
	[AS_HELP_STRING([--with-rlm-securid-include-dir=DIR],
		[Directory where the securid includes may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need rlm-securid-include-dir)
		;;
	yes)
		;;
	*)
		securid_include_dir="$withval"
		;;
	esac])

dnl extra argument: --with-rlm-securid-lib-dir=DIR
securid_lib_dir=
AC_ARG_WITH(rlm-securid-lib-dir,
	[AS_HELP_STRING([--with-rlm-securid-lib-dir=DIR],
		[Directory where the securid libraries may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need rlm-securid-lib-dir)
		;;
	yes)
		;;
	*)
		securid_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-rlm-securid-dir=DIR
AC_ARG_WITH(rlm-securid-dir,
	[AS_HELP_STRING([--with-rlm-securid-dir=DIR],
		[Base directory where securid is installed])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need rlm-securid-dir)
		;;
	yes)
		;;
	*)
		securid_lib_dir="$withval/lib"
		securid_include_dir="$withval/inc"
		;;
	esac])

dnl ############################################################
dnl # Check for header files
dnl ############################################################

smart_try_dir="$securid_include_dir"
FR_SMART_CHECK_INCLUDE(acexport.h)
if test "x$ac_cv_header_acexport_h" != "xyes"; then
	AC_MSG_WARN([securid headers not found. Use --with-rlm-securid-include-dir=<path>.])
	FR_MODULE_FAIL([acexport.h])
fi

dnl ############################################################
dnl # Check for libraries
dnl ############################################################

dnl try to link to securid
smart_try_dir="$securid_lib_dir"
FR_SMART_CHECK_LIB(aceclnt, SD_Init)
if test "x$ac_cv_lib_aceclnt_SD_Init" != "xyes"
then
	AC_MSG_WARN([securid libraries not found. Use --with-rlm-securid-lib-dir=<path>.])
	FR_MODULE_FAIL([libaceclnt])
fi

FR_MODULE_END_TESTS

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
