AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_eap_tnc.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_eap_tnc])

FR_MODULE_START_TESTS

dnl extra argument: --with-eap-tnc-include-dir=DIR
eap_tnc_include_dir=
AC_ARG_WITH(eap-tnc-include-dir,
	[AS_HELP_STRING([--with-eap-tnc-include-dir=DIR],
		[Directory where the libtnc includes may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need eap-tnc-include-dir)
		;;
	yes)
		;;
	*)
		eap_tnc_include_dir="$withval"
		;;
	esac])

dnl extra argument: --with-eap-tnc-lib-dir=DIR
eap_tnc_lib_dir=
AC_ARG_WITH(eap-tnc-lib-dir,
[AS_HELP_STRING([--with-eap-tnc-lib-dir=DIR],
	[Directory where the libtnc libraries may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need eap-tnc-lib-dir)
		;;
	yes)
		;;
	*)
		eap_tnc_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-eap-tnc-dir=DIR
AC_ARG_WITH(eap-tnc-dir,
[AS_HELP_STRING([--with-eap-tnc-dir=DIR],
	[Base directory where libtnc is installed])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need eap-tnc-dir)
		;;
	yes)
		;;
	*)
		eap_tnc_lib_dir="$withval/lib"
		eap_tnc_include_dir="$withval/include"
		;;
	esac])

dnl ############################################################
dnl # Check for eap-tnc includes
dnl ############################################################

smart_try_dir="$eap_tnc_include_dir"
FR_SMART_CHECK_INCLUDE([naaeap/naaeap.h])
if test "x$ac_cv_header_naaeap_naaeap_h" != "xyes"; then
	FR_MODULE_FAIL([naaeap.h])
fi

dnl ############################################################
dnl # Check for eap-tnc library
dnl ############################################################

smart_try_dir="$eap_tnc_lib_dir"
FR_SMART_CHECK_LIB([naaeap],[processEAPTNCData])
if test "x$ac_cv_lib_naaeap_processEAPTNCData" != "xyes"; then
	FR_MODULE_FAIL([libnaaeap])
fi

FR_MODULE_END_TESTS

FR_MODULE_TEST_FAIL_DO([
	AC_MSG_WARN([Required libraries are available from https://github.com/trustatfhh/tnc-fhh]);
])

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
