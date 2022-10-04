AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_eap_ikev2.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_eap_ikev2])

FR_MODULE_START_TESTS

dnl extra argument: --with-eap-ikev2-include-dir=DIR
eap_ikev2_include_dir=
AC_ARG_WITH(eap-ikev2-include-dir,
	[AS_HELP_STRING([--with-eap-ikev2-include-dir=DIR],
		[Directory where the eap-ikev2 includes may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need eap-ikev2-include-dir)
		;;
	yes)
		;;
	*)
		eap_ikev2_include_dir="$withval"
		;;
	esac])

dnl extra argument: --with-eap-ikev2-lib-dir=DIR
eap_ikev2_lib_dir=
AC_ARG_WITH(eap-ikev2-lib-dir,
	[AS_HELP_STRING([--with-eap-ikev2-lib-dir=DIR],
		[Directory where the eap-ikev2 libraries may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need eap-ikev2-lib-dir)
		;;
	yes)
		;;
	*)
		eap_ikev2_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-eap-ikev2-dir=DIR
AC_ARG_WITH(eap-ikev2-dir,
	[AS_HELP_STRING([--with-eap-ikev2-dir=DIR],
		[Base directory where eap-ikev2 is installed])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need eap-ikev2-dir)
		;;
	yes)
		;;
	*)
		eap_ikev2_lib_dir="$withval/lib"
		eap_ikev2_include_dir="$withval/include"
		;;
	esac])

dnl ############################################################
dnl # Check for OpenSSL support
dnl ############################################################

AC_MSG_CHECKING(for OpenSSL support)
if test "x$OPENSSL_LIBS" != "x"; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
	FR_MODULE_FAIL([OpenSSL])
fi

dnl ############################################################
dnl # Check for eap-ikev2 includes
dnl ############################################################

smart_try_dir="$eap_ikev2_include_dir"
FR_SMART_CHECK_INCLUDE([EAPIKEv2/connector.h])
if test "x$ac_cv_header_EAPIKEv2_connector_h" != "xyes"; then
	FR_MODULE_FAIL([EAPIKEv2/connector.h])
fi

dnl ############################################################
dnl # Check for eap-ikev2 library
dnl ############################################################

LIBS="${OPENSSL_LIBS}"
smart_try_dir="$eap_ikev2_lib_dir"
FR_SMART_CHECK_LIB([eap-ikev2],[ikev2_set_log_callback])
if test "x$ac_cv_lib_eap_ikev2_ikev2_set_log_callback" != "xyes"; then
	FR_MODULE_FAIL([libeap-ikev2])
fi

FR_MODULE_END_TESTS

mod_ldfags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
