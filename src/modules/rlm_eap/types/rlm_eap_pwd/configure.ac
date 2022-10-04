AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_eap_pwd.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_eap_pwd])

mod_ldflags=
mod_cflags=

FR_MODULE_START_TESTS

dnl ############################################################
dnl # Check for command line options
dnl ############################################################

dnl extra argument: --with-openssl-lib-dir
openssl_lib_dir=
AC_ARG_WITH(openssl-lib-dir,
	[AS_HELP_STRING([--with-openssl-lib-dir=DIR],
		[directory for LDAP library files])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need openssl-lib-dir)
		;;
	yes)
		;;
	*)
		openssl_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-openssl-include-dir
openssl_include_dir=
AC_ARG_WITH(openssl-include-dir,
	[AS_HELP_STRING([--with-openssl-include-dir=DIR],
		[directory for LDAP include files])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need openssl-include-dir)
		;;
	yes)
		;;
	*)
		openssl_include_dir="$withval"
		;;
	esac])

dnl ############################################################
dnl # Check for header files
dnl ############################################################

smart_try_dir=$openssl_include_dir
FR_SMART_CHECK_INCLUDE(openssl/ec.h)
if test "$ac_cv_header_openssl_ec_h" != "yes"; then
	FR_MODULE_FAIL([openssl/ec.h])
fi

smart_try_dir=$openssl_lib_dir
FR_SMART_CHECK_LIB(crypto, EVP_CIPHER_CTX_new)
if test "x$ac_cv_lib_crypto_EVP_CIPHER_CTX_new" != "xyes"; then
	FR_MODULE_FAIL([libssl])
else
	AC_CHECK_FUNCS(EVP_sha256)
	if test "x$ac_cv_func_EVP_sha256" != "xyes"; then
		AC_MSG_WARN([EVP_sha256 not found, may have issues with WiMAX certificates])
	fi

	AC_CHECK_FUNCS(EC_GROUP_free)
	if test "x$ac_cv_func_EC_GROUP_free" != "xyes"; then
		FR_MODULE_FAIL([EC_GROUP_free])
	fi
fi

FR_MODULE_END_TESTS

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
