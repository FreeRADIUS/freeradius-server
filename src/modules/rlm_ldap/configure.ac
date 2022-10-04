AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_ldap.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_ldap], [LDAP support])

SMART_LIBS=
SMART_CLFAGS=
SASL=

FR_MODULE_START_TESTS

dnl ############################################################
dnl # Check for compiler
dnl ############################################################

AC_PROG_CC

dnl ############################################################
dnl # Check for command line options
dnl ############################################################

dnl # extra argument: --with-rlm-ldap-lib-dir
rlm_ldap_lib_dir=
AC_ARG_WITH(rlm-ldap-lib-dir,
	[AS_HELP_STRING([--with-rlm-ldap-lib-dir=DIR],
		[directory for LDAP library files])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need rlm-ldap-lib-dir)
		;;
	yes)
		;;
	*)
		rlm_ldap_lib_dir="$withval"
		;;
		esac])

dnl # extra argument: --with-rlm-ldap-include-dir
rlm_ldap_include_dir=
AC_ARG_WITH(rlm-ldap-include-dir,
	[AS_HELP_STRING([--with-rlm-ldap-include-dir=DIR],
		[directory for LDAP include files])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need rlm-ldap-include-dir)
		;;
	yes)
		;;
	*)
		rlm_ldap_include_dir="$withval"
		;;
	esac])

dnl ############################################################
dnl # Check for libraries
dnl ############################################################

dnl #
dnl #  Official word from those who represent OpenLDAP say
dnl #  libldap_r is unsupported for use outside the OpenLDAP
dnl #  server. But libldap *may* work with the FreeRADIUS
dnl #  as we use a threadpool to prevent concurrent access to
dnl #  the same libldap handle.
dnl #
dnl #  In FreeRADIUS <= 3.0.6 we used libldap_r in preference
dnl #  to libldap, however, in order to support certain distros
dnl #  or packagers that only ship libldap in their OpenLDAP
dnl #  client packages, we're forced to switch to just libldap.
dnl #
smart_try_dir=$rlm_ldap_lib_dir
FR_SMART_CHECK_LIB(ldap, ldap_init)
if test "x$ac_cv_lib_ldap_ldap_init" != "xyes"; then
	FR_MODULE_FAIL([libldap])
fi

dnl ############################################################
dnl # Check for header files
dnl ############################################################

smart_try_dir=$rlm_ldap_include_dir
FR_SMART_CHECK_INCLUDE(ldap.h)
if test "$ac_cv_header_ldap_h" != "yes"; then
	FR_MODULE_FAIL([ldap.h])
fi

dnl ############################################################
dnl # Check for library functions
dnl ############################################################

FR_MODULE_TEST_PASS_DO([
	AC_CHECK_FUNCS(
		ldap_sasl_interactive_bind \
		ldap_unbind_ext_s \
		ldap_start_tls_s \
		ldap_initialize \
		ldap_set_rebind_proc \
		ldap_create_sort_control \
		ldap_create_sort_keylist \
		ldap_free_sort_keylist \
		ldap_url_parse \
		ldap_is_ldap_url \
		ldap_url_desc2str
	)
	AC_CACHE_CHECK(whether ldap_set_rebind_proc takes 3 arguments, ac_cv_ldap_set_rebind_proc, [
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
			#include <lber.h>
			#include <ldap.h>]], [[ldap_set_rebind_proc(0, 0, 0);]])],[ac_cv_ldap_set_rebind_proc=3],[ac_cv_ldap_set_rebind_proc=2])
	])
])

dnl ############################################################
dnl # Check for SASL support
dnl ############################################################
FR_SMART_CHECK_INCLUDE([sasl/sasl.h])
if test "x$ac_cv_header_sasl_sasl_h" = "xyes"; then
	if test x"$ac_cv_func_ldap_sasl_interactive_bind" = "xyes"; then
		AC_DEFINE(WITH_SASL, 1, [Build the server with support for SASL binds])
		SASL=sasl.c
		FR_MODULE_FEATURE([sasl], [with SASL support])
	fi
else
	FR_MODULE_FEATURE([sasl], [without SASL support])
fi

FR_MODULE_END_TESTS

AC_DEFINE(WITH_EDIR, 1, [Build the server with support for Novell eDir Universal Password])
AC_DEFINE_UNQUOTED(LDAP_SET_REBIND_PROC_ARGS, ${ac_cv_ldap_set_rebind_proc}, [Number of arguments the rebind procedure takes])

mod_ldflags=$SMART_LIBS
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)
AC_SUBST(SASL)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
