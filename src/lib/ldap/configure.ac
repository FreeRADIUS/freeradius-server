AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([base.c])
AC_REVISION($Revision$)
FR_INIT_LIBRARY([libfreeradius-ldap], [LDAP support])

SMART_LIBS=
SMART_CLFAGS=
SASL=

FR_LIBRARY_START_TESTS

	dnl ############################################################
	dnl # Check for compiler
	dnl ############################################################
	AC_PROG_CC

	dnl ############################################################
	dnl # Check for command line options
	dnl ############################################################

	dnl # extra argument: --with-libfreeradius-ldap-lib-dir
	libfreeradius_ldap_lib_dir=
	AC_ARG_WITH(libfreeradius-ldap-lib-dir,
	[  --with-libfreeradius-ldap-lib-dir=DIR	   directory for LDAP library files []],
	[ case "$withval" in
		no)
		AC_MSG_ERROR(Need libfreeradius-ldap-lib-dir)
		;;
		yes)
		;;
		*)
		libfreeradius_ldap_lib_dir="$withval"
		;;
	  esac ]
	)

	dnl # extra argument: --with-libfreeradius-ldap-include-dir
	libfreeradius_ldap_include_dir=
	AC_ARG_WITH(libfreeradius-ldap-include-dir,
	[  --with-libfreeradius-ldap-include-dir=DIR   directory for LDAP include files []],
	[ case "$withval" in
		no)
		AC_MSG_ERROR(Need libfreeradius-ldap-include-dir)
		;;
		yes)
		;;
		*)
		libfreeradius_ldap_include_dir="$withval"
		;;
	  esac ]
	)

	dnl ############################################################
	dnl # Check for libraries
	dnl ############################################################

	dnl #  We set this in libfreeradius_ldap.h when we include ldap.h, so for
	dnl #  consistency we need to set it here too,  else we might
	dnl #  get differing results for DECL checks.
	CFLAGS="-DLDAP_DEPRECATED=1 ${CFLAGS}"

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

	dnl #
	dnl #  FreeRADIUS 4.0 also has a requirement that libldap
	dnl #  exports OpenLDAP specific functions to managing async
	dnl #  I/O.
	dnl #
	smart_try_dir="$libfreeradius_ldap_lib_dir /usr/local/opt/openldap/lib"
	FR_SMART_CHECK_LIB(ldap, ldap_install_tls)
	if test "x$ac_cv_lib_ldap_ldap_install_tls" != "xyes"; then
		fail="$fail libldap (with async support)"
	fi

	FR_SMART_CHECK_LIB(lber, ber_get_next)
	if test "x$ac_cv_lib_lber_ber_get_next" != "xyes"; then
		fail="$fail lber"
	fi

	dnl ############################################################
	dnl # Check for header files
	dnl ############################################################

	smart_try_dir="$libfreeradius_ldap_include_dir /usr/local/opt/openldap/include"
	FR_SMART_CHECK_INCLUDE(ldap.h)
	if test "$ac_cv_header_ldap_h" != "yes"; then
	  fail="$fail ldap.h"
	fi

	dnl ############################################################
	dnl # Check for library functions
	dnl ############################################################

	if test "x$fail" = "x"; then
		AC_CHECK_FUNCS(
			ldap_create_session_tracking_control
		)

		AC_CHECK_DECLS([ldap_create_session_tracking_control], [], [], [[#include <ldap.h>]])
	fi

	dnl ############################################################
	dnl # Check for SASL support
	dnl ############################################################
	FR_SMART_CHECK_INCLUDE([sasl/sasl.h])
	if test "x$ac_cv_header_sasl_sasl_h" = "xyes"; then
	  if test x"$ac_cv_func_ldap_sasl_interactive_bind" = "xyes"; then
	    AC_DEFINE(WITH_SASL, 1, [Build the server with support for SASL binds])
	    SASL="sasl_s.c sasl.c"
	  fi
	fi

FR_LIBRARY_END_TESTS

AC_DEFINE(WITH_EDIR, 1, [Build the server with support for Novell eDir Universal Password])

mod_ldflags=$SMART_LIBS
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)
AC_SUBST(SASL)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
