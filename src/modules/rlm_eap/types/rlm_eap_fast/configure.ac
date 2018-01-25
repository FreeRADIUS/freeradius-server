#
# Autoconf input file.
#
# Version:	$Id$
#

AC_PREREQ([2.53])
AC_INIT(rlm_eap_fast.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_eap_fast])

mod_ldflags=
mod_cflags=

if test x$with_[]modname != xno; then

	dnl ############################################################
	dnl # Check for command line options
	dnl ############################################################
	dnl extra argument: --with-openssl-lib-dir
	openssl_lib_dir=
	AC_ARG_WITH(openssl-lib-dir,
	[  --with-openssl-lib-dir=DIR       directory for LDAP library files []],
	[ case "$withval" in
	    no)
		AC_MSG_ERROR(Need openssl-lib-dir)
		;;
	    yes)
		;;
	    *)
		openssl_lib_dir="$withval"
		;;
	  esac ]
	)

	dnl extra argument: --with-openssl-include-dir
	openssl_include_dir=
	AC_ARG_WITH(openssl-include-dir,
	[  --with-openssl-include-dir=DIR   directory for LDAP include files []],
	[ case "$withval" in
	    no)
		AC_MSG_ERROR(Need openssl-include-dir)
		;;
	    yes)
		;;
	    *)
		openssl_include_dir="$withval"
		;;
	  esac ]
	)

	dnl ############################################################
	dnl # Check for header files
	dnl ############################################################

	smart_try_dir=$openssl_include_dir
	FR_SMART_CHECK_INCLUDE(openssl/ec.h)
	if test "$ac_cv_header_openssl_ec_h" != "yes"; then
	  fail="$fail openssl/ec.h"
	fi

	smart_try_dir=$openssl_lib_dir
        FR_SMART_CHECK_LIB(crypto, EVP_CIPHER_CTX_new)
        if test "x$ac_cv_lib_crypto_EVP_CIPHER_CTX_new" != "xyes"; then
	  fail="libssl"
	fi

    AC_EGREP_CPP(yes,
      [#include <openssl/crypto.h>
       #if (OPENSSL_VERSION_NUMBER >= 0x01000100fL)
       yes
       #endif
      ],
      [
        AC_MSG_CHECKING([for OpenSSL version >= 1.0.1a])
        AC_MSG_RESULT(yes)
      ],
      [
        AC_MSG_CHECKING([for OpenSSL version >= 1.0.1a])
        AC_MSG_RESULT(no)
        fail="openssl>1.0.1"
      ]
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
		targetname=""
	fi
fi

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)
AC_SUBST(targetname)
AC_OUTPUT(all.mk)
