AC_PREREQ([2.53])
AC_INIT(rlm_unbound.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_unbound])

if test x$with_[]modname != xno; then
	AC_PROG_CC
	AC_PROG_CPP

	FR_SMART_CHECK_LIB(unbound, ub_ctx_create)
        	if test "x$ac_cv_lib_unbound_ub_ctx_create" != "xyes"; then
		fail="$fail libunbound"
	fi

	FR_SMART_CHECK_INCLUDE(unbound.h)
	if test "$ac_cv_header_unbound_h" != "yes"; then
		fail="$fail unbound.h"
	fi

dnl # This needs work as libunbound could be using NSS or various other
dnl # mixes of incompatible options and header/lib availability may occur.
dnl # Since libunbound needs openssl locking set up, and may be
dnl # linked against openssl even when we are not, play it safe.
	FR_SMART_CHECK_INCLUDE(openssl/crypto.h)
	if test "$ac_cv_header_openssl_crypto_h" != "yes"; then
		fail="$fail openssl/crypto.h"
	fi

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
		AC_MSG_WARN([FAILURE: ]modname[ requires: $fail.]);
		targetname=""
	fi
fi

mod_ldflags="${SMART_LIBS}"
mod_cflags="${SMART_CFLAGS}"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_CONFIG_HEADER(config.h)

AC_SUBST(targetname)
AC_OUTPUT(all.mk)
