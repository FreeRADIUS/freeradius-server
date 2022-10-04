AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_idn.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_idn])

FR_MODULE_START_TESTS

AC_PROG_CC
AC_PROG_CPP

FR_SMART_CHECK_LIB(idn, idna_to_ascii_8z)
if test "x$ac_cv_lib_idn_idna_to_ascii_8z" != "xyes"; then
	FR_MODULE_FAIL([libidn])
fi

FR_SMART_CHECK_INCLUDE(idna.h)
if test "$ac_cv_header_idna_h" != "yes"; then
	FR_MODULE_FAIL([idna.h])
fi

FR_MODULE_END_TESTS

mod_ldflags="${SMART_LIBS}"
mod_cflags="${SMART_CPPFLAGS}"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT

