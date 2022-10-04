AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_example.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_example])

FR_MODULE_START_TESTS

AC_PROG_CC
AC_PROG_CPP

FR_SMART_CHECK_LIB(c, printf)
if test "x$ac_cv_lib_c_printf" != "xyes"; then
	FR_MODULE_FAIL([libc])
fi

FR_SMART_CHECK_INCLUDE(stdio.h)
if test "$ac_cv_header_stdio_h" != "yes"; then
	FR_MODULE_FAIL([stdio.h])
fi

FR_MODULE_END_TESTS

mod_ldflags="${SMART_LIBS}"
mod_cflags="${SMART_CPPFLAGS}"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
