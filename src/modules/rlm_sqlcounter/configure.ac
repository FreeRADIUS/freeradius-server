AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_sqlcounter.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_sqlcounter])

FR_MODULE_START_TESTS

AC_PROG_CC
AC_PROG_CPP

FR_MODULE_END_TESTS

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
