AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_sqlippool.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_sqlippool], [support for IP pools in SQL])

FR_MODULE_START_TESTS

dnl  This module doesn't need any autoconf test which is not already
dnl  in top-level configure.

FR_MODULE_END_TESTS([nostrict])

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
