AC_PREREQ([2.71])
AC_INIT
AC_CONFIG_SRCDIR([rlm_radutmp.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_radutmp], [ability to maintain utmp-style sessions])

FR_MODULE_START_TESTS

AC_CHECK_HEADERS(sys/mman.h)

FR_MODULE_END_TESTS([nostrict])

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
