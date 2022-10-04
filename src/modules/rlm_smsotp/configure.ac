AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_smsotp.c])
AC_REVISION($Revision: 0.1 $)
FR_INIT_MODULE([rlm_smsotp])

FR_MODULE_START_TESTS

AC_PROG_CC
AC_PROG_CPP

AC_CHECK_HEADERS(sys/un.h)
if test "$ac_cv_header_sys_un_h" != "yes"; then
	FR_MODULE_FAIL([sys/un.h])
fi

FR_MODULE_END_TESTS

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
