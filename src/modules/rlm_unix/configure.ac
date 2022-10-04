AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_unix.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_unix])

FR_MODULE_START_TESTS

AC_PROG_CC
AC_PROG_CPP

AC_MSG_CHECKING([for system password file])
if test -f /etc/passwd; then
	AC_MSG_RESULT(/etc/passwd)
else
	AC_MSG_RESULT(no /etc/passwd file)
	FR_MODULE_FAIL([/etc/passwd])
fi

dnl useless?
AC_MSG_CHECKING([for system shadow password file])
if test -f /etc/shadow; then
	AC_MSG_RESULT(/etc/shadow)
else
	AC_MSG_RESULT(no /etc/shadow file)
fi

AC_CHECK_HEADERS(shadow.h pwd.h grp.h)
AC_CHECK_FUNCS(getspnam getusershell getpwnam)

if test "$ac_cv_func_getpwnam" != "yes"; then
	AC_MSG_RESULT(no getpwnam)
	FR_MODULE_FAIL([getpwnam])
fi

if test "$ac_cv_header_pwd_h" != "yes"; then
	AC_MSG_RESULT(no pwd.h)
	FR_MODULE_FAIL([pwd.h])
fi

AC_CHECK_LIB(shadow, getspnam, [
	mod_ldflags="${mod_ldflags} -lshadow"
	AC_DEFINE(HAVE_GETSPNAM)
])

FR_MODULE_END_TESTS

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
