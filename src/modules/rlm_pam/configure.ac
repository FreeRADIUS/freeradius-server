AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_pam.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_pam], [PAM authentication])

FR_MODULE_START_TESTS

AC_PROG_CC
AC_PROG_CPP

AC_CHECK_LIB(dl, dlopen,
	[ mod_ldflags="-ldl" ]
)

AC_CHECK_LIB(pam, pam_start,
	[ mod_ldflags="-lpam $mod_ldflags" ],
	[ FR_MODULE_FAIL([libpam]) ],
	[ $mod_ldflags ]
)

dnl #
dnl #	Yes, these DO have to be on separate lines,
dnl #	otherwise autoheader won't pick them up.
dnl #
AC_CHECK_HEADERS( \
	security/pam_appl.h \
	pam/pam_appl.h \
)
mod_cflags="-I."

FR_MODULE_END_TESTS

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
