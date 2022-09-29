AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_radutmp.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_radutmp])

if test x$with_[]modname != xno; then

	AC_CHECK_HEADERS(sys/mman.h)

	targetname=modname
else
	targetname=
	echo \*\*\* module modname is disabled.
fi

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)
AC_SUBST(targetname)
AC_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
