AC_PREREQ([2.68])
AC_INIT(rlm_radutmp.c)
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_radutmp], [radutmp support])

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
AC_OUTPUT(all.mk)
