AC_PREREQ([2.59])
AC_INIT(rlm_sqlippool.c)
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_sqlippool], [support for IP pools in SQL])

if test x$with_[]modname != xno; then

	dnl  This module doesn't need any autoconf test which is not already
	dnl  in top-level configure.

	targetname=modname
else
	targetname=
	echo \*\*\* module modname is disabled.
fi

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"
AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)
AC_SUBST(targetname)
AC_OUTPUT(all.mk)
