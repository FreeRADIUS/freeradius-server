AC_PREREQ([2.53])
AC_INIT(rlm_example.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_example])

if test x$with_[]modname != xno; then

	AC_PROG_CC
	AC_PROG_CPP

	dnl put configuration checks here.
	dnl set $fail to what's missing, on fatal errors.
	dnl use AC_MSG_WARN() on important messages.
	AC_CHECK_LIB(c, printf,
		[ mod_ldflags="$mod_ldflags -lc" ],
		[ fail=$fail" printf" ]
	)

	AC_CHECK_HEADER(stdio.h,
		[ mod_cflags="$mod_cflags -I/usr/include" ],
		[ fail=$fail" stdio.h" ]
	)

	AC_CHECK_HEADERS(stdio.h stdlib.h)
	AC_CHECK_FUNCS(printf)

	targetname=modname
else
	targetname=
	echo \*\*\* module modname is disabled.
fi

dnl  Don't change this section.
if test x"$fail" != x""; then
	if test x"${enable_strict_dependencies}" = x"yes"; then
		AC_MSG_ERROR([set --without-]modname[ to disable it explicitly.])
	else
		AC_MSG_WARN([silently not building ]modname[.])
		AC_MSG_WARN([FAILURE: ]modname[ requires: $fail.]);
		targetname=""
	fi
fi


AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_CONFIG_HEADER(config.h)

AC_SUBST(targetname)
AC_OUTPUT(all.mk)
