AC_PREREQ([2.53])
AC_INIT(rlm_pam.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_pam])
AC_DEFUN(modname_useropt,[m4_bpatsubst([]modname,[[-+.]],[_])])

AC_ARG_WITH([]modname,
[AS_HELP_STRING([--without-[]modname],[build without module])]
)

if test x$with_[]modname != xno; then

	AC_PROG_CC
	AC_PROG_CPP

	AC_CHECK_LIB(dl, dlopen,
		[ mod_ldflags="-ldl" ]
	)

	AC_CHECK_LIB(pam, pam_start,
		[ mod_ldflags="-lpam $mod_ldflags" ],
		[ fail=$fail" libpam" ],
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

	targetname=modname
else
	targetname=
	echo \*\*\* module modname is disabled.
fi

if test x"$fail" != x""; then
	if test x"${enable_strict_dependencies}" = x"yes"; then
		AC_MSG_ERROR([set --without-]modname[ to disable it explicitly.])
	else
		AC_MSG_WARN([silently not building ]modname[.])
		AC_MSG_WARN([FAILURE: ]modname[ requires: $fail.]);
		targetname=""
	fi
fi

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)
AC_SUBST(targetname)
AC_CONFIG_HEADER(config.h)
AC_OUTPUT(all.mk)
