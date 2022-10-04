AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_ruby.c])
AC_REVISION($Revision: 1.9 $)
FR_INIT_MODULE([rlm_ruby], [support for embedded Ruby functions])

mod_cflags=
mod_ldflags=

FR_MODULE_START_TESTS

AC_PROG_CC
AC_PROG_CPP

AX_WITH_PROG([RUBY],[ruby],[not-found],[${PATH}:/usr/bin:/usr/local/bin])

if test -n "$RUBY"; then
	AX_RUBY_DEVEL([1.8])

	if test -n "$RUBY_VERSION"; then
		mod_cflags=[$(echo "${RUBY_CFLAGS}" | sed 's/-I[ ]*/-isystem /g' | sed 's/-arch [^ ]*[ ]*//g')]

		AC_MSG_NOTICE([Sanitized cflags are \"${mod_cflags}\"])

		mod_ldflags="${RUBY_LDFLAGS} ${RUBY_EXTRA_LIBS}"
	else
		FR_MODULE_FAIL([ruby])
	fi
else
	FR_MODULE_FAIL([ruby])
fi

FR_MODULE_END_TESTS

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)
AC_SUBST(ruby_headers)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
