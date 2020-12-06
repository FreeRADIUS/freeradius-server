AC_PREREQ([2.53])
AC_INIT(rlm_smtp.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_smtp])
m4_include([../../lib/curl/m4/libcurl_check_config.m4])

if test x$with_[]modname != xno; then

	AC_PROG_CC
	AC_PROG_CPP

	dnl put configuration checks here.
	dnl set $fail to what's missing, on fatal errors.
	dnl use AC_MSG_WARN() on important messages.

	dnl ############################################################
	dnl # Check for curl >= 7.56.0
	dnl ############################################################

	dnl # Minimum version needed for SSL verification to work properly for rlm_smtp and rlm_imap
	LIBCURL_CHECK_CONFIG([], [7.56.0])

	if test "x$libcurl_cv_lib_version_ok" != "xyes"; then
		fail="$fail libcurl >= 7.56.0"
	fi

	dnl # cURL usability checks and setting of build flags is performed by libfreeradius-curl AC

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

AC_SUBST(targetname)
AC_OUTPUT(all.mk)
