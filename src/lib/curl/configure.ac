AC_PREREQ([2.53])
AC_INIT(base.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[libfreeradius-curl])
AC_CONFIG_HEADER(config.h)
m4_include([m4/libcurl_check_config.m4])

if test x$with_[]modname != xno; then

	AC_PROG_CC
	AC_PROG_CPP

	dnl put configuration checks here.
	dnl set $fail to what's missing, on fatal errors.
	dnl use AC_MSG_WARN() on important messages.

	dnl ############################################################
	dnl # Check for curl
	dnl ############################################################

	LIBCURL_CHECK_CONFIG([], [7.19.1])

	if test "x$libcurl_cv_lib_version_ok" != "xyes"; then
		fail="$fail libcurl >= 7.19.2"
	elif test "x$libcurl_cv_lib_curl_usable" != "xyes"; then
		fail="$fail libcurl"
	else
		if test x$libcurl_protocol_HTTP != xyes; then
			fail="$fail libcurl_protocol_http"
		fi

		if test x$libcurl_protocol_HTTPS != xyes || test x$libcurl_feature_SSL != xyes; then
			AC_MSG_WARN([silently building without HTTPS support. requires: libcurl_protocol_https.])
		else
			AC_MSG_NOTICE([curl-config's cflags were \"${LIBCURL_CPPFLAGS}\"])
			LIBCURL_CPPFLAGS=$(echo "$LIBCURL_CPPFLAGS" | sed 's/-I[ ]*/-isystem /g')
			AC_MSG_NOTICE([Sanitized cflags are \"$(echo "${LIBCURL_CPPFLAGS}" | sed 's/-I[ ]*/-isystem /g')\"])
		fi
	fi

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

mod_ldflags="$LIBCURL"
mod_cflags="$LIBCURL_CPPFLAGS"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_SUBST(targetname)
AC_OUTPUT(all.mk)

