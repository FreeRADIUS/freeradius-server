AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([base.c])
AC_REVISION($Revision$)
FR_INIT_LIBRARY([libfreeradius-curl], [libcurl support])

AC_CONFIG_HEADERS([config.h])

FR_LIBRARY_START_TESTS

	AC_PROG_CC
	AC_PROG_CPP

	dnl put configuration checks here.
	dnl set $fail to what's missing, on fatal errors.
	dnl use AC_MSG_WARN() on important messages.

	dnl ############################################################
	dnl # Check for curl
	dnl ############################################################

	dnl # Minimum version needed for SSL verification to work properly for rlm_smtp and rlm_imap
	LIBCURL_CHECK_CONFIG([], [7.24.0])

	if test "x$libcurl_cv_lib_version_ok" != "xyes"; then
		fail="$fail libcurl >= 7.24.0"
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

	version="$libcurl_cv_lib_curl_version"

FR_LIBRARY_END_TESTS

mod_ldflags="$LIBCURL"
mod_cflags="$LIBCURL_CPPFLAGS"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)
AC_SUBST(version)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
