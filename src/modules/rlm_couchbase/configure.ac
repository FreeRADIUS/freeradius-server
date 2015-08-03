AC_PREREQ([2.53])
AC_INIT(rlm_couchbase.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_couchbase])
AC_CONFIG_HEADER(config.h)

if test x$with_[]modname != xno; then

	AC_PROG_CC
	AC_PROG_CPP

	dnl put configuration checks here.
	dnl set $fail to what's missing, on fatal errors.
	dnl use AC_MSG_WARN() on important messages.

	dnl ############################################################
	dnl # Check for json-c
	dnl ############################################################

	dnl extra argument: --with-jsonc-include-dir=DIR
	jsonc_include_dir=
	AC_ARG_WITH(jsonc-include-dir,
		[AS_HELP_STRING([--with-jsonc-include-dir=DIR],
		[Directory where the json-c includes may be found])],
		[case "$withval" in
			no)
				AC_MSG_ERROR(Need jsonc-include-dir)
			;;
			yes)
			;;
			*)
				jsonc_include_dir="$withval"
			;;
		esac])

	dnl extra argument: --with-jsonc-lib-dir=DIR
	jsonc_lib_dir=
	AC_ARG_WITH(jsonc-lib-dir,
	[AS_HELP_STRING([--with-jsonc-lib-dir=DIR],
		[Directory where the json-c libraries may be found])],
		[case "$withval" in
			no)
				AC_MSG_ERROR(Need jsonc-lib-dir)
			;;
			yes)
			;;
			*)
				jsonc_lib_dir="$withval"
			;;
		esac])

	dnl extra argument: --with-jsonc-dir=DIR
	AC_ARG_WITH(jsonc-dir,
	[AS_HELP_STRING([--with-jsonc-dir=DIR],
		[Base directory where json-c is installed])],
		[case "$withval" in
			no)
				AC_MSG_ERROR(Need json-c-dir)
			;;
			yes)
			;;
			*)
				jsonc_lib_dir="$withval/lib"
				jsonc_include_dir="$withval/include"
			;;
		esac])

	dnl ############################################################
	dnl # Check for json-c header files
	dnl ############################################################

	have_json="yes"
	smart_try_dir="$jsonc_include_dir"
	FR_SMART_CHECK_INCLUDE([json/json.h])
	if test "x$ac_cv_header_json_json_h" != "xyes"; then
		FR_SMART_CHECK_INCLUDE([json-c/json.h])
		if test "x$ac_cv_header_jsonmc_json_h" != "xyes"; then
			have_json="no"
			AC_MSG_WARN([json-c headers not found. Use --with-jsonc-include-dir=<path>.])
			fail="$fail json.h"
		else
			AC_DEFINE([HAVE_JSONMC_JSON_H],[1],[json.h is at json-c/json.h relative to include dir])
		fi
	else
		AC_DEFINE([HAVE_JSON_JSON_H],[1],[json.h is at json/json.h relative to include dir])
	fi

	dnl ############################################################
	dnl # Check for json-c libraries
	dnl ############################################################

	smart_try_dir="$jsonc_lib_dir"
	dnl # Use a json-c specific function which is only
	dnl # available in newer versions.
	FR_SMART_CHECK_LIB([json-c], [json_c_version])
	if test "x$ac_cv_lib_json_c_json_c_version" != "xyes"; then
		dnl # Use a function which is included in legacy versions
		dnl # but which may be available in other json libraries
		FR_SMART_CHECK_LIB([json], [json_tokener_new])
		if test "x$ac_cv_lib_json_json_tokener_new" != "xyes"; then
			have_json="no"
			AC_MSG_WARN([json-c libraries not found. Use --with-jsonc-lib-dir=<path>.])
		fi
	fi

	if test "x$have_json" = "xyes"; then
		dnl # Ensure we use the library we just found the rest of the checks
		LDFLAGS="$SMART_LIBS"

		dnl # Add any optional functions here
		AC_CHECK_FUNCS(\
			json_c_version \
			json_object_get_string_len \
			json_object_object_get_ex \
			json_object_new_int64 \
			json_tokener_error_desc \
			json_tokener_get_error
		)
	else
		fail="$fail json-c"
	fi

	dnl ############################################################
	dnl # Check for libcouchbase
	dnl ############################################################

	dnl extra argument: --with-libcouchbase-include-dir=DIR
	libcouchbase_include_dir=
	AC_ARG_WITH(libcouchbase-include-dir,
		[AS_HELP_STRING([--with-libcouchbase-include-dir=DIR],
		[Directory where the libcouchbase includes may be found])],
		[case "$withval" in
			no)
				AC_MSG_ERROR(Need libcouchbase-include-dir)
			;;
			yes)
			;;
			*)
				libcouchbase_include_dir="$withval"
			;;
		esac])

	dnl extra argument: --with-libcouchbase-lib-dir=DIR
	libcouchbase_lib_dir=
	AC_ARG_WITH(libcouchbase-lib-dir,
	[AS_HELP_STRING([--with-libcouchbase-lib-dir=DIR],
		[Directory where the libcouchbase libraries may be found])],
		[case "$withval" in
			no)
				AC_MSG_ERROR(Need libcouchbase-lib-dir)
			;;
			yes)
			;;
			*)
				libcouchbase_lib_dir="$withval"
			;;
		esac])

	dnl extra argument: --with-libcouchbase-dir=DIR
	AC_ARG_WITH(libcouchbase-dir,
	[AS_HELP_STRING([--with-libcouchbase-dir=DIR],
		[Base directory where libcouchbase is installed])],
		[case "$withval" in
			no)
				AC_MSG_ERROR(Need libcouchbase-dir)
			;;
			yes)
			;;
			*)
				libcouchbase_lib_dir="$withval/lib"
				libcouchbase_include_dir="$withval/include"
			;;
		esac])

	dnl ############################################################
	dnl # Check for libcouchbase header files
	dnl ############################################################

	have_couchbase="yes"
	smart_try_dir="$libcouchbase_include_dir"
	FR_SMART_CHECK_INCLUDE([libcouchbase/couchbase.h])
	if test "x$ac_cv_header_libcouchbase_couchbase_h" != "xyes"; then
		have_couchbase="no"
		AC_MSG_WARN([libcouchbase headers not found. Use --with-libcouchbase-include-dir=<path>.])
	fi

	dnl ############################################################
	dnl # Check for libcouchbase libraries
	dnl ############################################################

	smart_try_dir="$libcouchbase_lib_dir"
	FR_SMART_CHECK_LIB([couchbase], [lcb_get_version])
	if test "x$ac_cv_lib_couchbase_lcb_get_version" != "xyes"; then
		have_couchbase="no"
		AC_MSG_WARN([libcouchbase libraries not found. Use --with-libcouchbase-lib-dir=<path>.])
	fi

	if test x"$have_couchbase" != x"yes"; then
		fail="$fail libcouchbase"
	fi

	dnl ############################################################
	dnl # Checks done - set targetname
	dnl ############################################################

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

mod_ldflags="${SMART_LIBS}"
mod_cflags="${SMART_CPPFLAGS}"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_SUBST(targetname)
AC_OUTPUT(all.mk)
