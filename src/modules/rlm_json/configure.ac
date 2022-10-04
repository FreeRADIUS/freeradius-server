AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_json.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_json], [JSON support from json-c])
AC_CONFIG_HEADER(config.h)

FR_MODULE_START_TESTS

AC_PROG_CC
AC_PROG_CPP

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
		FR_MODULE_FAIL([json.h])
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
if test "x$ac_cv_lib_json_c_json_c_version" != "xyes"
then
	dnl # Use a function which is included in legacy versions
	dnl # but which may be available in other json libraries
	FR_SMART_CHECK_LIB([json], [json_tokener_new])
	if test "x$ac_cv_lib_json_json_tokener_new" != "xyes"
	then
		have_json="no"
	fi
fi

if test "x$have_json" = "xyes"; then
	dnl # Ensure we use the library we just found the json of the checks
	LDFLAGS="$SMART_LIBS"

	dnl # Add any optional functions here
	AC_CHECK_FUNCS(\
		json_c_version \
		json_object_get_string_len \
		json_object_object_get_ex \
		json_object_object_add_ex \
		json_object_new_int64 \
		json_object_get_int64 \
		json_tokener_error_desc \
		json_tokener_get_error
	)
else
	AC_MSG_WARN([json-c libraries not found. Use --with-jsonc-lib-dir=<path>.])
	AC_MSG_WARN([silently building without JSON support. requires: json-c])
	FR_MODULE_FAIL([json-c])
fi

FR_MODULE_END_TESTS

FR_MODULE_TEST_PASS_DO([
    AC_DEFINE([HAVE_JSON],[1],[Build with JSON support from json-c])
])

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
