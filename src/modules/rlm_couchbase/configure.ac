AC_PREREQ([2.53])
AC_INIT(rlm_couchbase.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_couchbase])
AC_CONFIG_HEADER(config.h)

AC_ARG_WITH([]modname,
[AS_HELP_STRING([--without-[]modname],[build without module])]
)

if test x$with_[]modname != xno; then

	AC_PROG_CC
	AC_PROG_CPP

	dnl put configuration checks here.
	dnl set $fail to what's missing, on fatal errors.
	dnl use AC_MSG_WARN() on important messages.

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
