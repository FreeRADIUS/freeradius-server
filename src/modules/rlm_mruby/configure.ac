AC_INIT(rlm_mruby.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_mruby])

AC_ARG_WITH([]modname,
[AS_HELP_STRING([--without-[]modname],[build without module])]
)

if test x$with_[]modname != xno; then
	AC_PROG_CC
	AC_PROG_CPP

	dnl ############################################################
	dnl # Check for command line options
	dnl ############################################################

	dnl extra argument: --with-mruby-include-dir=DIR
	mruby_include_dir=
	AC_ARG_WITH(mruby-incude-dir,
		[AS_HELP_STRING([--with-mruby-include-dir=DIR],
			[Directory where the mruby includes may be found])],
		[case "$withval" in
			no)
				AC_MSG_ERROR(Need mruby-include-dir)
				;;
			yes)
				;;
			*)
				mruby_include_dir="$withval"
				;;
		esac])

	dnl extra argument: --with-mruby-lib-dir=DIR
	mruby_lib_dir=
	AC_ARG_WITH(mruby-lib-dir,
		[AS_HELP_STRING([--with-mruby-lib-dir=DIR],
			[Directory where the mruby libraries may be found])],
		[case "$withval" in
			no)
				AC_MSG_ERROR(Need mruby-lib-dir)
				;;
			yes)
				;;
			*)
				mruby_lib_dir="$withval"
			;;
		esac])

	dnl extra argument: --with-mruby-dir=DIR
	AC_ARG_WITH(mruby-dir,
		[AS_HELP_STRING([--with-mruby-dir=DIR],
			[Base directory where mruby is installed])],
		[case "$withval" in
			no)
				AC_MSG_ERROR(Need mruby-dir)
				;;
			yes)
				;;
			*)
				mruby_lib_dir="$withval/lib"
				mruby_include_dir="$withval/include"
				;;
		esac])

	dnl ############################################################
	dnl # Check for header files
	dnl ############################################################

	smart_try_dir="$mruby_include_dir /usr/include"
	FR_SMART_CHECK_INCLUDE(mruby.h, [])
	if test "x$ac_cv_header_mruby_h" != "xyes"; then
		AC_MSG_WARN([mruby.h not found. Use --with-mruby-include-dir=<path>.])
		fail="$fail mruby.h"
	fi

	FR_SMART_CHECK_INCLUDE(mruby/compile.h, [#include <mruby.h>])
	if test "x$ac_cv_header_mruby_compile_h" != "xyes"; then
		AC_MSG_WARN([mruby/compile.h not found. Use --with-mruby-include-dir=<path>.])
		fail="$fail mruby/compile.h"
	fi

	FR_SMART_CHECK_INCLUDE(mruby/array.h, [#include <mruby.h>])
	if test "x$ac_cv_header_mruby_array_h" != "xyes"; then
		AC_MSG_WARN([mruby/array.h not found. Use --with-mruby-include-dir=<path>.])
		fail="$fail mruby/array.h"
	fi

	old_LIBS=$LIBS
	LIBS="$LIBS -lmruby -lm"
	smart_try_dir="$mruby_lib_dir /usr/lib"
	FR_SMART_CHECK_LIB(mruby, mrb_run)
	LIBS=$old_LIBS
	if test "x$ac_cv_lib_mruby_mrb_run" = "xyes"; then
		mod_ldflags="${SMART_LIBS}"
	else
		AC_MSG_WARN([mruby libraries not found. Use --with-mruby-lib-dir=<path>.])
		fail="$fail libmruby"
	fi

	FR_SMART_CHECK_LIB(m, fmod)
	if test "x$ac_cv_lib_m_fmod" = "xyes"; then
		mod_ldflags="${mod_ldflags} ${SMART_LIBS}"
	else
		AC_MSG_WARN([m library not found.])
		fail="$fail libm"
	fi

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

mod_cflags="${SMART_CPPFLAGS}"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_SUBST(targetname)
AC_OUTPUT(all.mk)
