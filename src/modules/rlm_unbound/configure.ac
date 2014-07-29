AC_PREREQ([2.53])
AC_INIT(rlm_unbound.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_unbound])

if test x$with_[]modname != xno; then
	dnl extra argument: --with-rlm-unbound-lib-dir
	rlm_unbound_lib_dir=
	AC_ARG_WITH(rlm-unbound-lib-dir,
	[  --with-rlm-unbound-lib-dir=DIR       directory for libunbound library files []],
	[ case "$withval" in
	    no)
		AC_MSG_ERROR(Need rlm-unbound-lib-dir)
		;;
	    yes)
		;;
	    *)
		rlm_unbound_lib_dir="$withval"
		;;
	  esac ]
	)

	dnl extra argument: --with-rlm-unbound-include-dir
	rlm_unbound_include_dir=
	AC_ARG_WITH(rlm-unbound-include-dir,
	[  --with-rlm-unbound-include-dir=DIR   directory for libunbound include files []],
	[ case "$withval" in
	    no)
		AC_MSG_ERROR(Need rlm-unbound-include-dir)
		;;
	    yes)
		;;
	    *)
		rlm_unbound_include_dir="$withval"
		;;
	  esac ]
	)

	smart_try_dir=$rlm_unbound_lib_dir
	FR_SMART_CHECK_LIB(unbound, ub_ctx_create)
	if test "x$ac_cv_lib_unbound_ub_ctx_create" != "xyes"; then
		fail="$fail libunbound"
	fi

	smart_try_dir=$rlm_unbound_include_dir
	FR_SMART_CHECK_INCLUDE(unbound.h)
	if test "$ac_cv_header_unbound_h" != "yes"; then
		fail="$fail unbound.h"
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

mod_ldflags="${SMART_LIBS}"
mod_cflags="${SMART_CFLAGS}"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_CONFIG_HEADER(config.h)

AC_SUBST(targetname)
AC_OUTPUT(all.mk)
