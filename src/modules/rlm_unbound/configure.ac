AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_unbound.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_unbound])

FR_MODULE_START_TESTS

dnl extra argument: --with-rlm-unbound-lib-dir
rlm_unbound_lib_dir=
AC_ARG_WITH(rlm-unbound-lib-dir,
	[AS_HELP_STRING([--with-rlm-unbound-lib-dir=DIR],
		[directory for libunbound library files])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need rlm-unbound-lib-dir)
		;;
	yes)
		;;
	*)
		rlm_unbound_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-rlm-unbound-include-dir
rlm_unbound_include_dir=
AC_ARG_WITH(rlm-unbound-include-dir,
	[AS_HELP_STRING([--with-rlm-unbound-include-dir=DIR],
		[directory for libunbound include files])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need rlm-unbound-include-dir)
		;;
	yes)
		;;
	*)
		rlm_unbound_include_dir="$withval"
		;;
	esac])

smart_try_dir=$rlm_unbound_lib_dir
FR_SMART_CHECK_LIB(unbound, ub_ctx_create)
if test "x$ac_cv_lib_unbound_ub_ctx_create" != "xyes"; then
	FR_MODULE_FAIL([libunbound])
fi

smart_try_dir=$rlm_unbound_include_dir
FR_SMART_CHECK_INCLUDE(unbound.h)
if test "$ac_cv_header_unbound_h" != "yes"; then
	FR_MODULE_FAIL([unbound.h])
fi

FR_MODULE_END_TESTS

mod_ldflags="${SMART_LIBS}"
mod_cflags="${SMART_CFLAGS}"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
