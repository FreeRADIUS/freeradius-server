AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_counter.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_counter])

FR_MODULE_START_TESTS

AC_PROG_CC
AC_PROG_CPP

FR_SMART_CHECK_INCLUDE(gdbm.h)
FR_SMART_CHECK_LIB(gdbm, gdbm_open)
if test "x$ac_cv_lib_gdbm_gdbm_open" != "xyes"; then
	FR_MODULE_FAIL([libgdbm])
fi

FR_MODULE_TEST_PASS_DO([
	AC_MSG_CHECKING(to see GDBM_SYNC status)
	AC_EGREP_CPP(found-gdbm-sync, [
#include <gdbm.h>
#ifdef GDBM_SYNC
	found-gdbm-sync!
#else
	not found.  this version must use sync by default.
#endif
		], [
		AC_DEFINE(NEED_GDBM_SYNC, yes, [do we need GDBM_SYNC])
		AC_MSG_RESULT(needs it.)
		], [
		AC_MSG_RESULT(SYNCs by default.)
		]
	)
])

old_LIBS=$LIBS
LIBS="$LIBS $SMART_LIBS"
AC_CHECK_FUNC(gdbm_fdesc)
if test "x$ac_cv_func_gdbm_fdesc" = "xyes";
then
	AC_DEFINE(HAVE_GDBM_FDESC, [], [do we have gdbm_fdesc])
fi
LIBS=$old_LIBS

FR_MODULE_END_TESTS

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
