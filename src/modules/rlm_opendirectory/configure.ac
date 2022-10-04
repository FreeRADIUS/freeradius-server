AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_opendirectory.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_opendirectory], [OpenDirectory support])

FR_MODULE_START_TESTS

AC_PROG_CC
AC_PROG_CPP

mod_ldflags="${mod_ldflags} -F /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks -framework DirectoryService"

FR_SMART_CHECK_INCLUDE(membership.h)
if test "$ac_cv_header_membership_h" != "yes"; then
	FR_MODULE_FAIL([membership.h])
else
	AC_CHECK_DECLS(mbr_check_service_membership,
		[mod_cflags="${mod_cflags} -DHAVE_DECL_MBR_CHECK_SERVICE_MEMBERSHIP"],
		[],[#include <membership.h>])
	AC_CHECK_DECLS(mbr_check_membership_refresh,
		[mod_cflags="${mod_cflags} -DHAVE_DECL_MBR_CHECK_MEMBERSHIP_REFRESH"],
		[],[#include <membership.h>])
fi

FR_MODULE_END_TESTS

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
