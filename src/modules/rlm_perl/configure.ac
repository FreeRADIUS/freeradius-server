AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_perl.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_perl], [support for embedded Perl functions])

FR_MODULE_START_TESTS

AC_PROG_CC
AC_PROG_CPP

AX_WITH_PROG([PERL],[perl],[not-found],[${PATH}:/usr/bin:/usr/local/bin])

if test "$PERL" = "not-found" -o ! -x "$PERL"; then
	FR_MODULE_FAIL([perl])
else
	old_CFLAGS="${CFLAGS}"
	old_LIBS="${LIBS}"
	
	dnl ############################################################
	dnl # Call ExtUtils::Embed to get compiler flags
	dnl ############################################################

	AC_MSG_NOTICE([Calling ExtUtils::Embed to get 'ccopts'])
	mod_cflags=$($PERL -MExtUtils::Embed -e ccopts)
	
	AC_MSG_NOTICE([ExtUtil's ccopts were \"${mod_cflags}\"])
	
	mod_cflags=[$(echo "$mod_cflags" | sed 's/-I[ ]*/-isystem /g' | sed 's/-arch [^ ]*//g;s/  / /g;s/^ *//;s/ *$//')]
	
	AC_MSG_NOTICE([Sanitized ccopts are \"${mod_cflags}\"])
	
	CFLAGS="${mod_cflags} ${CFLAGS}"
	
	dnl ############################################################
	dnl #  Call ExtUtils::Embed to get linker flags
	dnl ############################################################

	AC_MSG_NOTICE([Calling ExtUtils::Embed to get 'ldflags'])
	mod_ldflags=$($PERL -MExtUtils::Embed -e ldopts)
	
	AC_MSG_NOTICE([ExtUtil's ldopts were \"${mod_ldflags}\"])
	
	mod_ldflags=[$(echo "$mod_ldflags" | sed 's/-arch [^ ]*//g;s/  / /g;s/^ *//;s/ *$//')]
	
	AC_MSG_NOTICE([Sanitized ldopts are \"${mod_ldflags}\"])

	LIBS="${mod_ldflags} ${LIBS}"

	dnl ############################################################
	dnl #  Check required headers are available
	dnl ############################################################

	smart_try_dir=
	FR_SMART_CHECK_INCLUDE(EXTERN.h)
	if test "x$ac_cv_header_EXTERN_h" != "xyes"; then
		FR_MODULE_FAIL([EXTERN.h])
	fi

	FR_SMART_CHECK_INCLUDE(perl.h, [#include <EXTERN.h>])
	if test "x$ac_cv_header_perl_h" != "xyes"; then
		FR_MODULE_FAIL([EXTERN.h])
	fi

	dnl ############################################################
	dnl #  Link test functions
	dnl ############################################################

	AC_MSG_CHECKING([we can link to boot_DynaLoader])	
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[
		extern char boot_DynaLoader();
		boot_DynaLoader();
	]])],[LINKS="yes"],[LINKS="no"])

	AC_MSG_RESULT($LINKS)
	if test "x$LINKS" = "xno"; then
		FR_MODULE_FAIL([libperl.so])
	fi

	AC_MSG_CHECKING([we can link to Perl_hv_store()])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[
		extern char Perl_hv_store();
		Perl_hv_store();
	]])],[LINKS="yes"],[LINKS="no"])

	AC_MSG_RESULT($LINKS)
	if test "x$LINKS" = "xno"; then
		FR_MODULE_FAIL([libperl.so])
	fi

	CFLAGS="$old_CFLAGS"
	LIBS="$old_LIBS"
fi

FR_MODULE_END_TESTS

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
