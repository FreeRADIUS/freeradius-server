AC_PREREQ([2.71])
AC_INIT
AC_CONFIG_SRCDIR([rlm_eap.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_eap], [EAP functionality])

SMART_LIBS=
SMART_CLFAGS=
eapsubdirs=

FR_MODULE_START_TESTS

AC_PROG_CC

for foo in `find ./types -name configure -print`; do
  bar=`echo $foo | sed 's%/configure$%%g'`
  eapsubdirs="$eapsubdirs $bar"
done

dnl # don't ask... this is done to avoid autoconf stupidities.
ln -s ../../../install-sh install-sh

AC_CONFIG_SUBDIRS($eapsubdirs)
rm install-sh

FR_MODULE_END_TESTS

FR_MODULE_TEST_FAIL_DO([eapsubdirs=""])

eaptypes=types
if test x"$eapsubdirs" = x""; then
	eaptypes=""
fi

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(eaptypes)
AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_OUTPUT
