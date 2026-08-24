AC_PREREQ([2.73])
AC_INIT
AC_CONFIG_SRCDIR([rlm_cache.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_cache], [module to cache attributes])

SMART_LIBS=
SMART_CLFAGS=

FR_MODULE_START_TESTS

AC_PROG_CC

mysubdirs=
if test "x$EXPERIMENTAL" = "xyes"; then
	for foo in `find ./drivers -name configure -print`; do
		bar=`echo $foo | sed 's%/configure$%%g'`
		mysubdirs="$mysubdirs $bar"
	done
else
	for foo in `cat stable`; do
		mysubdirs="$mysubdirs ./drivers/$foo"
	done
fi

dnl # don't ask... this is done to avoid autoconf stupidities.
ln -s ../../../install-sh install-sh

AC_CONFIG_SUBDIRS($mysubdirs)

dnl #
dnl #  No driver's sub-configure script depends on another, so
dnl #  AX_CONFIG_SUBDIRS_PARALLEL runs the driver sub-configure scripts at the
dnl #  same time. See m4/ax_config_subdirs_parallel.m4.
dnl #
AX_CONFIG_SUBDIRS_PARALLEL

rm install-sh

FR_MODULE_END_TESTS([nostrict])

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
