dnl Process this file with autoconf to create configure.

AC_INIT(ltdl.c)

dnl We shouldn't be using these internal macros of autoconf,
dnl but CONFIG_AUX_DIR($with_auxdir) breaks automake.
AC_ARG_WITH(auxdir,
[  --with-auxdir=DIR   path to autoconf auxiliary files],
[AC_CONFIG_AUX_DIRS($with_auxdir)],
[AC_CONFIG_AUX_DIR_DEFAULT])

if test -z "$enable_ltdl_install$enable_ltdl_convenience"; then
  if test -f ${srcdir}/ltmain.sh; then
    # if libltdl is libtoolized, it is assumed to be stand-alone and
    # installed unless the command line overrides it (tested above)
    enable_ltdl_install=yes
  else
    AC_MSG_WARN([*** The top-level configure must select either])
    AC_MSG_WARN([*** [A""C_LIBLTDL_INSTALLABLE] or [A""C_LIBLTDL_CONVENIENCE].])
    AC_MSG_ERROR([*** Maybe you want to --enable-ltdl-install?])
  fi
fi

AM_INIT_AUTOMAKE(libltdl,1.2,-)
AM_CONFIG_HEADER(config.h:config-h.in)
AM_MAINTAINER_MODE

AC_PROG_CC
AC_C_CONST
AC_C_INLINE

AC_LIBTOOL_WIN32_DLL
AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

AC_LIB_LTDL

dnl Output the makefile
AC_OUTPUT(Makefile)

# Local Variables:
# mode:shell-script
# sh-indentation:2
# End:
