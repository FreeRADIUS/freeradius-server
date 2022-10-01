AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([base.c])
AC_REVISION($Revision$)
FR_INIT_LIBRARY([libfreeradius-kafka], [rdkafka support])

SMART_LIBS=
SMART_CLFAGS=

FR_LIBRARY_START_TESTS

    dnl ############################################################
    dnl # Check for command line options
    dnl ############################################################

    dnl extra argument: --with-rdkafka-include-dir=DIR
    rdkafka_include_dir=
    AC_ARG_WITH(rdkafka-include-dir,
	[AS_HELP_STRING([--with-rdkafka-include-dir=DIR],
		[Directory where the rdkafka includes may be found])],
	[case "$withval" in
	    no)
		AC_MSG_ERROR(Need rdkafka-include-dir)
		;;
	    yes)
		;;
	    *)
		rdkafka_include_dir="$withval"
		;;
	esac])

    dnl extra argument: --with-rdkafka-lib-dir=DIR
    rdkafka_lib_dir=
    AC_ARG_WITH(rdkafka-lib-dir,
	[AS_HELP_STRING([--with-rdkafka-lib-dir=DIR],
		[Directory where the rdkafka libraries may be found])],
	[case "$withval" in
	    no)
		AC_MSG_ERROR(Need rdkafka-lib-dir)
		;;
	    yes)
		;;
	    *)
		rdkafka_lib_dir="$withval"
		;;
	esac])

    dnl extra argument: --with-rdkafka-dir=DIR
    AC_ARG_WITH(rdkafka-dir,
	[AS_HELP_STRING([--with-rdkafka-dir=DIR],
		[Base directory where rdkafka is installed])],
	[case "$withval" in
	    no)
		AC_MSG_ERROR(Need rdkafka-dir)
		;;
	    yes)
		;;
	    *)
		rdkafka_lib_dir="$withval/lib"
		rdkafka_include_dir="$withval/include"
		;;
	esac])

    dnl ############################################################
    dnl # Check for programs
    dnl ############################################################

    AC_PROG_CC

    dnl ############################################################
    dnl # Check for header files
    dnl ############################################################

    smart_try_dir="${rdkafka_include_dir}"
    FR_SMART_CHECK_INCLUDE([librdkafka/rdkafka.h])
    if test "x$ac_cv_header_librdkafka_rdkafka_h" != "xyes"; then
      AC_MSG_WARN([rdkafka headers not found. Use --with-rdkafka-include-dir=<path>.])
      fail="$fail rdkafka.h"
    fi

    dnl ############################################################
    dnl # Check for libraries
    dnl ############################################################

    smart_try_dir="$rdkafka_lib_dir"
    FR_SMART_CHECK_LIB(rdkafka, rd_kafka_version)
    if test "x$ac_cv_lib_rdkafka_rd_kafka_version" != "xyes"
    then
      AC_MSG_WARN([rdkafka libraries not found. Use --with-rdkafka-lib-dir=<path>.])
      fail="$fail libhirdkafka"
    fi

FR_LIBRARY_END_TESTS

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
