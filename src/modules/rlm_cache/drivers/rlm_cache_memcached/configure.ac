AC_PREREQ([2.53])
AC_INIT(rlm_cache_memcached.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_cache_memcached])

if test x$with_[]modname != xno; then

	AC_PROG_CC
	AC_PROG_CPP

	dnl put configuration checks here.
	dnl set $fail to what's missing, on fatal errors.
	dnl use AC_MSG_WARN() on important messages.

	dnl ############################################################
	dnl # Check for libmemcached
	dnl ############################################################

	dnl extra argument: --with-libmemcached-include-dir=DIR
	libmemcached_include_dir=
	AC_ARG_WITH(libmemcached-include-dir,
		[AS_HELP_STRING([--with-libmemcached-include-dir=DIR],
		[Directory where the libmemcached includes may be found])],
		[case "$withval" in
		    no)
			AC_MSG_ERROR(Need libmemcached-include-dir)
		    ;;
			yes)
		    ;;
		    *)
			libmemcached_include_dir="$withval"
		    ;;
		esac])

	dnl extra argument: --with-libmemcached-lib-dir=DIR
	libmemcached_lib_dir=
	AC_ARG_WITH(libmemcached-lib-dir,
	[AS_HELP_STRING([--with-libmemcached-lib-dir=DIR],
		[Directory where the libmemcached libraries may be found])],
		[case "$withval" in
		    no)
			AC_MSG_ERROR(Need libmemcached-lib-dir)
			;;
		    yes)
			;;
		    *)
			libmemcached_lib_dir="$withval"
			;;
		esac])

	dnl extra argument: --with-libmemcached-dir=DIR
	AC_ARG_WITH(libmemcached-dir,
	[AS_HELP_STRING([--with-libmemcached-dir=DIR],
		[Base directory where libmemcached is installed])],
		[case "$withval" in
		    no)
			AC_MSG_ERROR(Need libmemcached-dir)
			;;
		    yes)
			;;
		    *)
			libmemcached_lib_dir="$withval/lib"
			libmemcached_include_dir="$withval/include"
			;;
		esac])


	dnl ############################################################
	dnl # Check for libmemcached header files
	dnl ############################################################

	have_json="yes"
	smart_try_dir="$libmemcached_include_dir"
	FR_SMART_CHECK_INCLUDE([libmemcached/memcached.h])
	if test "x$ac_cv_header_libmemcached_memcached_h" != "xyes"; then
		AC_MSG_WARN([libmemcached headers not found. Use --with-libmemcached-include-dir=<path>.])
		fail='memcached.h'
	fi

	dnl ############################################################
	dnl # Check for libmemcached libraries
	dnl ############################################################

    dnl # Check if libpthread is available. Should add -lpthread
    dnl # to CFLAGS when checking for memcached.
    FR_SMART_CHECK_LIB([pthread], [pthread_once])

	smart_try_dir="$libmemcached_lib_dir"
	dnl # Use a libmemcached specific function which is only
	dnl # available in newer versions.
	FR_SMART_CHECK_LIB([memcached], [memcached])
	if test "x$ac_cv_lib_memcached_memcached" != "xyes"
	then
		AC_MSG_WARN([libmemcached libraries not found. Use --with-libmemcached-lib-dir=<path>.])
		fail="libmemcached $fail"
	else
		AC_CHECK_FUNCS(\
            memcached \
            memcached_free \
            memcached_get \
            memcached_set \
            memcached_delete \
            libmemcached_check_configuration \
        ,, [fail="memached functions"])
	fi

	targetname=modname
else
	targetname=
	echo \*\*\* module modname is disabled.
fi

dnl  Don't change this section.
if test x"$fail" != x""; then
	if test x"${enable_strict_dependencies}" = x"yes"; then
		AC_MSG_ERROR([set --without-]modname[ to disable it explicitly.])
	else
		AC_MSG_WARN([silently not building ]modname[.])
		AC_MSG_WARN([FAILURE: ]modname[ requires: $fail.]);
		targetname=""
	fi
fi

mod_ldflags="$LIBCURL $SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_SUBST(targetname)
AC_OUTPUT(all.mk)
