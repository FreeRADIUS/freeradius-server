AC_PREREQ([2.53])
AC_INIT(rlm_ldap.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_ldap])

fail=
SMART_LIBS=
SMART_CLFAGS=
if test x$with_[]modname != xno; then

	dnl ############################################################
	dnl # Check for compiler
	dnl ############################################################
	AC_PROG_CC

	dnl ############################################################
	dnl # Check for command line options
	dnl ############################################################

	dnl # extra argument: --with-rlm-ldap-lib-dir
	rlm_ldap_lib_dir=
	AC_ARG_WITH(rlm-ldap-lib-dir,
	[  --with-rlm-ldap-lib-dir=DIR       directory for LDAP library files []],
	[ case "$withval" in
	    no)
		AC_MSG_ERROR(Need rlm-ldap-lib-dir)
		;;
	    yes)
		;;
	    *)
		rlm_ldap_lib_dir="$withval"
		;;
	  esac ]
	)

	dnl # extra argument: --with-rlm-ldap-include-dir
	rlm_ldap_include_dir=
	AC_ARG_WITH(rlm-ldap-include-dir,
	[  --with-rlm-ldap-include-dir=DIR   directory for LDAP include files []],
	[ case "$withval" in
	    no)
		AC_MSG_ERROR(Need rlm-ldap-include-dir)
		;;
	    yes)
		;;
	    *)
		rlm_ldap_include_dir="$withval"
		;;
	  esac ]
	)

	dnl # extra argument: --with-threads
	rlm_ldap_with_threads=yes
	AC_ARG_WITH(threads,
	[  --with-threads          use threads, if available. (default=yes) ],
	[ case "$withval" in
	    no)
		rlm_ldap_with_threads=no
		;;
	    *)
		;;
	    esac ])

	dnl ############################################################
	dnl # Check for libraries
	dnl ############################################################

	dnl # Try "-lldap_r" or "-lldap"
	smart_try_dir=$rlm_ldap_lib_dir
    FR_SMART_CHECK_LIB(ldap_r, ldap_init)
    if test "x$ac_cv_lib_ldap_r_ldap_init" != "xyes"; then
        FR_SMART_CHECK_LIB(ldap, ldap_init)
        if test "x$ac_cv_lib_ldap_ldap_init" != "xyes"; then
            fail="$fail libldap"
        fi
    fi

	dnl ############################################################
	dnl # Check for header files
	dnl ############################################################

	smart_try_dir=$rlm_ldap_include_dir
	FR_SMART_CHECK_INCLUDE(ldap.h)
	if test "$ac_cv_header_ldap_h" != "yes"; then
	  fail="$fail ldap.h"
	fi

	dnl ############################################################
	dnl # Check for library functions
	dnl ############################################################

	if test "x$fail" = "x"; then
	    AC_CHECK_FUNCS(
	        ldap_sasl_bind \
	        ldap_unbind_ext_s \
	        ldap_start_tls_s \
	        ldap_initialize \
	        ldap_set_rebind_proc \
	    )
        AC_CACHE_CHECK(whether ldap_set_rebind_proc takes 3 arguments, ac_cv_ldap_set_rebind_proc, [
            AC_TRY_COMPILE([
                #include <lber.h>
                #include <ldap.h>], [ldap_set_rebind_proc(0, 0, 0);],
                [ac_cv_ldap_set_rebind_proc=3],
                [ac_cv_ldap_set_rebind_proc=2])
        ])
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
		AC_MSG_WARN([FAILURE: ]modname[ requires: $fail.])
		if test x"$headersuggestion" != x; then
			AC_MSG_WARN([$headersuggestion])
		fi
		if test x"$libsuggestion" != x; then
			AC_MSG_WARN([$libsuggestion])
		fi
		targetname=""
	fi
fi

AC_DEFINE(WITH_EDIR, 1, [Build the server with support for Novell eDir Universal Password])
AC_DEFINE(LDAP_DEPRECATED, 1, [Expose deprecated libldap functions])
AC_DEFINE_UNQUOTED(LDAP_SET_REBIND_PROC_ARGS, ${ac_cv_ldap_set_rebind_proc}, [Number of arguments the rebind procedure takes])

mod_ldflags=$SMART_LIBS
mod_cflags="$SMART_CPPFLAGS"
AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)
AC_SUBST(targetname)
AC_CONFIG_HEADER(config.h)
AC_OUTPUT(all.mk)
