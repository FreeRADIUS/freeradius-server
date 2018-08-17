AC_PREREQ([2.53])
AC_INIT(rlm_krb5.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_krb5])

if test x$with_[]modname != xno; then

	AC_PROG_CC
	AC_PROG_CPP

	dnl extra argument: --with-rlm-krb5-dir
	rlm_krb5_dir=
	AC_ARG_WITH(rlm-krb5-dir,
	[  --with-rlm-krb5-dir=DIR       Directory for krb5 files []],
	[ case "$withval" in
	    no)
		AC_MSG_ERROR(Need rlm-krb5-dir)
		;;
	    yes)
		;;
	    *)
		rlm_krb5_dir="$withval"
		;;
	  esac ]
	)

	AC_PATH_PROG(krb5_config, krb5-config, not-found, [${rlm_krb5_dir}/bin:${PATH}:/usr/bin:/usr/local/bin])
	dnl #
	dnl # If we can find krb5-config we can get the version of the library and determine
	dnl # whether it's safe to enable threading.
	dnl #
	if test "$krb5_config" != 'not-found'; then
		AC_MSG_CHECKING([krb5-config CFLAGS])
		SMART_CPPFLAGS=$($krb5_config --cflags)
		SMART_CPPFLAGS=[$(echo "$SMART_CPPFLAGS" | sed 's/-I[ ]*/-isystem /g')]
		AC_MSG_RESULT("$SMART_CPPFLAGS")

		AC_MSG_CHECKING([krb5-config LDFLAGS])
		SMART_LIBS=$($krb5_config --libs)
		AC_MSG_RESULT(${SMART_LIBS})

		AC_MSG_CHECKING([krb5-config reported version])
		krb5_version_raw=$($krb5_config --version)

		dnl # AWK originally from from https://github.com/hpc/lustre
		krb5_version=$(echo "$krb5_version_raw" | head -n 1 | \
			awk '{split($(4),v,"."); if (v@<:@"3"@:>@ = "") v@<:@"3"@:>@ = "0"; print v@<:@"1"@:>@v@<:@"2"@:>@v@<:@"3"@:>@ }')
		AC_MSG_RESULT([${krb5_version_raw} ($krb5_version)])

		AC_MSG_CHECKING([krb5-config reported vendor])
		krb5_vendor=$($krb5_config --vendor)
		AC_MSG_RESULT([${krb5_vendor}])

		AC_MSG_CHECKING([canonical API type])
		if test "$krb5_vendor" = "Massachusetts Institute of Technology" || \
			echo "$krb5_vendor" | grep -i 'MIT' > /dev/null 2>&1 || \
			echo "$krb5_version_raw" | grep -i 'MIT' > /dev/null 2>&1 ; then
			AC_MSG_RESULT([MIT])
			krb5_api_type='mit'
		else
			AC_MSG_RESULT([HEIMDAL])
			krb5_api_type='heimdal'
		fi
	else
		smart_try_dir="$rlm_krb5_dir/include"
		FR_SMART_CHECK_INCLUDE(krb5.h)
		if test "$ac_cv_header_krb5_h" != "yes"; then
			fail="$fail krb5.h"
		fi

		krb5libcrypto=
		smart_try_dir="$rlm_krb5_dir/lib"
		FR_SMART_CHECK_LIB(k5crypto, krb5_encrypt_data)
		if test "x$ac_cv_lib_k5crypto_krb5_encrypt_data" = xyes; then
			krb5libcrypto="-lk5crypto"
		fi

		if test "x$krb5libcrypto" = x; then
			FR_SMART_CHECK_LIB(crypto, DH_new)
			if test "x$ac_cv_lib_crypto_DH_new" = xyes; then
				krb5libcrypto="-lcrypto"
			fi
		fi

		if test "x$krb5libcrypto" = x; then
			AC_MSG_WARN([neither krb5 'k5crypto' nor 'crypto' libraries are found!])
		fi

		FR_SMART_CHECK_LIB(com_err, set_com_err_hook)
		if test "x$ac_cv_lib_com_err_set_com_err_hook" != xyes; then
			AC_MSG_WARN([the comm_err library isn't found!])
		fi

		dnl #
		dnl # Only the heimdal version of the library has this function
		dnl #
		FR_SMART_CHECK_LIB(krb5, krb5_verify_user_opt)
		if test "x$ac_cv_lib_krb5_krb5_verify_user_opt" = xyes; then
			krb5_api_type='heimdal'
		else
			krb5_api_type='mit'

			FR_SMART_CHECK_LIB(krb5, krb5_get_init_creds_password)
			if test "x$ac_cv_lib_krb5_krb5_get_init_creds_password" != xyes; then
			    fail="$fail krb5"
			fi
		fi

	fi

	dnl #
	dnl # Need to ensure the test program(s) link against the right library
	dnl #
	LDFLAGS="${LDFLAGS} ${SMART_LIBS}"
	CFLAGS="${CFLAGS} ${SMART_CPPFLAGS}"

	dnl #
	dnl # Check how to free things returned by krb5_get_error_message
	dnl #
	AC_CHECK_FUNCS([krb5_get_error_message krb5_free_error_string krb5_free_error_message])
	if test "x$ac_cv_func_krb5_get_error_message" = xyes; then
		krb5mod_cflags="${krb5mod_cflags} -DHAVE_KRB5_GET_ERROR_MESSAGE"
	fi
	if test "x$ac_cv_func_krb5_free_error_message" = xyes; then
		krb5mod_cflags="${krb5mod_cflags} -DHAVE_KRB5_FREE_ERROR_MESSAGE"
	fi
	if test "x$ac_cv_func_krb5_free_error_string" = xyes; then
		krb5mod_cflags="${krb5mod_cflags} -DHAVE_KRB5_FREE_ERROR_STRING"
	fi

	dnl #
	dnl # Only check if version checks have not found kerberos to be thread unsafe
	dnl #
	if test "$krb5threadsafe" != "no"; then
		krb5threadsafe=

		FR_SMART_CHECK_LIB(krb5, krb5_is_thread_safe)
		if test "x$ac_cv_lib_krb5_krb5_is_thread_safe" = xyes; then
			AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <krb5.h>]], [[return krb5_is_thread_safe() ? 0 : 1]])],
				[krb5threadsafe="-DKRB5_IS_THREAD_SAFE"], [AC_MSG_WARN([[libkrb5 is not threadsafe]])])
		fi
	else
		krb5threadsafe=""
	fi

	if test "$krb5_api_type" = "mit"; then
		dnl #
		dnl # This lives in different places depending on the distro
		dnl #
		FR_SMART_CHECK_INCLUDE([com_err.h])
		if test "$ac_cv_header_com_err_h" != "yes"; then
			FR_SMART_CHECK_INCLUDE([et/com_err.h])
			if test "$ac_cv_header_et_com_err_h" != "yes"; then
				fail="$fail com_err.h"
			else
				krb5mod_cflags="$krb5mod_cflags -DET_COMM_ERR "
			fi
		fi
	else
		krb5mod_cflags="$krb5mod_cflags -DHEIMDAL_KRB5"
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
		AC_MSG_WARN([FAILURE: ]modname[ requires: $fail.]);
		targetname=""
	fi
fi

mod_ldflags="$krb5mod_ldflags $krb5libcrypto $SMART_LIBS"
mod_cflags="$krb5mod_cflags $krb5threadsafe $SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)
AC_SUBST(targetname)
AC_OUTPUT(all.mk)
