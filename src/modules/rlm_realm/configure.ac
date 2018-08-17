AC_PREREQ([2.53])
AC_INIT(rlm_realm.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_realm])

if test x$with_[]modname != xno; then
	AC_PROG_CC
	AC_PROG_CPP

	FR_SMART_CHECK_LIB(tr_tid, tidc_create)
	FR_SMART_CHECK_LIB(tr_tid, tid_srvr_get_key_expiration)
	FR_SMART_CHECK_INCLUDE(trust_router/tr_dh.h)

	if test "x$ac_cv_lib_tr_tid_tidc_create" != "x"; then
		if test "x$ac_cv_header_trust_router_tr_dh_h" != "x"; then
			SMART_CPPFLAGS="$SMART_CPPFLAGS -DHAVE_TRUST_ROUTER_TR_DH_H"
			trustrouter=yes
			if test "x$ac_cv_lib_tr_tid_tid_srvr_get_key_expiration" != "x"; then
				SMART_CPPFLAGS="$SMART_CPPFLAGS -DHAVE_TRUST_ROUTER_GET_KEY_EXP"
			fi
		fi
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

mod_ldflags="${SMART_LIBS}"
mod_cflags="${SMART_CPPFLAGS}"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)
AC_SUBST(trustrouter)

AC_SUBST(targetname)
AC_OUTPUT(all.mk)
