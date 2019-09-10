AC_PREREQ([2.53])
AC_INIT(rlm_python.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_python])

if test x$with_[]modname != xno; then

	AC_PROG_CC
	AC_PROG_CPP

	dnl extra argument: --with-rlm-python-config-bin
	PYHTON_BIN=
	AC_ARG_WITH(rlm-python-config-bin,
	[  --with-rlm-python-bin=PATH   Path to python binary []],
	[ case "$withval" in
	    no)
		AC_MSG_ERROR(Need rlm-python-config-bin)
		;;
	    yes)
		;;
	    *)
		PYTHON_CONFIG_BIN="$withval"
		;;
	  esac ]
	)

	if test "x$PYTHON_CONFIG_BIN" = x; then
		AC_CHECK_PROGS(PYTHON_CONFIG_BIN, [ python2.7-config python-config ], not-found, [${PATH}:/usr/bin:/usr/local/bin])
	fi

	if test "x$PYTHON_CONFIG_BIN" = "xnot-found"; then
		fail="python-config"
	fi

	python_cflags=`${PYTHON_CONFIG_BIN} --cflags`
	AC_MSG_NOTICE([${PYTHON_CONFIG_BIN}'s cflags were \"${python_cflags}\"])

	dnl # Convert -I to -isystem to get rid of warnings about issues in Python headers
	dnl # Strip -systemroot
	dnl # Strip optimisation flags (-O[0-9]?)
	dnl # Strip debug symbol flags (-g[0-9]?)
	dnl # Strip -Werror

	dnl # Strip -DNDEBUG
	mod_cflags=`echo $python_cflags | sed -e '\
		s/-I/-isystem/g;\
		s/-isysroot[[ =]]\{0,1\}[[^-]]*//g;\
		s/-O[[[:digit:]]][[[:blank:]]]*//g;\
		s/-g[[[:digit:]]]*[[[:blank:]]]*//g;\
		s/-Werror[[[:blank:]]]*//g;\
		s/-DNDEBUG[[[:blank:]]]*//g'`
	AC_MSG_NOTICE([Sanitized cflags were \"${mod_cflags}\"])

	python_ldflags=`${PYTHON_CONFIG_BIN} --ldflags`
	AC_MSG_NOTICE([${PYTHON_CONFIG_BIN}'s ldflags were \"$python_ldflags}\"])

	mod_ldflags=$python_ldflags
	AC_MSG_NOTICE([Sanitized ldflags were \"${mod_ldflags}\"])

	targetname="rlm_python"
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



AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)
AC_SUBST(targetname)
AC_OUTPUT(all.mk)
