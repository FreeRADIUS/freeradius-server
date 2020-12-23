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
	[  --with-rlm-python-config-bin=PATH   Path to python-config binary []],
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
		AC_CHECK_PROGS(PYTHON_CONFIG_BIN, [ python3-config ], not-found, [${PATH}:/usr/bin:/usr/local/bin])
	fi

	if test "x$PYTHON_CONFIG_BIN" = "xnot-found"; then
		fail="python-config"
	else
		dnl #
		dnl # It is necessary due to a weird behavior with 'python-config'
		dnl #
		old_CFLAGS="$CFLAGS"
		unset CFLAGS

		dnl #
		dnl # Not all python3-config versions have --embed.  If doesn't
		dnl # the utility throws an error, and if it does, it omits the
		dnl # linker argument to link to Python.
		dnl #
		if ${PYTHON_CONFIG_BIN} --help 2>&1 | grep '\-\-embed'; then
			PYTHON_CONFIG_EMBED="--embed"
		else
			PYTHON_CONFIG_EMBED=""
		fi

		python_cflags=`${PYTHON_CONFIG_BIN} --cflags ${PYTHON_CONFIG_EMBED}`
		AC_MSG_NOTICE([${PYTHON_CONFIG_BIN}'s cflags were \"${python_cflags}\"])

		dnl # Convert -I to -isystem to get rid of warnings about issues in Python headers
		dnl # Strip -systemroot
		dnl # Strip optimisation flags (-O[0-9]?). We decide our optimisation level, not python.
		dnl # -D_FORTIFY_SOURCE needs -O.
		dnl # Strip debug symbol flags (-g[0-9]?). We decide on debugging symbols, not python
		dnl # Strip -W*, we decide what warnings are important
		dnl # Strip -DNDEBUG
		dnl # Strip -frecord-gcc-switches, We decide if we need that. not python.
		dnl # Strip -stack-clash-protection.  We don't need it for our module and it's not
		dnl # supported by clang < 11.
		dnl # Strip -frecord-gcc-switches. We decide if this needs recording, not python.
		dnl # Strip specs as they're only supported by GCC and cause warnings under clang
		mod_cflags=`echo " $python_cflags" | sed -e '\
			s/ -I/ -isystem/g;\
			s/ -isysroot[[ =]]\{0,1\}[[^-]]*/ /g;\
			s/ -O[[^[[:blank:]]]]*/ /g;\
			s/ -Wp,-D_FORTIFY_SOURCE=[[[:digit:]]]/ /g;\
			s/ -g[[^ ]]*/ /g;\
			s/ -W[[^ ]]*/ /g;\
			s/ -DNDEBUG[[[:blank:]]]*/ /g;\
			s/ -frecord-gcc-switches/ /g;\
			s/ -fstack-clash-protection[[[:blank:]]]*/ /g;
			s/ -specs=[[^ ]]*/ /g;
			'`
		AC_MSG_NOTICE([Sanitized cflags were \"${mod_cflags}\"])

		python_ldflags=`${PYTHON_CONFIG_BIN} --ldflags ${PYTHON_CONFIG_EMBED}`
		AC_MSG_NOTICE([${PYTHON_CONFIG_BIN}'s ldflags were \"$python_ldflags}\"])

		dnl # Strip -Wl,-O1... Is -O even a valid linker flag??
		dnl # Strip -Wl,-Bsymbolic-functions as thats not always supported or required
		dnl # Strip -Xlinker -export-dynamic as it causes weird linking issues on Linux
		dnl #   See: https://bugs.python.org/issue36508
		mod_ldflags=`echo $python_ldflags | sed -e '\
			s/-Wl,-O[[[:digit:]]][[[:blank:]]]*//g;\
			s/-Wl,-Bsymbolic-functions[[[:blank:]]]*//g;\
			s/-Xlinker -export-dynamic//g;\
			s/-Wl,-stack_size,[[[:digit:]]]*[[[:blank:]]]//g;
			'`
		AC_MSG_NOTICE([Sanitized ldflags were \"${mod_ldflags}\"])

		CFLAGS=$old_CFLAGS

		targetname="rlm_python"
	fi
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
