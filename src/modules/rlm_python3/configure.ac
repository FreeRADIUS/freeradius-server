AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_python3.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_python3], [support for embedded Python3])

FR_MODULE_START_TESTS

AC_PROG_CC
AC_PROG_CPP
AM_PATH_PYTHON([3.0],, [:])

dnl extra argument: --with-rlm-python3-config-bin
PYTHON3_CONFIG_BIN=
AC_ARG_WITH(rlm-python3-config-bin,
	[AS_HELP_STRING([--with-rlm-python3-config-bin=PATH],
		[Path to python-config3 binary])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need rlm-python3-config-bin)
		;;
	yes)
		;;
	*)
		PYTHON3_CONFIG_BIN="$withval"
		;;
	esac])

if test "x$PYTHON3_CONFIG_BIN" = x; then
	AC_CHECK_PROGS(PYTHON3_CONFIG_BIN, [ python3-config ], not-found, [${PATH}:/usr/bin:/usr/local/bin])
fi

if test "x$PYTHON3_CONFIG_BIN" = xnot-found; then
	FR_MODULE_FAIL([python3-config])
else
	dnl #
	dnl # It is necessary due to a weird behavior with 'python3-config'
	dnl #
	old_CFLAGS="$CFLAGS"
	unset CFLAGS

	python3_cflags=`${PYTHON3_CONFIG_BIN} --cflags`
	AC_MSG_NOTICE([${PYTHON3_CONFIG_BIN}'s cflags were \"${python3_cflags}\"])

	dnl # Convert -I to -isystem to get rid of warnings about issues in Python headers
	dnl # Strip -systemroot
	dnl # Strip optimisation flags (-O[0-9]?). We decide our optimisation level, not python.
	dnl # -D_FORTIFY_SOURCE needs -O.
	dnl # Strip debug symbol flags (-g[0-9]?). We decide on debugging symbols, not python
	dnl # Strip -W*, we decide what warnings are important
	dnl # Strip -DNDEBUG
	dnl # Strip -frecord-gcc-switches, We decide if we need that, not python.
	dnl # Strip -specs=/path/whatever.specs, We don't need the compiler .specs that comes from Python
	dnl # Strip -ffat-lto-objects, We decide if we need that, not python.
	dnl # Strip -flto=auto, We decide if we need that, not python.
	mod_cflags=`echo " $python3_cflags" | sed -e '\
		s/ -I/ -isystem/g;\
		s/ -isysroot[[ =]]\{0,1\}[[^-]]*/ /g;\
		s/ -O[[^[[:blank:]]]]*/ /g;\
		s/ -Wp,-D_FORTIFY_SOURCE=[[[:digit:]]]/ /g;\
		s/ -g[[^ ]]*/ /g;\
		s/ -W[[^ ]]*/ /g;\
		s/ -DNDEBUG[[[:blank:]]]*/ /g;\
		s/ -frecord-gcc-switches/ /g;\
		s/ -specs=[[^ ]]*/ /g; \
		s/ -ffat-lto-objects/ /g; \
		s/ -flto=[[^ ]]*/ /g;
		'`
	AC_MSG_NOTICE([Sanitized cflags were \"${mod_cflags}\"])

	dnl # From python 3.8, --embed is required
	dnl # https://bugs.python.org/issue36721
	AX_COMPARE_VERSION(${PYTHON_VERSION}, [ge], [3.8], [EMBED="--embed"], [])

	python3_ldflags=`${PYTHON3_CONFIG_BIN} --ldflags $EMBED`
	AC_MSG_NOTICE([${PYTHON3_CONFIG_BIN}'s ldflags were \"$python3_ldflags}\"])

	dnl # Strip -Wl,-O1... Is -O even a valid linker flag??
	dnl # Strip -Wl,-Bsymbolic-functions as thats not always supported or required
	dnl # Strip -Xlinker -export-dynamic as it causes weird linking issues on Linux
	dnl #   See: https://bugs.python.org/issue36508
	mod_ldflags=`echo $python3_ldflags | sed -e '\
		s/-Wl,-O[[[:digit:]]][[[:blank:]]]*//g;\
		s/-Wl,-Bsymbolic-functions[[[:blank:]]]*//g;\
		s/-Xlinker -export-dynamic//g;\
		s/-Wl,-stack_size,[[[:digit:]]]*[[[:blank:]]]//g;
		'`
	AC_MSG_NOTICE([Sanitized ldflags were \"${mod_ldflags}\"])

	CFLAGS=$old_CFLAGS
fi
AC_CHECK_FUNCS([dl_iterate_phdr])

FR_MODULE_END_TESTS

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
