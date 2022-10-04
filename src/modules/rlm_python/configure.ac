AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_python.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_python], [support for embedded Python2])

FR_MODULE_START_TESTS

AC_PROG_CC
AC_PROG_CPP

dnl extra argument: --with-rlm-python-bin
PYTHON_BIN=
AC_ARG_WITH(rlm-python-bin,
	[AS_HELP_STRING([--with-rlm-python-bin=PATH],
		[Path to python binary])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need rlm-python-bin)
		;;
	yes)
		;;
	*)
		PYTHON_BIN="$withval"
		;;
	esac])

if test "x$PYTHON_BIN" = x; then
	AC_CHECK_PROGS(PYTHON_BIN, [ python2.7 python2.6 python ], not-found, [${PATH}:/usr/bin:/usr/local/bin])
fi

if test "x$PYTHON_BIN" = "xnot-found"; then
	FR_MODULE_FAIL([python-binary])
fi

dnl extra argument: --with-rlm-python-lib-dir
PY_LIB_DIR=
AC_ARG_WITH(rlm-python-lib-dir,
	[AS_HELP_STRING([--with-rlm-python-lib-dir=DIR],
		[Directory for Python library files])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need rlm-python-lib-dir)
		;;
	yes)
		;;
	*)
		PY_LIB_DIR="$withval"
		;;
	esac])

dnl extra argument: --with-rlm-python-include-dir
PY_INC_DIR=
AC_ARG_WITH(rlm-python-include-dir,
	[AS_HELP_STRING([--with-rlm-python-include-dir=DIR],
		[Directory for Python include files])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need rlm-python-include-dir)
		;;
	yes)
		;;
	*)
		PY_INC_DIR="$withval"
		;;
	esac])

FR_MODULE_TEST_PASS_DO([
	PY_MAJOR_VER=`${PYTHON_BIN} -x 'import sys ; print(sys.version[[0]])'`
	if test $PY_MAJOR_VER -ne 2; then
		FR_MODULE_FAIL([not-python2])
	fi
])

FR_MODULE_TEST_PASS_DO([
	PY_PREFIX=`${PYTHON_BIN} -c 'import sys ; print(sys.prefix)'`
	AC_MSG_NOTICE([Python sys.prefix \"${PY_PREFIX}\"])

	PY_EXEC_PREFIX=`${PYTHON_BIN} -c 'import sys ; print(sys.exec_prefix)'`
	AC_MSG_NOTICE([Python sys.exec_prefix \"${PY_EXEC_PREFIX}\"])

	PY_SYS_VERSION=`${PYTHON_BIN} -c 'import sys ; print(sys.version[[0:3]])'`
	AC_MSG_NOTICE([Python sys.version \"${PY_SYS_VERSION}\"])

	if test "x$PY_LIB_DIR" = "x"; then
		PY_LIB_DIR="$PY_EXEC_PREFIX/lib/python${PY_SYS_VERSION}/config"
		PY_LIB_LOC="-L$PY_EXEC_PREFIX/lib/python${PY_SYS_VERSION}/config"
	fi

	PY_MAKEFILE="$PY_EXEC_PREFIX/lib/python${PY_SYS_VERSION}/config/Makefile"
	if test -f ${PY_MAKEFILE}; then
		PY_LOCAL_MOD_LIBS=`sed -n -e 's/^LOCALMODLIBS=\(.*\)/\1/p' $PY_MAKEFILE | sed -e 's/[[[:blank:]]]/ /g;s/^ *//;s/ *$//'`
		AC_MSG_NOTICE([Python local_mod_libs \"${PY_LOCAL_MOD_LIBS}\"])

		PY_BASE_MOD_LIBS=`sed -n -e 's/^BASEMODLIBS=\(.*\)/\1/p' $PY_MAKEFILE | sed -e 's/[[[:blank:]]]/ /g;s/^ *//;s/ *$//'`
		AC_MSG_NOTICE([Python base_mod_libs \"${PY_BASE_MOD_LIBS}\"])

		PY_OTHER_LIBS=`sed -n -e 's/^LIBS=\(.*\)/\1/p' $PY_MAKEFILE | sed -e 's/[[[:blank:]]]/ /g;s/  / /g;s/^ *//;s/ *$//'`
		PY_OTHER_LDFLAGS=`sed -n -e 's/^LINKFORSHARED=\(.*\)/\1/p' $PY_MAKEFILE | sed -e 's/[[[:blank:]]]/ /g;s/  / /g;s/^ *//;s/ *$//'`
		AC_MSG_NOTICE([Python other_libs \"${PY_OTHER_LDFLAGS} ${PY_OTHER_LIBS}\"])
	fi
	PY_EXTRA_LIBS="$PY_LOCALMODLIBS $PY_BASE_MOD_LIBS $PY_OTHER_LIBS"

	old_CFLAGS=$CFLAGS
	CFLAGS="$CFLAGS $PY_CFLAGS"
	smart_try_dir="$PY_PREFIX/include/python$PY_SYS_VERSION"
	FR_SMART_CHECK_INCLUDE(Python.h)
	CFLAGS=$old_CFLAGS

	if test "x$ac_cv_header_Python_h" = "xyes"; then
		mod_cflags="$SMART_CPPFLAGS"
	else
		FR_MODULE_FAIL([Python.h])
	fi

	old_LIBS=$LIBS
	LIBS="$LIBS $PY_LIB_LOC $PY_EXTRA_LIBS -lm"
	smart_try_dir=$PY_LIB_DIR
	FR_SMART_CHECK_LIB(python${PY_SYS_VERSION}, Py_Initialize)
	LIBS=$old_LIBS

	eval t=\${ac_cv_lib_${sm_lib_safe}_${sm_func_safe}}
	if test "x$t" = "xyes"; then
		mod_ldflags="$PY_LIB_LOC $PY_EXTRA_LIBS $SMART_LIBS -lm"
	else
		FR_SMART_CHECK_LIB(python${PY_SYS_VERSION}m, Py_Initialize)
		eval t=\${ac_cv_lib_${sm_lib_safe}_${sm_func_safe}}
		if test "x$t" = "xyes"; then
			mod_ldflags="$PY_LIB_LOC $PY_EXTRA_LIBS $SMART_LIBS -lm"
		else
			FR_MODULE_FAIL([libpython$PY_SYS_VERSION])
		fi
	fi
])

AC_CHECK_FUNCS([dl_iterate_phdr])

FR_MODULE_END_TESTS

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([all.mk])
AC_OUTPUT
