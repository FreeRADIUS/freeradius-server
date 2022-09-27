dnl #
dnl #  Look for a library in a number of places.
dnl #
dnl #  FR_SMART_CHECK_LIB(library, function)
dnl #
AC_DEFUN([FR_SMART_CHECK_LIB], [

sm_lib_safe=`echo "$1" | sed 'y%./+-%__p_%'`
sm_func_safe=`echo "$2" | sed 'y%./+-%__p_%'`

dnl #
dnl #  We pass all arguments for linker testing in CCPFLAGS as these
dnl #  will be passed to the compiler (then linker) first.
dnl #
dnl #  The linker will search through -L directories in the order they
dnl #  appear on the command line.  Unfortunately the same rules appear
dnl #  to apply to directories specified with --sysroot, so we must
dnl #  pass the user specified directory first.
dnl #
dnl #  Really we should be using LDFLAGS (-L<dir>) for this.
dnl #
old_LIBS="$LIBS"
old_CPPFLAGS="$CPPFLAGS"
smart_lib=
smart_ldflags=
smart_lib_dir=

dnl #
dnl #  Try first any user-specified directory, otherwise we may pick up
dnl #  the wrong version.
dnl #
if test "x$smart_try_dir" != "x"; then
  for try in $smart_try_dir; do
    AC_MSG_CHECKING([for $2 in -l$1 in $try])
    LIBS="-l$1 $old_LIBS"
    CPPFLAGS="-L$try -Wl,-rpath,$try $old_CPPFLAGS"
    AC_TRY_LINK([extern char $2();],
		[$2()],
		[
		 smart_lib="-l$1"
		 smart_ldflags="-L$try -Wl,-rpath,$try"
		 AC_MSG_RESULT(yes)
		 break
		],
		[AC_MSG_RESULT(no)])
  done
  LIBS="$old_LIBS"
  CPPFLAGS="$old_CPPFLAGS"
fi

dnl #
dnl #  Try using the default library path
dnl #
if test "x$smart_lib" = "x"; then
  AC_MSG_CHECKING([for $2 in -l$1])
  LIBS="-l$1 $old_LIBS"
  AC_TRY_LINK([extern char $2();],
	      [$2()],
	      [
	        smart_lib="-l$1"
	        AC_MSG_RESULT(yes)
	      ],
	      [AC_MSG_RESULT(no)])
  LIBS="$old_LIBS"
fi

dnl #
dnl #  Try to guess possible locations.
dnl #
if test "x$smart_lib" = "x"; then
  for try in /usr/local/lib /opt/lib; do
    AC_MSG_CHECKING([for $2 in -l$1 in $try])
    LIBS="-l$1 $old_LIBS"
    CPPFLAGS="-L$try -Wl,-rpath,$try $old_CPPFLAGS"
    AC_TRY_LINK([extern char $2();],
		[$2()],
		[
		  smart_lib="-l$1"
		  smart_ldflags="-L$try -Wl,-rpath,$try"
		  AC_MSG_RESULT(yes)
		  break
		],
		[AC_MSG_RESULT(no)])
  done
  LIBS="$old_LIBS"
  CPPFLAGS="$old_CPPFLAGS"
fi

dnl #
dnl #  Found it, set the appropriate variable.
dnl #
if test "x$smart_lib" != "x"; then
  eval "ac_cv_lib_${sm_lib_safe}_${sm_func_safe}=yes"
  LIBS="$smart_ldflags $smart_lib $old_LIBS"
  SMART_LIBS="$smart_ldflags $smart_lib $SMART_LIBS"
fi
])
