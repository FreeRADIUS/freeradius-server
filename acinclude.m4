dnl Checks to see if this is SUNPro we're building with
dnl Usage:
dnl AC_PROG_CC_SUNPRO
AC_DEFUN([AC_PROG_CC_SUNPRO],
[AC_CACHE_CHECK(whether we are using SUNPro C, ac_cv_prog_suncc,
[dnl The semicolon is to pacify NeXT's syntax-checking cpp.
cat > conftest.c <<EOF
#ifdef __SUNPRO_C
  yes;
#endif
EOF
if AC_TRY_COMMAND(${CC-cc} -E conftest.c) | egrep yes >/dev/null 2>&1; then
  ac_cv_prog_suncc=yes
else
  ac_cv_prog_suncc=no
fi])])

dnl #
dnl # FR_CHECK_TYPE_INCLUDE([#includes ...], type, default-C-types)
dnl #
dnl # This function is like AC_CHECK_TYPE, but you can give this one
dnl # a list of include files to check.
dnl #
AC_DEFUN([FR_CHECK_TYPE_INCLUDE],
[
  AC_CACHE_CHECK(for $2, ac_cv_type_$2,
    [ ac_cv_type_$2=no
      AC_TRY_COMPILE($1,
        [$2 foo],
        ac_cv_type_$2=yes,
      )
    ]
  )

  if test "$ac_cv_type_$2" != "yes"; then
         AC_DEFINE($2, $3, $4)
  fi
])

dnl #
dnl #  Locate the directory in which a particular file is found.
dnl #
dnl #  Usage: FR_LOCATE_DIR(MYSQLLIB_DIR, libmysqlclient.a)
dnl #
dnl #    Defines the variable MYSQLLIB_DIR to be the directory(s) in
dnl #    which the file libmysqlclient.a is to be found.
dnl #
dnl #
AC_DEFUN([FR_LOCATE_DIR],
[
dnl # If we have the program 'locate', then the problem of finding a
dnl # particular file becomes MUCH easier.
dnl #

dnl #
dnl #  No 'locate' defined, do NOT do anything.
dnl #
if test "x$LOCATE" != "x"; then
  dnl #
  dnl #  Root through a series of directories, looking for the given file.
  dnl #
  DIRS=
  file=$2

  for x in `${LOCATE} $file 2>/dev/null`; do
    dnl #
    dnl #  When asked for 'foo', locate will also find 'foo_bar', which we
    dnl #  don't want.  We want that EXACT filename.
    dnl #
    dnl #  We ALSO want to be able to look for files like 'mysql/mysql.h',
    dnl #  and properly match them, too.  So we try to strip off the last
    dnl #  part of the filename, using the name of the file we're looking
    dnl #  for.  If we CANNOT strip it off, then the name will be unchanged.
    dnl #
    base=`echo $x | sed "s%/${file}%%"`
    if test "x$x" = "x$base"; then
      continue;
    fi

    dir=`${DIRNAME} $x 2>/dev/null`
    dnl #
    dnl #  Exclude a number of directories.
    dnl #
    exclude=`echo ${dir} | ${GREP} /home`
    if test "x$exclude" != "x"; then
      continue
    fi

    dnl #
    dnl #  OK, we have an exact match.  Let's be sure that we only find ONE
    dnl #  matching directory.
    dnl #
    already=`echo \$$1 ${DIRS} | ${GREP} ${dir}`
    if test "x$already" = "x"; then
      DIRS="$DIRS $dir"
    fi
  done
fi

dnl #
dnl #  And remember the directory in which we found the file.
dnl #
eval "$1=\"\$$1 $DIRS\""
])


dnl #######################################################################
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
  FR_LOCATE_DIR(smart_lib_dir,[lib$1${libltdl_cv_shlibext}])
  FR_LOCATE_DIR(smart_lib_dir,[lib$1.a])

  for try in $smart_lib_dir /usr/local/lib /opt/lib; do
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

dnl #######################################################################
dnl #
dnl #  Look for a header file in a number of places.
dnl #
dnl #  FR_SMART_CHECK_INCLUDE(foo.h, [ #include <other.h> ])
dnl #
AC_DEFUN([FR_SMART_CHECK_INCLUDE], [

ac_safe=`echo "$1" | sed 'y%./+-%__pm%'`
old_CPPFLAGS="$CPPFLAGS"
smart_include=
smart_include_dir=

dnl #
dnl #  Try first any user-specified directory, otherwise we may pick up
dnl #  the wrong version.
dnl #
if test "x$smart_try_dir" != "x"; then
  for try in $smart_try_dir; do
    AC_MSG_CHECKING([for $1 in $try])
    CPPFLAGS="-isystem $try $old_CPPFLAGS"
    AC_TRY_COMPILE([$2
		    #include <$1>],
		   [int a = 1;],
		   [
		     smart_include="-isystem $try"
		     AC_MSG_RESULT(yes)
		     break
		   ],
		   [
		     smart_include=
		     AC_MSG_RESULT(no)
		   ])
  done
  CPPFLAGS="$old_CPPFLAGS"
fi

dnl #
dnl #  Try using the default includes.
dnl #
if test "x$smart_include" = "x"; then
  AC_MSG_CHECKING([for $1])
  AC_TRY_COMPILE([$2
		  #include <$1>],
		 [int a = 1;],
		 [
		   smart_include=" "
		   AC_MSG_RESULT(yes)
		   break
		 ],
		 [
		   smart_include=
		   AC_MSG_RESULT(no)
		 ])
fi

dnl #
dnl #  Try to guess possible locations.
dnl #
if test "x$smart_include" = "x"; then
  FR_LOCATE_DIR(smart_include_dir,$1)
  for try in $smart_include_dir /usr/local/include /opt/include; do
    AC_MSG_CHECKING([for $1 in $try])
    CPPFLAGS="-isystem $try $old_CPPFLAGS"
    AC_TRY_COMPILE([$2
		    #include <$1>],
		   [int a = 1;],
		   [
		     smart_include="-isystem $try"
		     AC_MSG_RESULT(yes)
		     break
		   ],
		   [
		     smart_include=
		     AC_MSG_RESULT(no)
		   ])
  done
  CPPFLAGS="$old_CPPFLAGS"
fi

dnl #
dnl #  Found it, set the appropriate variable.
dnl #
if test "x$smart_include" != "x"; then
  eval "ac_cv_header_$ac_safe=yes"
  CPPFLAGS="$smart_include $old_CPPFLAGS"
  SMART_CPPFLAGS="$smart_include $SMART_CPPFLAGS"
fi
])

dnl #######################################################################
dnl #
dnl #  Look for a header file in a number of places.
dnl #
dnl #  Usage:  FR_CHECK_STRUCT_HAS_MEMBER([#include <foo.h>], [struct foo], member)
dnl #  If the member is defined, then the variable
dnl #     ac_cv_type_struct_foo_has_member is set to 'yes'
dnl #
AC_DEFUN([FR_CHECK_STRUCT_HAS_MEMBER], [
  AC_MSG_CHECKING([for $3 in $2])

dnl BASED on 'offsetof':
dnl #define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
dnl

  AC_TRY_COMPILE([
$1
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif
#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((int) &((TYPE *)0)->MEMBER)
#endif
],
                 [ int foo = offsetof($2, $3) ],
                 has_element=" ",
                 has_element=)

  ac_safe_type=`echo "$2" | sed 'y% %_%'`
  if test "x$has_element" != "x"; then
    AC_MSG_RESULT(yes)
    eval "ac_cv_type_${ac_safe_type}_has_$3=yes"
  else
    AC_MSG_RESULT(no)
    eval "ac_cv_type_${ac_safe_type}_has_$3="
 fi
])

dnl Autoconf 2.61 breaks the support for chained configure scripts
dnl in combination with config.cache
m4_pushdef([AC_OUTPUT],
[
  unset ac_cv_env_LIBS_set
  unset ac_cv_env_LIBS_value
  m4_popdef([AC_OUTPUT])
  AC_OUTPUT([$1],[$2],[$3])
])

dnl #
dnl #  Figure out which storage class specifier for Thread Local Storage is supported by the compiler
dnl #
AC_DEFUN([FR_TLS],
[
dnl #
dnl #  See if the compilation works with __thread, for thread-local storage
dnl #
  AC_MSG_CHECKING(for __thread support in compiler)
  AC_RUN_IFELSE(
    [AC_LANG_SOURCE(
      [[
        static __thread int val;
        int main(int argc, char **argv) {
          val = 0;
          return val;
        }
      ]])
    ],[have_tls=yes],[have_tls=no],[have_tls=no])
  AC_MSG_RESULT($have_tls)
  if test "x$have_tls" = "xyes"; then
    AC_DEFINE([TLS_STORAGE_CLASS],[__thread],[Define if the compiler supports a thread local storage class])
  fi

dnl #
dnl #  __declspec(thread) does exactly the same thing as __thread, but is supported by MSVS
dnl #
  if test "x$have_tls" = "xno"; then
    AC_MSG_CHECKING(for __declspec(thread) support in compiler)
    AC_RUN_IFELSE(
      [AC_LANG_SOURCE(
        [[
          static _Thread_local int val;
          int main(int argc, char **argv) {
            val = 0;
            return val;
          }
        ]])
      ],[have_tls=yes],[have_tls=no],[have_tls=no])
    AC_MSG_RESULT($have_tls)
    if test "x$have_tls" = "xyes"; then
      AC_DEFINE([TLS_STORAGE_CLASS],[__declspec(thread)],[Define if the compiler supports a thread local storage class])
    fi
  fi
dnl #
dnl #  _Thread_local does exactly the same thing as __thread, but it's standards compliant with C11.
dnl #  we, however, state we are only compliant with C99, so the compiler will probably emit warnings
dnl #  if we use it.  So save it as a last resort.
dnl #
  if test "x$have_tls" = "xno"; then
    AC_MSG_CHECKING(for _Thread_local support in compiler)
    AC_RUN_IFELSE(
      [AC_LANG_SOURCE(
        [[
          static _Thread_local int val;
          int main(int argc, char **argv) {
            val = 0;
            return val;
          }
        ]])
      ],[have_tls=yes],[have_tls=no],[have_tls=no])
    AC_MSG_RESULT($have_tls)
    if test "x$have_tls" = "xyes"; then
      AC_DEFINE([TLS_STORAGE_CLASS],[_Thread_local],[Define if the compiler supports a thread local storage class])
    fi
  fi
])

AC_DEFUN([VL_LIB_READLINE], [
  AC_CACHE_CHECK([for a readline compatible library],
                 vl_cv_lib_readline, [
    ORIG_LIBS="$LIBS"
    for readline_lib in readline edit editline; do
      for termcap_lib in "" termcap curses ncurses; do
        if test -z "$termcap_lib"; then
          TRY_LIB="-l$readline_lib"
        else
          TRY_LIB="-l$readline_lib -l$termcap_lib"
        fi
        LIBS="$ORIG_LIBS $TRY_LIB"
        AC_TRY_LINK_FUNC(readline, vl_cv_lib_readline="$TRY_LIB")
        if test -n "$vl_cv_lib_readline"; then
          break
        fi
      done
      if test -n "$vl_cv_lib_readline"; then
        break
      fi
    done
    if test -z "$vl_cv_lib_readline"; then
      vl_cv_lib_readline="no"
      LIBS="$ORIG_LIBS"
    fi
  ])

  if test "$vl_cv_lib_readline" != "no"; then
    LIBREADLINE="$vl_cv_lib_readline"
    AC_DEFINE(HAVE_LIBREADLINE, 1,
              [Define if you have a readline compatible library])
    AC_CHECK_HEADERS(readline.h readline/readline.h)
    AC_CACHE_CHECK([whether readline supports history],
                   [vl_cv_lib_readline_history], [
      vl_cv_lib_readline_history="no"
      AC_TRY_LINK_FUNC([add_history], [vl_cv_lib_readline_history="yes"])
    ])
    if test "$vl_cv_lib_readline_history" = "yes"; then
      AC_DEFINE(HAVE_READLINE_HISTORY, 1,
                [Define if your readline library has \`add_history'])
      AC_CHECK_HEADERS(history.h readline/history.h)
    fi
  fi
  AC_SUBST(LIBREADLINE)
])dnl

AC_INCLUDE(aclocal.m4)
