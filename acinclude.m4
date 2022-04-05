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
dnl #  The default directories we search in (in addition to the compilers search path)
smart_include_dir="/usr/local/include /opt/include"

dnl #  Our local versions
_smart_try_dir=
_smart_include_dir=

dnl #  Add variants with the different prefixes and one with no prefix
for _prefix in $smart_prefix ""; do
  for _dir in $smart_try_dir; do
    _smart_try_dir="${_smart_try_dir} ${_dir}/${_prefix}"
  done

  for _dir in $smart_include_dir; do
    _smart_include_dir="${_smart_include_dir} ${_dir}/${_prefix}"
  done
done

dnl #
dnl #  Try any user-specified directory first otherwise we may pick up
dnl #  the wrong version.
dnl #
if test "x$_smart_try_dir" != "x"; then
  for try in $_smart_try_dir; do
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
dnl #  Try using the default includes (with prefixes).
dnl #
if test "x$smart_include" = "x"; then
  for _prefix in $smart_prefix; do
    AC_MSG_CHECKING([for ${_prefix}/$1])

    AC_TRY_COMPILE([$2
		    #include <$1>],
		   [int a = 1;],
		   [
		     smart_include="-isystem ${_prefix}/"
		     AC_MSG_RESULT(yes)
		     break
		   ],
		   [
		     smart_include=
		     AC_MSG_RESULT(no)
		   ])
  done
fi

dnl #
dnl #  Try using the default includes (without prefixes).
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

  for try in $_smart_include_dir; do
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

dnl #
dnl #  Consume prefix, it's not likely to be used
dnl #  between multiple calls.
dnl #
smart_prefix=
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

dnl #
dnl #  Check if we have the choose expr builtin
dnl #
AC_DEFUN([FR_HAVE_BUILTIN_CHOOSE_EXPR],
[
  AC_CACHE_CHECK([for __builtin_choose_expr support in compiler], [ax_cv_cc_builtin_choose_expr],[
    AC_RUN_IFELSE(
      [
        AC_LANG_SOURCE(
        [
          int main(int argc, char **argv) {
            if ((argc < 0) || !argv) return 1; /* -Werror=unused-parameter */
            return __builtin_choose_expr(0, 1, 0);
          }
        ])
      ],
      [ax_cv_cc_builtin_choose_expr=yes],
      [ax_cv_cc_builtin_choose_expr=no]
    )
  ])
  if test "x$ax_cv_cc_builtin_choose_expr" = "xyes"; then
    AC_DEFINE([HAVE_BUILTIN_CHOOSE_EXPR],1,[Define if the compiler supports __builtin_choose_expr])
  fi
])

dnl #
dnl #  Check if we have the types compatible p builtin
dnl #
AC_DEFUN([FR_HAVE_BUILTIN_TYPES_COMPATIBLE_P],
[
  AC_CACHE_CHECK([for __builtin_types_compatible_p support in compiler], [ax_cv_cc_builtin_types_compatible_p],[
    AC_RUN_IFELSE(
      [
        AC_LANG_SOURCE(
        [
          int main(int argc, char **argv) {
            if ((argc < 0) || !argv) return 1; /* -Werror=unused-parameter */
            return !(__builtin_types_compatible_p(char *, char *));
          }
        ])
      ],
      [ax_cv_cc_builtin_types_compatible_p=yes],
      [ax_cv_cc_builtin_types_compatible_p=no]
    )
  ])
  if test "x$ax_cv_cc_builtin_types_compatible_p" = "xyes"; then
    AC_DEFINE([HAVE_BUILTIN_TYPES_COMPATIBLE_P],1,[Define if the compiler supports __builtin_types_compatible_p])
  fi
])

dnl #
dnl #  Check if we have the bwsap64 builtin
dnl #
AC_DEFUN([FR_HAVE_BUILTIN_BSWAP64],
[
  AC_CACHE_CHECK([for __builtin_bswap64 support in compiler], [ax_cv_cc_builtin_bswap64],[
    AC_RUN_IFELSE(
      [
        AC_LANG_SOURCE([
          int main(int argc, char **argv) {
            if ((argc < 0) || !argv) return 1; /* -Werror=unused-parameter */
            return (__builtin_bswap64(0));
          }
        ])
      ],
      [ax_cv_cc_builtin_bswap64=yes],
      [ax_cv_cc_builtin_bswap64=no]
    )
  ])
  if test "x$ax_cv_cc_builtin_bswap64" = "xyes"; then
    AC_DEFINE([HAVE_BUILTIN_BSWAP_64],1,[Define if the compiler supports __builtin_bswap64])
  fi
])

dnl #
dnl #  Check if we have __attribute__((__bounded__)) (usually only OpenBSD with GCC)
dnl #
AC_DEFUN([FR_HAVE_BOUNDED_ATTRIBUTE],[
  AC_CACHE_CHECK([for __attribute__((__bounded__)) support in compiler], [ax_cv_cc_bounded_attribute],[
    CFLAGS_SAVED=$CFLAGS
    CFLAGS="$CFLAGS -Werror"
    AC_RUN_IFELSE(
      [
        AC_LANG_SOURCE([
          void test(char *buff) __attribute__ ((__bounded__ (__string__, 1, 1)));
          int main(int argc, char **argv) {
            if ((argc < 0) || !argv) return 1; /* -Werror=unused-parameter */
            return 0;
          }
        ])
      ],
      [ax_cv_cc_bounded_attribute=yes],
      [ax_cv_cc_bounded_attribute=no]
    )
    CFLAGS="$CFLAGS_SAVED"
  ])
  if test "x$ax_cv_cc_bounded_attribute" = "xyes"; then
    AC_DEFINE(HAVE_ATTRIBUTE_BOUNDED, 1, [Define if your compiler supports the __bounded__ attribute (usually OpenBSD gcc).])
  fi
])

AC_INCLUDE(aclocal.m4)
