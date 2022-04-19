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

dnl Autoconf 2.61 breaks the support for chained configure scripts
dnl in combination with config.cache
m4_pushdef([AC_OUTPUT],
[
unset ac_cv_env_LIBS_set
unset ac_cv_env_LIBS_value
m4_popdef([AC_OUTPUT])
AC_OUTPUT([$1],[$2],[$3])
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
LIBREADLINE_PREFIX=$(brew --prefix readline 2>/dev/null)

AC_SUBST(LIBREADLINE)
AC_SUBST(LIBREADLINE_PREFIX)
])dnl

AC_INCLUDE(aclocal.m4)
