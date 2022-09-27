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
