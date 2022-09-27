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
