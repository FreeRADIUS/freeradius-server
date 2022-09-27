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
