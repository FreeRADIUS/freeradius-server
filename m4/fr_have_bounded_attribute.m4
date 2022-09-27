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
