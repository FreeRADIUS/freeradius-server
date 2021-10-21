dnl #
dnl # check if were compiling with CLANG, autoconf GCC macro identifies CLANG as GCC
dnl #
AC_DEFUN([AX_CC_IS_CLANG],[
  AC_CACHE_CHECK([if compiler is clang], [ax_cv_cc_clang],[

  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([], [[
    #ifndef __clang__
         not clang
    #endif
    ]])],
    [ax_cv_cc_clang=yes],
    [ax_cv_cc_clang=no])
  ])
])

dnl #
dnl # clang and gcc originally used different flags to specify c11 support
dnl #
AC_DEFUN([AX_CC_STD_C11],[
  AC_CACHE_CHECK([for the compiler flag to enable C11 support], [ax_cv_cc_std_c11_flag],[
    ax_cv_cc_std_c11_flag=

    CFLAGS_SAVED=$CFLAGS
    CFLAGS="$CFLAGS -Werror -std=c11"

    AC_LANG_PUSH(C)
    AC_TRY_COMPILE(
      [],
      [
        struct foo {
          union {
            int a;
            int b;
          };
        } bar;
      ],
      [ax_cv_cc_std_c11_flag="-std=c11"])

    if test "x$ax_cv_cc_std_c11_flag" = x; then
      CFLAGS="$CFLAGS_SAVED -std=c1x"
      AC_TRY_COMPILE(
        [],
        [
          struct foo {
            union {
              int a;
              int b;
            };
          } bar;
        ],
        [ax_cv_cc_std_c11_flag="-std=c1x"])
    fi

    AC_LANG_POP
    CFLAGS="$CFLAGS_SAVED"
  ])
])

dnl #
dnl #  Check if we have the _Generic construct
dnl #
AC_DEFUN([AX_CC_HAVE_C11_GENERIC],
[
AC_CACHE_CHECK([for _Generic support in compiler], [ax_cv_cc_c11_generic],[
  AC_RUN_IFELSE(
    [
      AC_LANG_SOURCE(
      [
        int main(int argc, char **argv) {
          int foo = 1;
          return _Generic(foo, int: 0, char: 1);
        }
      ])
    ],
    [ax_cv_cc_c11_generic=yes],
    [ax_cv_cc_c11_generic=no]
  )
])
if test "x$ax_cv_cc_c11_generic" = "xyes"; then
  AC_DEFINE([HAVE_C11_GENERIC],1,[Define if the compiler supports the C11 _Generic construct])
fi
])

AC_DEFUN([AX_CC_QUNUSED_ARGUMENTS_FLAG],[
  AC_CACHE_CHECK([for the compiler flag "-Qunused-arguments"], [ax_cv_cc_qunused_arguments_flag],[

    CFLAGS_SAVED=$CFLAGS
    CFLAGS="$CFLAGS -Werror -Qunused-arguments -foobar"

    AC_LANG_PUSH(C)
    AC_TRY_COMPILE(
      [],
      [return 0;],
      [ax_cv_cc_qunused_arguments_flag="yes"],
      [ax_cv_cc_qunused_arguments_flag="no"])
    AC_LANG_POP

    CFLAGS="$CFLAGS_SAVED"
  ])
])

AC_DEFUN([AX_CC_NO_UNKNOWN_WARNING_OPTION_FLAG],[
  AC_CACHE_CHECK([for the compiler flag "-Wno-unknown-warning-option"], [ax_cv_cc_no_unknown_warning_option_flag],[

  CFLAGS_SAVED=$CFLAGS
  CFLAGS="-Werror -Wno-unknown-warning-option"

  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([], [[
    /*
     *  gcc will happily accept -Wno-unknown-warning-option
     *  only emitting an error about it, if an error ocurrs in the source file.
     */
    #if defined(__GNUC__) && !defined(__clang__)
        gcc sucks
    #endif

    return 0;
    ]])],
    [ax_cv_cc_no_unknown_warning_option_flag=yes],
    [ax_cv_cc_no_unknown_warning_option_flag=no])

  CFLAGS="$CFLAGS_SAVED"
  ])
])



AC_DEFUN([AX_CC_WEVERYTHING_FLAG],[
  AC_CACHE_CHECK([for the compiler flag "-Weverything"], [ax_cv_cc_weverything_flag],[

    CFLAGS_SAVED=$CFLAGS
    CFLAGS="$CFLAGS -Werror -Weverything -Wno-reserved-id-macro -Wno-unused-macros -Wno-unreachable-code-return -Wno-poison-system-directories"

    AC_LANG_PUSH(C)
    AC_TRY_COMPILE(
      [],
      [return 0;],
      [ax_cv_cc_weverything_flag="yes"],
      [ax_cv_cc_weverything_flag="no"])
    AC_LANG_POP

    CFLAGS="$CFLAGS_SAVED"
  ])
])

AC_DEFUN([AX_CC_WDOCUMENTATION_FLAG],[
  AC_CACHE_CHECK([for the compiler flag "-Wdocumentation"], [ax_cv_cc_wdocumentation_flag],[

    CFLAGS_SAVED=$CFLAGS
    CFLAGS="$CFLAGS -Werror -Wdocumentation"

    AC_LANG_PUSH(C)
    AC_TRY_COMPILE(
      [],
      [return 0;],
      [ax_cv_cc_wdocumentation_flag="yes"],
      [ax_cv_cc_wdocumentation_flag="no"])
    AC_LANG_POP

    CFLAGS="$CFLAGS_SAVED"
  ])
])

AC_DEFUN([AX_CC_IMPLICIT_FALLTHROUGH_FLAG],[
  AC_CACHE_CHECK([for the compiler flag "-Wimplicit-fallthrough"], [ax_cv_cc_wimplicit_fallthrough_flag],[

    CFLAGS_SAVED=$CFLAGS
    CFLAGS="$CFLAGS -Werror -Wimplicit-fallthrough"

    AC_LANG_PUSH(C)
    AC_TRY_COMPILE(
      [],
      [return 0;],
      [ax_cv_cc_wimplicit_fallthrough_flag="yes"],
      [ax_cv_cc_wimplicit_fallthrough_flag="no"])
    AC_LANG_POP

    CFLAGS="$CFLAGS_SAVED"
  ])
])

AC_DEFUN([AX_CC_NO_DATE_TIME_FLAG],[
  AC_CACHE_CHECK([for the compiler flag "-Wno-date-time"], [ax_cv_cc_no_date_time_flag],[

    CFLAGS_SAVED=$CFLAGS
    CFLAGS="$CFLAGS -Werror -Wno-date-time"

    AC_LANG_PUSH(C)
    AC_TRY_COMPILE(
      [],
      [return 0;],
      [ax_cv_cc_no_date_time_flag="yes"],
      [ax_cv_cc_no_date_time_flag="no"])
    AC_LANG_POP

    CFLAGS="$CFLAGS_SAVED"
  ])
])

AC_DEFUN([AX_CC_PTHREAD_FLAG],[
  AC_CACHE_CHECK([for the compiler flag "-pthread"], [ax_cv_cc_pthread_flag],[

    CFLAGS_SAVED=$CFLAGS
    CFLAGS="$CFLAGS -Werror -pthread"

    AC_LANG_PUSH(C)
    AC_TRY_COMPILE(
      [],
      [return 0;],
      [ax_cv_cc_pthread_flag="yes"],
      [ax_cv_cc_pthread_flag="no"])
    AC_LANG_POP

    CFLAGS="$CFLAGS_SAVED"
  ])
])

AC_DEFUN([AX_CC_SANITZE_ADDRESS_USE_AFTER_SCOPE_FLAG],[
  AC_CACHE_CHECK([for the compiler flag "-fsanitize-address-use-after-scope"], [ax_cv_cc_sanitize_address_use_after_scope],[

    dnl # Need -fsanitize=address else we get an unused argument error
    CFLAGS_SAVED=$CFLAGS
    CFLAGS="$CFLAGS -Werror -fsanitize=address -fsanitize-address-use-after-scope"

    AC_LANG_PUSH(C)
    AC_TRY_COMPILE(
      [],
      [return 0;],
      [ax_cv_cc_sanitize_address_use_after_scope="yes"],
      [ax_cv_cc_sanitize_address_use_after_scope="no"])
    AC_LANG_POP

    CFLAGS="$CFLAGS_SAVED"
  ])
])

dnl #
dnl #  Check if we have the choose expr builtin
dnl #
AC_DEFUN([AX_CC_BUILTIN_CHOOSE_EXPR],
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
AC_DEFUN([AX_CC_BUILTIN_TYPES_COMPATIBLE_P],
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
AC_DEFUN([AX_CC_BUILTIN_BSWAP64],
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
  AC_DEFINE([HAVE_BUILTIN_BSWAP64],1,[Define if the compiler supports __builtin_bswap64])
fi
])

dnl #
dnl #  Check if we have the clzll builtin
dnl #
AC_DEFUN([AX_CC_BUILTIN_CLZLL],
[
AC_CACHE_CHECK([for __builtin_clzll support in compiler], [ax_cv_cc_builtin_clzll],[
  AC_RUN_IFELSE(
    [
      AC_LANG_SOURCE([
        int main(int argc, char **argv) {
          if ((argc < 0) || !argv) return 1; /* -Werror=unused-parameter */
          return (__builtin_clzll(0) - (sizeof(unsigned long long) * 8));
        }
      ])
    ],
    [ax_cv_cc_builtin_clzll=yes],
    [ax_cv_cc_builtin_clzll=no]
  )
])
if test "x$ax_cv_cc_builtin_clzll" = "xyes"; then
  AC_DEFINE([HAVE_BUILTIN_CLZLL],1,[Define if the compiler supports __builtin_clzll])
fi
])

dnl #
dnl # Determine the number of system cores we have
dnl #
AC_DEFUN([AX_SYSTEM_CORES],[
  AC_CACHE_CHECK([number of system cores], [ax_cv_system_cores],
    [
      AC_LANG_PUSH(C)
      AC_TRY_RUN(
        [
          #include <stdio.h>
          #include <stdint.h>
          #ifdef _WIN32
          #  include <windows.h>
          #elif MACOS
          #  include <sys/param.h>
          #  include <sys/sysctl.h>
          #else
          #  include <unistd.h>
          #endif

          int main (int argc, char *argv[])
          {
            uint32_t count;

            #ifdef WIN32
            SYSTEM_INFO sysinfo;
            GetSystemInfo(&sysinfo);

            count = sysinfo.dwNumberOfProcessors;

            #elif MACOS
            int nm[2];
            size_t len = 4;

            nm[0] = CTL_HW;
            nm[1] = HW_AVAILCPU;
            sysctl(nm, 2, &count, &len, NULL, 0);

            if(count < 1) {
              nm[1] = HW_NCPU;
              sysctl(nm, 2, &count, &len, NULL, 0);
              if(count < 1) {
                count = 1;
              }
            }

            #else
      	    count = sysconf(_SC_NPROCESSORS_ONLN);
            #endif

            return count;
          }
        ],
        [ax_cv_system_cores=$?],
        [ax_cv_system_cores=$?],
        [ax_cv_system_cores=]
    )
    AC_LANG_POP
  ])
])

