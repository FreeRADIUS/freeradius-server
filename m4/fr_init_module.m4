dnl Macro to set the module name and other useful common functions
dnl
dnl Usages:
dnl   FR_INIT_MODULE([rlm_example])
dnl   FR_INIT_MODULE([rlm_example], [the example module])
dnl
AC_DEFUN([FR_INIT_MODULE],
[
  AC_DEFUN([modname],$1)

  AC_ARG_WITH([$1],
    [AS_HELP_STRING([--without-$1],[build without ]ifelse([$2],[],[$1],[$2]))])
])
