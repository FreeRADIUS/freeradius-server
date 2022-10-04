dnl Macro to set the module name and other useful common functions
dnl
dnl Usages:
dnl   FR_INIT_MODULE([rlm_example])
dnl   FR_INIT_MODULE([rlm_example], [the example module])
dnl
AC_DEFUN([FR_INIT_MODULE],
[
  AC_DEFUN([modname],$1)
  AC_DEFUN([modname_useropt],[m4_bpatsubst([]modname,[[-+.]],[_])])

  AC_ARG_WITH([$1],
    [AS_HELP_STRING([--without-$1],[build without ]ifelse([$2],[],[$1],[$2]))])
])

AC_DEFUN([FR_INIT_LIBRARY], m4_defn([FR_INIT_MODULE]))
