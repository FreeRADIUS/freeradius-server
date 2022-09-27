dnl Macro to set the module name for use later on.
dnl
AC_DEFUN([FR_INIT_MODULE],
[
AC_DEFUN([modname],$1)

AC_ARG_WITH([$1],
[AS_HELP_STRING([--without-$1],[build without ]ifelse([$2],[],[$1],[$2]))])
])
