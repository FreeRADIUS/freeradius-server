#
# SYNOPSIS
#
#   AX_WITH_FEATURE_ARGS(FEATURE)
#
# DESCRIPTION
#
#   Adds boilerplate arguments for controlling whether a feature is built
#
AC_DEFUN([AX_WITH_FEATURE_ARGS],[
    m4_toupper(with_$1)=m4_default([$2], [yes])
    
    AC_ARG_WITH([$1],
        [AS_HELP_STRING([--with-$1],
        [compile in support for $1 (default=$2)])],
        [case "$withval" in
            yes|no|'')
                ;;
            no|'')
                ;;
            *)
                AC_MSG_ERROR([--with[[out]]-$1 expects yes|no])
                ;;
        esac])

    if test x"$withval" == x"yes"; then
        AC_DEFINE(m4_toupper(with_$1), [1], [define if you want $1])
    else
        AC_DEFINE(m4_toupper(with_$1), [], [define if you want $1])
    fi
])
