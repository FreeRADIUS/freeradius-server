#
# SYNOPSIS
#
#   AX_WITH_LIB_ARGS(LIBRARY)
#   AX_WITH_LIB_ARGS_OPT(LIBRARY, DEFAULT)
#
# DESCRIPTION
#
#   Adds boilerplate arguments for controlling the location of library lib and
#   include directories.
#
AC_DEFUN([AX_WITH_LIB_ARGS],[
    dnl #
    dnl #  extra argument: --with-$1-lib-dir=DIR
    dnl #
    AC_ARG_WITH([$1-lib-dir],
        [AS_HELP_STRING([--with-$1-lib-dir=DIR],
        [directory in which to look for $1 library files])],
        [case "$withval" in
            yes|no|'')      
                AC_MSG_ERROR([--with[[out]]-$1-lib=PATH expects a valid PATH])
                ;;
            *)
                $1_lib_dir="$withval"
                ;;
        esac])

    dnl #
    dnl #  extra argument: --with-$1-include-dir=DIR
    dnl #
    AC_ARG_WITH([$1-include-dir],
        [AS_HELP_STRING([--with-$1-include-dir=DIR],
        [directory in which to look for $1 include files])],
        [case "$withval" in
            yes|no|'')      
                AC_MSG_ERROR([--with[[out]]-$1-include=PATH expects a valid PATH])
                ;;

            *)
                $1_include_dir="$withval"
                ;;
    esac])  
])

AC_DEFUN([AX_WITH_LIB_ARGS_OPT],[
    m4_toupper(with_$1)=m4_default([$2], [yes])
    
    dnl #
    dnl #  extra argument: --with-$1-lib-dir=DIR
    dnl #
    AC_ARG_WITH([$1],
        [AS_HELP_STRING([--with-$1],
        [build with $1 if available (default=$2)])],
        [case "$withval" in
            yes|no|'')      
                m4_toupper(with_$1)="$withval"
                ;;
            *)
                AC_MSG_ERROR([--with[[out]]-$1 expects yes|no|''])
                ;;
        esac])
    
    AX_WITH_LIB_ARGS($1)
])