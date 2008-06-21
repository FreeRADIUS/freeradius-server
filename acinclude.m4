dnl See whether we need a declaration for a function.
dnl RADIUSD_NEED_DECLARATION(FUNCTION [, EXTRA-HEADER-FILES])
AC_DEFUN([RADIUSD_NEED_DECLARATION],
[AC_MSG_CHECKING([whether $1 must be declared])
AC_CACHE_VAL(radius_cv_decl_needed_$1,
[AC_TRY_COMPILE([
#include <stdio.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_RESOURCE_H
#include <resource.h>
#endif
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_UTMP_H
#include <utmp.h>
#endif
#ifdef HAVE_UTMPX_H
#include <utmpx.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif
#ifdef HAVE_REGEX_H
#include <regex.h>
#endif
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
$2],
[char *(*pfn) = (char *(*)) $1],
eval "radius_cv_decl_needed_$1=no", eval "radius_cv_decl_needed_$1=yes")])
if eval "test \"`echo '$radius_cv_decl_needed_'$1`\" = yes"; then
  AC_MSG_RESULT(yes)
  radius_tr_decl=NEED_DECLARATION_`echo $1 | tr 'abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'`
  AC_DEFINE_UNQUOTED($radius_tr_decl)
else
  AC_MSG_RESULT(no)
fi
])dnl

dnl Check multiple functions to see whether each needs a declaration.
dnl RADIUSD_NEED_DECLARATIONS(FUNCTION... [, EXTRA-HEADER-FILES])
AC_DEFUN([RADIUSD_NEED_DECLARATIONS],
[for ac_func in $1
do
RADIUSD_NEED_DECLARATION($ac_func, $2)
done
])

dnl Checks to see if this is SUNPro we're building with
dnl Usage:
dnl AC_PROG_CC_SUNPRO
AC_DEFUN([AC_PROG_CC_SUNPRO],
[AC_CACHE_CHECK(whether we are using SUNPro C, ac_cv_prog_suncc,
[dnl The semicolon is to pacify NeXT's syntax-checking cpp.
cat > conftest.c <<EOF
#ifdef __SUNPRO_C
  yes;
#endif
EOF
if AC_TRY_COMMAND(${CC-cc} -E conftest.c) | egrep yes >/dev/null 2>&1; then
  ac_cv_prog_suncc=yes
else
  ac_cv_prog_suncc=no
fi])])

dnl #
dnl # FR_CHECK_TYPE_INCLUDE([#includes ...], type, default-C-types)
dnl #
dnl # This function is like AC_CHECK_TYPE, but you can give this one
dnl # a list of include files to check.
dnl #
AC_DEFUN([FR_CHECK_TYPE_INCLUDE],
[
  AC_CACHE_CHECK(for $2, ac_cv_type_$2,
    [ ac_cv_type_$2=no
      AC_TRY_COMPILE($1,
        [$2 foo],
        ac_cv_type_$2=yes,
      )
    ]
  )

  if test "$ac_cv_type_$2" != "yes"; then
         AC_DEFINE($2, $3, $4)
  fi
])

dnl #
dnl #  Locate the directory in which a particular file is found.
dnl #
dnl #  Usage: FR_LOCATE_DIR(MYSQLLIB_DIR, libmysqlclient.a)
dnl #
dnl #    Defines the variable MYSQLLIB_DIR to be the directory(s) in
dnl #    which the file libmysqlclient.a is to be found.
dnl #
dnl #
AC_DEFUN([FR_LOCATE_DIR],
[
dnl # If we have the program 'locate', then the problem of finding a
dnl # particular file becomes MUCH easier.
dnl #

dnl #
dnl #  No 'locate' defined, do NOT do anything.
dnl #
if test "x$LOCATE" != "x"; then
  dnl #
  dnl #  Root through a series of directories, looking for the given file.
  dnl #
  DIRS=
  file=$2

  for x in `${LOCATE} $file 2>/dev/null`; do
    dnl #
    dnl #  When asked for 'foo', locate will also find 'foo_bar', which we
    dnl #  don't want.  We want that EXACT filename.
    dnl #
    dnl #  We ALSO want to be able to look for files like 'mysql/mysql.h',
    dnl #  and properly match them, too.  So we try to strip off the last
    dnl #  part of the filename, using the name of the file we're looking
    dnl #  for.  If we CANNOT strip it off, then the name will be unchanged.
    dnl #
    base=`echo $x | sed "s%/${file}%%"`
    if test "x$x" = "x$base"; then
      continue;
    fi

    dir=`${DIRNAME} $x 2>/dev/null`
    dnl #
    dnl #  Exclude a number of directories.
    dnl #
    exclude=`echo ${dir} | ${GREP} /home`
    if test "x$exclude" != "x"; then
      continue
    fi

    dnl #
    dnl #  OK, we have an exact match.  Let's be sure that we only find ONE
    dnl #  matching directory.
    dnl #
    already=`echo \$$1 ${DIRS} | ${GREP} ${dir}`
    if test "x$already" = "x"; then
      DIRS="$DIRS $dir"
    fi
  done
fi

dnl #
dnl #  And remember the directory in which we found the file.
dnl #
eval "$1=\"\$$1 $DIRS\""
])


dnl #######################################################################
dnl #
dnl #  Look for a library in a number of places.
dnl #
dnl #  FR_SMART_CHECK_LIB(library, function)
dnl #
AC_DEFUN([FR_SMART_CHECK_LIB], [

sm_lib_safe=`echo "$1" | sed 'y%./+-%__p_%'`
sm_func_safe=`echo "$2" | sed 'y%./+-%__p_%'`
AC_MSG_CHECKING([for $2 in -l$1])

old_LIBS="$LIBS"
smart_lib=
smart_lib_dir=

dnl #
dnl #  Try first any user-specified directory, otherwise we may pick up
dnl #  the wrong version.
dnl #
if test "x$smart_try_dir" != "x"; then
  for try in $smart_try_dir; do
    LIBS="-L$try -l$1 $old_LIBS"
    AC_TRY_LINK([extern char $2();],
		[ $2()],
		smart_lib="-L$try -l$1")
    if test "x$smart_lib" != "x"; then
      break;
    fi
  done
  LIBS="$old_LIBS"
fi

dnl #
dnl #  Try using the default library path
dnl #
if test "x$smart_lib" = "x"; then
  LIBS="-l$1 $old_LIBS"
  AC_TRY_LINK([extern char $2();],
	      [ $2()],
	      smart_lib="-l$1")
  LIBS="$old_LIBS"
fi

dnl #
dnl #  Try to guess possible locations.
dnl #
if test "x$smart_lib" = "x"; then
  FR_LOCATE_DIR(smart_lib_dir,[lib$1${libltdl_cv_shlibext}])
  FR_LOCATE_DIR(smart_lib_dir,[lib$1.a])

  for try in $smart_lib_dir /usr/local/lib /opt/lib; do
    LIBS="-L$try -l$1 $old_LIBS"
    AC_TRY_LINK([extern char $2();],
		[ $2()],
		smart_lib="-L$try -l$1")
    if test "x$smart_lib" != "x"; then
      break;
    fi
  done
  LIBS="$old_LIBS"
fi

dnl #
dnl #  Found it, set the appropriate variable.
dnl #
if test "x$smart_lib" != "x"; then
  AC_MSG_RESULT(yes)
  eval "ac_cv_lib_${sm_lib_safe}_${sm_func_safe}=yes"
  LIBS="$smart_lib $old_LIBS"
  SMART_LIBS="$smart_lib $SMART_LIBS"
else
  AC_MSG_RESULT(no)
fi
])

dnl #######################################################################
dnl #
dnl #  Look for a header file in a number of places.
dnl #
dnl #  FR_SMART_CHECK_INCLUDE(foo.h, [ #include <other.h> ])
dnl #
AC_DEFUN([FR_SMART_CHECK_INCLUDE], [

ac_safe=`echo "$1" | sed 'y%./+-%__pm%'`
AC_MSG_CHECKING([for $1])

old_CFLAGS="$CFLAGS"
smart_include=
smart_include_dir=

dnl #
dnl #  Try first any user-specified directory, otherwise we may pick up
dnl #  the wrong version.
dnl #
if test "x$smart_try_dir" != "x"; then
  for try in $smart_try_dir; do
    CFLAGS="$old_CFLAGS -I$try"
    AC_TRY_COMPILE([$2
		    #include <$1>],
		   [ int a = 1;],
		   smart_include="-I$try",
		   smart_include=)
    if test "x$smart_include" != "x"; then
      break;
    fi
  done
  CFLAGS="$old_CFLAGS"
fi

dnl #
dnl #  Try using the default includes.
dnl #
if test "x$smart_include" = "x"; then
  AC_TRY_COMPILE([$2
		  #include <$1>],
		 [ int a = 1;],
		 smart_include=" ",
		 smart_include=)
fi

dnl #
dnl #  Try to guess possible locations.
dnl #
if test "x$smart_include" = "x"; then
  FR_LOCATE_DIR(smart_include_dir,$1)

  for try in $smart_include_dir /usr/local/include /opt/include; do
    CFLAGS="$old_CFLAGS -I$try"
    AC_TRY_COMPILE([$2
		    #include <$1>],
		   [ int a = 1;],
		   smart_include="-I$try",
		   smart_include=)
    if test "x$smart_include" != "x"; then
      break;
    fi
  done
  CFLAGS="$old_CFLAGS"
fi

dnl #
dnl #  Found it, set the appropriate variable.
dnl #
if test "x$smart_include" != "x"; then
  AC_MSG_RESULT(yes)
  eval "ac_cv_header_$ac_safe=yes"
  CFLAGS="$old_CFLAGS $smart_include"
  SMART_CFLAGS="$SMART_CFLAGS $smart_include"
else
  AC_MSG_RESULT(no)
fi
])

dnl #######################################################################
dnl #
dnl #  Look for a header file in a number of places.
dnl #
dnl #  Usage:  FR_CHECK_STRUCT_HAS_MEMBER([#include <foo.h>], [struct foo], member)
dnl #  If the member is defined, then the variable
dnl #     ac_cv_type_struct_foo_has_member is set to 'yes'
dnl #
AC_DEFUN([FR_CHECK_STRUCT_HAS_MEMBER], [
  AC_MSG_CHECKING([for $3 in $2])

dnl BASED on 'offsetof':
dnl #define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
dnl

  AC_TRY_COMPILE([
$1
#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((int) &((TYPE *)0)->MEMBER)
#endif
],
                 [ int foo = offsetof($2, $3) ],
                 has_element=" ",
                 has_element=)

  ac_safe_type=`echo "$2" | sed 'y% %_%'`
  if test "x$has_element" != "x"; then
    AC_MSG_RESULT(yes)
    eval "ac_cv_type_${ac_safe_type}_has_$3=yes"
  else
    AC_MSG_RESULT(no) 
    eval "ac_cv_type_${ac_safe_type}_has_$3="
 fi
])

dnl Autoconf 2.61 breaks the support for chained configure scripts
dnl in combination with config.cache
m4_pushdef([AC_OUTPUT],
[
  unset ac_cv_env_LIBS_set
  unset ac_cv_env_LIBS_value
  m4_popdef([AC_OUTPUT])
  AC_OUTPUT([$1],[$2],[$3])
])

AC_INCLUDE(aclocal.m4)
