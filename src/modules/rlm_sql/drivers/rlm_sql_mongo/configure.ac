AC_INIT(rlm_sql_mongo.c)
AC_REVISION($Revision: 1.10 $)
AC_DEFUN(modname,[rlm_sql_mongo])

fail=
mongoc_ldflags=
mongoc_cflags=

if test x$with_[]modname != xno; then

  AC_ARG_WITH(mongoc_lib_dir, [AC_HELP_STRING([--with-mongoc-lib-dir],
              [Path of libmongoc libraries])],
              [ mongoc_lib_dir="$withval" ], [ mongoc_lib_dir="" ])
  AC_ARG_WITH(mongoc_include_dir, [AC_HELP_STRING([--with-mongoc-include-dir],
              [Path of libmongoc includes])],
              [ mongoc_include_dir="$withval" ], [ mongoc_include_dir="" ])

  dnl ######################################################
  dnl # Check for header files of MongoC Libraries
  dnl ######################################################

  CFLAGS_PRE="$CFLAGS"
  if test x$mongoc_include_dir != x ; then
    mongoc_cflags="-I${mongoc_include_dir}"
  else
    mongoc_cflags="-I/usr/include/libmongoc-1.0 -I/usr/include/libbson-1.0"
  fi
  CFLAGS="$CFLAGS ${mongoc_cflags}"

  AC_CHECK_HEADER([mongoc.h], [],
                  [AC_MSG_ERROR([Libmongoc headers not found. Use --with-mongoc-include-dir=<path>.])],
                  [#include <mongoc.h>])
  CFLAGS="$CFLAGS_PRE"

  dnl ######################################################
  dnl # Check for libraries of MongoC
  dnl ######################################################

  LDFLAGS_PRE="$LDFLAGS"
  if test x$mongoc_lib_dir != x ; then
    mongoc_ldflags="-L${mongoc_lib_dir} -lmongoc-1.0 -lbson-1.0"
  else
    mongoc_ldflags="-L/usr/lib -lmongoc-1.0 -lbson-1.0"
  fi
  LDFLAGS="$LDFLAGS ${mongoc_ldflags}"

  AC_CHECK_LIB(mongoc-1.0, [ mongoc_init ], mongoc_present=1, mongoc_present=0)

  if test $mongoc_present -eq 0 ; then
    AC_MSG_ERROR([MongoC libraries not found. Use --with-mongoc-lib-dir=<path>.])
  fi
  LDFLAGS="$LDFLAGS_PRE"

  targetname=modname
else
  targetname=
  echo \*\*\* module modname is disabled.
fi

dnl Don't change this section.
if test "x$fail" != x; then
  if test "${enable_strict_dependencies}" = "yes"; then
    AC_MSG_ERROR([set --without-]modname[ to disable it explicitly.])
  else
    AC_MSG_WARN([silently not building ]modname[.])
    AC_MSG_WARN([FAILURE: ]modname[ requires:$fail.]);
    targetname=
  fi
fi

AC_SUBST(mongoc_cflags)
AC_SUBST(mongoc_ldflags)
AC_SUBST(targetname)
AC_OUTPUT(all.mk)
