AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_sql_mongo.c])
AC_REVISION($Revision: 1.10 $)
FR_INIT_MODULE([rlm_sql_mongo])

mongoc_ldflags=
mongoc_cflags=

FR_MODULE_START_TESTS

AC_ARG_WITH(mongoc_lib_dir,
	[AS_HELP_STRING([--with-mongoc-lib-dir],
		[Path of libmongoc libraries])],
	[ mongoc_lib_dir="$withval" ],
	[ mongoc_lib_dir="" ])

AC_ARG_WITH(mongoc_include_dir,
	[AS_HELP_STRING([--with-mongoc-include-dir],
		[Path of libmongoc includes])],
	[ mongoc_include_dir="$withval" ],
	[ mongoc_include_dir="" ])

AC_ARG_WITH(bson_lib_dir,
	[AS_HELP_STRING([--with-bson-lib-dir],
		[Path of libbson libraries])],
	[ bson_lib_dir="$withval" ],
	[ bson_lib_dir="" ])

AC_ARG_WITH(bson_include_dir,
	[AS_HELP_STRING([--with-bson-include-dir],
		[Path of libbson includes])],
	[ bson_include_dir="$withval" ],
	[ bson_include_dir="" ])

dnl ######################################################
dnl # Check for header files of Bson Libraries
dnl ######################################################

CFLAGS_PRE="$CFLAGS"
if test x$bson_include_dir != x ; then
	bson_cflags="-isystem ${bson_include_dir}"
else
	bson_cflags="-isystem /usr/include/libbson-1.0"
fi
CFLAGS="$CFLAGS ${bson_cflags}"

AC_CHECK_HEADER([bson/bson.h], [], [], [#include <bson/bson.h>])
CFLAGS="$CFLAGS_PRE"

if test "x$ac_cv_header_bson_bson_h" != "xyes"; then
	FR_MODULE_FAIL([bson/bson.h])
fi

dnl ######################################################
dnl # Check for libraries of Bson
dnl ######################################################

LDFLAGS_PRE="$LDFLAGS"
if test x$bson_lib_dir != x ; then
	bson_ldflags="-L${bson_lib_dir} -lbson-1.0"
else
	bson_ldflags="-L/usr/lib -lbson-1.0"
fi
LDFLAGS="$LDFLAGS ${bson_ldflags}"

AC_CHECK_LIB(bson-1.0, [ bson_iter_init_find ], [], [])
LDFLAGS="$LDFLAGS_PRE"

if test "x$ac_cv_lib_bson_1_0__bson_iter_init_find_" != "xyes"; then
	FR_MODULE_FAIL([libbson])
fi

dnl ######################################################
dnl # Check for header files of MongoC Libraries
dnl ######################################################

CFLAGS_PRE="$CFLAGS"
if test x$mongoc_include_dir != x ; then
	mongoc_cflags="-isystem ${mongoc_include_dir} ${bson_cflags}"
else
	mongoc_cflags="-isystem /usr/include/libmongoc-1.0 ${bson_cflags}"
fi
CFLAGS="$CFLAGS ${mongoc_cflags}"

AC_CHECK_HEADER([mongoc.h], [], [], [#include <mongoc.h>])
CFLAGS="$CFLAGS_PRE"

if test "x$ac_cv_header_mongoc_h" != "xyes"; then
	FR_MODULE_FAIL([mongoc.h])
fi

dnl ######################################################
dnl # Check for libraries of MongoC
dnl ######################################################

LDFLAGS_PRE="$LDFLAGS"
if test x$mongoc_lib_dir != x ; then
	mongoc_ldflags="-L${mongoc_lib_dir} -lmongoc-1.0 ${bson_ldflags}"
else
	mongoc_ldflags="-L/usr/lib -lmongoc-1.0 ${bson_ldflags}"
fi
LDFLAGS="$LDFLAGS ${mongoc_ldflags}"

AC_CHECK_LIB(mongoc-1.0, [ mongoc_init ], [], [])
LDFLAGS="$LDFLAGS_PRE"

if test "x$ac_cv_lib_mongoc_1_0__mongoc_init_" != "xyes"; then
	FR_MODULE_FAIL([libmongoc-1.0])
fi

FR_MODULE_END_TESTS

AC_SUBST(mongoc_cflags)
AC_SUBST(mongoc_ldflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
