AC_PREREQ([2.71])
AC_INIT
AC_CONFIG_SRCDIR([rlm_brotli.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_brotli], [support for the brotli compression scheme])

FR_MODULE_START_TESTS

dnl ############################################################
dnl # Check for command line options
dnl ############################################################

dnl ############################################################
dnl # brotli options
dnl ############################################################

dnl extra argument: --with-brotli-include-dir=DIR
brotli_include_dir=
AC_ARG_WITH(brotli-include-dir,
	[AS_HELP_STRING([--with-brotli-include-dir=DIR],
		[Directory where the brotli includes may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need brotli-include-dir)
		;;
	yes)
		;;
	*)
		brotli_include_dir="$withval"
		;;
	esac])

dnl extra argument: --with-brotli-lib-dir=DIR
brotli_lib_dir=
AC_ARG_WITH(brotli-lib-dir,
	[AS_HELP_STRING([--with-brotli-lib-dir=DIR],
		[Directory where the brotli libraries may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need brotli-lib-dir)
		;;
	yes)
		;;
	*)
		brotli_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-brotli-dir=DIR
AC_ARG_WITH(brotli-dir,
	[AS_HELP_STRING([--with-brotli-dir=DIR],
		[Base directory where brotli is installed])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need brotli-dir)
		;;
	yes)
		;;
	*)
		brotli_lib_dir="$withval/lib"
		brotli_include_dir="$withval/include"
		;;
	esac])

dnl ############################################################
dnl # Check for brotli header files (optional)
dnl ############################################################

have_brotli="yes"
smart_try_dir="$brotli_include_dir"
FR_SMART_CHECK_INCLUDE(brotli/encode.h)
if test "x$ac_cv_header_brotli_encode_h" != "xyes"; then
	have_ykclient="no"
	AC_MSG_WARN([brotli headers not found. Use --with-brotli-include-dir=<path>.])
fi

FR_SMART_CHECK_INCLUDE(brotli/decode.h)
if test "x$ac_cv_header_brotli_decode_h" != "xyes"; then
	have_ykclient="no"
	AC_MSG_WARN([brotli headers not found. Use --with-brotli-include-dir=<path>.])
fi


dnl ############################################################
dnl # Check for brotli libraries (optional)
dnl ############################################################

dnl try to link to brotli
smart_try_dir="$brotli_lib_dir"
FR_SMART_CHECK_LIB(brotlienc, BrotliEncoderCompress)
if test "x$ac_cv_lib_brotlienc_BrotliEncoderCompress" != "xyes"; then
	have_brotli="no"
	AC_MSG_WARN([brotli encode library not found. Use --with-brotli-lib-dir=<path>.])
fi

dnl try to link to brotli
smart_try_dir="$brotli_lib_dir"
FR_SMART_CHECK_LIB(brotlidec, BrotliDecoderDecompress)
if test "x$ac_cv_lib_brotlidec_BrotliDecoderDecompress" != "xyes"; then
	have_brotli="no"
	AC_MSG_WARN([brotli decode library not found. Use --with-brotli-lib-dir=<path>.])
fi

if test "x$have_brotli" = "xyes"; then
	AC_DEFINE([HAVE_brotli],[1],[Build with brotli compression/decompression support])
else
	AC_MSG_WARN([silently building without brotli compression support. requires: libbrotli])
	FR_MODULE_FEATURE([brotli], [without brotli compression support])
fi

FR_MODULE_END_TESTS

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_cflags)
AC_SUBST(mod_ldflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
