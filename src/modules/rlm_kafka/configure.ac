AC_PREREQ([2.69])
AC_INIT
AC_CONFIG_SRCDIR([rlm_kafka.c])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_kafka], [Kafka event processing platform support])

SMART_LIBS=
SMART_CLFAGS=

FR_MODULE_START_TESTS

dnl ############################################################
dnl # Check for command line options
dnl ############################################################

dnl extra argument: --with-kafka-include-dir=DIR
kafka_include_dir=
AC_ARG_WITH(kafka-include-dir,
	[AS_HELP_STRING([--with-kafka-include-dir=DIR],
		[Directory where the kafka includes may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need kafka-include-dir)
		;;
	yes)
		;;
	*)
		kafka_include_dir="$withval"
		;;
	esac])

dnl extra argument: --with-kafka-lib-dir=DIR
kafka_lib_dir=
AC_ARG_WITH(kafka-lib-dir,
	[AS_HELP_STRING([--with-kafka-lib-dir=DIR],
		[Directory where the kafka libraries may be found])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need kafka-lib-dir)
		;;
	yes)
		;;
	*)
		kafka_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-kafka-dir=DIR
AC_ARG_WITH(kafka-dir,
	[AS_HELP_STRING([--with-kafka-dir=DIR],
		[Base directory where kafka is installed])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need kafka-dir)
		;;
	yes)
		;;
	*)
		kafka_lib_dir="$withval/lib"
		kafka_include_dir="$withval/include"
		;;
	esac])

dnl extra argument: --with-openssl-lib-dir
openssl_lib_dir=
AC_ARG_WITH(openssl-lib-dir,
	[AS_HELP_STRING([--with-openssl-lib-dir=DIR],
		[directory for OpenSSL library files])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need openssl-lib-dir)
		;;
	yes)
		;;
	*)
		openssl_lib_dir="$withval"
		;;
	esac])

dnl extra argument: --with-openssl-include-dir
openssl_include_dir=
AC_ARG_WITH(openssl-include-dir,
	[AS_HELP_STRING([--with-openssl-include-dir=DIR],
		[directory for OpenSSL include files])],
	[case "$withval" in
	no)
		AC_MSG_ERROR(Need openssl-include-dir)
		;;
	yes)
		;;
	*)
		openssl_include_dir="$withval"
		;;
	esac])

dnl ############################################################
dnl # Check for programs
dnl ############################################################

AC_PROG_CC

dnl ############################################################
dnl # Check for header files
dnl ############################################################

smart_try_dir="${kafka_include_dir}"
FR_SMART_CHECK_INCLUDE([librdkafka/rdkafka.h])
if test "x$ac_cv_header_librdkafka_rdkafka_h" != "xyes"; then
	AC_MSG_WARN([kafka headers not found. Use --with-kafka-include-dir=<path>.])
	FR_MODULE_FAIL([rdkafka.h])
fi

AC_EGREP_CPP(yes,
	[#include <openssl/crypto.h>
		#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
		yes
		#endif
	],
	[
		AC_MSG_CHECKING([for OpenSSL version >= 1.1.0])
		AC_MSG_RESULT(yes)
	],
	[
		AC_MSG_CHECKING([for OpenSSL version >= 1.1.0])
		AC_MSG_RESULT(no)
		FR_MODULE_FAIL([OpenSSL>=1.1.0])
	]
)

dnl ############################################################
dnl # Check for librdkafka library
dnl ############################################################

smart_try_dir="$kafka_lib_dir"
FR_SMART_CHECK_LIB(rdkafka, rd_kafka_new)
if test "x$ac_cv_lib_rdkafka_rd_kafka_new" != "xyes"
then
	AC_MSG_WARN([kafka libraries not found. Use --with-kafka-lib-dir=<path>.])
	FR_MODULE_FAIL([librdkafka])
fi

dnl ############################################################
dnl # Checks done - set targetname
dnl ############################################################

FR_MODULE_END_TESTS

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_CONFIG_FILES([all.mk])
AC_OUTPUT
