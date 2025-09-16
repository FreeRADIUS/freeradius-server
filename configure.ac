dnl #############################################################
dnl #
dnl #  For information about autoconf, see:
dnl #
dnl #  http://www.gnu.org/software/autoconf/
dnl #
dnl #  The recommended order is:
dnl #
dnl #  AC_INIT
dnl #  0. checks for compiler, libtool, and command line options
dnl #  1. checks for programs
dnl #  2. checks for libraries
dnl #  3. checks for header files
dnl #  4. checks for typedefs
dnl #  5. checks for structures and functions
dnl #  6. checks for compiler characteristics
dnl #  7. checks for library functions
dnl #  8. checks for system services
dnl #  AC_OUTPUT
dnl #
dnl #############################################################

AC_PREREQ([2.69])
export CFLAGS LIBS LDFLAGS CPPFLAGS

AC_INIT([freeradius],[$Id$],[http://bugs.freeradius.org],[],[http://www.freeradius.org])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/main/radiusd.c])
AC_CONFIG_HEADER([src/include/autoconf.h])

dnl #############################################################
dnl #
dnl #  Custom hackery to discover version at configure time
dnl #
dnl #############################################################
RADIUSD_MAJOR_VERSION=`cat VERSION | cut -f1 -d.`
RADIUSD_MINOR_VERSION=`cat VERSION | cut -f2 -d.`
RADIUSD_INCRM_VERSION=`cat VERSION | cut -f3 -d. | sed 's/[[\.-]].*$//'`

RADIUSD_VERSION=`printf "%02i%02i%02i" $RADIUSD_MAJOR_VERSION $RADIUSD_MINOR_VERSION $RADIUSD_INCRM_VERSION`

dnl #
dnl #  Still useful for custom builds
dnl #
RADIUSD_VERSION_STRING=`cat VERSION`

dnl #
dnl #  Add definitions to Make.inc as it's used by various build targets
dnl #
AC_SUBST([RADIUSD_VERSION_STRING])

dnl #
dnl #  Add definitions to autoconf.h, so that the headers that we install
dnl #  contain the version number of the server.
dnl #
AC_DEFINE_UNQUOTED([RADIUSD_VERSION], [${RADIUSD_VERSION}], [Version integer in format <ma><ma><mi><mi><in><in>])
AC_DEFINE_UNQUOTED([RADIUSD_VERSION_STRING], ["${RADIUSD_VERSION_STRING}"], [Raw version string from VERSION file])

dnl #############################################################
dnl #
dnl #  Override some of the default autoconf variables such as
dnl #  CFLAGS if were building in developer mode
dnl #
dnl #############################################################

dnl #
dnl #  Unset ASAN_OPTIONS and LSAN_OPTIONS so they don't interfere
dnl #  with the build process.
dnl #
unset ASAN_OPTIONS
unset LSAN_OPTIONS

dnl #
dnl # check for JSON.pm, ASCIIDOCTOR and pandoc
dnl #
AC_PATH_PROG(ASCIIDOCTOR, asciidoctor)
if test "x$ac_cv_path_ASCIIDOCTOR" = "x"; then
  AC_MSG_WARN([asciidoctor not found - Please install if you want build the docs])
fi

AC_PATH_PROG(PANDOC, pandoc)
if test "x$ac_cv_path_PANDOC" = "x"; then
  AC_MSG_WARN([pandoc not found - Please install if you want build the docs])
else
  #
  #  Pandoc v2 onwards renamed --latex-engine to --pdf-engine
  #
  if pandoc --help 2>&1 | grep -q "latex-engine"; then
    PANDOC_ENGINE=latex
  else
    PANDOC_ENGINE=pdf
  fi
  AC_SUBST(PANDOC_ENGINE)
fi

# pandoc and asciidoctor is defined? then check it.
if test "x$ac_cv_path_PANDOC" != "x" && test "x$ac_cv_path_ASCIIDOCTOR" != "x"; then
  AX_PROG_PERL_MODULES(JSON, , AC_MSG_WARN([Perl JSON module not found - Please install if you want build the docs]))
fi

dnl #
dnl # check for doxygen
dnl #
AC_PATH_PROG(DOXYGEN, doxygen)
if test "x$ac_cv_path_DOXYGEN" != "x"; then
  AC_PATH_PROG(GRAPHVIZ_DOT, dot)
  if test "x$ac_cv_path_GRAPHVIZ_DOT" = "x"; then
    AC_MSG_WARN([dot not found - Please install the graphviz if you want to build the docs/source])
  fi
else
  AC_MSG_WARN([doxygen not found - Please install if you want build the docs/source])
fi

dnl #
dnl # check for Antora
dnl #
AC_PATH_PROG(ANTORA, antora)
if test "x$ac_cv_path_ANTORA" = "x"; then
  AC_MSG_WARN([antora not found - Please install if you want build the site])
fi

dnl #
dnl #  Enable developer features like debugging symbols.
dnl #  These checks must be done before expanding the AC_PROG_CC
dnl #  and AC_PROG_CXX macros.
dnl #
AC_ARG_ENABLE(developer,
[  --enable-developer      enables features of interest to developers.],
[ case "$enableval" in
  no)
    developer=no
    ;;
  *)
    developer=yes
  esac ]
)

dnl #
dnl #  Turn on the developer flag when taken from a git checkout (not a release)
dnl #
if test -d $srcdir/.git; then
  if test "x$developer" != "xno"; then
    AC_MSG_NOTICE([found .git directory, enabling developer build implicitly, disable with --disable-developer])
    developer="yes"
  fi
fi

dnl #
dnl #  Autoconf sets -O2 and -g by default, but this is a PITA for debugging
dnl #  so we remove the defaults if were building in developer mode, and set
dnl #  -g3 so nice things like macro values are included. Other arguments are
dnl #  added later when we know what compiler were using.
dnl #
if test "x$developer" = "xyes"; then
  : ${CFLAGS=-g3}
fi

dnl #
dnl #  The developer option WITH_VERIFY_PTR significantly scews profiling so
dnl #  we allow it to be disabled.
dnl #
AC_ARG_ENABLE(verify-ptr,
[  --disable-verify-ptr    disables WITH_VERIFY_PTR developer build option.],
[ case "$enableval" in
  no)
    verify_ptr=""
    ;;
  *)
    verify_ptr="-DWITH_VERIFY_PTR=1"
  esac ],
[ verify_ptr="-DWITH_VERIFY_PTR=1" ],
)

dnl #
dnl #  Hard-code FIPS support/
dnl #
AC_ARG_ENABLE(fips-workaround,
[  --enable-fips-workaround    enables local MD4, MD5, etc. functionality to avoid OpenSSL FIPS issues.],
[ case "$enableval" in
  no)
    ;;
  *)
    CFLAGS="$CFLAGS -DWITH_FIPS=1"
  esac ],
[ ],
)

dnl #############################################################
dnl #
dnl #  0. Checks for compiler, libtool, and command line options.
dnl #
dnl #############################################################

dnl #
dnl #  Get system information
dnl #
AC_CANONICAL_TARGET

dnl #
dnl #  clang etc. on OSX no longer searches the default paths for things,
dnl #  so we have to add them back in.
dnl #
case "$host" in
  *-darwin*)
    CFLAGS="$CFLAGS -DDARWIN"
    LDFLAGS="-L/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib $LDFLAGS"
    LIBS="-F /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/ -framework DirectoryService $LIBS"
    ;;
esac


dnl #
dnl #  Check for GNU cc
dnl #
AC_PROG_CC
AC_PROG_CXX

dnl #
dnl #  check for AIX, to allow us to use some BSD functions
dnl #  must be before macros that call the compiler.
dnl #
AC_USE_SYSTEM_EXTENSIONS

AC_PROG_GCC_TRADITIONAL
AC_PROG_CC_SUNPRO
AC_PROG_RANLIB

dnl #
dnl #  Definitive check for whether the compiler is clang
dnl #
AX_CC_IS_CLANG
if test "x$ax_cv_cc_clang" = "xyes"; then
  AC_SUBST(clang_path, "$CC")
else
  AC_SUBST(clang_path, "")
fi


dnl #
dnl #  Set Default CFLAGS for GCC compatible compilers
dnl #
if test "x$GCC" = "xyes"; then
  CFLAGS="$CFLAGS -Wall -std=c99 -D_GNU_SOURCE"
fi

dnl #
dnl # -Wno-unknown-warning-option means the compiler doesn't complain about diag pragmas
dnl # for warnings it doesn't understand.  This may sound like a bad idea, but consider
dnl # the number of different compiler versions we build under, and the fact that the
dnl # more anally retentive warnings are likely to be added in later versions.
dnl #
AX_CC_NO_UNKNOWN_WARNING_OPTION_FLAG
if test "x$ax_cv_cc_no_unknown_warning_option_flag" = "xyes"; then
  CFLAGS="$CFLAGS -Wno-unknown-warning-option"
fi

dnl #
dnl #  -Qunused-arguments means the compiler won't complain about unsupported arguments
dnl #
AX_CC_QUNUSED_ARGUMENTS_FLAG
if test "x$ax_cv_cc_qunused_arguments_flag" = "xyes"; then
  CFLAGS="$CFLAGS -Qunused-arguments"
  LDFLAGS="$LDFLAGS -Qunused-arguments"
fi

dnl #
dnl # Check for presence of -Wno-date-time warning. Older compilers
dnl # don't have it, and newer compilers warn without it...
dnl #
AX_CC_NO_DATE_TIME_FLAG

dnl #
dnl #  Compile in large (2G+) file support.
dnl #
AC_SYS_LARGEFILE

dnl #
dnl #  check for system bytesex
dnl #  AC_DEFINES WORDS_BIGENDIAN
dnl #
AC_C_BIGENDIAN(
  [AC_DEFINE(FR_BIG_ENDIAN, 1, [Define if your processor stores words with the most significant byte first])],
  [AC_DEFINE(FR_LITTLE_ENDIAN, 1, [Define if your processor stores words with the least significant byte first])]
)

dnl #
dnl #  Find GNU Make.
dnl #
AC_CHECK_PROG(GMAKE, gmake, yes, no)
if test $GMAKE = no; then
  AC_PATH_PROG(MAKE, make, /usr/local/bin/make)
else
  AC_PATH_PROG(MAKE, gmake, /usr/local/gnu/bin/make)
fi
makever=`$ac_cv_path_MAKE --version 2>&1 | grep "GNU Make"`
if test -z "$makever"; then
  AC_MSG_ERROR([GNU Make is not installed.  Please download and install it from ftp://prep.ai.mit.edu/pub/gnu/make/ before continuing.])
fi

dnl #
dnl #  autoconf explicitly sets MAKEFLAGS and MFLAGS to '' even though we
dnl #  didn't tell it to, so we have to use FR_MAKEFLAGS.
dnl #
dnl #  determine the number of cores available and set the number of build
dnl #  processes appropriately.
dnl #
AX_SYSTEM_CORES

dnl #  Temporarily disabled because test and installation targets do not
dnl #  have dependencies set up correctly for multiple build processes.
dnl if test "x$ax_cv_system_cores" != "x"; then
dnl  : ${FR_MAKEFLAGS=-j$ax_cv_system_cores}
dnl fi
AC_SUBST(FR_MAKEFLAGS)

dnl #
dnl #  See if we have Git.
dnl #
AC_CHECK_PROG(GIT, git, yes, no)

dnl Put this in later, when all distributed modules use autoconf.
dnl AC_ARG_WITH(disablemodulefoo,
dnl [  --without-rlm_foo         Disables module compilation.  Module list:]
dnl esyscmd([find src/modules -type d -name rlm_\* -print |\
dnl   sed -e 's%src/modules/.*/% (sub)- %; s%.*/%- %' |\
dnl   awk '{print "                            "$0}']))

AC_ARG_ENABLE(strict-dependencies,
[  --enable-strict-dependencies  fail configure on lack of module dependancy.])

AC_ARG_ENABLE(werror,
[  --enable-werror         causes the build to fail if any warnings are generated.],
[ case "$enableval" in
    no)
      werror=no
    ;;
    *)
      werror=yes
  esac ]
)

dnl #
dnl #  extra argument: --with-docdir
dnl #
docdir='${datadir}/doc/freeradius'
AC_MSG_CHECKING([docdir])
AC_ARG_WITH(docdir,
[  --with-docdir=DIR       directory for documentation [DATADIR/doc/freeradius] ],
[ case "$withval" in
  no)
    docdir=no
    ;;
  yes)
    ;;
  [[\\/$]]* | ?:[[\\/]]* )
    docdir="$withval"
    ;;
  *)
    AC_MSG_ERROR([expected an absolute directory name for --with-docdir: $withval])
    ;;
  esac ]
)
AC_SUBST(docdir)
AC_MSG_RESULT($docdir)
if test "x$docdir" = xno; then
  AC_MSG_WARN([Documentation files will NOT be installed.])
fi

dnl #
dnl #  extra argument: --with-logdir
dnl #
logdir='${localstatedir}/log/radius'
AC_MSG_CHECKING(logdir)
AC_ARG_WITH(logdir,
[  --with-logdir=DIR       directory for logfiles [LOCALSTATEDIR/log/radius] ],
[ case "$withval" in
  no)
    AC_MSG_ERROR([Need logdir])
    ;;
  yes)
    ;;
  [[\\/$]]* | ?:[[\\/]]* )
    logdir="$withval"
    ;;
  *)
    AC_MSG_ERROR([expected an absolute directory name for --with-logdir: $withval])
    ;;
  esac ]
)
AC_SUBST(logdir)
AC_MSG_RESULT($logdir)

dnl #
dnl #  extra argument: --with-radacctdir
dnl #
radacctdir='${logdir}/radacct'
AC_MSG_CHECKING(radacctdir)
AC_ARG_WITH(radacctdir,
[  --with-radacctdir=DIR   directory for detail files [LOGDIR/radacct] ],
[ case "$withval" in
  no)
    AC_MSG_ERROR([Need radacctdir])
    ;;
  yes)
    ;;
  [[\\/$]]* | ?:[[\\/]]* )
    radacctdir="$withval"
    ;;
  *)
    AC_MSG_ERROR([expected an absolute directory name for --with-radacctdir: $withval])
    ;;
  esac ]
)
AC_SUBST(radacctdir)
AC_MSG_RESULT($radacctdir)

dnl #
dnl #  extra argument: --with-raddbdir
dnl #
raddbdir='${sysconfdir}/raddb'
AC_MSG_CHECKING(raddbdir)
AC_ARG_WITH(raddbdir,
[  --with-raddbdir=DIR     directory for config files [SYSCONFDIR/raddb] ],
[ case "$withval" in
  no)
    AC_MSG_ERROR([Need raddbdir])
    ;;
  yes)
    ;;
  [[\\/$]]* | ?:[[\\/]]* )
    raddbdir="$withval"
    ;;
  *)
    AC_MSG_ERROR([expected an absolute directory name for --with-raddbdir: $withval])
    ;;
  esac ]
)
AC_SUBST(raddbdir)
AC_MSG_RESULT($raddbdir)

dnl #
dnl #  extra argument: --with-dictdir
dnl #
dictdir='${datarootdir}/freeradius'
AC_MSG_CHECKING(dictdir)
AC_ARG_WITH(dictdir,
[  --with-dictdir=DIR      directory for dictionary files [DATAROOTDIR/freeradius] ],
[ case "$withval" in
  no)
    AC_MSG_ERROR([Need dictdir])
    ;;
  yes)
    ;;
  [[\\/$]]* | ?:[[\\/]]* )
    dictdir="$withval"
    ;;
  *)
    AC_MSG_ERROR([expected an absolute directory name for --with-dictdir: $withval])
    ;;
  esac ]
)
AC_SUBST(dictdir)
AC_MSG_RESULT($dictdir)

modconfdir='${raddbdir}/mods-config'
AC_SUBST(modconfdir)

dnl #
dnl #  extra argument: --with-ascend-binary
dnl #
WITH_ASCEND_BINARY=yes
AC_ARG_WITH(ascend-binary,
[  --with-ascend-binary    include support for Ascend binary filter attributes (default=yes)],
[ case "$withval" in
  yes)
    ;;
  *)
    WITH_ASCEND_BINARY=no
  esac ]
)
if test "x$WITH_ASCEND_BINARY" = "xyes"; then
  AC_DEFINE(WITH_ASCEND_BINARY, [1], [include support for Ascend binary filter attributes])
fi

dnl #
dnl #  extra argument: --with-radiusv11
dnl #
WITH_RADIUSV11=
AC_ARG_WITH(radiusv11,
[  --with-radiusv11        compile in RADIUSv11 support. (default=no)],
[ case "$withval" in
  yes)
    WITH_RADIUSV11=yes
    ;;
  *)
    ;;
  esac ]
)
if test "x$WITH_RADIUSCV11" = "xyes"; then
  AC_DEFINE(WITH_RADIUSV11, [1], [define if you want RADIUSv11 support (For RADSec et al)])
fi

dnl #
dnl #  extra argument: --with-threads
dnl #
WITH_THREADS=yes
AC_ARG_WITH(threads,
[  --with-threads          use threads, if available.  (default=yes) ],
[ case "$withval" in
  yes)
    ;;
  *)
    WITH_THREADS=no
  esac ]
)

dnl #
dnl #  extra argument: --with-tcp
dnl #
WITH_TCP=yes
AC_ARG_WITH(tcp,
[  --with-tcp              compile in TCP support. (default=yes)],
[ case "$withval" in
  yes)
    ;;
  *)
    WITH_TCP=no
  esac ]
)
if test "x$WITH_TCP" = "xyes"; then
  AC_DEFINE(WITH_TCP, [1], [define if you want TCP support (For RADSec et al)])
fi

dnl #
dnl #  extra argument: --with-vmps
dnl #
WITH_VMPS=yes
AC_ARG_WITH(vmps,
[  --with-vmps             compile in VMPS support. (default=yes)],
[ case "$withval" in
  yes)
    ;;
  *)
    WITH_VMPS=no
  esac ]
)
if test "x$WITH_VMPS" = "xyes"; then
  AC_DEFINE(WITH_VMPS, [1], [define if you want VMPS support])
fi

dnl #
dnl #  extra argument: --with-dhcp
dnl #
WITH_DHCP=yes
AC_ARG_WITH(dhcp,
[  --with-dhcp             compile in DHCP support. (default=yes)],
[ case "$withval" in
  yes)
    ;;
  *)
    WITH_DHCP=no
  esac ]
)
if test "x$WITH_DHCP" = "xyes"; then
  AC_DEFINE(WITH_DHCP, [1], [define if you want DHCP support])
fi
AC_SUBST(WITH_DHCP)


dnl #
dnl #  extra argument: --with-radlast
dnl #
MANSKIP=
WITH_RADLAST=
AC_ARG_WITH(radlast,
[  --with-radlast          install radlast],
[ case "$withval" in
  yes)
    WITH_RADLAST=yes
    ;;
  *)
    WITH_RADLAST=no
  esac ]
)
AC_SUBST(WITH_RADLAST)


dnl #
dnl #  Allow the user to specify a list of modules to be linked
dnl #  statically to the server.
dnl #
STATIC_MODULES=
AC_ARG_WITH(static_modules,
[  --with-static-modules=QUOTED-MODULE-LIST],[
  for i in $withval; do
    STATIC_MODULES="$STATIC_MODULES -dlpreopen ../modules/rlm_$i/rlm_$i.la"
  done
])

USE_SHARED_LIBS=yes
AC_ARG_WITH(shared-libs,
[AS_HELP_STRING([--with-shared-libs ],
[build dynamic libraries and link against them. (default=yes)])],
[ case "$withval" in
  no)
    USE_SHARED_LIBS=no
    ;;
  *)
  esac
])

MODULES=
AC_ARG_WITH(modules,
[  --with-modules=QUOTED-MODULE-LIST],[
 for i in $withval; do
   MODULES="$MODULES $i"
 done
])

dnl #
dnl #  extra argument: --with-experimental-modules
dnl #
EXPERIMENTAL=
AC_ARG_WITH(experimental-modules,
[AS_HELP_STRING([--with-experimental-modules],
[use experimental and unstable modules. (default=no, unless --enable-developer=yes)])],
[ case "$withval" in
  yes)
    EXPERIMENTAL=yes
    ;;
  no)
    EXPERIMENTAL=no
    ;;
  *)
  esac ]
)

dnl #
dnl #  extra argument: --with-udpfromto
dnl #
WITH_UDPFROMTO=yes
AC_ARG_WITH(udpfromto,
[  --with-udpfromto        compile in UDPFROMTO support. (default=yes)],
[ case "$withval" in
  yes)
    WITH_UDPFROMTO=yes
    ;;
  *)
    WITH_UDPFROMTO=no
  esac ]
)

if test "x$WITH_UDPFROMTO" = "xyes"; then
  AC_DEFINE(WITH_UDPFROMTO, [], [define if you want udpfromto])
fi

dnl #
dnl #  These next two arguments don't actually do anything.  They're
dnl #  place holders so that the top-level configure script can tell
dnl #  the user how to configure lower-level modules
dnl #

dnl #
dnl #  extra argument: --with-rlm-FOO-lib-dir
dnl #
AC_ARG_WITH(rlm-FOO-lib-dir,
[AS_HELP_STRING([--with-rlm-FOO-lib-dir=DIR],
[directory in which to look for library files used by module FOO])],
[ case "$withval" in
  *)
    ;;
  esac ]
)

dnl #
dnl #  extra argument: --with-rlm-FOO-include-dir
dnl #
AC_ARG_WITH(rlm-FOO-include-dir,
[AS_HELP_STRING([--with-rlm-FOO-include-dir=DIR],
[directory in which to look for include files used by module FOO])],
[ case "$withval" in
  *)
    ;;
  esac ]
)

dnl #
dnl #  extra argument: --with-openssl
dnl #
WITH_OPENSSL=yes
AC_ARG_WITH(openssl,
[  --with-openssl          use OpenSSL. (default=yes)],
[ case "$withval" in
  no)
    WITH_OPENSSL=no
    ;;
  *)
    WITH_OPENSSL=yes
    ;;
  esac ]
)
if test "x$WITH_THREADS" = "xno"; then
  if test "x$WITH_OPENSSL" = "xyes"; then
    AC_MSG_ERROR([[Threads are required when using OpenSSL, use --with-threads=yes]])
  fi
fi

dnl #
dnl #  extra argument: --with-openssl-lib-dir=dir
dnl #
openssl_lib_dir=
AC_ARG_WITH(openssl-lib-dir,
[AS_HELP_STRING([--with-openssl-lib-dir=DIR],
[directory to look for OpenSSL library files])],
[ case "$withval" in
  *) openssl_lib_dir="$withval"
    ;;
  esac ]
)

dnl #
dnl #  extra argument: --with-openssl-includes=dir
dnl #
openssl_include_dir=
AC_ARG_WITH(openssl-include-dir,
[AS_HELP_STRING([--with-openssl-include-dir=DIR],
[directory to look for OpenSSL include files])],
[ case "$withval" in
  *) openssl_include_dir="$withval"
    ;;
  esac ]
)

dnl #
dnl #  extra argument: --disable-openssl-version-check
dnl #
AC_ARG_ENABLE(openssl-version-check,
[AS_HELP_STRING([--disable-openssl-version-check],
                [disable vulnerable OpenSSL version check])]
)
if test "x$enable_openssl_version_check" != "xno"; then
  AC_DEFINE(ENABLE_OPENSSL_VERSION_CHECK, [1],
            [Define to 1 to have OpenSSL version check enabled])
  openssl_version_check_config="\
	#
	#  allow_vulnerable_openssl: Allow the server to start with
	#  versions of OpenSSL known to have critical vulnerabilities.
	#
	#  This check is based on the version number reported by libssl
	#  and may not reflect patches applied to libssl by
	#  distribution maintainers.
	#
	allow_vulnerable_openssl = no"
else
  openssl_version_check_config=
fi
AC_SUBST([openssl_version_check_config])

dnl #
dnl #  extra argument: --enable-reproducible-builds
dnl #
AC_ARG_ENABLE(reproducible-builds,
[AS_HELP_STRING([--enable-reproducible-builds],
                [ensure the build does not change each time])],
[ case "$enableval" in
  yes)
    AC_DEFINE(ENABLE_REPRODUCIBLE_BUILDS, [1],
              [Define to ensure each build is the same])
    reproducible_builds=yes
    ;;
  *)
    reproducible_builds=no
  esac ]
)

dnl #
dnl #  Enable the -fsanitize=fuzzer and link in the address sanitizer
dnl #  libraries.
dnl #
AC_ARG_ENABLE(fuzzer,
[AS_HELP_STRING([--enable-fuzzer],
                [build with support for a fuzzer])],
[ case "$enableval" in
  no)
    fuzzer=no
    ;;
  *)
    fuzzer=yes
  esac ]
)

dnl #
dnl #  Enable the -fsanitize=address and link in the address sanitizer
dnl #  libraries.
dnl #
AC_ARG_ENABLE(address-sanitizer,
[AS_HELP_STRING([--enable-address-sanitizer],
                [build with support for address sanitizer.])],
[ case "$enableval" in
  no)
    address_sanitizer=no
    ;;
  *)
    address_sanitizer=yes
  esac ]
)

dnl #
dnl #  Enable -fsanitize=leak and link in the leak sanitizer
dnl #  libraries.
dnl #
AC_ARG_ENABLE(leak-sanitizer,
[AS_HELP_STRING([--enable-leak-sanitizer],
                [build with support for leak sanitizer.])],
[ case "$enableval" in
  no)
    leak_sanitizer=no
    ;;
  *)
    leak_sanitizer=yes
  esac ]
)

dnl #
dnl #  Enable -fsanitize=thread and link in the thread sanitizer
dnl #  libraries.
dnl #
AC_ARG_ENABLE(thread-sanitizer,
[AS_HELP_STRING([--enable-thread-sanitizer],
                [build with support for thread sanitizer.])],
[ case "$enableval" in
  no)
    thread_sanitizer=no
    ;;
  *)
    thread_sanitizer=yes
  esac ]
)

dnl #
dnl #  Enable the -fsanitize=undefined and link in the address sanitizer
dnl #  libraries.
dnl #
AC_ARG_ENABLE(undefined-behaviour-sanitizer,
[AS_HELP_STRING([--enable-undefined-behaviour-sanitizer],
                [build with support for undefined behaviour sanitizer.])],
[ case "$enableval" in
  no)
    undefined_behaviour_sanitizer=no
    ;;
  *)
    undefined_behaviour_sanitizer=yes
  esac ]
)

dnl #############################################################
dnl #
dnl #  1. Checks for programs
dnl #
dnl #############################################################

CHECKRAD=checkrad
AC_PATH_PROG(PERL, perl, /usr/local/bin/perl)
if test "x$ac_cv_path_PERL" = "x"; then
  AC_MSG_WARN([perl not found - Simultaneous-Use and checkrad may not work])
fi
AC_PATH_PROG(SNMPGET, snmpget)
if test "x$ac_cv_path_SNMPGET" = "x"; then
  AC_MSG_WARN([snmpget not found - Simultaneous-Use and checkrad may not work])
fi

AC_PATH_PROG(SNMPWALK, snmpwalk)
if test "x$ac_cv_path_SNMPWALK" = "x"; then
  AC_MSG_WARN([snmpwalk not found - Simultaneous-Use and checkrad may not work])
fi

AC_PATH_PROG(RUSERS, rusers, /usr/bin/rusers)


dnl #
dnl #  radlast depends on last
dnl #
if test "x$WITH_RADLAST" = "x"; then
  AC_CHECK_PROG(LAST, last, yes, no)
  WITH_RADLAST="$LAST"
fi
if test "x$WITH_RADLAST" != "xyes"; then
  MANSKIP="$MANSKIP man/man1/radlast.1"
fi


dnl #
dnl #  FIXME This is truly gross.
dnl #
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)

AC_PATH_PROG(DIRNAME,dirname)
AC_PATH_PROG(GREP,grep)

dnl #############################################################
dnl #
dnl #  2. Checks for libraries
dnl #
dnl #############################################################

dnl Check for talloc
dnl extra argument: --with-talloc-lib-dir=DIR
talloc_lib_dir=
AC_ARG_WITH(talloc-lib-dir,
  [AS_HELP_STRING([--with-talloc-lib-dir=DIR],
  [directory in which to look for talloc library files])],
  [case "$withval" in
    no)
      AC_MSG_ERROR([Need talloc-lib-dir])
      ;;
    yes)
      ;;
    *)
      talloc_lib_dir="$withval"
      ;;
  esac])

dnl extra argument: --with-talloc-include-dir=DIR
talloc_include_dir=
AC_ARG_WITH(talloc-include-dir,
  [AS_HELP_STRING([--with-talloc-include-dir=DIR],
  [directory in which to look for talloc include files])],
  [case "$withval" in
    no)
      AC_MSG_ERROR([Need talloc-include-dir])
      ;;
    yes)
      ;;
    *)
      talloc_include_dir="$withval"
      ;;
  esac])

smart_try_dir="$talloc_lib_dir"
FR_SMART_CHECK_LIB(talloc, _talloc)
if test "x$ac_cv_lib_talloc__talloc" != "xyes"; then
  AC_MSG_WARN([talloc library not found. Use --with-talloc-lib-dir=<path>.])
  AC_MSG_ERROR([FreeRADIUS requires libtalloc])
fi

TALLOC_LIBS="${smart_lib}"
TALLOC_LDFLAGS="${smart_ldflags}"
AC_SUBST(TALLOC_LIBS)
AC_SUBST(TALLOC_LDFLAGS)
LIBS="$old_LIBS"

dnl #
dnl #  If using pthreads, check for -lpthread (posix) or -lc_r (*BSD)
dnl #
old_CFLAGS=$CFLAGS
if test "x$WITH_THREADS" = "xyes"; then
  if test $ac_cv_prog_suncc = "yes"; then
    CFLAGS="$CFLAGS -mt"
  fi

  AC_CHECK_HEADERS(pthread.h, [],
    [
      WITH_THREADS="no"
      fail=[pthread.h]
    ])

  dnl #
  dnl #  pthread stuff is usually in -lpthread
  dnl #  or in -lc_r, on *BSD
  dnl #
  dnl #  On Some systems, we need extra pre-processor flags, to get them to
  dnl #  to do the threading properly.
  dnl #
  if test "x$WITH_THREADS" != "xno"; then
    AC_CHECK_LIB(pthread, pthread_create,
      [
        HAVE_LPTHREAD='yes'
        CFLAGS="$CFLAGS -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS"
        LIBS="-lpthread $LIBS"

        dnl #
        dnl #  -pthread should add all required CPP definitions and linker
        dnl #  arguments. But not all compilers support it, or some compilers
        dnl #  only support it on certain platforms.
        dnl #
        AX_CC_PTHREAD_FLAG
        if test "x$ax_cv_cc_pthread_flag" != 'xyes'; then
          CFLAGS="$CFLAGS -pthread"
        fi
      ]
    )

    dnl #
    dnl #  Check for libc_r which used to be the threading library used
    dnl #  for FreeBSD. Internet says it may be deprecated, but if we
    dnl #  can't find lpthread it's probably worth checking.
    dnl #
    if test "x$HAVE_LPTHREAD" != "xyes"; then
      AC_CHECK_LIB(c_r, pthread_create,
        [
          CFLAGS="$CFLAGS -D_THREAD_SAFE"

          dnl #
          dnl #  -pthread should add all required CPP definitions and linker
          dnl #  arguments. But not all compilers support it, or some compilers
          dnl #  only support it on certain platforms.
          dnl #
          AX_CC_PTHREAD_FLAG
          if test "x$ax_cv_cc_pthread_flag" != 'xyes'; then
            LIBS="-lc_r $LIBS"
          else
            CFLAGS="$CFLAGS -pthread"
          fi
        ],
        [ fail=[-lc_r or -lpthread] ]
      )
    fi
  fi

  if test "x$WITH_THREADS" != "xyes"; then
    AC_MSG_WARN([silently not building with thread support.])
    AC_MSG_WARN([FAILURE: thread support requires: $fail.])
  else
    AC_DEFINE(WITH_THREADS, [1], [define if you want thread support])
  fi
fi

dnl #
dnl #  If we have NO pthread libraries, remove any knowledge of threads.
dnl #
if test "x$WITH_THREADS" != "xyes"; then
  CFLAGS=$old_CFLAGS
  ac_cv_header_pthread_h="no"
  WITH_THREADS=no
else
  dnl #
  dnl #  We need sem_init() and friends, as they're the friendliest
  dnl #  semaphore functions for threading.
  dnl #
  dnl #  HP/UX requires linking with librt, too, to get the sem_* symbols.
  dnl #  Some systems have them in -lsem
  dnl #  Solaris has them in -lposix4
  dnl #  NetBSD has them in -lsemaphore
  dnl #

  AC_SEARCH_LIBS(sem_init, pthread sem posix4 rt semaphore,
    [],
    [AC_MSG_ERROR([[-lsem not found.  You may want to download it from ftp://ftp.to.gd-es.com/pub/BSDI/libsem.tar.bz2 or https://www.freeradius.org/ftp/pub/radius/contrib/libsem.tar.gz]])]
  )
fi

dnl #
dnl #  Check if we have -ldl
dnl #
AC_CHECK_LIB(dl, dlopen)

dnl #
dnl #  Check if we need -lsocket
dnl #
AC_CHECK_LIB(socket, getsockname)

dnl #
dnl #  Check for -lresolv
dnl #  This library may be needed later.
dnl #
AC_CHECK_LIB(resolv, inet_aton)

dnl #
dnl #  Check if we need -lnsl. Usually if we want to
dnl #  link against -lsocket we need to include -lnsl as well.
dnl #
AC_CHECK_LIB(nsl, inet_ntoa)
AC_CHECK_LIB(ws2_32, htonl)

dnl #
dnl #  Check the pcap library for the RADIUS sniffer.
dnl #
dnl extra argument: --with-pcap-lib-dir=DIR
pcap_lib_dir=
AC_ARG_WITH(pcap-lib-dir,
  [AS_HELP_STRING([--with-pcap-lib-dir=DIR],
  [directory in which to look for pcap library files])],
  [case "$withval" in
    no)
      AC_MSG_ERROR([Need pcap-lib-dir])
      ;;
    yes)
      ;;
    *)
      pcap_lib_dir="$withval"
      ;;
  esac])

dnl extra argument: --with-pcap-include-dir=DIR
pcap_include_dir=
AC_ARG_WITH(pcap-include-dir,
  [AS_HELP_STRING([--with-pcap-include-dir=DIR],
  [directory in which to look for pcap include files])],
  [case "$withval" in
    no)
      AC_MSG_ERROR([Need pcap-include-dir])
      ;;
    yes)
      ;;
    *)
      pcap_include_dir="$withval"
      ;;
  esac])

smart_try_dir="$pcap_lib_dir"
FR_SMART_CHECK_LIB(pcap, pcap_open_live)
if test "x$ac_cv_lib_pcap_pcap_open_live" != "xyes"; then
  AC_MSG_WARN([pcap library not found, silently disabling the RADIUS sniffer, and ARP listener.  Use --with-pcap-lib-dir=<path>.])
else
  AC_CHECK_FUNCS(\
    pcap_fopen_offline \
    pcap_dump_fopen \
    pcap_create \
    pcap_activate
  )

  PCAP_LIBS="${smart_lib}"
  PCAP_LDFLAGS="${smart_ldflags}"
fi
dnl Set by FR_SMART_CHECK_LIB
LIBS="${old_LIBS}"

dnl Check for collectdclient
dnl extra argument: --with-collectdclient-lib-dir=DIR
collectdclient_lib_dir=
AC_ARG_WITH(collectdclient-lib-dir,
  [AS_HELP_STRING([--with-collectdclient-lib-dir=DIR],
  [directory in which to look for collectdclient library files])],
  [case "$withval" in
    no)
      AC_MSG_ERROR([Need collectdclient-lib-dir])
      ;;
    yes)
      ;;
    *)
      collectdclient_lib_dir="$withval"
      ;;
  esac])

dnl extra argument: --with-collectdclient-include-dir=DIR
collectdclient_include_dir=
AC_ARG_WITH(collectdclient-include-dir,
  [AS_HELP_STRING([--with-collectdclient-include-dir=DIR],
  [directory in which to look for collectdclient include files])],
  [case "$withval" in
    no)
      AC_MSG_ERROR([Need collectdclient-include-dir])
      ;;
    yes)
      ;;
    *)
      collectdclient_include_dir="$withval"
      ;;
  esac])

smart_try_dir="$collectdclient_lib_dir"
FR_SMART_CHECK_LIB(collectdclient, lcc_connect)
if test "x$ac_cv_lib_collectdclient_lcc_connect" != "xyes"; then
  AC_MSG_WARN([collectdclient library not found. Use --with-collectdclient-lib-dir=<path>.])
else
  COLLECTDC_LIBS="${smart_lib}"
  COLLECTDC_LDFLAGS="${smart_ldflags}"
fi
dnl Set by FR_SMART_CHECKLIB
LIBS="${old_LIBS}"

dnl Check for cap
dnl extra argument: --with-cap-lib-dir=DIR
cap_lib_dir=
AC_ARG_WITH(cap-lib-dir,
  [AS_HELP_STRING([--with-cap-lib-dir=DIR],
  [directory in which to look for cap library files])],
  [case "$withval" in
    no)
      AC_MSG_ERROR([Need cap-lib-dir])
      ;;
    yes)
      ;;
    *)
      cap_lib_dir="$withval"
      ;;
  esac])

dnl extra argument: --with-cap-include-dir=DIR
cap_include_dir=
AC_ARG_WITH(cap-include-dir,
  [AS_HELP_STRING([--with-cap-include-dir=DIR],
  [directory in which to look for cap include files])],
  [case "$withval" in
    no)
      AC_MSG_ERROR([Need cap-include-dir])
      ;;
    yes)
      ;;
    *)
      cap_include_dir="$withval"
      ;;
  esac])

smart_try_dir="$cap_lib_dir"
FR_SMART_CHECK_LIB(cap, cap_get_proc)
if test "x$ac_cv_lib_cap_cap_get_proc" != "xyes"; then
  AC_MSG_WARN([cap library not found, debugger checks will not be enabled. Use --with-cap-lib-dir=<path>.])
else
  AC_DEFINE(HAVE_LIBCAP, 1,
    [Define to 1 if you have the `cap' library (-lcap).]
  )
  HAVE_LIBCAP=1
fi

dnl #
dnl #  Check for libreadline
dnl #
VL_LIB_READLINE

dnl #
dnl #  Checks for systemd
dnl #
dnl #  extra argument: --with-systemd
dnl #
AC_ARG_WITH([systemd],
            AS_HELP_STRING([--with-systemd], [add systemd support, if available (default=no)]),
            [ case "$withval" in
              no)
                WITH_SYSTEMD=no
                ;;
              *)
                WITH_SYSTEMD=yes
              esac ],
            [WITH_SYSTEMD=no])

dnl #
dnl #  extra argument: --systemd-lib-dir=dir
dnl #
systemd_lib_dir=
AC_ARG_WITH(systemd-lib-dir,
  [AS_HELP_STRING([--with-systemd-lib-dir=DIR],
  [directory to look for systemd library files])],
  [ case "$withval" in
    *) systemd_lib_dir="$withval"
      ;;
    esac ]
)

dnl #
dnl #  extra argument: --with-systemd-includes=dir
dnl #
systemd_include_dir=
AC_ARG_WITH(systemd-include-dir,
  [AS_HELP_STRING([--with-systemd-include-dir=DIR],
  [directory to look for systemd include files])],
  [ case "$withval" in
    *) systemd_include_dir="$withval"
      ;;
    esac ]
)

if test "x$WITH_SYSTEMD" = xyes; then
  smart_try_dir="$systemd_lib_dir"
  FR_SMART_CHECK_LIB(systemd, sd_notify)
  if test "x$ac_cv_lib_systemd_sd_notify" != "xyes"; then
    AC_MSG_WARN([systemd library not found. Use --with-systemd-lib-dir=<path>.])
  else
    AC_DEFINE([HAVE_SYSTEMD], [1],
      [Define to 1 if you have the `systemd' library (-lsystemd).]
    )
    HAVE_SYSTEMD=1
    SYSTEMD_LIBS="${smart_lib}"
    SYSTEMD_LDFLAGS="${smart_ldflags}"
  fi
  dnl Set by FR_SMART_CHECKLIB
  LIBS="${old_LIBS}"
fi

if test "x$HAVE_SYSTEMD" = x; then
  AC_MSG_NOTICE([skipping test for systemd watchdog])
else
  smart_try_dir="$systemd_lib_dir"
  FR_SMART_CHECK_LIB(systemd, sd_watchdog_enabled)
  if test "x$ac_cv_lib_systemd_sd_watchdog_enabled" != "xyes"; then
    AC_MSG_WARN([systemd watchdog is only available from systemd 209.])
  else
    AC_DEFINE([HAVE_SYSTEMD_WATCHDOG], [1],
      [Define to 1 if you have watchdog support in the `systemd' library (-lsystemd).]
    )
  fi
  dnl Set by FR_SMART_CHECKLIB
  LIBS="${old_LIBS}"
fi

dnl #
dnl #  Check for the systemd headers
dnl #
if test "x$WITH_SYSTEMD" != xyes || test "x$SYSTEMD_LIBS" = x; then
  AC_MSG_NOTICE([skipping test for systemd/sd-daemon.h.])
else
  smart_try_dir="$systemd_include_dir"
  FR_SMART_CHECK_INCLUDE([systemd/sd-daemon.h])
  if test "x$ac_cv_header_systemd_sdmdaemon_h" = "xyes"; then
    AC_DEFINE(HAVE_SYSTEMD_SD_DAEMON_H, 1, [Define to 1 if you have the <systemd/sd-daemon.h> header file.])
    AC_SUBST(SYSTEMD_LIBS)
    AC_SUBST(SYSTEMD_LDFLAGS)
  else
    AC_MSG_WARN([systemd headers not found.  Use --with-systemd-include-dir=<path>.])
  fi
fi

dnl #############################################################
dnl #
dnl #  3. Checks for header files
dnl #
dnl #############################################################

dnl #
dnl # Check for talloc header files
dnl #
smart_try_dir="$talloc_include_dir"
FR_SMART_CHECK_INCLUDE([talloc.h])
if test "x$ac_cv_header_talloc_h" != "xyes"; then
  AC_MSG_WARN([talloc headers not found. Use --with-talloc-include-dir=<path>.])
  AC_MSG_ERROR([FreeRADIUS requires libtalloc])
fi

dnl #
dnl #  Interix requires us to set -D_ALL_SOURCE, otherwise
dnl #  getopt will be #included, but won't link.  <sigh>
dnl #
dnl #  On the other hand, it's 20222.  Interix has likely been dead for a decade. :(
dnl #
case "$host" in
  *-interix*)
    CFLAGS="$CFLAGS -D_ALL_SOURCE"
    ;;
  *-darwin*)
    AC_DEFINE([__APPLE_USE_RFC_3542], 1, [Force OSX >= 10.7 Lion to use RFC2292 IPv6 socket options])
    ;;
esac

AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_TIME
AC_HEADER_SYS_WAIT

AC_CHECK_HEADERS( \
  arpa/inet.h \
  crypt.h \
  dlfcn.h \
  errno.h \
  fcntl.h \
  features.h \
  fnmatch.h \
  getopt.h \
  glob.h \
  grp.h \
  inttypes.h \
  limits.h \
  linux/if_packet.h \
  malloc.h \
  netdb.h \
  netinet/in.h \
  prot.h \
  pwd.h \
  resource.h \
  semaphore.h \
  sia.h \
  siad.h \
  signal.h \
  stdatomic.h \
  stdalign.h \
  stdbool.h \
  stddef.h \
  stdint.h \
  stdio.h \
  sys/event.h \
  sys/fcntl.h \
  sys/prctl.h \
  sys/procctl.h \
  sys/ptrace.h \
  sys/resource.h \
  sys/security.h \
  sys/select.h \
  sys/socket.h \
  sys/time.h \
  sys/types.h \
  sys/un.h \
  sys/wait.h \
  syslog.h \
  unistd.h \
  utime.h \
  utmp.h \
  utmpx.h \
  winsock.h
)

dnl #
dnl #  FreeBSD requires sys/socket.h before net/if.h
dnl #
AC_CHECK_HEADERS(net/if.h, [], [],
  [
    #ifdef HAVE_SYS_SOCKET_H
    #  include <sys/socket.h>
    #endif
  ]
)

dnl #
dnl #  other checks which require headers
dnl #
if test "x$ac_cv_header_sys_security_h" = "xyes" && test "x$ac_cv_header_prot_h" = "xyes"
then
  AC_DEFINE(OSFC2, [], [define if you have OSFC2 authentication])
fi

if test "x$ac_cv_header_sia_h" = "xyes" && test "x$ac_cv_header_siad_h" = "xyes"
then
  AC_DEFINE(OSFSIA, [], [define if you have OSFSIA authentication])
fi

dnl #
dnl #  Were we told to use OpenSSL, if we were and we find an error, call AC_MSG_FAILURE and exit
dnl #
if test "x$WITH_OPENSSL" = xyes; then
  OLD_LIBS="$LIBS"

  dnl #
  dnl #  Apparently OpenSSL will attempt to build with kerberos if we don't pass this?!
  dnl #
  CFLAGS="$CFLAGS -DOPENSSL_NO_KRB5"

  dnl #
  dnl #  Check we can link to libcrypto and libssl
  dnl #
  smart_try_dir="$openssl_lib_dir"
  FR_SMART_CHECK_LIB(crypto, DH_new)
  if test "x$ac_cv_lib_crypto_DH_new" = "xyes"; then
    AC_DEFINE(HAVE_LIBCRYPTO, 1, [Define to 1 if you have the `crypto' library (-lcrypto).])
    OPENSSL_LIBS="$smart_lib"
    OPENSSL_LDFLAGS="$smart_ldflags"

    FR_SMART_CHECK_LIB(ssl, SSL_new)
    if test "x$ac_cv_lib_ssl_SSL_new" != "xyes"; then
      AC_MSG_FAILURE([failed linking to libssl. Use --with-openssl-lib-dir=<path>, or --with-openssl=no (builds without OpenSSL)])
    else
      AC_DEFINE(HAVE_LIBSSL, 1, [Define to 1 if you have the `ssl' library (-lssl).])
      OPENSSL_LIBS="$OPENSSL_LIBS $smart_lib"

      if test "$OPENSSL_LDFLAGS" != "$smart_ldflags"; then
        AC_MSG_FAILURE(["inconsistent LDFLAGS between -lssl '$smart_ldflags' and -lcrypto '$OPENSSL_LDFLAGS'"])
      fi
    fi
  else
    AC_MSG_FAILURE([failed linking to libcrypto. Use --with-openssl-lib-dir=<path>, or --with-openssl=no (builds without OpenSSL)])
  fi

  smart_try_dir="$openssl_include_dir"
  FR_SMART_CHECK_INCLUDE(openssl/ssl.h)
  if test "x$ac_cv_header_openssl_ssl_h" = "xyes"; then
    AC_DEFINE(HAVE_OPENSSL_SSL_H, 1, [Define to 1 if you have the <openssl/ssl.h> header file.])

    AC_CHECK_HEADERS( \
      openssl/asn1.h \
      openssl/conf.h \
      openssl/crypto.h \
      openssl/err.h \
      openssl/evp.h \
      openssl/hmac.h \
      openssl/md5.h \
      openssl/md4.h \
      openssl/rand.h \
      openssl/sha.h \
      openssl/ssl.h \
      openssl/ocsp.h \
      openssl/engine.h,
      [ OPENSSL_CPPFLAGS="$smart_include" ],
      [
        AC_MSG_FAILURE([failed locating OpenSSL headers. Use --with-openssl-include-dir=<path>, or --with-openssl=no (builds without OpenSSL)])
      ]
    )

    AC_MSG_CHECKING([for OpenSSL version >= 1.0.2])
    AC_EGREP_CPP(yes,
      [#include <openssl/crypto.h>
       #if (OPENSSL_VERSION_NUMBER >= 0x10002000L)
       yes
       #endif
      ],
      [
        AC_MSG_RESULT(yes)
      ],
      [
        AC_MSG_RESULT(no)
        AC_MSG_FAILURE([OpenSSL version too old])
      ]
    )

    dnl #
    dnl #  CPPFLAGS are passed to the compiler first, so we use
    dnl #  them to ensure things like --sysroot don't override the
    dnl #  library location we discovered previously.
    dnl #
    old_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$OPENSSL_CPPFLAGS $CPPFLAGS"

    dnl #
    dnl #  Now check that the header versions match the library
    dnl #
    AC_MSG_CHECKING([OpenSSL library and header version consistency])
    AC_RUN_IFELSE(
      [AC_LANG_PROGRAM(
        [[
          #include <stdio.h>
          #include <openssl/opensslv.h>
          #include <openssl/crypto.h>
        ]],
        [[
          printf("library: %lx header: %lx... ", (unsigned long) SSLeay(), (unsigned long) OPENSSL_VERSION_NUMBER);
          if (SSLeay() == OPENSSL_VERSION_NUMBER) {
            return 0;
          } else {
            return 1;
          }
        ]]
      )],
      [
        AC_MSG_RESULT(yes)
      ],
      [
        AC_MSG_RESULT(no)
        AC_MSG_FAILURE([OpenSSL library version does not match header version])
      ],
      [
        AC_MSG_RESULT([cross-compiling (assuming yes)])
      ]
    )
    dnl #
    dnl #  Check if the new HMAC_CTX interface is defined
    dnl #
    AC_CHECK_FUNCS( \
      SSL_get_client_random \
      SSL_get_server_random \
      SSL_SESSION_get_master_key \
      HMAC_CTX_new \
      HMAC_CTX_free \
      ASN1_STRING_get0_data \
      CONF_modules_load_file \
      CRYPTO_set_id_callback \
      CRYPTO_set_locking_callback
    )
    CPPFLAGS="$old_CPPFLAGS"
  fi

  LIBS="$OLD_LIBS"
  AC_SUBST(OPENSSL_LIBS)
  AC_SUBST(OPENSSL_LDFLAGS)
  AC_SUBST(OPENSSL_CPPFLAGS)
  export OPENSSL_LIBS OPENSSL_LDFLAGS OPENSSL_CPPFLAGS
fi

dnl #
dnl #  Check the pcap includes for the RADIUS sniffer.
dnl #
if test "x$PCAP_LIBS" = x; then
  AC_MSG_NOTICE([skipping test for pcap.h.])
else
  dnl #
  dnl # Check for pcap header files
  dnl #
  smart_try_dir="$pcap_include_dir"
  FR_SMART_CHECK_INCLUDE([pcap.h])
  if test "x$ac_cv_header_pcap_h" = "xyes" && test "x$ac_cv_lib_pcap_pcap_open_live" = "xyes"; then
    AC_DEFINE(HAVE_LIBPCAP, 1, [Define to 1 if you have the `pcap' library (-lpcap) and header file <pcap.h>.])
    AC_SUBST(PCAP_LIBS)
    AC_SUBST(PCAP_LDFLAGS)
  else
    AC_MSG_WARN([pcap headers not found, silently disabling the RADIUS sniffer, and ARP listener. Use --with-pcap-include-dir=<path>.])
  fi
fi

dnl Check for collectd-client
if test "x$COLLECTDC_LIBS" = x; then
  AC_MSG_NOTICE([skipping test for collectd/client.h.])
else
  dnl #
  dnl # Check for collectd-client header files
  dnl #
  smart_try_dir="$collectdclient_include_dir"
  FR_SMART_CHECK_INCLUDE([collectd/client.h])
  if test "x$ac_cv_header_collectd_client_h" = "xyes"; then
    AC_DEFINE(HAVE_COLLECTDC_H, 1, [Define to 1 if you have the `collectdclient' library (-lcollectdclient).])
    AC_SUBST(COLLECTDC_LIBS)
    AC_SUBST(COLLECTDC_LDFLAGS)
  else
    AC_MSG_WARN([collectdclient headers not found. Use --with-collectdclient-include-dir=<path>.])
  fi
fi

dnl #
dnl #  Check the CAP includes for debugger checks
dnl #
if test "x$HAVE_LIBCAP" = x; then
  AC_MSG_NOTICE([skipping test for cap.h.])
else
  dnl #
  dnl # Check for CAP header files
  dnl #
  smart_try_dir="$cap_include_dir"
  FR_SMART_CHECK_INCLUDE([sys/capability.h])
  if test "x$ac_cv_header_sys_capability_h" = "xyes"; then
    AC_DEFINE(HAVE_CAPABILITY_H, 1, [Define to 1 if you have the <sys/capability.h> header file.])
  else
    AC_MSG_WARN([cap headers not found, will not perform debugger checks. Use --with-cap-include-dir=<path>.])
  fi
fi

dnl #############################################################
dnl #
dnl #  4. Checks for typedefs
dnl #
dnl #############################################################

dnl #
dnl #  Ensure that these are defined
dnl #
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T

dnl #
dnl #  Check for socklen_t
dnl #
FR_CHECK_TYPE_INCLUDE(
  [
    #ifdef HAVE_SYS_TYPES_H
    #  include <sys/types.h>
    #endif

    #ifdef HAVE_SYS_SOCKET_H
    #  include <sys/socket.h>
    #endif
  ],
  socklen_t, int, [socklen_t is generally 'int' on systems which don't use it]
)

dnl #
dnl #  Check for uint8_t
dnl #
FR_CHECK_TYPE_INCLUDE(
  [
    #ifdef HAVE_INTTYPES_H
    #  include <inttypes.h>
    #endif

    #ifdef HAVE_STDINT_H
    #  include <stdint.h>
    #endif
  ],
  uint8_t, unsigned char, [uint8_t should be the canonical 'octet' for network traffic]
)

dnl #
dnl #  Check for uint16_t
dnl #
FR_CHECK_TYPE_INCLUDE(
  [
    #ifdef HAVE_INTTYPES_H
    #  include <inttypes.h>
    #endif

    #ifdef HAVE_STDINT_H
    #  include <stdint.h>
    #endif
  ],
  uint16_t, unsigned short, [uint16_t should be the canonical '2 octets' for network traffic]
)

dnl #
dnl #  Check for uint32_t
dnl #
FR_CHECK_TYPE_INCLUDE(
  [
    #ifdef HAVE_INTTYPES_H
    #  include <inttypes.h>
    #endif

    #ifdef HAVE_STDINT_H
    #  include <stdint.h>
    #endif
  ],
  uint32_t, unsigned int, [uint32_t should be the canonical 'network integer']
)

dnl #
dnl #  Check for uint64_t
dnl #
FR_CHECK_TYPE_INCLUDE(
  [
    #ifdef HAVE_INTTYPES_H
    #  include <inttypes.h>
    #endif

    #ifdef HAVE_STDINT_H
    #  include <stdint.h>
    #endif
  ],
  uint64_t, unsigned long long, [uint64_t is required for larger counters]
)

dnl #
dnl #  Check for __uint128_t (compiler builtin)
dnl #
AC_CHECK_TYPE(__uint128_t, AC_DEFINE(HAVE___UINT128_T, 1, [compiler specific 128 bit unsigned integer]), [], [])

dnl #
dnl #  Check for uint128_t (fictitious future data type)
dnl #
AC_CHECK_TYPE(uint128_t, AC_DEFINE(HAVE_UINT128_T, 1, [128 bit unsigned integer]), [],
  [
    #ifdef HAVE_INTTYPES_H
    #  include <inttypes.h>
    #endif

    #ifdef HAVE_STDINT_H
    #  include <stdint.h>
    #endif
  ]
)

AC_CHECK_TYPE(struct in6_addr, AC_DEFINE(HAVE_STRUCT_IN6_ADDR, 1, [IPv6 address structure]), [],
  [
    #ifdef HAVE_NETINET_IN_H
    #  include <netinet/in.h>
    #endif
  ]
)

AC_CHECK_TYPE(struct sockaddr_storage, AC_DEFINE(HAVE_STRUCT_SOCKADDR_STORAGE, 1, [Generic socket addresses]), [],
  [
    #ifdef HAVE_NETINET_IN_H
    #  include <netinet/in.h>
    #endif

    #ifdef HAVE_SYS_SOCKET_H
    #  include <sys/socket.h>
    #endif
])

AC_CHECK_TYPE(struct sockaddr_in6, AC_DEFINE(HAVE_STRUCT_SOCKADDR_IN6, 1, [IPv6 socket addresses]), [],
  [
    #ifdef HAVE_NETINET_IN_H
    #  include <netinet/in.h>
    #endif
])

AC_CHECK_TYPE(struct addrinfo, AC_DEFINE(HAVE_STRUCT_ADDRINFO, 1, [Generic DNS lookups]), [],
  [
    #ifdef HAVE_SYS_TYPES_H
    #  include <sys/types.h>
    #endif

    #ifdef HAVE_SYS_SOCKET_H
    #  include <sys/socket.h>
    #endif

    #ifdef HAVE_NETDB_H
    #  include <netdb.h>
    #endif
  ]
)

dnl #
dnl #  Check for sig_t
dnl #
dnl #  FR_CHECK_TYPE_INCLUDE doesn't work for callbacks as it doesn't produce typedefs
dnl #
AC_MSG_CHECKING([if sig_t is defined])
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM(
    [[
      #ifdef HAVE_SIGNAL_H
      #  include <signal.h>
      #endif
    ]],
    [[
      sig_t func;
      return 0;
    ]]
  )],
  [
      AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_SIG_T, 1, [Define if the type sig_t is defined by signal.h])
  ],
  [
      AC_MSG_RESULT(no)
  ]
)

dnl #############################################################
dnl #
dnl #  5. Checks for structures and functions
dnl #
dnl #############################################################
AC_CHECK_FUNCS( \
  bindat \
  clock_gettime \
  closefrom \
  ctime_r \
  dladdr \
  fcntl \
  fopencookie \
  funopen \
  getaddrinfo \
  getnameinfo \
  getopt_long \
  getpeereid \
  getresuid \
  gettimeofday \
  getusershell \
  gmtime_r \
  if_indextoname \
  inet_aton \
  inet_ntop \
  inet_pton \
  initgroups \
  kqueue \
  localtime_r \
  mallopt \
  mkdirat \
  openat \
  pthread_sigmask \
  setlinebuf \
  setresuid \
  setsid \
  setuid \
  setvbuf \
  sigaction \
  sigprocmask \
  snprintf \
  strcasecmp \
  strlcat \
  strlcpy \
  strncasecmp \
  strsep \
  strsignal \
  unlinkat \
  vdprintf \
  vsnprintf
)

dnl #
dnl #  Check if we have utmpx.h
dnl #  if so, check if struct utmpx has entry ut_xtime
dnl #  if not, set it to define ut_xtime = ut_tv.tv_sec
dnl #
if test "x$ac_cv_header_utmpx_h" = "xyes"; then
 FR_CHECK_STRUCT_HAS_MEMBER([#include <utmpx.h>], [struct utmpx], ut_xtime)
 if test "x$ac_cv_type_struct_utmpx_has_ut_xtime" = "x"; then
   AC_DEFINE(ut_xtime, ut_tv.tv_sec, [define to something if you don't have ut_xtime in struct utmpx])
 fi
fi

dnl #
dnl #  struct ip_pktinfo
dnl #
FR_CHECK_STRUCT_HAS_MEMBER([#include <netinet/in.h>], [struct in_pktinfo], ipi_addr)
if test "x$ac_cv_type_struct_in_pktinfo_has_ipi_addr" = "xyes"; then
  AC_DEFINE(HAVE_IP_PKTINFO, [], [define if you have IP_PKTINFO (Linux)])
fi

dnl #
dnl #  struct in6_pktinfo
dnl #
FR_CHECK_STRUCT_HAS_MEMBER([#include <netinet/in.h>], [struct in6_pktinfo], ipi6_addr)
if test "x$ac_cv_type_struct_in6_pktinfo_has_ipi6_addr" = "xyes"; then
  AC_DEFINE(HAVE_IN6_PKTINFO, [], [define if you have IN6_PKTINFO (Linux)])
fi

dnl #
dnl #  Check for htonll and htonlll
dnl #
AC_MSG_CHECKING([if htonll is defined])
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM(
    [[
      #include <sys/types.h>
      #include <netinet/in.h>
    ]],
    [[
      return htonll(0);
    ]]
  )],
  [
      AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_HTONLL, 1, [Define if the function (or macro) htonll exists.])
  ],
  [
      AC_MSG_RESULT(no)
  ]
)

AC_MSG_CHECKING([if htonlll is defined])
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM(
    [[
      #include <sys/types.h>
      #include <netinet/in.h>
    ]],
    [[
      return htonlll(0);
    ]]
  )],
  [
      AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_HTONLLL, 1, [Define if the function (or macro) htonlll exists.])
  ],
  [
      AC_MSG_RESULT(no)
  ]
)

dnl #############################################################
dnl #
dnl #  6. Checks for compiler characteristics
dnl #
dnl #############################################################

dnl #
dnl #  Ensure that these are defined
dnl #
AC_C_CONST

dnl #
dnl #  See if this is OS/2
dnl #
AC_MSG_CHECKING([type of OS])
OS=`uname -s`
AC_MSG_RESULT($OS)
if test "$OS" = "OS/2"; then
  LIBPREFIX=
else
  LIBPREFIX=lib
fi
AC_SUBST(LIBPREFIX)

if test "x$developer" = "xyes"; then
  AC_MSG_NOTICE([Setting additional developer CFLAGS])

  dnl #
  dnl #  Tell the compiler to parse doxygen documentation and verify it against function and variable declarations
  dnl #
  AX_CC_WDOCUMENTATION_FLAG
  if test "x$ax_cv_cc_wdocumentation_flag" = "xyes"; then
    devcflags="-Wdocumentation"
    AC_DEFINE([HAVE_WDOCUMENTATION],1,[Define if the compiler supports -Wdocumentation])
  fi

  dnl #
  dnl #  If we have -Weverything, it really means *everything* unlike -Wall
  dnl #  It's so verbose we need to turn off warnings which aren't useful.
  dnl #
  AX_CC_WEVERYTHING_FLAG
  if test "x$ax_cv_cc_weverything_flag" = "xyes"; then
    devcflags="$devcflags -W -Weverything -Wformat=2 -Wno-missing-field-initializers -Wno-date-time -Wno-padded -Wno-gnu-zero-variadic-macro-arguments -Wno-shorten-64-to-32 -Wno-sign-conversion -Wno-conversion -Wno-switch-enum -Wno-gnu-statement-expression -Wno-extended-offsetof -Wno-cast-align -Wno-documentation-unknown-command -Wno-covered-switch-default -Wno-packed $verify_ptr
  else
    if test "x$GCC" = "xyes"; then
      devcflags="$devcflags -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wnested-externs -W -Wredundant-decls -Wundef -Wformat-y2k -Wno-format-extra-args -Wno-format-zero-length -Wno-cast-align -Wformat-nonliteral -Wformat-security -Wformat=2 $verify_ptr
      INSTALLSTRIP=""
    fi
  fi

  dnl #
  dnl #  Can't use mutliple -fsanitize flags, so we need to combine
  dnl #  the values into one.
  dnl #
  fsanitizeflags=

  dnl #
  dnl #  If running with clang, add in FUZZER
  dnl #
  if test "x$fuzzer" = "xyes" && test "x$ax_cv_cc_clang" = "xyes"; then
    dnl #
    dnl #  -fsanitize=fuzzer  - Build with fuzzer support
    dnl #
    fsanitizeflags="$fsanitizeflags,fuzzer-no-link"
  fi

  dnl #
  dnl #  Add in ASAN
  dnl #
  if test "x$address_sanitizer" = "xyes"; then
    dnl #
    dnl #  -fsanitize=address		- Build with address sanitizer support
    dnl #  -fno-omit-frame-pointer	- Always keep the frame pointer in a register
    dnl #  -fno-optimize-sibling-calls	- Don't optimize away tail recursion.
    dnl #
    devcflags="$devcflags -fno-omit-frame-pointer -fno-optimize-sibling-calls"

    AX_CC_SANITZE_ADDRESS_USE_AFTER_SCOPE_FLAG
    if test "x$ax_cv_cc_sanitize_address_use_after_scope" = "xyes"; then
      devcflags="$devcflags -fsanitize-address-use-after-scope"
    fi

    AC_CHECK_HEADERS(sanitizer/lsan_interface.h)
    fsanitizeflags="$fsanitizeflags,address"
  fi

  dnl #
  dnl #  Add in LSAN
  dnl #
  if test "x$leak_sanitizer" = "xyes"; then
    dnl #
    dnl #  -fsanitize=leak	- Build with lsan support
    dnl #
    fsanitizeflags="$fsanitizeflags,leak"
  fi

  dnl #
  dnl #  Add in TSAN
  dnl #
  if test "x$thread_sanitizer" = "xyes"; then
    dnl #
    dnl #  -fsanitize=thread	- Build with tsan support
    dnl #
    fsanitizeflags="$fsanitizeflags,thread"
  fi

  dnl #
  dnl #  Add in UBSAN
  dnl #
  if test "x$undefined_behaviour_sanitizer" = "xyes"; then
    dnl #
    dnl #  -fsanitize=undefined		- Build with ubsan support
    dnl #  -fno-omit-frame-pointer	- Always keep the frame pointer in a register
    dnl #
    devcflags="$devcflags -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
    devldflags="$devldflags -fno-sanitize-recover=undefined"
    fsanitizeflags="$fsanitizeflags,undefined"
  fi

  if test "x$fsanitizeflags" != "x"; then
    fsanitizeflags="$(echo $fsanitizeflags | sed 's/^,*//')"
    devcflags="-fsanitize=$fsanitizeflags $devcflags"
    devldflags="-fsanitize=$fsanitizeflags $devldflags"
  fi

  dnl #
  dnl # Clean the flags up
  dnl #
  devcflags="$(echo $devcflags | sed -e 's/\\t//g;s/  //g')"
  devldflags="$(echo $devldflags | sed -e 's/\\t//g;s/  //g')"

  AC_MSG_NOTICE([Developer CFLAGS are "$devcflags"])
  AC_MSG_NOTICE([Developer LDFLAGS are "$devldflags"])

  dnl #
  dnl #  Enable experimental modules (we want to know if code changes breaks one of them)
  dnl #
  if test "x$EXPERIMENTAL" != "xno"; then
    AC_MSG_NOTICE([is developer build, enabling experimental modules implicitly, disable with --without-experimental-modules])
    EXPERIMENTAL=yes
  fi
else
  devcflags=""
  devldflags=""
  CFLAGS="$CFLAGS -DNDEBUG"
  INSTALLSTRIP=""
fi

dnl #
dnl #  May of been set outside of this configure script
dnl #
AC_MSG_CHECKING([if building with -DNDEBUG])
if echo "$CFLAGS" | grep '\-DNDEBUG' > /dev/null; then
  AC_MSG_RESULT([yes])
  AC_DEFINE([WITH_NDEBUG], [1], [define if the server was built with -DNDEBUG])
else
  AC_MSG_RESULT([no])
fi

export EXPERIMENTAL

dnl #
dnl #  append the current git hash onto the version string
dnl #
if test -d $srcdir/.git -a "x$GIT" = "xyes"; then
  RADIUSD_VERSION_COMMIT=`git log --pretty=format:'%h' -n 1 | cut -c1-9`
  AC_DEFINE_UNQUOTED([RADIUSD_VERSION_COMMIT],[${RADIUSD_VERSION_COMMIT}],[Commit HEAD at time of configuring])
fi

dnl #
dnl #  check for some compiler features
dnl #
FR_TLS
FR_HAVE_BUILTIN_CHOOSE_EXPR
FR_HAVE_BUILTIN_TYPES_COMPATIBLE_P
FR_HAVE_BUILTIN_BSWAP64
FR_HAVE_BOUNDED_ATTRIBUTE

dnl #############################################################
dnl #
dnl #  7. Checks for library functions
dnl #
dnl #############################################################

dnl #
dnl # Check for talloc_set_memlimit
dnl # This was only included in version 2.0.8
dnl #
AC_CHECK_LIB(talloc, talloc_set_memlimit,
  [
    AC_DEFINE(HAVE_TALLOC_SET_MEMLIMIT, 1, [Define to 1 if you have the function talloc_set_memlimit.])
  ]
)

dnl #
dnl # Check for libcrypt
dnl # We use crypt(3) which may be in libc, or in libcrypt (eg FreeBSD)
dnl #
AC_CHECK_LIB(crypt, crypt,
  CRYPTLIB="-lcrypt"
)

if test "$CRYPTLIB" != ""; then
  AC_DEFINE(HAVE_CRYPT, [], [Do we have the crypt function])
else
  AC_CHECK_FUNC(crypt, AC_DEFINE(HAVE_CRYPT, [], [Do we have the crypt function]))
fi

dnl crypt_r is the GNU thread-safe version
AC_CHECK_LIB(crypt, crypt_r, AC_DEFINE(HAVE_CRYPT_R, [], [Do we have the crypt_r function]))

dnl Check for libcipher
AC_CHECK_LIB(cipher, setkey,
   CRYPTLIB="${CRYPTLIB} -lcipher"
)
AC_SUBST(CRYPTLIB)

dnl #
dnl #  Check for libexecinfo support, on some systems this is built into libc
dnl #  on others it's a separate library.
dnl #
dnl extra argument: --with-execinfo-lib-dir
execinfo_lib_dir=
AC_ARG_WITH(execinfo-lib-dir,
[AS_HELP_STRING([--with-execinfo-lib-dir=DIR],
[directory in which to look for execinfo library files])],
[ case "$withval" in
    no)
        AC_MSG_ERROR([Need execinfo-lib-dir])
	;;
    yes)
	;;
    *)
	execinfo_lib_dir="$withval"
	;;
  esac ]
)

dnl extra argument: --with-execinfo-include-dir
execinfo_include_dir=
AC_ARG_WITH(execinfo-include-dir,
[AS_HELP_STRING([--with-execinfo-include-dir=DIR],
[directory in which to look for execinfo include files])],
[ case "$withval" in
    no)
        AC_MSG_ERROR([Need execinfo-include-dir])
	;;
    yes)
	;;
    *)
	execinfo_include_dir="$withval"
	;;
  esac ]
)

dnl #
dnl #  Look for execinfo.h and symbols
dnl #
smart_try_dir=$execinfo_include_dir
FR_SMART_CHECK_INCLUDE(execinfo.h)
if test "x$ac_cv_header_execinfo_h" = "xyes"; then
  smart_try_dir=$execinfo_lib_dir
  FR_SMART_CHECK_LIB(execinfo, backtrace_symbols)
  if test "x$ac_cv_lib_execinfo_backtrace_symbols" != "xyes"; then
    dnl # Might be provided as part of libc
    AC_MSG_CHECKING([if execinfo provided as part of libc])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
        #include <execinfo.h>
      ]], [[
        void *sym[1];
        backtrace_symbols(&sym, sizeof(sym)) ]])],[
        AC_MSG_RESULT(yes)
        ac_cv_lib_execinfo_backtrace_symbols="yes"
      ],[
        AC_MSG_RESULT(no)
    ])
  fi

  if test "x$ac_cv_lib_execinfo_backtrace_symbols" = "xyes"; then
    AC_DEFINE(HAVE_EXECINFO, [1], [define this if we have <execinfo.h> and symbols])
  fi
fi

dnl #
dnl #  Check for regular expression support.
dnl #
dnl extra argument: --with-pcre
PCRE=yes
AC_ARG_WITH(pcre,
[AS_HELP_STRING([--with-pcre],
[use libpcre (if available). (default=yes)])],
[ case "$withval" in
    no)
    PCRE=no
	;;
    yes)
    PCRE=yes
	;;
  esac ]
)

dnl extra argument: --with-pcre-lib-dir
pcre_lib_dir=
AC_ARG_WITH(pcre-lib-dir,
[AS_HELP_STRING([--with-pcre-lib-dir=DIR],
[directory in which to look for pcre library files])],
[ case "$withval" in
    no)
	AC_MSG_ERROR(Need pcre-lib-dir)
	;;
    yes)
	;;
    *)
	pcre_lib_dir="$withval"
	;;
  esac ]
)

dnl extra argument: --with-pcre-include-dir
pcre_include_dir=
AC_ARG_WITH(pcre-include-dir,
[AS_HELP_STRING([--with-pcre-include-dir=DIR],
[directory in which to look for pcre include files])],
[ case "$withval" in
    no)
	AC_MSG_ERROR(Need pcre-include-dir)
	;;
    yes)
	;;
    *)
	pcre_include_dir="$withval"
	;;
  esac ]
)

dnl extra argument: --with-regex
REGEX=
AC_ARG_WITH(regex,
[AS_HELP_STRING([--with-regex],
[Whether to build with regular expressions (default=yes)])],
[ case "$withval" in
    no)
	REGEX=no
	;;
    *)
	;;
  esac ]
)

dnl #
dnl #  First look for PCRE
dnl #
if test "x$REGEX" != "xno" && test "x$PCRE" != "xno"; then
  smart_try_dir=$pcre_include_dir
  FR_SMART_CHECK_INCLUDE(pcre.h)
  if test "x$ac_cv_header_pcre_h" = "xyes"; then
    smart_try_dir=$pcre_lib_dir
    FR_SMART_CHECK_LIB(pcre, pcre_compile)
    if test "x$ac_cv_lib_pcre_pcre_compile" = "xyes"; then
      REGEX=yes
      AC_DEFINE(HAVE_PCRE, [1], [define this if we have libpcre])
      AC_DEFINE(HAVE_BINSAFE_REGEX, 1, [Define if we have a binary safe regular expression library])
    fi
  fi
fi

dnl #
dnl #  If no PCRE, look for PCRE2
dnl #
if test "x$REGEX" = "x" && test "x$PCRE" != "xno"; then
  smart_try_dir=$pcre_include_dir
  FR_SMART_CHECK_INCLUDE(pcre2.h,[#define PCRE2_CODE_UNIT_WIDTH (8)])
  if test "x$ac_cv_header_pcre2_h" = "xyes"; then
    smart_try_dir=$pcre_lib_dir
    FR_SMART_CHECK_LIB(pcre2-8, pcre2_compile_8)
    if test "x$ac_cv_lib_pcre2_8_pcre2_compile_8" = "xyes"; then
      REGEX=yes
      AC_DEFINE(HAVE_PCRE2, [1], [define this if we have libpcre2])
      AC_DEFINE(HAVE_BINSAFE_REGEX, 1, [Define if we have a binary safe regular expression library])
    fi
  fi
fi

dnl #
dnl #  If no PCRE2 or PCRE, fallback to POSIX regular expressions
dnl #
if test "x$REGEX" = "x"; then
  smart_try_dir=
  FR_SMART_CHECK_INCLUDE(regex.h)
  if test "x$ac_cv_header_regex_h" = "xyes"; then
    REGEX=yes
    AC_MSG_CHECKING([for extended regular expressions])
    AC_EGREP_CPP(yes,
      [
        #include <regex.h>
        #ifdef REG_EXTENDED
        yes
        #endif
      ],
      [
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_REG_EXTENDED, [1], [define this if we have REG_EXTENDED (from <regex.h>)])
      ],
      [
        AC_MSG_RESULT(no)
      ]
    )

    dnl #
    dnl #  Some platforms require the regex library to be linked explicitly
    dnl #
    AC_CHECK_LIB(regex, regcomp,
      [
        LIBS="-lregex $LIBS"
      ]
    )

    dnl #
    dnl #  Check for some BSD extensions which allow normal regexes to be
    dnl #  binary safe.
    dnl #
    AC_CHECK_FUNCS(\
      regncomp \
      regnexec
    )
    if test x"$ac_cv_func_regncomp" = x"yes" && test  x"$ac_cv_func_regnexec" = x"yes"; then
      AC_DEFINE(HAVE_BINSAFE_REGEX, 1, [Define if we have a binary safe regular expression library])
    fi
  fi
fi

#
#  Some platforms require an explicit -latomic
#
AC_SEARCH_LIBS([__atomic_load_4], [atomic])

if test "x$REGEX" = "xyes"; then
  AC_DEFINE(HAVE_REGEX, 1, [Define if we have any regular expression library])
fi

dnl #
dnl #  Check the style of gethostbyaddr, in order of preference
dnl #  GNU (_r eight args)
dnl #
AC_DEFINE(GNUSTYLE, [1], [GNU-Style get*byaddr_r])

dnl #
dnl #  SYSV (_r six args)
dnl #
AC_DEFINE(SYSVSTYLE, [2], [SYSV-Style get*byaddr_r])

dnl #
dnl #  BSD (three args, may not be thread safe)
dnl #
AC_DEFINE(BSDSTYLE, [3], [BSD-Style get*byaddr_r])

dnl #
dnl #  Tru64 has BSD version, but it is thread safe
dnl #  http://h30097.www3.hp.com/docs/base_doc/DOCUMENTATION/V51B_HTML/MAN/MAN3/1739____.HTM
dnl #  We need #stdio.h to define NULL on FreeBSD (at least)
dnl #
gethostbyaddrrstyle=""
AC_MSG_CHECKING([gethostbyaddr_r() syntax])
case "$host" in
  *-freebsd*)
    dnl #
    dnl #  With FreeBSD, check if there's a prototype for gethostbyaddr_r.
    dnl #  Some versions (FreeBSD 5.1?) have a symbol but no prototype - so we
    dnl #  override this test to BSDSTYLE. FreeBSD 6.2 and up have proper GNU
    dnl #  style support.
    dnl #
    AC_CHECK_DECLS([gethostbyaddr_r], [],
      [
        AC_DEFINE(GETHOSTBYADDRRSTYLE, BSDSTYLE,
          [style of gethostbyaddr_r functions ])
        gethostbyaddrrstyle=BSD
        AC_MSG_WARN([FreeBSD overridden to BSD-style])
      ],
      [
        #ifdef HAVE_NETDB_H
        #include <netdb.h>
        #endif
      ])
    ;;
esac

if test "x$gethostbyaddrrstyle" = "x"; then
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[
      #include <stdio.h>
      #include <netdb.h>
    ]], [[ gethostbyaddr_r(NULL, 0, 0, NULL, NULL, 0, NULL, NULL) ]])],[
      AC_DEFINE(GETHOSTBYADDRRSTYLE, GNUSTYLE, [style of gethostbyaddr_r functions ])
      gethostbyaddrrstyle=GNU
  ],[])
fi

if test "x$gethostbyaddrrstyle" = "x"; then
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[
      #include <stdio.h>
      #include <netdb.h>
    ]], [[ gethostbyaddr_r(NULL, 0, 0, NULL, NULL, 0, NULL)  ]])],[
      AC_DEFINE(GETHOSTBYADDRRSTYLE, SYSVSTYLE, [style of gethostbyaddr_r functions ])
      gethostbyaddrrstyle=SYSV
  ],[])
fi


if test "x$gethostbyaddrrstyle" = "x"; then
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[
      #include <stdio.h>
      #include <netdb.h>
    ]], [[ gethostbyaddr(NULL, 0, 0)  ]])],[
      AC_DEFINE(GETHOSTBYADDRRSTYLE, BSDSTYLE, [style of gethostbyaddr_r functions ])
      gethostbyaddrrstyle=BSD
  ],[])
fi

if test "x$gethostbyaddrrstyle" = "x"; then
  AC_MSG_RESULT([none!  It must not exist, here.])
else
  AC_MSG_RESULT([${gethostbyaddrrstyle}-style])
fi

if test "x$gethostbyaddrrstyle" = "xBSD"; then
  AC_MSG_WARN([ ****** BSD-style gethostbyaddr might NOT be thread-safe! ****** ])
fi

dnl #
dnl #  Check the style of gethostbyname, in order of preference
dnl #  GNU (_r seven args)
dnl #  SYSV (_r five args)
dnl #  BSD (two args, may not be thread safe)
dnl #  Tru64 has BSD version, but it _is_ thread safe
dnl #    http://h30097.www3.hp.com/docs/base_doc/DOCUMENTATION/V51B_HTML/MAN/MAN3/1946____.HTM
dnl #  We need #stdio.h to define NULL on FreeBSD (at least)
dnl #
gethostbynamerstyle=""
AC_MSG_CHECKING([gethostbyname_r() syntax])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
    #include <stdio.h>
    #include <netdb.h>
  ]], [[ gethostbyname_r(NULL, NULL, NULL, 0, NULL, NULL) ]])],[
    AC_DEFINE(GETHOSTBYNAMERSTYLE, GNUSTYLE, [style of gethostbyname_r functions ])
    gethostbynamerstyle=GNU
],[])

if test "x$gethostbynamerstyle" = "x"; then
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[
      #include <stdio.h>
      #include <netdb.h>
    ]], [[ gethostbyname_r(NULL, NULL, NULL, 0, NULL)  ]])],[
      AC_DEFINE(GETHOSTBYNAMERSTYLE, SYSVSTYLE, [style of gethostbyname_r functions ])
      gethostbynamerstyle=SYSV
  ],[])
fi

if test "x$gethostbynamerstyle" = "x"; then
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[
      #include <stdio.h>
      #include <netdb.h>
    ]], [[ gethostbyname(NULL) ]])],[
      AC_DEFINE(GETHOSTBYNAMERSTYLE, BSDSTYLE, [style of gethostbyname_r functions ])
      gethostbynamerstyle=BSD
  ],[])
fi

if test "x$gethostbynamerstyle" = "x"; then
  AC_MSG_RESULT([none!  It must not exist, here.])
else
  AC_MSG_RESULT([${gethostbynamerstyle}-style])
fi

if test "x$gethostbynamerstyle" = "xBSD"; then
  AC_MSG_WARN([ ****** BSD-style gethostbyname might NOT be thread-safe! ****** ])
fi

dnl #
dnl #  Check for thread-safe getpwnam_r and getgrnam_r
dnl #
if test "x$ac_cv_header_pwd_h" = "xyes"; then
  AC_MSG_CHECKING([getpwnam_r])
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[
      #include <stdlib.h>
      #include <sys/types.h>
      #include <pwd.h>
    ]], [[ getpwnam_r(NULL, NULL, NULL, 0, NULL) ]])],[
      AC_MSG_RESULT([yes])
      AC_DEFINE(HAVE_GETPWNAM_R, 1,
                [Define to 1 if you have the getpwnam_r.]
                )
    ],[
        AC_MSG_RESULT(no)
  ])
fi

if test "x$ac_cv_header_grp_h" = "xyes"; then
  AC_MSG_CHECKING([getgrnam_r])
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[
      #include <stdlib.h>
      #include <sys/types.h>
      #include <grp.h>
    ]], [[ getgrnam_r(NULL, NULL, NULL, 0, NULL) ]])],[
      AC_MSG_RESULT([yes])
      AC_DEFINE(HAVE_GETGRNAM_R, 1,
                [Define to 1 if you have the getgrnam_r.]
                )
    ],[
        AC_MSG_RESULT(no)
  ])
fi


dnl #
dnl #  Check for non-posix solaris ctime_r (extra buflen int arg)
dnl #
AC_DEFINE(POSIXSTYLE, [1], [Posix-Style ctime_r])
AC_DEFINE(SOLARISSTYLE, [2], [Solaris-Style ctime_r])
ctimerstyle=""
AC_MSG_CHECKING([ctime_r() syntax])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
    #include <time.h>
  ]], [[ ctime_r(NULL, NULL, 0) ]])],[
    AC_DEFINE(CTIMERSTYLE, SOLARISSTYLE, [style of ctime_r function])
    ctimerstyle="SOLARIS"
],[])

if test "x$ctimerstyle" = "x"; then
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[
      #include <time.h>
    ]], [[ ctime_r(NULL, NULL) ]])],[
      AC_DEFINE(CTIMERSTYLE, POSIXSTYLE, [style of ctime_r function])
      ctimerstyle="POSIX"
  ],[])
fi

if test "x$ctimerstyle" = "x"; then
    AC_MSG_RESULT([none!  It must not exist, here.])
else
    AC_MSG_RESULT([${ctimerstyle}-style])
fi

AC_SUBST(HOSTINFO, $host)

dnl #############################################################
dnl #
dnl #  8. Checks for system services
dnl #
dnl #############################################################

dnl #
dnl #  Figure out where libtool is located,
dnl #
top_builddir=`pwd`
export top_builddir
AC_MSG_RESULT([top_builddir=$top_builddir])
dnl #  AC_SUBST(top_builddir)

dnl #
dnl #  import libtool stuff
dnl #
dnl #############################################################
dnl #
dnl #  Configure in any module directories.
dnl #
dnl #############################################################

dnl ############################################################
dnl #  Remove any conflicting definitions if autoconf.h
dnl #  is being included by a module.
dnl #############################################################
AH_BOTTOM([#include <freeradius-devel/automask.h>])

dnl ############################################################
dnl #  make modules by list
dnl #############################################################
if test "x$EXPERIMENTAL" = "xyes"; then
  for foo in `ls -1 "${srcdir}"/src/modules | grep rlm_`; do
    MODULES="$MODULES $foo"
  done
else
   dnl #
   dnl #  make ONLY the stable modules
   dnl #
   for foo in `cat "${srcdir}"/src/modules/stable`; do
      MODULES="$MODULES $foo"
   done
fi

dnl ############################################################
dnl #  Add autoconf subdirs, based on the module list we
dnl #  previously created.
dnl #############################################################
mysubdirs=""
for bar in $MODULES; do
  if test -f "${srcdir}"/src/modules/$bar/configure; then
    mysubdirs="$mysubdirs src/modules/$bar"
  fi
done

dnl #
dnl #  Don't change the variable name here.  Autoconf goes bonkers
dnl #  if you do.
dnl #
AC_CONFIG_SUBDIRS($mysubdirs)
AC_SUBST(MODULES)

dnl #
dnl #  If reproducible builds are not enabled, disable
dnl #  -Wdate-time so the compiler doesn't croak.
dnl #
if test "x$ax_cv_cc_no_date_time_flag" = "xyes" && test "x$reproducible_builds" != "xyes"; then
  CFLAGS="-Wno-date-time $CFLAGS"
fi

dnl #############################################################
dnl #
dnl #  Add $devcflags, $devldflags and -Werror last, so they don't
dnl #  interfere with autoconf's test programs.
dnl #
dnl #############################################################
CFLAGS="$CFLAGS $devcflags"
LDFLAGS="$LDFLAGS $devldflags"

if test "x$werror" = "xyes"; then
  CFLAGS="-Werror $CFLAGS"
fi

dnl #############################################################
dnl #
dnl #  And finally, output the results.
dnl #
dnl #############################################################
AC_CONFIG_COMMANDS([stamp-h], [echo timestamp > src/include/stamp-h])
AC_CONFIG_COMMANDS([build-radpaths-h], [(cd ./src/include && /bin/sh ./build-radpaths-h)])
AC_CONFIG_COMMANDS([main-chmod], [(cd ./src/main && chmod +x checkrad radlast radtest)])
AC_CONFIG_COMMANDS([scripts-chmod], [(cd ./scripts && chmod +x rc.radiusd cron/radiusd.cron.daily cron/radiusd.cron.monthly cryptpasswd)])

dnl #
dnl #  Substitute whatever libraries we found to be necessary
dnl #
AC_SUBST(LIBS)
AC_SUBST(INSTALLSTRIP)

AC_SUBST(USE_SHARED_LIBS)
USE_STATIC_LIBS="yes"
AC_SUBST(USE_STATIC_LIBS)
AC_SUBST(STATIC_MODULES)
AC_SUBST(MANSKIP)

AC_CONFIG_FILES([\
  ./Make.inc \
  ./src/include/build-radpaths-h \
  ./src/main/radsniff.mk \
  ./src/main/radlast.mk \
  ./src/main/checkrad \
  ./src/main/radlast \
  ./src/main/radtest \
  ./scripts/rc.radiusd \
  ./scripts/cron/radiusd.cron.daily \
  ./scripts/cron/radiusd.cron.monthly \
  ./scripts/cryptpasswd \
  ./raddb/radrelay.conf \
  ./raddb/radiusd.conf
])
AC_OUTPUT

FR_MODULE_REPORT
