dnl #############################################################
dnl #
dnl #  For information about autoconf, see:
dnl #
dnl #  http://www.gnu.org/software/autoconf/
dnl #
dnl #  The recommended order is:
dnl #
dnl #  AC_INIT(file)
dnl #  0. checks for compiler, libtool, and command line options
dnl #  1. checks for programs
dnl #  2. checks for libraries
dnl #  3. checks for header files
dnl #  4. checks for typedefs
dnl #  5. checks for structures and functions
dnl #  6. checks for compiler characteristics
dnl #  7. checks for library functions
dnl #  8. checks for system services
dnl #  AC_OUTPUT([file...])
dnl #
dnl #############################################################

AC_PREREQ([2.59])
export CFLAGS LIBS LDFLAGS CPPFLAGS

AC_INIT([freeradius],[$]Id[$],[http://bugs.freeradius.org],,[http://www.freeradius.org])
AC_CONFIG_SRCDIR([src/bin/radiusd.c])
AC_CONFIG_HEADER([src/include/autoconf.h])
m4_include([m4/ax_cc.m4])
m4_include([m4/ax_with_lib_args.m4])
m4_include([m4/ax_with_feature_args.m4])
m4_include([m4/ax_prog_perl_modules.m4])

dnl #############################################################
dnl #
dnl #  Custom hackery to discover version at configure time
dnl #
dnl #############################################################

RADIUSD_VERSION_MAJOR=`cat VERSION | cut -f1 -d.`
RADIUSD_VERSION_MINOR=`cat VERSION | cut -f2 -d.`
RADIUSD_VERSION_INCRM=`cat VERSION | cut -f3 -d. | sed 's/[[\.-]].*$//'`

AC_MSG_CHECKING([build version])
RADIUSD_VERSION=`printf "%02i%02i%02i" $RADIUSD_VERSION_MAJOR $RADIUSD_VERSION_MINOR $RADIUSD_VERSION_INCRM`
AC_MSG_RESULT($RADIUSD_VERSION)

dnl #
dnl #  Still useful for custom builds
dnl #
AC_MSG_CHECKING([build version string])
RADIUSD_VERSION_STRING=`cat VERSION`
AC_MSG_RESULT($RADIUSD_VERSION_STRING)

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
dnl #  See if we have Git.
dnl #
AC_CHECK_PROG(GIT, git, yes, no)

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
if test "x$GIT" = "xyes" && git status 2>&1 > /dev/null; then
  if test "x$RADIUSD_VERSION_RELEASE" = "x"; then
    AC_MSG_CHECKING([build release])
    RADIUSD_VERSION_RELEASE=`git describe | sed -e 's/^.*-\([[0-9]]*\)-g[[0-9a-f]]*/\1/'`
    AC_MSG_RESULT($RADIUSD_VERSION_RELEASE)
  fi

  if test "x$RADIUSD_VERSION_COMMIT" = "x"; then
    AC_MSG_CHECKING([build commit])
    RADIUSD_VERSION_COMMIT=`git rev-parse --short=8 HEAD`
    AC_MSG_RESULT($RADIUSD_VERSION_COMMIT)
  fi

  if test "x$developer" != "xno"; then
    AC_MSG_NOTICE([in git repository, enabling developer build implicitly, disable with --disable-developer])
    developer="yes"
  fi
fi

if test "x$RADIUSD_VERSION_RELEASE" != "x"; then
  AC_DEFINE_UNQUOTED([RADIUSD_VERSION_RELEASE],[${RADIUSD_VERSION_RELEASE}],[Version release number at time of configuring])
fi

if test "x$RADIUSD_VERSION_COMMIT" != "x"; then
  AC_DEFINE_UNQUOTED([RADIUSD_VERSION_COMMIT],[${RADIUSD_VERSION_COMMIT}],[Commit HEAD at time of configuring])
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

dnl #############################################################
dnl #
dnl #  0. Checks for compiler
dnl #
dnl #############################################################

dnl #
dnl #  Get system information
dnl #
AC_CANONICAL_SYSTEM
AC_SUBST(TARGET_SYSTEM, "$target")

dnl #  Check for GNU cc
dnl #
AC_PROG_CC
AC_PROG_CXX

dnl #
dnl #  check for AIX, to allow us to use some BSD functions
dnl #  must be before macros that call the compiler.
dnl #
AC_AIX

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

AX_CC_STD_C11
if test "x$ax_cv_cc_std_c11_flag" != x; then
  CFLAGS="$CFLAGS $ax_cv_cc_std_c11_flag"
else
  AC_MSG_ERROR([FreeRADIUS requires a C11 compiler])
fi

dnl #
dnl #  Set Default CFLAGS for GCC compatible compilers
dnl #
if test "x$GCC" = "xyes"; then
  CFLAGS="$CFLAGS -Wall -D_GNU_SOURCE"
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

dnl #############################################################
dnl #
dnl #  0a. Enable/disable compiler checks and library checks
dnl #
dnl #############################################################

dnl # Put this in later, when all distributed modules use autoconf.
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
dnl #  Enable the -fsanitize=address and link in the address sanitizer
dnl #  libraries.
dnl #
AC_ARG_ENABLE(llvm-address-sanitizer,
[AS_HELP_STRING([--enable-llvm-address-sanitizer],
                [build with support for LLVM's address sanitizer (if building with clang).])],
[ case "$enableval" in
  no)
    llvm_address_sanitizer=no
    ;;
  *)
    llvm_address_sanitizer=yes
  esac ]
)

dnl #
dnl #  Enable the -fsanitize=undefined and link in the address sanitizer
dnl #  libraries.
dnl #
AC_ARG_ENABLE(llvm-undefined-behaviour-sanitizer,
[AS_HELP_STRING([--enable-llvm-undefined-behaviour-sanitizer],
                [build with support for LLVM's undefined behaviour sanitizer (if building with clang).])],
[ case "$enableval" in
  no)
    llvm_undefined_behaviour_sanitizer=no
    ;;
  *)
    llvm_undefined_behaviour_sanitizer=yes
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

dnl #############################################################
dnl #
dnl #  0b. Enable/disable modules
dnl #
dnl #############################################################

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

dnl #############################################################
dnl #
dnl #  0c. Set build/install directories
dnl #
dnl #############################################################

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
dictdir='${datarootdir}/freeradius/dictionary'
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

dnl #############################################################
dnl #
dnl #  0d. Enable/disable build time features
dnl #
dnl #############################################################

dnl #
dnl #  extra argument:		--with-ascend-binary
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

AX_WITH_FEATURE_ARGS([tcp],[yes])
AX_WITH_FEATURE_ARGS([vmps],[yes])
AX_WITH_FEATURE_ARGS([dhcp],[yes])
AX_WITH_FEATURE_ARGS([tacacs],[yes])
AX_WITH_FEATURE_ARGS([udpfromto],[yes])

dnl #############################################################
dnl #
dnl #  0e. Library/include paths
dnl #
dnl #############################################################

AX_WITH_LIB_ARGS_OPT([cap],[yes])
AX_WITH_LIB_ARGS_OPT([collectdclient],[yes])
AX_WITH_LIB_ARGS_OPT([execinfo],[yes])
AX_WITH_LIB_ARGS_OPT([gperftools],[yes])
AX_WITH_LIB_ARGS_OPT([openssl],[yes])
AX_WITH_LIB_ARGS([kqueue])
AX_WITH_LIB_ARGS_OPT([pcap],[yes])
AX_WITH_LIB_ARGS_OPT([pcre],[yes])
AX_WITH_LIB_ARGS_OPT([systemd],[yes])
AX_WITH_LIB_ARGS([talloc])

dnl #
dnl # extra argument: --with-regex
dnl #
WITH_REGEX=
AC_ARG_WITH(regex,
[AS_HELP_STRING([--with-regex],
[build with regular expressions if available(default=yes)])],
[ case "$withval" in
    no)
	WITH_REGEX=no
	;;
    *)
	;;
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
dnl #  FIXME This is truly gross.
dnl #
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)

AC_PATH_PROG(LOCATE,locate)
AC_PATH_PROG(DIRNAME,dirname)
AC_PATH_PROG(GREP,grep)

dnl #############################################################
dnl #
dnl #  2a. Checks for system libraries
dnl #
dnl #############################################################

dnl #
dnl #  If using pthreads, check for -lpthread (posix) or -lc_r (*BSD)
dnl #
old_CFLAGS=$CFLAGS
if test $ac_cv_prog_suncc = "yes"; then
  CFLAGS="$CFLAGS -mt"
fi

HAVE_THREADS=
AC_CHECK_HEADERS(pthread.h, [],
[
  HAVE_THREADS="no"
  fail=[pthread.h]
])

if test "x$HAVE_THREADS" != "xno"; then
  dnl #
  dnl #  pthread stuff is usually in -lpthread
  dnl #  or in -lc_r, on *BSD
  dnl #
  dnl #  On Some systems, we need extra pre-processor flags, to get them to
  dnl #  to do the threading properly.
  dnl #
  AC_CHECK_LIB(pthread, pthread_create,
    [
      HAVE_THREADS="yes"
      CFLAGS="$CFLAGS -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS"
      LIBS="-lpthread $LIBS"

      dnl #
      dnl #  -pthread should add all required CPP definitions and linker
      dnl #  arguments. But not all compilers support it, or some compilers
      dnl #  only support it on certain platforms.
      dnl #
      AX_CC_PTHREAD_FLAG
      if test "x$ax_cv_cc_pthread_flag" = 'xyes'; then
        CFLAGS="$CFLAGS -pthread"
      fi
    ]
  )
fi

dnl #
dnl #  Check for libc_r which used to be the threading library used
dnl #  for FreeBSD. Internet says it may be deprecated, but if we
dnl #  can't find lpthread it's probably worth checking.
dnl #
if test "x$HAVE_THREADS" != "xyes"; then
  AC_CHECK_LIB(c_r, pthread_create,
    [
      HAVE_THREADS="yes"
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

if test "x$HAVE_THREADS" != "xyes"; then
  AC_MSG_ERROR([FreeRADIUS requires thread support, missing: $fail])
fi

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
  [AC_MSG_ERROR([[-lsem not found.  You may want to download it from ftp://ftp.to.gd-es.com/pub/BSDI/libsem.tar.bz2 or ftp://ftp.freeradius.org/pub/radius/contrib/libsem.tar.gz]])]
)

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

dnl #
dnl #  Check if we need -lrt, this is required on
dnl #  older Linuxes for clock_gettime.
dnl #
AC_CHECK_LIB(rt, clock_gettime)

dnl #############################################################
dnl #
dnl #  2b. Checks for system header files
dnl #
dnl #############################################################

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
  valgrind.h
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

dnl #############################################################
dnl #
dnl #  3a. Checks for user libraries
dnl #
dnl #############################################################

dnl #
dnl #  Check for libtalloc
dnl #
smart_try_dir="$talloc_lib_dir"
FR_SMART_CHECK_LIB(talloc, _talloc)
if test "x$ac_cv_lib_talloc__talloc" != "xyes"; then
  AC_MSG_WARN([talloc library not found. Use --with-talloc-lib-dir=<path>.])
  AC_MSG_ERROR([FreeRADIUS requires libtalloc.  Please read doc/developers/dependencies.adoc for further instructions.])
fi

dnl #
dnl # Check for talloc_set_memlimit
dnl # This was only included in version 2.0.8
dnl # Needs to be done here with the talloc linker flags set
dnl #
AC_CHECK_FUNCS(
  talloc_set_memlimit \
  _talloc_pooled_object
)

TALLOC_LIBS="${smart_lib}"
TALLOC_LDFLAGS="${smart_ldflags}"
AC_SUBST(TALLOC_LIBS)
AC_SUBST(TALLOC_LDFLAGS)
LIBS="$old_LIBS"

dnl #
dnl #  Check for libkqueue (or system kqueue present on OSX and the BSDs)
dnl #
AC_CHECK_FUNC([kqueue])
if test "x$ac_cv_func_kqueue" != "xyes"; then
  smart_try_dir="$kqueue_lib_dir"
  FR_SMART_CHECK_LIB(kqueue, kqueue)
  if test "x$ac_cv_lib_kqueue_kqueue" != "xyes"; then
    AC_MSG_WARN([kqueue library not found. Use --with-kqueue-lib-dir=<path>.])
    AC_MSG_ERROR([FreeRADIUS requires libkqueue (or system kqueue).  Please read doc/developers/dependencies.adoc for further instructions.])
  fi
fi

KQUEUE_LIBS="${smart_lib}"
KQUEUE_LDFLAGS="${smart_ldflags}"
AC_SUBST(KQUEUE_LIBS)
AC_SUBST(KQUEUE_LDFLAGS)
LIBS="$old_LIBS"

dnl #
dnl #  Check for libpcap
dnl #
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

dnl #
dnl #  Check for collectdclient
dnl #
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

dnl #
dnl #  Check for cap (Linux capabilities)
dnl #
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
dnl #  Look for gperftools, we could just ldpreload it, but google recommends linking
dnl #  it in properly.
dnl #
if test "x$WITH_GPERFTOOLS" = xyes; then
  smart_try_dir="$gperftools_lib_dir"
  FR_SMART_CHECK_LIB(profiler, ProfilerStart)
  if test "x$ac_cv_lib_profiler_ProfilerStart" != "xyes"; then
    AC_MSG_WARN([libprofiler (gperftools) library not found. Use --with-gperftools-lib-dir=<path>.])
  else
    GPERFTOOLS_LIBS="${smart_lib}"
    GPERFTOOLS_LDFLAGS="${smart_ldflags}"
  fi
  dnl Set by FR_SMART_CHECKLIB
  LIBS="${old_LIBS}"
fi

dnl #
dnl #  Check for systemd
dnl #
if test "x$WITH_SYSTEMD" = xyes; then
  smart_try_dir="$systemd_lib_dir"
  FR_SMART_CHECK_LIB(systemd, sd_notify)
  if test "x$ac_cv_lib_systemd_sd_notify" != "xyes"; then
    AC_MSG_WARN([systemd library not found. Use --with-systemd-lib-dir=<path>.])
  else
    AC_DEFINE(HAVE_SYSTEMD, 1,
      [Define to 1 if you have the 'systemd' library (-lsystemd).]
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
    AC_DEFINE(HAVE_SYSTEMD_WATCHDOG, 1,
      [Define to 1 if you have watchdog support in the 'systemd' library (-lsystemd).]
    )
  fi
  dnl Set by FR_SMART_CHECKLIB
  LIBS="${old_LIBS}"
fi

dnl #
dnl #  Check for libreadline
dnl #
VL_LIB_READLINE

dnl #############################################################
dnl #
dnl #  3b. Checks for header files
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
dnl # Check for kqueue header files
dnl #
if test "x$ac_cv_header_sys_event_h" != "xyes"; then
  smart_try_dir="${kqueue_include_dir:-/usr/include/kqueue}"
  FR_SMART_CHECK_INCLUDE([sys/event.h])
  if test "x$ac_cv_header_sys_event_h" != "xyes"; then
    AC_MSG_WARN([kqueue headers not found. Use --with-kqueue-include-dir=<path>.])
    AC_MSG_ERROR([FreeRADIUS requires libkqueue (or system kqueue)])
  fi
fi

dnl #
dnl #  Interix requires us to set -D_ALL_SOURCE, otherwise
dnl #  getopt will be #included, but won't link.  <sigh>
dnl #
case "$target" in
  *-interix*)
    CFLAGS="$CFLAGS -D_ALL_SOURCE"
    ;;
  *-darwin*)
    CFLAGS="$CFLAGS -DDARWIN"
    LIBS="-framework DirectoryService $LIBS"
    AC_DEFINE([__APPLE_USE_RFC_3542], 1, [Force OSX >= 10.7 Lion to use RFC2292 IPv6 socket options])
    ;;
esac

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
      openssl/crypto.h \
      openssl/err.h \
      openssl/evp.h \
      openssl/md5.h \
      openssl/md4.h \
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
  if test "x$ac_cv_header_pcap_h" = "xyes"; then
    AC_DEFINE(HAVE_LIBPCAP, 1, [Define to 1 if you have the `pcap' library (-lpcap) and header file <pcap.h>.])
    AC_SUBST(PCAP_LIBS)
    AC_SUBST(PCAP_LDFLAGS)
  else
    AC_MSG_WARN([pcap headers not found, silently disabling the RADIUS sniffer, and ARP listener. Use --with-pcap-include-dir=<path>.])
  fi
fi

dnl #
dnl # Check for collectd-client
dnl #
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

dnl #
dnl #  Check for the gperftools headers
dnl #
if test "x$WITH_GPERFTOOLS" != xyes || test "x$GPERFTOOLS_LIBS" = x; then
  AC_MSG_NOTICE([skipping test for google/profiler.h.])
else
  smart_try_dir="$gperftools_include_dir"
  FR_SMART_CHECK_INCLUDE([gperftools/profiler.h])
  if test "x$ac_cv_header_gperftools_profiler_h" = "xyes"; then
    AC_DEFINE(HAVE_GPERFTOOLS_PROFILER_H, 1, [Define to 1 if you have the <gperftools/profiler.h> header file.])
    AC_SUBST(GPERFTOOLS_LIBS)
    AC_SUBST(GPERFTOOLS_LDFLAGS)
  else
    AC_MSG_WARN([gperftools headers not found.  Use --with-gperftools-include-dir=<path>.])
  fi
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


dnl #
dnl #  Check for the gnumake headers
dnl #  Why is GNU make not smart enough to export a variable saying where the heck this is?
dnl #
FR_SMART_CHECK_INCLUDE([gnumake.h])
if test "x$ac_cv_header_gnumake_h" = "xyes"; then
  AC_DEFINE(HAVE_GNUMAKE_H, 1, [Define to 1 if you have the <gnumake.h> header file.])
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
  fchmodat \
  fchownat \
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
  localtime_r \
  mallopt \
  memrchr \
  mkdirat \
  openat \
  pthread_sigmask \
  recvmmsg \
  sendmmsg \
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

AC_TYPE_SIGNAL

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
    devcflags="$devcflags \
	-W \
	-Weverything \
	-Wformat=2 \
	-DWITH_VERIFY_PTR=1 \
	-Wno-disabled-macro-expansion \
	-Wno-missing-field-initializers \
	-Wno-date-time \
    	-Wno-padded \
    	-Wno-gnu-zero-variadic-macro-arguments \
    	-Wno-shorten-64-to-32 \
    	-Wno-sign-conversion \
    	-Wno-conversion \
    	-Wno-switch-enum \
    	-Wno-gnu-statement-expression \
    	-Wno-extended-offsetof \
    	-Wno-cast-align \
    	-Wno-documentation-unknown-command \
    	-Wno-covered-switch-default \
    	-Wno-packed \
    	-Wno-reserved-id-macro \
    	-Wno-format-pedantic"
  else
    if test "x$GCC" = "xyes"; then
      devcflags="$devcflags \
      	-Wshadow \
      	-Wpointer-arith \
      	-Wcast-qual \
      	-Wcast-align \
      	-Wwrite-strings \
      	-Wstrict-prototypes \
      	-Wmissing-prototypes \
      	-Wmissing-declarations \
      	-Wnested-externs \
      	-W \
      	-Wredundant-decls \
      	-Wundef \
      	-Wformat-y2k \
      	-Wno-missing-field-initializers \
      	-Wno-format-extra-args \
      	-Wno-format-zero-length \
      	-Wno-cast-align \
      	-Wformat-nonliteral \
      	-Wformat-security \
      	-Wformat=2 \
      	-DWITH_VERIFY_PTR=1"
      INSTALLSTRIP=""
    fi
  fi

  dnl #
  dnl #  Older versions of GCC don't support this, but 7 seems to
  dnl #
  AX_CC_IMPLICIT_FALLTHROUGH_FLAG
  if test "x$ax_cv_cc_wimplicit_fallthrough_flag" = "xyes"; then
    devcflags="$devcflags -Wimplicit-fallthrough"
  fi

  dnl #
  dnl #  If running with clang, add in ASAN
  dnl #
  if test "x$llvm_address_sanitizer" = "xyes" && test "x$ax_cv_cc_clang" = "xyes"; then
    dnl #
    dnl #  -fsanitize=address		- Build with address sanitizer support
    dnl #  -fno-omit-frame-pointer	- Always keep the frame pointer in a register
    dnl #  -fno-optimize-sibling-calls	- Don't optimize away tail recursion.
    dnl #
    devcflags="$devcflags -fsanitize=address -fno-omit-frame-pointer -fno-optimize-sibling-calls"

    AX_CC_SANITZE_ADDRESS_USE_AFTER_SCOPE_FLAG
    if test "x$ax_cv_cc_sanitize_address_use_after_scope" = "xyes"; then
      devcflags="$devcflags -fsanitize-address-use-after-scope"
    fi

    AC_CHECK_HEADERS(sanitizer/lsan_interface.h)

    devldflags="$devldflags -fsanitize=address"
  fi

  dnl #
  dnl #  If running with clang, add in UBSAN
  dnl #
  if test "x$llvm_undefined_behaviour_sanitizer" = "xyes" && test "x$ax_cv_cc_clang" = "xyes"; then
    dnl #
    dnl #  -fsanitize=undefined		- Build with ubsan support
    dnl #  -fno-omit-frame-pointer	- Always keep the frame pointer in a register
    dnl #
    devcflags="$devcflags -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
    devldflags="$devldflags -fno-sanitize-recover=undefined"
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
  CFLAGS="$CFLAGS -DTALLOC_GET_TYPE_ABORT_NOOP"
else
  AC_MSG_RESULT([no])
fi

export EXPERIMENTAL

dnl #
dnl #  check for some compiler features
dnl #
FR_TLS
AX_CC_BUILTIN_CHOOSE_EXPR
AX_CC_BUILTIN_TYPES_COMPATIBLE_P
AX_CC_BUILTIN_BSWAP64
AX_CC_BUILTIN_CLZLL

AX_CC_HAVE_C11_GENERIC
if test "x$ax_cv_cc_c11_generic" != "xyes"; then
  AC_MSG_ERROR([FreeRADIUS requires support for the C11 _Generic keyword])
fi

dnl #############################################################
dnl #
dnl #  7. Checks for library functions
dnl #
dnl #############################################################

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

dnl #
dnl # Check for libcrypt
dnl # We use crypt_r(3) which may be in libc, or in libcrypt (eg FreeBSD)
dnl #
AC_CHECK_LIB(crypt, crypt_r,
  CRYPTLIB_R="-lcrypt"
)

if test "$CRYPTLIB_R" != ""; then
  CRYPTLIB="${CRYPTLIB} ${CRYPTLIB_R}"
  AC_DEFINE(HAVE_CRYPT_R, [], [Do we have the crypt_r function])
else
  AC_CHECK_FUNC(crypt_r, AC_DEFINE(HAVE_CRYPT_R, [], [Do we have the crypt_r function]))
fi

dnl Check for libcipher
AC_CHECK_LIB(cipher, setkey,
   CRYPTLIB="${CRYPTLIB} -lcipher"
)
AC_SUBST(CRYPTLIB)

dnl #
dnl #  Check for libexecinfo support, on some systems this is built into libc
dnl #  on others it's a separate library.
dnl #

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
    AC_TRY_LINK(
      [
        #include <execinfo.h>
      ],
      [
        void *sym[1];
        backtrace_symbols(&sym, sizeof(sym)) ],
      [
        AC_MSG_RESULT(yes)
        ac_cv_lib_execinfo_backtrace_symbols="yes"
      ],
      [
        AC_MSG_RESULT(no)
      ]
    )
  fi

  if test "x$ac_cv_lib_execinfo_backtrace_symbols" = "xyes"; then
    AC_DEFINE(HAVE_EXECINFO, [1], [define this if we have <execinfo.h> and symbols])
  fi
fi

dnl #
dnl #  Check for regular expression support.
dnl #

dnl #
dnl #  First look for PCRE
dnl #
if test "x$WITH_REGEX" != "xno" && test "x$WITH_PCRE" != "xno"; then
  smart_try_dir=$pcre_include_dir

  dnl #
  dnl #  Prefer libpcre2 over libpcre
  dnl #
  FR_SMART_CHECK_INCLUDE(pcre2.h,[#define PCRE2_CODE_UNIT_WIDTH (8)])
  if test "x$ac_cv_header_pcre2_h" = "xyes"; then
    smart_try_dir=$pcre_lib_dir
     FR_SMART_CHECK_LIB(pcre2-8, pcre2_compile_8)
     if test "x$ac_cv_lib_pcre2_8_pcre2_compile_8" = "xyes"; then
       REGEX=yes
       AC_DEFINE(HAVE_REGEX_PCRE2, [1], [define this if we have libpcre2])
       AC_DEFINE(HAVE_BINSAFE_REGEX, 1, [Define if we have a binary safe regular expression library])
     fi
  fi

  dnl #
  dnl #  Fallback to libpcre
  dnl #
  if test "x$REGEX" != "xyes"; then
    FR_SMART_CHECK_INCLUDE(pcre.h)
    if test "x$ac_cv_header_pcre_h" = "xyes"; then
      smart_try_dir=$pcre_lib_dir
      FR_SMART_CHECK_LIB(pcre, pcre_compile)
      if test "x$ac_cv_lib_pcre_pcre_compile" = "xyes"; then
        AC_MSG_CHECKING([libpcre library and header version consistency])
          AC_RUN_IFELSE(
            [AC_LANG_PROGRAM(
              [[
                #include <stdio.h>
                #include <pcre.h>
                #include <stdlib.h>
                #define XSTRINGIFY(x) #x
                #define STRINGIFY(x) XSTRINGIFY(x)
              ]],
              [[
                char const *p = pcre_version();
                char *q;
                unsigned long ver;

                printf("library: %s header: %u.%u %s... ", p, PCRE_MAJOR, PCRE_MINOR, STRINGIFY(PCRE_DATE));

                ver = strtoul(p, &q, 10);
                if (*q != '.') return 1;
                if (ver != PCRE_MAJOR) return 65;
                p = ++q;

                ver = strtoul(p, &q, 10);
                if (ver != PCRE_MINOR) return 1;
              ]]
            )],
            [
               AC_MSG_RESULT(yes)
               REGEX=yes
               AC_DEFINE(HAVE_REGEX_PCRE, [1], [define this if we have libpcre])
               AC_DEFINE(HAVE_BINSAFE_REGEX, 1, [Define if we have a binary safe regular expression library])
            ],
            [
               AC_MSG_RESULT(no)
               AC_MSG_FAILURE([libpcre library version does not match header version])
            ],
            [
               AC_MSG_RESULT([cross-compiling (assuming yes)])
            ]
          )
      fi
    fi
  fi
fi

dnl #
dnl #  If no PCRE, fallback to POSIX regular expressions
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
    AC_DEFINE(HAVE_REGEX_POSIX, [1], [define this if we have POSIX regular expressions])
  fi
fi

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
case "$target" in
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
  AC_TRY_LINK(
    [
      #include <stdio.h>
      #include <netdb.h>
    ],
    [ gethostbyaddr_r(NULL, 0, 0, NULL, NULL, 0, NULL, NULL) ],
    [
      AC_DEFINE(GETHOSTBYADDRRSTYLE, GNUSTYLE, [style of gethostbyaddr_r functions ])
      gethostbyaddrrstyle=GNU
    ]
  )
fi

if test "x$gethostbyaddrrstyle" = "x"; then
  AC_TRY_LINK(
    [
      #include <stdio.h>
      #include <netdb.h>
    ],
    [ gethostbyaddr_r(NULL, 0, 0, NULL, NULL, 0, NULL) ] ,
    [
      AC_DEFINE(GETHOSTBYADDRRSTYLE, SYSVSTYLE, [style of gethostbyaddr_r functions ])
      gethostbyaddrrstyle=SYSV
    ]
  )
fi


if test "x$gethostbyaddrrstyle" = "x"; then
  AC_TRY_LINK(
    [
      #include <stdio.h>
      #include <netdb.h>
    ],
    [ gethostbyaddr(NULL, 0, 0)  ],
    [
      AC_DEFINE(GETHOSTBYADDRRSTYLE, BSDSTYLE, [style of gethostbyaddr_r functions ])
      gethostbyaddrrstyle=BSD
    ]
  )
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
AC_TRY_LINK(
  [
    #include <stdio.h>
    #include <netdb.h>
  ],
  [ gethostbyname_r(NULL, NULL, NULL, 0, NULL, NULL) ],
  [
    AC_DEFINE(GETHOSTBYNAMERSTYLE, GNUSTYLE, [style of gethostbyname_r functions ])
    gethostbynamerstyle=GNU
  ]
)

if test "x$gethostbynamerstyle" = "x"; then
  AC_TRY_LINK(
    [
      #include <stdio.h>
      #include <netdb.h>
    ],
    [ gethostbyname_r(NULL, NULL, NULL, 0, NULL) ] ,
    [
      AC_DEFINE(GETHOSTBYNAMERSTYLE, SYSVSTYLE, [style of gethostbyname_r functions ])
      gethostbynamerstyle=SYSV
    ]
  )
fi

if test "x$gethostbynamerstyle" = "x"; then
  AC_TRY_LINK(
    [
      #include <stdio.h>
      #include <netdb.h>
    ],
    [ gethostbyname(NULL) ],
    [
      AC_DEFINE(GETHOSTBYNAMERSTYLE, BSDSTYLE, [style of gethostbyname_r functions ])
      gethostbynamerstyle=BSD
    ]
  )
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
  AC_TRY_LINK(
    [
      #include <stdlib.h>
      #include <sys/types.h>
      #include <pwd.h>
    ],
    [ getpwnam_r(NULL, NULL, NULL, 0, NULL) ],
    [
      AC_MSG_RESULT([yes])
      AC_DEFINE(HAVE_GETPWNAM_R, 1,
                [Define to 1 if you have the getpwnam_r.]
                )
    ],
    [
        AC_MSG_RESULT(no)
    ]
  )
fi

if test "x$ac_cv_header_grp_h" = "xyes"; then
  AC_MSG_CHECKING([getgrnam_r])
  AC_TRY_LINK(
    [
      #include <stdlib.h>
      #include <sys/types.h>
      #include <grp.h>
    ],
    [ getgrnam_r(NULL, NULL, NULL, 0, NULL) ],
    [
      AC_MSG_RESULT([yes])
      AC_DEFINE(HAVE_GETGRNAM_R, 1,
                [Define to 1 if you have the getgrnam_r.]
                )
    ],
    [
        AC_MSG_RESULT(no)
    ]
  )
fi


dnl #
dnl #  Check for non-posix solaris ctime_r (extra buflen int arg)
dnl #
AC_DEFINE(POSIXSTYLE, [1], [Posix-Style ctime_r])
AC_DEFINE(SOLARISSTYLE, [2], [Solaris-Style ctime_r])
ctimerstyle=""
AC_MSG_CHECKING([ctime_r() syntax])
AC_TRY_LINK(
  [
    #include <time.h>
  ],
  [ ctime_r(NULL, NULL, 0) ],
  [
    AC_DEFINE(CTIMERSTYLE, SOLARISSTYLE, [style of ctime_r function])
    ctimerstyle="SOLARIS"
  ]
)

if test "x$ctimerstyle" = "x"; then
  AC_TRY_LINK(
    [
      #include <time.h>
    ],
    [ ctime_r(NULL, NULL) ],
    [
      AC_DEFINE(CTIMERSTYLE, POSIXSTYLE, [style of ctime_r function])
      ctimerstyle="POSIX"
    ]
  )
fi

if test "x$ctimerstyle" = "x"; then
    AC_MSG_RESULT([none!  It must not exist, here.])
else
    AC_MSG_RESULT([${ctimerstyle}-style])
fi

AC_DEFINE_UNQUOTED(HOSTINFO, ["${host}"], [Architecture information for the target platform])

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
  for foo in `ls -1 "${srcdir}"/src/modules/rlm_eap/types/ | grep rlm_`; do
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

dnl ############################################################
dnl #  Find any support libraries we need to build
dnl #############################################################
for foo in `find "${srcdir}"/src/lib/ -type f -name configure`; do
  mysubdirs="$mysubdirs $(dirname $foo)"
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
AC_CONFIG_COMMANDS([main-chmod], [(cd ./src/bin && chmod +x checkrad radlast radtest)])
AC_CONFIG_COMMANDS([scripts-chmod], [(cd ./scripts && chmod +x rc.radiusd cron/radiusd.cron.daily cron/radiusd.cron.monthly cryptpasswd)])

dnl #
dnl #  Substitute whatever libraries we found to be necessary
dnl #
AC_SUBST(LIBS)
AC_SUBST(INSTALLSTRIP)

AC_OUTPUT(\
  ./Make.inc \
  ./src/include/build-radpaths-h \
  ./src/bin/checkrad \
  ./src/bin/radlast \
  ./src/bin/radtest \
  ./scripts/rc.radiusd \
  ./scripts/cron/radiusd.cron.daily \
  ./scripts/cron/radiusd.cron.monthly \
  ./scripts/cryptpasswd \
  ./raddb/radrelay.conf \
  ./raddb/radiusd.conf
)
