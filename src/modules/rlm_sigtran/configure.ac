AC_PREREQ([2.61])
AC_INIT(rlm_sigtran.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_sigtran])

AC_ARG_WITH([]modname,
[AS_HELP_STRING([--without-[]modname],[build without module])]
)

fail=
SMART_LIBS=
SMART_CLFAGS=
if test x$with_[]modname != xno; then
    dnl ############################################################
    dnl # Check for command line options
    dnl ############################################################

    dnl extra argument: --with-sigtran-include-dir=DIR
    sigtran_include_dir=
    AC_ARG_WITH(sigtran-include-dir,
	[AS_HELP_STRING([--with-sigtran-include-dir=DIR],
		[Directory where osmocore and osmosccp may be found])],
	[case "$withval" in
	    no)
		AC_MSG_ERROR(Need sigtran-lib-dir)
		;;
	    yes)
		;;
	    *)
		sigtran_lib_dir="$withval"
		;;
	esac])

    dnl extra argument: --with-sigtran-dir=DIR
    AC_ARG_WITH(sigtran-dir,
	[AS_HELP_STRING([--with-sigtran-dir=DIR],
		[Base directory where osmocore and osmosccp are installed])],
	[case "$withval" in
	    no)
		AC_MSG_ERROR(Need sigtran-dir)
		;;
	    yes)
		;;
	    *)
		sigtran_lib_dir="$withval/lib"
		sigtran_include_dir="$withval/include"
		;;
	esac])

    dnl ############################################################
    dnl # Check for programs
    dnl ############################################################

    AC_PROG_CC

    dnl ############################################################
    dnl # Check for header files
    dnl ############################################################

    FR_SMART_PKGCONFIG_INCLUDE([libosmocore], "${sigtran_include_dir}")
    FR_SMART_CHECK_INCLUDE([osmocom/core/msgb.h])
    if test "x$ac_cv_header_osmocom_core_msgb_h" != "xyes"; then
      AC_MSG_WARN([libosmocomcore headers not found. Use --with-sigtran-include-dir=<path>.])
      fail="$fail osmocom/core/msgb.h"
    fi

    FR_SMART_PKGCONFIG_INCLUDE([libosmo-sccp], "${sigtran_include_dir}")
    old_cflags="$CFLAGS"
    CFLAGS="${CFLAGS} -include stdint.h -include osmocom/core/linuxlist.h"
    FR_SMART_CHECK_INCLUDE([osmocom/sccp/sccp.h])
    if test "x$ac_cv_header_osmocom_sccp_sccp_h" != "xyes"; then
      AC_MSG_WARN([libosmocom-sccp headers not found. Use --with-sigtran-include-dir=<path>.])
      fail="$fail osmocom/sccp/sccp.h"
    fi
    CFLAGS="$old_cflags"

    dnl ############################################################
    dnl # Check for libraries
    dnl ############################################################

    FR_SMART_PKGCONFIG_LIB([libosmocore], "${sigtran_lib_dir}")
    FR_SMART_CHECK_LIB([osmocore], msgb_alloc)
    if test "x$ac_cv_lib_osmocore_msgb_alloc" != "xyes"
    then
      AC_MSG_WARN([libosmocore libraries not found. Use --with-sigtran-lib-dir=<path>.])
      fail="$fail libosmocore"
    fi

    FR_SMART_PKGCONFIG_LIB([libosmo-sccp], "${sigtran_lib_dir}")
    FR_SMART_CHECK_LIB([osmo-sccp], sccp_connection_connect)
    if test "x$ac_cv_lib_sccp_sccp_connection_connect" != "xyes" -a "x$ac_cv_lib_osmo_sccp_sccp_connection_connect" != "xyes"
    then
      AC_MSG_WARN([libsccp libraries not found. Use --with-sigtran-lib-dir=<path>.])
      fail="$fail lib$NAMESCCP"
    fi

    FR_SMART_PKGCONFIG_LIB([libosmo-xua], "${sigtran_lib_dir}")
    FR_SMART_CHECK_LIB([osmo-xua], xua_msg_alloc)
    if test "x$ac_cv_lib_xua_xua_msg_alloc" != "xyes" -a "x$ac_cv_lib_osmo_xua_xua_msg_alloc" != "xyes"
    then
      AC_MSG_WARN([libxua libraries not found. Use --with-sigtran-lib-dir=<path>.])
      fail="$fail lib$NAMEXUA"
    fi

    FR_SMART_PKGCONFIG_LIB([libosmo-mtp], "${sigtran_lib_dir}")
    FR_SMART_CHECK_LIB([osmo-mtp], mtp_pcap_write_header)
    if test "x$ac_cv_lib_mtp_mtp_pcap_write_header" != "xyes" -a "x$ac_cv_lib_osmo_mtp_mtp_pcap_write_header" != "xyes"
    then
      AC_MSG_WARN([libmtp libraries not found. Use --with-sigtran-lib-dir=<path>.])
      fail="$fail lib$NAMEMTP"
    fi
    targetname=modname
else
    targetname=
    echo \*\*\* module modname is disabled.
fi

dnl Don't change this section.
if test "x$fail" != x; then
	if test "x${enable_strict_dependencies}" = xyes; then
		AC_MSG_ERROR([set --without-]modname[ to disable it explicitly.])
	else
		AC_MSG_WARN([silently not building ]modname[.])
		AC_MSG_WARN([FAILURE: ]modname[ requires:$fail.]);
		targetname=
	fi
fi

mod_ldflags="$SMART_LIBS $(pkg-config --libs-only-other libosmocore) $(pkg-config --libs-only-other libosmo-sccp) $(pkg-config --libs-only-other libosmo-xua) $(pkg-config --libs-only-other libosmo-mtp) $(net-snmp-config --agent-libs 2>&-) -lsctp"
mod_cflags="$SMART_CPPFLAGS"
AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)
AC_SUBST(targetname)
AC_OUTPUT(all.mk)

