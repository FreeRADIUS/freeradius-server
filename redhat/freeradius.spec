%bcond_with rlm_yubikey
%bcond_with experimental_modules
%bcond_with rlm_sigtran
%bcond_with wbclient
%bcond_without ldap

# Many distributions have extremely old versions of OpenSSL
# if you'd like to build with the FreeRADIUS openssl packages
# which are installed in /opt/openssl you should pass
# _with_freeradius_openssl

%{!?_with_rlm_eap_pwd: %global _without_rlm_eap_pwd --without-rlm_eap_pwd}

%{!?_with_rlm_cache_memcached: %global _without_rlm_cache_memcached --without-rlm_cache_memcached}
%{!?_with_rlm_eap_pwd: %global _without_rlm_eap_pwd --without-rlm_eap_pwd}
%{!?_with_rlm_eap_tnc: %global _without_rlm_eap_tnc --without-rlm_eap_tnc}
%{!?_with_rlm_yubikey: %global _without_rlm_yubikey --without-rlm_yubikey}
%{!?_with_rlm_sigtran: %global _without_rlm_sigtran --without-rlm_sigtran}
%{?_without_ldap: %global _without_libfreeradius_ldap --without-libfreeradius-ldap}

# experimental modules
%bcond_with rlm_idn
%bcond_with rlm_mruby
%bcond_with rlm_sql_oracle
%{?_with_rlm_idn: %global _with_experimental_modules --with-experimental-modules}
%{?_with_rlm_opendirectory: %global _with_experimental_modules --with-experimental-modules}
%{?_with_rlm_mruby: %global _with_experimental_modules --with-experimental-modules}
%{?_with_rlm_securid: %global _with_experimental_modules --with-experimental-modules}
%{?_with_rlm_sql_oracle: %global _with_experimental_modules --with-experimental-modules}

%if %{?_with_experimental_modules:1}%{!?_with_experimental_modules:0}
%{!?_with_rlm_idn: %global _without_rlm_idn --without-rlm_idn}
%{!?_with_rlm_opendirectory: %global _without_rlm_opendirectory --without-rlm_opendirectory}
%{!?_with_rlm_mruby: %global _without_rlm_mruby --without-rlm_mruby}
%{!?_with_rlm_securid: %global _without_rlm_securid --without-rlm_securid}
%{!?_with_rlm_sql_oracle: %global _without_rlm_sql_oracle --without-rlm_sql_oracle}
%endif

Summary: High-performance and highly configurable free RADIUS server
Name: freeradius
Version: 4.0.0
Release: %{?_release}%{!?_release:1}%{?dist}
License: GPLv2+ and LGPLv2+
Group: System Environment/Daemons
URL: http://www.freeradius.org/

Source0: ftp://ftp.freeradius.org/pub/radius/freeradius-server-%{version}.tar.bz2

%if %{?_unitdir:1}%{!?_unitdir:0}
Source100: radiusd.service
Source104: freeradius-tmpfiles-conf
%else
Source100: freeradius-radiusd-init
%define initddir %{?_initddir:%{_initddir}}%{!?_initddir:%{_initrddir}}
%endif

Source102: freeradius-logrotate
Source103: freeradius-pam-conf

Obsoletes: freeradius-devel
Obsoletes: freeradius-libs
Obsoletes: freeradius < %{version}-%{release}%{?dist}

%define docdir %{_docdir}/freeradius-%{version}

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: autoconf
BuildRequires: gdbm-devel
%if %{?_with_freeradius_openssl:1}%{!?_with_freeradius_openssl:0}
BuildRequires: freeradius-openssl, freeradius-openssl-devel
%else
BuildRequires: openssl, openssl-devel
%endif

BuildRequires: libcap-devel
BuildRequires: libkqueue-devel
BuildRequires: libpcap-devel
BuildRequires: libtalloc-devel
BuildRequires: net-snmp-devel
BuildRequires: net-snmp-utils
%if %{?_with_wbclient:1}%{!?_with_wbclient:0}
%{?el7:BuildRequires: libwbclient-devel}
%{?el7:BuildRequires: samba-devel}
%endif
%if %{?_unitdir:1}%{!?_unitdir:0}
BuildRequires: systemd-devel
%endif
BuildRequires: pam-devel
BuildRequires: readline-devel
BuildRequires: zlib-devel

Requires(pre): shadow-utils glibc-common
Requires(post): /sbin/chkconfig /usr/sbin/setsebool
Requires(preun): /sbin/chkconfig
Requires: freeradius-config = %{version}-%{release}
%if %{?_with_freeradius_openssl:1}%{!?_with_freeradius_openssl:0}
Requires: freeradius-openssl
%else
# Need openssl-perl for c_rehash, which is used when
# generating certificates
Requires: openssl, openssl-perl
%endif

Requires: libcap
Requires: libkqueue
Requires: libpcap
Requires: libtalloc
Requires: net-snmp
Requires: readline
%if %{?_with_wbclient:1}%{!?_with_wbclient:0}
%{?el7:Requires: libwbclient}
%endif
Requires: zlib
Requires: pam

%if %{?_with_rlm_idn:1}%{?!_with_rlm_idn:0}
Requires: libidn
BuildRequires: libidn-devel
%endif

%description
The FreeRADIUS Server Project is a high performance and highly configurable
GPL'd free RADIUS server. The server is similar in some respects to
Livingston's 2.0 server.  While FreeRADIUS started as a variant of the
Cistron RADIUS server, they don't share a lot in common any more. It now has
many more features than Cistron or Livingston, and is much more configurable.

FreeRADIUS is an Internet authentication daemon, which implements the RADIUS
protocol, as defined in RFC 2865 (and others). It allows Network Access
Servers (NAS boxes) to perform authentication for dial-up users. There are
also RADIUS clients available for Web servers, firewalls, Unix logins, and
more.  Using RADIUS allows authentication and authorization for a network to
be centralized, and minimizes the amount of re-configuration which has to be
done when adding or deleting new users.

%if %{?_with_rlm_cache_memcached:1}%{?!_with_rlm_cache_memcached:0}
%package memcached
Summary: Memcached support for freeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: libmemcached
BuildRequires: libmemcached-devel

%description memcached
Adds support for rlm_memcached as a cache driver.
%endif

%package config
Group: System Environment/Daemons
Summary: FreeRADIUS config files
Provides: freeradius-config
Requires: make

%description config
FreeRADIUS default config files
This package should be used as a base for a site local package
to configure the FreeRADIUS server.

%package utils
Group: System Environment/Daemons
Summary: FreeRADIUS utilities
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: libpcap >= 0.9.4

%description utils
The FreeRADIUS server has a number of features found in other servers,
and additional features not found in any other server. Rather than
doing a feature by feature comparison, we will simply list the features
of the server, and let you decide if they satisfy your needs.

Support for RFC and VSA Attributes Additional server configuration
attributes Selecting a particular configuration Authentication methods

%package perl-util
Group: System Environment/Daemons
Summary: FreeRADIUS Perl utilities
Requires: perl-Net-IP

%description perl-util
This package provides Perl utilities for managing IP pools stored in
SQL databases.

%package json
Summary: JSON support for FreeRADIUS
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: freeradius-libfreeradius-json = %{version}-%{release}

%description json
This plugin provides JSON tree mapping, and JSON string escaping for the FreeRADIUS server project.

%package krb5
Summary: Kerberos 5 support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: krb5-libs
BuildRequires: krb5-devel

%description krb5
This plugin provides Kerberos 5 support for the FreeRADIUS server project.

%if %{!?_without_ldap:1}%{?_without_ldap:0}
%package ldap
Summary: LDAP support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: openldap-ltb
BuildRequires: openldap-ltb

%description ldap
This plugin provides LDAP support for the FreeRADIUS server project.
%endif

%package libfreeradius-curl
Summary: curl wrapper library for FreeRADIUS
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: freeradius-libfreeradius-util = %{version}-%{release}
Requires: libcurl >= 7.24.0
BuildRequires: libcurl-devel >= 7.24.0

%description libfreeradius-curl
Integrates libcurl with FreeRADIUS' internal event loop.

%package libfreeradius-util
Summary: Utility library used by all other FreeRADIUS libraries

%description libfreeradius-util
Provides common functions used by other FreeRADIUS libraries and modules.

%package libfreeradius-radius
Summary: RADIUS protocol library for FreeRADIUS
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: freeradius-libfreeradius-util = %{version}-%{release}

%description libfreeradius-radius
Provides protocol encoders and decoders for the RADIUS protocol.

%package libfreeradius-json
Summary: Internal support library for FreeRADIUS modules using json-c
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: json-c >= 0.13
BuildRequires: json-c-devel >= 0.13

%description libfreeradius-json
Internal support library for FreeRADIUS modules using json-c, required by all modules that use json-c.

%package libfreeradius-redis
Summary: Internal support library for FreeRADIUS modules using hiredis
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: hiredis >= 0.10
BuildRequires: hiredis-devel >= 0.10

%description libfreeradius-redis
Internal support library for FreeRADIUS modules using hiredis, required by all modules that use hiredis.

%package perl
Summary: Perl support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
%{?fedora:BuildRequires: perl-devel}
%if 0%{?rhel} <= 5
BuildRequires: perl
%endif
%if 0%{?rhel} >= 6
BuildRequires: perl-devel
%endif
BuildRequires: perl(ExtUtils::Embed)

%description perl
This plugin provides Perl support for the FreeRADIUS server project.

%package python
Summary: Python support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: python3
BuildRequires: python3-devel

%description python
This plugin provides Python support for the FreeRADIUS server project.

%package mysql
Summary: MySQL support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: mysql
BuildRequires: mysql-devel

%description mysql
This plugin provides MySQL support for the FreeRADIUS server project.

%package postgresql
Summary: PostgreSQL support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: postgresql
BuildRequires: postgresql-devel

%description postgresql
This plugin provides PostgreSQL support for the FreeRADIUS server project.

%package sqlite
Summary: SQLite support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: sqlite
BuildRequires: sqlite-devel

%description sqlite
This plugin provides SQLite support for the FreeRADIUS server project.

%package unixODBC
Summary: unixODBC support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: unixODBC
BuildRequires: unixODBC-devel

%description unixODBC
This plugin provides unixODBC support for the FreeRADIUS server project.

%package freetds
Summary: FreeTDS support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: freetds
BuildRequires: freetds-devel

%description freetds
This plugin provides FreeTDS support for the FreeRADIUS server project.

%if %{?_with_rlm_sql_oracle:1}%{!?_with_rlm_sql_oracle:0}
%package oracle
Summary: Oracle support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: oracle-instantclient11.2
BuildRequires: oracle-instantclient11.2-devel

%description oracle
This plugin provides Oracle support for the FreeRADIUS server project.

%ifarch x86_64
%global oracle_include_dir /usr/include/oracle/11.2/client64
%global oracle_lib_dir %{_prefix}/lib/oracle/11.2/client64/lib
%endif
%ifarch i386
%global oracle_include_dir /usr/include/oracle/11.2/client
%global oracle_lib_dir %{_prefix}/lib/oracle/11.2/client/lib
%endif
%endif

%package redis
Summary: Redis support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: freeradius-libfreeradius-redis = %{version}

%description redis
This plugin provides Redis support for the FreeRADIUS server project.

%package rest
Summary: REST support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: freeradius-libfreeradius-json = %{version}
Requires: freeradius-libfreeradius-curl = %{version}

%description rest
This plugin provides the ability to interact with REST APIs for the FreeRADIUS server project.

%if %{?_with_rlm_mruby:1}%{!?_with_rlm_mruby:0}
%package ruby
Summary: Ruby support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: ruby
BuildRequires: ruby ruby-devel

%description ruby
This plugin provides Ruby support for the FreeRADIUS server project.
%endif

%if %{?_with_rlm_sigtran:1}%{!?_with_rlm_sigtran:0}
%package sigtran
Summary: Sigtran support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: libosmo-sccp, libosmo-xua, libosmo-mtp, libosmocore
BuildRequires: libosmo-sccp-devel, libosmo-xua-devel, libosmo-mtp-devel, libosmocore-devel

%description sigtran
This plugin provides an experimental M3UA/SCCP/TCAP/MAP stack for the FreeRADIUS server project.
%endif

%if %{?_with_rlm_yubikey:1}%{!?_with_rlm_yubikey:0}
%package yubikey
Summary: YubiCloud support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: ykclient >= 2.10
BuildRequires: ykclient-devel >= 2.10

%description yubikey
This plugin provides YubiCloud support for the FreeRADIUS server project.
%endif

# CentOS defines debug package by default. Only define it if not already defined
# This apparently needs to come _after_ all the package definitions
%if 0%{!?_enable_debug_packages:1}
%debug_package
%endif

# Disable _debugsource_packages.  If you're installing the debuginfo you probably want the source files
# otherwise they're pretty much useless.
#
# Disable _debuginfo_subpackage.  They don't work. rpbuild doesn't split out the debug info for the files
# into the subpackages.  It also doesn't split out the source files.
%if 0%{?fedora} >= 27
%undefine _debugsource_packages
%undefine _debuginfo_subpackages
%endif
%if 0%{?rhel} >= 8
%undefine _debugsource_packages
%undefine _debuginfo_subpackages
%endif

%prep
%setup -q -n freeradius-server-%{version}
# Some source files mistakenly have execute permissions set
find $RPM_BUILD_DIR/freeradius-server-%{version} \( -name '*.c' -o -name '*.h' \) -a -perm /0111 -exec chmod a-x {} +

%build
# Retain CFLAGS from the environment...
%if %{?_with_developer:1}%{!?_with_developer:0}
export CFLAGS="$CFLAGS -g3 -fpic"
export CXXFLAGS="$CFLAGS"
%endif

# The build system seems to feed the compiler relative paths for the source files.  This is usually fine
# but it means the source paths in the ELF headers of the binaries are also relative.
#
# As a post install step a helper script (find-debuginfo.sh) is called to create the debug info files and
# perform stripping on the original binaries.
#
# find-debuginfo.sh calls another utility (debugedit) to rewrite the source paths in the ELF headers of
# the binaries so they'll match where the source files will actually be installed.
#
# find-debuginfo.sh assumes that the paths in the ELF headers will be '$RPM_BUILD_DIR/src', but because the
# compiler only gets relative paths, they end up being 'src/'.
#
# Unfortunately another helper utility (check-buildroot) gets excited when it finds $RPM_BUILD_ROOT in the
# any binaries due to be installed, and as debugedit doesn't do a perfect job of correcting the paths
# and we record the CFLAGS freeradius was built with, it fires and fails the build if we try to rewrite
# the paths to $RPM_BUILD_ROOT/src/.
#
# The only remaining option is to rewrite the paths at the compiler level, to what debugedit would have
# used, so we do that below.
#
# This flag has only been supported since clang10 and gcc8, so ensure a recent compiler is being used.
export CFLAGS="$CFLAGS -ffile-prefix-map=src/=%{_usrsrc}/debug/%{name}-%{version}-%{release}.%{_arch}/src/"

# Need to pass these explicitly for clang, else rpmbuilder bails when trying to extract debug info from
# the libraries.  Guessing GCC does this by default.  Why use clang over gcc? The version of clang
# which ships with RHEL 6 has basic C11 support, gcc doesn't.
export LDFLAGS="-Wl,--build-id"

# Pass in the release number, which was passed to us by whatever called rpmbuild
%if %{?_release:1}%{!?_release:0}
export RADIUSD_VERSION_RELEASE="%{release}"
%endif

%configure \
        --libdir=%{_libdir}/freeradius \
        --sysconfdir=%{_sysconfdir} \
        --disable-ltdl-install \
        --with-gnu-ld \
        --with-threads \
        --with-thread-pool \
        --with-docdir=%{docdir} \
%if %{!?_without_ldap:1}%{?_without_ldap:0}
        --with-libfreeradius-ldap-include-dir=/usr/local/openldap/include \
        --with-libfreeradius-ldap-lib-dir=/usr/local/openldap/lib64 \
%endif
        --with-rlm-sql_postgresql-include-dir=/usr/include/pgsql \
        --with-rlm-sql-postgresql-lib-dir=%{_libdir} \
        --with-rlm-sql_mysql-include-dir=/usr/include/mysql \
        --with-mysql-lib-dir=%{_libdir}/mysql \
        --with-unixodbc-lib-dir=%{_libdir} \
        --with-rlm-dbm-lib-dir=%{_libdir} \
        --with-rlm-krb5-include-dir=/usr/kerberos/include \
        --without-rlm_eap_ikev2 \
        --without-rlm_sql_firebird \
        --without-rlm_sql_db2 \
        --with-jsonc-lib-dir=%{_libdir} \
        --with-jsonc-include-dir=/usr/include/json \
        --with-winbind-include-dir=/usr/include/samba-4.0 \
        --with-winbind-lib-dir=/usr/lib64/samba \
%if %{?_with_freeradius_openssl:1}%{!?_with_freeradius_openssl:0}
        --with-openssl-lib-dir=/opt/openssl/lib \
        --with-openssl-include-dir=/opt/openssl/include \
%endif
%if %{?_with_developer:1}%{!?_with_developer:0}
        --enable-developer=yes \
        --with-gperftools \
%endif
%if %{?_with_address_sanitizer:1}%{!?_with_address_sanitizer:0}
        --enable-address-sanitizer \
%endif
%if %{?_with_leak_sanitizer:1}%{!?_with_leak_sanitizer:0}
        --enable-leak-sanitizer \
%endif
%if %{?_with_thread_sanitizer:1}%{!?_with_thread_sanitizer:0}
        --enable-thread-sanitizer \
%endif
%if %{?_with_undefined_behaviour_sanitizer:1}%{!?_with_undefined_behaviour_sanitizer:0}
        --enable-undefined-behaviour-sanitizer \
%endif
        %{?_with_rlm_yubikey} \
        %{?_without_rlm_yubikey} \
        %{?_with_rlm_sql_oracle} \
        %{?_with_rlm_sql_oracle: --with-oracle-include-dir=%{oracle_include_dir}} \
        %{?_with_rlm_sql_oracle: --with-oracle-lib-dir=%{oracle_lib_dir}} \
        %{?_without_rlm_sql_oracle} \
        %{?_with_experimental_modules} \
        %{?_without_experimental_modules} \
        %{?_without_rlm_eap_pwd} \
        %{?_without_rlm_eap_tnc} \
        %{?_with_rlm_idn} \
        %{?_without_rlm_idn} \
        %{?_with_rlm_opendirectory} \
        %{?_without_rlm_opendirectory} \
        %{?_with_rlm_securid} \
        %{?_without_rlm_securid} \
        %{?_with_rlm_sigtran} \
        %{?_without_rlm_sigtran} \
        %{?_with_rlm_mruby} \
        %{?_without_rlm_mruby} \
        %{?_with_rlm_cache_memcached} \
        %{?_without_rlm_cache_memcached} \
        %{?_without_libfreeradius_ldap} \
#        --with-modules="rlm_wimax" \

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/var/run/radiusd
mkdir -p $RPM_BUILD_ROOT/var/lib/radiusd
mkdir -p $RPM_BUILD_ROOT/%{docdir}
make install R=$RPM_BUILD_ROOT
# modify default configuration
RADDB=$RPM_BUILD_ROOT%{_sysconfdir}/raddb
perl -i -pe 's/^#user =.*$/user = radiusd/'   $RADDB/radiusd.conf
perl -i -pe 's/^#group =.*$/group = radiusd/' $RADDB/radiusd.conf
# logs
mkdir -p $RPM_BUILD_ROOT/var/log/radius/radacct
touch $RPM_BUILD_ROOT/var/log/radius/{radutmp,radius.log}

# For systemd based systems, that define _unitdir, install the radiusd unit
%if %{?_unitdir:1}%{!?_unitdir:0}
install -D -m 644 %{SOURCE100} $RPM_BUILD_ROOT/%{_unitdir}/radiusd.service
install -D -m 644 %{SOURCE104} $RPM_BUILD_ROOT/%{_prefix}/lib/tmpfiles.d/radiusd.conf
# For SystemV install the init script
%else
install -D -m 755 %{SOURCE100} $RPM_BUILD_ROOT/%{initddir}/radiusd
%endif

install -D -m 644 %{SOURCE102} $RPM_BUILD_ROOT/%{_sysconfdir}/logrotate.d/radiusd
install -D -m 644 %{SOURCE103} $RPM_BUILD_ROOT/%{_sysconfdir}/pam.d/radiusd

# remove unneeded stuff
rm -rf doc/00-OLD
rm -f $RPM_BUILD_ROOT/usr/sbin/rc.radiusd
rm -rf $RPM_BUILD_ROOT/%{_libdir}/freeradius/*.a
rm -rf $RPM_BUILD_ROOT/%{_libdir}/freeradius/*.la
%if %{?_with_rlm_idn:0}%{!?_with_rlm_idn:1}
rm -f $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-available/idn
%endif
%if %{?_with_rlm_mruby:0}%{!?_with_rlm_mruby:1}
rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/ruby
%endif
%if %{?_with_rlm_sql_oracle:0}%{!?_with_rlm_sql_oracle:1}
rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/sql/ippool/oracle
rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/sql/main/oracle
%endif
%if %{?_with_rlm_unbound:0}%{!?_with_rlm_unbound:1}
rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/unbound
%endif
rm -rf $RPM_BUILD_ROOT/%{_libdir}/freeradius/rlm_test.so

# remove header files, we don't ship a devel package and the
# headers have multilib conflicts
rm -rf $RPM_BUILD_ROOT/%{_includedir}

# remove unsupported config files
rm -f $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/experimental.conf

# install doc files omitted by standard install
for f in COPYRIGHT CREDITS; do
    cp $f $RPM_BUILD_ROOT/%{docdir}
done
cp LICENSE $RPM_BUILD_ROOT/%{docdir}/LICENSE.gpl
cp src/LICENSE.openssl $RPM_BUILD_ROOT/%{docdir}/LICENSE.openssl

# add Red Hat specific documentation
cat >> $RPM_BUILD_ROOT/%{docdir}/REDHAT << EOF

Red Hat, RHEL, Fedora, and CentOS specific information can be found on the
FreeRADIUS Wiki in the Red Hat FAQ.

http://wiki.freeradius.org/guide/Red_Hat_FAQ

Please reference that document.

EOF

%clean
rm -rf $RPM_BUILD_ROOT


# Make sure our user/group is present prior to any package or subpackage installation
%pre
getent group  radiusd >/dev/null || /usr/sbin/groupadd -r -g 95 radiusd
getent passwd radiusd >/dev/null || /usr/sbin/useradd  -r -g radiusd -u 95 -c "radiusd user" -s /sbin/nologin radiusd > /dev/null 2>&1
exit 0

# Make sure our user/group is present prior to any package or subpackage installation
%pre config
getent group  radiusd >/dev/null || /usr/sbin/groupadd -r -g 95 radiusd
getent passwd radiusd >/dev/null || /usr/sbin/useradd  -r -g radiusd -u 95 -c "radiusd user" -s /sbin/nologin radiusd > /dev/null 2>&1
exit 0


%post
if [ $1 = 1 ]; then
  /usr/sbin/setsebool -P radius_use_jit=1 &> /dev/null || :
%if %{?_unitdir:1}%{!?_unitdir:0}
  /bin/systemctl enable radiusd
%else
  /sbin/chkconfig --add radiusd
%endif
fi

%post config
if [ $1 = 1 ]; then
  if [ ! -e %{_sysconfdir}/raddb/certs/server.pem ]; then
    /sbin/runuser -g radiusd -c 'umask 007; %{_sysconfdir}/raddb/certs/bootstrap' > /dev/null 2>&1 || :
  fi
fi


%preun
if [ $1 = 0 ]; then
%if %{?_unitdir:1}%{!?_unitdir:0}
  /bin/systemctl disable radiusd
%else
  /sbin/chkconfig --del radiusd
%endif
fi


%postun
if [ $1 -ge 1 ]; then
  /sbin/service radiusd condrestart >/dev/null 2>&1 || :
fi


%files
%defattr(-,root,root)
%doc %{docdir}/
%config(noreplace) %{_sysconfdir}/pam.d/radiusd
%config(noreplace) %{_sysconfdir}/logrotate.d/radiusd

%if %{?_unitdir:1}%{!?_unitdir:0}
%{_unitdir}/radiusd.service
%config(noreplace) %{_prefix}/lib/tmpfiles.d/radiusd.conf
%else
%{initddir}/radiusd
%endif

%dir %attr(755,radiusd,radiusd) /var/lib/radiusd
%dir %attr(755,radiusd,radiusd) /var/run/radiusd/
# binaries
%defattr(-,root,root)
/usr/sbin/checkrad
/usr/sbin/raddebug
/usr/sbin/radiusd
/usr/sbin/radmin
# man-pages
%doc %{_mandir}/man1/smbencrypt.1.gz
%doc %{_mandir}/man5/checkrad.5.gz
%doc %{_mandir}/man5/clients.conf.5.gz
%doc %{_mandir}/man5/dictionary.5.gz
%doc %{_mandir}/man5/radiusd.conf.5.gz
%doc %{_mandir}/man5/unlang.5.gz
%doc %{_mandir}/man5/users.5.gz
%doc %{_mandir}/man8/radcrypt.8.gz
%doc %{_mandir}/man8/raddebug.8.gz
%doc %{_mandir}/man8/radmin.8.gz
%doc %{_mandir}/man8/radiusd.8.gz
# dictionaries
%dir %attr(755,root,root) /usr/share/freeradius
/usr/share/freeradius/*
# logs
%dir %attr(700,radiusd,radiusd) /var/log/radius/
%dir %attr(700,radiusd,radiusd) /var/log/radius/radacct/
%ghost %attr(644,radiusd,radiusd) /var/log/radius/radutmp
%ghost %attr(600,radiusd,radiusd) /var/log/radius/radius.log
# RADIUS shared libs
%attr(755,root,root) %{_libdir}/freeradius/lib*.so*
# RADIUS Loadable Modules
%dir %attr(755,root,root) %{_libdir}/freeradius
%{_libdir}/freeradius/*.so


%{?_with_rlm_idn: %{_libdir}/freeradius/rlm_idn.so}
%if %{?_with_experimental_modules:1}%{!?_with_experimental_modules:0}
%endif

%files config
%dir %attr(755,root,radiusd) %{_sysconfdir}/raddb
%defattr(-,root,radiusd)
%attr(644,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/dictionary
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/clients.conf
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/panic.gdb
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/radiusd.conf
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/trigger.conf
%config(noreplace) %{_sysconfdir}/raddb/users
%dir %attr(770,root,radiusd) %{_sysconfdir}/raddb/certs
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/certs/*
%attr(755,root,radiusd) %{_sysconfdir}/raddb/certs/bootstrap
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/sites-available
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/sites-available/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/sites-enabled
%config(noreplace) %{_sysconfdir}/raddb/sites-enabled/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/policy.d
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/policy.d/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/template.d
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/template.d/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-available
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-available/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/attr_filter
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/attr_filter/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/csv
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/csv/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/files
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/files/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/isc_dhcp
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/isc_dhcp/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/lua
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/lua/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/perl
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/perl/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/python
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/python/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-enabled
%config(noreplace) %{_sysconfdir}/raddb/mods-enabled/*
# ruby
%if %{?_with_rlm_mruby:1}%{!?_with_rlm_mruby:0}
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/ruby
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/ruby/*
%endif

#
#  SQL Databases - generic
#
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/counter
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/cui
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/driver
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/ippool
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/main

#
#  MySQL/MariaDB
#
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/driver/mysql
%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/main/mysql
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/main/mysql/*

%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/counter/mysql
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/counter/mysql/*
%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/cui/mysql
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/cui/mysql/*
%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/ippool/mysql
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/ippool/mysql/*

#
#  NDB
#
%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/main/ndb
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/main/ndb/*

#
#  PostgreSQL
#
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/driver/postgresql
%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/main/postgresql
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/main/postgresql/*

%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/counter/postgresql
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/counter/postgresql/*
%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/cui/postgresql
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/cui/postgresql/*
%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/ippool/postgresql
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/ippool/postgresql/*

#
#  SQLite
#
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/driver/sqlite
%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/main/sqlite
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/main/sqlite/*

%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/counter/sqlite
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/counter/sqlite/*
%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/cui/sqlite
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/cui/sqlite/*
%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/ippool/sqlite
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/ippool/sqlite/*

#
#  Cassandra
#
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/driver/cassandra
%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/main/cassandra
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/main/cassandra/*

#
#  MS-SQL (Sybase / FreeTDS)
#
%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/main/mssql
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/main/mssql/*

%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/ippool/mssql
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/ippool/mssql/*

#
#  Oracle
#
%if %{?_with_rlm_sql_oracle:1}%{!?_with_rlm_sql_oracle:0}
%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/main/oracle
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/main/oracle/*

%dir %attr(750,root,radiusd)			%{_sysconfdir}/raddb/mods-config/sql/ippool/oracle
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/ippool/oracle/*
%endif

%files utils
%exclude /usr/bin/*_tests
%exclude /usr/bin/unit_test_*
%defattr(-,root,root)
/usr/bin/dhcpclient
/usr/bin/radclient
/usr/bin/radcrypt
/usr/bin/radict
/usr/bin/radlast
/usr/bin/radlock
/usr/bin/radsniff
/usr/bin/radsnmp
/usr/bin/radsqlrelay
/usr/bin/radtest
/usr/bin/radwho
/usr/bin/radzap
/usr/bin/smbencrypt
# man-pages
%doc %{_mandir}/man1/dhcpclient.1.gz
%doc %{_mandir}/man1/radclient.1.gz
%doc %{_mandir}/man1/radlast.1.gz
%doc %{_mandir}/man1/radtest.1.gz
%doc %{_mandir}/man1/radwho.1.gz
%doc %{_mandir}/man1/radzap.1.gz
%doc %{_mandir}/man8/radsniff.8.gz
%doc %{_mandir}/man8/radsqlrelay.8.gz

%files perl-util
%defattr(-,root,root)
/usr/bin/rlm_sqlippool_tool
#man-pages
%doc %{_mandir}/man8/rlm_sqlippool_tool.8.gz

%files json
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_json.so

%files libfreeradius-curl
%defattr(-,root,root)
%{_libdir}/freeradius/libfreeradius-curl.so

%files libfreeradius-util
%defattr(-,root,root)
%{_libdir}/freeradius/libfreeradius-util.so

%files libfreeradius-radius
%defattr(-,root,root)
%{_libdir}/freeradius/libfreeradius-radius.so

%files libfreeradius-json
%defattr(-,root,root)
%{_libdir}/freeradius/libfreeradius-json.so

%files libfreeradius-redis
%defattr(-,root,root)
%{_libdir}/freeradius/libfreeradius-redis.so

%if %{?_with_rlm_cache_memcached:1}%{!?_with_rlm_cache_memcached:0}
%files memcached
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_cache_memcached.so
%endif

%files krb5
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_krb5.so

%files perl
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_perl.so

%files python
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_python.so

%files mysql
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sql_mysql.so

%files postgresql
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sql_postgresql.so

%files sqlite
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sql_sqlite.so

%if %{!?_without_ldap:1}%{?_without_ldap:0}
%files ldap
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_ldap.so
%endif

%files unixODBC
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sql_unixodbc.so

%files redis
%defattr(-,root,root)
/usr/bin/rlm_redis_ippool_tool
%{_libdir}/freeradius/rlm_redis.so
%{_libdir}/freeradius/rlm_rediswho.so
%{_libdir}/freeradius/rlm_cache_redis.so
%{_libdir}/freeradius/rlm_redis_ippool.so
%doc %{_mandir}/man8/rlm_redis_ippool_tool.8.gz

%files rest
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_rest.so

%if %{?_with_rlm_sigtran:1}%{!?_with_rlm_sigtran:0}
%files sigtran
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sigtran.so
%endif

%if %{?_with_rlm_mruby:1}%{!?_with_rlm_mruby:0}
%files ruby
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_mruby.so
%endif

%files freetds
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sql_freetds.so

%if %{?_with_rlm_sql_oracle:1}%{!?_with_rlm_sql_oracle:0}
%files oracle
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sql_oracle.so
%endif

%if %{?_with_rlm_yubikey:1}%{!?_with_rlm_yubikey:0}
%files yubikey
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_yubikey.so
%endif


%changelog
* Wed Sep 25 2013 Alan DeKok <aland@freeradius.org> - 3.0.0
- upgrade to latest upstream release
