# Selinux type we're building for
%global selinuxtype targeted

# Optional modules and libraries
%bcond_with rlm_cache_memcached
%bcond_with rlm_idn
%bcond_with rlm_lua
%bcond_with rlm_mruby
%bcond_with rlm_opendirectory
%bcond_with rlm_securid
%bcond_with rlm_sigtran

#
#  Oracle conditions and definitions
#
#  The name of instantclient packages, and where they install libraries and headers
#  varies wildly between the version of the package and what operating system you're
#  using.  The following definitions allow the defaults for the rlm_sql_oracle module
#  to be overridden.
#
#  Pass in --with rlm_sql_oracle to build with Oracle support
#
#  Specify the version of Oracle you're using with:
#    --define '_oracle_version <version>'
#  Specify the include and lib directories for Oracle with:
#    --define '_oracle_include_dir <dir>' and --define '_oracle_lib_dir <dir>'
#  Specify runtime dependencies with:
#    --define '_oracle_requires <package>'
#  Specify the build dependencies with:
#    --define '_oracle_build_requires <package>'
#
%bcond_with rlm_sql_oracle
%if %{with rlm_sql_oracle}
  %{!?_oracle_requires:%define _oracle_requires oracle-instantclient%{?_oracle_version}}
  %{!?_oracle_build_requires:%define _oracle_build_requires oracle-instantclient%{?_oracle_version}-devel}
  %ifarch x86_64
    %{!?_oracle_include_dir:%define _oracle_include_dir /usr/include/oracle%{?_oracle_version:/%{_oracle_version}}/client64}
    %{!?_oracle_lib_dir:%define _oracle_lib_dir %{_prefix}/lib/oracle/%{?_oracle_version:/%{_oracle_version}}/client64/lib}
  %endif
  %ifarch i386
    %{!?_oracle_include_dir:%define _oracle_include_dir /usr/include/oracle%{?_oracle_version:/%{_oracle_version}}/client}
    %{!?_oracle_lib_dir:%define _oracle_lib_dir %{_prefix}/lib/oracle/%{?_oracle_version:/%{_oracle_version}}/client/lib}
  %endif
%endif

%bcond_with rlm_yubikey

# Build all experimental modules
%bcond_with experimental-modules

# Build without OpenLDAP (no rlm_ldap, proto_ldap_sync)
%bcond_without ldap

# Build without Python
%bcond_without rlm_python

# Build without unbound
%bcond_without rlm_unbound

# Many distributions have extremely old versions of OpenSSL
# if you'd like to build with the FreeRADIUS openssl packages
# which are installed in /opt/openssl you should pass
# --with freeradius_openssl
%bcond_with freeradius_openssl

# Build against Symas openldap's packaging
%bcond_with symas_openldap

# Build with the samba project's winbind client
%bcond_without wbclient

# Enable asserts and additional debugging
%bcond_with developer

# Integrate with gperftools
%bcond_with gperftools

# Enable various clang/gcc debugging tool support
%bcond_with address_sanitizer
%bcond_with leak_sanitizer
%bcond_with thread_sanitizer
%bcond_with undefined_behaviour_sanitizer

%global _version 4.0

Summary: High-performance and highly configurable free RADIUS server
Name: freeradius
Version: %{?version}%{!?version:%{_version}}
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
%if %{with freeradius_openssl}
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
%if %{with wbclient}
BuildRequires: libwbclient-devel
BuildRequires: samba-devel
%endif
%if %{?_unitdir:1}%{!?_unitdir:0}
BuildRequires: systemd-devel
%endif
BuildRequires: pam-devel
BuildRequires: pcre2-devel
BuildRequires: readline-devel
BuildRequires: zlib-devel

Requires(pre): shadow-utils glibc-common
Requires(post): /sbin/chkconfig /usr/sbin/setsebool
Requires(preun): /sbin/chkconfig
Requires: freeradius-config = %{version}-%{release}
Requires: freeradius-common = %{version}-%{release}
Requires: (%{name}-selinux if selinux-policy-%{selinuxtype})
%if %{with freeradius_openssl}
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
%if %{with wbclient}
Requires: libwbclient
%endif
Requires: zlib
Requires: pam

%if %{with rlm_idn}
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

%package config
Group: System Environment/Daemons
Summary: FreeRADIUS config files
Provides: freeradius-config
Requires: make
Requires: util-linux

%description config
FreeRADIUS default config files
This package should be used as a base for a site local package
to configure the FreeRADIUS server.

%package common
Summary: Main utility library, protocol libraries, and dictionaries

%description common
Provides the main utility library, protocol libraries, and the dictionaries

%package utils
Group: System Environment/Daemons
Summary: FreeRADIUS utilities
Requires: freeradius-common = %{version}-%{release}
Requires: libpcap >= 0.9.4

%description utils
The FreeRADIUS server has a number of features found in other servers,
and additional features not found in any other server. Rather than
doing a feature by feature comparison, we will simply list the features
of the server, and let you decide if they satisfy your needs.

Support for RFC and VSA Attributes Additional server configuration
attributes Selecting a particular configuration Authentication methods

# No requirements here, as selinux is installed by the base package
# as are any of the utilities we need to compile/manage policies.
%package selinux
Summary: A custom selinux policy for FreeRADIUS which adds multiple bools
Requires: %{name} = %{version}-%{release}
Requires: selinux-policy-%{selinuxtype}
Requires(post): selinux-policy-%{selinuxtype}
BuildRequires: selinux-policy-devel
%{?selinux_requires}

%description selinux
This packages installs a custom selinux policy to allow the FreeRADIUS
daemon to operate on additional ports, and communicate with other services
directly using unix sockets.

%package snmp
Summary: SNMP MIBs and SNMP utilities used by FreeRADIUS
Requires: net-snmp-utils

%description snmp
This package install the FreeRADIUS custom MIBs in the default location
used by net-snmp.  This package is required for the default triggers
(which generate SNMP traps) to function.

%package perl-util
Group: System Environment/Daemons
Summary: FreeRADIUS Perl utilities
Requires: perl-Net-IP

%description perl-util
This package provides Perl utilities for managing IP pools stored in
SQL databases.

#
# BEGIN 3rd party utility library packages
#
%package libfreeradius-curl
Summary: curl wrapper library for FreeRADIUS
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: freeradius-common = %{version}-%{release}
Requires: libcurl >= 7.24.0
BuildRequires: libcurl-devel >= 7.24.0

%description libfreeradius-curl
Integrates libcurl with FreeRADIUS' internal event loop.

%package libfreeradius-json
Summary: Internal support library for FreeRADIUS modules using json-c
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: json-c >= 0.13
BuildRequires: json-c-devel >= 0.13

%description libfreeradius-json
Internal support library for FreeRADIUS modules using json-c, required by all modules that use json-c.

#
# BEGIN kafka libraries and modules
#
%package libfreeradius-kafka
Summary: Internal support library for FreeRADIUS modules using librdkafka
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: librdkafka
BuildRequires: librdkafka-devel

%description libfreeradius-kafka
Provides common functions for Kafka production and consumer modules

%files libfreeradius-kafka
%defattr(-,root,root)
%{_libdir}/freeradius/libfreeradius-kafka.so

%package kafka
Summary: Kafka producer support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: librdkafka
Requires: freeradius-libfreeradius-kafka = %{version}-%{release}
BuildRequires: librdkafka-devel

%description kafka
Provides a producer module to push messages into a Kafka queue

%files kafka
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_kafka.so
#
# END kafka libraries and modules
#

%package libfreeradius-redis
Summary: Internal support library for FreeRADIUS modules using hiredis
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: hiredis >= 0.10
BuildRequires: hiredis-devel >= 0.10

%description libfreeradius-redis
Internal support library for FreeRADIUS modules using hiredis, required by all modules that use hiredis.

#
# END 3rd party utility library packages
#
%package brotli
Summary: Brotli compression and decompression
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: brotli
BuildRequires: brotli-devel

%description brotli
This module adds brotli compression and decompression support to FreeRADIUS.

%package imap
Summary: IMAP support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: freeradius-libfreeradius-curl = %{version}

%description imap
This module provides the ability to authenticate users against an IMAP server.

%if %{with rlm_cache_memcached}
%package memcached
Summary: Memcached support for freeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: libmemcached
BuildRequires: libmemcached-devel

%description memcached
Adds support for rlm_memcached as a cache driver.
%endif

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

%if %{with ldap}
%package ldap
Summary: LDAP support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: cyrus-sasl
BuildRequires: cyrus-sasl-devel
%if %{with symas_openldap}
Requires: symas-openldap-clients
BuildRequires: symas-openldap-devel
%else
%if 0%{?rhel}%{?fedora} < 9
AutoReqProv: no
Requires: openldap-ltb
BuildRequires: openldap-ltb
%else
Requires: openldap
BuildRequires: openldap-devel
%endif
%endif

%description ldap
This plugin provides LDAP support for the FreeRADIUS server project.
%endif

%package perl
Summary: Perl support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
%{?fedora:BuildRequires: perl-devel}
BuildRequires: perl-devel
BuildRequires: perl(ExtUtils::Embed)

%description perl
This plugin provides Perl support for the FreeRADIUS server project.

%if %{with rlm_python}
%package python
Summary: Python support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
%if 0%{?rhel} < 9
Requires: python38
BuildRequires: python38-devel
%else
Requires: python3
BuildRequires: python3-devel
%endif

%description python
This plugin provides Python support for the FreeRADIUS server project.
%endif

%package mysql
Summary: MySQL support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: mariadb-connector-c
BuildRequires: mariadb-connector-c-devel

%description mysql
This plugin provides MySQL / MariaDB support for the FreeRADIUS server project.

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

%if %{with rlm_sql_oracle}
%package oracle
Summary: Oracle support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: %{_oracle_requires}
BuildRequires: %{_oracle_build_requires}
%description oracle
This plugin provides Oracle support for the FreeRADIUS server project.
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

%if %{with rlm_unbound}
%package unbound
Summary: Unbound DNS support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: unbound
BuildRequires: unbound-devel

%description unbound
This plugin provides unbound DNS support for the FreeRADIUS server project.
%endif

%if %{with rlm_lua}
%package lua
Summary: Lua support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: ( lua or luajit )
BuildRequires: ( lua-devel or luajit-devel )

%description lua
This plugin provides Lua support for the FreeRADIUS server project.
%endif

%if %{with rlm_mruby}
%package ruby
Summary: Ruby support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: ruby
BuildRequires: ruby ruby-devel

%description ruby
This plugin provides Ruby support for the FreeRADIUS server project.
%endif

%if %{with rlm_sigtran}
%package sigtran
Summary: Sigtran support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: libosmo-sccp, libosmo-xua, libosmo-mtp, libosmocore
BuildRequires: libosmo-sccp-devel, libosmo-xua-devel, libosmo-mtp-devel, libosmocore-devel

%description sigtran
This plugin provides an experimental M3UA/SCCP/TCAP/MAP stack for the FreeRADIUS server project.
%endif

%package smtp
Summary: SMTP support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
Requires: freeradius-libfreeradius-curl = %{version}

%description smtp
This plugin provides the ability to authenticate users against SMTP servers and send email.

%if %{with rlm_yubikey}
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
%undefine _debugsource_packages
%undefine _debuginfo_subpackages

%prep
%setup -q -n freeradius-server-%{version}
# Some source files mistakenly have execute permissions set
find $RPM_BUILD_DIR/freeradius-server-%{version} \( -name '*.c' -o -name '*.h' \) -a -perm /0111 -exec chmod a-x {} +

%build
# Retain CFLAGS from the environment...
%if %{with developer}
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

# Note: It's a bad idea to set PATH here as this may interfere with the modified path passed in by
# code-ready-builder.  If the path needs to be modified, _install_script_path should be set in
# /etc/rpm/macros.  e.g. echo "%_install_script_path   /usr/sbin:/usr/bin:/usr/X11R6/bin" > /etc/rpm/macros
#
# If altering _install_script_path does not change the PATH set by rpmbuild, secure_path may have been
# enabled in /etc/sudoers. The secure_path directive should be removed to allow rpmbuild to manipulate PATH
# in the build environment.

# Pass in the release number, which was passed to us by whatever called rpmbuild
%if %{?_release:1}%{!?_release:0}
export RADIUSD_VERSION_RELEASE="%{release}"
%endif

# Due to an autoconf quirk --with-modules=<module> and --without-<module> are actually correct.
# --with-modules forms the module list we want to explicitly configure, and --without-<module>
# is ignored by the main configure script, but passed down to the individual configure scripts
# where it's used to turn the configure run for the module into a noop.
%define autoconf_mod_with() %{expand:%%{?with_%{1}:--with-modules=%{1}}%%{!?with_%{1}:--without-%{1}}}

%configure \
        --libdir=%{_libdir}/freeradius \
        --sysconfdir=%{_sysconfdir} \
        --disable-ltdl-install \
        --with-gnu-ld \
        --with-threads \
        --with-thread-pool \
        --with-docdir=%{docdir} \
%if %{without developer}
        --disable-developer \
%else
        --enable-developer \
%endif
        %{autoconf_mod_with experimental-modules} \
        %{autoconf_mod_with rlm_cache_memcached} \
        %{autoconf_mod_with rlm_idn} \
        %{autoconf_mod_with rlm_lua} \
        %{autoconf_mod_with rlm_mruby} \
        %{autoconf_mod_with rlm_opendirectory} \
        %{autoconf_mod_with rlm_python} \
%if 0%{?rhel} < 9
        --with-rlm-python-config-bin=/usr/bin/python3.8-config \
%endif
        %{autoconf_mod_with rlm_securid} \
        %{autoconf_mod_with rlm_sigtran} \
        %{autoconf_mod_with rlm_sql_oracle} \
	%{autoconf_mod_with rlm_unbound} \
        %{autoconf_mod_with rlm_yubikey} \
%if %{without ldap}
        --without-libfreeradius-ldap \
%else
%if %{with symas_openldap}
        --with-libfreeradius-ldap-include-dir=/opt/symas/include \
        --with-libfreeradius-ldap-lib-dir=/opt/symas/lib \
%else
        --with-libfreeradius-ldap-include-dir=/usr/local/openldap/include \
        --with-libfreeradius-ldap-lib-dir=/usr/local/openldap/lib64 \
%endif
%endif
        --with-rlm-sql_postgresql-include-dir=/usr/include/pgsql \
        --with-rlm-sql-postgresql-lib-dir=%{_libdir} \
        --with-rlm-sql_mysql-include-dir=/usr/include/mysql \
%if %{without rlm_sql_oracle}
        --without-rlm_sql_oracle \
%else
        --with-oracle-include-dir=%{_oracle_include_dir} \
        --with-oracle-lib-dir=%{_oracle_lib_dir} \
%endif
        --with-mysql-lib-dir=%{_libdir}/mysql \
        --with-unixodbc-lib-dir=%{_libdir} \
        --with-rlm-dbm-lib-dir=%{_libdir} \
        --with-rlm-krb5-include-dir=/usr/kerberos/include \
        --without-rlm_sql_firebird \
        --without-rlm_sql_db2 \
        --with-jsonc-lib-dir=%{_libdir} \
        --with-jsonc-include-dir=/usr/include/json \
        --with-winbind-include-dir=/usr/include/samba-4.0 \
        --with-winbind-lib-dir=/usr/lib64/samba \
%if %{with freeradius_openssl}
        --with-openssl-lib-dir=/opt/openssl/lib \
        --with-openssl-include-dir=/opt/openssl/include \
%endif
%if %{with gperftools}
        --with-gperftools \
%endif
%if %{with address_sanitizer}
        --enable-address-sanitizer \
%endif
%if %{with leak_sanitizer}
        --enable-leak-sanitizer \
%endif
%if %{with thread_sanitizer}
        --enable-thread-sanitizer \
%endif
%if %{with undefined_behaviour_sanitizer}
        --enable-undefined-behaviour-sanitizer \
%endif

# Do not use %__make here, as we may be using the non-system make
make %{?_smp_mflags}

# Compile the selinux policy and produce the .bz2 containing the compiled policy
make -f redhat/selinux/Makefile

%install
%__rm -rf $RPM_BUILD_ROOT
%__mkdir_p $RPM_BUILD_ROOT/var/run/radiusd
%__mkdir_p $RPM_BUILD_ROOT/var/lib/radiusd
%__mkdir_p $RPM_BUILD_ROOT/var/lib/radiusd/snmp
%__mkdir_p $RPM_BUILD_ROOT/%{docdir}
make install R=$RPM_BUILD_ROOT

# modify default configuration
RADDB=$RPM_BUILD_ROOT%{_sysconfdir}/raddb
%__sed -ie 's/^#user =.*$/user = radiusd/'   $RADDB/radiusd.conf
%__sed -ie 's/^#group =.*$/group = radiusd/' $RADDB/radiusd.conf

# logs
%__mkdir_p $RPM_BUILD_ROOT/var/log/radius/radacct
touch $RPM_BUILD_ROOT/var/log/radius/radius.log

%__install -D -m 644 %{SOURCE102} $RPM_BUILD_ROOT/%{_sysconfdir}/logrotate.d/radiusd
%__install -D -m 644 %{SOURCE103} $RPM_BUILD_ROOT/%{_sysconfdir}/pam.d/radiusd

# For systemd based systems, that define _unitdir, install the radiusd unit
%if %{?_unitdir:1}%{!?_unitdir:0}
%__install -D -m 644 %{SOURCE100} $RPM_BUILD_ROOT/%{_unitdir}/radiusd.service
%__install -D -m 644 %{SOURCE104} $RPM_BUILD_ROOT/%{_prefix}/lib/tmpfiles.d/radiusd.conf
# For SystemV install the init script
%else
%__install -D -m 755 %{SOURCE100} $RPM_BUILD_ROOT/%{initddir}/radiusd
%endif

# remove unneeded stuff
# unknown which errant sed command produces this, but it needs to be removed
%__rm -f $RADDB/radiusd.confe

%__rm -rf doc/00-OLD
%__rm -f $RPM_BUILD_ROOT/usr/bin/radsizes
%__rm -f $RPM_BUILD_ROOT/usr/sbin/rc.radiusd
%__rm -rf $RPM_BUILD_ROOT/%{_libdir}/freeradius/*.a
%__rm -rf $RPM_BUILD_ROOT/%{_libdir}/freeradius/*.la

%if %{without rlm_idn}
%__rm -f $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-available/idn
%endif

%if %{without rlm_lua}
%__rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/lua
%endif

%if %{without rlm_ruby}
%__rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/ruby
%endif
%if %{without rlm_sql_oracle}
%__rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/sql/ippool/oracle
%__rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/sql/main/oracle
%__rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/sql/driver/oracle
%endif
%__rm -rf $RPM_BUILD_ROOT/%{_libdir}/freeradius/rlm_test.so

# remove header files, we don't ship a devel package and the
# headers have multilib conflicts
%__rm -rf $RPM_BUILD_ROOT/%{_includedir}

# remove unsupported config files
%__rm -f $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/experimental.conf

# install doc files omitted by standard install
for f in COPYRIGHT CREDITS; do
    %__cp $f $RPM_BUILD_ROOT/%{docdir}
done
%__cp LICENSE $RPM_BUILD_ROOT/%{docdir}/LICENSE.gpl
%__cp src/LICENSE.openssl $RPM_BUILD_ROOT/%{docdir}/LICENSE.openssl

# add Red Hat specific documentation
%__cat >> $RPM_BUILD_ROOT/%{docdir}/REDHAT << EOF

Red Hat, RHEL, Fedora, and CentOS specific information can be found on the
FreeRADIUS Wiki in the Red Hat FAQ.

http://wiki.freeradius.org/guide/Red_Hat_FAQ

Please reference that document.

EOF

# Install the selinux module
%__install -D -m 0644 -t %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype} redhat/selinux/%{name}.pp.bz2

%clean
%__rm -rf $RPM_BUILD_ROOT

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

%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post
if [ $1 = 1 ]; then
  %selinux_set_booleans -s %{selinuxtype} radius_use_jit=on
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

%post selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{name}.pp.bz2
%selinux_relabel_post -s %{selinuxtype}

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
%selinux_unset_booleans -s %{selinuxtype} radius_jit

%postun selinux
if [ $1 -eq 0 ]; then
  %selinux_modules_uninstall -s %{selinuxtype} %{name}
fi

%posttrans selinux
%selinux_relabel_post -s %{selinuxtype}

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

%dir %attr(755,radiusd,radiusd) %{_sharedstatedir}/radiusd/
%dir %attr(755,radiusd,radiusd) /var/run/radiusd/
# binaries
%defattr(-,root,root)
# man-pages
%doc %{_mandir}/man1/smbencrypt.1.gz
%doc %{_mandir}/man5/checkrad.5.gz
%doc %{_mandir}/man5/clients.conf.5.gz
%doc %{_mandir}/man5/radiusd.conf.5.gz
%doc %{_mandir}/man5/unlang.5.gz
%doc %{_mandir}/man8/radcrypt.8.gz
%doc %{_mandir}/man8/raddebug.8.gz
%doc %{_mandir}/man8/radmin.8.gz
%doc %{_mandir}/man8/radiusd.8.gz
# logs
%dir %attr(700,radiusd,radiusd) /var/log/radius/
%dir %attr(700,radiusd,radiusd) /var/log/radius/radacct/
%ghost %attr(600,radiusd,radiusd) /var/log/radius/radius.log

#
#  rpmbuild isn't smart enough to prevent globbed
#  matches from appearing in multiple packages
#  so we have to list each .so file individually here
#  otherwise it gets included in both the main FreeRADIUS
#  package and any module specific packages
#
%defattr(755,root,root,755)
/usr/sbin/checkrad
/usr/sbin/raddebug
/usr/sbin/radiusd
/usr/sbin/radlock
/usr/sbin/radmin

# Needed to set directory permissions correctly
%dir %{_libdir}/freeradius

# Protocol state machines without external deps
%{_libdir}/freeradius/process_arp.so
%{_libdir}/freeradius/process_bfd.so
%{_libdir}/freeradius/process_control.so
%{_libdir}/freeradius/process_dhcpv4.so
%{_libdir}/freeradius/process_dhcpv6.so
%{_libdir}/freeradius/process_dns.so
%{_libdir}/freeradius/process_eap_aka.so
%{_libdir}/freeradius/process_eap_aka_prime.so
%{_libdir}/freeradius/process_eap_sim.so
%{_libdir}/freeradius/process_radius.so
%{_libdir}/freeradius/process_tacacs.so
%{_libdir}/freeradius/process_tls.so
%{_libdir}/freeradius/process_ttls.so
%{_libdir}/freeradius/process_vmps.so

# Proto modules without external deps
%{_libdir}/freeradius/proto_arp.so
%{_libdir}/freeradius/proto_arp_ethernet.so
%{_libdir}/freeradius/proto_bfd.so
%{_libdir}/freeradius/proto_bfd_udp.so
%{_libdir}/freeradius/proto_control.so
%{_libdir}/freeradius/proto_control_unix.so
%{_libdir}/freeradius/proto_cron.so
%{_libdir}/freeradius/proto_cron_crontab.so
%{_libdir}/freeradius/proto_detail.so
%{_libdir}/freeradius/proto_detail_file.so
%{_libdir}/freeradius/proto_detail_work.so
%{_libdir}/freeradius/proto_dhcpv4.so
%{_libdir}/freeradius/proto_dhcpv4_udp.so
%{_libdir}/freeradius/proto_dhcpv6.so
%{_libdir}/freeradius/proto_dhcpv6_udp.so
%{_libdir}/freeradius/proto_dns.so
%{_libdir}/freeradius/proto_dns_udp.so
%{_libdir}/freeradius/proto_load.so
%{_libdir}/freeradius/proto_load_step.so
%{_libdir}/freeradius/proto_radius.so
%{_libdir}/freeradius/proto_radius_tcp.so
%{_libdir}/freeradius/proto_radius_udp.so
%{_libdir}/freeradius/proto_tacacs.so
%{_libdir}/freeradius/proto_tacacs_tcp.so
%{_libdir}/freeradius/proto_vmps.so
%{_libdir}/freeradius/proto_vmps_udp.so

# Support libraries without external deps.
# Protocol libraries should not be included here, they should be added to the common package instead.
%{_libdir}/freeradius/libfreeradius-control.so
%{_libdir}/freeradius/libfreeradius-io.so
%{_libdir}/freeradius/libfreeradius-server.so
%{_libdir}/freeradius/libfreeradius-tls.so
%{_libdir}/freeradius/libfreeradius-totp.so
%{_libdir}/freeradius/libfreeradius-unlang.so

# Backend modules without external deps
%{_libdir}/freeradius/rlm_always.so
%{_libdir}/freeradius/rlm_attr_filter.so
%{_libdir}/freeradius/rlm_cache.so
%{_libdir}/freeradius/rlm_cache_rbtree.so
%{_libdir}/freeradius/rlm_chap.so
%{_libdir}/freeradius/rlm_cipher.so
%{_libdir}/freeradius/rlm_client.so
%{_libdir}/freeradius/rlm_csv.so
%{_libdir}/freeradius/rlm_date.so
%{_libdir}/freeradius/rlm_delay.so
%{_libdir}/freeradius/rlm_detail.so
%{_libdir}/freeradius/rlm_dhcpv4.so
%{_libdir}/freeradius/rlm_dict.so
%{_libdir}/freeradius/rlm_digest.so
%{_libdir}/freeradius/rlm_eap.so
%{_libdir}/freeradius/rlm_eap_aka.so
%{_libdir}/freeradius/rlm_eap_aka_prime.so
%{_libdir}/freeradius/rlm_eap_fast.so
%{_libdir}/freeradius/rlm_eap_gtc.so
%{_libdir}/freeradius/rlm_eap_md5.so
%{_libdir}/freeradius/rlm_eap_mschapv2.so
%{_libdir}/freeradius/rlm_eap_peap.so
%{_libdir}/freeradius/rlm_eap_pwd.so
%{_libdir}/freeradius/rlm_eap_sim.so
%{_libdir}/freeradius/rlm_eap_tls.so
%{_libdir}/freeradius/rlm_eap_ttls.so
%{_libdir}/freeradius/rlm_escape.so
%{_libdir}/freeradius/rlm_exec.so
%{_libdir}/freeradius/rlm_files.so
%{_libdir}/freeradius/rlm_icmp.so
%{_libdir}/freeradius/rlm_isc_dhcp.so
%{_libdir}/freeradius/rlm_linelog.so
%{_libdir}/freeradius/rlm_logtee.so
%{_libdir}/freeradius/rlm_mschap.so
%{_libdir}/freeradius/rlm_pam.so
%{_libdir}/freeradius/rlm_pap.so
%{_libdir}/freeradius/rlm_passwd.so
%{_libdir}/freeradius/rlm_radius.so
%{_libdir}/freeradius/rlm_sometimes.so
%{_libdir}/freeradius/rlm_sql.so
%{_libdir}/freeradius/rlm_sql_null.so
%{_libdir}/freeradius/rlm_sqlcounter.so
%{_libdir}/freeradius/rlm_sqlippool.so
%{_libdir}/freeradius/rlm_stats.so
%{_libdir}/freeradius/rlm_tacacs.so
%{_libdir}/freeradius/rlm_tacacs_tcp.so
%{_libdir}/freeradius/rlm_totp.so
%{_libdir}/freeradius/rlm_unix.so
%{_libdir}/freeradius/rlm_unpack.so
%{_libdir}/freeradius/rlm_utf8.so
%{_libdir}/freeradius/rlm_wimax.so

%{?with_rlm_idn: %{_libdir}/freeradius/rlm_idn.so}
%if %{with experimental_modules}
%endif

%files common
# The protocol libraries are needed to load dictionaries, which are used by the server
# and the majority of utility binaries.
%{_libdir}/freeradius/libfreeradius-arp.so
%{_libdir}/freeradius/libfreeradius-bfd.so
%{_libdir}/freeradius/libfreeradius-cbor.so
%{_libdir}/freeradius/libfreeradius-der.so
%{_libdir}/freeradius/libfreeradius-dhcpv4.so
%{_libdir}/freeradius/libfreeradius-dhcpv6.so
%{_libdir}/freeradius/libfreeradius-dns.so
%{_libdir}/freeradius/libfreeradius-eap-aka-sim.so
%{_libdir}/freeradius/libfreeradius-eap.so
%{_libdir}/freeradius/libfreeradius-ethernet.so
%{_libdir}/freeradius/libfreeradius-internal.so
%{_libdir}/freeradius/libfreeradius-radius.so
%{_libdir}/freeradius/libfreeradius-radius-bio.so
%{_libdir}/freeradius/libfreeradius-sim.so
%{_libdir}/freeradius/libfreeradius-tacacs.so
%{_libdir}/freeradius/libfreeradius-tftp.so
%{_libdir}/freeradius/libfreeradius-vmps.so

# Utility libraries
%{_libdir}/freeradius/libfreeradius-bio.so
%{_libdir}/freeradius/libfreeradius-bio-config.so
%{_libdir}/freeradius/libfreeradius-util.so

# dictionaries
%dir %attr(755,root,root) /usr/share/freeradius
%{_datadir}/freeradius/dictionary/*

# man pages for dictionaries
%doc %{_mandir}/man5/dictionary.5.gz

%files config
%dir %attr(755,root,radiusd) %{_sysconfdir}/raddb
%defattr(640,root,radiusd,750)
%attr(644,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/dictionary
%config(noreplace) %{_sysconfdir}/raddb/clients.conf
%config(noreplace) %{_sysconfdir}/raddb/panic.gdb
%config(noreplace) %{_sysconfdir}/raddb/radiusd.conf
%config(noreplace) %{_sysconfdir}/raddb/trigger.conf
%config(noreplace) %{_sysconfdir}/raddb/users

%config(noreplace) %{_sysconfdir}/raddb/certs
%attr(755,root,radiusd) %{_sysconfdir}/raddb/certs/bootstrap

%config(noreplace) %{_sysconfdir}/raddb/sites-available

%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/sites-enabled
%config(noreplace) %{_sysconfdir}/raddb/sites-enabled
%config(noreplace) %{_sysconfdir}/raddb/policy.d
%config(noreplace) %{_sysconfdir}/raddb/global.d
%config(noreplace) %{_sysconfdir}/raddb/template.d

%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config
%config(noreplace) %{_sysconfdir}/raddb/mods-config/attr_filter

%config(noreplace) %{_sysconfdir}/raddb/mods-config/csv
%config(noreplace) %{_sysconfdir}/raddb/mods-config/files
%config(noreplace) %{_sysconfdir}/raddb/mods-config/isc_dhcp

%config(noreplace) %{_sysconfdir}/raddb/mods-enabled
%config(noreplace) %{_sysconfdir}/raddb/mods-available

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
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/driver/mysql
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/main/mysql

%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/counter/mysql
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/cui/mysql
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/ippool/mysql

#
#  NDB
#
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/main/ndb

#
#  PostgreSQL
#
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/driver/postgresql
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/main/postgresql

%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/counter/postgresql
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/cui/postgresql
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/ippool/postgresql

#
#  SQLite
#
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/driver/sqlite
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/main/sqlite

%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/counter/sqlite
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/cui/sqlite
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/ippool/sqlite

#
#  Cassandra
#
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/driver/cassandra
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/main/cassandra

#
#  MS-SQL (Sybase / FreeTDS)
#
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/main/mssql
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/ippool/mssql

#
#  Oracle
#
%if %{with rlm_sql_oracle}
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/main/oracle
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/ippool/oracle
%attr(640,root,radiusd) %config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/driver/oracle
%endif

#
#  Firebird / InterBase
#
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/main/firebird
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/sql/ippool/firebird

%if %{with rlm_unbound}
%config(noreplace)	%{_sysconfdir}/raddb/mods-config/unbound/default.conf
%endif

%files utils
%exclude /usr/bin/*_tests
%exclude /usr/bin/unit_test_*
%defattr(-,root,root)
/usr/bin/dhcpclient
/usr/bin/radclient
/usr/bin/radcrypt
/usr/bin/radict
/usr/bin/radsniff
/usr/bin/radsqlrelay
/usr/bin/radtest
/usr/bin/raduat
/usr/bin/smbencrypt
# man-pages
%doc %{_mandir}/man1/dhcpclient.1.gz
%doc %{_mandir}/man1/radclient.1.gz
%doc %{_mandir}/man1/radtest.1.gz
%doc %{_mandir}/man8/radsniff.8.gz
%doc %{_mandir}/man8/radsqlrelay.8.gz

%files snmp
%defattr(-,root,root)
/usr/bin/radsnmp
%{_datadir}/snmp/mibs/*
%dir %attr(750,radiusd,radiusd) %{_sharedstatedir}/radiusd/snmp

%files selinux
%defattr(-,root,root,0755)
%attr(0644,root,root) %{_datadir}/selinux/packages/%{selinuxtype}/*.pp.bz2

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

%files libfreeradius-json
%defattr(-,root,root)
%{_libdir}/freeradius/libfreeradius-json.so

%files libfreeradius-redis
%defattr(-,root,root)
%{_libdir}/freeradius/libfreeradius-redis.so

%files brotli
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_brotli.so

%if %{with rlm_cache_memcached}
%files memcached
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_cache_memcached.so
%endif

%files imap
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_imap.so

%files krb5
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_krb5.so

%files perl
%defattr(-,root,root,750)
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/perl
%{_libdir}/freeradius/rlm_perl.so

%if %{with rlm_python}
%files python
%defattr(-,root,root,750)
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/python
%{_libdir}/freeradius/rlm_python.so
%endif

%files mysql
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sql_mysql.so

%files postgresql
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sql_postgresql.so

%files sqlite
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sql_sqlite.so

%if %{with ldap}
%files ldap
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_ldap.so
%{_libdir}/freeradius/process_ldap_sync.so
%{_libdir}/freeradius/proto_ldap_sync.so
%{_libdir}/freeradius/proto_ldap_sync_ldap.so
%{_libdir}/freeradius/libfreeradius-ldap.so
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

%if %{with rlm_unbound}
%files unbound
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_unbound.so
%doc %{_mandir}/man5/rlm_unbound.5.gz
%endif

%if %{with rlm_sigtran}
%files sigtran
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sigtran.so
%endif

%if %{with rlm_lua}
%files ruby
%defattr(-,root,root,750)
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/lua
%{_libdir}/freeradius/rlm_lua.so
%endif

%if %{with rlm_mruby}
%files ruby
%defattr(-,root,root,750)
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/ruby
%{_libdir}/freeradius/rlm_mruby.so
%endif

%files smtp
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_smtp.so

%files freetds
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sql_freetds.so

%if %{with rlm_sql_oracle}
%files oracle
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sql_oracle.so
%endif

%if %{with rlm_yubikey}
%files yubikey
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_yubikey.so
%endif


%changelog
* Wed Sep 25 2013 Alan DeKok <aland@freeradius.org> - 3.0.0
- upgrade to latest upstream release
