%bcond_with rlm_yubikey
%bcond_without ldap
# %%bcond_with experimental_modules

%{!?_with_rlm_cache_memcached: %global _without_rlm_cache_memcached --without-rlm_cache_memcached}
%{!?_with_rlm_eap_pwd: %global _without_rlm_eap_pwd --without-rlm_eap_pwd}
%{!?_with_rlm_eap_tnc: %global _without_rlm_eap_tnc --without-rlm_eap_tnc}
%{!?_with_rlm_yubikey: %global _without_rlm_yubikey --without-rlm_yubikey}
%{?_without_ldap: %global _without_libfreeradius_ldap --without-libfreeradius-ldap}
%{?el7: %global _without_rlm_eap_teap --without-rlm_eap_teap}

# experimental modules
%bcond_with rlm_idn
%bcond_with rlm_ruby
%bcond_with rlm_sql_oracle
%{?_with_rlm_idn: %global _with_experimental_modules --with-experimental-modules}
%{?_with_rlm_opendirectory: %global _with_experimental_modules --with-experimental-modules}
%{?_with_rlm_ruby: %global _with_experimental_modules --with-experimental-modules}
%{?_with_rlm_securid: %global _with_experimental_modules --with-experimental-modules}
%{?_with_rlm_sql_oracle: %global _with_experimental_modules --with-experimental-modules}

%if %{?_with_experimental_modules:1}%{!?_with_experimental_modules:0}
%{!?_with_rlm_idn: %global _without_rlm_idn --without-rlm_idn}
%{!?_with_rlm_opendirectory: %global _without_rlm_opendirectory --without-rlm_opendirectory}
%{!?_with_rlm_ruby: %global _without_rlm_ruby --without-rlm_ruby}
%{!?_with_rlm_securid: %global _without_rlm_securid --without-rlm_securid}
%{!?_with_rlm_sql_oracle: %global _without_rlm_sql_oracle --without-rlm_sql_oracle}
%endif

%{?el6: %global _without_libwbclient --with-winbind-dir=/nonexistant}

Summary: High-performance and highly configurable free RADIUS server
Name: freeradius
Version: 3.2.6
Release: 1%{?dist}
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

%define docdir %{_docdir}/freeradius-%{version}
%define initddir %{?_initddir:%{_initddir}}%{!?_initddir:%{_initrddir}}

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: autoconf
BuildRequires: gdbm-devel
BuildRequires: openssl, openssl-devel
BuildRequires: pam-devel
BuildRequires: pcre-devel
BuildRequires: zlib-devel
BuildRequires: net-snmp-devel
BuildRequires: net-snmp-utils
BuildRequires: libwbclient-devel
BuildRequires: samba-devel
%if %{?_unitdir:1}%{!?_unitdir:0}
BuildRequires: systemd-devel
%endif
BuildRequires: readline-devel
BuildRequires: libpcap-devel
BuildRequires: libtalloc-devel
BuildRequires: libcurl-devel

Requires(pre): shadow-utils glibc-common
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig
Requires: freeradius-config = %{version}-%{release}
Requires: openssl
Requires: libpcap
Requires: readline
Requires: libtalloc
Requires: net-snmp
Requires: libwbclient
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

# CentOS defines debug package by default. Only define it if not already defined
%if 0%{!?_enable_debug_packages:1}
%debug_package
%endif

%if %{?_with_rlm_cache_memcached:1}%{?!_with_rlm_cache_memcached:0}
%package memcached
Summary: Memcached support for freeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: libmemcached
BuildRequires: libmemcached-devel

%description memcached
Adds support for rlm_memcached as a cache driver.
%endif

%package config
Group: System Environment/Daemons
Summary: FreeRADIUS config files
Provides: freeradius-config

%description config
FreeRADIUS default config files
This package should be used as a base for a site local package
to configure the FreeRADIUS server.
Requires: make
Requires: util-linux

%package utils
Group: System Environment/Daemons
Summary: FreeRADIUS utilities
Requires: %{name} = %{version}-%{release}
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

%if %{!?_without_ldap:1}%{?_without_ldap:0}
%package ldap
Summary: LDAP support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
%if 0%{?rhel} <= 8
Requires: openldap-ltb, cyrus-sasl
BuildRequires: openldap-ltb, cyrus-sasl-devel
%endif
%if 0%{?rhel} >= 9
Requires: openldap, cyrus-sasl
BuildRequires: openldap-devel, cyrus-sasl-devel
%endif

%description ldap
This plugin provides LDAP support for the FreeRADIUS server project.
%endif

%package krb5
Summary: Kerberos 5 support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: krb5-libs
BuildRequires: krb5-devel

%description krb5
This plugin provides Kerberos 5 support for the FreeRADIUS server project.

%package perl
Summary: Perl support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
BuildRequires: perl-devel
BuildRequires: perl(ExtUtils::Embed)

%description perl
This plugin provides Perl support for the FreeRADIUS server project.

%if %{?el6:0}%{!?el6:1}
%package python
Summary: Python support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
%{?fedora:Requires: python2}
%{?fedora:BuildRequires: python2-devel}
%if 0%{?rhel} <= 7
Requires: python
BuildRequires: python-devel
%endif
%if 0%{?rhel} == 8
Requires: python2
Requires: python3
BuildRequires: python2-devel
BuildRequires: python3-devel
%endif
%if 0%{?rhel} >= 9
Requires: python3
BuildRequires: python3-devel
%endif

%description python
This plugin provides Python support for the FreeRADIUS server project.
%endif

%package mysql
Summary: MySQL support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
%if 0%{?rhel} <= 7
Requires: mysql
%endif
%if 0%{?rhel} >= 8
Requires: mysql-libs
%endif
BuildRequires: mysql-devel

%description mysql
This plugin provides MySQL support for the FreeRADIUS server project.

%package postgresql
Summary: PostgreSQL support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: postgresql
BuildRequires: postgresql-devel

%description postgresql
This plugin provides PostgreSQL support for the FreeRADIUS server project.

%package sqlite
Summary: SQLite support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: sqlite
BuildRequires: sqlite-devel

%description sqlite
This plugin provides SQLite support for the FreeRADIUS server project.

%package unixODBC
Summary: unixODBC support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: unixODBC
BuildRequires: unixODBC-devel

%description unixODBC
This plugin provides unixODBC support for the FreeRADIUS server project.

%package freetds
Summary: FreeTDS support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: freetds
BuildRequires: freetds-devel

%description freetds
This plugin provides FreeTDS support for the FreeRADIUS server project.

%if %{?_with_rlm_sql_oracle:1}%{!?_with_rlm_sql_oracle:0}
%package oracle
Summary: Oracle support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
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

%if %{?el6:0}%{!?el6:1}
%package redis
Summary: Redis support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: hiredis
BuildRequires: hiredis-devel

%description redis
This plugin provides Redis support for the FreeRADIUS server project.
%endif

%package rest
Summary: REST and JSON support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: json-c >= 0.10
BuildRequires: json-c-devel >= 0.10

%description rest
This plugin provides REST support for the FreeRADIUS server project.

%if %{?_with_rlm_ruby:1}%{!?_with_rlm_ruby:0}
%package ruby
Summary: Ruby support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: ruby
BuildRequires: ruby ruby-devel

%description ruby
This plugin provides Ruby support for the FreeRADIUS server project.
%endif

%package unbound
Summary: Unbound DNS support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: unbound
BuildRequires: unbound-devel

%description unbound
This plugin provides unbound DNS support for the FreeRADIUS server project.

%if %{?_with_rlm_yubikey:1}%{!?_with_rlm_yubikey:0}
%package yubikey
Summary: YubiCloud support for FreeRADIUS
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires: ykclient >= 2.10
BuildRequires: ykclient-devel >= 2.10

%description yubikey
This plugin provides YubiCloud support for the FreeRADIUS server project.
%endif


%prep
%setup -q -n freeradius-server-%{version}
# Some source files mistakenly have execute permissions set
find $RPM_BUILD_DIR/freeradius-server-%{version} \( -name '*.c' -o -name '*.h' \) -a -perm /0111 -exec chmod a-x {} +


%build
# Retain CFLAGS from the environment...
%if %{?_with_developer:1}%{!?_with_developer:0}
export CFLAGS="$CFLAGS -fpic"
export CXXFLAGS="$CFLAGS"
%endif

# Need to pass these explicitly for clang, else rpmbuilder bails when trying to extract debug info from
# the libraries.  Guessing GCC does this by default.  Why use clang over gcc? The version of clang
# which ships with RHEL 6 has basic C11 support, gcc doesn't.
export LDFLAGS="-Wl,--build-id"

%configure \
        --libdir=%{_libdir}/freeradius \
        --sysconfdir=%{_sysconfdir} \
        --disable-ltdl-install \
        --with-gnu-ld \
        --with-threads \
        --with-thread-pool \
        --with-docdir=%{docdir} \
%if %{!?_without_ldap:1}%{?_without_ldap:0}
        --with-rlm-ldap-include-dir=/usr/local/openldap/include \
        --with-rlm-ldap-lib-dir=/usr/local/openldap/lib64 \
%endif
        --with-rlm-sql_postgresql-include-dir=/usr/include/pgsql \
        --with-rlm-sql-postgresql-lib-dir=%{_libdir} \
        --with-rlm-sql_mysql-include-dir=/usr/include/mysql \
        --with-mysql-lib-dir=%{_libdir}/mysql \
        --with-unixodbc-lib-dir=%{_libdir} \
        --with-rlm-dbm-lib-dir=%{_libdir} \
        --with-rlm-krb5-include-dir=/usr/kerberos/include \
        --without-rlm_eap_ikev2 \
        --without-rlm_sql_iodbc \
        --without-rlm_sql_firebird \
        --without-rlm_sql_db2 \
        --without-rlm_sql_mongo \
        --with-jsonc-lib-dir=%{_libdir} \
        --with-jsonc-include-dir=/usr/include/json \
        --with-winbind-include-dir=/usr/include/samba-4.0 \
        --with-winbind-lib-dir=/usr/lib64/samba \
        --with-systemd \
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
        %{?_with_rlm_ruby} \
        %{?_without_rlm_ruby} \
        %{?_with_rlm_cache_memcached} \
        %{?_without_rlm_cache_memcached} \
        %{?_without_libwbclient} \
        %{?_without_libfreeradius_ldap} \
#        --with-modules="rlm_wimax" \

make %_smp_mflags

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/var/run/radiusd
mkdir -p $RPM_BUILD_ROOT/var/lib/radiusd
make install R=$RPM_BUILD_ROOT PACKAGE='redhat'
# modify default configuration
RADDB=$RPM_BUILD_ROOT%{_sysconfdir}/raddb
perl -i -pe 's/^#user =.*$/user = radiusd/'   $RADDB/radiusd.conf
perl -i -pe 's/^#group =.*$/group = radiusd/' $RADDB/radiusd.conf
# logs
mkdir -p $RPM_BUILD_ROOT/var/log/radius/radacct
touch $RPM_BUILD_ROOT/var/log/radius/{radutmp,radius.log}
install -m 755 scripts/raduat $RPM_BUILD_ROOT/%{_bindir}/raduat

# For systemd based systems, that define _unitdir, install the radiusd unit
%if %{?_unitdir:1}%{!?_unitdir:0}
install -D -m 755 redhat/radiusd.service $RPM_BUILD_ROOT/%{_unitdir}/radiusd.service
install -D -m 644 %{SOURCE104} $RPM_BUILD_ROOT/%{_prefix}/lib/tmpfiles.d/radiusd.conf
# For SystemV install the init script
%else
install -D -m 755 redhat/freeradius-radiusd-init $RPM_BUILD_ROOT/%{initddir}/radiusd
%endif

install -D -m 644 redhat/freeradius-logrotate $RPM_BUILD_ROOT/%{_sysconfdir}/logrotate.d/radiusd
install -D -m 644 redhat/freeradius-pam-conf $RPM_BUILD_ROOT/%{_sysconfdir}/pam.d/radiusd

# remove unneeded stuff
rm -rf doc/00-OLD
rm -f $RPM_BUILD_ROOT/usr/sbin/rc.radiusd
rm -rf $RPM_BUILD_ROOT/%{_libdir}/freeradius/*.a
rm -rf $RPM_BUILD_ROOT/%{_libdir}/freeradius/*.la
%if %{?_with_rlm_idn:0}%{!?_with_rlm_idn:1}
# Does not delete file. Why?
rm -f $RPM_BUILD_ROOT/%{_mandir}/man5/rlm_idn.5.gz
rm -f $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-available/idn
%endif
%if %{?_with_rlm_ruby:0}%{!?_with_rlm_ruby:1}
rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/ruby
%endif
%if %{?_with_rlm_sql_oracle:0}%{!?_with_rlm_sql_oracle:1}
rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/sql/dhcp/oracle
rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/sql/ippool/oracle
rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/sql/ippool-dhcp/oracle
rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/sql/main/oracle
%endif
rm -rf $RPM_BUILD_ROOT/%{_libdir}/freeradius/rlm_test.so
# remove header files, we don't ship a devel package and the
# headers have multilib conflicts
rm -rf $RPM_BUILD_ROOT/%{_includedir}

# remove unsupported config files
rm -f $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/experimental.conf
rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/sql/ippool/mongo
rm -rf $RPM_BUILD_ROOT/%{_sysconfdir}/raddb/mods-config/sql/main/mongo

# install doc files omitted by standard install
for f in COPYRIGHT CREDITS INSTALL.rst README.rst; do
    cp $f $RPM_BUILD_ROOT/%{docdir}
done
cp LICENSE $RPM_BUILD_ROOT/%{docdir}/LICENSE.gpl
cp src/lib/LICENSE $RPM_BUILD_ROOT/%{docdir}/LICENSE.lgpl
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
%if %{?_unitdir:1}%{!?_unitdir:0}
  /bin/systemctl enable radiusd.service
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
  /bin/systemctl stop radiusd.service || :
  /bin/systemctl disable radiusd.service || :
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
%doc %{_mandir}/man5/radrelay.conf.5.gz
%doc %{_mandir}/man5/rlm_always.5.gz
%doc %{_mandir}/man5/rlm_attr_filter.5.gz
%doc %{_mandir}/man5/rlm_chap.5.gz
%doc %{_mandir}/man5/rlm_counter.5.gz
%doc %{_mandir}/man5/rlm_detail.5.gz
%doc %{_mandir}/man5/rlm_digest.5.gz
%doc %{_mandir}/man5/rlm_expr.5.gz
%doc %{_mandir}/man5/rlm_files.5.gz
%doc %{_mandir}/man5/rlm_idn.5.gz
# %%{?_with_rlm_idn: %doc %{_mandir}/man5/rlm_idn.5.gz}
%doc %{_mandir}/man5/rlm_mschap.5.gz
%doc %{_mandir}/man5/rlm_pap.5.gz
%doc %{_mandir}/man5/rlm_passwd.5.gz
%doc %{_mandir}/man5/rlm_realm.5.gz
%doc %{_mandir}/man5/rlm_sql.5.gz
%doc %{_mandir}/man5/rlm_unbound.5.gz
%doc %{_mandir}/man5/rlm_unix.5.gz
%doc %{_mandir}/man5/unlang.5.gz
%doc %{_mandir}/man5/users.5.gz
%doc %{_mandir}/man8/radcrypt.8.gz
%doc %{_mandir}/man8/raddebug.8.gz
%doc %{_mandir}/man8/radiusd.8.gz
%doc %{_mandir}/man8/radmin.8.gz
%doc %{_mandir}/man8/radrelay.8.gz
%doc %{_mandir}/man8/radsniff.8.gz
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
%{_libdir}/freeradius/proto_dhcp.so
%{_libdir}/freeradius/proto_vmps.so
%{_libdir}/freeradius/rlm_always.so
%{_libdir}/freeradius/rlm_attr_filter.so
%{_libdir}/freeradius/rlm_cache.so
%{_libdir}/freeradius/rlm_cache_rbtree.so
%{_libdir}/freeradius/rlm_chap.so
%{_libdir}/freeradius/rlm_counter.so
%{_libdir}/freeradius/rlm_date.so
%{_libdir}/freeradius/rlm_detail.so
%{_libdir}/freeradius/rlm_dhcp.so
%{_libdir}/freeradius/rlm_digest.so
%{_libdir}/freeradius/rlm_dpsk.so
%{_libdir}/freeradius/rlm_dynamic_clients.so
%{_libdir}/freeradius/rlm_eap.so
%{_libdir}/freeradius/rlm_eap_fast.so
%{_libdir}/freeradius/rlm_eap_gtc.so
%{_libdir}/freeradius/rlm_eap_md5.so
%{_libdir}/freeradius/rlm_eap_mschapv2.so
%{_libdir}/freeradius/rlm_eap_peap.so
%{_libdir}/freeradius/rlm_eap_sim.so
%if 0%{?rhel} >= 8
%{_libdir}/freeradius/rlm_eap_teap.so
%endif
%{_libdir}/freeradius/rlm_eap_tls.so
%{_libdir}/freeradius/rlm_eap_ttls.so
%{_libdir}/freeradius/rlm_exec.so
%{_libdir}/freeradius/rlm_expiration.so
%{_libdir}/freeradius/rlm_expr.so
%{_libdir}/freeradius/rlm_files.so
%{_libdir}/freeradius/rlm_ippool.so
%{_libdir}/freeradius/rlm_linelog.so
%{_libdir}/freeradius/rlm_logintime.so
%{_libdir}/freeradius/rlm_mschap.so
%{_libdir}/freeradius/rlm_pam.so
%{_libdir}/freeradius/rlm_pap.so
%{_libdir}/freeradius/rlm_passwd.so
%{_libdir}/freeradius/rlm_preprocess.so
%{_libdir}/freeradius/rlm_radutmp.so
%{_libdir}/freeradius/rlm_realm.so
%{_libdir}/freeradius/rlm_replicate.so
%{_libdir}/freeradius/rlm_soh.so
%{_libdir}/freeradius/rlm_sometimes.so
%{_libdir}/freeradius/rlm_sql.so
%{_libdir}/freeradius/rlm_sql_null.so
%{_libdir}/freeradius/rlm_sql_sqlite.so
%{_libdir}/freeradius/rlm_sqlcounter.so
%{_libdir}/freeradius/rlm_sqlippool.so
%{_libdir}/freeradius/rlm_sql_map.so

%{_libdir}/freeradius/rlm_totp.so
%{_libdir}/freeradius/rlm_unpack.so
%{_libdir}/freeradius/rlm_unix.so
%{_libdir}/freeradius/rlm_utf8.so
%{_libdir}/freeradius/rlm_wimax.so
%{?_with_rlm_idn: %{_libdir}/freeradius/rlm_idn.so}
%if %{?_with_experimental_modules:1}%{!?_with_experimental_modules:0}
%{_libdir}/freeradius/rlm_example.so
%{_libdir}/freeradius/rlm_smsotp.so
%endif

%files config
%dir %attr(755,root,radiusd) %{_sysconfdir}/raddb
%defattr(-,root,radiusd)
%attr(644,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/dictionary
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/clients.conf
%config(noreplace) %{_sysconfdir}/raddb/hints
%config(noreplace) %{_sysconfdir}/raddb/huntgroups
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/panic.gdb
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/README.rst
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/proxy.conf
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/radiusd.conf
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/trigger.conf
%config(noreplace) %{_sysconfdir}/raddb/users
%dir %attr(770,root,radiusd) %{_sysconfdir}/raddb/certs
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/certs/README.md
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/certs/Makefile
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/certs/bootstrap
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/certs/xpextensions
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/certs/*.cnf
%dir %attr(770,root,radiusd) %{_sysconfdir}/raddb/certs/realms
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/certs/realms/*
%attr(750,root,radiusd) %{_sysconfdir}/raddb/certs/bootstrap
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/sites-available
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/sites-available/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/sites-enabled
%config(noreplace) %{_sysconfdir}/raddb/sites-enabled/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/policy.d
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/policy.d/*
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/templates.conf
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-available
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-available/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/README.rst
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/attr_filter
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/attr_filter/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/files
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/files/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/perl
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/perl/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/preprocess
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/preprocess/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/unbound
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/unbound/*
%if %{?el6:0}%{!?el6:1}
%if 0%{?rhel} <= 8
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/python
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/python/*
%endif
%if 0%{?rhel} >= 8
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/python3
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/python3/*
%endif
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/realm
%attr(-,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/realm/*
%endif
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-enabled
%config(noreplace) %{_sysconfdir}/raddb/mods-enabled/*
# ruby
%if %{?_with_rlm_ruby:1}%{!?_with_rlm_ruby:0}
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/ruby
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/ruby/*
%endif
#
# sql - general
#
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/counter
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/cui
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/dhcp
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/ippool
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/ippool-dhcp
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/main
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/moonshot-targeted-ids
#
# mysql
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/counter/mysql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/counter/mysql/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/cui/mysql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/cui/mysql/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/dhcp/mysql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/dhcp/mysql/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/ippool/mysql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/ippool/mysql/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/ippool-dhcp/mysql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/ippool-dhcp/mysql/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/main/mysql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/main/mysql/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/main/mysql/extras
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/main/mysql/extras/wimax
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/main/mysql/extras/wimax/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/main/ndb
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/main/ndb/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/moonshot-targeted-ids/mysql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/moonshot-targeted-ids/mysql/*
#
# postgres
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/counter/postgresql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/counter/postgresql/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/cui/postgresql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/cui/postgresql/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/dhcp/postgresql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/dhcp/postgresql/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/ippool/postgresql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/ippool/postgresql/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/ippool-dhcp/postgresql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/ippool-dhcp/postgresql/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/main/postgresql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/main/postgresql/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/main/postgresql/extras
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/main/postgresql/extras/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/moonshot-targeted-ids/postgresql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/moonshot-targeted-ids/postgresql/*
#
# sqlite
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/counter/sqlite
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/counter/sqlite/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/cui/sqlite
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/cui/sqlite/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/dhcp/sqlite
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/dhcp/sqlite/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/ippool/sqlite
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/ippool/sqlite/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/ippool-dhcp/sqlite
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/ippool-dhcp/sqlite/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/main/sqlite
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/main/sqlite/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/moonshot-targeted-ids/sqlite
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/moonshot-targeted-ids/sqlite/*
#
# freetds
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/dhcp/mssql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/dhcp/mssql/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/ippool/mssql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/ippool/mssql/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/ippool-dhcp/mssql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/ippool-dhcp/mssql/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/main/mssql
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/main/mssql/*
#
# oracle
%if %{?_with_rlm_sql_oracle:1}%{!?_with_rlm_sql_oracle:0}
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/dhcp/oracle
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/dhcp/oracle/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/ippool/oracle
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/ippool/oracle/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/ippool-dhcp/oracle
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/ippool-dhcp/oracle/*
%dir %attr(750,root,radiusd) %{_sysconfdir}/raddb/mods-config/sql/main/oracle
%attr(640,root,radiusd) %config(noreplace) %{_sysconfdir}/raddb/mods-config/sql/main/oracle/*
%endif

%files utils
%defattr(-,root,root)
/usr/bin/dhcpclient
/usr/bin/map_unit
/usr/bin/rad_counter
/usr/bin/radattr
/usr/bin/radclient
/usr/bin/radcrypt
/usr/bin/radeapclient
/usr/bin/radlast
/usr/bin/radtest
/usr/bin/radsecret
/usr/bin/radsniff
/usr/bin/radsqlrelay
/usr/bin/raduat
/usr/bin/radwho
/usr/bin/radzap
/usr/bin/rlm_ippool_tool
/usr/bin/smbencrypt
# man-pages
%doc %{_mandir}/man1/dhcpclient.1.gz
%doc %{_mandir}/man1/rad_counter.1.gz
%doc %{_mandir}/man1/radclient.1.gz
%doc %{_mandir}/man1/radeapclient.1.gz
%doc %{_mandir}/man1/radlast.1.gz
%doc %{_mandir}/man8/radsqlrelay.8.gz
%doc %{_mandir}/man1/radtest.1.gz
%doc %{_mandir}/man1/radwho.1.gz
%doc %{_mandir}/man1/radzap.1.gz
%doc %{_mandir}/man8/rlm_ippool_tool.8.gz

%files perl-util
%defattr(-,root,root)
/usr/bin/rlm_sqlippool_tool
#man-pages
%doc %{_mandir}/man8/rlm_sqlippool_tool.8.gz

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

%if %{?el6:0}%{!?el6:1}
%files python
%defattr(-,root,root)
%if 0%{?rhel} <= 8
%{_libdir}/freeradius/rlm_python.so
%endif
%if 0%{?rhel} >= 8
%{_libdir}/freeradius/rlm_python3.so
%endif
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

%if %{!?_without_ldap:1}%{?_without_ldap:0}
%files ldap
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_ldap.so
%endif

%files unixODBC
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sql_unixodbc.so

%if %{?el6:0}%{!?el6:1}
%files redis
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_redis.so
%{_libdir}/freeradius/rlm_rediswho.so
%{_libdir}/freeradius/rlm_cache_redis.so
%endif

%files rest
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_rest.so
%{_libdir}/freeradius/rlm_json.so

%if %{?_with_rlm_ruby:1}%{!?_with_rlm_ruby:0}
%files ruby
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_ruby.so
%endif

%files freetds
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sql_freetds.so

%if %{?_with_rlm_sql_oracle:1}%{!?_with_rlm_sql_oracle:0}
%files oracle
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_sql_oracle.so
%endif

%files unbound
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_unbound.so

%if %{?_with_rlm_yubikey:1}%{!?_with_rlm_yubikey:0}
%files yubikey
%defattr(-,root,root)
%{_libdir}/freeradius/rlm_yubikey.so
%endif

%changelog
* Wed Sep 25 2013 Alan DeKok <aland@freeradius.org> - 3.0.0
- upgrade to latest upstream release
